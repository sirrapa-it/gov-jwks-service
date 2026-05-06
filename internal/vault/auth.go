// Package vault provides a minimal, stdlib-only HTTP client for HashiCorp
// Vault's KV v1 secrets engine. No external SDK dependency is required.
package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

// httpDoFn is the HTTP executor used by KubernetesAuth.Authenticate.
// Tests can substitute a failing implementation to cover the Do error path.
var httpDoFn = func(c *http.Client, r *http.Request) (*http.Response, error) {
	return c.Do(r)
}

// Authenticator obtains a Vault token and reports its TTL.
// The token is cached by Client and renewed before it expires.
type Authenticator interface {
	Authenticate(ctx context.Context, baseURL string, httpClient *http.Client) (token string, ttl time.Duration, err error)
}

// TokenAuth is a static-token Authenticator for development and CI.
// Never use in production — use KubernetesAuth instead.
type TokenAuth struct {
	Token string
}

func (a *TokenAuth) Authenticate(_ context.Context, _ string, _ *http.Client) (string, time.Duration, error) {
	if a.Token == "" {
		return "", 0, fmt.Errorf("vault: TokenAuth: token must not be empty")
	}
	return a.Token, 24 * time.Hour, nil
}

// KubernetesAuth exchanges the pod service-account JWT for a Vault token
// via the Vault Kubernetes auth method.
//
// Required Vault role configuration:
//
//	vault write auth/kubernetes/role/jwks-service \
//	    bound_service_account_names=jwks-service \
//	    bound_service_account_namespaces=platform \
//	    policies=jwks-service_ro \
//	    alias_name_source=serviceaccount_name \
//	    ttl=1h
type KubernetesAuth struct {
	Role                    string
	MountPath               string
	ServiceAccountTokenPath string
}

func (a *KubernetesAuth) Authenticate(ctx context.Context, baseURL string, httpClient *http.Client) (string, time.Duration, error) {
	mountPath := a.MountPath
	if mountPath == "" {
		mountPath = "kubernetes"
	}
	tokenPath := a.ServiceAccountTokenPath
	if tokenPath == "" {
		tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	}

	saJWT, err := os.ReadFile(tokenPath)
	if err != nil {
		return "", 0, fmt.Errorf("vault: KubernetesAuth: read service account token from %s: %w", tokenPath, err)
	}

	payload, _ := json.Marshal(map[string]string{"role": a.Role, "jwt": string(saJWT)})
	url := fmt.Sprintf("%s/v1/auth/%s/login", baseURL, mountPath)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpDoFn(httpClient, req)
	if err != nil {
		return "", 0, fmt.Errorf("vault: KubernetesAuth: login request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("vault: KubernetesAuth: login returned HTTP %d", resp.StatusCode)
	}

	var loginResp struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		return "", 0, fmt.Errorf("vault: KubernetesAuth: decode login response: %w", err)
	}
	if loginResp.Auth.ClientToken == "" {
		return "", 0, fmt.Errorf("vault: KubernetesAuth: empty token in login response")
	}

	ttl := time.Duration(loginResp.Auth.LeaseDuration) * time.Second
	if ttl == 0 {
		ttl = time.Hour
	}
	return loginResp.Auth.ClientToken, ttl, nil
}
