package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ErrNotFound is returned by SecretStore.Get when no secret exists at the path.
var ErrNotFound = fmt.Errorf("vault: secret not found")

// SecretStore is the interface the keystore packages depend on.
type SecretStore interface {
	Put(ctx context.Context, mount, path string, data map[string]any) error
	Get(ctx context.Context, mount, path string) (map[string]any, error)
	List(ctx context.Context, mount, path string) ([]string, error)
	Delete(ctx context.Context, mount, path string) error
}

// Client is a Vault HTTP client for the KV v1 secrets engine.
// It manages token acquisition and automatic renewal transparently.
// Client is safe for concurrent use.
type Client struct {
	baseURL      string
	httpClient   *http.Client
	auth         Authenticator
	mu           sync.RWMutex
	token        string
	tokenExpires time.Time
}

// ClientConfig holds the parameters for NewClient.
type ClientConfig struct {
	Address     string
	Auth        Authenticator
	HTTPTimeout time.Duration
}

// NewClient creates a Client and immediately authenticates against Vault.
func NewClient(ctx context.Context, cfg ClientConfig) (*Client, error) {
	if cfg.HTTPTimeout == 0 {
		cfg.HTTPTimeout = 10 * time.Second
	}
	c := &Client{
		baseURL:    strings.TrimRight(cfg.Address, "/"),
		httpClient: &http.Client{Timeout: cfg.HTTPTimeout},
		auth:       cfg.Auth,
	}
	if err := c.authenticate(ctx); err != nil {
		return nil, fmt.Errorf("vault: initial authentication failed: %w", err)
	}
	return c, nil
}

// Put writes data to the KV v1 engine at {mount}/{path}.
func (c *Client) Put(ctx context.Context, mount, path string, data map[string]any) error {
	if err := c.refreshIfNeeded(ctx); err != nil {
		return err
	}
	body, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("vault: marshal request body: %w", err)
	}
	url := c.url(mount, path)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c.setToken(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("vault: PUT %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return c.apiError("PUT", path, resp)
	}
	return nil
}

// Get retrieves the secret at {mount}/{path}. Returns ErrNotFound for 404.
func (c *Client) Get(ctx context.Context, mount, path string) (map[string]any, error) {
	if err := c.refreshIfNeeded(ctx); err != nil {
		return nil, err
	}
	url := c.url(mount, path)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	c.setToken(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault: GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, c.apiError("GET", path, resp)
	}
	var envelope struct {
		Data map[string]any `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("vault: decode response for %s: %w", path, err)
	}
	return envelope.Data, nil
}

// List returns the keys beneath {mount}/{path}. Returns empty slice for 404.
func (c *Client) List(ctx context.Context, mount, path string) ([]string, error) {
	if err := c.refreshIfNeeded(ctx); err != nil {
		return nil, err
	}
	url := c.url(mount, path)
	req, _ := http.NewRequestWithContext(ctx, "LIST", url, nil)
	c.setToken(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault: LIST %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return []string{}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, c.apiError("LIST", path, resp)
	}
	var envelope struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("vault: decode list response for %s: %w", path, err)
	}
	return envelope.Data.Keys, nil
}

// Delete removes the secret at {mount}/{path}.
func (c *Client) Delete(ctx context.Context, mount, path string) error {
	if err := c.refreshIfNeeded(ctx); err != nil {
		return err
	}
	url := c.url(mount, path)
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	c.setToken(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("vault: DELETE %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return c.apiError("DELETE", path, resp)
	}
	return nil
}

func (c *Client) authenticate(ctx context.Context) error {
	token, ttl, err := c.auth.Authenticate(ctx, c.baseURL, c.httpClient)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = token
	c.tokenExpires = time.Now().Add(time.Duration(float64(ttl) * 0.8))
	return nil
}

func (c *Client) refreshIfNeeded(ctx context.Context) error {
	c.mu.RLock()
	expired := time.Now().After(c.tokenExpires)
	c.mu.RUnlock()
	if !expired {
		return nil
	}
	return c.authenticate(ctx)
}

func (c *Client) setToken(req *http.Request) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	req.Header.Set("X-Vault-Token", c.token)
}

// url builds the full KV v1 URL. KV v1 uses flat paths — no data/ prefix.
func (c *Client) url(mount, path string) string {
	return fmt.Sprintf("%s/v1/%s/%s", c.baseURL, mount, strings.TrimLeft(path, "/"))
}

func (c *Client) apiError(method, path string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var vaultErr struct {
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(body, &vaultErr) == nil && len(vaultErr.Errors) > 0 {
		return fmt.Errorf("vault: %s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.Join(vaultErr.Errors, "; "))
	}
	return fmt.Errorf("vault: %s %s: HTTP %d", method, path, resp.StatusCode)
}
