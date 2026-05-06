// Internal test file — accesses unexported httpDoFn hook.
package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func saFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	os.WriteFile(p, []byte(content), 0600)
	return p
}

// ---- KubernetesAuth --------------------------------------------------------

func TestKubernetesAuth_Success(t *testing.T) {
	tokenFile := saFile(t, "fake-sa-jwt")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["jwt"] != "fake-sa-jwt" || body["role"] != "test-role" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{"client_token": "k8s-tok", "lease_duration": 3600},
		})
	}))
	defer srv.Close()

	auth := &KubernetesAuth{Role: "test-role", ServiceAccountTokenPath: tokenFile}
	tok, ttl, err := auth.Authenticate(context.Background(), srv.URL, &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if tok != "k8s-tok" {
		t.Errorf("token = %q, want k8s-tok", tok)
	}
	if ttl != 3600*time.Second {
		t.Errorf("ttl = %v, want 1h", ttl)
	}
}

func TestKubernetesAuth_DefaultMountPath(t *testing.T) {
	tokenFile := saFile(t, "jwt")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/kubernetes/login" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{"client_token": "tok", "lease_duration": 100},
		})
	}))
	defer srv.Close()

	auth := &KubernetesAuth{Role: "r", ServiceAccountTokenPath: tokenFile}
	_, _, err := auth.Authenticate(context.Background(), srv.URL, &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("expected default mount to be 'kubernetes': %v", err)
	}
}

func TestKubernetesAuth_MissingTokenFile(t *testing.T) {
	auth := &KubernetesAuth{Role: "r", ServiceAccountTokenPath: "/nonexistent/token"}
	_, _, err := auth.Authenticate(context.Background(), "http://unused", &http.Client{})
	if err == nil {
		t.Fatal("expected error for missing token file")
	}
}

func TestKubernetesAuth_Non200Response(t *testing.T) {
	tokenFile := saFile(t, "jwt")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	auth := &KubernetesAuth{Role: "r", ServiceAccountTokenPath: tokenFile}
	_, _, err := auth.Authenticate(context.Background(), srv.URL, &http.Client{Timeout: 5 * time.Second})
	if err == nil {
		t.Fatal("expected error for 401")
	}
}

func TestKubernetesAuth_BadJSONResponse(t *testing.T) {
	tokenFile := saFile(t, "jwt")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "{bad json")
	}))
	defer srv.Close()

	auth := &KubernetesAuth{Role: "r", ServiceAccountTokenPath: tokenFile}
	_, _, err := auth.Authenticate(context.Background(), srv.URL, &http.Client{Timeout: 5 * time.Second})
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestKubernetesAuth_EmptyClientToken(t *testing.T) {
	tokenFile := saFile(t, "jwt")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{"client_token": "", "lease_duration": 3600},
		})
	}))
	defer srv.Close()

	auth := &KubernetesAuth{Role: "r", ServiceAccountTokenPath: tokenFile}
	_, _, err := auth.Authenticate(context.Background(), srv.URL, &http.Client{Timeout: 5 * time.Second})
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestKubernetesAuth_ZeroLeaseDuration_Fallback(t *testing.T) {
	tokenFile := saFile(t, "jwt")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{"client_token": "tok", "lease_duration": 0},
		})
	}))
	defer srv.Close()

	auth := &KubernetesAuth{Role: "r", ServiceAccountTokenPath: tokenFile}
	_, ttl, err := auth.Authenticate(context.Background(), srv.URL, &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if ttl != time.Hour {
		t.Errorf("ttl = %v, want 1h fallback for zero lease_duration", ttl)
	}
}

func TestKubernetesAuth_HTTPDoError(t *testing.T) {
	tokenFile := saFile(t, "jwt")
	orig := httpDoFn
	httpDoFn = func(_ *http.Client, _ *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("injected HTTP error")
	}
	t.Cleanup(func() { httpDoFn = orig })

	auth := &KubernetesAuth{Role: "r", ServiceAccountTokenPath: tokenFile}
	_, _, err := auth.Authenticate(context.Background(), "http://unused", &http.Client{})
	if err == nil {
		t.Fatal("expected error when HTTP Do fails")
	}
}

func TestKubernetesAuth_DefaultSATokenPath_NotFound(t *testing.T) {
	// No ServiceAccountTokenPath set — reads the default K8s path which
	// doesn't exist outside a cluster. Covers the default-path branch.
	auth := &KubernetesAuth{Role: "r"}
	_, _, err := auth.Authenticate(context.Background(), "http://unused", &http.Client{})
	if err == nil {
		t.Fatal("expected error for missing default SA token file")
	}
}

// ---- TokenAuth --------------------------------------------------------------

func TestTokenAuth_ValidToken(t *testing.T) {
	a := &TokenAuth{Token: "hvs.test"}
	tok, ttl, err := a.Authenticate(context.Background(), "", nil)
	if err != nil || tok != "hvs.test" || ttl <= 0 {
		t.Errorf("Authenticate() = (%q, %v, %v)", tok, ttl, err)
	}
}

func TestTokenAuth_EmptyToken(t *testing.T) {
	a := &TokenAuth{}
	_, _, err := a.Authenticate(context.Background(), "", nil)
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}

// ---- Token refresh ----------------------------------------------------------

func TestClient_RefreshToken_WhenExpired(t *testing.T) {
	srv := newKVServerForRefresh(t)
	c, err := NewClient(context.Background(), ClientConfig{
		Address: srv.URL,
		Auth:    &TokenAuth{Token: "test-token"},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// Force the token to be considered expired.
	c.mu.Lock()
	c.tokenExpires = c.tokenExpires.Add(-24 * time.Hour)
	c.mu.Unlock()

	// Next operation should trigger a refresh (TokenAuth re-authenticates silently).
	if _, err := c.Get(context.Background(), "secret", "some/path"); err != nil {
		t.Fatalf("Get after forced expiry: %v", err)
	}

	c.mu.RLock()
	expires := c.tokenExpires
	c.mu.RUnlock()

	if !expires.After(time.Now()) {
		t.Error("tokenExpires should be in the future after refresh")
	}
}

func TestClient_RefreshToken_AuthFailure(t *testing.T) {
	srv := newKVServerForRefresh(t)
	c, err := NewClient(context.Background(), ClientConfig{
		Address: srv.URL,
		Auth:    &TokenAuth{Token: "test-token"},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// Replace auth with one that always fails, then expire the token.
	c.auth = &failingAuth{}
	c.mu.Lock()
	c.tokenExpires = c.tokenExpires.Add(-24 * time.Hour)
	c.mu.Unlock()

	if err := c.Put(context.Background(), "s", "p", map[string]any{"k": "v"}); err == nil {
		t.Fatal("expected error when re-auth fails")
	}
}

// ---- helpers ----------------------------------------------------------------

type failingAuth struct{}

func (f *failingAuth) Authenticate(_ context.Context, _ string, _ *http.Client) (string, time.Duration, error) {
	return "", 0, fmt.Errorf("injected auth failure")
}

func newKVServerForRefresh(t *testing.T) *httptest.Server {
	t.Helper()
	store := map[string]map[string]any{
		"secret/some/path": {"k": "v"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/v1/"), "/", 2)
		if len(parts) < 2 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		key := parts[0] + "/" + parts[1]
		switch r.Method {
		case http.MethodGet:
			d, ok := store[key]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]any{"errors": []string{"not found"}})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"data": d})
		case http.MethodPost:
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			store[key] = body
			w.WriteHeader(http.StatusNoContent)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}
