package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirrapa-it/gov-jwks-service/internal/config"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 10}))
}

func saTokenFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	os.WriteFile(p, []byte("fake-sa-jwt"), 0600)
	return p
}

func vaultMock(t *testing.T) *httptest.Server {
	t.Helper()
	store := map[string]map[string]any{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kvServe(w, r, store)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func k8sMock(t *testing.T, mount string) *httptest.Server {
	t.Helper()
	store := map[string]map[string]any{}
	loginPath := "/v1/auth/" + mount + "/login"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == loginPath {
			json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]any{"client_token": "k8s-tok", "lease_duration": 3600},
			})
			return
		}
		kvServe(w, r, store)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func kvServe(w http.ResponseWriter, r *http.Request, store map[string]map[string]any) {
	key := r.URL.Path
	switch r.Method {
	case http.MethodGet:
		d, ok := store[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]any{"errors": []string{"not found"}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"data": d})
	case http.MethodPost, http.MethodPut:
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		store[key] = body
		w.WriteHeader(http.StatusNoContent)
	case "LIST":
		var keys []string
		prefix := key + "/"
		for k := range store {
			if len(k) > len(prefix) && k[:len(prefix)] == prefix {
				keys = append(keys, k[len(prefix):])
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"keys": keys}})
	case http.MethodDelete:
		delete(store, key)
		w.WriteHeader(http.StatusNoContent)
	}
}

func rotatorCfg(vaultURL string) *config.RotatorConfig {
	return &config.RotatorConfig{
		KeyBits: 1024, GracePeriod: time.Hour,
		LogLevel: "error",
		Vault: config.VaultConfig{
			Addr: vaultURL, Token: "tok",
			Mount: "secret", SecretPath: "jwks-rot",
		},
	}
}

// ---- newLogger --------------------------------------------------------------

func TestNewLogger_AllLevels(t *testing.T) {
	for _, lvl := range []string{"debug", "info", "warn", "error", "unknown"} {
		if l := newLogger(lvl); l == nil {
			t.Errorf("newLogger(%q) = nil", lvl)
		}
	}
}

// ---- missingVaultAuthError --------------------------------------------------

func TestMissingVaultAuthError_Message(t *testing.T) {
	if (&missingVaultAuthError{}).Error() == "" {
		t.Error("expected non-empty error message")
	}
}

// ---- buildVaultClient -------------------------------------------------------

func TestBuildVaultClient_TokenAuth(t *testing.T) {
	srv := vaultMock(t)
	c, err := buildVaultClient(context.Background(), config.VaultConfig{
		Addr: srv.URL, Token: "tok",
	}, discardLogger())
	if err != nil || c == nil {
		t.Fatalf("token auth: %v", err)
	}
}

func TestBuildVaultClient_K8sAuth(t *testing.T) {
	tokenFile := saTokenFile(t)
	srv := k8sMock(t, "kubernetes")
	c, err := buildVaultClient(context.Background(), config.VaultConfig{
		Addr: srv.URL, K8sRole: "jwks-rotator",
		K8sMountPath: "kubernetes", K8sSATokenPath: tokenFile,
	}, discardLogger())
	if err != nil || c == nil {
		t.Fatalf("k8s auth: %v", err)
	}
}

func TestBuildVaultClient_NoAuth_ReturnsError(t *testing.T) {
	_, err := buildVaultClient(context.Background(), config.VaultConfig{
		Addr: "http://127.0.0.1:8200",
	}, discardLogger())
	if err == nil {
		t.Fatal("expected error with no auth")
	}
}

// ---- rotate() ---------------------------------------------------------------

func TestRotate_Success_Returns0(t *testing.T) {
	srv := vaultMock(t)
	if code := rotate(context.Background(), rotatorCfg(srv.URL), discardLogger()); code != 0 {
		t.Errorf("rotate() = %d, want 0", code)
	}
}

func TestRotate_NoVaultAddr_Returns1(t *testing.T) {
	cfg := &config.RotatorConfig{KeyBits: 1024, GracePeriod: time.Hour}
	if code := rotate(context.Background(), cfg, discardLogger()); code != 1 {
		t.Errorf("rotate() = %d, want 1 when VAULT_ADDR not set", code)
	}
}

func TestRotate_VaultUnreachable_Returns1(t *testing.T) {
	cfg := rotatorCfg("http://127.0.0.1:1")
	if code := rotate(context.Background(), cfg, discardLogger()); code != 1 {
		t.Errorf("rotate() = %d, want 1 for unreachable Vault", code)
	}
}

func TestRotate_RotationError_Returns1(t *testing.T) {
	// Vault returns 403 for all operations → rotation fails.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]any{"errors": []string{"denied"}})
	}))
	defer srv.Close()

	cfg := rotatorCfg(srv.URL)
	if code := rotate(context.Background(), cfg, discardLogger()); code != 1 {
		t.Errorf("rotate() = %d, want 1 when rotation fails", code)
	}
}

func TestRotate_MultipleRuns_Idempotent(t *testing.T) {
	srv := vaultMock(t)
	cfg := rotatorCfg(srv.URL)
	for i := 0; i < 3; i++ {
		if code := rotate(context.Background(), cfg, discardLogger()); code != 0 {
			t.Errorf("rotation %d failed: code=%d", i, code)
		}
	}
}

func TestRotate_LogsSucceededEvent(t *testing.T) {
	srv := vaultMock(t)
	// Just verify it completes without error — log output goes to discard.
	if code := rotate(context.Background(), rotatorCfg(srv.URL), discardLogger()); code != 0 {
		t.Errorf("rotate() = %d, want 0", code)
	}
}
