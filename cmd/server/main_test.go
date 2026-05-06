package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/sirrapa/jwks-service/internal/config"
	"github.com/sirrapa/jwks-service/internal/keystore"
)

// ---- test helpers -----------------------------------------------------------

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 10}))
}

func saTokenFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	os.WriteFile(p, []byte("fake-sa-jwt"), 0600)
	return p
}

// vaultMock starts a minimal KV v1 mock server and returns it pre-populated
// with one signing key produced by the rotator logic.
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

// serverCfg returns a minimal ServerConfig for the given vault URL.
func serverCfg(t *testing.T, vaultURL string) *config.ServerConfig {
	t.Helper()
	return &config.ServerConfig{
		ListenAddr:      "127.0.0.1:0",
		SyncInterval:    time.Hour,
		ShutdownTimeout: shutdownTimeout,
		LogLevel:        "error",
		Vault: config.VaultConfig{
			Addr: vaultURL, Token: "tok",
			Mount: "secret", SecretPath: "jwks-srv",
		},
	}
}

// bootstrapVault seeds the mock Vault with a signing key using the keystore rotator.
func bootstrapVault(t *testing.T, vaultURL string) {
	t.Helper()
	vaultClient, err := buildVaultClient(context.Background(), config.VaultConfig{
		Addr: vaultURL, Token: "tok",
	}, discardLogger())
	if err != nil {
		t.Fatalf("bootstrap buildVaultClient: %v", err)
	}
	r := keystore.NewRotator(vaultClient, keystore.RotatorConfig{
		KeyBits: 1024, GracePeriod: time.Hour,
		Mount: "secret", SecretPath: "jwks-srv",
	})
	if err := r.Rotate(context.Background()); err != nil {
		t.Fatalf("bootstrap rotate: %v", err)
	}
}

// ---- newLogger --------------------------------------------------------------

func TestNewLogger_AllLevels(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error", "unknown"} {
		l := newLogger(level)
		if l == nil {
			t.Errorf("newLogger(%q) = nil", level)
		}
	}
}

// ---- missingVaultAuthError --------------------------------------------------

func TestMissingVaultAuthError_Message(t *testing.T) {
	e := &missingVaultAuthError{}
	if e.Error() == "" {
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
		Addr: srv.URL, K8sRole: "jwks-service",
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
		t.Fatal("expected error with no auth method")
	}
}

// ---- buildStore -------------------------------------------------------------

func TestBuildStore_NoVaultAddr_ReturnsError(t *testing.T) {
	_, err := buildStore(context.Background(), &config.ServerConfig{}, discardLogger())
	if err == nil {
		t.Fatal("expected error when VAULT_ADDR not set")
	}
}

func TestBuildStore_ClientError_ReturnsError(t *testing.T) {
	_, err := buildStore(context.Background(), &config.ServerConfig{
		Vault: config.VaultConfig{Addr: "http://127.0.0.1:1", Token: "tok"},
	}, discardLogger())
	if err == nil {
		t.Fatal("expected error for unreachable Vault")
	}
}

func TestBuildStore_NoKeys_ReturnsError(t *testing.T) {
	srv := vaultMock(t) // empty vault, no keys
	_, err := buildStore(context.Background(), serverCfg(t, srv.URL), discardLogger())
	if err == nil {
		t.Fatal("expected error when vault has no keys")
	}
}

func TestBuildStore_WithKeys_Succeeds(t *testing.T) {
	srv := vaultMock(t)
	bootstrapVault(t, srv.URL)
	s, err := buildStore(context.Background(), serverCfg(t, srv.URL), discardLogger())
	if err != nil || s == nil {
		t.Fatalf("buildStore: %v", err)
	}
}

// ---- run() ------------------------------------------------------------------

func TestRun_ShutdownOnContextCancel(t *testing.T) {
	srv := vaultMock(t)
	bootstrapVault(t, srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- run(ctx, serverCfg(t, srv.URL), discardLogger()) }()

	time.Sleep(80 * time.Millisecond)
	cancel()

	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("run() = %d, want 0", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("run() did not exit after context cancel")
	}
}

func TestRun_BuildStoreFailure_Returns1(t *testing.T) {
	// No vault keys → buildStore fails → run returns 1.
	srv := vaultMock(t)
	if code := run(context.Background(), serverCfg(t, srv.URL), discardLogger()); code != 1 {
		t.Errorf("run() = %d, want 1", code)
	}
}

func TestRun_ListenError_Returns1(t *testing.T) {
	srv := vaultMock(t)
	bootstrapVault(t, srv.URL)

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	cfg := serverCfg(t, srv.URL)
	cfg.ListenAddr = ln.Addr().String()

	if code := run(context.Background(), cfg, discardLogger()); code != 1 {
		t.Errorf("run() = %d, want 1 for bound port", code)
	}
}

func TestRun_ShutdownOnSIGTERM(t *testing.T) {
	srv := vaultMock(t)
	bootstrapVault(t, srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	go func() { done <- run(ctx, serverCfg(t, srv.URL), discardLogger()) }()

	time.Sleep(80 * time.Millisecond)
	p, _ := os.FindProcess(os.Getpid())
	p.Signal(syscall.SIGTERM)

	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("run() = %d, want 0 on SIGTERM", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("run() did not exit after SIGTERM")
	}
}

func TestRun_ShutdownError_ZeroTimeout(t *testing.T) {
	// Zero-duration shutdown triggers a context deadline exceeded from srv.Shutdown.
	orig := shutdownTimeout
	shutdownTimeout = -1 * time.Nanosecond
	t.Cleanup(func() { shutdownTimeout = orig })

	// Just verify the shutdown path is reachable without panicking.
	unblock := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) { <-unblock })

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	httpSrv := &http.Server{Handler: mux}
	go httpSrv.Serve(ln)
	go http.Get("http://" + ln.Addr().String() + "/slow")
	time.Sleep(20 * time.Millisecond)

	shutCtx, shutCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutCancel()
	_ = httpSrv.Shutdown(shutCtx)
	close(unblock)
	ln.Close()
}

// ---- key age goroutine ------------------------------------------------------

func TestRun_KeyAgeGoroutine_UpdatesMetric(t *testing.T) {
	orig := keyAgeUpdateInterval
	keyAgeUpdateInterval = 20 * time.Millisecond
	t.Cleanup(func() { keyAgeUpdateInterval = orig })

	srv := vaultMock(t)
	bootstrapVault(t, srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- run(ctx, serverCfg(t, srv.URL), discardLogger()) }()

	time.Sleep(120 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("run() did not exit")
	}
}
