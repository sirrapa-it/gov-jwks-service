// Command server is the JWKS HTTP server.
// It serves public signing keys and refreshes its cache from Vault periodically.
// The server never writes to Vault — use the rotator binary for key generation.
//
// Run the rotator at least once before deploying the server.
//
// # Endpoints
//
//   - GET /.well-known/jwks.json  — JSON Web Key Set (RFC 7517)
//   - GET /healthz                — Kubernetes liveness probe
//   - GET /metrics                — Prometheus metrics
//   - POST /internal/sign         — test token issuer (signing build tag only)
//
// # Configuration
//
// See config.LoadServerConfig for all environment variables.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirrapa-it/gov-jwks-service/internal/config"
	"github.com/sirrapa-it/gov-jwks-service/internal/handler"
	"github.com/sirrapa-it/gov-jwks-service/internal/keystore"
	"github.com/sirrapa-it/gov-jwks-service/internal/vault"
)

// shutdownTimeout is the maximum time to drain in-flight requests.
// Overridable by tests.
var shutdownTimeout = 10 * time.Second

// keyAgeUpdateInterval controls how often the key age metric is updated.
// Overridable by tests.
var keyAgeUpdateInterval = 30 * time.Second

func main() {
	cfg := config.LoadServerConfig()
	os.Exit(run(context.Background(), cfg, newLogger(cfg.LogLevel)))
}

// run is the testable entry point. Returns 0 on success, 1 on error.
func run(ctx context.Context, cfg *config.ServerConfig, logger *slog.Logger) int {
	logger.Info("starting jwks server",
		"addr", cfg.ListenAddr,
		"sync_interval", cfg.SyncInterval,
		"vault_enabled", cfg.Vault.Enabled(),
	)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	store, err := buildStore(ctx, cfg, logger)
	if err != nil {
		logger.Error("failed to initialise key store", "error", err)
		return 1
	}

	key, _ := store.ActiveKey()
	logger.Info("active signing key ready", "kid", key.Kid)

	store.StartSync(ctx, cfg.SyncInterval)

	go func() {
		ticker := time.NewTicker(keyAgeUpdateInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if k, err := store.ActiveKey(); err == nil {
					keystore.UpdateActiveKeyAge(k.CreatedAt)
				}
			}
		}
	}()

	mux := http.NewServeMux()
	handler.New(store, logger).RegisterRoutes(mux)

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		select {
		case <-quit:
		case <-ctx.Done():
		}
		logger.Info("shutting down server")
		cancel()
		shutCtx, shutCancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer shutCancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			logger.Error("shutdown error", "error", err)
		}
	}()

	logger.Info("listening", "addr", cfg.ListenAddr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server error", "error", err)
		return 1
	}
	return 0
}

// buildStore constructs the VaultKeyStore from server config.
func buildStore(ctx context.Context, cfg *config.ServerConfig, logger *slog.Logger) (*keystore.VaultKeyStore, error) {
	if !cfg.Vault.Enabled() {
		return nil, fmt.Errorf("VAULT_ADDR is required — the server has no in-memory fallback")
	}
	vaultClient, err := buildVaultClient(ctx, cfg.Vault, logger)
	if err != nil {
		return nil, err
	}
	return keystore.NewVaultKeyStore(ctx, keystore.VaultKeyStoreConfig{
		Vault:      vaultClient,
		Mount:      cfg.Vault.Mount,
		SecretPath: cfg.Vault.SecretPath,
		Logger:     logger,
	})
}

// buildVaultClient constructs a Vault client using the correct authenticator:
//   - K8sRole set → KubernetesAuth (production)
//   - Token set   → TokenAuth (development / CI)
//   - neither     → error
func buildVaultClient(ctx context.Context, vcfg config.VaultConfig, logger *slog.Logger) (*vault.Client, error) {
	var auth vault.Authenticator
	switch {
	case vcfg.K8sRole != "":
		logger.Info("using Kubernetes Vault auth", "role", vcfg.K8sRole)
		auth = &vault.KubernetesAuth{
			Role:                    vcfg.K8sRole,
			MountPath:               vcfg.K8sMountPath,
			ServiceAccountTokenPath: vcfg.K8sSATokenPath,
		}
	case vcfg.Token != "":
		logger.Warn("using static Vault token — not suitable for production")
		auth = &vault.TokenAuth{Token: vcfg.Token}
	default:
		return nil, &missingVaultAuthError{}
	}
	return vault.NewClient(ctx, vault.ClientConfig{Address: vcfg.Addr, Auth: auth})
}

type missingVaultAuthError struct{}

func (e *missingVaultAuthError) Error() string {
	return "no Vault authentication configured: set VAULT_K8S_ROLE (production) or VAULT_TOKEN (development)"
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	switch level {
	case "debug":
		l = slog.LevelDebug
	case "info":
		l = slog.LevelInfo
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelWarn
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}
