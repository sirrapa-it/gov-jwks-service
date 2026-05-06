// Command rotator performs a single key rotation and exits.
// Designed to run as a Kubernetes CronJob (concurrencyPolicy: Forbid).
//
// Monthly rotation with RSA 4096 satisfies BIO (max 4-year key lifetime)
// and NIS2 Article 21 (demonstrable key management process).
//
// See config.LoadRotatorConfig for all environment variables.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirrapa/jwks-service/internal/config"
	"github.com/sirrapa/jwks-service/internal/keystore"
	"github.com/sirrapa/jwks-service/internal/vault"
)

func main() {
	cfg := config.LoadRotatorConfig()
	os.Exit(rotate(context.Background(), cfg, newLogger(cfg.LogLevel)))
}

// rotate is the testable entry point. Returns 0 on success, 1 on failure.
func rotate(ctx context.Context, cfg *config.RotatorConfig, logger *slog.Logger) int {
	logger.Info("starting key rotation",
		"key_bits", cfg.KeyBits,
		"grace_period", cfg.GracePeriod,
	)

	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if !cfg.Vault.Enabled() {
		logger.Error("VAULT_ADDR is required")
		return 1
	}

	vaultClient, err := buildVaultClient(ctx, cfg.Vault, logger)
	if err != nil {
		logger.Error("failed to connect to Vault", "error", err)
		return 1
	}

	r := keystore.NewRotator(vaultClient, keystore.RotatorConfig{
		KeyBits:     cfg.KeyBits,
		GracePeriod: cfg.GracePeriod,
		Mount:       cfg.Vault.Mount,
		SecretPath:  cfg.Vault.SecretPath,
		Logger:      logger,
	})

	start := time.Now()
	if err := r.Rotate(ctx); err != nil {
		logger.Error("key rotation failed",
			"event.action", "rotation.failed",
			"event.category", "authentication",
			"error", err,
			"duration", time.Since(start),
		)
		return 1
	}

	logger.Info("key rotation succeeded",
		"event.action", "rotation.succeeded",
		"event.category", "authentication",
		"duration", time.Since(start),
	)
	return 0
}

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
