package keystore

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/sirrapa-it/gov-jwks-service/internal/vault"
)

// RotatorConfig holds the parameters for a Rotator.
type RotatorConfig struct {
	KeyBits     int
	GracePeriod time.Duration
	Mount       string
	SecretPath  string
	Logger      *slog.Logger
}

// Rotator generates and persists signing keys. Used only by the rotator binary.
// It is designed for single-execution (Kubernetes CronJob) and must not run
// concurrently. Use concurrencyPolicy: Forbid on the CronJob.
type Rotator struct {
	vault  vault.SecretStore
	cfg    RotatorConfig
	logger *slog.Logger
}

// NewRotator creates a Rotator with the given configuration.
func NewRotator(v vault.SecretStore, cfg RotatorConfig) *Rotator {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Rotator{vault: v, cfg: cfg, logger: logger}
}

// Rotate performs a single key rotation:
//  1. Generates a new RSA key pair and persists it to Vault.
//  2. Marks all previously active keys with ExpiresAt = now + GracePeriod.
//  3. Deletes keys whose ExpiresAt has passed.
//  4. Updates the /active pointer.
func (r *Rotator) Rotate(ctx context.Context) error {
	now := time.Now()

	newKey, err := newManagedKey(r.cfg.KeyBits, time.Time{})
	if err != nil {
		keyRotationErrorsTotal.Inc()
		return fmt.Errorf("rotator: generate key: %w", err)
	}

	if err := r.writeKey(ctx, newKey); err != nil {
		keyRotationErrorsTotal.Inc()
		return fmt.Errorf("rotator: write new key: %w", err)
	}
	r.logger.Info("new signing key generated",
		"event.action", "key.created",
		"event.category", "authentication",
		"kid", newKey.Kid,
		"key_bits", r.cfg.KeyBits,
	)

	if err := r.markExistingExpiring(ctx, newKey.Kid, now); err != nil {
		keyRotationErrorsTotal.Inc()
		return err
	}

	if err := r.pruneExpired(ctx, now); err != nil {
		r.logger.Warn("failed to prune some expired keys", "error", err)
	}

	if err := r.vault.Put(ctx, r.cfg.Mount, r.cfg.SecretPath+"/active", map[string]any{
		"kid":        newKey.Kid,
		"rotated_at": now.UTC().Format(time.RFC3339),
	}); err != nil {
		keyRotationErrorsTotal.Inc()
		return fmt.Errorf("rotator: update active pointer: %w", err)
	}

	keyRotationsTotal.Inc()
	lastRotationTimestamp.SetToCurrentTime()

	r.logger.Info("key rotation complete",
		"event.action", "key.rotated",
		"event.category", "authentication",
		"new_kid", newKey.Kid,
		"grace_until", now.Add(r.cfg.GracePeriod).UTC(),
	)
	return nil
}

func (r *Rotator) writeKey(ctx context.Context, k *ManagedKey) error {
	pemBytes, err := pemEncodeFn(k.Private)
	if err != nil {
		return fmt.Errorf("encode PEM: %w", err)
	}
	record := map[string]any{
		"pem":        string(pemBytes),
		"kid":        k.Kid,
		"created_at": k.CreatedAt.UTC().Format(time.RFC3339),
		"expires_at": "",
	}
	return r.vault.Put(ctx, r.cfg.Mount, r.cfg.SecretPath+"/keys/"+k.Kid, record)
}

func (r *Rotator) markExistingExpiring(ctx context.Context, newKid string, now time.Time) error {
	kids, err := r.vault.List(ctx, r.cfg.Mount, r.cfg.SecretPath+"/keys")
	if err != nil {
		return fmt.Errorf("rotator: list keys: %w", err)
	}
	expiry := now.Add(r.cfg.GracePeriod)
	for _, kid := range kids {
		if kid == newKid {
			continue
		}
		path := r.cfg.SecretPath + "/keys/" + kid
		data, err := r.vault.Get(ctx, r.cfg.Mount, path)
		if err != nil {
			r.logger.Warn("skipping key during expiry marking", "kid", kid, "error", err)
			continue
		}
		rec := parseRecord(data)
		if rec.ExpiresAt != "" {
			continue
		}
		rec.ExpiresAt = expiry.UTC().Format(time.RFC3339)
		if err := r.vault.Put(ctx, r.cfg.Mount, path, map[string]any{
			"pem": rec.PEM, "kid": rec.Kid,
			"created_at": rec.CreatedAt, "expires_at": rec.ExpiresAt,
		}); err != nil {
			return fmt.Errorf("rotator: mark key %s as expiring: %w", kid, err)
		}
		r.logger.Info("key grace period started",
			"event.action", "key.grace_period_started",
			"event.category", "authentication",
			"kid", kid,
			"grace_until", expiry.UTC(),
		)
	}
	return nil
}

func (r *Rotator) pruneExpired(ctx context.Context, now time.Time) error {
	kids, err := r.vault.List(ctx, r.cfg.Mount, r.cfg.SecretPath+"/keys")
	if err != nil {
		return fmt.Errorf("rotator: list keys for pruning: %w", err)
	}
	var lastErr error
	for _, kid := range kids {
		path := r.cfg.SecretPath + "/keys/" + kid
		data, err := r.vault.Get(ctx, r.cfg.Mount, path)
		if err != nil {
			continue
		}
		rec := parseRecord(data)
		if rec.ExpiresAt == "" {
			continue
		}
		expiresAt, err := time.Parse(time.RFC3339, rec.ExpiresAt)
		if err != nil || now.Before(expiresAt) {
			continue
		}
		if err := r.vault.Delete(ctx, r.cfg.Mount, path); err != nil {
			r.logger.Warn("failed to delete expired key", "kid", kid, "error", err)
			lastErr = err
			continue
		}
		keysExpiredTotal.Inc()
		r.logger.Info("expired key removed",
			"event.action", "key.expired",
			"event.category", "authentication",
			"kid", kid,
			"expired_at", expiresAt.UTC(),
		)
	}
	return lastErr
}

// pemEncodeFn is the PEM encoding hook for tests.
var pemEncodeFn = EncodePrivateKeyPEM
