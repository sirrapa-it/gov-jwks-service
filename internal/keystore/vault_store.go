package keystore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/sirrapa/jwks-service/internal/vault"
)

// vaultKeyRecord is the data structure stored in Vault for each signing key.
type vaultKeyRecord struct {
	PEM       string
	Kid       string
	CreatedAt string
	ExpiresAt string
}

// VaultKeyStoreConfig holds the parameters for NewVaultKeyStore.
type VaultKeyStoreConfig struct {
	Vault      vault.SecretStore
	Mount      string
	SecretPath string
	Logger     *slog.Logger
}

// VaultKeyStore is a read-only Store backed by HashiCorp Vault KV v1.
// It loads signing keys on startup and refreshes them via StartSync.
// The server binary uses this type; it never writes to Vault.
// VaultKeyStore is safe for concurrent use.
type VaultKeyStore struct {
	mu         sync.RWMutex
	keys       []*ManagedKey
	vault      vault.SecretStore
	mount      string
	secretPath string
	logger     *slog.Logger
}

// NewVaultKeyStore creates a VaultKeyStore and performs an initial load from
// Vault. Returns an error when no valid keys are found — run the rotator first.
func NewVaultKeyStore(ctx context.Context, cfg VaultKeyStoreConfig) (*VaultKeyStore, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	s := &VaultKeyStore{
		vault:      cfg.Vault,
		mount:      cfg.Mount,
		secretPath: cfg.SecretPath,
		logger:     logger,
	}
	if err := s.sync(ctx); err != nil {
		return nil, fmt.Errorf("vault keystore: initial sync: %w", err)
	}
	if len(s.keys) == 0 {
		return nil, fmt.Errorf("vault keystore: no valid signing keys found — run the rotator first")
	}
	logger.Info("keystore initialised",
		"event.action", "keystore.initialised",
		"event.category", "authentication",
		"key_count", len(s.keys),
	)
	activeKeysGauge.Set(float64(len(s.keys)))
	return s, nil
}

// ActiveKey returns the current signing key (ExpiresAt.IsZero()).
func (s *VaultKeyStore) ActiveKey() (*ManagedKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	for i := len(s.keys) - 1; i >= 0; i-- {
		k := s.keys[i]
		if k.IsValid(now) && k.ExpiresAt.IsZero() {
			return k, nil
		}
	}
	return nil, fmt.Errorf("vault keystore: no active signing key available")
}

// PublicKeySet returns all currently valid public keys for the JWKS response.
func (s *VaultKeyStore) PublicKeySet() JWKSet {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	set := JWKSet{Keys: make([]JWK, 0, len(s.keys))}
	for _, k := range s.keys {
		if k.IsValid(now) {
			set.Keys = append(set.Keys, toJWK(k))
		}
	}
	return set
}

// StartSync starts a background goroutine that refreshes the in-memory key
// cache from Vault on every tick of interval.
func (s *VaultKeyStore) StartSync(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := s.sync(ctx); err != nil {
					s.logger.Error("vault sync failed",
						"event.action", "keystore.sync_failed",
						"event.category", "authentication",
						"error", err,
					)
					syncErrorsTotal.Inc()
					continue
				}
				lastSyncTimestamp.SetToCurrentTime()
				s.mu.RLock()
				count := len(s.keys)
				s.mu.RUnlock()
				activeKeysGauge.Set(float64(count))
				s.logger.Debug("vault sync complete",
					"event.action", "keystore.synced",
					"event.category", "authentication",
					"key_count", count,
				)
			}
		}
	}()
}

// KeyCount returns the number of keys in the in-memory cache.
func (s *VaultKeyStore) KeyCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.keys)
}

// sync fetches all valid signing keys from Vault and atomically replaces the
// in-memory cache.
func (s *VaultKeyStore) sync(ctx context.Context) error {
	keysPath := s.secretPath + "/keys"
	kids, err := s.vault.List(ctx, s.mount, keysPath)
	if err != nil {
		if errors.Is(err, vault.ErrNotFound) {
			s.mu.Lock()
			s.keys = nil
			s.mu.Unlock()
			return nil
		}
		return fmt.Errorf("list keys at %s: %w", keysPath, err)
	}

	now := time.Now()
	loaded := make([]*ManagedKey, 0, len(kids))
	for _, kid := range kids {
		mk, err := s.loadKey(ctx, kid, now)
		if err != nil {
			s.logger.Warn("skipping unloadable key", "kid", kid, "error", err)
			continue
		}
		if mk == nil {
			continue
		}
		s.logger.Info("key loaded",
			"event.action", "key.loaded",
			"event.category", "authentication",
			"kid", mk.Kid,
			"created_at", mk.CreatedAt.UTC(),
			"expires_at", mk.ExpiresAt.UTC(),
		)
		loaded = append(loaded, mk)
	}

	s.mu.Lock()
	s.keys = loaded
	s.mu.Unlock()
	return nil
}

func (s *VaultKeyStore) loadKey(ctx context.Context, kid string, now time.Time) (*ManagedKey, error) {
	path := s.secretPath + "/keys/" + kid
	data, err := s.vault.Get(ctx, s.mount, path)
	if err != nil {
		return nil, fmt.Errorf("get %s: %w", path, err)
	}
	rec := parseRecord(data)
	if rec.PEM == "" {
		return nil, fmt.Errorf("key record %s has empty PEM", kid)
	}
	priv, err := DecodePrivateKeyPEM([]byte(rec.PEM))
	if err != nil {
		return nil, fmt.Errorf("decode PEM for %s: %w", kid, err)
	}
	mk := &ManagedKey{Kid: rec.Kid, Private: priv}
	if t, err := time.Parse(time.RFC3339, rec.CreatedAt); err == nil {
		mk.CreatedAt = t
	}
	if rec.ExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339, rec.ExpiresAt); err == nil {
			mk.ExpiresAt = t
		}
	}
	if !mk.IsValid(now) {
		return nil, nil
	}
	return mk, nil
}

func parseRecord(data map[string]any) vaultKeyRecord {
	rec := vaultKeyRecord{}
	if v, ok := data["pem"].(string); ok {
		rec.PEM = v
	}
	if v, ok := data["kid"].(string); ok {
		rec.Kid = v
	}
	if v, ok := data["created_at"].(string); ok {
		rec.CreatedAt = v
	}
	if v, ok := data["expires_at"].(string); ok {
		rec.ExpiresAt = v
	}
	return rec
}
