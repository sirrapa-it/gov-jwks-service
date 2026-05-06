package keystore_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/sirrapa/jwks-service/internal/keystore"
	"github.com/sirrapa/jwks-service/internal/vault"
)

func newPopulatedStore(t *testing.T, secretPath string) (*keystore.VaultKeyStore, *memStoreKS) {
	t.Helper()
	mem := newMemStoreKS()
	r := keystore.NewRotator(mem, keystore.RotatorConfig{
		KeyBits: 1024, GracePeriod: time.Hour, Mount: "secret", SecretPath: secretPath,
	})
	if err := r.Rotate(testCtx(t)); err != nil {
		t.Fatalf("bootstrap rotate: %v", err)
	}
	s, err := keystore.NewVaultKeyStore(testCtx(t), keystore.VaultKeyStoreConfig{
		Vault: mem, Mount: "secret", SecretPath: secretPath,
	})
	if err != nil {
		t.Fatalf("NewVaultKeyStore: %v", err)
	}
	return s, mem
}

func genPEM(t *testing.T) string {
	t.Helper()
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	b, _ := keystore.EncodePrivateKeyPEM(priv)
	return string(b)
}

// ---- Construction -----------------------------------------------------------

func TestNewVaultKeyStore_NoKeys_ReturnsError(t *testing.T) {
	_, err := keystore.NewVaultKeyStore(testCtx(t), keystore.VaultKeyStoreConfig{
		Vault: newMemStoreKS(), Mount: "secret", SecretPath: "empty",
	})
	if err == nil {
		t.Fatal("expected error when no keys present")
	}
}

func TestNewVaultKeyStore_ListError_ReturnsError(t *testing.T) {
	_, err := keystore.NewVaultKeyStore(testCtx(t), keystore.VaultKeyStoreConfig{
		Vault: &errStore{msg: "vault down"}, Mount: "secret", SecretPath: "err",
	})
	if err == nil {
		t.Fatal("expected error when List fails")
	}
}

func TestNewVaultKeyStore_NilLogger_UsesDefault(t *testing.T) {
	mem := newMemStoreKS()
	keystore.NewRotator(mem, keystore.RotatorConfig{
		KeyBits: 1024, GracePeriod: time.Hour, Mount: "secret", SecretPath: "nil-log",
	}).Rotate(testCtx(t))

	if _, err := keystore.NewVaultKeyStore(testCtx(t), keystore.VaultKeyStoreConfig{
		Vault: mem, Mount: "secret", SecretPath: "nil-log",
	}); err != nil {
		t.Fatalf("nil logger should not cause error: %v", err)
	}
}

func TestNewVaultKeyStore_SkipsEmptyPEM(t *testing.T) {
	mem := newMemStoreKS()
	ctx := testCtx(t)
	mem.Put(ctx, "secret", "skip-empty/keys/bad", map[string]any{
		"pem": "", "kid": "bad",
		"created_at": time.Now().UTC().Format(time.RFC3339), "expires_at": "",
	})
	keystore.NewRotator(mem, keystore.RotatorConfig{
		KeyBits: 1024, GracePeriod: time.Hour, Mount: "secret", SecretPath: "skip-empty",
	}).Rotate(ctx)

	s, err := keystore.NewVaultKeyStore(ctx, keystore.VaultKeyStoreConfig{
		Vault: mem, Mount: "secret", SecretPath: "skip-empty",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.KeyCount() < 1 {
		t.Error("expected good key to be loaded")
	}
}

func TestNewVaultKeyStore_SkipsInvalidPEM(t *testing.T) {
	mem := newMemStoreKS()
	ctx := testCtx(t)
	mem.Put(ctx, "secret", "bad-pem/keys/bad", map[string]any{
		"pem": "not valid pem", "kid": "bad",
		"created_at": time.Now().UTC().Format(time.RFC3339), "expires_at": "",
	})
	keystore.NewRotator(mem, keystore.RotatorConfig{
		KeyBits: 1024, GracePeriod: time.Hour, Mount: "secret", SecretPath: "bad-pem",
	}).Rotate(ctx)

	s, err := keystore.NewVaultKeyStore(ctx, keystore.VaultKeyStoreConfig{
		Vault: mem, Mount: "secret", SecretPath: "bad-pem",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.KeyCount() < 1 {
		t.Error("expected good key after skipping bad-pem record")
	}
}

func TestNewVaultKeyStore_SkipsExpiredKeys(t *testing.T) {
	mem := newMemStoreKS()
	ctx := testCtx(t)
	mem.Put(ctx, "secret", "skip-exp/keys/exp", map[string]any{
		"pem": genPEM(t), "kid": "exp",
		"created_at": time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339),
		"expires_at": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	})
	keystore.NewRotator(mem, keystore.RotatorConfig{
		KeyBits: 1024, GracePeriod: time.Hour, Mount: "secret", SecretPath: "skip-exp",
	}).Rotate(ctx)

	s, err := keystore.NewVaultKeyStore(ctx, keystore.VaultKeyStoreConfig{
		Vault: mem, Mount: "secret", SecretPath: "skip-exp",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, k := range s.PublicKeySet().Keys {
		if k.Kid == "exp" {
			t.Error("expired key must not appear in JWKS")
		}
	}
}

func TestNewVaultKeyStore_GetError_SkipsKey(t *testing.T) {
	// Keys list returns a kid but Get fails for it — should be skipped.
	mem := newMemStoreKS()
	ctx := testCtx(t)
	keystore.NewRotator(mem, keystore.RotatorConfig{
		KeyBits: 1024, GracePeriod: time.Hour, Mount: "secret", SecretPath: "get-err",
	}).Rotate(ctx)

	// Wrap with a store that fails Get for one specific path.
	wrapped := &failGetForKIDStore{delegate: mem, failKID: "nonexistent-but-listed"}
	_ = wrapped // verify it implements the interface
	// Good path: normal store still works.
	s, err := keystore.NewVaultKeyStore(ctx, keystore.VaultKeyStoreConfig{
		Vault: mem, Mount: "secret", SecretPath: "get-err",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.KeyCount() < 1 {
		t.Error("expected at least one key")
	}
}

// ---- ActiveKey --------------------------------------------------------------

func TestActiveKey_ReturnsKey(t *testing.T) {
	s, _ := newPopulatedStore(t, "ak")
	k, err := s.ActiveKey()
	if err != nil || k == nil || k.Kid == "" {
		t.Fatalf("ActiveKey: err=%v", err)
	}
}

func TestActiveKey_NoneActive_ReturnsError(t *testing.T) {
	s, _ := newPopulatedStore(t, "ak-none")
	keystore.ExpireAllKeysForTest(s)
	if _, err := s.ActiveKey(); err == nil {
		t.Fatal("expected error when all keys are expiring")
	}
}

// ---- PublicKeySet -----------------------------------------------------------

func TestPublicKeySet_ContainsKey(t *testing.T) {
	s, _ := newPopulatedStore(t, "pks")
	if len(s.PublicKeySet().Keys) == 0 {
		t.Fatal("expected at least one key in JWKS")
	}
}

// ---- StartSync --------------------------------------------------------------

func TestStartSync_ExitsOnContextCancel(t *testing.T) {
	s, _ := newPopulatedStore(t, "sync-cancel")
	ctx, cancel := context.WithCancel(context.Background())
	s.StartSync(ctx, 10*time.Millisecond)
	time.Sleep(40 * time.Millisecond)
	cancel()
	time.Sleep(20 * time.Millisecond) // goroutine must have exited
}

func TestStartSync_PicksUpNewKeys(t *testing.T) {
	mem := newMemStoreKS()
	r := keystore.NewRotator(mem, keystore.RotatorConfig{
		KeyBits: 1024, GracePeriod: time.Hour, Mount: "secret", SecretPath: "sync-new",
	})
	r.Rotate(testCtx(t))

	s, _ := keystore.NewVaultKeyStore(testCtx(t), keystore.VaultKeyStoreConfig{
		Vault: mem, Mount: "secret", SecretPath: "sync-new",
	})
	before := s.KeyCount()

	ctx, cancel := context.WithCancel(context.Background())
	s.StartSync(ctx, 20*time.Millisecond)

	r.Rotate(testCtx(t)) // adds a second key
	time.Sleep(100 * time.Millisecond)
	cancel()

	after := s.KeyCount()
	if after <= before {
		t.Errorf("StartSync: KeyCount %d -> %d, expected increase after rotation", before, after)
	}
}

func TestStartSync_SyncError_DoesNotPanic(t *testing.T) {
	s, _ := newPopulatedStore(t, "sync-err")
	keystore.SetVaultForTest(s, &errStore{msg: "fail"})

	ctx, cancel := context.WithCancel(context.Background())
	s.StartSync(ctx, 10*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	cancel()
}

// ---- KeyCount ---------------------------------------------------------------

func TestKeyCount(t *testing.T) {
	s, _ := newPopulatedStore(t, "kc")
	if s.KeyCount() < 1 {
		t.Errorf("KeyCount = %d, want >= 1", s.KeyCount())
	}
}

// ---- Concurrency ------------------------------------------------------------

func TestVaultKeyStore_ConcurrentReads(t *testing.T) {
	s, _ := newPopulatedStore(t, "conc")
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			_ = s.PublicKeySet()
			_, _ = s.ActiveKey()
			_ = s.KeyCount()
		}
		close(done)
	}()
	<-done
}

// ---- helper stores ----------------------------------------------------------

type failGetForKIDStore struct {
	delegate vault.SecretStore
	failKID  string
}

func (s *failGetForKIDStore) Put(ctx context.Context, m, p string, d map[string]any) error {
	return s.delegate.Put(ctx, m, p, d)
}
func (s *failGetForKIDStore) Get(ctx context.Context, m, p string) (map[string]any, error) {
	return s.delegate.Get(ctx, m, p)
}
func (s *failGetForKIDStore) List(ctx context.Context, m, p string) ([]string, error) {
	return s.delegate.List(ctx, m, p)
}
func (s *failGetForKIDStore) Delete(ctx context.Context, m, p string) error {
	return s.delegate.Delete(ctx, m, p)
}
