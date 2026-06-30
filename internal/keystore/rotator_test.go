package keystore_test

import (
	"context"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/sirrapa-it/gov-jwks-service/internal/keystore"
	"github.com/sirrapa-it/gov-jwks-service/internal/vault"
)

func newRotator(t *testing.T, mem *memStoreKS, secretPath string) *keystore.Rotator {
	t.Helper()
	return keystore.NewRotator(mem, keystore.RotatorConfig{
		KeyBits: 1024, GracePeriod: 2 * time.Hour,
		Mount: "secret", SecretPath: secretPath,
	})
}

// ---- NewRotator -------------------------------------------------------------

func TestNewRotator_NilLogger_UsesDefault(t *testing.T) {
	r := keystore.NewRotator(newMemStoreKS(), keystore.RotatorConfig{
		KeyBits: 1024, GracePeriod: time.Hour,
		Mount: "secret", SecretPath: "nil-log",
	})
	if r == nil {
		t.Fatal("expected non-nil Rotator")
	}
}

// ---- Rotate — happy path ---------------------------------------------------

func TestRotator_Rotate_CreatesKeyInVault(t *testing.T) {
	mem := newMemStoreKS()
	r := newRotator(t, mem, "rot-create")
	if err := r.Rotate(testCtx(t)); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	kids, _ := mem.List(testCtx(t), "secret", "rot-create/keys")
	if len(kids) == 0 {
		t.Fatal("expected key to be persisted in Vault")
	}
}

func TestRotator_Rotate_SetsActivePointer(t *testing.T) {
	mem := newMemStoreKS()
	r := newRotator(t, mem, "rot-active")
	r.Rotate(testCtx(t))

	active, err := mem.Get(testCtx(t), "secret", "rot-active/active")
	if err != nil {
		t.Fatalf("active pointer not found: %v", err)
	}
	if active["kid"] == "" {
		t.Error("active pointer must have a non-empty kid")
	}
}

func TestRotator_Rotate_MarksOldKeyExpiring(t *testing.T) {
	mem := newMemStoreKS()
	r := newRotator(t, mem, "rot-mark")

	r.Rotate(testCtx(t)) // creates first key
	kids1, _ := mem.List(testCtx(t), "secret", "rot-mark/keys")
	firstKid := kids1[0]

	r.Rotate(testCtx(t)) // second rotation marks first key expiring

	data, _ := mem.Get(testCtx(t), "secret", "rot-mark/keys/"+firstKid)
	if data["expires_at"] == "" {
		t.Error("first key should have expires_at set after second rotation")
	}
}

func TestRotator_Rotate_PrunesExpiredKey(t *testing.T) {
	mem := newMemStoreKS()
	r := keystore.NewRotator(mem, keystore.RotatorConfig{
		KeyBits: 1024, GracePeriod: 0, // zero grace — expires immediately
		Mount: "secret", SecretPath: "rot-prune",
	})

	r.Rotate(testCtx(t)) // creates key A
	firstKids, _ := mem.List(testCtx(t), "secret", "rot-prune/keys")
	firstKid := firstKids[0]

	// Small sleep so the timestamp is definitely in the past.
	time.Sleep(time.Millisecond)

	r.Rotate(testCtx(t)) // should prune key A and create key B

	_, err := mem.Get(testCtx(t), "secret", "rot-prune/keys/"+firstKid)
	if err != vault.ErrNotFound {
		t.Errorf("expected first key to be deleted after pruning, got err=%v", err)
	}
}

func TestRotator_Rotate_SkipsAlreadyExpiringKeys(t *testing.T) {
	mem := newMemStoreKS()
	r := newRotator(t, mem, "rot-skip-exp")

	r.Rotate(testCtx(t))
	r.Rotate(testCtx(t)) // marks first key expiring

	kids, _ := mem.List(testCtx(t), "secret", "rot-skip-exp/keys")
	var expiringCount int
	for _, kid := range kids {
		d, _ := mem.Get(testCtx(t), "secret", "rot-skip-exp/keys/"+kid)
		if d["expires_at"] != "" {
			expiringCount++
		}
	}
	if expiringCount != 1 {
		t.Errorf("expected exactly 1 expiring key, got %d", expiringCount)
	}
}

func TestRotator_Rotate_MultipleRotations_UniqueKids(t *testing.T) {
	mem := newMemStoreKS()
	r := newRotator(t, mem, "rot-unique")
	seen := map[string]bool{}

	for i := 0; i < 3; i++ {
		r.Rotate(testCtx(t))
		active, _ := mem.Get(testCtx(t), "secret", "rot-unique/active")
		kid := active["kid"].(string)
		if seen[kid] {
			t.Errorf("duplicate kid %q on rotation %d", kid, i)
		}
		seen[kid] = true
	}
}

// ---- Rotate — error paths --------------------------------------------------

func TestRotator_Rotate_KeyGenFailure(t *testing.T) {
	orig := *keystore.RsaKeyGenForTest
	*keystore.RsaKeyGenForTest = func(_ int) (*rsa.PrivateKey, error) {
		return nil, errInjected("keygen fail")
	}
	t.Cleanup(func() { *keystore.RsaKeyGenForTest = orig })

	r := newRotator(t, newMemStoreKS(), "rot-keygen-err")
	if err := r.Rotate(testCtx(t)); err == nil {
		t.Fatal("expected error when key generation fails")
	}
}

func TestRotator_Rotate_WriteKeyFailure(t *testing.T) {
	mem := newMemStoreKS()
	r := keystore.NewRotator(
		&countingPutStore{delegate: mem, failAfter: 0},
		keystore.RotatorConfig{
			KeyBits: 1024, GracePeriod: time.Hour, Mount: "secret", SecretPath: "rot-write-err",
		},
	)
	if err := r.Rotate(testCtx(t)); err == nil {
		t.Fatal("expected error when writeKey fails")
	}
}

func TestRotator_Rotate_ListFailure_InMarkExpiring(t *testing.T) {
	mem := newMemStoreKS()
	// First Put (writeKey) succeeds, then List fails in markExistingExpiring.
	r := keystore.NewRotator(
		&listErrAfterNStore{delegate: mem, failAfter: 0},
		keystore.RotatorConfig{
			KeyBits: 1024, GracePeriod: time.Hour, Mount: "secret", SecretPath: "rot-list-err",
		},
	)
	if err := r.Rotate(testCtx(t)); err == nil {
		t.Fatal("expected error when List fails in markExistingExpiring")
	}
}

func TestRotator_Rotate_MarkExpiringPutFailure_ReturnsError(t *testing.T) {
	mem := newMemStoreKS()
	// First rotation creates a key.
	keystore.NewRotator(mem, keystore.RotatorConfig{
		KeyBits: 1024, GracePeriod: time.Hour, Mount: "secret", SecretPath: "rot-mark-err",
	}).Rotate(testCtx(t))

	// Second rotation: writeKey (Put #1) succeeds, markExistingExpiring Put fails.
	r := keystore.NewRotator(
		&countingPutStore{delegate: mem, failAfter: 1},
		keystore.RotatorConfig{
			KeyBits: 1024, GracePeriod: time.Hour, Mount: "secret", SecretPath: "rot-mark-err",
		},
	)
	if err := r.Rotate(testCtx(t)); err == nil {
		t.Fatal("expected error when marking existing key expiring fails")
	}
}

func TestRotator_Rotate_ActivePointerPutFailure(t *testing.T) {
	mem := newMemStoreKS()
	// First rotation so markExistingExpiring has nothing to mark.
	// On second rotation: writeKey succeeds, markExpiring has nothing,
	// then updating /active fails.
	// failAfter=1: writeKey=1 Put success, then /active Put fails.
	r := keystore.NewRotator(
		&countingPutStore{delegate: mem, failAfter: 1},
		keystore.RotatorConfig{
			KeyBits: 1024, GracePeriod: time.Hour, Mount: "secret", SecretPath: "rot-active-err",
		},
	)
	if err := r.Rotate(testCtx(t)); err == nil {
		t.Fatal("expected error when updating active pointer fails")
	}
}

func TestRotator_Rotate_PEMEncodeFailure(t *testing.T) {
	orig := *keystore.PemEncodeFnForTest
	*keystore.PemEncodeFnForTest = func(_ *rsa.PrivateKey) ([]byte, error) {
		return nil, errInjected("pem encode fail")
	}
	t.Cleanup(func() { *keystore.PemEncodeFnForTest = orig })

	r := newRotator(t, newMemStoreKS(), "rot-pem-err")
	if err := r.Rotate(testCtx(t)); err == nil {
		t.Fatal("expected error when PEM encoding fails")
	}
}

func TestRotator_Rotate_DeleteFailure_IsNonFatal(t *testing.T) {
	mem := newMemStoreKS()
	r := keystore.NewRotator(mem, keystore.RotatorConfig{
		KeyBits: 1024, GracePeriod: 0, Mount: "secret", SecretPath: "rot-del-err",
	})
	r.Rotate(testCtx(t))
	time.Sleep(time.Millisecond)

	// Second rotation with a store that fails on Delete.
	r2 := keystore.NewRotator(&deleteErrStore{mem: mem}, keystore.RotatorConfig{
		KeyBits: 1024, GracePeriod: 0, Mount: "secret", SecretPath: "rot-del-err",
	})
	// Rotate must not return an error for delete failures (non-fatal).
	if err := r2.Rotate(testCtx(t)); err != nil {
		t.Errorf("Rotate should not fail on delete error, got: %v", err)
	}
}

func TestRotator_Rotate_GetErrorDuringMark_Skips(t *testing.T) {
	mem := newMemStoreKS()
	// First rotation creates a key.
	keystore.NewRotator(mem, keystore.RotatorConfig{
		KeyBits: 1024, GracePeriod: time.Hour, Mount: "secret", SecretPath: "rot-get-err",
	}).Rotate(testCtx(t))

	// Second rotation with Get always failing — markExistingExpiring skips the key.
	r2 := keystore.NewRotator(&errGetStore{delegate: mem}, keystore.RotatorConfig{
		KeyBits: 1024, GracePeriod: time.Hour, Mount: "secret", SecretPath: "rot-get-err",
	})
	// Should still succeed (Get error in mark is a warning, not fatal).
	if err := r2.Rotate(testCtx(t)); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---- helper types -----------------------------------------------------------

type errInjected string

func (e errInjected) Error() string { return string(e) }

// errGetStore fails on Get but delegates everything else.
type errGetStore struct{ delegate vault.SecretStore }

func (s *errGetStore) Put(ctx context.Context, m, p string, d map[string]any) error {
	return s.delegate.Put(ctx, m, p, d)
}
func (s *errGetStore) Get(_ context.Context, _, _ string) (map[string]any, error) {
	return nil, errInjected("injected get error")
}
func (s *errGetStore) List(ctx context.Context, m, p string) ([]string, error) {
	return s.delegate.List(ctx, m, p)
}
func (s *errGetStore) Delete(ctx context.Context, m, p string) error {
	return s.delegate.Delete(ctx, m, p)
}
