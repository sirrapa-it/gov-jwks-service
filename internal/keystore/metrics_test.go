package keystore_test

import (
	"context"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/sirrapa/jwks-service/internal/keystore"
)

func TestUpdateActiveKeyAge_SetsPositiveValue(t *testing.T) {
	keystore.UpdateActiveKeyAge(time.Now().Add(-30 * time.Minute))
	v := testutil.ToFloat64(keystore.ActiveKeyAgeSecondsForTest)
	if v <= 0 {
		t.Errorf("activeKeyAgeSeconds = %f, want > 0", v)
	}
}

func TestUpdateActiveKeyAge_RecentKey_LowValue(t *testing.T) {
	keystore.UpdateActiveKeyAge(time.Now().Add(-5 * time.Second))
	v := testutil.ToFloat64(keystore.ActiveKeyAgeSecondsForTest)
	if v > 60 {
		t.Errorf("expected < 60s for recent key, got %f", v)
	}
}

func TestUpdateActiveKeyAge_OldKey_HighValue(t *testing.T) {
	keystore.UpdateActiveKeyAge(time.Now().Add(-24 * time.Hour))
	v := testutil.ToFloat64(keystore.ActiveKeyAgeSecondsForTest)
	if v < 3600 {
		t.Errorf("expected > 3600s for 24h-old key, got %f", v)
	}
}

func TestKeyRotationsTotal_Increments(t *testing.T) {
	mem := newMemStoreKS()
	r := keystore.NewRotator(mem, keystore.RotatorConfig{
		KeyBits: 1024, GracePeriod: time.Hour, Mount: "secret", SecretPath: "met-rot",
	})
	before := testutil.ToFloat64(keystore.KeyRotationsTotalForTest)
	r.Rotate(testCtx(t))
	after := testutil.ToFloat64(keystore.KeyRotationsTotalForTest)
	if after <= before {
		t.Errorf("keyRotationsTotal: before=%f after=%f — expected increment", before, after)
	}
}

func TestLastRotationTimestamp_Updates(t *testing.T) {
	mem := newMemStoreKS()
	r := keystore.NewRotator(mem, keystore.RotatorConfig{
		KeyBits: 1024, GracePeriod: time.Hour, Mount: "secret", SecretPath: "met-ts",
	})
	before := testutil.ToFloat64(keystore.LastRotationTimestampForTest)
	time.Sleep(10 * time.Millisecond)
	r.Rotate(testCtx(t))
	after := testutil.ToFloat64(keystore.LastRotationTimestampForTest)
	if after <= before {
		t.Errorf("lastRotationTimestamp: before=%f after=%f — expected update", before, after)
	}
}

func TestKeysExpiredTotal_Increments(t *testing.T) {
	mem := newMemStoreKS()
	r := keystore.NewRotator(mem, keystore.RotatorConfig{
		KeyBits: 1024, GracePeriod: 0, Mount: "secret", SecretPath: "met-exp",
	})
	r.Rotate(testCtx(t))
	time.Sleep(time.Millisecond)
	before := testutil.ToFloat64(keystore.KeysExpiredTotalForTest)
	r.Rotate(testCtx(t)) // prunes the first key
	after := testutil.ToFloat64(keystore.KeysExpiredTotalForTest)
	if after <= before {
		t.Errorf("keysExpiredTotal: before=%f after=%f — expected increment", before, after)
	}
}

func TestKeyRotationErrorsTotal_Increments_OnKeyGenFailure(t *testing.T) {
	orig := *keystore.RsaKeyGenForTest
	*keystore.RsaKeyGenForTest = func(_ int) (*rsa.PrivateKey, error) {
		return nil, errInjected("fail")
	}
	t.Cleanup(func() { *keystore.RsaKeyGenForTest = orig })

	r := keystore.NewRotator(newMemStoreKS(), keystore.RotatorConfig{
		KeyBits: 1024, GracePeriod: time.Hour, Mount: "secret", SecretPath: "met-err",
	})
	before := testutil.ToFloat64(keystore.KeyRotationErrorsTotalForTest)
	r.Rotate(testCtx(t))
	after := testutil.ToFloat64(keystore.KeyRotationErrorsTotalForTest)
	if after <= before {
		t.Errorf("keyRotationErrorsTotal: before=%f after=%f — expected increment", before, after)
	}
}

func TestSyncErrorsTotal_Increments_OnSyncFailure(t *testing.T) {
	s, _ := newPopulatedStore(t, "met-sync-err")
	keystore.SetVaultForTest(s, &errStore{msg: "sync fail"})

	before := testutil.ToFloat64(keystore.SyncErrorsTotalForTest)

	ctx, cancel := newCancelCtx(t)
	s.StartSync(ctx, 10*time.Millisecond)
	time.Sleep(60 * time.Millisecond)
	cancel()

	after := testutil.ToFloat64(keystore.SyncErrorsTotalForTest)
	if after <= before {
		t.Errorf("syncErrorsTotal: before=%f after=%f — expected increment", before, after)
	}
}

func TestActiveKeysGauge_SetAfterSync(t *testing.T) {
	mem := newMemStoreKS()
	r := keystore.NewRotator(mem, keystore.RotatorConfig{
		KeyBits: 1024, GracePeriod: time.Hour, Mount: "secret", SecretPath: "met-gauge",
	})
	r.Rotate(testCtx(t))

	_, _ = keystore.NewVaultKeyStore(testCtx(t), keystore.VaultKeyStoreConfig{
		Vault: mem, Mount: "secret", SecretPath: "met-gauge",
	})

	v := testutil.ToFloat64(keystore.ActiveKeysGaugeForTest)
	if v < 1 {
		t.Errorf("activeKeysGauge = %f, want >= 1", v)
	}
}

func TestLastSyncTimestamp_UpdatesAfterSuccessfulSync(t *testing.T) {
	s, _ := newPopulatedStore(t, "met-last-sync")
	before := testutil.ToFloat64(keystore.LastSyncTimestampForTest)
	time.Sleep(10 * time.Millisecond)

	ctx, cancel := newCancelCtx(t)
	s.StartSync(ctx, 20*time.Millisecond)
	time.Sleep(80 * time.Millisecond)
	cancel()

	after := testutil.ToFloat64(keystore.LastSyncTimestampForTest)
	if after <= before {
		t.Errorf("lastSyncTimestamp: before=%f after=%f — expected update", before, after)
	}
}

// newCancelCtx returns a context and cancel func, cancelling on test cleanup.
func newCancelCtx(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return ctx, cancel
}
