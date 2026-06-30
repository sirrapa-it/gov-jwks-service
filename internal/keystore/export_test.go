// export_test.go — compiled only when running tests.
// Exposes unexported package variables for test injection and assertion.
package keystore

import (
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/sirrapa-it/gov-jwks-service/internal/vault"
)

// RsaKeyGenForTest is a pointer to the rsaKeyGen hook.
// Tests can replace the function to inject failures.
var RsaKeyGenForTest = &rsaKeyGen

// DeriveKIDForTest exposes deriveKID so tests can assert the RFC 7638
// thumbprint is computed correctly.
var DeriveKIDForTest = deriveKID

// PemEncodeFnForTest is a pointer to the pemEncodeFn hook.
var PemEncodeFnForTest = &pemEncodeFn

// Prometheus metric exports for testutil assertions.
var (
	ActiveKeysGaugeForTest        prometheus.Gauge   = activeKeysGauge
	ActiveKeyAgeSecondsForTest    prometheus.Gauge   = activeKeyAgeSeconds
	LastSyncTimestampForTest      prometheus.Gauge   = lastSyncTimestamp
	SyncErrorsTotalForTest        prometheus.Counter = syncErrorsTotal
	KeyRotationsTotalForTest      prometheus.Counter = keyRotationsTotal
	LastRotationTimestampForTest  prometheus.Gauge   = lastRotationTimestamp
	KeysExpiredTotalForTest       prometheus.Counter = keysExpiredTotal
	KeyRotationErrorsTotalForTest prometheus.Counter = keyRotationErrorsTotal
)

// SetVaultForTest replaces the VaultKeyStore's vault backend.
// Used to inject error-producing stores in tests.
func SetVaultForTest(s *VaultKeyStore, v vault.SecretStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vault = v
}

// ExpireAllKeysForTest marks all keys in the store as expiring (ExpiresAt = now+1h).
// After calling this, ActiveKey() returns an error.
func ExpireAllKeysForTest(s *VaultKeyStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.keys {
		k.ExpiresAt = time.Now().Add(time.Hour)
	}
}

// failingKeyGen is a key generation function that always returns an error.
// Assign to *RsaKeyGenForTest to inject failures.
func failingKeyGen(_ int) (*rsa.PrivateKey, error) {
	return nil, fmt.Errorf("injected RSA generation failure")
}

// Ensure failingKeyGen is referenced to avoid unused-declaration errors.
var _ = failingKeyGen
