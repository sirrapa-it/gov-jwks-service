package keystore_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/sirrapa-it/gov-jwks-service/internal/keystore"
)

// newTestKey generates a small RSA key for testing.
func newTestKey(t *testing.T) *keystore.ManagedKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &keystore.ManagedKey{
		Kid:       "test-kid",
		Private:   priv,
		CreatedAt: time.Now(),
	}
}

// ---- deriveKID (RFC 7638 thumbprint) ----------------------------------------

// TestDeriveKID_RFC7638Example pins deriveKID to the worked example from
// RFC 7638 Section 3.1. Because the kid is the standard JWK thumbprint, any
// RFC 7638-compliant signer or verifier derives the same kid for this key.
func TestDeriveKID_RFC7638Example(t *testing.T) {
	// RSA public key from RFC 7638 §3.1.
	const (
		nB64    = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
		eB64    = "AQAB"
		wantKID = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	)

	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		t.Fatalf("decode n: %v", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		t.Fatalf("decode e: %v", err)
	}
	pub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}

	if got := keystore.DeriveKIDForTest(pub); got != wantKID {
		t.Errorf("deriveKID = %q, want RFC 7638 thumbprint %q", got, wantKID)
	}
}

// TestDeriveKID_StableAndUnique verifies the kid is deterministic per key and
// differs between keys.
func TestDeriveKID_StableAndUnique(t *testing.T) {
	k1 := newTestKey(t)
	k2 := newTestKey(t)

	kid1 := keystore.DeriveKIDForTest(&k1.Private.PublicKey)
	if kid1 != keystore.DeriveKIDForTest(&k1.Private.PublicKey) {
		t.Error("deriveKID is not stable for the same key")
	}
	if kid1 == keystore.DeriveKIDForTest(&k2.Private.PublicKey) {
		t.Error("deriveKID collided for two distinct keys")
	}
}

// ---- ManagedKey.IsValid -----------------------------------------------------

func TestManagedKey_IsValid_ZeroExpiry(t *testing.T) {
	k := &keystore.ManagedKey{ExpiresAt: time.Time{}}
	if !k.IsValid(time.Now()) {
		t.Error("key with zero expiry should always be valid")
	}
}

func TestManagedKey_IsValid_FutureExpiry(t *testing.T) {
	k := &keystore.ManagedKey{ExpiresAt: time.Now().Add(time.Hour)}
	if !k.IsValid(time.Now()) {
		t.Error("key with future expiry should be valid")
	}
}

func TestManagedKey_IsValid_PastExpiry(t *testing.T) {
	k := &keystore.ManagedKey{ExpiresAt: time.Now().Add(-time.Second)}
	if k.IsValid(time.Now()) {
		t.Error("key with past expiry should not be valid")
	}
}

func TestManagedKey_IsValid_ExactlyAtExpiry(t *testing.T) {
	now := time.Now()
	k := &keystore.ManagedKey{ExpiresAt: now}
	// time.Before is strictly less than, so exactly at expiry is NOT valid.
	if k.IsValid(now) {
		t.Error("key at exact expiry time should not be valid")
	}
}

// ---- SignRS256 --------------------------------------------------------------

func TestSignRS256_ProducesNonEmptySignature(t *testing.T) {
	key := newTestKey(t)
	sig, err := keystore.SignRS256(key, []byte("test.payload"))
	if err != nil {
		t.Fatalf("SignRS256: %v", err)
	}
	if len(sig) == 0 {
		t.Error("expected non-empty signature")
	}
}

func TestSignRS256_DifferentInputProducesDifferentSignatures(t *testing.T) {
	key := newTestKey(t)
	sig1, _ := keystore.SignRS256(key, []byte("payload1"))
	sig2, _ := keystore.SignRS256(key, []byte("payload2"))
	if string(sig1) == string(sig2) {
		t.Error("different inputs should produce different signatures")
	}
}

func TestSignRS256_SameInputProducesVerifiableSignature(t *testing.T) {
	key := newTestKey(t)
	data := []byte("header.payload")
	sig, err := keystore.SignRS256(key, data)
	if err != nil {
		t.Fatalf("SignRS256: %v", err)
	}

	// Verify manually using the public key.
	h := sha256.Sum256(data)
	if err := rsa.VerifyPKCS1v15(&key.Private.PublicKey, crypto.SHA256, h[:], sig); err != nil {
		t.Errorf("signature verification failed: %v", err)
	}
}

// ---- JWKSet / toJWK (via PublicKeySet on VaultKeyStore) -------------------

func TestJWK_FieldValues_ViaRotatorAndStore(t *testing.T) {
	mem := newMemStoreKS()
	r := keystore.NewRotator(mem, keystore.RotatorConfig{
		KeyBits: 1024, GracePeriod: time.Hour,
		Mount: "secret", SecretPath: "ks-jwk",
	})
	if err := r.Rotate(testCtx(t)); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	store, err := keystore.NewVaultKeyStore(testCtx(t), keystore.VaultKeyStoreConfig{
		Vault: mem, Mount: "secret", SecretPath: "ks-jwk",
	})
	if err != nil {
		t.Fatalf("NewVaultKeyStore: %v", err)
	}

	set := store.PublicKeySet()
	if len(set.Keys) == 0 {
		t.Fatal("expected at least one key in JWKS")
	}
	k := set.Keys[0]
	if k.Kty != "RSA" {
		t.Errorf("kty = %q, want RSA", k.Kty)
	}
	if k.Use != "sig" {
		t.Errorf("use = %q, want sig", k.Use)
	}
	if k.Alg != "RS256" {
		t.Errorf("alg = %q, want RS256", k.Alg)
	}
	if k.Kid == "" {
		t.Error("kid must not be empty")
	}
	if k.N == "" {
		t.Error("N must not be empty")
	}
	if k.E == "" {
		t.Error("E must not be empty")
	}
}

func TestJWK_E_IsBase64URL(t *testing.T) {
	mem := newMemStoreKS()
	r := keystore.NewRotator(mem, keystore.RotatorConfig{
		KeyBits: 1024, GracePeriod: time.Hour,
		Mount: "secret", SecretPath: "ks-e",
	})
	r.Rotate(testCtx(t))

	store, _ := keystore.NewVaultKeyStore(testCtx(t), keystore.VaultKeyStoreConfig{
		Vault: mem, Mount: "secret", SecretPath: "ks-e",
	})

	k := store.PublicKeySet().Keys[0]
	if _, err := base64.RawURLEncoding.DecodeString(k.E); err != nil {
		t.Errorf("E is not valid base64url: %v", err)
	}
	if _, err := base64.RawURLEncoding.DecodeString(k.N); err != nil {
		t.Errorf("N is not valid base64url: %v", err)
	}
}
