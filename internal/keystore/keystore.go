// Package keystore manages RSA signing keys for JWT issuance.
//
// The server binary uses VaultKeyStore (read-only) to serve public keys.
// The rotator binary uses Rotator (write-only) to generate and persist keys.
//
// All keys are RSA 4096-bit, satisfying the BIO guideline of a maximum
// 4-year key lifetime for RSA 4096.
package keystore

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"
)

// rsaKeyGen is the RSA key generation hook. Tests can substitute a failing
// implementation without modifying the public API.
var rsaKeyGen = func(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

// ManagedKey wraps an RSA key pair with lifecycle metadata.
type ManagedKey struct {
	Kid       string
	Private   *rsa.PrivateKey
	CreatedAt time.Time
	// ExpiresAt is zero for the active signing key.
	ExpiresAt time.Time
}

// IsValid reports whether the key may still be used to verify tokens.
func (k *ManagedKey) IsValid(now time.Time) bool {
	return k.ExpiresAt.IsZero() || now.Before(k.ExpiresAt)
}

// JWK represents a single JSON Web Key (RFC 7517).
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKSet is the JSON Web Key Set returned by the JWKS endpoint.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// Store is the read interface used by the handler layer.
type Store interface {
	ActiveKey() (*ManagedKey, error)
	PublicKeySet() JWKSet
}

// SignRS256 signs data with RSASSA-PKCS1-v1_5 SHA-256 (RS256).
func SignRS256(key *ManagedKey, data []byte) ([]byte, error) {
	h := crypto.SHA256.New()
	h.Write(data)
	return rsa.SignPKCS1v15(rand.Reader, key.Private, crypto.SHA256, h.Sum(nil))
}

// deriveKID returns the RFC 7638 JWK thumbprint of the public key, base64url
// encoded, for use as the key ID. The thumbprint is the JOSE-standard
// fingerprint of a key, so any RFC 7638-compliant signer or verifier derives
// the same kid for the same key — no out-of-band agreement on the kid scheme is
// needed for interoperability.
func deriveKID(pub *rsa.PublicKey) string {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	// Canonical JWK per RFC 7638 §3.2: the required RSA members only, in
	// lexicographic order, with no whitespace: {"e":...,"kty":"RSA","n":...}.
	// The n and e encodings must match those used in the JWK itself (see toJWK).
	canonical := fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, e, n)
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// toJWK converts a ManagedKey to its RFC 7517 representation.
func toJWK(k *ManagedKey) JWK {
	pub := &k.Private.PublicKey
	return JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: k.Kid,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// newManagedKey generates an RSA key pair and wraps it in a ManagedKey.
func newManagedKey(bits int, expiresAt time.Time) (*ManagedKey, error) {
	priv, err := rsaKeyGen(bits)
	if err != nil {
		return nil, fmt.Errorf("keystore: generate RSA key: %w", err)
	}
	return &ManagedKey{
		Kid:       deriveKID(&priv.PublicKey),
		Private:   priv,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}, nil
}
