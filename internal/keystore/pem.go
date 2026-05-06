package keystore

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

const pemTypeRSAPrivateKey = "RSA PRIVATE KEY"

// EncodePrivateKeyPEM serialises an RSA private key to PKCS#1 PEM format.
// Returns an error when key is nil.
func EncodePrivateKeyPEM(key *rsa.PrivateKey) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("keystore: cannot encode nil private key")
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  pemTypeRSAPrivateKey,
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}), nil
}

// DecodePrivateKeyPEM parses a PKCS#1 PEM-encoded RSA private key.
// Returns an error when the PEM block is missing, has the wrong type,
// or contains malformed DER data.
func DecodePrivateKeyPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("keystore: no PEM block found in input")
	}
	if block.Type != pemTypeRSAPrivateKey {
		return nil, fmt.Errorf("keystore: expected PEM type %q, got %q", pemTypeRSAPrivateKey, block.Type)
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keystore: parse PKCS#1 private key: %w", err)
	}
	return key, nil
}
