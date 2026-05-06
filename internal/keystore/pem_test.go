package keystore_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"testing"

	"github.com/sirrapa/jwks-service/internal/keystore"
)

func TestEncodePrivateKeyPEM_ValidKey(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pemBytes, err := keystore.EncodePrivateKeyPEM(priv)
	if err != nil {
		t.Fatalf("EncodePrivateKeyPEM: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("expected valid PEM block")
	}
	if block.Type != "RSA PRIVATE KEY" {
		t.Errorf("block.Type = %q, want RSA PRIVATE KEY", block.Type)
	}
}

func TestEncodePrivateKeyPEM_NilKey_ReturnsError(t *testing.T) {
	_, err := keystore.EncodePrivateKeyPEM(nil)
	if err == nil {
		t.Fatal("expected error for nil key")
	}
}

func TestDecodePrivateKeyPEM_ValidPEM(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pemBytes, _ := keystore.EncodePrivateKeyPEM(priv)

	decoded, err := keystore.DecodePrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatalf("DecodePrivateKeyPEM: %v", err)
	}
	if decoded.N.Cmp(priv.N) != 0 {
		t.Error("decoded modulus does not match original")
	}
}

func TestDecodePrivateKeyPEM_Empty_ReturnsError(t *testing.T) {
	_, err := keystore.DecodePrivateKeyPEM([]byte{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestDecodePrivateKeyPEM_NoPEMBlock_ReturnsError(t *testing.T) {
	_, err := keystore.DecodePrivateKeyPEM([]byte("not a pem block"))
	if err == nil {
		t.Fatal("expected error for non-PEM input")
	}
}

func TestDecodePrivateKeyPEM_WrongType_ReturnsError(t *testing.T) {
	wrongType := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("fake")})
	_, err := keystore.DecodePrivateKeyPEM(wrongType)
	if err == nil {
		t.Fatal("expected error for wrong PEM type")
	}
}

func TestDecodePrivateKeyPEM_CorruptDER_ReturnsError(t *testing.T) {
	// Correct PEM type but garbage DER — exercises x509.ParsePKCS1PrivateKey error.
	corrupt := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("not-valid-der"),
	})
	_, err := keystore.DecodePrivateKeyPEM(corrupt)
	if err == nil {
		t.Fatal("expected error for corrupt DER")
	}
}

func TestEncodeDecodePrivateKeyPEM_RoundTrip(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pemBytes, _ := keystore.EncodePrivateKeyPEM(priv)
	decoded, err := keystore.DecodePrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatalf("round-trip: %v", err)
	}
	if decoded.Precomputed.Dp == nil {
		t.Error("expected Dp precomputed after decode")
	}
}
