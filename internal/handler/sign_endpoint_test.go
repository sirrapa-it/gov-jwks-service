//go:build signing

package handler_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sirrapa-it/gov-jwks-service/internal/handler"
	"github.com/sirrapa-it/gov-jwks-service/internal/keystore"
)

type signResp struct {
	Token string `json:"token"`
	Kid   string `json:"kid"`
	Exp   int64  `json:"exp"`
}

func signRequest(t *testing.T, mux *http.ServeMux, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/internal/sign",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func validSignStore(t *testing.T) *mockStore {
	t.Helper()
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	return &mockStore{
		activeKey: &keystore.ManagedKey{
			Kid: "sign-kid", Private: priv, CreatedAt: time.Now(),
		},
	}
}

// ---- Sign happy path --------------------------------------------------------

func TestSign_Returns200(t *testing.T) {
	mux := newTestMux(t, validSignStore(t))
	rr := signRequest(t, mux, `{"sub":"user@test","aud":"svc"}`)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
}

func TestSign_ResponseContainsToken(t *testing.T) {
	mux := newTestMux(t, validSignStore(t))
	rr := signRequest(t, mux, `{"sub":"u","aud":"a"}`)
	var resp signResp
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Token == "" {
		t.Fatal("expected non-empty token in response")
	}
}

func TestSign_TokenHasThreeParts(t *testing.T) {
	mux := newTestMux(t, validSignStore(t))
	rr := signRequest(t, mux, `{"sub":"u","aud":"a"}`)
	var resp signResp
	json.NewDecoder(rr.Body).Decode(&resp)
	parts := strings.Split(resp.Token, ".")
	if len(parts) != 3 {
		t.Errorf("expected 3 JWT parts, got %d", len(parts))
	}
}

func TestSign_WithRoles(t *testing.T) {
	mux := newTestMux(t, validSignStore(t))
	rr := signRequest(t, mux, `{"sub":"u","aud":"a","roles":["read","write"]}`)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d", rr.Code)
	}
}

func TestSign_WithExtra(t *testing.T) {
	mux := newTestMux(t, validSignStore(t))
	rr := signRequest(t, mux, `{"sub":"u","aud":"a","extra":{"tenant":"x"}}`)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d", rr.Code)
	}
}

func TestSign_CustomTTL(t *testing.T) {
	mux := newTestMux(t, validSignStore(t))
	rr := signRequest(t, mux, `{"sub":"u","aud":"a","ttl":"5m"}`)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d", rr.Code)
	}
	var resp signResp
	json.NewDecoder(rr.Body).Decode(&resp)
	expectedExp := time.Now().Add(5 * time.Minute).Unix()
	if resp.Exp < expectedExp-5 || resp.Exp > expectedExp+5 {
		t.Errorf("exp = %d, want ~%d", resp.Exp, expectedExp)
	}
}

// ---- Sign validation errors -------------------------------------------------

func TestSign_MissingSub_Returns400(t *testing.T) {
	mux := newTestMux(t, validSignStore(t))
	rr := signRequest(t, mux, `{"aud":"svc"}`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestSign_MissingAud_Returns400(t *testing.T) {
	mux := newTestMux(t, validSignStore(t))
	rr := signRequest(t, mux, `{"sub":"user"}`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestSign_InvalidBody_Returns400(t *testing.T) {
	mux := newTestMux(t, validSignStore(t))
	rr := signRequest(t, mux, `{invalid json`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestSign_InvalidTTL_Returns400(t *testing.T) {
	mux := newTestMux(t, validSignStore(t))
	rr := signRequest(t, mux, `{"sub":"u","aud":"a","ttl":"not-a-duration"}`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestSign_NegativeTTL_Returns400(t *testing.T) {
	mux := newTestMux(t, validSignStore(t))
	rr := signRequest(t, mux, `{"sub":"u","aud":"a","ttl":"-1m"}`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// ---- Sign service errors ---------------------------------------------------

func TestSign_NoActiveKey_Returns503(t *testing.T) {
	store := &mockStore{activeErr: errors.New("no active key")}
	mux := newTestMux(t, store)
	rr := signRequest(t, mux, `{"sub":"u","aud":"a"}`)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rr.Code)
	}
}

func TestSign_SigningFailure_Returns500(t *testing.T) {
	orig := *handler.RsaSignFnForTest
	*handler.RsaSignFnForTest = func(_ *keystore.ManagedKey, _ []byte) ([]byte, error) {
		return nil, errors.New("injected signing failure")
	}
	t.Cleanup(func() { *handler.RsaSignFnForTest = orig })

	mux := newTestMux(t, validSignStore(t))
	rr := signRequest(t, mux, `{"sub":"u","aud":"a"}`)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}
}

func TestSign_JSONMarshalFailure_Returns500(t *testing.T) {
	orig := *handler.JSONMarshalFnForTest
	*handler.JSONMarshalFnForTest = func(_ any) ([]byte, error) {
		return nil, errors.New("injected marshal failure")
	}
	t.Cleanup(func() { *handler.JSONMarshalFnForTest = orig })

	mux := newTestMux(t, validSignStore(t))
	rr := signRequest(t, mux, `{"sub":"u","aud":"a"}`)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}
}
