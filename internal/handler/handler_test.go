package handler_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sirrapa-it/gov-jwks-service/internal/handler"
	"github.com/sirrapa-it/gov-jwks-service/internal/keystore"
)

// mockStore implements keystore.Store for handler tests.
type mockStore struct {
	activeKey *keystore.ManagedKey
	activeErr error
	jwkSet    keystore.JWKSet
}

func (m *mockStore) ActiveKey() (*keystore.ManagedKey, error) {
	return m.activeKey, m.activeErr
}
func (m *mockStore) PublicKeySet() keystore.JWKSet { return m.jwkSet }

func validStore(t *testing.T) *mockStore {
	t.Helper()
	return &mockStore{
		activeKey: &keystore.ManagedKey{
			Kid:       "test-kid",
			CreatedAt: time.Now(),
		},
		jwkSet: keystore.JWKSet{
			Keys: []keystore.JWK{
				{Kty: "RSA", Use: "sig", Alg: "RS256", Kid: "test-kid", N: "mod", E: "exp"},
			},
		},
	}
}

func newTestMux(t *testing.T, store keystore.Store) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	handler.New(store, nil).RegisterRoutes(mux)
	return mux
}

// ---- JWKS endpoint ----------------------------------------------------------

func TestJWKS_Returns200(t *testing.T) {
	mux := newTestMux(t, validStore(t))
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

func TestJWKS_ContentTypeJSON(t *testing.T) {
	mux := newTestMux(t, validStore(t))
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestJWKS_CacheControlHeader(t *testing.T) {
	mux := newTestMux(t, validStore(t))
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	cc := rr.Header().Get("Cache-Control")
	if !strings.Contains(cc, "max-age=3600") {
		t.Errorf("Cache-Control = %q, want max-age=3600", cc)
	}
}

func TestJWKS_XContentTypeOptionsHeader(t *testing.T) {
	mux := newTestMux(t, validStore(t))
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("expected X-Content-Type-Options: nosniff")
	}
}

func TestJWKS_ValidBody(t *testing.T) {
	mux := newTestMux(t, validStore(t))
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	var set keystore.JWKSet
	if err := json.NewDecoder(rr.Body).Decode(&set); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(set.Keys) != 1 || set.Keys[0].Kid != "test-kid" {
		t.Errorf("unexpected JWKS body: %+v", set)
	}
}

// ---- Health endpoint --------------------------------------------------------

func TestHealth_Returns200(t *testing.T) {
	mux := newTestMux(t, validStore(t))
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

func TestHealth_BodyContainsOk(t *testing.T) {
	mux := newTestMux(t, validStore(t))
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if !strings.Contains(rr.Body.String(), "ok") {
		t.Errorf("body = %q, want 'ok'", rr.Body.String())
	}
}

// ---- Metrics endpoint -------------------------------------------------------

func TestMetrics_Returns200(t *testing.T) {
	mux := newTestMux(t, validStore(t))
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("metrics status = %d, want 200", rr.Code)
	}
}

// ---- ParseBearerToken -------------------------------------------------------

func TestParseBearerToken_Valid(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Bearer my.test.token")
	tok, err := handler.ParseBearerToken(req)
	if err != nil || tok != "my.test.token" {
		t.Errorf("ParseBearerToken() = (%q, %v), want (my.test.token, nil)", tok, err)
	}
}

func TestParseBearerToken_MissingHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	if _, err := handler.ParseBearerToken(req); err == nil {
		t.Fatal("expected error for missing Authorization header")
	}
}

func TestParseBearerToken_MalformedHeader(t *testing.T) {
	for _, v := range []string{"NotBearer token", "Bearer", "token"} {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Authorization", v)
		if _, err := handler.ParseBearerToken(req); err == nil {
			t.Errorf("expected error for Authorization: %q", v)
		}
	}
}

func TestParseBearerToken_CaseInsensitiveBearer(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "BEARER tok")
	tok, err := handler.ParseBearerToken(req)
	if err != nil || tok != "tok" {
		t.Errorf("case-insensitive bearer: (%q, %v)", tok, err)
	}
}

// ---- NilLogger --------------------------------------------------------------

func TestNew_NilLogger_UsesDefault(t *testing.T) {
	h := handler.New(validStore(t), nil)
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
}
