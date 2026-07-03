package vault_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirrapa-it/gov-jwks-service/internal/vault"
)

// ---- Put / Get --------------------------------------------------------------

func TestClient_Put_Get_RoundTrip(t *testing.T) {
	srv, _ := kvServer(t)
	c := newTestClient(t, srv.URL)

	data := map[string]any{"pem": "key-data", "kid": "k1"}
	if err := c.Put(context.Background(), "secret", "jwks/keys/k1", data); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := c.Get(context.Background(), "secret", "jwks/keys/k1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got["pem"] != "key-data" {
		t.Errorf("pem = %q, want key-data", got["pem"])
	}
}

func TestClient_Get_NotFound(t *testing.T) {
	srv, _ := kvServer(t)
	c := newTestClient(t, srv.URL)

	_, err := c.Get(context.Background(), "secret", "does/not/exist")
	if err != vault.ErrNotFound {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestClient_Put_Overwrites(t *testing.T) {
	srv, _ := kvServer(t)
	c := newTestClient(t, srv.URL)
	ctx := context.Background()

	c.Put(ctx, "secret", "jwks/active", map[string]any{"kid": "old"})
	c.Put(ctx, "secret", "jwks/active", map[string]any{"kid": "new"})

	got, _ := c.Get(ctx, "secret", "jwks/active")
	if got["kid"] != "new" {
		t.Errorf("kid = %q, want new", got["kid"])
	}
}

// ---- Delete -----------------------------------------------------------------

func TestClient_Delete_RemovesKey(t *testing.T) {
	srv, _ := kvServer(t)
	c := newTestClient(t, srv.URL)
	ctx := context.Background()

	c.Put(ctx, "secret", "jwks/keys/del", map[string]any{"v": "1"})
	if err := c.Delete(ctx, "secret", "jwks/keys/del"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := c.Get(ctx, "secret", "jwks/keys/del"); err != vault.ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestClient_Delete_NonOK_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]any{"errors": []string{"denied"}})
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	if err := c.Delete(context.Background(), "s", "p"); err == nil {
		t.Fatal("expected error for 403")
	}
}

// ---- List -------------------------------------------------------------------

func TestClient_List_ReturnsKeys(t *testing.T) {
	srv, _ := kvServer(t)
	c := newTestClient(t, srv.URL)
	ctx := context.Background()

	for _, kid := range []string{"a", "b", "c"} {
		c.Put(ctx, "secret", "jwks/keys/"+kid, map[string]any{"kid": kid})
	}
	keys, err := c.List(ctx, "secret", "jwks/keys")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 3 {
		t.Errorf("got %d keys, want 3", len(keys))
	}
}

func TestClient_List_EmptyPath_ReturnsEmpty(t *testing.T) {
	srv, _ := kvServer(t)
	c := newTestClient(t, srv.URL)
	keys, err := c.List(context.Background(), "secret", "nonexistent")
	if err != nil {
		t.Fatalf("List empty path should not error: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected empty, got %v", keys)
	}
}

func TestClient_List_NonOK_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]any{"errors": []string{"denied"}})
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	if _, err := c.List(context.Background(), "s", "p"); err == nil {
		t.Fatal("expected error for 403 on LIST")
	}
}

func TestClient_List_DecodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "{invalid json")
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	if _, err := c.List(context.Background(), "s", "p"); err == nil {
		t.Fatal("expected decode error")
	}
}

// ---- Get decode error -------------------------------------------------------

func TestClient_Get_DecodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "{invalid json")
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	if _, err := c.Get(context.Background(), "s", "p"); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestClient_Get_NonOK_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]any{"errors": []string{"denied"}})
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	if _, err := c.Get(context.Background(), "s", "p"); err == nil {
		t.Fatal("expected error for 403")
	}
}

// ---- Put marshal error ------------------------------------------------------

func TestClient_Put_MarshalError(t *testing.T) {
	srv, _ := kvServer(t)
	c := newTestClient(t, srv.URL)
	// json.Marshal fails on function values.
	if err := c.Put(context.Background(), "s", "p", map[string]any{"fn": func() {}}); err == nil {
		t.Fatal("expected marshal error")
	}
}

func TestClient_Put_NonOK_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]any{"errors": []string{"denied"}})
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	if err := c.Put(context.Background(), "s", "p", map[string]any{"k": "v"}); err == nil {
		t.Fatal("expected error for 403")
	}
}

// ---- HTTP Do errors (server closed with valid token) -----------------------

func TestClient_Put_HTTPDoError(t *testing.T) {
	srv, _ := kvServer(t)
	c := newTestClient(t, srv.URL)
	srv.Close()
	if err := c.Put(context.Background(), "s", "p", map[string]any{"k": "v"}); err == nil {
		t.Fatal("expected error when server closed")
	}
}

func TestClient_Get_HTTPDoError(t *testing.T) {
	srv, _ := kvServer(t)
	c := newTestClient(t, srv.URL)
	srv.Close()
	if _, err := c.Get(context.Background(), "s", "p"); err == nil {
		t.Fatal("expected error when server closed")
	}
}

func TestClient_List_HTTPDoError(t *testing.T) {
	srv, _ := kvServer(t)
	c := newTestClient(t, srv.URL)
	srv.Close()
	if _, err := c.List(context.Background(), "s", "p"); err == nil {
		t.Fatal("expected error when server closed")
	}
}

func TestClient_Delete_HTTPDoError(t *testing.T) {
	srv, _ := kvServer(t)
	c := newTestClient(t, srv.URL)
	srv.Close()
	if err := c.Delete(context.Background(), "s", "p"); err == nil {
		t.Fatal("expected error when server closed")
	}
}

// ---- apiError JSON vs plain text -------------------------------------------

func TestClient_APIError_WithVaultErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied", "policy mismatch"}})
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	err := c.Put(context.Background(), "s", "p", map[string]any{"k": "v"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_APIError_PlainText(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "internal error plain text")
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	if _, err := c.Get(context.Background(), "s", "p"); err == nil {
		t.Fatal("expected error for 500")
	}
}

// ---- Token auth errors ------------------------------------------------------

func TestTokenAuth_EmptyToken_Errors(t *testing.T) {
	_, err := vault.NewClient(context.Background(), vault.ClientConfig{
		Address: "http://unused",
		Auth:    &vault.TokenAuth{Token: ""},
	})
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}
