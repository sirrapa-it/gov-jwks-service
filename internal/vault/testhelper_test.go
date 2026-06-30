// Package vault_test shared test helpers.
package vault_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/sirrapa-it/gov-jwks-service/internal/vault"
)

// memStore is a thread-safe in-memory SecretStore for tests.
type memStore struct {
	mu   sync.RWMutex
	data map[string]map[string]any
}

func newMemStore() *memStore {
	return &memStore{data: make(map[string]map[string]any)}
}

func (m *memStore) key(mount, path string) string { return mount + "/" + path }

func (m *memStore) Put(_ context.Context, mount, path string, data map[string]any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make(map[string]any, len(data))
	for k, v := range data {
		cp[k] = v
	}
	m.data[m.key(mount, path)] = cp
	return nil
}

func (m *memStore) Get(_ context.Context, mount, path string) (map[string]any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.data[m.key(mount, path)]
	if !ok {
		return nil, vault.ErrNotFound
	}
	return d, nil
}

func (m *memStore) List(_ context.Context, mount, path string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	prefix := mount + "/" + path + "/"
	seen := map[string]bool{}
	for k := range m.data {
		if strings.HasPrefix(k, prefix) {
			seen[k[len(prefix):]] = true
		}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	return keys, nil
}

func (m *memStore) Delete(_ context.Context, mount, path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, m.key(mount, path))
	return nil
}

// kvServer builds a minimal KV v1 Vault mock server.
func kvServer(t *testing.T) (*httptest.Server, *memStore) {
	t.Helper()
	store := newMemStore()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/kubernetes/login", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{"client_token": "mock-token", "lease_duration": 3600},
		})
	})
	mux.HandleFunc("/v1/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/v1/"), "/", 2)
		if len(parts) < 2 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mount, path := parts[0], parts[1]
		switch r.Method {
		case http.MethodGet:
			d, err := store.Get(r.Context(), mount, path)
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]any{"errors": []string{"not found"}})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"data": d})
		case http.MethodPost, http.MethodPut:
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			store.Put(r.Context(), mount, path, body)
			w.WriteHeader(http.StatusNoContent)
		case "LIST":
			keys, _ := store.List(r.Context(), mount, path)
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"keys": keys}})
		case http.MethodDelete:
			store.Delete(r.Context(), mount, path)
			w.WriteHeader(http.StatusNoContent)
		}
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, store
}

// newTestClient builds a Client using TokenAuth pointed at the given server.
func newTestClient(t *testing.T, serverURL string) *vault.Client {
	t.Helper()
	c, err := vault.NewClient(context.Background(), vault.ClientConfig{
		Address: serverURL,
		Auth:    &vault.TokenAuth{Token: "mock-token"},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}
