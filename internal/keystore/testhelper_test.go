package keystore_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/sirrapa/jwks-service/internal/vault"
)

// testCtx returns a background context that is cancelled when the test ends.
func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return ctx
}

// ---- in-memory SecretStore --------------------------------------------------

// memStoreKS is a thread-safe in-memory vault.SecretStore for keystore tests.
type memStoreKS struct {
	mu   sync.RWMutex
	data map[string]map[string]any
}

func newMemStoreKS() *memStoreKS {
	return &memStoreKS{data: make(map[string]map[string]any)}
}

func (m *memStoreKS) k(mount, path string) string { return mount + "/" + path }

func (m *memStoreKS) Put(_ context.Context, mount, path string, data map[string]any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make(map[string]any, len(data))
	for k, v := range data {
		cp[k] = v
	}
	m.data[m.k(mount, path)] = cp
	return nil
}

func (m *memStoreKS) Get(_ context.Context, mount, path string) (map[string]any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.data[m.k(mount, path)]
	if !ok {
		return nil, vault.ErrNotFound
	}
	return d, nil
}

func (m *memStoreKS) List(_ context.Context, mount, path string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	prefix := mount + "/" + path + "/"
	seen := map[string]bool{}
	for k := range m.data {
		if len(k) > len(prefix) && k[:len(prefix)] == prefix {
			seen[k[len(prefix):]] = true
		}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	return keys, nil
}

func (m *memStoreKS) Delete(_ context.Context, mount, path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, m.k(mount, path))
	return nil
}

// ---- error-injecting stores -------------------------------------------------

// errStore always returns an error for all operations.
type errStore struct{ msg string }

func (s *errStore) Put(_ context.Context, _, _ string, _ map[string]any) error {
	return errors.New(s.msg)
}
func (s *errStore) Get(_ context.Context, _, _ string) (map[string]any, error) {
	return nil, errors.New(s.msg)
}
func (s *errStore) List(_ context.Context, _, _ string) ([]string, error) {
	return nil, errors.New(s.msg)
}
func (s *errStore) Delete(_ context.Context, _, _ string) error { return errors.New(s.msg) }

// countingPutStore succeeds for the first n Put calls then fails.
type countingPutStore struct {
	mu        sync.Mutex
	delegate  vault.SecretStore
	failAfter int
	calls     int
}

func (s *countingPutStore) Put(ctx context.Context, mount, path string, data map[string]any) error {
	s.mu.Lock()
	s.calls++
	fail := s.calls > s.failAfter
	s.mu.Unlock()
	if fail {
		return errors.New("injected put error")
	}
	return s.delegate.Put(ctx, mount, path, data)
}
func (s *countingPutStore) Get(ctx context.Context, m, p string) (map[string]any, error) {
	return s.delegate.Get(ctx, m, p)
}
func (s *countingPutStore) List(ctx context.Context, m, p string) ([]string, error) {
	return s.delegate.List(ctx, m, p)
}
func (s *countingPutStore) Delete(ctx context.Context, m, p string) error {
	return s.delegate.Delete(ctx, m, p)
}

// deleteErrStore delegates all ops to a memStore but always fails on Delete.
type deleteErrStore struct{ mem *memStoreKS }

func (s *deleteErrStore) Put(ctx context.Context, m, p string, d map[string]any) error {
	return s.mem.Put(ctx, m, p, d)
}
func (s *deleteErrStore) Get(ctx context.Context, m, p string) (map[string]any, error) {
	return s.mem.Get(ctx, m, p)
}
func (s *deleteErrStore) List(ctx context.Context, m, p string) ([]string, error) {
	return s.mem.List(ctx, m, p)
}
func (s *deleteErrStore) Delete(_ context.Context, _, _ string) error {
	return errors.New("injected delete error")
}

// listErrAfterNStore returns an error from List after n successful calls.
type listErrAfterNStore struct {
	mu        sync.Mutex
	delegate  vault.SecretStore
	failAfter int
	calls     int
}

func (s *listErrAfterNStore) List(ctx context.Context, m, p string) ([]string, error) {
	s.mu.Lock()
	s.calls++
	fail := s.calls > s.failAfter
	s.mu.Unlock()
	if fail {
		return nil, errors.New("injected list error")
	}
	return s.delegate.List(ctx, m, p)
}
func (s *listErrAfterNStore) Put(ctx context.Context, m, p string, d map[string]any) error {
	return s.delegate.Put(ctx, m, p, d)
}
func (s *listErrAfterNStore) Get(ctx context.Context, m, p string) (map[string]any, error) {
	return s.delegate.Get(ctx, m, p)
}
func (s *listErrAfterNStore) Delete(ctx context.Context, m, p string) error {
	return s.delegate.Delete(ctx, m, p)
}
