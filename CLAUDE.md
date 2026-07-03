# CLAUDE.md — jwks-service project context

This file provides context for Claude Code sessions working on this repository.

## What this project is

Internal JWKS (JSON Web Key Set) service for a Private Cloud Kubernetes cluster.
Manages RSA-4096 signing keys for internal JWT issuance.

Two binaries in one repository:
- `cmd/server` — stateless HTTP server, read-only Vault, 2+ replicas
- `cmd/rotator` — one-shot CronJob, writes to Vault, runs monthly

## Critical rules

- **Never use the word "cjib" or "CJIB"** anywhere in code, comments, logs or tests
- Module path: `github.com/sirrapa-it/gov-jwks-service`
- All code comments and documentation in **English**
- No external Go dependencies except `github.com/prometheus/client_golang`
- Vault KV **v1** (not v2) — no `data/` prefix in paths
- The server **never writes** to Vault — only the rotator writes

## Architecture decisions (see docs/adr/)

- ADR-004: stdlib-only Vault client, no HashiCorp SDK
- ADR-007: KV v1 (flat paths, no data/ prefix)
- ADR-008: Kubernetes auth with `alias_name_source=serviceaccount_name`
- ADR-009: `/internal/sign` only with `-tags signing` build tag
- ADR-011: rotation via CronJob with `concurrencyPolicy: Forbid`, not in-service goroutine
- ADR-013: server returns hard error when no Vault keys found — no in-memory fallback

## Directory structure

```
cmd/server/main.go          server entry point
cmd/rotator/main.go         rotator entry point
internal/config/            environment variable config
internal/vault/             Vault KV v1 client (auth.go + client.go)
internal/keystore/          key management (vault_store.go + rotator.go)
internal/handler/           HTTP handlers
deploy/server/              Dockerfile + k8s.yaml for server
deploy/rotator/             Dockerfile + k8s.yaml for CronJob
deploy/vault/               HCL policies + setup script
docs/adr/                   Architecture Decision Records
```

## Vault path layout

```
secret/jwks-service/active           → {"kid": "...", "rotated_at": "..."}
secret/jwks-service/keys/{kid}       → {pem, kid, created_at, expires_at}
```

## Build commands

```bash
# Build both binaries
go build ./cmd/server
go build ./cmd/rotator

# Tests without sign endpoint
go test ./...

# Tests with sign endpoint
go test -tags signing ./... -coverprofile=coverage.out -covermode=atomic

# Production server build (no sign endpoint)
go build -trimpath -ldflags "-s -w" -o jwks-server ./cmd/server

# Rotator build
go build -trimpath -ldflags "-s -w" -o jwks-rotator ./cmd/rotator
```

## Test conventions

- 100% coverage target for all `internal/` packages
- `cmd/` packages: 95%+ (excluding `main()` itself which calls `os.Exit`)
- All test helpers in `testhelper_test.go` per package
- Unexported hooks exposed via `export_test.go` (compiled only during tests)
- In-memory `memStoreKS` (keystore tests) and `memStore` (vault tests) as fake Vault
- Error injection via `countingPutStore`, `errStore`, `deleteErrStore` etc.
- No `t.Parallel()` on tests that modify package-level hook variables

## Key types

```go
// vault.SecretStore — interface both VaultKeyStore and Rotator depend on
type SecretStore interface {
    Put(ctx, mount, path string, data map[string]any) error
    Get(ctx, mount, path string) (map[string]any, error)
    List(ctx, mount, path string) ([]string, error)
    Delete(ctx, mount, path string) error
}

// keystore.Store — interface handler depends on
type Store interface {
    ActiveKey() (*ManagedKey, error)
    PublicKeySet() JWKSet
}
```

## Prometheus metrics

All defined in `internal/keystore/metrics.go`:

| Metric | Type | Updated by |
|---|---|---|
| `jwks_active_keys` | Gauge | VaultKeyStore.sync() |
| `jwks_active_key_age_seconds` | Gauge | UpdateActiveKeyAge() — server goroutine |
| `jwks_last_sync_timestamp_seconds` | Gauge | VaultKeyStore.StartSync() |
| `jwks_sync_errors_total` | Counter | VaultKeyStore.StartSync() |
| `jwks_key_rotations_total` | Counter | Rotator.Rotate() |
| `jwks_last_rotation_timestamp_seconds` | Gauge | Rotator.Rotate() |
| `jwks_keys_expired_total` | Counter | Rotator.pruneExpired() |
| `jwks_key_rotation_errors_total` | Counter | Rotator.Rotate() on error |

## ECS audit log fields

All lifecycle events include:
- `event.action` — `key.created`, `key.loaded`, `key.rotated`, `key.grace_period_started`, `key.expired`
- `event.category` — always `authentication`

## Compliance notes

- RSA-4096: BIO allows up to 4-year key lifetime for RSA-4096
- Monthly rotation: NIS2 Article 21 requires demonstrable key management
- Grace period 2h: exceeds the 1h JWKS cache (Cache-Control: max-age=3600)
- JWT TTL 15m: NIS2 principle of least privilege
- Vault audit logging must be enabled separately (not in application scope)
