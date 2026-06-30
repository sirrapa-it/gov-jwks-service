# jwks-service

Internal JWKS (JSON Web Key Set) service for the Private Cloud Kubernetes cluster.
Manages RSA-4096 signing keys for JWT issuance, with automatic rotation via a
Kubernetes CronJob and durable key storage in HashiCorp Vault.

Compliant with **BIO** (Baseline Informatiebeveiliging Overheid) and **NIS2** Article 21.

## Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [API endpoints](#api-endpoints)
- [Configuration](#configuration)
- [Vault integration](#vault-integration)
- [Local development](#local-development)
- [Running tests](#running-tests)
- [Deployment](#deployment)
- [Key rotation](#key-rotation)
- [Package structure](#package-structure)
- [Architecture Decision Records](#architecture-decision-records)

---

## Overview

The service acts as the central trust anchor for JWT verification within the cluster.
Two separate binaries share this repository:

| Binary | Role | Vault access | Kubernetes resource |
|---|---|---|---|
| `cmd/server` | Serves JWKS endpoint, refreshes cache from Vault | Read-only | Deployment (2 replicas) |
| `cmd/rotator` | Generates new keys, prunes expired keys | Read-write | CronJob (monthly) |

```
External user
      │
      ▼
API Gateway (Gloo)
      │  validates external OIDC token
      ▼
extauth-service
      │  reads private key from Vault → signs internal JWT
      ▼
Backend services
      │  receive JWT, want to verify signature
      ▼
jwks-service   ◄──── HashiCorp Vault (key storage)
      │  GET /.well-known/jwks.json → public keys
      ▼
Backend services verify signature ✓
```

---

## Architecture

```
jwks-service/
├── cmd/
│   ├── server/main.go          # HTTP server binary
│   └── rotator/main.go         # CronJob rotation binary
├── internal/
│   ├── config/config.go        # Environment variable configuration
│   ├── vault/
│   │   ├── auth.go             # TokenAuth, KubernetesAuth
│   │   └── client.go           # KV v1 HTTP client (stdlib only, no SDK)
│   ├── keystore/
│   │   ├── keystore.go         # ManagedKey, JWKSet, Store interface, SignRS256
│   │   ├── pem.go              # PKCS#1 PEM encode/decode
│   │   ├── metrics.go          # Prometheus metrics + UpdateActiveKeyAge()
│   │   ├── vault_store.go      # VaultKeyStore (read-only, StartSync)
│   │   └── rotator.go          # Rotator (write-only, monthly CronJob)
│   └── handler/
│       ├── handler.go          # JWKS, Health, /metrics endpoints
│       ├── sign_endpoint.go    # POST /internal/sign (build tag: signing)
│       └── sign_endpoint_stub.go
├── deploy/
│   ├── server/
│   │   ├── Dockerfile
│   │   └── k8s.yaml            # Deployment, Service, HPA, ServiceMonitor, PrometheusRule
│   ├── rotator/
│   │   ├── Dockerfile
│   │   └── k8s.yaml            # Bootstrap Job + monthly CronJob
│   └── vault/
│       ├── policy-ro.hcl       # Read-only policy for server
│       ├── policy-rw.hcl       # Read-write policy for rotator
│       └── setup.sh            # Vault bootstrap script
├── docs/adr/                   # Architecture Decision Records
├── Makefile
├── go.mod
└── README.md
```

### Vault path layout (KV v1)

```
secret/jwks-service/active           ← {"kid": "...", "rotated_at": "..."}
secret/jwks-service/keys/{kid}       ← {pem, kid, created_at, expires_at}
```

### Key lifecycle

```
T+0   Rotator runs: new key B generated, old key A gets ExpiresAt = T+2h
T+0   Both A and B visible in JWKS response (grace period)
T+2h  Server sync drops key A from response
T+2h  Next rotator run deletes key A from Vault
```

---

## API endpoints

### `GET /.well-known/jwks.json`

Returns all currently valid public keys (RFC 7517).

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
      "n": "0Z3VS5JJcds3xHn...",
      "e": "AQAB"
    }
  ]
}
```

The `kid` is the **RFC 7638 JWK thumbprint** of the public key. Because it is the
standard fingerprint of a key, any RFC 7638-compliant signer derives the same
`kid` for the same key — no out-of-band agreement on the kid scheme is required
for a signer's tokens to match the published key.

Headers: `Cache-Control: public, max-age=3600`, `X-Content-Type-Options: nosniff`

### `GET /healthz`

Kubernetes liveness probe. Returns `{"status":"ok"}` with HTTP 200.

### `GET /metrics`

Prometheus metrics endpoint.

### `POST /internal/sign`

**Testing only — not compiled into the default build.**
Enable with the `signing` build tag. Do not expose via the external gateway.

```bash
go run -tags signing ./cmd/server
```

Request:
```json
{"sub": "user@platform.internal", "aud": "zaak-service", "roles": ["read"], "ttl": "15m"}
```

---

## Configuration

All configuration is read from environment variables.

### Server (`cmd/server`)

| Variable | Default | Description |
|---|---|---|
| `LISTEN_ADDR` | `:8080` | TCP bind address |
| `SYNC_INTERVAL` | `5m` | How often to refresh keys from Vault |
| `SHUTDOWN_TIMEOUT` | `10s` | Graceful shutdown drain time |
| `LOG_LEVEL` | `warn` | `debug` / `info` / `warn` / `error` |

### Rotator (`cmd/rotator`)

| Variable | Default | Description |
|---|---|---|
| `KEY_BITS` | `4096` | RSA key size (BIO: RSA-4096 = 4-year lifetime) |
| `GRACE_PERIOD` | `2h` | Old key visibility after rotation (NIS2/BIO compliant) |
| `LOG_LEVEL` | `warn` | `debug` / `info` / `warn` / `error` |

### Vault (both binaries)

| Variable | Default | Description |
|---|---|---|
| `VAULT_ADDR` | *(required)* | Vault server URL |
| `VAULT_K8S_ROLE` | *(empty)* | Kubernetes auth role — use in production |
| `VAULT_K8S_MOUNT` | `kubernetes` | Kubernetes auth mount path |
| `VAULT_TOKEN` | *(empty)* | Static token — development/CI only |
| `VAULT_MOUNT` | `secret` | KV v1 mount path |
| `VAULT_SECRET_PATH` | `jwks-service` | Key storage prefix |

---

## Vault integration

### Production (Kubernetes auth)

```bash
bash deploy/vault/setup.sh
```

Or manually:

```bash
vault write auth/kubernetes/role/jwks-service \
    bound_service_account_names=jwks-service \
    bound_service_account_namespaces=platform \
    policies=jwks-service_ro \
    alias_name_source=serviceaccount_name \
    ttl=1h

vault write auth/kubernetes/role/jwks-rotator \
    bound_service_account_names=jwks-rotator \
    bound_service_account_namespaces=platform \
    policies=jwks-service_rw \
    alias_name_source=serviceaccount_name \
    ttl=1h
```

### Development (static token)

```bash
export VAULT_ADDR="http://localhost:8200"
export VAULT_TOKEN="root"
```

> **Never use `VAULT_TOKEN` in production.**

---

## Local development

### Requirements

- Go 1.22 or higher
- Docker (optional)

### Start with local Vault

```bash
# Terminal 1 — Vault in dev mode
vault server -dev -dev-root-token-id="root"

# Terminal 2 — bootstrap keys and start server
export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="root"

go run ./cmd/rotator          # generate initial key
go run -tags signing ./cmd/server  # start server with sign endpoint
```

### Inspect a JWT

```bash
curl -s -X POST http://localhost:8080/internal/sign \
  -H "Content-Type: application/json" \
  -d '{"sub":"test@platform.internal","aud":"my-service","roles":["read"]}' \
  | jq -r .token \
  | cut -d. -f2 \
  | base64 -d 2>/dev/null \
  | jq .
```

Or paste the token at [jwt.io](https://jwt.io).

---

## Running tests

```bash
# All tests (sign endpoint excluded — default build)
go test ./...

# All tests including sign endpoint
go test -tags signing ./...

# With coverage report
go test -tags signing ./... -coverprofile=coverage.out -covermode=atomic
go tool cover -func=coverage.out

# HTML coverage report
go tool cover -html=coverage.out
```

### Coverage targets

| Package | Target |
|---|---|
| `internal/config` | 100% |
| `internal/vault` | 100% |
| `internal/keystore` | 100% |
| `internal/handler` | 100% |
| `cmd/server` | ≥ 95% |
| `cmd/rotator` | ≥ 95% |

`main()` itself (2 lines, calls `os.Exit`) is untestable by Go convention.

---

## Deployment

### First deployment

```bash
# 1. Configure Vault
bash deploy/vault/setup.sh

# 2. Build and push images
make build push VERSION=1.0.0

# 3. Bootstrap — creates the first signing key
kubectl apply -f deploy/rotator/k8s.yaml
kubectl wait --for=condition=complete job/jwks-bootstrap -n platform --timeout=120s

# 4. Deploy the server
kubectl apply -f deploy/server/k8s.yaml
```

### Subsequent deployments

```bash
make build push VERSION=1.x.x
kubectl set image deployment/jwks-service jwks-service=registry.github.com/sirrapa/platform/jwks-service:1.x.x -n platform
```

### Emergency rotation (NIS2 incident response)

```bash
# Immediate rotation with zero grace period
kubectl create job --from=cronjob/jwks-rotator jwks-emergency-$(date +%s) -n platform
# Then patch env: GRACE_PERIOD=0s for instant key expiry
```

### Resource limits

| Resource | Server request | Server limit | Rotator request | Rotator limit |
|---|---|---|---|---|
| CPU | 50m | 200m | 100m | 500m |
| Memory | 64Mi | 128Mi | 64Mi | 128Mi |

### Health checks

| Probe | Path | Initial delay | Period |
|---|---|---|---|
| Readiness | `/healthz` | 3s | 10s |
| Liveness | `/healthz` | 5s | 30s |

---

## Key rotation

Rotation runs monthly (`0 2 1 * *`) via Kubernetes CronJob with `concurrencyPolicy: Forbid`.

**Why monthly?**
- BIO: RSA-4096 allows up to 4-year key lifetime. Monthly rotation provides a large safety margin.
- NIS2 Article 21: Requires a demonstrable, auditable key management process.

**Rotation process:**

1. Generate new RSA-4096 key pair → persist to Vault
2. Mark all currently active keys with `ExpiresAt = now + GRACE_PERIOD`
3. Delete keys whose `ExpiresAt` is in the past
4. Update `/active` pointer to new key
5. Emit ECS-compatible audit log entries

**Grace period** (default 2h): old keys remain in the JWKS response for 2 hours after rotation, ensuring downstream services with a 1-hour JWKS cache never encounter an unknown `kid`.

**Emergency rotation** procedure is documented in [ADR-012](docs/adr/ADR-012-grace-period-key-rotatie.md).

---

## Package structure

### `internal/config`

Loads all configuration from environment variables. Each field documents its default and the corresponding variable. Both `ServerConfig` and `RotatorConfig` are returned as concrete structs — never nil.

### `internal/vault`

Minimal Vault KV v1 HTTP client built on the Go standard library — no external SDK. Supports `Put`, `Get`, `List`, `Delete` and two authenticators:

- `TokenAuth` — static token, for development and CI
- `KubernetesAuth` — exchanges the pod service-account JWT for a Vault token; use in production

Tokens are renewed automatically at 80% of TTL.

### `internal/keystore`

- **`VaultKeyStore`** — read-only, used by `cmd/server`. Loads keys on startup, refreshes via `StartSync`. Never writes to Vault.
- **`Rotator`** — write-only, used by `cmd/rotator`. Generates, persists and prunes keys. Designed for single-execution (CronJob).
- **`metrics.go`** — Prometheus gauges and counters. `UpdateActiveKeyAge()` is called by the server on a 30-second tick.

Both depend on the `vault.SecretStore` interface, making them fully testable with in-memory stores.

### `internal/handler`

HTTP handlers for JWKS, health and metrics. The `POST /internal/sign` endpoint exists only when compiled with `-tags signing`.

### `cmd/server`

Wires `VaultKeyStore` + `handler` + HTTP server. Starts `StartSync` goroutine and key-age metric goroutine. Graceful shutdown on `SIGTERM`/`SIGINT` or context cancellation.

### `cmd/rotator`

Wires `Rotator` + Vault client. Runs `Rotate()` once and exits with code 0 (success) or 1 (failure).

---

## Architecture Decision Records

| ADR | Title | Status |
|---|---|---|
| [ADR-001](docs/adr/ADR-001-sleutelbeheer-jwks-service.md) | Key management centralised in jwks-service | Accepted |
| [ADR-002](docs/adr/ADR-002-aparte-repositories.md) | Separate repositories for server and extauth | Accepted |
| [ADR-003](docs/adr/ADR-003-gedeeld-keypair.md) | Shared keypair for all extauth services | Accepted |
| [ADR-004](docs/adr/ADR-004-stdlib-geen-vault-sdk.md) | Go stdlib only — no external Vault SDK | Accepted |
| [ADR-005](docs/adr/ADR-005-rs256-signing-algoritme.md) | RS256 as JWT signing algorithm | Accepted |
| [ADR-006](docs/adr/ADR-006-vault-als-key-storage.md) | HashiCorp Vault as key storage | Accepted |
| [ADR-007](docs/adr/ADR-007-kv-v1-secrets-engine.md) | KV v1 as Vault secrets engine | Accepted |
| [ADR-008](docs/adr/ADR-008-kubernetes-vault-auth.md) | Kubernetes auth for Vault | Accepted |
| [ADR-009](docs/adr/ADR-009-sign-endpoint-build-tag.md) | /internal/sign behind signing build tag | Accepted |
| [ADR-010](docs/adr/ADR-010-jwt-levensduur.md) | JWT lifetime of 15 minutes | Accepted |
| [ADR-011](docs/adr/ADR-011-cronjob-rotatie.md) | Key rotation via CronJob (not in-service goroutine) | Accepted |
| [ADR-012](docs/adr/ADR-012-grace-period-key-rotatie.md) | Grace period on key rotation | Accepted |
| [ADR-013](docs/adr/ADR-013-server-read-only.md) | Server binary is read-only (no fallback) | Accepted |
