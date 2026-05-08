# jwks-server

HTTP service that exposes a [JWKS](https://datatracker.ietf.org/doc/html/rfc7517) endpoint backed by RSA-4096 signing keys stored in HashiCorp Vault.

Companion image: [`sirrapa/jwks-rotator`](https://hub.docker.com/r/sirrapa/jwks-rotator) generates and prunes keys; the server is read-only and never writes to Vault.

Source: https://github.com/sirrapa/jwks-service

## What it serves

| Path | Purpose |
|---|---|
| `GET /.well-known/jwks.json` | Public keys in RFC 7517 format. `Cache-Control: public, max-age=3600`. |
| `GET /healthz` | Kubernetes liveness/readiness probe. |
| `GET /metrics` | Prometheus metrics. |

The image does **not** include `POST /internal/sign` (the signing endpoint is gated by the `signing` build tag and is excluded from production builds — see ADR-009).

## Tags

| Tag | Meaning |
|---|---|
| `0.1.2` | Exact version. |
| `0.1` / `0` | Floating major / minor. |
| `sha-<short>` | Git SHA pin for forensic traceability. |

Pin to an exact version in production.

## Configuration

All configuration is read from environment variables.

### Server

| Variable | Default | Description |
|---|---|---|
| `LISTEN_ADDR` | `:8080` | TCP bind address. |
| `SYNC_INTERVAL` | `5m` | How often to refresh keys from Vault. |
| `SHUTDOWN_TIMEOUT` | `10s` | Graceful shutdown drain time. |
| `LOG_LEVEL` | `warn` | `debug` / `info` / `warn` / `error`. |

### Vault

| Variable | Default | Description |
|---|---|---|
| `VAULT_ADDR` | *(required)* | Vault server URL. |
| `VAULT_K8S_ROLE` | *(empty)* | Kubernetes auth role — use in production. |
| `VAULT_K8S_MOUNT` | `kubernetes` | Kubernetes auth mount path. |
| `VAULT_TOKEN` | *(empty)* | Static token — development/CI only. |
| `VAULT_MOUNT` | `secret` | KV v1 mount path. |
| `VAULT_SECRET_PATH` | `jwks-service` | Key storage prefix. |

## Runtime

- Distroless static base image, runs as UID `65534:65534`.
- Exposes port `8080`.
- No shell, no package manager, no writable filesystem.

## Quick start (development)

```bash
docker run --rm -p 8080:8080 \
  -e VAULT_ADDR=http://host.docker.internal:8200 \
  -e VAULT_TOKEN=root \
  -e LOG_LEVEL=info \
  sirrapa/jwks-server:0.0.1

curl http://localhost:8080/.well-known/jwks.json | jq
```

## Kubernetes

The server is designed for 2+ replicas behind an HPA. A reference manifest is in [`deploy/server/k8s.yaml`](https://github.com/sirrapa/jwks-service/blob/main/deploy/server/k8s.yaml).

Resource baseline:

| | Request | Limit |
|---|---|---|
| CPU | 50m | 200m |
| Memory | 64Mi | 128Mi |

## Compliance

- **BIO** — RSA-4096 keys, ≤ 4-year lifetime, monthly rotation.
- **NIS2 Article 21** — demonstrable key management with audit logs in ECS format.

## License

See the source repository.
