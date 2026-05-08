# jwks-rotator

One-shot binary that generates RSA-4096 signing keys, persists them to HashiCorp Vault, and prunes expired keys past their grace period. Designed to run as a Kubernetes `CronJob`, **not** as a long-running process.

Companion image: [`sirrapa/jwks-server`](https://hub.docker.com/r/sirrapa/jwks-server) reads the keys this rotator writes.

Source: https://github.com/sirrapa/jwks-service

## What it does on each run

1. Generates a new RSA-4096 key pair, persists it to Vault.
2. Marks the previously active key with `ExpiresAt = now + GRACE_PERIOD`.
3. Updates the `/active` pointer to the new key.
4. Deletes any key whose `ExpiresAt` is already in the past.
5. Emits ECS-compatible audit log entries (`event.action`: `key.created`, `key.rotated`, `key.grace_period_started`, `key.expired`).

Exit code `0` on success, `1` on failure. Use `concurrencyPolicy: Forbid` on the CronJob.

## Tags

| Tag | Meaning |
|---|---|
| `0.1.2` | Exact version. |
| `0.1` / `0` | Floating major / minor. |
| `sha-<short>` | Git SHA pin for forensic traceability. |

Pin to an exact version in production.

## Configuration

All configuration is read from environment variables.

### Rotator

| Variable | Default | Description |
|---|---|---|
| `KEY_BITS` | `4096` | RSA key size. BIO permits up to a 4-year lifetime for RSA-4096. |
| `GRACE_PERIOD` | `2h` | How long the previous key remains visible after rotation. Must exceed the JWKS cache TTL (1h). |
| `LOG_LEVEL` | `warn` | `debug` / `info` / `warn` / `error`. |

### Vault

| Variable | Default | Description |
|---|---|---|
| `VAULT_ADDR` | *(required)* | Vault server URL. |
| `VAULT_K8S_ROLE` | *(empty)* | Kubernetes auth role — use in production. The rotator role needs read+write on the `jwks-service` path. |
| `VAULT_K8S_MOUNT` | `kubernetes` | Kubernetes auth mount path. |
| `VAULT_TOKEN` | *(empty)* | Static token — development/CI only. |
| `VAULT_MOUNT` | `secret` | KV v1 mount path. |
| `VAULT_SECRET_PATH` | `jwks-service` | Key storage prefix. |

## Runtime

- Distroless static base image, runs as UID `65534:65534`.
- No exposed ports.
- No shell, no package manager, no writable filesystem.

## Bootstrap and rotation cadence

| Run type | When | Manifest |
|---|---|---|
| Bootstrap `Job` | Once, before the server starts | [`deploy/rotator/k8s.yaml`](https://github.com/sirrapa/jwks-service/blob/main/deploy/rotator/k8s.yaml) |
| Monthly `CronJob` | `0 2 1 * *` | same manifest |
| Emergency `Job` | Manual, on incident | `kubectl create job --from=cronjob/jwks-rotator jwks-emergency-$(date +%s)` |

Resource baseline:

| | Request | Limit |
|---|---|---|
| CPU | 100m | 500m |
| Memory | 64Mi | 128Mi |

## Compliance

- **BIO** — RSA-4096, monthly rotation as a defence-in-depth measure.
- **NIS2 Article 21** — demonstrable, auditable key management. Audit events are emitted in ECS format on every rotation.

## License

See the source repository.
