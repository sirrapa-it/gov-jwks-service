# jwks-rotator

One-shot binary that generates RSA-4096 signing keys, persists them to HashiCorp Vault, and prunes expired keys past their grace period. Designed to run as a Kubernetes `CronJob` (and once at bootstrap as a `Job`) — **never** as a long-running process.

The rotator is the only component that **writes** to Vault. The companion service [`ghcr.io/sirrapa-it/gov-jwks-service`](https://github.com/sirrapa-it/gov-jwks-service/pkgs/container/gov-jwks-service) reads the keys it produces (ADR-013).

- Source: https://github.com/sirrapa-it/gov-jwks-service
- Companion image: [`ghcr.io/sirrapa-it/gov-jwks-service`](https://github.com/sirrapa-it/gov-jwks-service/pkgs/container/gov-jwks-service)

## Contents

- [What it does](#what-it-does)
- [Tags and versioning](#tags-and-versioning)
- [Configuration](#configuration)
- [Vault setup](#vault-setup)
- [Bootstrap (first deployment)](#bootstrap-first-deployment)
- [Monthly CronJob](#monthly-cronjob)
- [Emergency rotation](#emergency-rotation)
- [Quick start (Docker)](#quick-start-docker)
- [Prometheus metrics](#prometheus-metrics)
- [Audit logs (ECS)](#audit-logs-ecs)
- [Failure semantics](#failure-semantics)
- [Image internals](#image-internals)
- [Compatibility](#compatibility)
- [Troubleshooting](#troubleshooting)
- [Compliance](#compliance)

## What it does

On each invocation, in order:

1. **Generate** a new RSA-4096 key pair and persist it to `secret/jwks-service/keys/{kid}` with `created_at`.
2. **Mark** the previously active key with `expires_at = now + GRACE_PERIOD` so the server keeps serving it during the cache window.
3. **Update** `secret/jwks-service/active` to point at the new `kid`.
4. **Prune** any key whose `expires_at` is in the past.
5. **Emit** ECS audit log entries and update Prometheus metrics.

Exit code:
- `0` — rotation (or bootstrap) completed.
- `1` — any step failed; details in the audit log.

The binary terminates after one rotation. There is no internal scheduler — the cadence comes from the Kubernetes CronJob (ADR-011).

### Idempotency

If the rotator runs while a recent rotation is still inside its grace period, a new key is added and the previous becomes the "expiring" one. Running it twice in quick succession is safe but produces an unnecessary key — `concurrencyPolicy: Forbid` on the CronJob avoids overlapping invocations.

## Tags and versioning

| Tag form | Example | Use case |
|---|---|---|
| `<major>.<minor>.<patch>` | `0.4.2` | **Production.** Pin exactly. |
| `<major>.<minor>` | `0.4` | Track patch updates within a minor line. |
| `<major>` | `0` | Track minor + patch updates. **Pre-1.0: breaking changes possible in any release.** |
| `sha-<short>` | `sha-1a2b3c4` | Forensic pin to a specific Git SHA. |

Releases follow [Semantic Versioning](https://semver.org/). `latest` is **not** published — pin to a version. The rotator and server are released in lockstep — use the same version tag for both.

## Configuration

All configuration is read from environment variables.

### Rotator

| Variable | Default | Description |
|---|---|---|
| `KEY_BITS` | `4096` | RSA modulus size. BIO permits ≤ 4-year lifetime for RSA-4096. |
| `GRACE_PERIOD` | `2h` | How long the previous key remains visible after rotation. **Must exceed the JWKS cache TTL** (server sets `Cache-Control: max-age=3600`, so a value below 1h will cause `kid` lookup failures downstream). |
| `LOG_LEVEL` | `warn` | One of `debug`, `info`, `warn`, `error`. |

### Vault

| Variable | Default | Description |
|---|---|---|
| `VAULT_ADDR` | *(required)* | Vault server URL, e.g. `https://vault.platform.svc:8200`. |
| `VAULT_K8S_ROLE` | *(empty)* | Kubernetes auth role. **Use this in production.** |
| `VAULT_K8S_MOUNT` | `kubernetes` | Kubernetes auth backend mount path. |
| `VAULT_TOKEN` | *(empty)* | Static Vault token. **Development/CI only.** |
| `VAULT_MOUNT` | `secret` | KV v1 mount path. |
| `VAULT_SECRET_PATH` | `jwks-service` | Key storage prefix under the mount. |

If both `VAULT_K8S_ROLE` and `VAULT_TOKEN` are set, Kubernetes auth wins.

### Custom / private CA

To trust additional root CAs (e.g. an internal CA fronting Vault), mount the certificate(s) and set `SSL_CERT_DIR` to that directory. The Go runtime reads every PEM file there and adds it to the pool **alongside** the system bundle — no application configuration required.

```bash
docker run --rm \
  -v $(pwd)/certs:/etc/ssl/extra-cas:ro \
  -e SSL_CERT_DIR=/etc/ssl/extra-cas \
  -e VAULT_ADDR=https://vault.internal:8200 \
  -e VAULT_K8S_ROLE=jwks-rotator \
  ghcr.io/sirrapa-it/gov-jwks-rotator:v0.0.2
```

The Helm chart automates this via `trustedCAs.bundles` or `trustedCAs.existingSecret`.

## Vault setup

The rotator uses **KV v1** (no `data/` prefix). Path layout:

```
secret/jwks-service/active           # {"kid": "...", "rotated_at": "..."}
secret/jwks-service/keys/{kid}       # {pem, kid, created_at, expires_at}
```

### Read-write policy (rotator)

```hcl
path "secret/jwks-service/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
```

### Kubernetes auth role binding

```bash
vault write auth/kubernetes/role/jwks-rotator \
    bound_service_account_names=jwks-rotator \
    bound_service_account_namespaces=platform \
    policies=jwks-service_rw \
    alias_name_source=serviceaccount_name \
    ttl=1h
```

The rotator role is **separate** from the server role. Do not give the read-only server policy `delete` capability.

## Bootstrap (first deployment)

Before the server can start, Vault must contain at least one key. Run the rotator once as a Kubernetes `Job`:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: jwks-bootstrap
  namespace: platform
spec:
  backoffLimit: 1
  template:
    spec:
      restartPolicy: Never
      serviceAccountName: jwks-rotator
      containers:
        - name: rotator
          image: ghcr.io/sirrapa-it/gov-jwks-rotator:v0.0.2
          env:
            - name: VAULT_ADDR
              value: "https://vault.platform.svc:8200"
            - name: VAULT_K8S_ROLE
              value: "jwks-rotator"
            - name: LOG_LEVEL
              value: "info"
          resources:
            requests: { cpu: 100m, memory: 64Mi }
            limits:   { cpu: 500m, memory: 128Mi }
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 65534
            capabilities: { drop: [ALL] }
            seccompProfile: { type: RuntimeDefault }
```

Wait for completion, then deploy the server:

```bash
kubectl apply -f bootstrap.yaml
kubectl wait --for=condition=complete job/jwks-bootstrap -n platform --timeout=120s
kubectl apply -f deploy/server/k8s.yaml
```

## Monthly CronJob

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: jwks-rotator
  namespace: platform
spec:
  schedule: "0 2 1 * *"          # 02:00 on the 1st of each month
  concurrencyPolicy: Forbid       # never run two rotations in parallel
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 3
  jobTemplate:
    spec:
      backoffLimit: 0             # do not retry — surfaces failure to the operator
      template:
        spec:
          restartPolicy: Never
          serviceAccountName: jwks-rotator
          containers:
            - name: rotator
              image: ghcr.io/sirrapa-it/gov-jwks-rotator:v0.0.2
              env:
                - name: VAULT_ADDR
                  value: "https://vault.platform.svc:8200"
                - name: VAULT_K8S_ROLE
                  value: "jwks-rotator"
                - name: GRACE_PERIOD
                  value: "2h"
                - name: LOG_LEVEL
                  value: "info"
              resources:
                requests: { cpu: 100m, memory: 64Mi }
                limits:   { cpu: 500m, memory: 128Mi }
              securityContext:
                allowPrivilegeEscalation: false
                readOnlyRootFilesystem: true
                runAsNonRoot: true
                runAsUser: 65534
                capabilities: { drop: [ALL] }
                seccompProfile: { type: RuntimeDefault }
```

Reference manifest: [`deploy/rotator/k8s.yaml`](https://github.com/sirrapa-it/gov-jwks-service/blob/main/deploy/rotator/k8s.yaml).

### Why monthly?

- BIO permits RSA-4096 lifetimes up to four years; monthly rotation provides a wide safety margin.
- NIS2 Article 21 requires a **demonstrable**, auditable key management process. A CronJob with audit logs is auditable; an in-service goroutine isn't (ADR-011).

## Emergency rotation

After a suspected key compromise, rotate immediately by triggering an out-of-schedule run:

```bash
kubectl create job --from=cronjob/jwks-rotator jwks-emergency-$(date +%s) -n platform
```

For instant key expiry (skipping the grace period), patch `GRACE_PERIOD=0s` for that one Job. Be aware that any client with a cached JWKS response will start failing verification until it refreshes.

## Quick start (Docker)

```bash
# Vault dev mode in another terminal:
#   vault server -dev -dev-root-token-id="root"

docker run --rm \
  -e VAULT_ADDR=http://host.docker.internal:8200 \
  -e VAULT_TOKEN=root \
  -e LOG_LEVEL=info \
  ghcr.io/sirrapa-it/gov-jwks-rotator:v0.0.2

# Inspect the result
vault list secret/jwks-service/keys
vault read  secret/jwks-service/active
```

## Prometheus metrics

The rotator process is short-lived and **does not** expose a `/metrics` endpoint. Metrics are emitted to stdout in the audit log and recorded by the server (which scrapes Vault state on its sync tick). The metrics defined for the rotator are:

| Metric | Type | When updated |
|---|---|---|
| `jwks_key_rotations_total` | Counter | After a successful rotation. |
| `jwks_last_rotation_timestamp_seconds` | Gauge | After a successful rotation. |
| `jwks_keys_expired_total` | Counter | Each time an expired key is removed. |
| `jwks_key_rotation_errors_total` | Counter | Any failed rotation attempt. |

Because these come from a one-shot process, the recommended scrape strategy is to use [Prometheus Pushgateway](https://github.com/prometheus/pushgateway) **or** to derive them from logs via a log-based metric pipeline. The default deployment uses the latter: an alert on the absence of a `key.rotated` log line within ~32 days is the simplest reliable signal.

Suggested alerts:

```promql
# No rotation in 32 days (allows for a 2-day grace on the monthly cadence)
time() - max(jwks_last_rotation_timestamp_seconds) > 86400 * 32

# Any rotation failed
increase(jwks_key_rotation_errors_total[1h]) > 0
```

## Audit logs (ECS)

All lifecycle events are JSON, one event per line, with the following ECS fields:

- `event.category`: `authentication`
- `event.action`: one of `key.created`, `key.rotated`, `key.grace_period_started`, `key.expired`

Examples:

```json
{"time":"2026-05-01T02:00:00Z","level":"INFO","msg":"key created","event.action":"key.created","event.category":"authentication","kid":"new-kid","key_bits":4096}
{"time":"2026-05-01T02:00:00Z","level":"INFO","msg":"active key rotated","event.action":"key.rotated","event.category":"authentication","kid":"new-kid","previous_kid":"old-kid"}
{"time":"2026-05-01T02:00:00Z","level":"INFO","msg":"key grace period started","event.action":"key.grace_period_started","event.category":"authentication","kid":"old-kid","grace_until":"2026-05-01T04:00:00Z"}
{"time":"2026-05-01T02:00:00Z","level":"INFO","msg":"expired key removed","event.action":"key.expired","event.category":"authentication","kid":"older-kid","expired_at":"2026-04-30T20:00:00Z"}
```

These events are intended to be ingested into your SIEM. The CronJob keeps the last 3 successful and 3 failed Job logs by default.

## Failure semantics

| Step | If it fails |
|---|---|
| Vault auth | Process exits with code `1`; no key is written. |
| New key generation | Process exits with code `1`; existing active key untouched. |
| New key persist | Process exits with code `1`; existing active key untouched. |
| Mark previous key with `expires_at` | Logs an error and continues — the new key is still promoted. The next rotator run will re-attempt the marking. |
| Update `/active` pointer | Process exits with code `1`; the new key exists in Vault but is not yet served. The next run will succeed and clean up. |
| Prune expired keys | Logs a warning per failed deletion and continues. The next run will retry. |

`backoffLimit: 0` is recommended on the Job/CronJob so that a failed rotation surfaces immediately rather than being masked by retries.

## Image internals

| Property | Value |
|---|---|
| Base image | [`gcr.io/distroless/static`](https://github.com/GoogleContainerTools/distroless) |
| User | `65534:65534` (`nobody`) |
| Shell | None |
| Package manager | None |
| Writable filesystem | None (use `readOnlyRootFilesystem: true`) |
| Exposed ports | None |
| Entrypoint | `/jwks-rotator` |
| Architectures | `linux/amd64` |
| Build | Multi-stage; `CGO_ENABLED=0`, `-trimpath`, `-ldflags "-s -w"` |
| Static analysis | `go test ./... -tags signing` runs in the test stage |

## Compatibility

| Component | Required version |
|---|---|
| HashiCorp Vault | 1.13+ (KV v1) |
| Kubernetes | 1.27+ |
| Go (build) | 1.26 |
| Server ↔ Rotator | Match major+minor; patches independent |

Pre-1.0 — any release may contain breaking changes. Consult the [GitHub release notes](https://github.com/sirrapa-it/gov-jwks-service/releases) before upgrading.

## Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| `vault: 403 permission denied` writing to `secret/jwks-service/keys/...` | Read-only policy attached to the rotator role | Apply the read-write policy from above. |
| Job marked `Failed` immediately | Vault auth failed | Check the rotator's logs for the underlying HTTP status. Verify `VAULT_K8S_ROLE` exists and binds the `jwks-rotator` ServiceAccount. |
| Server pods crash with "no signing keys" after rotation | Rotator deleted the only key (clock skew or `GRACE_PERIOD` set lower than expected) | Inspect `secret/jwks-service/keys/*`; if empty, run the bootstrap Job. Audit `GRACE_PERIOD` configuration. |
| `key.expired` event appears for a key that should still be active | Clock skew between rotator and Vault, or `GRACE_PERIOD < SYNC_INTERVAL + cache TTL` | Verify NTP sync; raise `GRACE_PERIOD` to at least `1h + SYNC_INTERVAL`. |
| Multiple Jobs running concurrently | `concurrencyPolicy: Allow` (or unset) | Set `concurrencyPolicy: Forbid` on the CronJob. |

## Compliance

| Framework | How this image supports it |
|---|---|
| **BIO** (Baseline Informatiebeveiliging Overheid) | RSA-4096 keys, ≤ 4-year lifetime; monthly rotation as defence-in-depth. |
| **NIS2 Article 21** | Demonstrable, auditable key management. ECS-formatted audit events on every key creation, rotation, grace-period start, and expiry. |

Vault's own audit logging must be enabled separately and is out of scope for this image.

## License

See the source repository.
