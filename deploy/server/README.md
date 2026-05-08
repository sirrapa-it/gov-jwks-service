# jwks-server

HTTP service that serves a [JWKS](https://datatracker.ietf.org/doc/html/rfc7517) endpoint backed by RSA-4096 signing keys stored in HashiCorp Vault. Used by backend services to verify the signature on internally issued JWTs.

The server is **read-only**: it never writes to Vault. Key creation and rotation are handled by [`sirrapa/jwks-rotator`](https://hub.docker.com/r/sirrapa/jwks-rotator).

- Source: https://github.com/sirrapa/jwks-service
- Companion image: [`sirrapa/jwks-rotator`](https://hub.docker.com/r/sirrapa/jwks-rotator)

## Contents

- [What it serves](#what-it-serves)
- [Architecture](#architecture)
- [Tags and versioning](#tags-and-versioning)
- [Configuration](#configuration)
- [Vault setup](#vault-setup)
- [Quick start (Docker)](#quick-start-docker)
- [Kubernetes deployment](#kubernetes-deployment)
- [Health and readiness](#health-and-readiness)
- [Prometheus metrics](#prometheus-metrics)
- [Logs](#logs)
- [Image internals](#image-internals)
- [Compatibility](#compatibility)
- [Troubleshooting](#troubleshooting)
- [Compliance](#compliance)

## What it serves

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/.well-known/jwks.json` | Public keys in RFC 7517 JWKS format. `Cache-Control: public, max-age=3600`, `X-Content-Type-Options: nosniff`. |
| `GET` | `/healthz` | Kubernetes liveness/readiness probe. Returns `{"status":"ok"}`. |
| `GET` | `/metrics` | Prometheus metrics in text format. |

The image **does not** include `POST /internal/sign`. Token signing lives behind the `signing` Go build tag and is excluded from production images (ADR-009).

### JWKS response shape

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "Rp4IUbmNpISW6guVCWlSCA",
      "n": "0Z3VS5JJcds3xHn...",
      "e": "AQAB"
    }
  ]
}
```

During a rotation grace period (default 2h) the response contains both the new and the previous key — clients with a cached `kid` continue to validate.

## Architecture

```
External request
       │
       ▼
API Gateway ──► extauth-service ──► signs internal JWT
                                          │
                                          ▼
                              Backend services (verify JWT)
                                          │
                                          ▼  GET /.well-known/jwks.json
                                  jwks-server  ◄── HashiCorp Vault (KV v1)
                                       ▲
                                       │ refreshes every SYNC_INTERVAL (default 5m)
                                  jwks-rotator (CronJob, monthly)
```

The server starts with an initial Vault load and then refreshes on a tick. If Vault is empty at startup, the server fails fast (ADR-013) — there is no in-memory fallback.

## Tags and versioning

| Tag form | Example | Use case |
|---|---|---|
| `<major>.<minor>.<patch>` | `0.4.2` | **Production.** Pin exactly. |
| `<major>.<minor>` | `0.4` | Track patch updates within a minor line. |
| `<major>` | `0` | Track minor + patch updates. **Pre-1.0: breaking changes possible in any release.** |
| `sha-<short>` | `sha-1a2b3c4` | Forensic pin to a specific Git SHA. |

Releases follow [Semantic Versioning](https://semver.org/). `latest` is **not** published — pin to a version.

The server and rotator are released in lockstep from the same repository. Use the same version tag for both.

## Configuration

All configuration is read from environment variables. There is no config file.

### Server

| Variable | Default | Description |
|---|---|---|
| `LISTEN_ADDR` | `:8080` | TCP bind address. |
| `SYNC_INTERVAL` | `5m` | How often to refresh keys from Vault. |
| `SHUTDOWN_TIMEOUT` | `10s` | Graceful shutdown drain time on `SIGTERM`. |
| `LOG_LEVEL` | `warn` | One of `debug`, `info`, `warn`, `error`. |

### Vault

| Variable | Default | Description |
|---|---|---|
| `VAULT_ADDR` | *(required)* | Vault server URL, e.g. `https://vault.platform.svc:8200`. |
| `VAULT_K8S_ROLE` | *(empty)* | Kubernetes auth role. **Use this in production.** |
| `VAULT_K8S_MOUNT` | `kubernetes` | Kubernetes auth backend mount path. |
| `VAULT_TOKEN` | *(empty)* | Static Vault token. **Development/CI only — never set this in production.** |
| `VAULT_MOUNT` | `secret` | KV v1 mount path. |
| `VAULT_SECRET_PATH` | `jwks-service` | Key storage prefix under the mount. |

If both `VAULT_K8S_ROLE` and `VAULT_TOKEN` are set, Kubernetes auth wins.

## Vault setup

The server uses **KV v1** (no `data/` prefix in paths). Path layout:

```
secret/jwks-service/active           # {"kid": "...", "rotated_at": "..."}
secret/jwks-service/keys/{kid}       # {pem, kid, created_at, expires_at}
```

### Read-only policy (server)

```hcl
path "secret/jwks-service/active" {
  capabilities = ["read"]
}

path "secret/jwks-service/keys/*" {
  capabilities = ["read", "list"]
}
```

### Kubernetes auth role binding

```bash
vault write auth/kubernetes/role/jwks-service \
    bound_service_account_names=jwks-service \
    bound_service_account_namespaces=platform \
    policies=jwks-service_ro \
    alias_name_source=serviceaccount_name \
    ttl=1h
```

`alias_name_source=serviceaccount_name` is required (ADR-008) — without it, alias collisions can occur after pod restarts.

The token is auto-renewed at 80% of TTL.

## Quick start (Docker)

For local experimentation against a Vault dev server:

```bash
# Terminal 1 — Vault in dev mode
vault server -dev -dev-root-token-id="root"

# Terminal 2 — bootstrap a key with the rotator, then start the server
docker run --rm \
  -e VAULT_ADDR=http://host.docker.internal:8200 \
  -e VAULT_TOKEN=root \
  sirrapa/jwks-rotator:0.0.1

docker run --rm -p 8080:8080 \
  -e VAULT_ADDR=http://host.docker.internal:8200 \
  -e VAULT_TOKEN=root \
  -e LOG_LEVEL=info \
  sirrapa/jwks-server:0.0.1

curl -s http://localhost:8080/.well-known/jwks.json | jq
```

The server **will exit** at startup if no keys are present in Vault. Always run the rotator (or bootstrap Job) first.

## Kubernetes deployment

Reference manifest: [`deploy/server/k8s.yaml`](https://github.com/sirrapa/jwks-service/blob/main/deploy/server/k8s.yaml).

Minimum viable Deployment:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: jwks-service
  namespace: platform
spec:
  replicas: 2
  selector:
    matchLabels: { app: jwks-service }
  template:
    metadata:
      labels: { app: jwks-service }
    spec:
      serviceAccountName: jwks-service
      containers:
        - name: jwks-service
          image: sirrapa/jwks-server:0.0.1
          ports:
            - containerPort: 8080
          env:
            - name: VAULT_ADDR
              value: "https://vault.platform.svc:8200"
            - name: VAULT_K8S_ROLE
              value: "jwks-service"
            - name: LOG_LEVEL
              value: "info"
          readinessProbe:
            httpGet: { path: /healthz, port: 8080 }
            initialDelaySeconds: 3
            periodSeconds: 10
          livenessProbe:
            httpGet: { path: /healthz, port: 8080 }
            initialDelaySeconds: 5
            periodSeconds: 30
          resources:
            requests: { cpu: 50m, memory: 64Mi }
            limits:   { cpu: 200m, memory: 128Mi }
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 65534
            capabilities: { drop: [ALL] }
            seccompProfile: { type: RuntimeDefault }
```

Run **2 or more replicas** behind a Service. The server is fully stateless — any replica can serve any request.

### Resource baseline

| | Request | Limit |
|---|---|---|
| CPU | 50m | 200m |
| Memory | 64Mi | 128Mi |

A single key import is a small allocation (the RSA public key plus its base64-url encoding). Memory usage is dominated by Go runtime overhead, not key material.

## Health and readiness

| Probe | Path | Initial delay | Period | Behaviour |
|---|---|---|---|---|
| Readiness | `/healthz` | 3s | 10s | Returns 200 once at least one key is loaded. |
| Liveness | `/healthz` | 5s | 30s | Always returns 200 while the process is up. |

`/healthz` does **not** call Vault — it is safe to scrape aggressively. Vault connectivity is monitored via `jwks_sync_errors_total` and `jwks_last_sync_timestamp_seconds`.

## Prometheus metrics

Exposed on `GET /metrics`.

| Metric | Type | Description |
|---|---|---|
| `jwks_active_keys` | Gauge | Number of keys currently in the JWKS response. `2` during a rotation grace period. |
| `jwks_active_key_age_seconds` | Gauge | Age of the current active signing key. Alert when this approaches the rotation interval. |
| `jwks_last_sync_timestamp_seconds` | Gauge | Unix timestamp of the last successful Vault key sync. |
| `jwks_sync_errors_total` | Counter | Total failed Vault sync attempts. |

Suggested alerts:

```promql
# No active key — service is broken
jwks_active_keys == 0

# Sync hasn't succeeded in 30 minutes (default SYNC_INTERVAL is 5m)
time() - jwks_last_sync_timestamp_seconds > 1800

# Rotation overdue (NIS2 audit signal) — adjust threshold to your policy
jwks_active_key_age_seconds > 86400 * 35
```

## Logs

Structured JSON, one event per line. All key-lifecycle events follow the [ECS](https://www.elastic.co/guide/en/ecs/current/index.html) schema with:

- `event.category`: `authentication`
- `event.action`: `key.loaded`

Example:

```json
{
  "time": "2026-05-08T09:01:23Z",
  "level": "INFO",
  "msg": "active key loaded",
  "event.action": "key.loaded",
  "event.category": "authentication",
  "kid": "Rp4IUbmNpISW6guVCWlSCA"
}
```

`LOG_LEVEL=info` is recommended for production — it produces one line on startup and one per Vault sync. `debug` is verbose and not suitable for production.

## Image internals

| Property | Value |
|---|---|
| Base image | [`gcr.io/distroless/static`](https://github.com/GoogleContainerTools/distroless) |
| User | `65534:65534` (`nobody`) |
| Shell | None |
| Package manager | None |
| Writable filesystem | None (use `readOnlyRootFilesystem: true`) |
| Exposed port | `8080` |
| Entrypoint | `/jwks-server` |
| Architectures | `linux/amd64` |
| Build | Multi-stage; `CGO_ENABLED=0`, `-trimpath`, `-ldflags "-s -w"` |
| Static analysis | `go test ./... -tags signing` runs in the test stage |

There is no shell in the image, so `kubectl exec` will fail. Use logs and `/metrics` to debug.

## Compatibility

| Component | Required version |
|---|---|
| HashiCorp Vault | 1.13+ (KV v1 has been stable far earlier; tested against 1.13–1.16) |
| Kubernetes | 1.27+ |
| Go (build) | 1.26 |
| Server ↔ Rotator | Match major+minor; patches independent |

Pre-1.0 — any release may contain breaking changes. Consult the [GitHub release notes](https://github.com/sirrapa/jwks-service/releases) before upgrading.

## Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| Pod CrashLoopBackOff at startup with `no signing keys found` | Vault is empty — rotator hasn't run | Run the bootstrap Job from [`deploy/rotator/k8s.yaml`](https://github.com/sirrapa/jwks-service/blob/main/deploy/rotator/k8s.yaml). |
| `vault: 403 permission denied` | Vault policy missing `read` on `secret/jwks-service/*` | Apply the read-only policy above. |
| `vault: 403 invalid role or JWT` | K8s auth role does not bind the `jwks-service` ServiceAccount | Re-run the `vault write auth/kubernetes/role/jwks-service ...` command. |
| `jwks_sync_errors_total` increasing | Network or auth failure to Vault | Check Vault audit log; check `VAULT_ADDR` resolves from the pod. |
| Clients see `kid` not found after rotation | Grace period shorter than client cache TTL | Increase rotator `GRACE_PERIOD` to `>=` client `Cache-Control: max-age`. |
| `503` from `/healthz` | Server is shutting down (`SIGTERM` received) | Normal during rolling deploy. |

## Compliance

| Framework | How this image supports it |
|---|---|
| **BIO** (Baseline Informatiebeveiliging Overheid) | RSA-4096 keys, ≤ 4-year lifetime; monthly rotation enforced by the rotator. |
| **NIS2 Article 21** | Demonstrable, auditable key management. ECS-formatted audit logs on every key event. |

Vault's own audit logging must be enabled separately and is out of scope for this image.

## License

See the source repository.
