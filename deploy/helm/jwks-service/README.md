# jwks-service Helm chart

Deploys the JWKS server (read-only Deployment) and rotator (write-only CronJob) from a single release. Both share a HashiCorp Vault backend (KV v1) but use separate ServiceAccounts and Vault roles.

## TL;DR

```bash
# 1. Bind the ServiceAccounts to Vault roles (one-time, out of band).
#    See "Vault setup" below.

# 2. Install from the public Helm repo:
helm repo add sirrapa https://sirrapa.github.io/jwks-service
helm repo update
helm install jwks-service sirrapa/jwks-service \
    -n platform --create-namespace \
    --set vault.addr=https://vault.platform.svc:8200

# Or install from a local checkout:
helm install jwks-service ./deploy/helm/jwks-service \
    -n platform --create-namespace \
    --set vault.addr=https://vault.platform.svc:8200
```

The pre-install bootstrap Job runs first to seed Vault with an initial signing key, then the server Deployment rolls out.

## Helm repository

Charts are published to GitHub Pages on every push to `main` that touches `deploy/helm/**` and increases the chart version.

| Field | Value |
|---|---|
| Repo URL | `https://sirrapa.github.io/jwks-service` |
| Add command | `helm repo add sirrapa https://sirrapa.github.io/jwks-service` |
| Search | `helm search repo sirrapa/jwks-service --versions` |

To publish a new version, bump `version` in [`Chart.yaml`](./Chart.yaml) (and `appVersion` if the application changed) and merge to `main`. The CI workflow `Release Helm Chart` packages the chart, creates a GitHub Release with the `.tgz` attached, and updates `index.yaml` on the `gh-pages` branch.

## Prerequisites

| Prerequisite | Notes |
|---|---|
| Kubernetes ≥ 1.27 | Required for `CronJob` v1 GA semantics. |
| HashiCorp Vault, KV v1 | Server and rotator both authenticate via the Kubernetes auth backend. |
| Two Vault policies | `jwks-service_ro` and `jwks-service_rw` — see below. |
| `monitoring.coreos.com` CRDs | Only needed if `monitoring.serviceMonitor.enabled` or `monitoring.prometheusRule.enabled` is `true`. |

## Installation

```bash
helm install jwks ./deploy/helm/jwks-service \
    -n platform --create-namespace \
    --values my-values.yaml
```

The chart uses Helm hooks (`pre-install`) for the bootstrap so the server doesn't crash-loop on first install. The rotator ServiceAccount is also a `pre-install` hook to ensure it exists before the bootstrap Job runs — this means it lingers after `helm uninstall`. Delete it manually if you fully tear down the release:

```bash
kubectl -n platform delete sa $(kubectl -n platform get sa -l app.kubernetes.io/component=rotator -o name)
```

## Configuration

The full set of values is in [`values.yaml`](./values.yaml). Highlights:

### Vault

| Key | Default | Notes |
|---|---|---|
| `vault.addr` | `https://vault.platform.svc:8200` | Vault server URL. |
| `vault.k8sMount` | `kubernetes` | Vault Kubernetes auth mount path. |
| `vault.k8sRole.server` | `jwks-service` | Read-only role bound to the server SA. |
| `vault.k8sRole.rotator` | `jwks-rotator` | Read-write role bound to the rotator SA. |
| `vault.mount` | `secret` | KV v1 mount. |
| `vault.secretPath` | `jwks-service` | Key storage prefix (no `data/`, KV v1). |

### Trusted CAs

| Key | Default | Notes |
|---|---|---|
| `trustedCAs.bundles` | `{}` | Inline map of `<name>: <PEM>`. Each becomes a `<name>.crt` file in the trust directory. |
| `trustedCAs.existingSecret` | `""` | Reference an existing Secret. Every key whose value is a PEM cert is trusted. Wins over `bundles`. |
| `trustedCAs.mountPath` | `/etc/ssl/jwks-service-cas` | Where the certs are mounted. Set as `SSL_CERT_DIR`. |

The chart adds custom root CAs to the **Go runtime trust store** via `SSL_CERT_DIR`. Because the chart leaves `SSL_CERT_FILE` unset, distroless's bundled `/etc/ssl/certs/ca-certificates.crt` keeps loading public CAs — the `SSL_CERT_DIR` certs are **additive**.

No application code or env vars (`VAULT_CACERT`, etc.) are required: the runtime picks up the certificates automatically for every outbound TLS call (Vault today, any future external service tomorrow).

**Inline bundles** — chart creates and mounts a Secret automatically. Use any number:

```yaml
trustedCAs:
  bundles:
    vault-ca: |
      -----BEGIN CERTIFICATE-----
      MIID...
      -----END CERTIFICATE-----
    sirrapa-root: |
      -----BEGIN CERTIFICATE-----
      MIID...
      -----END CERTIFICATE-----
```

**Existing Secret** — useful when the CAs are managed by cert-manager / external-secrets / another release. Every key in the Secret whose value is a PEM cert becomes trusted:

```yaml
trustedCAs:
  existingSecret: corp-trust-bundle
```

The pod template carries a `checksum/trusted-cas` annotation, so editing `bundles` and `helm upgrade` triggers a rolling restart. For `existingSecret` rotations, restart manually or use [stakater/Reloader](https://github.com/stakater/Reloader).

### Server

| Key | Default | Notes |
|---|---|---|
| `server.image.repository` | `sirrapa/jwks-server` | |
| `server.image.tag` | `""` | Falls back to `.Chart.AppVersion`. |
| `server.replicaCount` | `2` | Ignored when `server.autoscaling.enabled=true`. |
| `server.autoscaling.enabled` | `true` | HPA on CPU. |
| `server.autoscaling.minReplicas` | `2` | |
| `server.autoscaling.maxReplicas` | `5` | |
| `server.config.syncInterval` | `5m` | Vault refresh cadence. |
| `server.config.logLevel` | `warn` | `debug` / `info` / `warn` / `error`. |
| `server.podDisruptionBudget.enabled` | `true` | `minAvailable: 1` by default. |
| `server.extraEnv` / `server.extraEnvFrom` | `[]` | Inject extra env (e.g. from secrets/configmaps). |

### Rotator

| Key | Default | Notes |
|---|---|---|
| `rotator.image.repository` | `sirrapa/jwks-rotator` | |
| `rotator.config.keyBits` | `4096` | RSA modulus size. |
| `rotator.config.gracePeriod` | `2h` | Must exceed JWKS `Cache-Control: max-age` (1h). |
| `rotator.cronjob.schedule` | `0 2 1 * *` | Monthly at 02:00 UTC, day 1. |
| `rotator.cronjob.timeZone` | `""` | Set e.g. `"Europe/Amsterdam"` (K8s ≥ 1.27). |
| `rotator.cronjob.concurrencyPolicy` | `Forbid` | Never run two rotations in parallel. |
| `rotator.bootstrap.enabled` | `true` | First-install Helm hook that seeds the initial key. |

### Monitoring

| Key | Default |
|---|---|
| `monitoring.serviceMonitor.enabled` | `false` |
| `monitoring.prometheusRule.enabled` | `false` |

The chart's PrometheusRule covers four alerts — see `monitoring.prometheusRule.alerts.*` to enable/adjust each.

## Vault setup

KV v1 paths (no `data/` prefix):

```
secret/jwks-service/active           # {"kid": "...", "rotated_at": "..."}
secret/jwks-service/keys/{kid}       # {pem, kid, created_at, expires_at}
```

Read-only policy `jwks-service_ro` (server):

```hcl
path "secret/jwks-service/active" {
  capabilities = ["read"]
}
path "secret/jwks-service/keys/*" {
  capabilities = ["read", "list"]
}
```

Read-write policy `jwks-service_rw` (rotator):

```hcl
path "secret/jwks-service/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
```

Bind both ServiceAccounts to their roles:

```bash
vault write auth/kubernetes/role/jwks-service \
    bound_service_account_names=<release>-jwks-service-server \
    bound_service_account_namespaces=platform \
    policies=jwks-service_ro \
    alias_name_source=serviceaccount_name \
    ttl=1h

vault write auth/kubernetes/role/jwks-rotator \
    bound_service_account_names=<release>-jwks-service-rotator \
    bound_service_account_namespaces=platform \
    policies=jwks-service_rw \
    alias_name_source=serviceaccount_name \
    ttl=1h
```

The ServiceAccount names follow the pattern `<release-name>-jwks-service-<component>` by default. Override with `server.serviceAccount.name` and `rotator.serviceAccount.name` to use stable names.

## Bootstrap behaviour

When `rotator.bootstrap.enabled=true` (default):

1. `pre-install` hook: rotator ServiceAccount is created (annotation `helm.sh/hook-delete-policy: before-hook-creation`).
2. `pre-install` hook: bootstrap Job runs (annotation `helm.sh/hook-delete-policy: before-hook-creation,hook-succeeded`). The Job creates the first key in Vault and exits.
3. Regular install phase: server Deployment + Service + HPA + CronJob are applied.

On `helm upgrade`, the bootstrap does **not** re-run — the hook is `pre-install` only. The CronJob handles all subsequent rotations.

For environments where Vault already contains keys (e.g. installing into a namespace that previously had this chart), set `rotator.bootstrap.enabled=false`.

## Upgrading

```bash
helm upgrade jwks ./deploy/helm/jwks-service -n platform --reuse-values
```

The chart and image versions are released in lockstep — the chart's `appVersion` matches the image tag. Pin both:

```yaml
server:
  image:
    tag: "0.1.2"
rotator:
  image:
    tag: "0.1.2"
```

## Uninstalling

```bash
helm uninstall jwks -n platform
```

Hook resources (rotator ServiceAccount) and Vault keys are **not** removed. To fully clean up:

```bash
kubectl -n platform delete sa -l app.kubernetes.io/component=rotator
vault delete secret/jwks-service/active
vault list secret/jwks-service/keys/ | xargs -I {} vault delete secret/jwks-service/keys/{}
```

## Troubleshooting

| Symptom | Action |
|---|---|
| Bootstrap Job times out | Inspect `kubectl logs job/<release>-jwks-service-rotator-bootstrap`. Most common cause: Vault role not yet bound to the rotator SA. |
| Server pods CrashLoopBackOff with "no signing keys" | The bootstrap Job failed (or `bootstrap.enabled=false` and Vault is empty). Run the rotator manually with `kubectl create job --from=cronjob/<release>-jwks-service-rotator ...`. |
| `helm install` fails after timeout but resources exist | Re-run `helm upgrade --install` — the chart is idempotent. The bootstrap hook will be skipped on the upgrade. |
| ServiceMonitor / PrometheusRule not picked up | Ensure the kube-prometheus-stack `Prometheus` resource selects this namespace (or set `monitoring.serviceMonitor.labels` to match the operator's selector). |
