# jwks-service Helm chart

Deploys the JWKS server (read-only Deployment) and rotator (write-only CronJob) from a single release. Both share a HashiCorp Vault backend (KV v1) but use separate ServiceAccounts and Vault roles.

## TL;DR

```bash
# 1. Bind the ServiceAccounts to Vault roles (one-time, out of band).
#    See "Vault setup" below.

# 2. Install:
helm install jwks ./deploy/helm/jwks-service \
    -n platform --create-namespace \
    --set vault.addr=https://vault.platform.svc:8200
```

The pre-install bootstrap Job runs first to seed Vault with an initial signing key, then the server Deployment rolls out.

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
