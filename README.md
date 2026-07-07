# gov-jwks-service Helm chart repository

This branch hosts the packaged Helm charts and the `index.yaml` published
to GitHub Pages by [chart-releaser-action][cr]. It is updated automatically;
do not commit directly.

## Use the repository

```bash
helm repo add sirrapa https://sirrapa-it.github.io/gov-jwks-service
helm repo update
helm search repo sirrapa/gov-jwks-service --versions
helm install jwks sirrapa/gov-jwks-service \
    -n platform --create-namespace \
    --set vault.addr=https://vault.platform.svc:8200
```

Chart sources live on the [`main`][main] branch under `charts/gov-jwks-service/`.

[cr]: https://github.com/helm/chart-releaser-action
[main]: https://github.com/sirrapa-it/gov-jwks-service/tree/main/charts/gov-jwks-service
