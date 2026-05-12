# jwks-service Helm chart repository

This branch hosts the packaged Helm charts and the `index.yaml` published
to GitHub Pages by [chart-releaser-action][cr]. It is updated automatically;
do not commit directly.

## Use the repository

```bash
helm repo add sirrapa https://sirrapa.github.io/jwks-service
helm repo update
helm search repo sirrapa/jwks-service --versions
helm install jwks sirrapa/jwks-service \
    -n platform --create-namespace \
    --set vault.addr=https://vault.platform.svc:8200
```

Chart sources live on the [`main`][main] branch under `charts/jwks-service/`.

[cr]: https://github.com/helm/chart-releaser-action
[main]: https://github.com/sirrapa/jwks-service/tree/main/charts/jwks-service
