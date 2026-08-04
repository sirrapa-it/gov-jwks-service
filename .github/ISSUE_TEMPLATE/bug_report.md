---
name: Bug report
about: Report a defect in gov-jwks-service or its Helm chart
title: "[bug] "
labels: bug
assignees: ''
---

<!--
For security vulnerabilities do NOT use this template. Follow SECURITY.md.
-->

## Summary

<!-- One sentence describing the bug. -->

## Environment

- jwks-server image tag:        <!-- e.g. ghcr.io/sirrapa-it/gov-jwks-service:0.0.2 -->
- jwks-rotator image tag:       <!-- e.g. ghcr.io/sirrapa-it/gov-jwks-rotator:0.0.2 -->
- Helm chart version:           <!-- e.g. 0.0.2 -->
- Kubernetes version:           <!-- `kubectl version --short` -->
- Vault version + KV backend:   <!-- e.g. 1.16.0, KV v1 -->
- Cloud / distribution:         <!-- e.g. on-prem RKE2, EKS, kind -->

## Reproduction steps

<!--
Minimal, ordered steps that reliably reproduce the bug.
Include `helm install` flags or values.yaml fragments where relevant.
-->

1.
2.
3.

## Expected behaviour

## Actual behaviour

## Logs

<details>
<summary>jwks-server logs</summary>

```
<!-- kubectl logs -n <ns> deploy/<release>-server -->
```

</details>

<details>
<summary>jwks-rotator logs (if relevant)</summary>

```
<!-- kubectl logs -n <ns> job/<release>-rotator-<timestamp> -->
```

</details>

## Additional context

<!-- ADR references, related issues, screenshots, anything else useful. -->
