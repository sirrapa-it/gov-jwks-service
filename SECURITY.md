# Security Policy

## Reporting a Vulnerability

**Please do not file public GitHub issues for security vulnerabilities.**

Report suspected vulnerabilities privately via GitHub's Security Advisory
mechanism:

> https://github.com/sirrapa/jwks-service/security/advisories/new

Provide as much detail as you can:

- Affected versions (image tag or chart version).
- A description of the issue and its impact.
- Steps to reproduce, or a proof-of-concept.
- Any mitigating factors you are aware of.

We will acknowledge receipt within **5 working days** and aim to provide an
initial assessment within **10 working days**. Once a fix is available we will
coordinate a disclosure timeline with you.

## Supported Versions

Security fixes are issued for the latest `MAJOR.MINOR` release line of both
the container images (`sirrapa/jwks-server`, `sirrapa/jwks-rotator`) and the
Helm chart. Older minor versions are best-effort.

## Scope

In scope:

- The `cmd/server` and `cmd/rotator` binaries.
- The published Docker images.
- The Helm chart under `deploy/helm/jwks-service/`.
- The Vault interaction code paths (`internal/vault`, `internal/keystore`).

Out of scope:

- Misconfiguration of the deploying cluster, Vault, or upstream identity
  providers — those are the operator's responsibility.
- Findings that require an already-compromised cluster, node, or Vault
  operator credential.
- Denial-of-service through resource exhaustion against a single replica
  (the chart provisions ≥2 replicas + HPA by default).
