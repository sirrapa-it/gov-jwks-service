# ADR-013: Server binary is read-only — no in-memory fallback

## Status
Accepted

## Date
2026-04-24

## Context

The previous iteration of the service had an in-memory fallback: if `VAULT_ADDR`
was not set, keys were generated in memory (lost on restart). This was convenient
for local development but created a footgun — a misconfigured production deployment
would silently start with ephemeral keys.

## Decision

The server binary requires Vault to be configured and to contain at least one
valid signing key. If either condition is not met, the server exits with code 1.
There is no in-memory fallback.

## Rationale

Failing fast with a clear error message is safer than silently degrading. A
production operator who forgets to set `VAULT_ADDR` will see an immediate crash
loop with a descriptive log message, rather than discovering the problem after
JWTs fail to verify because keys changed on every pod restart.

For local development, a local Vault in dev mode (`vault server -dev`) is a
one-command setup and is documented in the README.

## Consequences

The rotator must be run at least once before the server can start. This is enforced
by the bootstrap Job in `deploy/rotator/k8s.yaml`.
