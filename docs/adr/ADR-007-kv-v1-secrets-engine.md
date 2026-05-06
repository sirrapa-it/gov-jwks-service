# ADR-007: KV v1 as Vault secrets engine

## Status
Accepted

## Date
2026-04-24

## Context

Vault offers KV v1 (flat key-value) and KV v2 (versioned). KV v2 adds a `data/`
prefix and `metadata/` path to every operation.

## Decision

KV v1. The available Vault installation does not have KV v2 available.

## Rationale

KV v1 has a simpler URL structure. The application manages its own key versioning
via `expires_at` timestamps — Vault version history is not needed. Using KV v1
avoids the `data/` prefix that can cause subtle bugs when mixing environments.

## Consequences

The Vault client uses flat paths: `secret/jwks-service/keys/{kid}` with no
`data/` prefix. If the installation is upgraded to KV v2, the client's `url()`
method requires a single-line change.
