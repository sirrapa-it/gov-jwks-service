# ADR-008: Kubernetes auth method for Vault

## Status
Accepted

## Date
2026-04-24

## Context

Services in the Kubernetes cluster need to authenticate with Vault. Options:
static token, AppRole, Kubernetes auth.

## Decision

Kubernetes auth (`alias_name_source=serviceaccount_name`) for production.
Static token (`VAULT_TOKEN`) is permitted for local development and CI only.

## Rationale

Kubernetes auth requires no static secrets to be managed — the pod uses its
auto-mounted service account JWT. Tokens are short-lived (1h) and renewed
automatically. `alias_name_source=serviceaccount_name` ties the Vault identity
to the service account name rather than the UID, making it stable across
pod restarts and namespace re-creations.

## Consequences

Vault must be able to reach the Kubernetes API server to verify tokens.
Each service requires a dedicated service account and a corresponding Vault role.
