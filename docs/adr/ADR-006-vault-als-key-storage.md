# ADR-006: HashiCorp Vault as key storage

## Status
Accepted

## Date
2026-04-24

## Context

RSA private keys must be stored securely and be accessible across pod restarts and
replicas. Options considered: HashiCorp Vault, Kubernetes Secrets, HSM.

## Decision

HashiCorp Vault with KV v1 secrets engine.

## Rationale

Vault is already present in the infrastructure. It provides fine-grained access
control (per-service policies), full audit logging (every read is logged), and
Kubernetes-native authentication. Kubernetes Secrets are stored unencrypted in etcd
by default and offer coarser RBAC than Vault policies. An HSM would require
significant investment not justified by the current threat model.

## Consequences

Vault is a critical dependency. The server caches keys in memory so a Vault outage
does not immediately affect the JWKS endpoint, but new keys after rotation cannot
be loaded until Vault is available again.
