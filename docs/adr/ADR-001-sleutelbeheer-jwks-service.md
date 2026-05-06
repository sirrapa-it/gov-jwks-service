# ADR-001: Key management centralised in the jwks-service

## Status
Accepted

## Date
2026-04-24

## Context

Multiple extauth services (one per domain: zaak, boete, inning, etc.) need to sign
internal JWTs with the same keypair so backend services can verify them via a single
JWKS endpoint. Someone has to own the keypair — the jwks-service or one of the
extauth services.

**Option A — jwks-service owns the keys**
The jwks-service generates, stores and rotates the keypair. Extauth services read
the private key from Vault and sign locally.

**Option B — extauth-service owns the keys**
One extauth service generates and rotates the keypair. The jwks-service reads only
the public key.

## Decision

Option A: the jwks-service is the sole owner of the RSA keypair. Only the rotator
binary (jwks-service) has write access to Vault. All extauth services have read-only
access.

## Rationale

With multiple extauth services, Option B introduces ambiguity: which extauth service
owns the key? Rotation logic would need to live in one of them, giving it a special
role. Option A keeps a single, clear responsibility boundary.

## Consequences

- New extauth services only require a read-only Vault policy
- Rotation logic is implemented and tested in one place
- Extauth services depend on Vault being available to read the private key
  (mitigated by in-memory caching)
