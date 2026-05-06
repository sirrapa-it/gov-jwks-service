# ADR-003: Shared keypair for all extauth services

## Status
Accepted

## Date
2026-04-24

## Context

Multiple extauth services issue internal JWTs. Should each service have its own
keypair, or should all services share one keypair?

## Decision

All extauth services use the same RSA keypair managed by the jwks-service.

## Rationale

With a shared keypair there is one JWKS endpoint and one trust anchor. Backend
services configure a single issuer URL. With per-service keypairs, backend services
would need to trust multiple issuers or the JWKS endpoint would need to bundle
multiple keys with associated issuer metadata — significant added complexity.

Domain isolation is expressed in JWT claims (`aud`, `roles`) not in the signing key.

## Consequences

If the private key is compromised, all services are affected. This is mitigated by
Vault audit logging, short JWT TTL (15 min) and a monthly rotation schedule.
