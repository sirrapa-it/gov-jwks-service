# ADR-005: RS256 as JWT signing algorithm

## Status
Accepted

## Date
2026-04-24

## Context

JWT tokens can be signed with symmetric (HS256) or asymmetric algorithms (RS256,
ES256). With multiple extauth services signing and many backend services verifying,
the algorithm choice has security implications.

## Decision

RS256 (RSASSA-PKCS1-v1_5 with SHA-256).

## Rationale

HS256 requires all verifying parties to possess the shared secret, which would
expose the signing secret to every backend service. RS256 allows the private key
to remain exclusively with the extauth services while the public key is distributed
freely via the JWKS endpoint.

RS256 is chosen over ES256 for broader library support across Java (Spring Security),
Go and Python backends, and because the existing Vault KV infrastructure handles
PKCS#1 PEM natively.

## Consequences

RSA-4096 keys are larger than EC keys (~1800 bytes vs ~100 bytes for P-256),
but this is negligible at the expected request volumes.
