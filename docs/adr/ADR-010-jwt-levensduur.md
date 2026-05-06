# ADR-010: JWT lifetime of 15 minutes

## Status
Accepted

## Date
2026-04-24

## Context

Internal JWTs issued by extauth services need a lifetime that balances security
(short = smaller exposure window) with operational overhead (short = more frequent
re-issuance).

## Decision

Default JWT lifetime: 15 minutes. Configurable per request via the `ttl` field.

## Rationale

15 minutes is the industry standard for access tokens (AWS STS, Azure AD, Google
Cloud). A compromised token is usable for at most 15 minutes. This is well within
the 2-hour grace period on key rotation, ensuring every valid token can always be
verified until it naturally expires.

NIS2 Article 21 (principle of least privilege) supports short-lived credentials.

## Consequences

Extauth services must implement token refresh for long-running operations.
