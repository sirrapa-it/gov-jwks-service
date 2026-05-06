# ADR-012: Grace period on key rotation

## Status
Accepted

## Date
2026-04-24

## Context

When a new signing key is activated, downstream services that cached the old JWKS
response will continue using the old key for verification until their cache expires.
Without a grace period, tokens signed with the old key become unverifiable
immediately after rotation.

## Decision

After rotation, the old key remains visible in the JWKS response for `GRACE_PERIOD`
(default 2 hours, configurable). The server syncs from Vault every 5 minutes and
drops keys whose `ExpiresAt` is in the past.

## Rationale

The JWKS endpoint serves `Cache-Control: max-age=3600`. A 2-hour grace period
gives all downstream services at least one full cache cycle to refresh. The maximum
JWT TTL is 15 minutes, so any token issued before rotation will have expired well
before the grace period ends.

For emergency rotation (key compromise), set `GRACE_PERIOD=0s` on the CronJob
invocation to remove the old key immediately. Backend services will encounter a
brief window of validation failures until they refresh their JWKS cache.

## Consequences

Two keys are simultaneously valid during the grace period. The JWKS endpoint
returns both. This is the intended and correct behaviour per RFC 7517.
