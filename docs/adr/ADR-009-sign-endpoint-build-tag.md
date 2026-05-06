# ADR-009: /internal/sign endpoint behind signing build tag

## Status
Accepted

## Date
2026-04-24

## Context

The `POST /internal/sign` endpoint is useful for integration tests and local
development but must never be reachable in production — it allows arbitrary JWT
creation.

Options: always compile and gate with an environment variable; compile only when
a build tag is present; remove entirely.

## Decision

The endpoint is compiled only when the `signing` build tag is explicitly provided.
By default (and in production builds) the endpoint does not exist in the binary.

## Rationale

An environment variable gate means the code exists in the production binary and
could be accidentally activated by a misconfigured ConfigMap. A build tag provides
a compile-time guarantee: if the tag is absent, there is literally no code path
that could serve the endpoint. This is more robust than a runtime check.

## Consequences

Developers must pass `-tags signing` when they want to use the sign endpoint
locally or in integration tests. This is documented in the README and CLAUDE.md.
