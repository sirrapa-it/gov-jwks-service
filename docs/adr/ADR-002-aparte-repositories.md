# ADR-002: Separate repositories for jwks-service and extauth-service

## Status
Accepted

## Date
2026-04-24

## Context

The jwks-service and extauth services are related but serve different purposes.
Should they share a repository (monorepo) or be maintained separately?

## Decision

Separate repositories. Each service has its own lifecycle, CI/CD pipeline and team
ownership.

## Rationale

The services share no code. Their deployment cycles differ: the jwks-service is
a platform component that rarely changes; extauth services change as domain logic
evolves. A commit in one should not trigger a build of the other.

## Consequences

If shared JWT claim structures are needed in the future, a third
`jwt-commons` library repository can be introduced.
