# ADR-011: Key rotation via CronJob, not in-service goroutine

## Status
Accepted

## Date
2026-04-24

## Context

With multiple server replicas, an in-service rotation goroutine causes race
conditions: two replicas can simultaneously generate different keys, both write
to Vault, and end up with divergent in-memory caches. This leads to inconsistent
JWKS responses and JWT validation failures.

Options: in-service goroutine with leader election; separate CronJob.

## Decision

Key rotation runs as a Kubernetes CronJob (`concurrencyPolicy: Forbid`) separate
from the server Deployment. The server is purely read-only.

## Rationale

A CronJob with `concurrencyPolicy: Forbid` provides the "at most one instance
running" guarantee without implementing distributed locking (leader election).
It also enforces the separation of concerns in Vault policies: the server
ServiceAccount has a read-only policy and cannot write keys even if a bug
were to attempt it.

This is the pattern used by Keycloak, Dex and other production identity providers.

## Consequences

The server must be bootstrapped (run the rotator at least once) before the first
deployment. The CronJob must be monitored — a failed rotation is not immediately
visible from the server's perspective.
