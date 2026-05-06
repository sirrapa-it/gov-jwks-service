# ADR-004: Go standard library only — no external Vault SDK

## Status
Accepted

## Date
2026-04-24

## Context

The jwks-service and rotator communicate with HashiCorp Vault. The official
HashiCorp Vault Go SDK is available, but so is a hand-rolled HTTP client.

## Decision

Use the Go standard library (`net/http`, `encoding/json`) with no external SDK.
The only external dependency is `github.com/prometheus/client_golang`.

## Rationale

The service needs exactly four Vault operations: `PUT`, `GET`, `LIST`, `DELETE` on
KV v1, plus Kubernetes auth login. The full SDK adds hundreds of KB and dozens of
transitive dependencies for features we never use. A minimal client is easier to
audit, test with `httptest`, and maintain across Vault upgrades.

## Consequences

New Vault features (e.g. different auth methods) must be implemented manually.
The `SecretStore` interface abstracts the client, so switching to the SDK later
requires only a new implementation — no changes to keystore or handler packages.
