# Architecture Decision Records

This directory contains all Architecture Decision Records (ADRs) for the
jwks-service and the surrounding JWT authentication chain.

## Index

| ADR | Title | Status |
|---|---|---|
| [ADR-001](ADR-001-sleutelbeheer-jwks-service.md) | Key management centralised in the jwks-service | Accepted |
| [ADR-002](ADR-002-aparte-repositories.md) | Separate repositories for jwks-service and extauth-service | Accepted |
| [ADR-003](ADR-003-gedeeld-keypair.md) | Shared keypair for all extauth services | Accepted |
| [ADR-004](ADR-004-stdlib-geen-vault-sdk.md) | Go standard library only — no external Vault SDK | Accepted |
| [ADR-005](ADR-005-rs256-signing-algoritme.md) | RS256 as JWT signing algorithm | Accepted |
| [ADR-006](ADR-006-vault-als-key-storage.md) | HashiCorp Vault as key storage | Accepted |
| [ADR-007](ADR-007-kv-v1-secrets-engine.md) | KV v1 as Vault secrets engine | Accepted |
| [ADR-008](ADR-008-kubernetes-vault-auth.md) | Kubernetes auth method for Vault | Accepted |
| [ADR-009](ADR-009-sign-endpoint-build-tag.md) | /internal/sign behind signing build tag | Accepted |
| [ADR-010](ADR-010-jwt-levensduur.md) | JWT lifetime of 15 minutes | Accepted |
| [ADR-011](ADR-011-cronjob-rotatie.md) | Key rotation via CronJob, not in-service goroutine | Accepted |
| [ADR-012](ADR-012-grace-period-key-rotatie.md) | Grace period on key rotation | Accepted |
| [ADR-013](ADR-013-server-read-only.md) | Server binary is read-only — no in-memory fallback | Accepted |

## Statuses

| Status | Meaning |
|---|---|
| Proposed | Under discussion, not yet decided |
| Accepted | Approved and implemented |
| Deprecated | Superseded by a later ADR |

## Template

```markdown
# ADR-NNN: Title

## Status
Proposed

## Date
YYYY-MM-DD

## Context
Describe the situation and the problem.

## Decision
Describe the chosen solution.

## Rationale
Why was this choice made?

## Consequences
What are the trade-offs?
```
