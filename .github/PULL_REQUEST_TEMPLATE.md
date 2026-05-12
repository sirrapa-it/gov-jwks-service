<!--
Thanks for contributing! Please fill in the sections below.
For trivial fixes (typos, docs) you can shorten or remove sections
that don't apply.
-->

## Summary

<!-- What does this PR do? One or two sentences. -->

## Motivation

<!-- Why is this change needed? Link to an issue if applicable: Closes #123 -->

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would alter existing behaviour)
- [ ] Refactor (no functional change)
- [ ] Documentation only
- [ ] Helm chart change
- [ ] CI / tooling change

## Test plan

<!-- How did you verify this change? Include commands and expected output. -->

- [ ] `make test` passes locally
- [ ] `helm lint charts/jwks-service` passes (if chart touched)
- [ ] `helm unittest charts/jwks-service` passes (if chart touched)
- [ ] New code paths have test coverage
- [ ] Manual verification (describe below)

## Architecture / ADR impact

<!--
Does this change a documented architecture decision? If yes:
  - Reference the ADR being modified or superseded.
  - Add a new ADR under docs/adr/ if the decision is new.
Otherwise: "None."
-->

## Backwards compatibility

<!--
For chart changes: does this require a values.yaml migration?
For binary changes: are environment variables, Vault paths, or HTTP
endpoints affected?
Otherwise: "None."
-->

## Checklist

- [ ] I have read [CONTRIBUTING.md](../CONTRIBUTING.md).
- [ ] My commit messages are clear and follow the project style.
- [ ] I have updated documentation (README, chart values, ADRs) where relevant.
- [ ] I have not introduced new external Go dependencies (unless explicitly justified).
- [ ] No secrets, tokens, or production data are included in this PR.
