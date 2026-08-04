# Contributing to jwks-service

Thanks for taking the time to contribute. This document covers the
development workflow, testing expectations, and review process.

## Code of Conduct

Participation in this project is governed by our
[Code of Conduct](CODE_OF_CONDUCT.md). By participating you agree to uphold
it.

## Reporting bugs and requesting features

- **Bugs**: use the [bug report](.github/ISSUE_TEMPLATE/bug_report.md) issue
  template. Include the chart/image version, Kubernetes version, and a
  minimal reproduction.
- **Features**: use the [feature request](.github/ISSUE_TEMPLATE/feature_request.md)
  template. State the problem first, the proposed solution second.
- **Security**: do **not** open a public issue. Follow [SECURITY.md](SECURITY.md).

## Development environment

Required tooling:

- Go (version pinned in `go.mod`)
- Docker (for image builds)
- Helm v3.13+ (chart development)
- `helm-unittest` plugin (chart tests):
  ```bash
  helm plugin install https://github.com/helm-unittest/helm-unittest --verify=false
  ```

## Building and testing

The `Makefile` is the canonical entry point:

```bash
# Run Go tests with coverage (mirrors CI)
make test

# Build both Docker images
make build

# Lint
make lint
```

Two build tags are relevant:

- Default build excludes the `/internal/sign` endpoint (production server).
- `-tags signing` enables it for tests and local debugging (see ADR-009).

### Coverage targets

- `internal/` packages: **100%**.
- `cmd/` packages: **≥95%** (excluding `main()` which calls `os.Exit`).

CI fails if total coverage drops below 95%.

### Helm chart tests

```bash
helm lint charts/gov-jwks-service
helm unittest charts/gov-jwks-service
```

Test suites live under `charts/gov-jwks-service/tests/`. Each template has
its own suite plus a cross-template suite for the trustedCAs helpers.

## Pull request process

1. **Branch from `main`.** Use a descriptive branch name (`fix/...`,
   `feat/...`, `chore/...`).
2. **Keep changes focused.** One concern per PR. Refactors that touch the
   same lines as a fix should be split.
3. **Add or update tests.** New code paths need test coverage; new chart
   values need a helm-unittest assertion.
4. **Update documentation.** README, chart values, and ADRs where relevant.
5. **Run the full test suite locally** before pushing.
6. **Fill in the PR template** including the test plan and any ADR impact.
7. **Resolve review feedback in new commits** (don't force-push) until the
   PR is approved. Squash on merge is fine.

## Architecture decisions

Significant design changes warrant a new ADR under `docs/adr/`. Use the
existing ADRs as a template. Keep them short — context, decision,
consequences. Do not modify accepted ADRs except to mark them superseded.

## Conventions

- Module path: `github.com/sirrapa-it/gov-jwks-service`.
- All comments, commit messages, and documentation in **English**.
- No external Go dependencies except `github.com/prometheus/client_golang`.
- Vault KV v1 (not v2) — no `data/` prefix in paths.
- The server **never** writes to Vault. Only the rotator writes.

## Commit messages

Use the imperative mood, scoped to one concern:

```
Add helm-unittest suite for cronjob template

Cover schedule, concurrencyPolicy, image, env, and the trusted-CAs
mount when bundles are configured.
```

Reference issues in the body (`Closes #42`) rather than the subject.

## Release process

Container images are published on tag push (`v*.*.*`) by
`.github/workflows/release.yml`. They carry the same `v` prefix as the git
tag: `v1.2.3`, `v1.2`, `v1`. The Helm chart is published on push to `main`
under `charts/**` by `.github/workflows/chart-release.yml`.

Bump `Chart.yaml`'s `version` and `appVersion` together when releasing. Note
that the two use different formats: `appVersion` is the image tag and carries
the `v` prefix (`"v1.2.3"`), while `version` is the chart's own version and
must be bare SemVer (`1.2.3`) — Helm and `chart-releaser` build the package
filename from it.

## Licensing

By submitting a contribution, you agree that your work is licensed under the
[Apache License 2.0](LICENSE) that governs this project.
