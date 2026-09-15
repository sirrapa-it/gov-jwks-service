# hadolint ignore=InvalidDefaultArgInFrom
ARG GO_BUILD_IMAGE=golang:1.27-alpine

# ── Stage 1: dependencies ────────────────────────────────────────────────────
FROM ${GO_BUILD_IMAGE} AS deps
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# ── Stage 2: test ─────────────────────────────────────────────────────────────
FROM deps AS test
COPY . .
ARG GOOS=linux
ARG GOARCH=amd64
ARG LDFLAGS
RUN CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
    go test -tags signing -ldflags "$LDFLAGS" -count=1 ./...

# ── Stage 3: build ────────────────────────────────────────────────────────────
FROM test AS build
RUN CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
    go build -trimpath -ldflags "-s -w $LDFLAGS" -o /jwks-server ./cmd/server

# ── Stage 4: runtime ──────────────────────────────────────────────────────────
FROM gcr.io/distroless/static AS runtime
COPY --from=build /jwks-server /jwks-server
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["/jwks-server"]
