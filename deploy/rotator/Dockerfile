# hadolint ignore=InvalidDefaultArgInFrom
ARG GO_BUILD_IMAGE=golang:1.27-alpine

FROM ${GO_BUILD_IMAGE} AS deps
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download && go mod verify

FROM deps AS test
COPY . .
ARG GOOS=linux
ARG GOARCH=amd64
ARG LDFLAGS
RUN CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
    go test -ldflags "$LDFLAGS" -count=1 ./...

FROM test AS build
RUN CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
    go build -trimpath -ldflags "-s -w $LDFLAGS" -o /jwks-rotator ./cmd/rotator

FROM gcr.io/distroless/static AS runtime
COPY --from=build /jwks-rotator /jwks-rotator
USER 65534:65534
ENTRYPOINT ["/jwks-rotator"]
