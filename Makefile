IMAGE_REGISTRY ?= ghcr.io/sirrapa-it
VERSION        ?= 0.0.1
GO_BUILD_IMAGE ?= golang:1.22-alpine

SERVER_IMAGE  := $(IMAGE_REGISTRY)/gov-jwks-service:$(VERSION)
ROTATOR_IMAGE := $(IMAGE_REGISTRY)/gov-jwks-rotator:$(VERSION)

.PHONY: build test lint vault-setup bootstrap deploy help

## build: build both Docker images
build: build-server build-rotator

build-server:
	docker build --no-cache \
	  --build-arg GO_BUILD_IMAGE=$(GO_BUILD_IMAGE) \
	  -f deploy/server/Dockerfile \
	  -t $(SERVER_IMAGE) .

build-rotator:
	docker build --no-cache \
	  --build-arg GO_BUILD_IMAGE=$(GO_BUILD_IMAGE) \
	  -f deploy/rotator/Dockerfile \
	  -t $(ROTATOR_IMAGE) .

## push: push both images to the registry
push:
	docker push $(SERVER_IMAGE)
	docker push $(ROTATOR_IMAGE)

## test: run all tests with coverage
test:
	go test -tags signing ./... \
	  -coverprofile=coverage.out \
	  -covermode=atomic
	go tool cover -func=coverage.out

## test-cover: open HTML coverage report
test-cover: test
	go tool cover -html=coverage.out

## lint: run golangci-lint (v2, pinned to match CI)
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not found; install v2 with:"; \
		echo "  go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2"; \
		exit 1; \
	fi

## vault-setup: configure Vault policies and roles
vault-setup:
	bash deploy/vault/setup.sh

## bootstrap: run the bootstrap Job (first deployment only)
bootstrap:
	kubectl apply -f deploy/rotator/k8s.yaml
	kubectl wait --for=condition=complete \
	  --timeout=120s job/jwks-bootstrap -n platform

## deploy: apply all Kubernetes manifests
deploy:
	kubectl apply -f deploy/server/k8s.yaml
	kubectl apply -f deploy/rotator/k8s.yaml

## rotate-now: trigger an emergency rotation (skips normal schedule)
rotate-now:
	kubectl create job --from=cronjob/jwks-rotator \
	  jwks-emergency-$(shell date +%Y%m%d%H%M%S) -n platform

## help: show available targets
help:
	@grep -E '^## ' Makefile | sed 's/## //'
