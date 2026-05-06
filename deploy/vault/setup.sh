#!/usr/bin/env bash
# Configures Vault for the jwks-service.
# Requires: vault CLI, VAULT_ADDR, VAULT_TOKEN environment variables.
set -euo pipefail

NAMESPACE="${NAMESPACE:-platform}"
K8S_API="${K8S_API:-https://kubernetes.default.svc}"

echo "==> Enabling KV v1 secrets engine"
vault secrets enable -path=secret kv || echo "already enabled"

echo "==> Enabling Kubernetes auth method"
vault auth enable kubernetes || echo "already enabled"

echo "==> Configuring Kubernetes auth"
vault write auth/kubernetes/config kubernetes_host="${K8S_API}"

echo "==> Creating read-only policy (server)"
vault policy write jwks-service_ro deploy/vault/policy-ro.hcl

echo "==> Creating read-write policy (rotator)"
vault policy write jwks-service_rw deploy/vault/policy-rw.hcl

echo "==> Creating Kubernetes auth role for server (read-only)"
vault write auth/kubernetes/role/jwks-service \
    bound_service_account_names=jwks-service \
    bound_service_account_namespaces="${NAMESPACE}" \
    policies=jwks-service_ro \
    alias_name_source=serviceaccount_name \
    ttl=1h

echo "==> Creating Kubernetes auth role for rotator (read-write)"
vault write auth/kubernetes/role/jwks-rotator \
    bound_service_account_names=jwks-rotator \
    bound_service_account_namespaces="${NAMESPACE}" \
    policies=jwks-service_rw \
    alias_name_source=serviceaccount_name \
    ttl=1h

echo "==> Vault setup complete"
vault read auth/kubernetes/role/jwks-service
vault read auth/kubernetes/role/jwks-rotator
