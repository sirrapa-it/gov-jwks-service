# Vault policy for the jwks-rotator (read-write).
# Bind to Vault role: jwks-service_rw
# K8s service account: jwks-rotator (namespace: platform)

# Full access to manage signing keys
path "secret/jwks-service/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
