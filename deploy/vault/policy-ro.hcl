# Vault policy for the jwks-service server (read-only).
# Bind to Vault role: jwks-service_ro
# K8s service account: jwks-service (namespace: platform)

# Read the active key pointer
path "secret/jwks-service/active" {
  capabilities = ["read"]
}

# Read individual signing keys
path "secret/jwks-service/keys/*" {
  capabilities = ["read", "list"]
}
