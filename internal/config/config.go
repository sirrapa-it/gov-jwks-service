// Package config provides environment-based runtime configuration.
// All values are read from environment variables with documented defaults.
//
// # BIO / NIS2 compliance
//
// The default values are chosen to satisfy the Dutch government security
// baseline (BIO) and the NIS2 Directive:
//
//   - RSA 4096 keys satisfy BIO's maximum 4-year key lifetime.
//   - Monthly rotation (ROTATION_SCHEDULE) provides an auditable, demonstrable
//     key management process as required by NIS2 Article 21.
//   - A default GRACE_PERIOD of 2 hours exceeds the 1-hour JWKS cache TTL,
//     ensuring zero-downtime rotation.
//   - A default JWT_MAX_TTL of 15 minutes limits the exposure window of a
//     compromised token (NIS2 Article 21 — principle of least privilege).
package config

import (
	"os"
	"strconv"
	"time"
)

// ServerConfig holds runtime configuration for the server binary.
type ServerConfig struct {
	// ListenAddr is the TCP address the HTTP server binds to.
	// Default: ":8080". Override with LISTEN_ADDR.
	ListenAddr string

	// SyncInterval controls how often the server refreshes its key cache
	// from Vault. A shorter interval reduces the lag between rotation and
	// the server serving the new key.
	// Default: 5m. Override with SYNC_INTERVAL.
	SyncInterval time.Duration

	// ShutdownTimeout is the maximum time to drain in-flight requests.
	// Default: 10s. Override with SHUTDOWN_TIMEOUT.
	ShutdownTimeout time.Duration

	// LogLevel controls the minimum log level. Accepted: debug, info, warn, error.
	// Default: "warn". Override with LOG_LEVEL.
	LogLevel string

	// Vault holds the Vault connection and authentication parameters.
	Vault VaultConfig
}

// RotatorConfig holds runtime configuration for the rotator binary.
type RotatorConfig struct {
	// KeyBits is the RSA key size in bits.
	// BIO: RSA 4096 supports a key lifetime of up to 4 years.
	// Default: 4096. Override with KEY_BITS.
	KeyBits int

	// GracePeriod is how long an old signing key remains in the JWKS response
	// after rotation. Must be >= the longest JWKS cache TTL of any downstream
	// service. NIS2/BIO: 2 hours provides a safety margin above the 1-hour
	// Cache-Control max-age.
	// Default: 2h. Override with GRACE_PERIOD.
	GracePeriod time.Duration

	// LogLevel controls the minimum log level.
	// Default: "warn". Override with LOG_LEVEL.
	LogLevel string

	// Vault holds the Vault connection and authentication parameters.
	Vault VaultConfig
}

// VaultConfig holds HashiCorp Vault connection and authentication parameters.
type VaultConfig struct {
	// Addr is the Vault server URL. Required.
	// Set via VAULT_ADDR.
	Addr string

	// Token is a static Vault token for development and CI only.
	// Set via VAULT_TOKEN. Never use in production.
	Token string

	// K8sRole is the Vault Kubernetes auth role name.
	// When set, the pod service-account JWT is used for authentication.
	// Set via VAULT_K8S_ROLE. Use in production.
	K8sRole string

	// K8sMountPath is the Kubernetes auth method mount path in Vault.
	// Default: "kubernetes". Override with VAULT_K8S_MOUNT.
	K8sMountPath string

	// K8sSATokenPath overrides the default Kubernetes SA token file path.
	// Leave empty in production; used in tests only.
	K8sSATokenPath string

	// Mount is the KV v1 secrets engine mount path.
	// Default: "secret". Override with VAULT_MOUNT.
	Mount string

	// SecretPath is the prefix under which signing keys are stored.
	// Default: "jwks-service". Override with VAULT_SECRET_PATH.
	SecretPath string
}

// Enabled reports whether a Vault address has been configured.
func (v VaultConfig) Enabled() bool { return v.Addr != "" }

// LoadServerConfig reads the server configuration from environment variables.
func LoadServerConfig() *ServerConfig {
	return &ServerConfig{
		ListenAddr:      getEnv("LISTEN_ADDR", ":8080"),
		SyncInterval:    getEnvDuration("SYNC_INTERVAL", 5*time.Minute),
		ShutdownTimeout: getEnvDuration("SHUTDOWN_TIMEOUT", 10*time.Second),
		LogLevel:        getEnv("LOG_LEVEL", "warn"),
		Vault:           loadVaultConfig(),
	}
}

// LoadRotatorConfig reads the rotator configuration from environment variables.
func LoadRotatorConfig() *RotatorConfig {
	return &RotatorConfig{
		KeyBits:     getEnvInt("KEY_BITS", 4096),
		GracePeriod: getEnvDuration("GRACE_PERIOD", 2*time.Hour),
		LogLevel:    getEnv("LOG_LEVEL", "warn"),
		Vault:       loadVaultConfig(),
	}
}

func loadVaultConfig() VaultConfig {
	return VaultConfig{
		Addr:           getEnv("VAULT_ADDR", ""),
		Token:          getEnv("VAULT_TOKEN", ""),
		K8sRole:        getEnv("VAULT_K8S_ROLE", ""),
		K8sMountPath:   getEnv("VAULT_K8S_MOUNT", "kubernetes"),
		K8sSATokenPath: getEnv("VAULT_K8S_SA_TOKEN_PATH", ""),
		Mount:          getEnv("VAULT_MOUNT", "secret"),
		SecretPath:     getEnv("VAULT_SECRET_PATH", "jwks-service"),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
