package config_test

import (
	"os"
	"testing"
	"time"

	"github.com/sirrapa/jwks-service/internal/config"
)

// setEnv sets an env var for the duration of a test and restores it on cleanup.
func setEnv(t *testing.T, key, value string) {
	t.Helper()
	prev, had := os.LookupEnv(key)
	os.Setenv(key, value)
	t.Cleanup(func() {
		if had {
			os.Setenv(key, prev)
		} else {
			os.Unsetenv(key)
		}
	})
}

func clearEnv(t *testing.T, key string) {
	t.Helper()
	prev, had := os.LookupEnv(key)
	os.Unsetenv(key)
	t.Cleanup(func() {
		if had {
			os.Setenv(key, prev)
		}
	})
}

func clearAll(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"LISTEN_ADDR", "SYNC_INTERVAL", "SHUTDOWN_TIMEOUT", "LOG_LEVEL",
		"KEY_BITS", "GRACE_PERIOD",
		"VAULT_ADDR", "VAULT_TOKEN", "VAULT_K8S_ROLE", "VAULT_K8S_MOUNT",
		"VAULT_K8S_SA_TOKEN_PATH", "VAULT_MOUNT", "VAULT_SECRET_PATH",
	} {
		clearEnv(t, k)
	}
}

// ---- ServerConfig defaults --------------------------------------------------

func TestLoadServerConfig_Defaults(t *testing.T) {
	clearAll(t)
	cfg := config.LoadServerConfig()

	if cfg.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q, want :8080", cfg.ListenAddr)
	}
	if cfg.SyncInterval != 5*time.Minute {
		t.Errorf("SyncInterval = %v, want 5m", cfg.SyncInterval)
	}
	if cfg.ShutdownTimeout != 10*time.Second {
		t.Errorf("ShutdownTimeout = %v, want 10s", cfg.ShutdownTimeout)
	}
	if cfg.LogLevel != "warn" {
		t.Errorf("LogLevel = %q, want warn", cfg.LogLevel)
	}
}

func TestLoadServerConfig_Override_ListenAddr(t *testing.T) {
	clearAll(t)
	setEnv(t, "LISTEN_ADDR", ":9090")
	if got := config.LoadServerConfig().ListenAddr; got != ":9090" {
		t.Errorf("ListenAddr = %q, want :9090", got)
	}
}

func TestLoadServerConfig_Override_SyncInterval(t *testing.T) {
	clearAll(t)
	setEnv(t, "SYNC_INTERVAL", "2m")
	if got := config.LoadServerConfig().SyncInterval; got != 2*time.Minute {
		t.Errorf("SyncInterval = %v, want 2m", got)
	}
}

func TestLoadServerConfig_Override_ShutdownTimeout(t *testing.T) {
	clearAll(t)
	setEnv(t, "SHUTDOWN_TIMEOUT", "30s")
	if got := config.LoadServerConfig().ShutdownTimeout; got != 30*time.Second {
		t.Errorf("ShutdownTimeout = %v, want 30s", got)
	}
}

func TestLoadServerConfig_Override_LogLevel(t *testing.T) {
	clearAll(t)
	setEnv(t, "LOG_LEVEL", "debug")
	if got := config.LoadServerConfig().LogLevel; got != "debug" {
		t.Errorf("LogLevel = %q, want debug", got)
	}
}

func TestLoadServerConfig_InvalidSyncInterval_UsesDefault(t *testing.T) {
	clearAll(t)
	setEnv(t, "SYNC_INTERVAL", "not-a-duration")
	if got := config.LoadServerConfig().SyncInterval; got != 5*time.Minute {
		t.Errorf("SyncInterval = %v, want default 5m for bad value", got)
	}
}

func TestLoadServerConfig_InvalidShutdownTimeout_UsesDefault(t *testing.T) {
	clearAll(t)
	setEnv(t, "SHUTDOWN_TIMEOUT", "bad")
	if got := config.LoadServerConfig().ShutdownTimeout; got != 10*time.Second {
		t.Errorf("ShutdownTimeout = %v, want default 10s for bad value", got)
	}
}

// ---- RotatorConfig defaults -------------------------------------------------

func TestLoadRotatorConfig_Defaults(t *testing.T) {
	clearAll(t)
	cfg := config.LoadRotatorConfig()

	if cfg.KeyBits != 4096 {
		t.Errorf("KeyBits = %d, want 4096", cfg.KeyBits)
	}
	if cfg.GracePeriod != 2*time.Hour {
		t.Errorf("GracePeriod = %v, want 2h", cfg.GracePeriod)
	}
	if cfg.LogLevel != "warn" {
		t.Errorf("LogLevel = %q, want warn", cfg.LogLevel)
	}
}

func TestLoadRotatorConfig_Override_KeyBits(t *testing.T) {
	clearAll(t)
	setEnv(t, "KEY_BITS", "2048")
	if got := config.LoadRotatorConfig().KeyBits; got != 2048 {
		t.Errorf("KeyBits = %d, want 2048", got)
	}
}

func TestLoadRotatorConfig_InvalidKeyBits_UsesDefault(t *testing.T) {
	clearAll(t)
	setEnv(t, "KEY_BITS", "not-a-number")
	if got := config.LoadRotatorConfig().KeyBits; got != 4096 {
		t.Errorf("KeyBits = %d, want default 4096 for bad value", got)
	}
}

func TestLoadRotatorConfig_Override_GracePeriod(t *testing.T) {
	clearAll(t)
	setEnv(t, "GRACE_PERIOD", "1h")
	if got := config.LoadRotatorConfig().GracePeriod; got != time.Hour {
		t.Errorf("GracePeriod = %v, want 1h", got)
	}
}

func TestLoadRotatorConfig_InvalidGracePeriod_UsesDefault(t *testing.T) {
	clearAll(t)
	setEnv(t, "GRACE_PERIOD", "bad")
	if got := config.LoadRotatorConfig().GracePeriod; got != 2*time.Hour {
		t.Errorf("GracePeriod = %v, want default 2h for bad value", got)
	}
}

// ---- VaultConfig defaults ---------------------------------------------------

func TestVaultConfig_Defaults(t *testing.T) {
	clearAll(t)
	v := config.LoadServerConfig().Vault

	if v.Addr != "" {
		t.Errorf("Addr = %q, want empty", v.Addr)
	}
	if v.K8sMountPath != "kubernetes" {
		t.Errorf("K8sMountPath = %q, want kubernetes", v.K8sMountPath)
	}
	if v.Mount != "secret" {
		t.Errorf("Mount = %q, want secret", v.Mount)
	}
	if v.SecretPath != "jwks-service" {
		t.Errorf("SecretPath = %q, want jwks-service", v.SecretPath)
	}
}

func TestVaultConfig_Override_AllFields(t *testing.T) {
	clearAll(t)
	setEnv(t, "VAULT_ADDR", "https://vault.example.com:8200")
	setEnv(t, "VAULT_TOKEN", "hvs.test")
	setEnv(t, "VAULT_K8S_ROLE", "my-role")
	setEnv(t, "VAULT_K8S_MOUNT", "k8s-prod")
	setEnv(t, "VAULT_K8S_SA_TOKEN_PATH", "/tmp/token")
	setEnv(t, "VAULT_MOUNT", "kv")
	setEnv(t, "VAULT_SECRET_PATH", "my-service/keys")

	v := config.LoadServerConfig().Vault
	if v.Addr != "https://vault.example.com:8200" {
		t.Errorf("Addr = %q", v.Addr)
	}
	if v.Token != "hvs.test" {
		t.Errorf("Token = %q", v.Token)
	}
	if v.K8sRole != "my-role" {
		t.Errorf("K8sRole = %q", v.K8sRole)
	}
	if v.K8sMountPath != "k8s-prod" {
		t.Errorf("K8sMountPath = %q", v.K8sMountPath)
	}
	if v.K8sSATokenPath != "/tmp/token" {
		t.Errorf("K8sSATokenPath = %q", v.K8sSATokenPath)
	}
	if v.Mount != "kv" {
		t.Errorf("Mount = %q", v.Mount)
	}
	if v.SecretPath != "my-service/keys" {
		t.Errorf("SecretPath = %q", v.SecretPath)
	}
}

// ---- VaultConfig.Enabled ----------------------------------------------------

func TestVaultConfig_Enabled_True(t *testing.T) {
	v := config.VaultConfig{Addr: "https://vault.example.com"}
	if !v.Enabled() {
		t.Error("Enabled() = false, want true when Addr is set")
	}
}

func TestVaultConfig_Enabled_False(t *testing.T) {
	v := config.VaultConfig{}
	if v.Enabled() {
		t.Error("Enabled() = true, want false when Addr is empty")
	}
}
