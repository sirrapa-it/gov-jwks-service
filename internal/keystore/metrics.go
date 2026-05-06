package keystore

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// activeKeysGauge is the number of keys currently in the JWKS response.
	// During a grace period this will be 2 (old + new key).
	activeKeysGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "jwks_active_keys",
		Help: "Number of signing keys currently present in the JWKS response.",
	})

	// activeKeyAgeSeconds is the age of the current signing key in seconds.
	// Used to alert when rotation is overdue (NIS2/BIO compliance).
	activeKeyAgeSeconds = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "jwks_active_key_age_seconds",
		Help: "Age in seconds of the current active signing key.",
	})

	// lastSyncTimestamp is the Unix timestamp of the last successful Vault sync.
	lastSyncTimestamp = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "jwks_last_sync_timestamp_seconds",
		Help: "Unix timestamp of the last successful Vault key sync by the server.",
	})

	// syncErrorsTotal counts failed Vault sync attempts by the server.
	syncErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "jwks_sync_errors_total",
		Help: "Total number of failed Vault key sync attempts.",
	})

	// keyRotationsTotal counts successful rotations performed by the rotator.
	keyRotationsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "jwks_key_rotations_total",
		Help: "Total number of successful key rotations.",
	})

	// lastRotationTimestamp is the Unix timestamp of the last successful rotation.
	lastRotationTimestamp = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "jwks_last_rotation_timestamp_seconds",
		Help: "Unix timestamp of the last successful key rotation.",
	})

	// keysExpiredTotal counts keys removed after their grace period ended.
	keysExpiredTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "jwks_keys_expired_total",
		Help: "Total number of signing keys that have expired and been removed.",
	})

	// keyRotationErrorsTotal counts failed rotation attempts.
	keyRotationErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "jwks_key_rotation_errors_total",
		Help: "Total number of failed key rotation attempts.",
	})
)

// UpdateActiveKeyAge updates the Prometheus gauge with the age of the given key.
// Called by the server on a periodic tick.
func UpdateActiveKeyAge(createdAt time.Time) {
	activeKeyAgeSeconds.Set(time.Since(createdAt).Seconds())
}
