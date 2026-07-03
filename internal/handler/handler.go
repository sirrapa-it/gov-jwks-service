// Package handler implements the HTTP API for the jwks-service server.
package handler

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/sirrapa-it/gov-jwks-service/internal/keystore"
)

// jsonMarshalFn and rsaSignFn are test hooks for the sign endpoint.
var jsonMarshalFn = json.Marshal
var rsaSignFn = keystore.SignRS256

// Handler bundles all HTTP handlers.
type Handler struct {
	store  keystore.Store
	logger *slog.Logger
}

// New creates a Handler. Uses slog.Default() when logger is nil.
func New(store keystore.Store, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{store: store, logger: logger}
}

// RegisterRoutes attaches all routes to mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle("GET /.well-known/jwks.json", h.logging(h.JWKS()))
	mux.Handle("GET /healthz", h.logging(h.Health()))
	mux.Handle("GET /metrics", promhttp.Handler())
	h.registerSignEndpoint(mux)
}

// JWKS serves all currently valid public signing keys (RFC 7517).
//
//	GET /.well-known/jwks.json
func (h *Handler) JWKS() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		set := h.store.PublicKeySet()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		writeJSON(w, http.StatusOK, set)
	}
}

// Health returns a liveness response for Kubernetes probes.
//
//	GET /healthz
func (h *Handler) Health() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

func (h *Handler) logging(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		h.logger.Info("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.status,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		_ = err
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// ParseBearerToken extracts the token from an Authorization: Bearer header.
func ParseBearerToken(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", fmt.Errorf("missing Authorization header")
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", fmt.Errorf("malformed Authorization header")
	}
	return parts[1], nil
}
