//go:build signing

package handler

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/sirrapa/jwks-service/internal/keystore"
)

type signRequest struct {
	Subject  string            `json:"sub"`
	Audience string            `json:"aud"`
	Roles    []string          `json:"roles"`
	Extra    map[string]string `json:"extra,omitempty"`
	TTL      string            `json:"ttl,omitempty"`
}

type signResponse struct {
	Token string `json:"token"`
	Kid   string `json:"kid"`
	Exp   int64  `json:"exp"`
}

// registerSignEndpoint registers the /internal/sign route.
// Only compiled with the "signing" build tag.
func (h *Handler) registerSignEndpoint(mux *http.ServeMux) {
	mux.Handle("POST /internal/sign", h.logging(h.Sign()))
}

// Sign issues a signed JWT. For integration testing and local development only.
func (h *Handler) Sign() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req signRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if req.Subject == "" {
			writeError(w, http.StatusBadRequest, "sub is required")
			return
		}
		if req.Audience == "" {
			writeError(w, http.StatusBadRequest, "aud is required")
			return
		}
		ttl := 15 * time.Minute
		if req.TTL != "" {
			d, err := time.ParseDuration(req.TTL)
			if err != nil || d <= 0 {
				writeError(w, http.StatusBadRequest, "invalid ttl: use Go duration format, e.g. 15m")
				return
			}
			ttl = d
		}
		key, err := h.store.ActiveKey()
		if err != nil {
			h.logger.Error("no active signing key", "error", err)
			writeError(w, http.StatusServiceUnavailable, "signing key unavailable")
			return
		}
		now := time.Now()
		exp := now.Add(ttl).Unix()
		token, err := buildJWT(key, req, now.Unix(), exp)
		if err != nil {
			h.logger.Error("JWT signing failed", "error", err, "kid", key.Kid)
			writeError(w, http.StatusInternalServerError, "signing failed")
			return
		}
		writeJSON(w, http.StatusOK, signResponse{Token: token, Kid: key.Kid, Exp: exp})
	}
}

func buildJWT(key *keystore.ManagedKey, req signRequest, iat, exp int64) (string, error) {
	headerJSON, err := jsonMarshalFn(map[string]string{"typ": "JWT", "alg": "RS256", "kid": key.Kid})
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	claims := map[string]any{
		"iss": "https://jwks.platform.internal",
		"sub": req.Subject, "aud": req.Audience,
		"iat": iat, "exp": exp,
	}
	if len(req.Roles) > 0 {
		claims["roles"] = req.Roles
	}
	for k, v := range req.Extra {
		claims[k] = v
	}
	payloadJSON, err := jsonMarshalFn(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(payloadJSON)
	sig, err := rsaSignFn(key, []byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("signing: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
