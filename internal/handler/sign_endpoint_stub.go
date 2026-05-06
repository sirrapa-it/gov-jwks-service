//go:build !signing

package handler

import "net/http"

// registerSignEndpoint is a no-op stub when the "signing" build tag is absent.
// The /internal/sign endpoint does not exist in the default and production builds.
func (h *Handler) registerSignEndpoint(_ *http.ServeMux) {}
