// Package widow provides session management, token validation, and HTTP middleware.
package widow

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// TokenHeader is the  response header used for rotated tokens.
const TokenHeader = "X-Widow-Token"

type contextKey string

const sessionContextKey contextKey = "widow-session"

// FromContext returns the Session attached to ctx, if any.
func FromContext(ctx context.Context) (*Session, bool) {
	sess, ok := ctx.Value(sessionContextKey).(*Session)
	return sess, ok
}

// bearerToken extracts a bearer token from the Authorization header.
func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return "", false
	}

	token := strings.TrimSpace(strings.TrimPrefix(h, prefix))
	if token == "" {
		return "", false
	}

	return token, true
}

// errorEnvelope defines the JSON error response format.
type errorEnvelope struct {
	Error string `json:"error"`
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(errorEnvelope{Error: message})
}

func statusForAuthError(err error) (int, string) {
	switch {
	case errors.Is(err, ErrExpired):
		return http.StatusUnauthorized, "session expired"
	case errors.Is(err, ErrRevoked):
		return http.StatusUnauthorized, "session revoked"
	case errors.Is(err, ErrReplayed):
		return http.StatusUnauthorized, "token already used"
	case errors.Is(err, ErrNotFound):
		return http.StatusUnauthorized, "session not found"
	case errors.Is(err, ErrInvalidToken):
		return http.StatusUnauthorized, "invalid token"
	default:
		return http.StatusUnauthorized, "authentication failed"
	}
}

// RequireAuth  validates bearer tokens and attaches the Session to the request context.
func (m *SessionManager) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}

		sess, newToken, err := m.Authenticate(token)
		if err != nil {
			status, msg := statusForAuthError(err)
			writeError(w, status, msg)
			return
		}

		w.Header().Set(TokenHeader, newToken)

		ctx := context.WithValue(r.Context(), sessionContextKey, sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})

}

// RequirePermission checks that the authenticated Session has the given scope.
func (m *SessionManager) RequirePermission(scope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := FromContext(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}

		if !hasScope(sess.Scopes, scope) {
			writeError(w, http.StatusForbidden, "missing required permission:"+scope)
			return
		}
		next.ServeHTTP(w, r)
	})

}

func hasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}

	return false
}
