// Package widow provides tests for HTTP authentication and permission middleware.
package widow

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// okHandler verifies the authenticated session is available in the context.
func okHandler(w http.ResponseWriter, r *http.Request) {
	sess, ok := FromContext(r.Context())
	if !ok {
		http.Error(w, "no session in context", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(sess.UserID))
}

// TestAuthenticateMiddlewareAllowsValidToken verifies valid tokens reach the handler.
func TestAuthenticateMiddlewareAllowsValidToken(t *testing.T) {
	m := testManager()
	token, _ := m.Issue("user-1", "read")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	m.RequireAuth(http.HandlerFunc(okHandler)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "user-1" {
		t.Fatalf("expected handler to see user-1 in context, got %q", rec.Body.String())
	}
}

// TestAuthenticateMiddlewareSetsRotatedTokenHeader verifies token rotation in responses.
func TestAuthenticateMiddlewareSetsRotatedTokenHeader(t *testing.T) {
	m := testManager()
	token, _ := m.Issue("user-1")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	m.RequireAuth(http.HandlerFunc(okHandler)).ServeHTTP(rec, req)

	rotated := rec.Header().Get(TokenHeader)
	if rotated == "" {
		t.Fatal("expected rotated token in response header")
	}
	if rotated == token {
		t.Fatal("expected rotated token to differ from the original")
	}
}

// TestAuthenticateMiddlewareRejectsMissingToken verifies requests without tokens are rejected.
func TestAuthenticateMiddlewareRejectsMissingToken(t *testing.T) {
	m := testManager()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	m.RequireAuth(http.HandlerFunc(okHandler)).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing token, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected JSON error body, got Content-Type %q", ct)
	}
}

// TestAuthenticateMiddlewareRejectsMalformedHeader verifies malformed authorization headers are rejected.
func TestAuthenticateMiddlewareRejectsMalformedHeader(t *testing.T) {
	m := testManager()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "not-a-bearer-token")
	rec := httptest.NewRecorder()

	m.RequireAuth(http.HandlerFunc(okHandler)).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for malformed Authorization header, got %d", rec.Code)
	}
}

// TestAuthenticateMiddlewareRejectsReplayedToken verifies replayed tokens are rejected.
func TestAuthenticateMiddlewareRejectsReplayedToken(t *testing.T) {
	m := testManager()
	token, _ := m.Issue("user-1")

	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.Header.Set("Authorization", "Bearer "+token)
	rec1 := httptest.NewRecorder()
	m.RequireAuth(http.HandlerFunc(okHandler)).ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("expected first request to succeed, got %d", rec1.Code)
	}

	// Replay the original token after it has been consumed.
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	rec2 := httptest.NewRecorder()
	m.RequireAuth(http.HandlerFunc(okHandler)).ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on replay, got %d: %s", rec2.Code, rec2.Body.String())
	}
}

// TestAuthenticateMiddlewareRejectsExpiredSession verifies expired sessions are rejected.
func TestAuthenticateMiddlewareRejectsExpiredSession(t *testing.T) {
	m := NewSessionManager([]byte("test-cluster-key"), -time.Minute)
	token, _ := m.Issue("user-1")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	m.RequireAuth(http.HandlerFunc(okHandler)).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired session, got %d", rec.Code)
	}
}

// TestRequirePermissionAllowsScopedSession verifies sessions with the required scope are allowed.
func TestRequirePermissionAllowsScopedSession(t *testing.T) {
	m := testManager()
	token, _ := m.Issue("user-1", "admin:access")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler := m.RequireAuth(m.RequirePermission("admin:access", http.HandlerFunc(okHandler)))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestRequirePermissionRejectsMissingScope verifies sessions without the required scope are rejected.
func TestRequirePermissionRejectsMissingScope(t *testing.T) {
	m := testManager()
	token, _ := m.Issue("user-1", "read")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler := m.RequireAuth(m.RequirePermission("admin:access", http.HandlerFunc(okHandler)))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for missing scope, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestRequirePermissionWithoutAuthenticateReturnsUnauthorized verifies missing sessions return 401.
func TestRequirePermissionWithoutAuthenticateReturnsUnauthorized(t *testing.T) {
	m := testManager()

	// RequirePermission used without Authenticate first.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	m.RequirePermission("admin:access", http.HandlerFunc(okHandler)).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when no session is present, got %d", rec.Code)
	}
}
