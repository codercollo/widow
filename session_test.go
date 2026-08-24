// Package widow provides tests for session management and token handling.
package widow

import (
	"errors"
	"testing"
	"time"
)

// testManager returns a SessionManager configured for tests .
func testManager() *SessionManager {
	return NewSessionManager([]byte("test-cluster-key"), time.Hour)
}

// TestIssueAndAuthenticate verifies sessions can be issued and authenticated.
func TestIssueAndAuthenticate(t *testing.T) {
	m := testManager()

	token, err := m.Issue("user-1", "read", "write")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	sess, newToken, err := m.Authenticate(token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if sess.UserID != "user-1" {
		t.Fatalf("expected UserID user-1, got %s", sess.UserID)
	}
	if newToken == token {
		t.Fatal("expected Authenticate to return a rotated (different) token")
	}
}

// TestAuthenticateRejectsReplayedToken verifies reused tokens are rejected.
func TestAuthenticateRejectsReplayedToken(t *testing.T) {
	m := testManager()
	token, _ := m.Issue("user-1")

	// First use succeeds and rotates the token.
	if _, _, err := m.Authenticate(token); err != nil {
		t.Fatalf("expected first use to succeed: %v", err)
	}

	// Presenting the *same* original token again must fail — this is
	// the scenario where a captured token is replayed by an attacker
	// after the legitimate client has already moved on to the next one.
	if _, _, err := m.Authenticate(token); !errors.Is(err, ErrReplayed) {
		t.Fatalf("expected ErrReplayed on reuse, got: %v", err)
	}
}

// TestRotatedTokenContinuesToWork verifies rotated tokens remain valid.
func TestRotatedTokenContinuesToWork(t *testing.T) {
	m := testManager()
	token, _ := m.Issue("user-1")

	_, token2, err := m.Authenticate(token)
	if err != nil {
		t.Fatalf("first Authenticate: %v", err)
	}

	_, token3, err := m.Authenticate(token2)
	if err != nil {
		t.Fatalf("expected rotated token to authenticate successfully: %v", err)
	}
	if token3 == token2 {
		t.Fatal("expected a further rotation on the second call")
	}
}

// TestAuthenticateRejectsUnknownToken verifies tokens signed with another key are rejected.
func TestAuthenticateRejectsUnknownToken(t *testing.T) {
	m := testManager()
	other := NewSessionManager([]byte("a-completely-different-key"), time.Hour)

	token, _ := other.Issue("user-1")

	if _, _, err := m.Authenticate(token); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for a token signed under a different key, got: %v", err)
	}
}

// TestAuthenticateRejectsExpiredSession verifies expired sessions are rejected.
func TestAuthenticateRejectsExpiredSession(t *testing.T) {
	m := NewSessionManager([]byte("test-cluster-key"), -time.Minute) // already expired
	token, _ := m.Issue("user-1")

	if _, _, err := m.Authenticate(token); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired, got: %v", err)
	}
}

// TestLogoutRevokesSession verifies logout prevents further authentication.
func TestLogoutRevokesSession(t *testing.T) {
	m := testManager()
	token, _ := m.Issue("user-1")

	sess, rotatedToken, err := m.Authenticate(token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if err := m.Logout(sess.ID); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	// The rotated token from before Logout is still cryptographically
	// valid and its counter hasn't been used yet — but the session
	// itself is revoked, so Authenticate must still reject it.
	if _, _, err := m.Authenticate(rotatedToken); !errors.Is(err, ErrRevoked) {
		t.Fatalf("expected ErrRevoked after logout, got: %v", err)
	}
}

// TestInvalidateAllRevokesEverySessionForUser verifies all user sessions are revoked
func TestInvalidateAllRevokesEverySessionForUser(t *testing.T) {
	m := testManager()

	tokenA, _ := m.Issue("user-1")
	tokenB, _ := m.Issue("user-1")

	sessA, _, err := m.Authenticate(tokenA)
	if err != nil {
		t.Fatalf("Authenticate A: %v", err)
	}
	sessB, _, err := m.Authenticate(tokenB)
	if err != nil {
		t.Fatalf("Authenticate B: %v", err)
	}

	if err := m.InvalidateAll("user-1"); err != nil {
		t.Fatalf("InvalidateAll: %v", err)
	}

	m.mu.RLock()
	revokedA := m.sessions[sessA.ID].Revoked
	revokedB := m.sessions[sessB.ID].Revoked
	m.mu.RUnlock()

	if !revokedA || !revokedB {
		t.Fatal("expected InvalidateAll to revoke every session for the user")
	}
}

// TestInvalidateAllDoesNotAffectOtherUsers verifies other users remain unaffected.
func TestInvalidateAllDoesNotAffectOtherUsers(t *testing.T) {
	m := testManager()

	tokenA, _ := m.Issue("user-1")
	tokenB, _ := m.Issue("user-2")

	sessB, _, err := m.Authenticate(tokenB)
	if err != nil {
		t.Fatalf("Authenticate user-2: %v", err)
	}

	if err := m.InvalidateAll("user-1"); err != nil {
		t.Fatalf("InvalidateAll: %v", err)
	}

	m.mu.RLock()
	revokedB := m.sessions[sessB.ID].Revoked
	m.mu.RUnlock()

	if revokedB {
		t.Fatal("expected user-2's session to be unaffected by user-1's InvalidateAll")
	}

	_ = tokenA
}
