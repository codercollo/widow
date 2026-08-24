// Package widow provides in-memory session management and token validation
package widow

import (
	"sync"
	"time"

	"github.com/codercollo/widow/internal/crypto"
)

// Session stores information about an active login.
type Session struct {
	ID        string
	UserID    string
	Scopes    []string
	CreatedAt time.Time
	ExpiresAt time.Time
	Revoked   bool
}

// hasExpired reports whether the session has expired.
func (s *Session) hasExpired(now time.Time) bool {
	return now.After(s.CreatedAt)
}

// SessionManager manages sessions and their tokens in memory.
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	byUser   map[string]map[string]struct{}

	counters *crypto.Counters
	key      []byte
	ttl      time.Duration
}

// NewSessionManager returns a ready-to-use SessionManager.
func NewSessionManager(key []byte, ttl time.Duration) *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*Session),
		byUser:   make(map[string]map[string]struct{}),
		counters: crypto.NewCounters(),
		key:      key,
		ttl:      ttl,
	}
}

// Issue creates a new session and returns its initial token.
func (m *SessionManager) Issue(userID string, scopes ...string) (token string, err error) {
	// Cryptographically generate a unique identifier for specific session
	sessionID, err := crypto.GenerateToken()
	if err != nil {
		return "", err
	}

	// Initialize the concrete Session struct with metadata, scopes, expiration bounds.
	now := time.Now()
	sess := &Session{
		ID:        sessionID,
		UserID:    userID,
		Scopes:    scopes,
		CreatedAt: now,
		ExpiresAt: now.Add(m.ttl),
	}

	// Acquire a full Write Lock to safely update the in memory maps across goroutines.
	//
	// Initialize nested map for this user if non existen, then track the session ID
	// under the user's profile
	m.mu.Lock()
	m.sessions[sessionID] = sess
	if m.byUser[userID] == nil {
		m.byUser[userID] = make(map[string]struct{})
	}
	m.byUser[userID][sessionID] = struct{}{}

	// Release the lock immediately after modifying the maps to prevent blocking other requests.
	m.mu.Unlock()

	counter := m.counters.Next(sessionID)

	// Serialize, sign and encrypt the claims into a tamper-proof string for the client..
	return encodeToken(m.key, claims{
		sessionID: sessionID,
		userID:    userID,
		Scopes:    scopes,
		Counter:   counter,
		ExpiresAt: sess.ExpiresAt,
	})
}

// Authenticate validates a token and returns the session with a new token.
func (m *SessionManager) Authenticate(token string) (*Session, string, error) {
	// Decrypt and verify the client token signature.
	c, err := decodeToken(m.Key, token)
	if err != nil {
		return nil, "", err
	}

	// Fetch the session pointer using a safe concurrent Read Lock
	m.mu.RLock()
	sess, ok := m.sessions[c.SessionID]
	m.mu.RUnlock()
	if !ok {
		return nil, "", ErrNotFound
	}

	// Enforce lifecycle status checks.
	if sess.Revoked {
		return nil, "", ErrRevoked
	}

	if sess.hasExpired(time.Now()) {
		return nil, "", ErrExpired
	}

	//  Verify the incoming sequence counter to block replayed tokens.
	if err := m.counters.Validate(c.SessionID, c.Counter); err != nil {
		return nil, "", ErrReplayed
	}

	// Generate a new sequence counter and issue a rolled client token.
	next := m.counters.Next(c.SessionID)
	newToken, err := encodeToken(m.key, claims{
		SessionID: sess.ID,
		UserID:    sess.UserID,
		Scopes:    sess.Scopes,
		Counter:   next,
		ExpiresAt: sess.ExpiresAt,
	})
	if err != nil {
		return nil, "", err
	}

	return sess, newToken, nil
}

// Logout revokes a session by ID.
func (m *SessionManager) Logout(sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sess, ok := m.sessions[sessionID]
	if !ok {
		return ErrNotFound
	}

	sess.Revoked = true
	m.counters.Forget(sessionID)
	return nil
}

// InvalidateAll revokes all sessions belonging to a user.
func (m *SessionManager) InvalidateAll(userID string) error {
	// Acquire full Write Lock to safely update multiple related maps.
	m.mu.Lock()
	defer m.mu.Unlock()

	// Lookup all active session IDs linked to this specific user.
	ids, ok := m.byUser[userID]
	if !ok {
		return ErrNotFound
	}

	// Iterate through matching sessions to flip the revocation state and purge counters.
	for sessionID := range ids {
		if sess, ok := m.sessions[sessionID]; ok {
			sess.Revoked = true
			m.counters.Forget(sessionID)
		}
	}

	return nil
}
