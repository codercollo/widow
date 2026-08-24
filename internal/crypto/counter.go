// Package crypto contains the cryptographic and replay-protection primitives used by Widow.

package crypto

import (
	"errors"
	"sync"
)

// ErrReplayed is returned when a token counter has already been validated.
var ErrReplayed = errors.New("crypto: token replayed")

// Counters tracks issued and validated counters for each session.
//
// A counter must be greater than the previously validated counter.
// Access is protected by mu so counters is safe for concurrent use.
type Counters struct {
	mu        sync.Mutex
	issued    map[string]uint64 //session ID  last issued counter
	validated map[string]uint64 //session ID   highest validated counter
}

// NewCounters returns an empty, ready-to-use Counters.
func NewCounters() *Counters {
	return &Counters{
		issued:    make(map[string]uint64),
		validated: make(map[string]uint64),
	}
}

// Next returns the next counter for sessionID.
//
// The counter is issued but not considered validated until Validate succeeds.
func (c *Counters) Next(sessionID string) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.issued[sessionID]++
	return c.issued[sessionID]
}

// Validate accepts counter if it is greated than the last validated counter
//
// A counter that is equal to or lower than the current value is rejected as a replay.
func (c *Counters) Validate(sessionID string, counter uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if counter <= c.validated[sessionID] {
		return ErrReplayed
	}

	c.validated[sessionID] = counter
	return nil
}

// Forget removes all counter state for sessionID.
//
// This is useful after a session has been permanetly invalidated.
func (c *Counters) Forget(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.issued, sessionID)
	delete(c.validated, sessionID)
}
