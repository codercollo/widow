package crypto

import (
	"sync"
	"testing"
)

func TestCountersAcceptsIncreasingValues(t *testing.T) {
	c := NewCounters()
	session := "session-1"

	n1 := c.Next(session)
	if err := c.Validate(session, n1); err != nil {
		t.Fatalf("expected first counter to validate, got: %v", err)
	}

	n2 := c.Next(session)
	if n2 <= n1 {
		t.Fatalf("expected Next to return an increasing value, got %d after %d", n2, n1)
	}
	if err := c.Validate(session, n2); err != nil {
		t.Fatalf("expected increasing counter to validate, got: %v", err)
	}
}

func TestCountersRejectsReplay(t *testing.T) {
	c := NewCounters()
	session := "session-1"

	n1 := c.Next(session)
	if err := c.Validate(session, n1); err != nil {
		t.Fatalf("expected first use to validate, got: %v", err)
	}

	// Same counter value presented again — this is the captured/leaked
	// token being replayed. It must be rejected.
	if err := c.Validate(session, n1); err != ErrReplayed {
		t.Fatalf("expected ErrReplayed on reuse, got: %v", err)
	}
}

func TestCountersRejectsOutOfOrder(t *testing.T) {
	c := NewCounters()
	session := "session-1"

	c.Next(session)       // 1
	n2 := c.Next(session) // 2
	if err := c.Validate(session, n2); err != nil {
		t.Fatalf("expected counter 2 to validate: %v", err)
	}

	// Presenting counter 1 after 2 has already been seen — also a replay.
	if err := c.Validate(session, 1); err != ErrReplayed {
		t.Fatalf("expected stale counter to be rejected as replay, got: %v", err)
	}
}

func TestCountersAreIndependentPerSession(t *testing.T) {
	c := NewCounters()

	a := c.Next("session-a")
	b := c.Next("session-b")

	if err := c.Validate("session-a", a); err != nil {
		t.Fatalf("session-a should validate independently: %v", err)
	}
	if err := c.Validate("session-b", b); err != nil {
		t.Fatalf("session-b should validate independently: %v", err)
	}
}

func TestCountersForget(t *testing.T) {
	c := NewCounters()
	session := "session-1"

	n1 := c.Next(session)
	c.Validate(session, n1)
	c.Forget(session)

	// After Forget, the high-water mark resets — a fresh session with
	// the same ID (unlikely, but defensively worth checking) starts clean.
	if err := c.Validate(session, n1); err != nil {
		t.Fatalf("expected forgotten session to accept counter again, got: %v", err)
	}
}

func TestCountersConcurrentAccess(t *testing.T) {
	c := NewCounters()
	session := "session-concurrent"

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Next(session)
		}()
	}
	wg.Wait()

	// go test -race is what actually proves this is safe; this just
	// sanity-checks the final state is consistent.
	if c.issued[session] != 100 {
		t.Fatalf("expected 100 increments, got %d", c.issued[session])
	}
}
