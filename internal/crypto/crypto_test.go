// Package crypto provides tests for token generation, hashing, signing, and verification.
package crypto

import "testing"

// TestGenerateTokenIsUniqueAndNonEmpty verifies generated tokens are non-empty and unique.
func TestGenerateTokenIsUniqueAndNonEmpty(t *testing.T) {
	a, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken:%v", err)
	}

	b, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	if a == "" || b == "" {
		t.Fatal("expected non-empty tokens")
	}

	if a == b {
		t.Fatal("expected two calls to produce different tokens")
	}
}

// TestHashTokenIsDeterministic verifies hashing the same token produces the same hash.
func TestHashTokenIsDeterministic(t *testing.T) {
	tok, _ := GenerateToken()
	h1 := HashToken(tok)
	h2 := HashToken(tok)
	if h1 != h2 {
		t.Fatal("expected hashing the same token twice to produe the same hash")
	}

	if !EqualHash(h1, h2) {
		t.Fatal("expected EqualHash to report equal hashes as equal")
	}
}

// TestHashTokenDiffersForDifferentTokens verifies different tokens produce different hashes.
func TestHashTokenDiffersForDifferentTokens(t *testing.T) {
	tokA, _ := GenerateToken()
	tokB, _ := GenerateToken()
	if HashToken(tokA) == HashToken(tokB) {
		t.Fatal("expected different tokens to hash differently")
	}
}

// TestSignAndVerify verifies a valid signature can be verified.
func TestSignAndVerify(t *testing.T) {
	key := []byte("cluster-secret")
	payload := []byte("session-id=abc123;counter=1")

	sig := Sign(key, payload)
	if err := Verify(key, payload, sig); err != nil {
		t.Fatalf("expected valid signature to verify, got: %v", err)
	}
}

// TestVerifyRejectsTamperedPayload verifies tampered payloads are rejected.
func TestVerifyRejectsTamperedPayload(t *testing.T) {
	key := []byte("cluster-secret")
	sig := Sign(key, []byte("original-payload"))

	err := Verify(key, []byte("tampered-payload"), sig)
	if err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature, got: %v", err)
	}
}

// TestVerifyRejectsWrongKey verifies signatures made with a different key are rejected.
func TestVerifyRejectsWrongKey(t *testing.T) {
	payload := []byte("session-id=abc123;counter=1")
	sig := Sign([]byte("key-one"), payload)

	err := Verify([]byte("key-two"), payload, sig)
	if err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature for mismatched key, got: %v", err)
	}
}
