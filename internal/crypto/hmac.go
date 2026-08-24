// Package crypto provides HMAC signing and verifications utilities.
package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// ErrInvalidSignature is returned when a signature does not match its payload.
var ErrInvalidSignature = errors.New("crypto: invalid signature")

// Sign returns an HMAC-SHA256 signature for payload using key.
func Sign(key []byte, payload []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify checks that sig is a valid HMAC-SHA256 signature for payload
func Verify(key []byte, payload []byte, sig string) error {
	want := Sign(key, payload)
	if !hmac.Equal([]byte(want), []byte(sig)) {
		return ErrInvalidSignature
	}

	return nil
}
