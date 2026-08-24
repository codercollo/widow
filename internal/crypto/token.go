// Package crypto provides cryptographic primitives used by Widow.
package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// TokenBytes is the number of random bytes generated for a token.
const TokenBytes = 32

// GenerateToken returns a cryptographically secure, URL-safe token.
func GenerateToken() (string, error) {
	buf := make([]byte, TokenBytes)

	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("crypto : generate token: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil

}
