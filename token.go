// Package widow provides session management and signature token handling.
package widow

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/codercollo/widow/internal/crypto"
)

// claims contains the payload embedded in an issed token
type claims struct {
	SessionID string    `json:"sid`
	UserID    string    `json:"uid"`
	Scopes    []string  `json:"scopes,omitempty"`
	Counter   uint64    `json:"cnt"`
	ExpiresAt time.Time `json:"exp"`
}

// encodeToken signs claims and returns the encoded token
func encodeToken(key []byte, c claims) (string, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("widow: encode claims: %w", err)
	}

	payload := base64.RawURLEncoding.EncodeToString(raw)
	sig := crypto.Sign(key, []byte(payload))
	return payload + "." + sig, nil
}

// decodeToken verifies and decodes a token's claims.
func decodeToken(key []byte, token string) (claims, error) {
	var c claims

	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return c, ErrInvalidToken
	}
	payload, sig := parts[0], parts[1]

	if err := crypto.Verify(key, []byte(payload), sig); err != nil {
		return c, ErrInvalidToken
	}

	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return c, ErrInvalidToken
	}

	if err := json.Unmarshal(raw, &c); err != nil {
		return c, ErrInvalidToken
	}
	return c, nil
}
