// Package widow provides session management and token validation.
package widow

import "errors"

// Sentinel errors returned by SessionManager.
var (
	ErrNotFound     = errors.New("widow: session not found")
	ErrExpired      = errors.New("widow: session expired")
	ErrRevoked      = errors.New("widow: session revoked")
	ErrReplayed     = errors.New("widow: token replayed")
	ErrInvalidToken = errors.New("widow: invalid token")
)
