// Package  transport provides mutual TSL configuration and peer verification.
package transport

import (
	"crypto/x509"
	"fmt"
)

// ErrUntrustedPeer is returned when a peer certificate is not allowed.
var ErrUntrustedPeer = fmt.Errorf("transport: peer certificate not in allowed set")

// RequireCommonName returns a callback that requires an allowed certificate CommonName.
func RequireCommonName(allowed ...string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	// Convert the allowed list into a hash map for 0(1) loopkup
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		allowedSet[name] = struct{}{}
	}

	// Return the TLS verification callback function
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// Inspect each verified certificate chain provided by the handshake
		for _, chain := range verifiedChains {
			if len(chain) == 0 {
				continue
			}

			// Check if the peer's leaf certificate CommonName.
			leaf := chain[0]
			if _, ok := allowedSet[leaf.Subject.CommonName]; ok {
				return nil
			}
		}

		// Reject the handshake if no matching CommonName
		return ErrUntrustedPeer
	}
}
