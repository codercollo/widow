// Package transport provides shared mutual-TLS configuration for networked nodes.
package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// LoadTLSConfig builds a mutual-TLS configuration for a mesh node.
func LoadTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	// Load the node's public certificate and private key pair for identity proof.
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("transport: load node cert/key: %w", err)
	}

	// Read the raw Certificate Authority file from disk.
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("transport: read CA file: %w", err)
	}

	// Create a secure root certificate pool and populate it with the CA data.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("transport: no valid certificates found in %s", caFile)
	}

	// Assemble and return the final mutual-TLS (mTLS) configuration.
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,                           // Verify external servers {Outbound TLS}
		ClientCAs:    pool,                           // Verify incoming clients {Inbound TLS}
		ClientAuth:   tls.RequireAndVerifyClientCert, // Mandates strict cryptographic proof from clients
		MinVersion:   tls.VersionTLS12,               // Enforces modern, secure TLS protocols
	}, nil
}
