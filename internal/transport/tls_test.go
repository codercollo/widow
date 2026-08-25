// Package transport provides tests for  mutual-TLS config and peer verification.
package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"testing"
	"time"
)

// attemptRoundTrip performs a TLS handshake and verifies the connection can exchange data.
func attemptRoundTrip(t *testing.T, addr string, cfg *tls.Config) error {
	t.Helper()

	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		return err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("hello")); err != nil {
		return err
	}

	buf := make([]byte, 5)
	_, err = io.ReadFull(conn, buf)
	return err
}

// setupNode creates a test node certificate and loads its TLS configurations.
func setupNode(t *testing.T, ca *testCA, name string) *tls.Config {
	t.Helper()

	// Issue the certificate and private key for the node
	certPEM, keyPEM := ca.issue(t, name)

	// Write the certificates and CA to temporary files
	certFile := writeTemp(t, name+"-cert.pem", certPEM)
	keyFile := writeTemp(t, name+" -key.pem", keyPEM)
	caFile := writeTemp(t, "ca.pem", ca.certPEM)

	// Load and initialize  the TLS configuration.
	cfg, err := LoadTLSConfig(certFile, keyFile, caFile)
	if err != nil {
		t.Fatalf("LoadTLSConfig for %s: %v", name, err)
	}

	return cfg
}

// serveOnce starts a TLS listener that accepts and echoes one connection.
func serveOnce(t *testing.T, cfg *tls.Config) (addr string, errCh chan error) {
	t.Helper()

	// Start the TLS listener on a random local port
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("listen: %v", err)

	}

	// Initialize buffered channel for asynchronous error reporting
	errCh = make(chan error, 1)

	// Handle the single connection in a background goroutine
	go func() {
		defer ln.Close()

		// Accept the incoming client connection
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()

		// Read exactly 5 bytes from the  connection
		buf := make([]byte, 5)
		if _, err := io.ReadFull(conn, buf); err != nil {
			errCh <- err
			return
		}

		// Echo the identical 5 bytes back to the client
		if _, err := conn.Write(buf); err != nil {
			errCh <- err
			return
		}

		// Signal successful execution with no errors
		errCh <- nil

	}()

	return ln.Addr().String(), errCh

}

// TestMutualTLSHandshakeSucceedsWithValidCerts verifies valid peer certificates are accepted.
func TestMutualTLSHandshakeSucceedsWithValidCerts(t *testing.T) {
	ca := newTestCA(t)
	serverCfg := setupNode(t, ca, "node-server")
	clientCfg := setupNode(t, ca, "node-client")

	addr, errCh := serveOnce(t, serverCfg)

	conn, err := tls.Dial("tcp", addr, clientCfg)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("expected echoed 'hello', got %q", buf)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("server side error: %v", err)
	}
}

// TestHandshakeFailsWithUntrustedClientCert verifies untrusted client certificates are rejected.
func TestHandshakeFailsWithUntrustedClientCert(t *testing.T) {
	serverCA := newTestCA(t)
	rogueCA := newTestCA(t)

	serverCfg := setupNode(t, serverCA, "node-server")

	clientCertPEM, clientKeyPEM := rogueCA.issue(t, "node-client")
	clientCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		t.Fatalf("build client keypair: %v", err)
	}
	trustServerCA := x509.NewCertPool()
	trustServerCA.AppendCertsFromPEM(serverCA.certPEM)
	clientCfg := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      trustServerCA,
		MinVersion:   tls.VersionTLS12,
	}

	addr, errCh := serveOnce(t, serverCfg)

	if err := attemptRoundTrip(t, addr, clientCfg); err == nil {
		t.Fatal("expected the round trip to fail: client cert is signed by a CA the server doesn't trust")
	}

	if err := <-errCh; err == nil {
		t.Fatal("expected server to report an error for the untrusted client cert")
	}
}

// TestHandshakeFailsWithNoClientCert verifies clients without certificates are rejected.
func TestHandshakeFailsWithNoClientCert(t *testing.T) {
	ca := newTestCA(t)
	serverCfg := setupNode(t, ca, "node-server")

	addr, errCh := serveOnce(t, serverCfg)

	bareClientCfg := &tls.Config{InsecureSkipVerify: true}

	if err := attemptRoundTrip(t, addr, bareClientCfg); err == nil {
		t.Fatal("expected the round trip to fail: client presented no certificate")
	}

	if err := <-errCh; err == nil {
		t.Fatal("expected server to report an error for the missing client certificate")
	}
}

// TestRequireCommonNameAcceptsAllowedPeer verifies allowed CommonNames are accepted.
func TestRequireCommonNameAcceptsAllowedPeer(t *testing.T) {
	ca := newTestCA(t)
	serverCfg := setupNode(t, ca, "node-server")
	serverCfg.VerifyPeerCertificate = RequireCommonName("node-client")

	clientCfg := setupNode(t, ca, "node-client")

	addr, errCh := serveOnce(t, serverCfg)

	conn, err := tls.Dial("tcp", addr, clientCfg)
	if err != nil {
		t.Fatalf("expected dial to succeed for an allowed CommonName, got: %v", err)
	}
	defer conn.Close()

	conn.Write([]byte("hello"))
	if err := <-errCh; err != nil {
		t.Fatalf("server side error: %v", err)
	}
}

// TestRequireCommonNameRejectsDisallowedPeer verifies disallowed CommonNames are rejected.
func TestRequireCommonNameRejectsDisallowedPeer(t *testing.T) {
	ca := newTestCA(t)
	serverCfg := setupNode(t, ca, "node-server")
	serverCfg.VerifyPeerCertificate = RequireCommonName("node-client")

	intruderCfg := setupNode(t, ca, "intruder")

	addr, errCh := serveOnce(t, serverCfg)

	if err := attemptRoundTrip(t, addr, intruderCfg); err == nil {
		t.Fatal("expected the round trip to fail: CommonName not in the allowed set")
	}

	if err := <-errCh; err == nil {
		t.Fatal("expected server to reject the connection")
	}
}

// TestLoadTLSConfigErrorsOnMissingFiles verifies missing certificate files return an error.
func TestLoadTLSConfigErrorsOnMissingFiles(t *testing.T) {
	_, err := LoadTLSConfig("does-not-exist.pem", "also-missing.pem", "nope.pem")
	if err == nil {
		t.Fatal("expected an error for nonexistent cert files")
	}
}

// TestLoadTLSConfigErrorsOnInvalidCA verifies invalid CA files return an error.
func TestLoadTLSConfigErrorsOnInvalidCA(t *testing.T) {
	ca := newTestCA(t)
	certPEM, keyPEM := ca.issue(t, "node")
	certFile := writeTemp(t, "cert.pem", certPEM)
	keyFile := writeTemp(t, "key.pem", keyPEM)
	badCAFile := writeTemp(t, "ca.pem", []byte("not a valid PEM certificate"))

	_, err := LoadTLSConfig(certFile, keyFile, badCAFile)
	if err == nil {
		t.Fatal("expected an error for a CA file with no valid certificates")
	}
}

// TestRequireCommonNameReturnsErrUntrustedPeer verifies the expected verification error is returned.
func TestRequireCommonNameReturnsErrUntrustedPeer(t *testing.T) {
	verify := RequireCommonName("allowed-name")
	ca := newTestCA(t)
	_ = ca

	err := verify(nil, nil)
	if !errors.Is(err, ErrUntrustedPeer) {
		t.Fatalf("expected ErrUntrustedPeer for empty verified chains, got: %v", err)
	}
}
