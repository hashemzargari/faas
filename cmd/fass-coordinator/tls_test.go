package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testPKI writes a CA, a server certificate for 127.0.0.1 and a client
// certificate into dir and returns their paths.
func testPKI(t *testing.T) (caFile, certFile, keyFile, clientCertFile, clientKeyFile string) {
	t.Helper()
	dir := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fass-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	issue := func(name string, isServer bool) (certPath, keyPath string) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: name},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		if isServer {
			tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			tpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		} else {
			tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		certPath = filepath.Join(dir, name+"-cert.pem")
		keyPath = filepath.Join(dir, name+"-key.pem")
		writePEM(t, certPath, "CERTIFICATE", der)
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		writePEM(t, keyPath, "EC PRIVATE KEY", keyDER)
		return certPath, keyPath
	}

	caFile = filepath.Join(dir, "ca.pem")
	writePEM(t, caFile, "CERTIFICATE", caDER)
	certFile, keyFile = issue("server", true)
	clientCertFile, clientKeyFile = issue("client", false)
	return caFile, certFile, keyFile, clientCertFile, clientKeyFile
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestCoordinatorTLSFailsClosed: no certificate outside dev is a startup error;
// dev may stay plaintext; the two halves of a key pair must be supplied together.
func TestCoordinatorTLSFailsClosed(t *testing.T) {
	ca, cert, key, _, _ := testPKI(t)

	if _, _, err := coordinatorTLS(config{}); err == nil {
		t.Fatalf("non-dev coordinator without TLS started")
	}
	devCfg, insecure, err := coordinatorTLS(config{dev: true})
	if err != nil || devCfg != nil || !insecure {
		t.Fatalf("dev plaintext = cfg %v insecure %v err %v", devCfg, insecure, err)
	}
	if _, insecure, err := coordinatorTLS(config{devBootstrap: true}); err != nil || !insecure {
		t.Fatalf("--dev-bootstrap must imply dev: insecure %v err %v", insecure, err)
	}
	if _, _, err := coordinatorTLS(config{tlsCert: cert, dev: true}); err == nil {
		t.Fatalf("cert without key accepted")
	}
	cfg, insecure, err := coordinatorTLS(config{tlsCert: cert, tlsKey: key, tlsClientCA: ca, requireMTLS: true})
	if err != nil || cfg == nil || insecure {
		t.Fatalf("mTLS config = %v insecure %v err %v", cfg, insecure, err)
	}
}

// TestTLSServerHandshake starts the configured listener and completes a real TLS
// request; with --require-mtls a client without a certificate is rejected.
func TestTLSServerHandshake(t *testing.T) {
	ca, cert, key, clientCert, clientKey := testPKI(t)

	serve := func(t *testing.T, cfg config) (addr string, shutdown func()) {
		t.Helper()
		tlsCfg, _, err := coordinatorTLS(cfg)
		if err != nil {
			t.Fatalf("coordinatorTLS: %v", err)
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		if tlsCfg != nil {
			ln = tls.NewListener(ln, tlsCfg)
		}
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "ok")
		})}
		go srv.Serve(ln)
		return ln.Addr().String(), func() { _ = srv.Close() }
	}

	t.Run("client-verifies-server", func(t *testing.T) {
		addr, shutdown := serve(t, config{tlsCert: cert, tlsKey: key})
		defer shutdown()
		pool := x509.NewCertPool()
		caPEM, err := os.ReadFile(ca)
		if err != nil {
			t.Fatal(err)
		}
		pool.AppendCertsFromPEM(caPEM)
		hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}}}
		resp, err := hc.Get("https://" + addr + "/healthz")
		if err != nil {
			t.Fatalf("TLS handshake/request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d", resp.StatusCode)
		}
	})

	t.Run("mtls-rejects-client-without-cert", func(t *testing.T) {
		addr, shutdown := serve(t, config{tlsCert: cert, tlsKey: key, tlsClientCA: ca, requireMTLS: true})
		defer shutdown()
		pool := x509.NewCertPool()
		caPEM, _ := os.ReadFile(ca)
		pool.AppendCertsFromPEM(caPEM)
		hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}}}
		if _, err := hc.Get("https://" + addr + "/healthz"); err == nil {
			t.Fatalf("mTLS listener accepted a client without a certificate")
		}
	})

	t.Run("mtls-accepts-client-with-cert", func(t *testing.T) {
		addr, shutdown := serve(t, config{tlsCert: cert, tlsKey: key, tlsClientCA: ca, requireMTLS: true})
		defer shutdown()
		pair, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		caPEM, _ := os.ReadFile(ca)
		pool.AppendCertsFromPEM(caPEM)
		hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair},
		}}}
		resp, err := hc.Get("https://" + addr + "/healthz")
		if err != nil {
			t.Fatalf("mTLS client with certificate failed: %v", err)
		}
		resp.Body.Close()
	})
}
