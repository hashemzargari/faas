package pki

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testCA(t *testing.T) (*CA, string) {
	t.Helper()
	dir := t.TempDir()
	ca, err := InitCA(filepath.Join(dir, "ca"), CAOptions{CommonName: "test-ca"})
	if err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	return ca, dir
}

func TestInitCAWritesFilesWithSafePermissions(t *testing.T) {
	ca, dir := testCA(t)
	caDir := filepath.Join(dir, "ca")
	certInfo, err := os.Stat(filepath.Join(caDir, CAFile))
	if err != nil {
		t.Fatal(err)
	}
	keyInfo, err := os.Stat(filepath.Join(caDir, CAKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("CA key permissions = %o, want 600", keyInfo.Mode().Perm())
	}
	if certInfo.Mode().Perm() != 0o644 {
		t.Fatalf("CA cert permissions = %o, want 644", certInfo.Mode().Perm())
	}
	if !ca.Cert.IsCA || ca.Cert.Subject.CommonName != "test-ca" {
		t.Fatalf("CA cert = %+v", ca.Cert)
	}

	// Reload verify-only (the runtime shape: no CA key on disk for components).
	loaded, err := LoadCA(ca.CertFile, "")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.CertFile != ca.CertFile {
		t.Fatalf("CertFile = %q", loaded.CertFile)
	}
	if _, err := loaded.IssueClient("x", time.Hour, t.TempDir()); !errors.Is(err, ErrNoSigningKey) {
		t.Fatalf("verify-only CA issued a cert: %v", err)
	}
}

func TestIssueAndVerifyServerAndClient(t *testing.T) {
	ca, dir := testCA(t)
	srv, err := ca.IssueServer([]string{"agent-1.internal"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour, filepath.Join(dir, "server"))
	if err != nil {
		t.Fatal(err)
	}
	cli, err := ca.IssueClient("gateway-1", time.Hour, filepath.Join(dir, "client"))
	if err != nil {
		t.Fatal(err)
	}
	caPEM, _ := os.ReadFile(ca.CertFile)
	srvPEM, _ := os.ReadFile(srv.CertFile)
	cliPEM, _ := os.ReadFile(cli.CertFile)

	if _, err := VerifyChain(srvPEM, caPEM, VerifyOptions{Usage: UsageServer, DNSName: "agent-1.internal"}); err != nil {
		t.Fatalf("verify server: %v", err)
	}
	if _, err := VerifyChain(srvPEM, caPEM, VerifyOptions{Usage: UsageServer, DNSName: "127.0.0.1"}); err != nil {
		t.Fatalf("verify server by IP: %v", err)
	}
	if _, err := VerifyChain(cliPEM, caPEM, VerifyOptions{Usage: UsageClient}); err != nil {
		t.Fatalf("verify client: %v", err)
	}
	if _, err := VerifyChain(cliPEM, caPEM, VerifyOptions{Usage: UsageServer}); !errors.Is(err, ErrWrongUsage) && !strings.Contains(err.Error(), "extended key usage") {
		t.Fatalf("client cert accepted as a server: %v", err)
	}
	if _, err := VerifyChain(srvPEM, caPEM, VerifyOptions{Usage: UsageServer, DNSName: "other.internal"}); !errors.Is(err, ErrHostnameMismatch) {
		t.Fatalf("hostname mismatch error = %v", err)
	}

	// Wrong CA → actionable unknown-authority error.
	otherDir := t.TempDir()
	other, err := InitCA(filepath.Join(otherDir, "ca"), CAOptions{})
	if err != nil {
		t.Fatal(err)
	}
	otherPEM, _ := os.ReadFile(other.CertFile)
	if _, err := VerifyChain(srvPEM, otherPEM, VerifyOptions{Usage: UsageServer, DNSName: "agent-1.internal"}); !errors.Is(err, ErrUntrustedCA) {
		t.Fatalf("wrong CA error = %v", err)
	}
}

// expiredCA issues a certificate that is already expired by backdating a copy.
func expiredCertificate(t *testing.T, ca *CA) []byte {
	t.Helper()
	// Issue a short-lived cert, then verify with a clock after NotAfter: that is
	// exactly the production failure mode and avoids sleeping.
	issued, err := ca.Issue(CertRequest{CommonName: "stale-agent", Usage: UsageClient, TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ParseCertificate(issued.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := ca.CertPEM
	if _, err := VerifyChain(issued.CertPEM, caPEM, VerifyOptions{
		Usage: UsageClient,
		Now:   leaf.NotAfter.Add(time.Hour),
	}); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired error = %v, want ErrExpired", err)
	} else {
		for _, want := range []string{"expired at", "renew/re-enroll", "docs/08"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("expired error is not actionable (%q missing): %v", want, err)
			}
		}
	}
	return issued.CertPEM
}

func TestExpiredCertificateIsActionable(t *testing.T) {
	ca, _ := testCA(t)
	expiredCertificate(t, ca)
}

func TestServerConfigRequiresTLS13AndClientCA(t *testing.T) {
	ca, dir := testCA(t)
	srv, err := ca.IssueServer([]string{"localhost"}, nil, time.Hour, filepath.Join(dir, "server"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ServerConfig(srv.CertFile, srv.KeyFile, "", true); !errors.Is(err, ErrMissingCA) {
		t.Fatalf("require-mtls without CA error = %v", err)
	}
	cfg, err := ServerConfig(srv.CertFile, srv.KeyFile, ca.CertFile, true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %x, want TLS 1.3", cfg.MinVersion)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert || cfg.ClientCAs == nil {
		t.Fatalf("client auth = %v, CAs = %v", cfg.ClientAuth, cfg.ClientCAs)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("server config has %d certificates (GetCertificate wrappers expect one)", len(cfg.Certificates))
	}
}

func TestClientConfigAlwaysSetsServerName(t *testing.T) {
	ca, _ := testCA(t)
	if _, err := ClientConfig(ca.CertFile, "", "", ""); !errors.Is(err, ErrMissingServerName) {
		t.Fatalf("empty ServerName error = %v, want ErrMissingServerName", err)
	}
	cfg, err := ClientConfig(ca.CertFile, "", "", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerName != "127.0.0.1" || cfg.MinVersion != tls.VersionTLS13 || cfg.RootCAs == nil {
		t.Fatalf("client config = %+v", cfg)
	}
}

// TestMTLSHandshake exercises a real mutual-TLS handshake over TCP: server
// requires client certs, client presents one, and a client without a cert is
// rejected.
func TestMTLSHandshake(t *testing.T) {
	ca, dir := testCA(t)
	srvFiles, err := ca.IssueServer(nil, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour, filepath.Join(dir, "server"))
	if err != nil {
		t.Fatal(err)
	}
	cliFiles, err := ca.IssueClient("gateway-1", time.Hour, filepath.Join(dir, "client"))
	if err != nil {
		t.Fatal(err)
	}
	srvCfg, err := ServerConfig(srvFiles.CertFile, srvFiles.KeyFile, ca.CertFile, true)
	if err != nil {
		t.Fatal(err)
	}
	cliCfg, err := ClientConfig(ca.CertFile, cliFiles.CertFile, cliFiles.KeyFile, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for i := 0; i < 2; i++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.(*tls.Conn).Handshake()
			}(conn)
		}
	}()
	addr := ln.Addr().String()
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		addr = "127.0.0.1:" + strings.TrimPrefix(addr, "[::]:")
	}

	conn, err := tls.Dial("tcp", addr, cliCfg)
	if err == nil {
		_ = conn.Close()
	} else {
		t.Fatalf("mTLS handshake failed: %v", err)
	}

	// A client with no certificate must be rejected by strict mTLS.
	noCertCfg, err := ClientConfig(ca.CertFile, "", "", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	conn2, err := tls.Dial("tcp", addr, noCertCfg)
	if err == nil {
		_, werr := conn2.Write([]byte("nope"))
		_ = conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, rerr := conn2.Read(make([]byte, 1))
		conn2.Close()
		if werr == nil && rerr == nil {
			t.Fatal("strict mTLS accepted a client without a certificate")
		}
	}
}

// reloader is the production shape of hot certificate rotation: GetCertificate
// reloads from disk when the cached certificate is inside its renewal window.
type reloader struct {
	mu       sync.Mutex
	certFile string
	keyFile  string
	cert     *tls.Certificate
	leaf     *x509.Certificate
	reloads  int
}

func (r *reloader) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	reload := r.cert == nil || r.leaf == nil || ShouldRenew(r.leaf)
	if reload {
		cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
		if err != nil {
			if r.cert != nil {
				return r.cert, nil // transient torn file during rotate: keep serving
			}
			return nil, err
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, err
		}
		r.cert, r.leaf = &cert, leaf
		r.reloads++
	}
	return r.cert, nil
}

// TestRotationWithoutDowntime rotates the server certificate on disk while
// requests are flowing. No request may fail; connections are deliberately not
// reused (DisableKeepAlives) so every request needs a fresh handshake.
func TestRotationWithoutDowntime(t *testing.T) {
	ca, dir := testCA(t)
	serverDir := filepath.Join(dir, "server")
	srvFiles, err := ca.IssueServer(nil, []net.IP{net.ParseIP("127.0.0.1")}, 2*time.Minute, serverDir)
	if err != nil {
		t.Fatal(err)
	}
	reload := &reloader{certFile: srvFiles.CertFile, keyFile: srvFiles.KeyFile}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	baseCfg, err := ServerConfig(srvFiles.CertFile, srvFiles.KeyFile, "", false)
	if err != nil {
		t.Fatal(err)
	}
	baseCfg.GetCertificate = reload.getCertificate
	baseCfg.Certificates = nil // GetCertificate is the single source of truth
	ln, err := tls.Listen("tcp", "127.0.0.1:0", baseCfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	url := "https://" + ln.Addr().String()
	host, _, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cliCfg, err := ClientConfig(ca.CertFile, "", "", host)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   cliCfg,
		DisableKeepAlives: true,
	}, Timeout: 5 * time.Second}

	first := fetchFingerprint(t, client, url)
	// Rotate: issue a fresh certificate and atomically replace the files.
	rotated, err := ca.IssueServer(nil, []net.IP{net.ParseIP("127.0.0.1")}, 2*time.Minute, serverDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(rotated.CertFile); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		_ = fetchFingerprint(t, client, url)
	}
	last := fetchFingerprint(t, client, url)
	if first == last {
		t.Fatalf("server kept serving the old certificate after rotation (fingerprint %s)", first)
	}
	if reload.reloads < 2 {
		t.Fatalf("expected at least two reloads, got %d", reload.reloads)
	}
}

func fetchFingerprint(t *testing.T, client *http.Client, url string) string {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("request during rotation failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status during rotation = %d", resp.StatusCode)
	}
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		t.Fatal("no peer certificate")
	}
	return Fingerprint(resp.TLS.PeerCertificates[0])
}

// TestPlaintextPeerGetsActionableError covers the mixed-mode failure mode: a
// gateway in strict TLS mode dials an old plaintext agent.
func TestPlaintextPeerGetsActionableError(t *testing.T) {
	ca, _ := testCA(t)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "plain")
	}))
	defer plain.Close()
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(plain.URL, "http://"))
	cfg, err := ClientConfig(ca.CertFile, "", "", host)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 3 * time.Second}
	_, reqErr := client.Get("https://" + host + "/")
	if reqErr == nil {
		t.Fatal("TLS client talked to a plaintext server")
	}
	msg := ExplainTLSHandshakeError(reqErr, host)
	if !strings.Contains(msg.Error(), "plaintext") && !strings.Contains(msg.Error(), "TLS handshake") {
		t.Fatalf("handshake error is not actionable: %v", msg)
	}
}

func TestRenewalWindow(t *testing.T) {
	ca, _ := testCA(t)
	issued, err := ca.Issue(CertRequest{CommonName: "agent", Usage: UsageClient, TTL: 90 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	w, err := RenewalWindow(issued.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	if w != 24*time.Hour {
		t.Fatalf("90-day cert renewal window = %v, want 24h (capped)", w)
	}
	short, err := ca.Issue(CertRequest{CommonName: "short", Usage: UsageClient, TTL: 2 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	w, err = RenewalWindow(short.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	if w != 5*time.Minute {
		t.Fatalf("2-minute cert renewal window = %v, want 5m floor", w)
	}
	notAfter, err := NotAfter(short.CertPEM)
	if err != nil || time.Until(notAfter) > 3*time.Minute {
		t.Fatalf("NotAfter = %v err=%v", notAfter, err)
	}
	if fmt.Sprint(Fingerprint(issued.Cert)) == "" {
		t.Fatal("empty fingerprint")
	}
}
