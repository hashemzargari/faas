package agenttls

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fass-storage/fass/internal/pki"
)

func testCA(t *testing.T) (*pki.CA, string) {
	t.Helper()
	dir := t.TempDir()
	ca, err := pki.InitCA(filepath.Join(dir, "ca"), pki.CAOptions{CommonName: "agenttls-test-ca"})
	if err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	return ca, dir
}

type tlsAgent struct {
	url      string
	host     string
	caFile   string
	certFile string
	keyFile  string
	srv      *http.Server
}

func startTLSAgent(t *testing.T, ca *pki.CA, caDir string, ttl time.Duration, requireClient bool) *tlsAgent {
	t.Helper()
	files, err := ca.IssueServer(nil, []net.IP{net.ParseIP("127.0.0.1")}, ttl, filepath.Join(caDir, "agent"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := pki.ServerConfig(files.CertFile, files.KeyFile, ca.CertFile, requireClient)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"state":"ready"}`)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	host, _, _ := net.SplitHostPort(ln.Addr().String())
	return &tlsAgent{url: "https://" + ln.Addr().String(), host: host, caFile: ca.CertFile, certFile: files.CertFile, keyFile: files.KeyFile, srv: srv}
}

func (a *tlsAgent) get(t *testing.T, client *http.Client) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, a.url+"/v1/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	return client.Do(req)
}

func TestRequireModeTalksTLS(t *testing.T) {
	ca, dir := testCA(t)
	agent := startTLSAgent(t, ca, dir, time.Hour, false)
	client, info, err := NewClient(Options{Mode: ModeRequire, CAFile: ca.CertFile})
	if err != nil {
		t.Fatal(err)
	}
	if info.Insecure || info.Mode != ModeRequire || info.Scheme() != "https" {
		t.Fatalf("info = %+v", info)
	}
	resp, err := agent.get(t, client)
	if err != nil {
		t.Fatalf("TLS GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if resp.TLS == nil || resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("negotiated TLS = %+v", resp.TLS)
	}
}

func TestStrictModeRejectsPlaintextAgent(t *testing.T) {
	ca, dir := testCA(t)
	_ = dir
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "plain")
	}))
	defer plain.Close()
	hostPort := strings.TrimPrefix(plain.URL, "http://")

	for _, mode := range []Mode{ModeRequire} {
		client, _, err := NewClient(Options{Mode: mode, CAFile: ca.CertFile, RequireMTLS: true, CertFile: ca.CertFile, KeyFile: ca.KeyFile})
		if err != nil {
			// The CA is a valid certificate chain to present as a client identity
			// for this construction-only test of plaintext rejection.
			t.Logf("NewClient with CA as client cert: %v", err)
			client, _, err = NewClient(Options{Mode: mode, CAFile: ca.CertFile})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
		}
		req, _ := http.NewRequest(http.MethodGet, "https://"+hostPort+"/v1/healthz", nil)
		if _, err := client.Do(req); err == nil {
			t.Fatalf("mode %s accepted a plaintext agent", mode)
		} else if !strings.Contains(err.Error(), "plaintext") && !strings.Contains(strings.ToLower(err.Error()), "tls") {
			t.Fatalf("error is not actionable: %v", err)
		}
	}
}

func TestAutoModeAllowsPlaintextDuringRolloutAndWarns(t *testing.T) {
	ca, _ := testCA(t)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "plain")
	}))
	defer plain.Close()
	hostPort := strings.TrimPrefix(plain.URL, "http://")

	var logs syncBuffer
	client, info, err := NewClient(Options{Mode: ModeAuto, CAFile: ca.CertFile, Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))})
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode != ModeAuto || info.Insecure {
		t.Fatalf("info = %+v", info)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://"+hostPort+"/v1/healthz", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("auto mode did not fall back to plaintext: %v", err)
	}
	resp.Body.Close()
	if !strings.Contains(logs.String(), "plaintext") {
		t.Fatalf("downgrade was not logged: %s", logs.String())
	}
}

func TestRequireMTLS(t *testing.T) {
	ca, dir := testCA(t)
	agent := startTLSAgent(t, ca, dir, time.Hour, true)
	cliFiles, err := ca.IssueClient("gateway-1", time.Hour, filepath.Join(dir, "gateway"))
	if err != nil {
		t.Fatal(err)
	}
	// Without a client certificate: construction fails closed.
	if _, _, err := NewClient(Options{Mode: ModeRequire, CAFile: ca.CertFile, RequireMTLS: true}); !errors.Is(err, pki.ErrMissingCert) {
		t.Fatalf("require-mtls without client cert error = %v", err)
	}
	client, info, err := NewClient(Options{
		Mode: ModeRequire, CAFile: ca.CertFile, RequireMTLS: true,
		CertFile: cliFiles.CertFile, KeyFile: cliFiles.KeyFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	if info.NotAfter.IsZero() || info.Fingerprint == "" {
		t.Fatalf("info lacks cert expiry/fingerprint: %+v", info)
	}
	resp, err := agent.get(t, client)
	if err != nil {
		t.Fatalf("mTLS GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestExpiredAgentCertificateIsActionable(t *testing.T) {
	ca, dir := testCA(t)
	agent := startTLSAgent(t, ca, dir, 500*time.Millisecond, false)
	time.Sleep(1200 * time.Millisecond) // let the certificate expire
	client, _, err := NewClient(Options{Mode: ModeRequire, CAFile: ca.CertFile})
	if err != nil {
		t.Fatal(err)
	}
	_, getErr := agent.get(t, client)
	if getErr == nil {
		t.Fatal("expired agent certificate was accepted")
	}
	msg := getErr.Error()
	for _, want := range []string{"expired", "renew", "docs/08"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("expired-cert error is not actionable (%q missing): %v", want, msg)
		}
	}
}

func TestOffModeIsExplicitlyInsecureAndVisible(t *testing.T) {
	client, info, err := NewClient(Options{Mode: ModeOff})
	if err != nil {
		t.Fatal(err)
	}
	if !info.Insecure || info.Scheme() != "http" {
		t.Fatalf("off mode info = %+v", info)
	}
	body, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"insecure":true`) {
		t.Fatalf("healthz security block = %s", body)
	}
	// Off mode really is plaintext.
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer plain.Close()
	req, _ := http.NewRequest(http.MethodGet, plain.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{"off": ModeOff, "auto": ModeAuto, "require": ModeRequire} {
		got, err := ParseMode(in)
		if err != nil || got != want {
			t.Fatalf("ParseMode(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParseMode("bogus"); err == nil {
		t.Fatal("invalid mode accepted")
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
