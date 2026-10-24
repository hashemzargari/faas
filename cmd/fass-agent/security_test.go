package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fass-storage/fass/internal/agent/transport"
	"github.com/fass-storage/fass/internal/pki"
)

func testCA(t *testing.T) (*pki.CA, string) {
	t.Helper()
	dir := t.TempDir()
	ca, err := pki.InitCA(dir, pki.CAOptions{CommonName: "fass-test-ca"})
	if err != nil {
		t.Fatalf("pki.InitCA: %v", err)
	}
	return ca, ca.CertFile
}

func issueTestServerCert(t *testing.T, ca *pki.CA, ttl time.Duration) pki.CertFiles {
	t.Helper()
	files, err := ca.IssueServer([]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, ttl, t.TempDir())
	if err != nil {
		t.Fatalf("IssueServer: %v", err)
	}
	return files
}

func issueTestClientCert(t *testing.T, ca *pki.CA) pki.CertFiles {
	t.Helper()
	files, err := ca.IssueClient("agent-1", time.Hour, t.TempDir())
	if err != nil {
		t.Fatalf("IssueClient: %v", err)
	}
	return files
}

// issueTestBothCert writes a certificate usable as both TLS server and client
// (pki.UsageBoth), which is what an agent that also repairs over mTLS needs.
func issueTestBothCert(t *testing.T, ca *pki.CA) pki.CertFiles {
	t.Helper()
	issued, err := ca.Issue(pki.CertRequest{
		CommonName:  "agent-both",
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		Usage:       pki.UsageBoth,
		TTL:         time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue(UsageBoth): %v", err)
	}
	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, issued.CertPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, issued.KeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return pki.CertFiles{CertFile: certFile, KeyFile: keyFile, CAFile: ca.CertFile}
}

func captureLogger() (*slog.Logger, *lockedBuffer) {
	buf := &lockedBuffer{}
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})), buf
}

func TestBuildAgentSecurityRules(t *testing.T) {
	ca, caFile := testCA(t)
	server := issueTestServerCert(t, ca, time.Hour)
	client := issueTestClientCert(t, ca)
	both := issueTestBothCert(t, ca)

	base := config{
		tlsCert: server.CertFile,
		tlsKey:  server.KeyFile,
		tlsCA:   caFile,
	}

	cases := []struct {
		name    string
		cfg     config
		wantErr string
		check   func(t *testing.T, sec *agentSecurity)
	}{
		{
			name: "insecure explicit plaintext",
			cfg:  config{insecure: true},
			check: func(t *testing.T, sec *agentSecurity) {
				if !sec.insecure || sec.serverTLS != nil || sec.httpClient != nil || sec.scheme != "http" {
					t.Fatalf("insecure security = %+v", sec)
				}
			},
		},
		{
			name:    "insecure conflicts with TLS material",
			cfg:     config{insecure: true, tlsCert: server.CertFile, tlsKey: server.KeyFile},
			wantErr: "conflicting TLS configuration",
		},
		{
			name:    "no TLS material and no insecure",
			cfg:     config{},
			wantErr: "TLS is required",
		},
		{
			name:    "cert without key",
			cfg:     config{tlsCert: server.CertFile},
			wantErr: "TLS is required",
		},
		{
			name:    "require-mtls without CA",
			cfg:     config{tlsCert: server.CertFile, tlsKey: server.KeyFile, requireMTLS: true},
			wantErr: "--tls-ca",
		},
		{
			name:    "repair without CA",
			cfg:     config{tlsCert: server.CertFile, tlsKey: server.KeyFile, repair: true},
			wantErr: "--tls-ca",
		},
		{
			name:    "server-only cert cannot be the repair client identity",
			cfg:     config{tlsCert: server.CertFile, tlsKey: server.KeyFile, tlsCA: caFile, repair: true},
			wantErr: "client authentication",
		},
		{
			name:    "half a client cert pair",
			cfg:     config{tlsCert: server.CertFile, tlsKey: server.KeyFile, tlsCA: caFile, repair: true, tlsClientCert: client.CertFile},
			wantErr: "must be set together",
		},
		{
			name: "TLS without repair or CA is valid (server-auth only)",
			cfg:  config{tlsCert: server.CertFile, tlsKey: server.KeyFile, repair: false},
			check: func(t *testing.T, sec *agentSecurity) {
				if sec.insecure || sec.serverTLS == nil || sec.httpClient != nil || sec.scheme != "https" {
					t.Fatalf("security = %+v", sec)
				}
				info := sec.serverTLS.Info()
				if !info.Enabled || info.Mutual || info.NotAfter.IsZero() || info.Issuer == "" {
					t.Fatalf("info = %+v", info)
				}
			},
		},
		{
			name: "repair TLS with an explicit client identity",
			cfg:  config{tlsCert: server.CertFile, tlsKey: server.KeyFile, tlsCA: caFile, repair: true, tlsClientCert: client.CertFile, tlsClientKey: client.KeyFile},
			check: func(t *testing.T, sec *agentSecurity) {
				if sec.httpClient == nil || sec.scheme != "https" {
					t.Fatalf("security = %+v", sec)
				}
			},
		},
		{
			name: "repair TLS with a both-usage identity as fallback",
			cfg:  config{tlsCert: both.CertFile, tlsKey: both.KeyFile, tlsCA: caFile, repair: true},
			check: func(t *testing.T, sec *agentSecurity) {
				if sec.httpClient == nil {
					t.Fatalf("security = %+v", sec)
				}
			},
		},
		{
			name: "require-mtls with CA",
			cfg:  config{tlsCert: server.CertFile, tlsKey: server.KeyFile, tlsCA: caFile, requireMTLS: true, repair: false},
			check: func(t *testing.T, sec *agentSecurity) {
				if !sec.serverTLS.Mutual() {
					t.Fatal("require-mtls did not enable mutual TLS")
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logger, buf := captureLogger()
			sec, err := buildAgentSecurity(tc.cfg, logger)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("buildAgentSecurity succeeded, want error containing %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("buildAgentSecurity: %v", err)
			}
			if tc.check != nil {
				tc.check(t, sec)
			}
			if tc.cfg.insecure && !strings.Contains(buf.String(), "TRANSPORT IS PLAINTEXT") {
				t.Fatalf("insecure start did not log the plaintext warning:\n%s", buf.String())
			}
		})
	}
}

func TestInsecureWarnsOnEveryStart(t *testing.T) {
	logger, buf := captureLogger()
	for i := 0; i < 2; i++ {
		if _, err := buildAgentSecurity(config{insecure: true}, logger); err != nil {
			t.Fatalf("buildAgentSecurity: %v", err)
		}
	}
	if strings.Count(buf.String(), "TRANSPORT IS PLAINTEXT") != 2 {
		t.Fatalf("plaintext warning not logged once per start:\n%s", buf.String())
	}
}

func TestEnvTLSFlagsAndPrecedence(t *testing.T) {
	ca, caFile := testCA(t)
	server := issueTestServerCert(t, ca, time.Hour)

	cfg, err := parseFlagsWithEnv(nil, mapEnv(map[string]string{
		"FASS_AGENT_TLS_CERT":  server.CertFile,
		"FASS_AGENT_TLS_KEY":   server.KeyFile,
		"FASS_AGENT_TLS_CA":    caFile,
		"FASS_AGENT_REQUIRE_MTLS": "true",
		"FASS_AGENT_REPAIR":    "false",
	}))
	if err != nil {
		t.Fatalf("parseFlagsWithEnv: %v", err)
	}
	if cfg.tlsCert != server.CertFile || cfg.tlsKey != server.KeyFile || cfg.tlsCA != caFile {
		t.Fatalf("TLS env not applied: %+v", cfg)
	}
	if !cfg.requireMTLS || cfg.repair {
		t.Fatalf("requireMTLS/repair = %v/%v", cfg.requireMTLS, cfg.repair)
	}

	// Explicit flags beat the environment.
	cfg, err = parseFlagsWithEnv([]string{"--tls-cert", "/flag/cert.pem", "--require-mtls=false"},
		mapEnv(map[string]string{
			"FASS_AGENT_TLS_CERT":     server.CertFile,
			"FASS_AGENT_REQUIRE_MTLS": "true",
		}))
	if err != nil {
		t.Fatalf("parseFlagsWithEnv: %v", err)
	}
	if cfg.tlsCert != "/flag/cert.pem" || cfg.requireMTLS {
		t.Fatalf("flags did not override TLS env: %+v", cfg)
	}

	// FASS_AGENT_INSECURE is a real boolean env var.
	cfg, err = parseFlagsWithEnv(nil, mapEnv(map[string]string{"FASS_AGENT_INSECURE": "true"}))
	if err != nil {
		t.Fatalf("parseFlagsWithEnv: %v", err)
	}
	if !cfg.insecure {
		t.Fatal("FASS_AGENT_INSECURE was not applied")
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// startAgentForTest runs run() in the background and returns a stop function
// plus the captured log buffer.
func startAgentForTest(t *testing.T, cfg config) (stop func(), logs *lockedBuffer) {
	t.Helper()
	logger, buf := captureLogger()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg, logger) }()
	stop = func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("run: %v", err)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("agent did not stop")
		}
	}
	return stop, buf
}

func waitForHTTP(t *testing.T, hc *http.Client, url string) *http.Response {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := hc.Get(url)
		if err == nil {
			return resp
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("endpoint %s never became reachable: %v", url, lastErr)
	return nil
}

func TestRunInsecureHealthzEndToEnd(t *testing.T) {
	port := freePort(t)
	env := baseEnv(t, "http://127.0.0.1:1") // no coordinator contact needed
	env["FASS_AGENT_PORT"] = itoa(port)
	cfg, err := parseFlagsWithEnv(nil, mapEnv(env))
	if err != nil {
		t.Fatalf("parseFlagsWithEnv: %v", err)
	}
	stop, logs := startAgentForTest(t, cfg)
	defer stop()

	resp := waitForHTTP(t, &http.Client{Timeout: 2 * time.Second}, "http://127.0.0.1:"+itoa(port)+"/v1/healthz")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d", resp.StatusCode)
	}
	var health map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatal(err)
	}
	if health["tls"] != false || health["insecure"] != true {
		t.Fatalf("healthz = %v, want tls:false insecure:true", health)
	}
	if !strings.Contains(logs.String(), "TRANSPORT IS PLAINTEXT") {
		t.Fatalf("startup did not warn about plaintext:\n%s", logs.String())
	}
}

func TestRunTLSListenerEndToEnd(t *testing.T) {
	ca, caFile := testCA(t)
	server := issueTestServerCert(t, ca, time.Hour)
	port := freePort(t)

	env := baseEnv(t, "http://127.0.0.1:1")
	env["FASS_AGENT_PORT"] = itoa(port)
	delete(env, "FASS_AGENT_INSECURE") // TLS is the default; no opt-out here
	env["FASS_AGENT_TLS_CERT"] = server.CertFile
	env["FASS_AGENT_TLS_KEY"] = server.KeyFile
	env["FASS_AGENT_TLS_CA"] = caFile
	env["FASS_AGENT_REPAIR"] = "false"

	cfg, err := parseFlagsWithEnv(nil, mapEnv(env))
	if err != nil {
		t.Fatalf("parseFlagsWithEnv: %v", err)
	}
	stop, logs := startAgentForTest(t, cfg)
	defer stop()

	clientCfg, err := pki.ClientConfig(caFile, "", "", "127.0.0.1")
	if err != nil {
		t.Fatalf("pki.ClientConfig: %v", err)
	}
	hc := &http.Client{
		Transport: &http.Transport{TLSClientConfig: clientCfg},
		Timeout:   5 * time.Second,
	}
	resp := waitForHTTP(t, hc, "https://127.0.0.1:"+itoa(port)+"/v1/healthz")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("TLS healthz status = %d", resp.StatusCode)
	}
	var health map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatal(err)
	}
	if health["tls"] != true || health["insecure"] != false {
		t.Fatalf("healthz = %v, want tls:true insecure:false", health)
	}
	if health["tls_not_after"] == nil {
		t.Fatalf("healthz is missing tls_not_after: %v", health)
	}

	statsResp, err := hc.Get("https://127.0.0.1:" + itoa(port) + "/v1/stats")
	if err != nil {
		t.Fatalf("stats over TLS: %v", err)
	}
	defer statsResp.Body.Close()
	var stats struct {
		TLS struct {
			Enabled  bool    `json:"enabled"`
			Insecure bool    `json:"insecure"`
			NotAfter *string `json:"not_after"`
		} `json:"tls"`
	}
	if err := json.NewDecoder(statsResp.Body).Decode(&stats); err != nil {
		t.Fatal(err)
	}
	if !stats.TLS.Enabled || stats.TLS.Insecure || stats.TLS.NotAfter == nil {
		t.Fatalf("stats tls block = %+v", stats.TLS)
	}
	if !strings.Contains(logs.String(), "shard listener TLS enabled") {
		t.Fatalf("no TLS startup log:\n%s", logs.String())
	}
}

func TestHeartbeatSecurityFields(t *testing.T) {
	notAfter := time.Unix(1_800_000_000, 0).UTC()
	sec := heartbeatSecurity{TLSEnabled: true, CertNotAfter: &notAfter}
	hb, err := buildHeartbeat("agent-1", "disk-1", "", zeroStats(), 0, "", sec, time.Now().UTC())
	if err != nil {
		t.Fatalf("buildHeartbeat: %v", err)
	}
	if !hb.TLSEnabled || hb.Insecure {
		t.Fatalf("heartbeat TLS fields = tls:%v insecure:%v", hb.TLSEnabled, hb.Insecure)
	}
	if hb.CertNotAfter == nil || !hb.CertNotAfter.Equal(notAfter) {
		t.Fatalf("CertNotAfter = %v, want %v", hb.CertNotAfter, notAfter)
	}

	fromTransport := heartbeatSecurityFrom(transport.SecurityInfo{Enabled: true, NotAfter: notAfter})
	if !fromTransport.TLSEnabled || fromTransport.CertNotAfter == nil || !fromTransport.CertNotAfter.Equal(notAfter) {
		t.Fatalf("heartbeatSecurityFrom = %+v", fromTransport)
	}
	insecure := heartbeatSecurityFrom(transport.SecurityInfo{Insecure: true})
	if insecure.TLSEnabled || !insecure.Insecure || insecure.CertNotAfter != nil {
		t.Fatalf("insecure heartbeat security = %+v", insecure)
	}
}

// TestAgentCertificateMustHaveClientAuthEKU asserts the startup check that keeps
// a server-only certificate from silently failing later during repair.
func TestAgentCertificateMustHaveClientAuthEKU(t *testing.T) {
	ca, caFile := testCA(t)
	server := issueTestServerCert(t, ca, time.Hour)
	if err := requireClientAuthUsage(server.CertFile); !errors.Is(err, pki.ErrWrongUsage) {
		t.Fatalf("server-only cert accepted as client cert: %v", err)
	}
	client := issueTestClientCert(t, ca)
	if err := requireClientAuthUsage(client.CertFile); err != nil {
		t.Fatalf("client cert rejected: %v", err)
	}
	_ = caFile

	// Also prove the parse path rejects garbage.
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := requireClientAuthUsage(bad); err == nil {
		t.Fatal("garbage certificate accepted")
	}
}

func zeroStats() (stats storeStatsAlias) { return }

func itoa(v int) string {
	return strconvItoa(v)
}

// small indirections keep the test file's imports stable.
type storeStatsAlias = storeStats

func strconvItoa(v int) string { return strconv.Itoa(v) }

var _ = pem.Block{}
var _ = x509.Certificate{}
var _ = tls.VersionTLS13
var _ = io.Discard
