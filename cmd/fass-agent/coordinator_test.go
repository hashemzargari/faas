package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/pki"
)

func TestBuildCoordinatorClientFailClosed(t *testing.T) {
	ca, caFile := testCA(t)
	server := issueTestServerCert(t, ca, time.Hour)
	client := issueTestClientCert(t, ca)
	const httpsURL = "https://127.0.0.1:7000"

	cases := []struct {
		name    string
		cfg     config
		wantErr string
	}{
		{
			name:    "https without coordinator CA refuses to start",
			cfg:     config{coordURL: httpsURL},
			wantErr: "without --coordinator-ca",
		},
		{
			name:    "https does not fall back to shard-listener CA",
			cfg:     config{coordURL: httpsURL, tlsCert: server.CertFile, tlsKey: server.KeyFile, tlsCA: caFile},
			wantErr: "without --coordinator-ca",
		},
		{
			name:    "https with missing CA file",
			cfg:     config{coordURL: httpsURL, coordCA: "/nonexistent/ca.crt"},
			wantErr: "read CA bundle",
		},
		{
			name:    "https with server-only explicit client certificate",
			cfg:     config{coordURL: httpsURL, coordCA: caFile, coordClientCert: server.CertFile, coordClientKey: server.KeyFile},
			wantErr: "client-auth EKU",
		},
		{
			name:    "https with half a client certificate pair",
			cfg:     config{coordURL: httpsURL, coordCA: caFile, coordClientCert: client.CertFile},
			wantErr: "must be set together",
		},
		{
			name:    "http outside insecure refuses",
			cfg:     config{coordURL: "http://127.0.0.1:7000"},
			wantErr: "plaintext http://",
		},
		{
			name:    "schemeless host:port is treated as plaintext and refuses",
			cfg:     config{coordURL: "127.0.0.1:7000"},
			wantErr: "plaintext http://",
		},
		{
			name:    "insecure conflicts with coordinator TLS flags",
			cfg:     config{coordURL: "http://127.0.0.1:7000", insecure: true, coordCA: caFile},
			wantErr: "conflicts with coordinator TLS flags",
		},
		{
			name:    "unsupported scheme",
			cfg:     config{coordURL: "ftp://127.0.0.1:7000"},
			wantErr: "unsupported coordinator URL scheme",
		},
		{
			name:    "empty URL",
			cfg:     config{},
			wantErr: "coordinator URL is empty",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logger, _ := captureLogger()
			_, err := buildCoordinatorClient(tc.cfg, logger)
			if err == nil {
				t.Fatalf("buildCoordinatorClient succeeded, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}

	// Valid configurations.
	valid := []struct {
		name string
		cfg  config
	}{
		{
			name: "https derives server name from URL host",
			cfg:  config{coordURL: httpsURL, coordCA: caFile},
		},
		{
			name: "https with explicit server name",
			cfg:  config{coordURL: httpsURL, coordCA: caFile, coordServerName: "localhost"},
		},
		{
			name: "https with explicit client identity",
			cfg: config{coordURL: httpsURL, coordCA: caFile,
				coordClientCert: client.CertFile, coordClientKey: client.KeyFile},
		},
		{
			name: "plaintext with insecure",
			cfg:  config{coordURL: "http://127.0.0.1:7000", insecure: true},
		},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			logger, buf := captureLogger()
			cli, err := buildCoordinatorClient(tc.cfg, logger)
			if err != nil {
				t.Fatalf("buildCoordinatorClient: %v", err)
			}
			if cli == nil {
				t.Fatal("nil coordinator client")
			}
			if strings.HasPrefix(tc.cfg.coordURL, "https://") &&
				!strings.Contains(buf.String(), "coordinator control-plane TLS enabled") {
				t.Fatalf("missing TLS startup log:\n%s", buf.String())
			}
		})
	}
}

func TestCoordinatorClientIdentitySelection(t *testing.T) {
	ca, _ := testCA(t)
	server := issueTestServerCert(t, ca, time.Hour)
	client := issueTestClientCert(t, ca)
	both := issueTestBothCert(t, ca)

	cases := []struct {
		name        string
		cfg         config
		wantCert    string
		wantErr     bool
		errContains string
	}{
		{
			name:     "explicit coordinator identity",
			cfg:      config{coordClientCert: client.CertFile, coordClientKey: client.KeyFile},
			wantCert: client.CertFile,
		},
		{
			name:        "explicit server-only identity fails",
			cfg:         config{coordClientCert: server.CertFile, coordClientKey: server.KeyFile},
			wantErr:     true,
			errContains: "client-auth EKU",
		},
		{
			name:     "fallback to repair identity",
			cfg:      config{tlsClientCert: client.CertFile, tlsClientKey: client.KeyFile},
			wantCert: client.CertFile,
		},
		{
			name:     "fallback to both-usage listener identity",
			cfg:      config{tlsCert: both.CertFile, tlsKey: both.KeyFile},
			wantCert: both.CertFile,
		},
		{
			name:     "server-only listener identity is skipped (server-auth-only coordinator)",
			cfg:      config{tlsCert: server.CertFile, tlsKey: server.KeyFile},
			wantCert: "",
		},
		{
			name:     "no identity at all is allowed",
			cfg:      config{},
			wantCert: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert, _, err := coordinatorClientIdentity(tc.cfg)
			if tc.wantErr {
				if err == nil {
					t.Fatal("coordinatorClientIdentity succeeded, want error")
				}
				if !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("err = %v, want %q", err, tc.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("coordinatorClientIdentity: %v", err)
			}
			if cert != tc.wantCert {
				t.Fatalf("cert = %q, want %q", cert, tc.wantCert)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TLS coordinator test double
// ---------------------------------------------------------------------------

type tlsFakeCoordinator struct {
	mu         sync.Mutex
	peerCNs    []string
	announces  int
	heartbeats int
	announceCh chan struct{}
}

func (f *tlsFakeCoordinator) heartbeatCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.heartbeats
}

func (f *tlsFakeCoordinator) firstPeerCN() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.peerCNs) == 0 {
		return ""
	}
	return f.peerCNs[0]
}

// newTLSFakeCoordinator serves the announce/heartbeat endpoints over mutual TLS
// using a pki-issued coordinator certificate that requires client certificates.
func newTLSFakeCoordinator(t *testing.T, ca *pki.CA, caFile string) (*tlsFakeCoordinator, *httptest.Server) {
	t.Helper()
	served := issueTestServerCert(t, ca, time.Hour)
	serverCfg, err := pki.ServerConfig(served.CertFile, served.KeyFile, caFile, true)
	if err != nil {
		t.Fatalf("pki.ServerConfig: %v", err)
	}

	f := &tlsFakeCoordinator{announceCh: make(chan struct{}, 4)}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/agents/announce", func(w http.ResponseWriter, r *http.Request) {
		var req contract.AnnounceRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode announce: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cn := ""
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			cn = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		f.mu.Lock()
		f.announces++
		f.peerCNs = append(f.peerCNs, cn)
		f.mu.Unlock()
		select {
		case f.announceCh <- struct{}{}:
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(contract.AnnounceResult{
			AgentID: "agent-tls", NexusID: "nexus-tls", State: "active",
		})
	})
	mux.HandleFunc("POST /v1/agents/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.heartbeats++
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})

	ts := httptest.NewUnstartedServer(mux)
	ts.TLS = serverCfg
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return f, ts
}

func coordinatorHostPort(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	u := strings.TrimPrefix(ts.URL, "https://")
	u = strings.TrimPrefix(u, "http://")
	if _, _, err := net.SplitHostPort(u); err != nil {
		t.Fatalf("bad test server URL %q: %v", ts.URL, err)
	}
	return u
}

func TestCoordinatorTLSAnnounceHeartbeatWithClientCert(t *testing.T) {
	ca, caFile := testCA(t)
	fake, ts := newTLSFakeCoordinator(t, ca, caFile)
	client := issueTestClientCert(t, ca)

	logger, _ := captureLogger()
	cli, err := buildCoordinatorClient(config{
		coordURL:        ts.URL,
		coordCA:         caFile,
		coordServerName: "127.0.0.1",
		coordClientCert: client.CertFile,
		coordClientKey:  client.KeyFile,
	}, logger)
	if err != nil {
		t.Fatalf("buildCoordinatorClient: %v", err)
	}

	res, err := cli.Announce(context.Background(), contract.AnnounceRequest{
		PublicKey: []byte{1, 2, 3}, Secret: "s", NodeID: "node-tls", DiskID: "disk-tls", Port: 7100,
	})
	if err != nil {
		t.Fatalf("Announce over TLS: %v", err)
	}
	if res.AgentID != "agent-tls" {
		t.Fatalf("announce result = %+v", res)
	}
	if err := cli.Heartbeat(context.Background(), contract.Heartbeat{AgentID: res.AgentID, DiskID: "disk-tls"}); err != nil {
		t.Fatalf("Heartbeat over TLS: %v", err)
	}
	if got := fake.firstPeerCN(); got != "agent-1" {
		t.Fatalf("coordinator saw client cert CN %q, want agent-1", got)
	}
	if fake.heartbeatCount() == 0 {
		t.Fatal("coordinator received no heartbeat")
	}
}

func TestCoordinatorRequireMTLSRejectsAgentWithoutClientCert(t *testing.T) {
	ca, caFile := testCA(t)
	_, ts := newTLSFakeCoordinator(t, ca, caFile)

	logger, _ := captureLogger()
	cli, err := buildCoordinatorClient(config{
		coordURL:        ts.URL,
		coordCA:         caFile,
		coordServerName: "127.0.0.1",
	}, logger)
	if err != nil {
		t.Fatalf("buildCoordinatorClient: %v", err)
	}
	_, err = cli.Announce(context.Background(), contract.AnnounceRequest{
		PublicKey: []byte{1}, Secret: "s", NodeID: "node-tls", DiskID: "disk-tls", Port: 7100,
	})
	if err == nil {
		t.Fatal("announce without a client certificate succeeded against an mTLS coordinator")
	}
	if !strings.Contains(err.Error(), "mutual TLS") || !strings.Contains(err.Error(), "coordinator-client-cert") {
		t.Fatalf("error is not actionable: %v", err)
	}
}

func TestHTTPSURLAgainstPlaintextCoordinatorDoesNotSilentlyWork(t *testing.T) {
	ca, caFile := testCA(t)
	_ = ca
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(contract.AnnounceResult{AgentID: "should-not-happen"})
	}))
	defer plain.Close()

	logger, _ := captureLogger()
	httpsURL := "https://" + strings.TrimPrefix(plain.URL, "http://")
	cli, err := buildCoordinatorClient(config{coordURL: httpsURL, coordCA: caFile}, logger)
	if err != nil {
		t.Fatalf("buildCoordinatorClient: %v", err)
	}
	res, err := cli.Announce(context.Background(), contract.AnnounceRequest{
		PublicKey: []byte{1}, Secret: "s", NodeID: "n", DiskID: "d", Port: 7100,
	})
	if err == nil {
		t.Fatalf("https:// client silently talked to a plaintext server: %+v", res)
	}
	if !strings.Contains(err.Error(), "plaintext") && !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("error is not actionable: %v", err)
	}
}

func TestRunAnnouncesOverTLSControlPlane(t *testing.T) {
	ca, caFile := testCA(t)
	fake, ts := newTLSFakeCoordinator(t, ca, caFile)
	client := issueTestClientCert(t, ca)
	port := freePort(t)

	env := baseEnv(t, ts.URL) // shard listener stays plaintext (--insecure) in this test
	env["FASS_AGENT_PORT"] = strconv.Itoa(port)
	env["FASS_AGENT_SECRET"] = "tls-control-secret"
	env["FASS_AGENT_COORDINATOR_CA"] = caFile
	env["FASS_AGENT_COORDINATOR_SERVER_NAME"] = "127.0.0.1"
	env["FASS_AGENT_COORDINATOR_CLIENT_CERT"] = client.CertFile
	env["FASS_AGENT_COORDINATOR_CLIENT_KEY"] = client.KeyFile
	env["FASS_AGENT_HEARTBEAT_INTERVAL"] = "25ms"

	cfg, err := parseFlagsWithEnv(nil, mapEnv(env))
	if err != nil {
		t.Fatalf("parseFlagsWithEnv: %v", err)
	}
	stop, logs := startAgentForTest(t, cfg)
	defer stop()

	select {
	case <-fake.announceCh:
	case <-time.After(10 * time.Second):
		t.Fatalf("agent did not announce over TLS; logs:\n%s", logs.String())
	}
	deadline := time.Now().Add(10 * time.Second)
	for fake.heartbeatCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("agent did not heartbeat over TLS; logs:\n%s", logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := fake.firstPeerCN(); got != "agent-1" {
		t.Fatalf("coordinator saw client cert CN %q, want agent-1", got)
	}
	if !strings.Contains(logs.String(), "coordinator control-plane TLS enabled") {
		t.Fatalf("missing control-plane TLS startup log:\n%s", logs.String())
	}
}

func TestRunWithoutClientCertLogsActionableMTLSError(t *testing.T) {
	ca, caFile := testCA(t)
	_, ts := newTLSFakeCoordinator(t, ca, caFile)
	port := freePort(t)

	env := baseEnv(t, ts.URL)
	env["FASS_AGENT_PORT"] = strconv.Itoa(port)
	env["FASS_AGENT_SECRET"] = "tls-control-secret"
	env["FASS_AGENT_COORDINATOR_CA"] = caFile
	env["FASS_AGENT_COORDINATOR_SERVER_NAME"] = "127.0.0.1"

	cfg, err := parseFlagsWithEnv(nil, mapEnv(env))
	if err != nil {
		t.Fatalf("parseFlagsWithEnv: %v", err)
	}
	stop, logs := startAgentForTest(t, cfg)
	time.Sleep(750 * time.Millisecond) // let at least one announce attempt fail
	stop()

	if !strings.Contains(logs.String(), "mutual TLS") || !strings.Contains(logs.String(), "coordinator-client-cert") {
		t.Fatalf("mTLS rejection was not explained actionably:\n%s", logs.String())
	}
}
