package coordclient_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fass-storage/fass/internal/agent/coordclient"
	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/pki"
)

func testPKI(t *testing.T, serverRequiresClient bool) (caFile, serverCert, serverKey string, ts *httptest.Server) {
	t.Helper()
	caDir := t.TempDir()
	ca, err := pki.InitCA(caDir, pki.CAOptions{CommonName: "test-ca"})
	if err != nil {
		t.Fatalf("pki.InitCA: %v", err)
	}
	served, err := ca.IssueServer([]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour, t.TempDir())
	if err != nil {
		t.Fatalf("IssueServer: %v", err)
	}
	cfg, err := pki.ServerConfig(served.CertFile, served.KeyFile, ca.CertFile, serverRequiresClient)
	if err != nil {
		t.Fatalf("ServerConfig: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/agents/announce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(contract.AnnounceResult{AgentID: "agent-1"})
	})
	ts = httptest.NewUnstartedServer(mux)
	ts.TLS = cfg
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ca.CertFile, served.CertFile, served.KeyFile, ts
}

func TestTLSHandshakeErrorsAreActionable(t *testing.T) {
	caFile, _, _, ts := testPKI(t, true)

	// Server-auth-only client (no client certificate) against an mTLS server.
	clientCfg, err := pki.ClientConfig(caFile, "", "", "127.0.0.1")
	if err != nil {
		t.Fatalf("ClientConfig: %v", err)
	}
	hc := &http.Client{
		Transport: &http.Transport{TLSClientConfig: clientCfg.Clone()},
		Timeout:   5 * time.Second,
	}
	cli, err := coordclient.New(ts.URL, coordclient.Options{
		HTTPClient: hc, TLSEnabled: true, PeerName: "coordinator-test", Logger: discardLogger(),
	})
	if err != nil {
		t.Fatalf("coordclient.New: %v", err)
	}
	_, err = cli.Announce(context.Background(), contract.AnnounceRequest{
		PublicKey: []byte{1}, Secret: "s", NodeID: "n", DiskID: "d", Port: 7100,
	})
	if err == nil {
		t.Fatal("announce without a client certificate succeeded against an mTLS coordinator")
	}
	msg := err.Error()
	if !strings.Contains(msg, "mutual TLS") || !strings.Contains(msg, "coordinator-client-cert") {
		t.Fatalf("error is not actionable: %v", err)
	}
}

func TestSchemeValidation(t *testing.T) {
	for _, raw := range []string{"ftp://127.0.0.1:7000", "unix:///tmp/sock"} {
		if _, err := coordclient.New(raw, coordclient.Options{Logger: discardLogger()}); err == nil {
			t.Fatalf("coordclient.New(%q) accepted an unsupported scheme", raw)
		}
	}
}

var _ = tls.VersionTLS13
