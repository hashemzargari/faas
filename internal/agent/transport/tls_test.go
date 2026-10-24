package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/fass-storage/fass/internal/agent/client"
	"github.com/fass-storage/fass/internal/agent/shard"
	"github.com/fass-storage/fass/internal/agent/store"
	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/pki"
)

// newTestCA creates a throwaway cluster CA and returns it plus the CA cert path.
func newTestCA(t *testing.T) (*pki.CA, string) {
	t.Helper()
	dir := t.TempDir()
	ca, err := pki.InitCA(dir, pki.CAOptions{CommonName: "fass-test-ca"})
	if err != nil {
		t.Fatalf("pki.InitCA: %v", err)
	}
	return ca, ca.CertFile
}

func issueServerCert(t *testing.T, ca *pki.CA, ttl time.Duration) pki.CertFiles {
	t.Helper()
	files, err := ca.IssueServer([]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, ttl, t.TempDir())
	if err != nil {
		t.Fatalf("IssueServer: %v", err)
	}
	return files
}

func issueClientCert(t *testing.T, ca *pki.CA, identity string) pki.CertFiles {
	t.Helper()
	files, err := ca.IssueClient(identity, time.Hour, t.TempDir())
	if err != nil {
		t.Fatalf("IssueClient: %v", err)
	}
	return files
}

// startTLSTransport runs a transport with the given TLS settings on a random
// loopback port and returns its "host:port" endpoint.
func startTLSTransport(t *testing.T, st *store.Store, sec *ServerTLS) string {
	t.Helper()
	srv, err := New(Options{Store: st, TLS: sec, Logger: discardLogger(), Version: "test"})
	if err != nil {
		t.Fatalf("transport.New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.ServeListener(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Errorf("transport did not stop")
		}
	})
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

func tlsHTTPClient(t *testing.T, caFile, certFile, keyFile, serverName string, disableKeepAlive bool) *http.Client {
	t.Helper()
	cfg, err := pki.ClientConfig(caFile, certFile, keyFile, serverName)
	if err != nil {
		t.Fatalf("pki.ClientConfig: %v", err)
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   cfg,
			DisableKeepAlives: disableKeepAlive,
		},
		Timeout: 10 * time.Second,
	}
}

func httpsGet(t *testing.T, hc *http.Client, url string) (*http.Response, []byte) {
	t.Helper()
	resp, err := hc.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	return resp, body
}

func mustHealthz(t *testing.T, hc *http.Client, endpoint string) healthResponse {
	t.Helper()
	resp, body := httpsGet(t, hc, "https://"+endpoint+"/v1/healthz")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d, body=%s", resp.StatusCode, body)
	}
	var out healthResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode healthz: %v", err)
	}
	return out
}

func TestTLSShardRoundTrip(t *testing.T) {
	ca, caFile := newTestCA(t)
	server := issueServerCert(t, ca, time.Hour)
	sec, err := NewServerTLS(server.CertFile, server.KeyFile, caFile, false, discardLogger())
	if err != nil {
		t.Fatalf("NewServerTLS: %v", err)
	}
	st := newTestStore(t, store.Options{})
	endpoint := startTLSTransport(t, st, sec)

	hc := tlsHTTPClient(t, caFile, "", "", "127.0.0.1", false)
	health := mustHealthz(t, hc, endpoint)
	if !health.TLS || health.Insecure {
		t.Fatalf("healthz security = tls:%v insecure:%v, want tls:true insecure:false", health.TLS, health.Insecure)
	}
	if health.TLSNotAfter == nil {
		t.Fatal("healthz is missing tls_not_after")
	}

	// The real shard data path must work end-to-end over TLS.
	c := client.New(client.Options{Scheme: "https", HTTPClient: hc})
	setID := contract.ShardSetID("aaaaaaaa-1111-4222-8333-444455556666")
	payload := bytes.Repeat([]byte("tls-shard"), 128)
	if err := c.PutShard(context.Background(), endpoint, contract.PutShardRequest{
		ShardSetID: setID,
		GeoGroup:   0,
		LocalIndex: 0,
		Params:     testParams,
		PayloadLen: len(payload),
		Checksum:   shard.Sum64(payload),
		Body:       bytes.NewReader(payload),
	}); err != nil {
		t.Fatalf("PutShard over TLS: %v", err)
	}
	rc, info, err := c.GetShard(context.Background(), endpoint, setID, 0, 0)
	if err != nil {
		t.Fatalf("GetShard over TLS: %v", err)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatalf("read shard over TLS: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("shard payload mismatch over TLS")
	}
	if info.Checksum != shard.Sum64(payload) {
		t.Fatalf("shard checksum = %016x", info.Checksum)
	}
}

func TestRequireMTLSRejectsCertlessAndPlaintextPeers(t *testing.T) {
	ca, caFile := newTestCA(t)
	server := issueServerCert(t, ca, time.Hour)
	sec, err := NewServerTLS(server.CertFile, server.KeyFile, caFile, true, discardLogger())
	if err != nil {
		t.Fatalf("NewServerTLS: %v", err)
	}
	if !sec.Mutual() {
		t.Fatal("ServerTLS.Mutual() = false, want true")
	}
	st := newTestStore(t, store.Options{})
	endpoint := startTLSTransport(t, st, sec)

	// A plaintext HTTP client cannot reach the shard API: the TLS listener
	// answers the bogus handshake with an HTTP 400 and never runs a handler.
	plain := &http.Client{Timeout: 2 * time.Second}
	plainResp, plainErr := plain.Get("http://" + endpoint + "/v1/healthz")
	if plainErr == nil {
		defer plainResp.Body.Close()
		if plainResp.StatusCode == http.StatusOK {
			t.Fatal("plaintext request to TLS listener served the agent API")
		}
		if plainResp.StatusCode != http.StatusBadRequest {
			t.Fatalf("plaintext request status = %d, want 400 TLS rejection", plainResp.StatusCode)
		}
	}

	// A TLS client without a client certificate is rejected because --require-mtls.
	certless := tlsHTTPClient(t, caFile, "", "", "127.0.0.1", false)
	_, err = certless.Get("https://" + endpoint + "/v1/healthz")
	if err == nil {
		t.Fatal("certless TLS client was accepted under --require-mtls")
	}
	explained := pki.ExplainTLSHandshakeError(err, "agent")
	if !bytes.Contains([]byte(explained.Error()), []byte("certificate")) {
		t.Fatalf("explained error is not actionable: %v", explained)
	}

	// With a client certificate issued by the cluster CA mTLS succeeds.
	clientCert := issueClientCert(t, ca, "gateway-1")
	mtls := tlsHTTPClient(t, caFile, clientCert.CertFile, clientCert.KeyFile, "127.0.0.1", false)
	health := mustHealthz(t, mtls, endpoint)
	if !health.TLS || health.Insecure {
		t.Fatalf("mTLS healthz = %+v", health)
	}
}

func TestExpiredCertificateRejectedWithActionableError(t *testing.T) {
	ca, caFile := newTestCA(t)
	server := issueServerCert(t, ca, 900*time.Millisecond)
	sec, err := NewServerTLS(server.CertFile, server.KeyFile, caFile, false, discardLogger())
	if err != nil {
		t.Fatalf("NewServerTLS: %v", err)
	}
	st := newTestStore(t, store.Options{})
	endpoint := startTLSTransport(t, st, sec)

	time.Sleep(1500 * time.Millisecond)

	hc := tlsHTTPClient(t, caFile, "", "", "127.0.0.1", false)
	_, err = hc.Get("https://" + endpoint + "/v1/healthz")
	if err == nil {
		t.Fatal("expired server certificate was accepted")
	}
	explained := pki.ExplainTLSHandshakeError(err, "agent")
	if !errors.Is(explained, pki.ErrExpired) {
		t.Fatalf("explained error = %v, want pki.ErrExpired", explained)
	}
	if !bytes.Contains([]byte(explained.Error()), []byte("renew")) {
		t.Fatalf("error is not actionable about renewal: %v", explained)
	}
}

func TestTLSHotReloadRotationWithoutFailedRequests(t *testing.T) {
	ca, caFile := newTestCA(t)
	// A 2s-lived certificate is already inside the renewal window (floor 5m),
	// so every handshake reloads from disk — exactly what we need to prove
	// rotation without restart.
	server := issueServerCert(t, ca, 2*time.Second)
	sec, err := NewServerTLS(server.CertFile, server.KeyFile, caFile, false, discardLogger())
	if err != nil {
		t.Fatalf("NewServerTLS: %v", err)
	}
	initial, err := pki.NotAfter(mustReadFile(t, server.CertFile))
	if err != nil {
		t.Fatal(err)
	}
	st := newTestStore(t, store.Options{})
	endpoint := startTLSTransport(t, st, sec)

	// Disable keep-alives so every request performs a fresh handshake.
	hc := tlsHTTPClient(t, caFile, "", "", "127.0.0.1", true)
	c := client.New(client.Options{Scheme: "https", HTTPClient: hc})
	setID := contract.ShardSetID("bbbbbbbb-1111-4222-8333-444455556666")

	put := func(i int) {
		payload := []byte{byte(i), byte(i + 1), byte(i + 2)}
		if err := c.PutShard(context.Background(), endpoint, contract.PutShardRequest{
			ShardSetID: setID,
			GeoGroup:   0,
			LocalIndex: i,
			Params:     testParams,
			PayloadLen: len(payload),
			Checksum:   shard.Sum64(payload),
			Body:       bytes.NewReader(payload),
		}); err != nil {
			t.Fatalf("PutShard(%d) during rotation: %v", i, err)
		}
	}

	probeSerial := func() *big.Int {
		t.Helper()
		probe := tlsHTTPClient(t, caFile, "", "", "127.0.0.1", true)
		resp, err := probe.Get("https://" + endpoint + "/v1/healthz")
		if err != nil {
			t.Fatalf("healthz probe: %v", err)
		}
		defer resp.Body.Close()
		if len(resp.TLS.PeerCertificates) == 0 {
			t.Fatal("probe saw no peer certificate")
		}
		return resp.TLS.PeerCertificates[0].SerialNumber
	}

	put(0)
	firstSerial := probeSerial()

	// Rotate: issue a fresh certificate and atomically replace the files the
	// listener reloads from. No restart, no dropped request.
	rotated := issueServerCert(t, ca, 90*24*time.Hour)
	if err := os.WriteFile(server.CertFile, mustReadFile(t, rotated.CertFile), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(server.KeyFile, mustReadFile(t, rotated.KeyFile), 0o600); err != nil {
		t.Fatal(err)
	}

	put(1)
	secondSerial := probeSerial()
	if firstSerial.Cmp(secondSerial) == 0 {
		t.Fatal("server still presents the pre-rotation certificate")
	}

	info := sec.Info()
	if !info.NotAfter.After(initial) {
		t.Fatalf("reloaded NotAfter %v does not advance past %v", info.NotAfter, initial)
	}
	if info.RenewalDue {
		t.Fatalf("reloaded certificate still reports RenewalDue (not_after=%v)", info.NotAfter)
	}
	put(2)
}

func TestHotReloadKeepsServingWhileCertificateFilesAreTorn(t *testing.T) {
	ca, caFile := newTestCA(t)
	server := issueServerCert(t, ca, 2*time.Second) // immediate reload attempts
	sec, err := NewServerTLS(server.CertFile, server.KeyFile, caFile, false, discardLogger())
	if err != nil {
		t.Fatalf("NewServerTLS: %v", err)
	}
	st := newTestStore(t, store.Options{})
	endpoint := startTLSTransport(t, st, sec)
	hc := tlsHTTPClient(t, caFile, "", "", "127.0.0.1", true)
	mustHealthz(t, hc, endpoint)

	// Simulate a rotation caught mid-write: the key file is garbage.
	if err := os.WriteFile(server.KeyFile, []byte("not a pem key"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustHealthz(t, hc, endpoint) // cached certificate keeps serving
}

func TestInsecureHealthzShape(t *testing.T) {
	_, ts, _, _ := newTestServer(t, store.Options{})
	resp, body := httpsGet(t, ts.Client(), ts.URL+"/v1/healthz")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d", resp.StatusCode)
	}
	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["tls"] != false || fields["insecure"] != true {
		t.Fatalf("healthz security fields = %v (want tls:false insecure:true)", fields)
	}

	_, statsBody := httpsGet(t, ts.Client(), ts.URL+"/v1/stats")
	var stats statsResponse
	if err := json.Unmarshal(statsBody, &stats); err != nil {
		t.Fatal(err)
	}
	if stats.TLS.Enabled || !stats.TLS.Insecure || stats.TLS.NotAfter != nil {
		t.Fatalf("stats tls block = %+v", stats.TLS)
	}
}

func TestTLSStatsSecurityBlock(t *testing.T) {
	ca, caFile := newTestCA(t)
	server := issueServerCert(t, ca, time.Hour)
	sec, err := NewServerTLS(server.CertFile, server.KeyFile, caFile, false, discardLogger())
	if err != nil {
		t.Fatalf("NewServerTLS: %v", err)
	}
	st := newTestStore(t, store.Options{})
	endpoint := startTLSTransport(t, st, sec)
	hc := tlsHTTPClient(t, caFile, "", "", "127.0.0.1", false)

	resp, body := httpsGet(t, hc, "https://"+endpoint+"/v1/stats")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stats status = %d", resp.StatusCode)
	}
	var stats statsResponse
	if err := json.Unmarshal(body, &stats); err != nil {
		t.Fatal(err)
	}
	if !stats.TLS.Enabled || stats.TLS.Insecure || stats.TLS.Mutual {
		t.Fatalf("stats tls block = %+v", stats.TLS)
	}
	if stats.TLS.NotAfter == nil {
		t.Fatal("stats is missing tls.not_after")
	}
	notAfter, ok := sec.NotAfter()
	if !ok || !stats.TLS.NotAfter.Equal(notAfter) {
		t.Fatalf("stats not_after %v != served %v", stats.TLS.NotAfter, notAfter)
	}
	if stats.TLS.Issuer == "" || stats.TLS.Subject == "" {
		t.Fatalf("stats is missing issuer/subject: %+v", stats.TLS)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}
