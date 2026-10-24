package bridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fass-storage/fass/internal/gateway/sigv4"
)

// proxyFixture wires a source fake, a target fake, a ready bridge and the S3
// proxy handler.
type proxyFixture struct {
	src, tgt *fakeS3
	mgr      *Manager
	bridgeID string
	api      *httptest.Server
	b        *bridge
}

func newProxyFixture(t *testing.T) *proxyFixture {
	t.Helper()
	srcF := newFakeS3(t)
	src := httptest.NewServer(srcF)
	t.Cleanup(src.Close)
	tgtF := newFakeS3(t)
	tgt := httptest.NewServer(tgtF)
	t.Cleanup(tgt.Close)
	m, req := newTestManager(t, t.TempDir(), src, tgt, Options{Concurrency: 1})
	st, err := m.Create(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(NewS3ProxyHandler(m, ProxySecurity{TLS: false, Insecure: true}))
	t.Cleanup(api.Close)
	m.mu.Lock()
	b := m.bridges[st.BridgeID]
	m.mu.Unlock()
	return &proxyFixture{src: srcF, tgt: tgtF, mgr: m, bridgeID: st.BridgeID, api: api, b: b}
}

// proxyDo issues a SigV4-signed request as the target credentials would.
func (f *proxyFixture) proxyDo(t *testing.T, method, path string, body []byte, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, f.api.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = strings.TrimPrefix(f.api.URL, "http://")
	if body != nil {
		sum := sha256.Sum256(body)
		req.Header.Set("x-amz-content-sha256", hex.EncodeToString(sum[:]))
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	payload := req.Header.Get("x-amz-content-sha256")
	if payload == "" {
		payload = sigv4.EmptyStringSHA256
	}
	if err := sigv4.SignRequest(req, "tgt-ak", "tgt-sk", time.Now(), payload); err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, got
}

func TestProxyReadFallsThroughToSource(t *testing.T) {
	f := newProxyFixture(t)
	f.src.seed("src", "k", []byte("source bytes"), time.Unix(1000, 0))
	resp, body := f.proxyDo(t, http.MethodGet, "/src/k", nil, nil)
	if resp.StatusCode != http.StatusOK || string(body) != "source bytes" {
		t.Fatalf("GET = %d %q", resp.StatusCode, body)
	}
}

func TestProxyPrefersNewerTarget(t *testing.T) {
	f := newProxyFixture(t)
	f.src.seed("src", "k", []byte("old source"), time.Unix(1000, 0))
	f.tgt.seed("src", "k", []byte("new target"), time.Unix(2000, 0))
	resp, body := f.proxyDo(t, http.MethodGet, "/src/k", nil, nil)
	if resp.StatusCode != http.StatusOK || string(body) != "new target" {
		t.Fatalf("GET = %d %q", resp.StatusCode, body)
	}
}

// HEAD and GET must agree about which copy they serve.
func TestProxyHeadAndGetAgree(t *testing.T) {
	f := newProxyFixture(t)
	f.src.seed("src", "k", []byte("source version is longer"), time.Unix(1000, 0))
	f.tgt.seed("src", "k", []byte("tgt"), time.Unix(2000, 0))

	head, _ := f.proxyDo(t, http.MethodHead, "/src/k", nil, nil)
	get, body := f.proxyDo(t, http.MethodGet, "/src/k", nil, nil)
	if head.StatusCode != 200 || get.StatusCode != 200 {
		t.Fatalf("HEAD=%d GET=%d", head.StatusCode, get.StatusCode)
	}
	if got := head.Header.Get("Content-Length"); got != fmt.Sprint(len(body)) {
		t.Fatalf("HEAD Content-Length %q != GET body length %d", got, len(body))
	}
	if string(body) != "tgt" {
		t.Fatalf("GET body = %q, want the target copy", body)
	}
}

// The copy completing between the proxy's HEAD decision and its source GET must
// not turn into a 404: retry the target, where the object now lives.
func TestProxyCopiedBetweenHeadAndGet(t *testing.T) {
	f := newProxyFixture(t)
	f.src.seed("src", "k", []byte("payload"), time.Unix(1000, 0))
	// On the source GET, simulate the mover finishing: copy to target and delete
	// the source object, then answer 404.
	f.src.getHooks["src/k"] = func() bool {
		f.tgt.seed("src", "k", []byte("payload"), time.Unix(3000, 0))
		f.src.deleteObject("src", "k")
		return false
	}
	resp, body := f.proxyDo(t, http.MethodGet, "/src/k", nil, nil)
	if resp.StatusCode != http.StatusOK || string(body) != "payload" {
		t.Fatalf("GET = %d %q, want the target copy after mid-request migration", resp.StatusCode, body)
	}
}

func TestProxySourceDeletedAfterCopy(t *testing.T) {
	f := newProxyFixture(t)
	f.tgt.seed("src", "k", []byte("target only"), time.Unix(2000, 0))
	resp, body := f.proxyDo(t, http.MethodGet, "/src/k", nil, nil)
	if resp.StatusCode != 200 || string(body) != "target only" {
		t.Fatalf("GET = %d %q", resp.StatusCode, body)
	}
}

func TestProxyRangeFallsThroughToSource(t *testing.T) {
	f := newProxyFixture(t)
	f.src.seed("src", "k", []byte("0123456789abcdefghij"), time.Unix(1000, 0))
	resp, body := f.proxyDo(t, http.MethodGet, "/src/k", nil, map[string]string{"Range": "bytes=5-9"})
	if resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206", resp.StatusCode)
	}
	if string(body) != "56789" {
		t.Fatalf("range body = %q", body)
	}
	if got := resp.Header.Get("Content-Range"); !strings.HasPrefix(got, "bytes 5-9/") {
		t.Fatalf("Content-Range = %q", got)
	}
}

func TestProxyWritesAlwaysTarget(t *testing.T) {
	f := newProxyFixture(t)
	f.src.seed("src", "old", []byte("source copy"), time.Unix(1000, 0))
	resp, _ := f.proxyDo(t, http.MethodPut, "/src/new", []byte("written through bridge"), nil)
	if resp.StatusCode/100 != 2 {
		t.Fatalf("PUT = %d", resp.StatusCode)
	}
	if got, ok := f.tgt.object("src", "new"); !ok || string(got) != "written through bridge" {
		t.Fatalf("target does not hold the write: %q", got)
	}
	if _, ok := f.src.object("src", "new"); ok {
		t.Fatal("PUT reached the source")
	}
	// DELETE: authoritative on target, and the stale source copy is removed so the
	// mover cannot resurrect the object.
	resp, _ = f.proxyDo(t, http.MethodDelete, "/src/old", nil, nil)
	if resp.StatusCode/100 != 2 {
		t.Fatalf("DELETE = %d", resp.StatusCode)
	}
	if _, ok := f.tgt.object("src", "old"); ok {
		t.Fatal("target object not deleted")
	}
	if _, ok := f.src.object("src", "old"); ok {
		t.Fatal("source copy survived a proxy DELETE; the mover could resurrect it")
	}
}

func TestProxyRejectsUnsignedRequests(t *testing.T) {
	f := newProxyFixture(t)
	f.src.seed("src", "k", []byte("x"), time.Unix(1000, 0))
	resp, err := http.Get(f.api.URL + "/src/k")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unsigned GET = %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "AccessDenied") && !strings.Contains(string(body), "SignatureDoesNotMatch") {
		t.Fatalf("auth error body = %s", body)
	}
}

func TestProxyListingSourceIsExplicit(t *testing.T) {
	f := newProxyFixture(t)
	f.src.seed("src", "from-source", []byte("a"), time.Unix(1000, 0))
	f.tgt.seed("src", "written-to-target", []byte("b"), time.Unix(2000, 0))

	resp, body := f.proxyDo(t, http.MethodGet, "/src?list-type=2", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("list = %d %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("x-fass-bridge-listing"); got != "source" {
		t.Fatalf("listing marker = %q, want source while in-progress", got)
	}
	if !strings.Contains(string(body), "from-source") || strings.Contains(string(body), "written-to-target") {
		t.Fatalf("in-progress listing should come from the source: %s", body)
	}
	// The status API must make the caveat visible, not just the docs.
	st, err := f.mgr.Status(f.bridgeID)
	if err != nil {
		t.Fatal(err)
	}
	if st.Buckets[0].ListingSource != "source" {
		t.Fatalf("listing_source = %q, want source", st.Buckets[0].ListingSource)
	}

	// Once completed the proxy is a pass-through to the target.
	f.b.mu.Lock()
	f.b.st.Buckets[0].Completed = true
	f.b.mu.Unlock()
	resp, body = f.proxyDo(t, http.MethodGet, "/src?list-type=2", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("completed list = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("x-fass-bridge-listing"); got != "target" {
		t.Fatalf("listing marker = %q, want target when completed", got)
	}
	if !strings.Contains(string(body), "written-to-target") {
		t.Fatalf("completed listing should come from the target: %s", body)
	}
	_ = json.Valid // keep json import for fixture symmetry
}

func TestProxyCopyOnReadPrioritisesFallthroughObject(t *testing.T) {
	f := newProxyFixture(t)
	f.src.seed("src", "wanted", []byte("hot object"), time.Unix(1000, 0))
	f.b.mu.Lock()
	f.b.st.Status = StatusInProgress
	f.b.mu.Unlock()

	resp, body := f.proxyDo(t, http.MethodGet, "/src/wanted", nil, nil)
	if resp.StatusCode != 200 || string(body) != "hot object" {
		t.Fatalf("fallthrough GET = %d %q", resp.StatusCode, body)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if got, ok := f.tgt.object("src", "wanted"); ok && string(got) == "hot object" {
			if _, stillThere := f.src.object("src", "wanted"); stillThere {
				t.Fatal("copy-on-read did not delete the verified source copy")
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("copy-on-read did not copy the fallthrough object")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestProxyHealthzReportsPosture(t *testing.T) {
	f := newProxyFixture(t)
	resp, err := http.Get(f.api.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Status   string `json:"status"`
		Security struct {
			TLS      bool `json:"tls"`
			Insecure bool `json:"insecure"`
		} `json:"security"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if out.Status != "ok" || out.Security.TLS || !out.Security.Insecure {
		t.Fatalf("healthz = %+v", out)
	}
}
