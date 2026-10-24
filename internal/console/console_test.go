package console

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fass-storage/fass/internal/contract"
)

// ---------------------------------------------------------------------------
// Fake coordinator (docs/07 HTTP+JSON only; the console must not need anything
// else)
// ---------------------------------------------------------------------------

type fakeCoordinator struct {
	mu       sync.Mutex
	topology Topology
	buckets  []contract.BucketConfig
	list     contract.ListResult
	manifest contract.Manifest
	actions  []string
	metrics  string
}

func newFakeCoordinator() *fakeCoordinator {
	at := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	f := &fakeCoordinator{
		metrics: "fass_coordinator_http_requests_total{method=\"GET\",route=\"/v1/topology\",status=\"200\"} 10\n" +
			"fass_coordinator_http_requests_total{method=\"GET\",route=\"/v1/objects\",status=\"500\"} 2\n",
		list: contract.ListResult{
			Entries: []contract.ObjectEntry{
				{Key: "e2e/object.bin", Size: 20 << 20, ETag: "abc123", LastModified: at, VersionID: "v-1"},
				{Key: "logs/app.log", Size: 4096, ETag: "def456", LastModified: at, VersionID: "v-2"},
			},
			KeyCount: 2,
		},
		manifest: contract.Manifest{
			Key: "e2e/object.bin", VersionID: "v-1", Size: 20 << 20, ETag: "abc123",
			ChunkSize: 6 << 20, ContentType: "application/octet-stream", CreatedAt: at,
			RCID: "dev-rc", RingID: "dev-ring",
			Chunks: []contract.ChunkRef{{Index: 0, ShardSize: 1024, CiphertextLen: 6 << 20, Generation: 3}},
		},
	}
	f.topology = Topology{
		SnapshotID: "snap-1",
		At:         at,
		Swarms:     []Swarm{{ID: "dev-swarm", Name: "dev-swarm", Region: "eu-west-1"}},
		Nexuses: []Nexus{
			{ID: "nexus-a", Name: "nexus-a"},
			{ID: "nexus-b", Name: "nexus-b"},
			{ID: "nexus-c", Name: "nexus-c", WriteDegraded: false},
		},
		Nodes: []Node{
			{ID: "node-a1", NexusID: "nexus-a", Hostname: "host-a1"},
			{ID: "node-a2", NexusID: "nexus-a", Hostname: "host-a2"},
		},
		Rings: []Ring{{
			ID: "dev-ring", Name: "dev-ring", RCID: "dev-rc",
			NexusIDs: []string{"nexus-a", "nexus-b", "nexus-c"},
			AgentIDs: []string{"agent-01", "agent-02"},
			Capacity: 1 << 30, UsedBytes: 1 << 28,
		}},
		RedundancyClasses: []RedundancyClass{{
			ID: "dev-rc", Name: "dev-rc",
			Params:    Params{GeoN: 2, GeoK: 1, LocalN: 3, LocalK: 1},
			AAG:       2,
			ChunkSize: 6 << 20,
		}},
	}
	for i := 0; i < 12; i++ {
		state := "active"
		if i == 11 {
			state = "pending"
		}
		f.topology.Agents = append(f.topology.Agents, Agent{
			ID:            fmt.Sprintf("agent-%02d", i),
			NodeID:        fmt.Sprintf("node-%c%d", 'a'+i/4, i%2+1),
			NexusID:       fmt.Sprintf("nexus-%c", 'a'+i/4),
			DiskID:        fmt.Sprintf("disk-%02d", i),
			State:         state,
			LastSeen:      at,
			CapacityBytes: 1 << 30,
			UsedBytes:     1 << 28,
			ShardCount:    int64(i * 10),
			RingIDs:       []string{"dev-ring"},
		})
	}
	f.buckets = []contract.BucketConfig{{
		Name: "dev-bucket", Region: "eu-west-1", Versioning: "Enabled",
		Ownership: "ObjectWriter", DefaultRCID: "dev-rc", CreatedAt: at,
	}}
	return f
}

func (f *fakeCoordinator) handler() http.Handler {
	mux := http.NewServeMux()
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"status": "ok", "schema_version": 7})
	})
	mux.HandleFunc("GET /v1/topology", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		writeJSON(w, f.topology)
	})
	mux.HandleFunc("GET /v1/buckets", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		writeJSON(w, map[string]any{"buckets": f.buckets})
	})
	mux.HandleFunc("GET /v1/buckets/{bucket}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, b := range f.buckets {
			if b.Name == r.PathValue("bucket") {
				writeJSON(w, b)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error":{"code":"NoSuchBucket","message":"no such bucket"}}`)
	})
	mux.HandleFunc("GET /v1/objects", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		writeJSON(w, f.list)
	})
	mux.HandleFunc("GET /v1/objects/{bucket}/{key...}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.PathValue("key") != f.manifest.Key {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":{"code":"NoSuchKey","message":"missing"}}`)
			return
		}
		writeJSON(w, f.manifest)
	})
	mux.HandleFunc("GET /v1/agents/{agentID}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, a := range f.topology.Agents {
			if a.ID == r.PathValue("agentID") {
				writeJSON(w, a)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error":{"code":"NoSuchAgent","message":"missing"}}`)
	})
	mux.HandleFunc("POST /v1/agents/{agentID}/activate", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.actions = append(f.actions, "activate:"+r.PathValue("agentID"))
		f.mu.Unlock()
		writeJSON(w, map[string]any{"ring_ids": []string{"dev-ring"}})
	})
	mux.HandleFunc("POST /v1/agents/{agentID}/decommission", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			On bool `json:"on"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.actions = append(f.actions, fmt.Sprintf("decommission:%s:%v", r.PathValue("agentID"), body.On))
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		f.mu.Lock()
		defer f.mu.Unlock()
		fmt.Fprint(w, f.metrics)
	})
	return mux
}

func (f *fakeCoordinator) actionList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.actions...)
}

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

type consoleFixture struct {
	fake    *fakeCoordinator
	coord   *httptest.Server
	console *httptest.Server
	srv     *Server
}

func newFixture(t *testing.T, readOnly bool) *consoleFixture {
	t.Helper()
	fake := newFakeCoordinator()
	coord := httptest.NewServer(fake.handler())
	t.Cleanup(coord.Close)
	srv, err := New(Config{
		CoordinatorURL: coord.URL,
		User:           "operator",
		Password:       "s3cret",
		ReadOnly:       readOnly,
		Version:        "test",
		Now:            func() time.Time { return time.Date(2026, 10, 24, 12, 30, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("console.New: %v", err)
	}
	web := httptest.NewServer(srv.Handler())
	t.Cleanup(web.Close)
	return &consoleFixture{fake: fake, coord: coord, console: web, srv: srv}
}

func (f *consoleFixture) get(t *testing.T, path string, auth bool) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, f.console.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if auth {
		req.SetBasicAuth("operator", "s3cret")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

func (f *consoleFixture) postForm(t *testing.T, path string, values url.Values, cookies []*http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, f.console.URL+path, strings.NewReader(values.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("operator", "s3cret")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

func csrfFrom(resp *http.Response) (string, *http.Cookie) {
	for _, c := range resp.Cookies() {
		if c.Name == csrfCookie {
			return c.Value, c
		}
	}
	return "", nil
}

func mustContain(t *testing.T, body, want, context string) {
	t.Helper()
	if !strings.Contains(body, want) {
		t.Errorf("%s: body does not contain %q\n%.4000s", context, want, body)
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestRequiresBasicAuth(t *testing.T) {
	f := newFixture(t, true)
	resp, body := f.get(t, "/", false)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("WWW-Authenticate"), "Basic") {
		t.Errorf("WWW-Authenticate = %q", resp.Header.Get("WWW-Authenticate"))
	}
	if strings.Contains(body, "Cluster overview") {
		t.Error("unauthenticated response leaked page content")
	}
	// Wrong password is rejected too.
	req, _ := http.NewRequest(http.MethodGet, f.console.URL+"/", nil)
	req.SetBasicAuth("operator", "wrong")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password status = %d", resp2.StatusCode)
	}
}

func TestOverviewRenders(t *testing.T) {
	f := newFixture(t, true)
	resp, body := f.get(t, "/", true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	for _, want := range []string{
		"Cluster overview", "12", "11 / 12 active", "2.00x", "dev-rc", "nexus-a",
		"Rings", "redundancy class", "Coordinator", "read-only",
	} {
		mustContain(t, body, want, "overview")
	}
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "default-src 'self'") {
		t.Error("missing CSP header")
	}
}

func TestOverviewShowsAttentionAndErrors(t *testing.T) {
	f := newFixture(t, true)
	f.fake.mu.Lock()
	f.fake.topology.Agents[0].State = "offline"
	f.fake.topology.Nexuses[2].WriteDegraded = true
	f.fake.topology.Rings[0].UsedBytes = f.fake.topology.Rings[0].Capacity * 9 / 10
	f.fake.mu.Unlock()

	_, body := f.get(t, "/", true)
	mustContain(t, body, "OFFLINE", "overview attention")
	mustContain(t, body, "write-degraded", "overview attention")
	mustContain(t, body, "is 90.0% full", "overview ring attention")
	mustContain(t, body, "HTTP 5xx since coordinator start: 2", "overview 5xx counter")
}

func TestPartialsRender(t *testing.T) {
	f := newFixture(t, true)
	for _, path := range []string{"/partials/overview", "/partials/agents"} {
		resp, body := f.get(t, path, true)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s status = %d", path, resp.StatusCode)
		}
		if !strings.Contains(body, `id="`) {
			t.Errorf("%s did not return an HTMX fragment: %.500s", path, body)
		}
		if strings.Contains(body, "<html") {
			t.Errorf("%s returned a full page, not a fragment", path)
		}
	}
	if _, body := f.get(t, "/partials/overview", true); !strings.Contains(body, "overview-body") {
		t.Error("overview partial root id missing")
	}
	if _, body := f.get(t, "/partials/agents", true); !strings.Contains(body, "agents-body") {
		t.Error("agents partial root id missing")
	}
}

func TestBucketsPage(t *testing.T) {
	f := newFixture(t, true)
	resp, body := f.get(t, "/buckets", true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	for _, want := range []string{"Buckets", "dev-bucket", "20.0 MiB", "Enabled", "dev-rc", ">2<"} {
		mustContain(t, body, want, "buckets page")
	}
}

func TestBucketPageAndObjectDrawer(t *testing.T) {
	f := newFixture(t, true)
	resp, body := f.get(t, "/buckets/dev-bucket", true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bucket page status = %d", resp.StatusCode)
	}
	mustContain(t, body, `hx-get="/buckets/dev-bucket/object?key=e2e%2Fobject.bin`, "bucket page")
	mustContain(t, body, "Objects", "bucket page")
	mustContain(t, body, "Prefix", "bucket page")

	resp, fragment := f.get(t, "/buckets/dev-bucket/object?key=e2e%2Fobject.bin", true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("drawer status = %d", resp.StatusCode)
	}
	for _, want := range []string{"Chunk table (1)", "abc123", "v-1", "20.0 MiB", "application/octet-stream"} {
		mustContain(t, fragment, want, "object drawer")
	}
	if strings.Contains(fragment, "<html") {
		t.Error("drawer returned a full page instead of a fragment")
	}

	_, missing := f.get(t, "/buckets/dev-bucket/object?key=missing", true)
	mustContain(t, missing, "Object error", "drawer missing key")
}

func TestAgentsPageReadOnly(t *testing.T) {
	f := newFixture(t, true)
	resp, body := f.get(t, "/agents", true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	for _, want := range []string{"Agents", "agent-00", "disk-00", "pending", "read-only: actions disabled"} {
		mustContain(t, body, want, "agents page")
	}
	if strings.Contains(body, `action="/agents/agent-00/activate"`) {
		t.Error("read-only console rendered a write form")
	}
	if !strings.Contains(body, `hx-trigger="every 10s"`) {
		t.Error("agents table is missing its HTMX auto-refresh")
	}
}

func TestAgentDetail(t *testing.T) {
	f := newFixture(t, true)
	resp, body := f.get(t, "/agents/agent-00", true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	for _, want := range []string{"agent-00", "disk-00", "host-a1", "Inventory digest", "Shards"} {
		mustContain(t, body, want, "agent detail")
	}
	// Unknown agent degrades to a page, not a 500.
	resp, body = f.get(t, "/agents/nope", true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unknown agent status = %d (console must degrade)", resp.StatusCode)
	}
	mustContain(t, body, "No data for this agent", "unknown agent")
}

func TestActivateReadOnlyForbidden(t *testing.T) {
	f := newFixture(t, true)
	resp, body := f.get(t, "/agents", true)
	token, cookie := csrfFrom(resp)
	if token == "" {
		t.Fatal("no CSRF cookie set on GET")
	}
	post := f.postForm(t, "/agents/agent-11/activate", url.Values{"csrf": {token}}, []*http.Cookie{cookie})
	if post.StatusCode != http.StatusForbidden {
		t.Fatalf("read-only POST status = %d, want 403", post.StatusCode)
	}
	if actions := f.fake.actionList(); len(actions) != 0 {
		t.Fatalf("read-only console called the coordinator: %v", actions)
	}
	_ = body
}

func TestActivateWithCSRF(t *testing.T) {
	f := newFixture(t, false)
	resp, _ := f.get(t, "/agents", true)
	token, cookie := csrfFrom(resp)
	if token == "" || cookie == nil {
		t.Fatal("no CSRF cookie set on GET")
	}
	post := f.postForm(t, "/agents/agent-11/activate", url.Values{"csrf": {token}}, []*http.Cookie{cookie})
	if post.StatusCode != http.StatusSeeOther {
		t.Fatalf("activate status = %d, want 303 (body: %s)", post.StatusCode, post.Header)
	}
	if loc := post.Header.Get("Location"); !strings.HasPrefix(loc, "/agents?flash=") {
		t.Errorf("Location = %q", loc)
	}
	actions := f.fake.actionList()
	if len(actions) != 1 || actions[0] != "activate:agent-11" {
		t.Fatalf("coordinator actions = %v", actions)
	}
}

func TestActivateRejectsMissingOrWrongCSRF(t *testing.T) {
	f := newFixture(t, false)
	resp, _ := f.get(t, "/agents", true)
	_, cookie := csrfFrom(resp)

	// No token at all.
	if post := f.postForm(t, "/agents/agent-11/activate", url.Values{}, []*http.Cookie{cookie}); post.StatusCode != http.StatusForbidden {
		t.Fatalf("missing CSRF status = %d, want 403", post.StatusCode)
	}
	// Token that does not match the cookie.
	if post := f.postForm(t, "/agents/agent-11/activate", url.Values{"csrf": {strings.Repeat("a", 64)}}, []*http.Cookie{cookie}); post.StatusCode != http.StatusForbidden {
		t.Fatalf("mismatched CSRF status = %d, want 403", post.StatusCode)
	}
	// No cookie at all.
	if post := f.postForm(t, "/agents/agent-11/activate", url.Values{"csrf": {strings.Repeat("a", 64)}}, nil); post.StatusCode != http.StatusForbidden {
		t.Fatalf("missing cookie status = %d, want 403", post.StatusCode)
	}
	if actions := f.fake.actionList(); len(actions) != 0 {
		t.Fatalf("CSRF failures reached the coordinator: %v", actions)
	}
}

func TestDecommissionWithCSRF(t *testing.T) {
	f := newFixture(t, false)
	resp, _ := f.get(t, "/agents", true)
	token, cookie := csrfFrom(resp)
	post := f.postForm(t, "/agents/agent-00/decommission", url.Values{"csrf": {token}}, []*http.Cookie{cookie})
	if post.StatusCode != http.StatusSeeOther {
		t.Fatalf("decommission status = %d", post.StatusCode)
	}
	actions := f.fake.actionList()
	if len(actions) != 1 || actions[0] != "decommission:agent-00:true" {
		t.Fatalf("coordinator actions = %v", actions)
	}

	// on=false cancels a decommission.
	post = f.postForm(t, "/agents/agent-00/decommission", url.Values{"csrf": {token}, "on": {"false"}}, []*http.Cookie{cookie})
	if post.StatusCode != http.StatusSeeOther {
		t.Fatalf("cancel decommission status = %d", post.StatusCode)
	}
	actions = f.fake.actionList()
	if len(actions) != 2 || actions[1] != "decommission:agent-00:false" {
		t.Fatalf("coordinator actions = %v", actions)
	}
}

func TestCoordinatorDownDegrades(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := dead.URL
	dead.Close()

	srv, err := New(Config{CoordinatorURL: url, User: "operator", Password: "s3cret", ReadOnly: true, Version: "test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	web := httptest.NewServer(srv.Handler())
	defer web.Close()

	for _, path := range []string{"/", "/buckets", "/agents", "/buckets/some-bucket", "/agents/whatever"} {
		req, _ := http.NewRequest(http.MethodGet, web.URL+path, nil)
		req.SetBasicAuth("operator", "s3cret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status %d, want 200 (degraded page)", path, resp.StatusCode)
		}
		if !strings.Contains(string(body), "Coordinator unreachable or degraded") {
			t.Errorf("%s: missing degraded banner", path)
		}
	}
}

func TestHealthzAndStaticAssets(t *testing.T) {
	f := newFixture(t, true)
	resp, body := f.get(t, "/healthz", false)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"status":"ok"`) {
		t.Fatalf("healthz = %d %q", resp.StatusCode, body)
	}
	for _, asset := range []string{"/static/style.css", "/static/app.js", "/static/htmx.min.js"} {
		resp, body := f.get(t, asset, false)
		if resp.StatusCode != http.StatusOK || len(body) == 0 {
			t.Errorf("%s = %d (%d bytes)", asset, resp.StatusCode, len(body))
		}
	}
	ct := ""
	resp, _ = f.get(t, "/static/style.css", false)
	ct = resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/css") {
		t.Errorf("style.css Content-Type = %q", ct)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	f := newFixture(t, false)
	req, _ := http.NewRequest(http.MethodPost, f.console.URL+"/", strings.NewReader(""))
	req.SetBasicAuth("operator", "s3cret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("POST / should not succeed, got %d", resp.StatusCode)
	}
}

func TestNewRejectsMissingCredentials(t *testing.T) {
	if _, err := New(Config{CoordinatorURL: "http://127.0.0.1:7000", User: "a"}); err == nil {
		t.Fatal("New must refuse an empty password")
	}
	if _, err := New(Config{CoordinatorURL: "nope", User: "a", Password: "b"}); err == nil {
		t.Fatal("New must refuse a coordinator URL without a scheme")
	}
}

func TestCountServerErrors(t *testing.T) {
	raw := `# HELP x
fass_coordinator_http_requests_total{method="GET",route="/a",status="200"} 4
fass_coordinator_http_requests_total{method="GET",route="/b",status="500"} 3
fass_coordinator_http_requests_total{method="POST",route="/c",status="503"} 2
fass_coordinator_other_total 9
`
	if got := countServerErrors(raw); got != 5 {
		t.Fatalf("countServerErrors = %d, want 5", got)
	}
}
