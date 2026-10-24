package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fass-storage/fass/internal/agent/shard"
	"github.com/fass-storage/fass/internal/agent/store"
	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/ec"
)

var testParams = ec.Params{GeoN: 2, GeoK: 1, LocalN: 16, LocalK: 4}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type fakeScrubber struct {
	mu       sync.Mutex
	triggers int
	cursor   string
}

func (f *fakeScrubber) Trigger() {
	f.mu.Lock()
	f.triggers++
	f.mu.Unlock()
}

func (f *fakeScrubber) Cursor() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cursor
}

func newTestStore(t *testing.T, opts store.Options) *store.Store {
	t.Helper()
	if opts.Root == "" {
		opts.Root = t.TempDir()
	}
	if opts.Logger == nil {
		opts.Logger = discardLogger()
	}
	st, err := store.Open(context.Background(), opts)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("store.Close: %v", err)
		}
	})
	return st
}

func newTestServer(t *testing.T, opts store.Options) (*Server, *httptest.Server, *store.Store, *fakeScrubber) {
	t.Helper()
	st := newTestStore(t, opts)
	scrub := &fakeScrubber{}
	srv, err := New(Options{
		Store:    st,
		Scrubber: scrub,
		NodeID:   "node-test",
		Version:  "test",
		Logger:   discardLogger(),
	})
	if err != nil {
		t.Fatalf("transport.New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts, st, scrub
}

func shardPath(setID contract.ShardSetID, group, index int) string {
	return fmt.Sprintf("/v1/shards/%s/%d/%d", setID, group, index)
}

func putShardHTTP(t *testing.T, ts *httptest.Server, setID contract.ShardSetID, group, index int, params ec.Params, payload []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, ts.URL+shardPath(setID, group, index), bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = int64(len(payload))
	req.Header.Set("X-Fass-Params", shard.ParamsHeader(params))
	req.Header.Set("X-Fass-Chunk-Index", "0")
	req.Header.Set("X-Fass-Checksum", strconv.FormatUint(shard.Sum64(payload), 10))
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("PUT shard: %v", err)
	}
	return resp
}

func readJSON(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

func readBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return b
}

func TestHealthzAndStats(t *testing.T) {
	_, ts, st, _ := newTestServer(t, store.Options{})
	setID := contract.ShardSetID("11111111-1111-4111-8111-111111111111")
	payload := []byte("stats shard")
	resp := putShardHTTP(t, ts, setID, 0, 0, testParams, payload)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
	resp.Body.Close()

	resp, err := ts.Client().Get(ts.URL + "/v1/healthz")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d", resp.StatusCode)
	}
	var health healthResponse
	readJSON(t, resp, &health)
	if health.State != "ready" || health.DiskID != st.DiskID() {
		t.Fatalf("healthz = %+v", health)
	}

	resp, err = ts.Client().Get(ts.URL + "/v1/stats")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stats status = %d", resp.StatusCode)
	}
	var stats statsResponse
	readJSON(t, resp, &stats)
	if stats.ShardCount != 1 || stats.UsedBytes == 0 || stats.DiskID != st.DiskID() ||
		stats.Version != "test" || stats.NodeID != "node-test" {
		t.Fatalf("stats = %+v", stats)
	}
	if stats.FreeBytes < 0 {
		t.Fatalf("free_bytes = %d", stats.FreeBytes)
	}
}

func TestPutGetShardWireContract(t *testing.T) {
	_, ts, _, _ := newTestServer(t, store.Options{})
	setID := contract.ShardSetID("22222222-2222-4222-8222-222222222222")
	payload := bytes.Repeat([]byte("wire-contract"), 50)
	checksum := shard.Sum64(payload)

	resp := putShardHTTP(t, ts, setID, 1, 7, testParams, payload)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT status = %d, body = %s", resp.StatusCode, readBody(t, resp))
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("PUT content-type = %q", ct)
	}
	if rid := resp.Header.Get("X-Fass-Request-Id"); rid == "" {
		t.Fatal("missing generated X-Fass-Request-Id")
	}
	var put putShardResponse
	readJSON(t, resp, &put)
	if put.Checksum != checksum || put.Stored != int64(len(payload)) {
		t.Fatalf("PUT response = %+v", put)
	}

	// Idempotent rewrite.
	resp = putShardHTTP(t, ts, setID, 1, 7, testParams, payload)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("idempotent PUT status = %d", resp.StatusCode)
	}
	var again putShardResponse
	readJSON(t, resp, &again)
	if again.Stored != 0 {
		t.Fatalf("idempotent PUT stored = %d, want 0", again.Stored)
	}

	// GET contract.
	resp, err := ts.Client().Get(ts.URL + shardPath(setID, 1, 7))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("GET content-type = %q", ct)
	}
	if resp.ContentLength != int64(len(payload)) {
		t.Fatalf("GET content-length = %d, want %d", resp.ContentLength, len(payload))
	}
	if got := resp.Header.Get("X-Fass-Checksum"); got != strconv.FormatUint(checksum, 10) {
		t.Fatalf("X-Fass-Checksum = %q", got)
	}
	if got := resp.Header.Get("X-Fass-Created-At"); got == "" {
		t.Fatal("missing X-Fass-Created-At")
	} else if _, err := time.Parse(time.RFC3339, got); err != nil {
		t.Fatalf("X-Fass-Created-At = %q: %v", got, err)
	}
	if got := readBody(t, resp); !bytes.Equal(got, payload) {
		t.Fatal("GET payload mismatch")
	}

	// Missing shard → 404 NoSuchShard.
	resp, err = ts.Client().Get(ts.URL + shardPath(setID, 1, 8))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET missing status = %d", resp.StatusCode)
	}
	var env errorEnvelope
	readJSON(t, resp, &env)
	if env.Error.Code != "NoSuchShard" {
		t.Fatalf("error code = %q", env.Error.Code)
	}
}

func TestPutConflictAndValidation(t *testing.T) {
	_, ts, _, _ := newTestServer(t, store.Options{MaxShardBytes: 1024})
	setID := contract.ShardSetID("33333333-3333-4333-8333-333333333333")
	original := []byte("original")
	resp := putShardHTTP(t, ts, setID, 0, 0, testParams, original)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT status = %d", resp.StatusCode)
	}

	// Different bytes at the same address → 409 Conflict.
	conflict := []byte("different")
	resp = putShardHTTP(t, ts, setID, 0, 0, testParams, conflict)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("conflict status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
	var env errorEnvelope
	readJSON(t, resp, &env)
	if env.Error.Code != "Conflict" {
		t.Fatalf("conflict code = %q", env.Error.Code)
	}

	// Wrong checksum header → 400 InvalidChecksum.
	req, _ := http.NewRequest(http.MethodPut, ts.URL+shardPath(setID, 0, 1), bytes.NewReader([]byte("abc")))
	req.ContentLength = 3
	req.Header.Set("X-Fass-Params", shard.ParamsHeader(testParams))
	req.Header.Set("X-Fass-Checksum", "1234")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad checksum status = %d", resp.StatusCode)
	}
	env = errorEnvelope{}
	readJSON(t, resp, &env)
	if env.Error.Code != "InvalidChecksum" {
		t.Fatalf("bad checksum code = %q", env.Error.Code)
	}

	// Malformed params header → 400 InvalidParams.
	req, _ = http.NewRequest(http.MethodPut, ts.URL+shardPath(setID, 0, 2), bytes.NewReader([]byte("abc")))
	req.ContentLength = 3
	req.Header.Set("X-Fass-Params", "not,params")
	req.Header.Set("X-Fass-Checksum", "1")
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad params status = %d", resp.StatusCode)
	}
	env = errorEnvelope{}
	readJSON(t, resp, &env)
	if env.Error.Code != "InvalidParams" {
		t.Fatalf("bad params code = %q", env.Error.Code)
	}

	// Non-numeric path slot → 400.
	resp, err = ts.Client().Get(ts.URL + "/v1/shards/" + string(setID) + "/x/0")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad group status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Oversized shard → 413.
	big := bytes.Repeat([]byte("z"), 2048)
	resp = putShardHTTP(t, ts, setID, 0, 3, testParams, big)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
	resp.Body.Close()
}

func TestPutInsufficientStorage(t *testing.T) {
	_, ts, _, _ := newTestServer(t, store.Options{
		ReservePct: 5,
		CapacityFunc: func(string) (int64, int64, error) {
			return 1000, 100, nil // 50 reserved => 50 net free
		},
	})
	setID := contract.ShardSetID("44444444-4444-4444-8444-444444444444")
	payload := bytes.Repeat([]byte("x"), 200)
	resp := putShardHTTP(t, ts, setID, 0, 0, testParams, payload)
	if resp.StatusCode != http.StatusInsufficientStorage {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
	var env errorEnvelope
	readJSON(t, resp, &env)
	if env.Error.Code != "InsufficientStorage" {
		t.Fatalf("code = %q", env.Error.Code)
	}
}

func TestHasAndDeleteSet(t *testing.T) {
	_, ts, st, _ := newTestServer(t, store.Options{})
	setA := contract.ShardSetID("55555555-5555-4555-8555-555555555555")
	setB := contract.ShardSetID("66666666-6666-4666-8666-666666666666")
	for i := 0; i < 3; i++ {
		resp := putShardHTTP(t, ts, setA, 0, i, testParams, []byte{byte(i)})
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("PUT status = %d", resp.StatusCode)
		}
	}
	resp := putShardHTTP(t, ts, setB, 1, 0, testParams, []byte("b"))
	resp.Body.Close()

	body, _ := json.Marshal(hasRequest{IDs: []string{string(setA), string(setB), "missing-set"}})
	resp, err := ts.Client().Post(ts.URL+"/v1/shards:has", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("has status = %d", resp.StatusCode)
	}
	var has hasResponse
	readJSON(t, resp, &has)
	if len(has.Present) != 3 || !has.Present[0] || !has.Present[1] || has.Present[2] {
		t.Fatalf("present = %v", has.Present)
	}

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/v1/shards/"+string(setA), nil)
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status = %d", resp.StatusCode)
	}
	resp.Body.Close()
	if st.Stats().ShardCount != 1 {
		t.Fatalf("shard count after delete = %d", st.Stats().ShardCount)
	}

	// GET on deleted shard → 404.
	resp, err = ts.Client().Get(ts.URL + shardPath(setA, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET deleted status = %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestInventoryPaginationHTTP(t *testing.T) {
	_, ts, _, _ := newTestServer(t, store.Options{})
	const n = 5
	for i := 0; i < n; i++ {
		setID := contract.ShardSetID(fmt.Sprintf("77777777-7777-4777-8777-00000000000%d", i))
		resp := putShardHTTP(t, ts, setID, 0, 0, testParams, []byte{byte(i)})
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("PUT status = %d", resp.StatusCode)
		}
	}

	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		url := ts.URL + "/v1/inventory?limit=2"
		if cursor != "" {
			url += "&after=" + cursor
		}
		resp, err := ts.Client().Get(url)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("inventory status = %d", resp.StatusCode)
		}
		var page inventoryResponse
		readJSON(t, resp, &page)
		pages++
		for _, entry := range page.Entries {
			if seen[string(entry.ShardSetID)] {
				t.Fatalf("duplicate entry %s", entry.ShardSetID)
			}
			seen[string(entry.ShardSetID)] = true
			if entry.Size <= 0 || entry.Checksum == 0 {
				t.Fatalf("entry metadata incomplete: %+v", entry)
			}
		}
		if page.Next == "" {
			break
		}
		cursor = page.Next
		if pages > 5 {
			t.Fatal("pagination did not terminate")
		}
	}
	if len(seen) != n {
		t.Fatalf("inventory returned %d shards, want %d", len(seen), n)
	}
	if pages != 3 {
		t.Fatalf("pages = %d, want 3", pages)
	}

	// Invalid limit → 400.
	resp, err := ts.Client().Get(ts.URL + "/v1/inventory?limit=zero")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad limit status = %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestScrubHealthzAndMetrics(t *testing.T) {
	_, ts, _, scrub := newTestServer(t, store.Options{})

	resp, err := ts.Client().Post(ts.URL+"/v1/scrub", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("scrub status = %d", resp.StatusCode)
	}
	var scr scrubResponse
	readJSON(t, resp, &scr)
	if scr.State != "scheduled" {
		t.Fatalf("scrub state = %q", scr.State)
	}
	scrub.mu.Lock()
	triggers := scrub.triggers
	scrub.mu.Unlock()
	if triggers != 1 {
		t.Fatalf("scrubber triggers = %d, want 1", triggers)
	}

	setID := contract.ShardSetID("88888888-8888-4888-8888-888888888888")
	putShardHTTP(t, ts, setID, 0, 0, testParams, []byte("metrics")).Body.Close()

	resp, err = ts.Client().Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics status = %d", resp.StatusCode)
	}
	body := string(readBody(t, resp))
	for _, want := range []string{
		"fass_agent_http_requests_total",
		"fass_agent_shard_count 1",
		"fass_agent_used_bytes",
		"fass_agent_free_bytes",
		"fass_agent_scrub_triggered_total 1",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics missing %q:\n%s", want, body)
		}
	}
}

func TestMethodNotAllowedAndNotFoundAreJSON(t *testing.T) {
	_, ts, _, _ := newTestServer(t, store.Options{})

	cases := []struct {
		method, path string
		wantStatus   int
		wantCode     string
	}{
		{http.MethodDelete, "/v1/stats", http.StatusMethodNotAllowed, "MethodNotAllowed"},
		{http.MethodPost, "/v1/healthz", http.StatusMethodNotAllowed, "MethodNotAllowed"},
		{http.MethodGet, "/v1/nope", http.StatusNotFound, "NotFound"},
		{http.MethodPut, "/v1/inventory", http.StatusMethodNotAllowed, "MethodNotAllowed"},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, ts.URL+tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := ts.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Fatalf("content-type = %q", ct)
			}
			var env errorEnvelope
			readJSON(t, resp, &env)
			if env.Error.Code != tc.wantCode {
				t.Fatalf("code = %q, want %q", env.Error.Code, tc.wantCode)
			}
		})
	}
}

func TestRequestIDPropagation(t *testing.T) {
	_, ts, _, _ := newTestServer(t, store.Options{})

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/healthz", nil)
	req.Header.Set("X-Fass-Request-Id", "test-request-id")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("X-Fass-Request-Id"); got != "test-request-id" {
		t.Fatalf("request id = %q", got)
	}
}

func TestCorruptStoredShardIsNotServed(t *testing.T) {
	_, ts, st, _ := newTestServer(t, store.Options{})
	setID := contract.ShardSetID("99999999-9999-4999-8999-999999999999")
	payload := bytes.Repeat([]byte("integrity"), 10)
	resp := putShardHTTP(t, ts, setID, 0, 2, testParams, payload)
	resp.Body.Close()

	// Flip a payload byte on disk behind the agent's back.
	id := shard.ID(setID, 0, 2)
	path := st.Root() + "/shards/" + id[0:2] + "/" + id[2:4] + "/" + id + ".shard"
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := f.Stat()
	if _, err := f.WriteAt([]byte{0x00}, fi.Size()-1); err != nil {
		t.Fatal(err)
	}
	f.Close()

	resp, err = ts.Client().Get(ts.URL + shardPath(setID, 0, 2))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("corrupt GET status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
	var env errorEnvelope
	readJSON(t, resp, &env)
	if env.Error.Code != "CorruptShard" {
		t.Fatalf("corrupt code = %q", env.Error.Code)
	}
}

func TestMissingContentLengthRejected(t *testing.T) {
	_, ts, _, _ := newTestServer(t, store.Options{})
	setID := contract.ShardSetID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	// A chunked body has ContentLength == -1 on the server side.
	req, err := http.NewRequest(http.MethodPut, ts.URL+shardPath(setID, 0, 0), io.NopCloser(bytes.NewReader([]byte("abc"))))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Fass-Params", shard.ParamsHeader(testParams))
	req.Header.Set("X-Fass-Checksum", strconv.FormatUint(shard.Sum64([]byte("abc")), 10))
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusLengthRequired {
		t.Fatalf("status = %d, want 411", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestStatsAndHealthReportBoundDiskID(t *testing.T) {
	const want = "disk-explicit-42"
	_, ts, st, _ := newTestServer(t, store.Options{DiskID: want})
	if got := st.DiskID(); got != want {
		t.Fatalf("store DiskID = %q, want %q", got, want)
	}

	resp, err := ts.Client().Get(ts.URL + "/v1/stats")
	if err != nil {
		t.Fatal(err)
	}
	var stats statsResponse
	readJSON(t, resp, &stats)
	if stats.DiskID != want {
		t.Fatalf("stats disk_id = %q, want %q", stats.DiskID, want)
	}

	resp, err = ts.Client().Get(ts.URL + "/v1/healthz")
	if err != nil {
		t.Fatal(err)
	}
	var health healthResponse
	readJSON(t, resp, &health)
	if health.DiskID != want {
		t.Fatalf("healthz disk_id = %q, want %q", health.DiskID, want)
	}
}
