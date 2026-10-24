package bridge

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Fake S3 endpoint
// ---------------------------------------------------------------------------

type fakeObject struct {
	data         []byte
	etag         string
	lastModified time.Time
}

type fakeBucket struct {
	objects    map[string]fakeObject
	objectLock bool
}

type fakeS3 struct {
	mu       sync.Mutex
	buckets  map[string]*fakeBucket
	failGets map[string]bool
	corrupt  map[string]func([]byte) []byte
	puts     map[string]int // bucket/key -> successful object PUT count
	listMax  int
	uploads  map[string][]fakePart
	// getHooks run before a GET is served (outside the fake's lock). Returning
	// false makes the fake answer 404, modelling an object that vanished between
	// a proxy HEAD and its GET.
	getHooks map[string]func() bool
	now      func() time.Time
	// getDelay slows GETs so resume tests can interrupt mid-migration.
	getDelay time.Duration
}

type fakePart struct {
	number int
	data   []byte
}

func newFakeS3(t *testing.T) *fakeS3 {
	t.Helper()
	return &fakeS3{
		buckets:  map[string]*fakeBucket{},
		failGets: map[string]bool{},
		corrupt:  map[string]func([]byte) []byte{},
		puts:     map[string]int{},
		listMax:  2, // force pagination in tests
		uploads:  map[string][]fakePart{},
		getHooks: map[string]func() bool{},
		now:      time.Now,
	}
}

func (f *fakeS3) seed(bucket, key string, data []byte, lastModified time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b := f.bucketLocked(bucket)
	b.objects[key] = fakeObject{data: append([]byte(nil), data...), etag: md5hex(data), lastModified: lastModified}
}

func (f *fakeS3) object(bucket, key string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.buckets[bucket]
	if !ok {
		return nil, false
	}
	o, ok := b.objects[key]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), o.data...), true
}

func (f *fakeS3) keys(bucket string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.buckets[bucket]
	if !ok {
		return nil
	}
	out := make([]string, 0, len(b.objects))
	for k := range b.objects {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (f *fakeS3) putCount(bucket, key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.puts[bucket+"/"+key]
}

func (f *fakeS3) bucketLocked(name string) *fakeBucket {
	b, ok := f.buckets[name]
	if !ok {
		b = &fakeBucket{objects: map[string]fakeObject{}}
		f.buckets[name] = b
	}
	return b
}

func (f *fakeS3) deleteObject(bucket, key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if b, ok := f.buckets[bucket]; ok {
		delete(b.objects, key)
	}
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if d := f.getDelay; d > 0 && r.Method == http.MethodGet {
		time.Sleep(d) // set before the migration starts; avoids holding the lock
	}
	pathForHook := strings.TrimPrefix(r.URL.Path, "/")
	if r.Method == http.MethodGet {
		f.mu.Lock()
		hook := f.getHooks[pathForHook]
		f.mu.Unlock()
		if hook != nil && !hook() {
			http.Error(w, `<Error><Code>NoSuchKey</Code><Message>gone</Message></Error>`, http.StatusNotFound)
			return
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	path := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.SplitN(path, "/", 2)
	bucket := parts[0]
	var key string
	if len(parts) == 2 {
		key = parts[1]
	}
	q := r.URL.Query()

	switch {
	case bucket == "" && r.Method == http.MethodGet:
		f.listBuckets(w)
	case key == "" && r.Method == http.MethodPut:
		f.bucketLocked(bucket)
		w.WriteHeader(http.StatusOK)
	case key == "" && q.Has("object-lock"):
		b := f.bucketLocked(bucket)
		if b.objectLock {
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprint(w, `<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>`)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `<Error><Code>ObjectLockConfigurationNotFoundError</Code><Message>none</Message></Error>`)
	case key == "" && r.Method == http.MethodGet && q.Get("list-type") == "2":
		f.listObjects(w, bucket, q.Get("continuation-token"))
	case key != "":
		f.handleObject(w, r, bucket, key, q)
	default:
		http.Error(w, "unsupported", http.StatusNotImplemented)
	}
}

func (f *fakeS3) listBuckets(w http.ResponseWriter) {
	names := make([]string, 0, len(f.buckets))
	for n := range f.buckets {
		names = append(names, n)
	}
	sort.Strings(names)
	var sb strings.Builder
	sb.WriteString(`<ListAllMyBucketsResult><Buckets>`)
	for _, n := range names {
		fmt.Fprintf(&sb, `<Bucket><Name>%s</Name></Bucket>`, n)
	}
	sb.WriteString(`</Buckets></ListAllMyBucketsResult>`)
	w.Header().Set("Content-Type", "application/xml")
	fmt.Fprint(w, sb.String())
}

func (f *fakeS3) listObjects(w http.ResponseWriter, bucket, token string) {
	b := f.bucketLocked(bucket)
	keys := make([]string, 0, len(b.objects))
	for k := range b.objects {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var page []string
	for _, k := range keys {
		if token != "" && k <= token {
			continue
		}
		page = append(page, k)
	}
	truncated := len(page) > f.listMax
	if truncated {
		page = page[:f.listMax]
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, `<ListBucketResult><IsTruncated>%t</IsTruncated>`, truncated)
	if truncated && len(page) > 0 {
		fmt.Fprintf(&sb, `<NextContinuationToken>%s</NextContinuationToken>`, page[len(page)-1])
	}
	for _, k := range page {
		o := b.objects[k]
		fmt.Fprintf(&sb, `<Contents><Key>%s</Key><Size>%d</Size><ETag>&quot;%s&quot;</ETag><LastModified>%s</LastModified></Contents>`,
			k, len(o.data), o.etag, o.lastModified.UTC().Format(time.RFC3339))
	}
	sb.WriteString(`</ListBucketResult>`)
	w.Header().Set("Content-Type", "application/xml")
	fmt.Fprint(w, sb.String())
}

func (f *fakeS3) handleObject(w http.ResponseWriter, r *http.Request, bucket, key string, q map[string][]string) {
	b := f.bucketLocked(bucket)
	obj, exists := b.objects[key]

	switch {
	case r.Method == http.MethodHead:
		if !exists {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(obj.data)))
		w.Header().Set("ETag", `"`+obj.etag+`"`)
		w.Header().Set("Last-Modified", obj.lastModified.UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)

	case r.Method == http.MethodGet:
		if f.failGets[bucket+"/"+key] {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `<Error><Code>InternalError</Code><Message>simulated shard failure</Message></Error>`)
			return
		}
		if !exists {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `<Error><Code>NoSuchKey</Code><Message>no</Message></Error>`)
			return
		}
		body := obj.data
		if rng := r.Header.Get("Range"); strings.HasPrefix(rng, "bytes=") {
			spec := strings.TrimPrefix(rng, "bytes=")
			var start, end int
			if _, err := fmt.Sscanf(spec, "%d-%d", &start, &end); err == nil {
				if start < 0 {
					start = 0
				}
				if end >= len(body) {
					end = len(body) - 1
				}
				if start <= end && start < len(body) {
					w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(body)))
					w.Header().Set("Content-Length", fmt.Sprint(end-start+1))
					w.WriteHeader(http.StatusPartialContent)
					_, _ = w.Write(body[start : end+1])
					return
				}
			}
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		w.Header().Set("ETag", `"`+obj.etag+`"`)
		w.Header().Set("Last-Modified", obj.lastModified.UTC().Format(http.TimeFormat))
		_, _ = w.Write(body)

	case r.Method == http.MethodPut && len(q["partNumber"]) > 0:
		id := q["uploadId"][0]
		body, _ := io.ReadAll(r.Body)
		var number int
		fmt.Sscanf(q["partNumber"][0], "%d", &number)
		f.uploads[id] = append(f.uploads[id], fakePart{number: number, data: body})
		w.Header().Set("ETag", `"`+md5hex(body)+`"`)
		w.WriteHeader(http.StatusOK)

	case r.Method == http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		if fn, ok := f.corrupt[bucket+"/"+key]; ok {
			body = fn(body)
		}
		b.objects[key] = fakeObject{data: body, etag: md5hex(body), lastModified: f.now()}
		f.puts[bucket+"/"+key]++
		w.Header().Set("ETag", `"`+md5hex(body)+`"`)
		w.WriteHeader(http.StatusOK)

	case r.Method == http.MethodPost && len(q["uploads"]) > 0:
		id := fmt.Sprintf("upload-%d", len(f.uploads)+1)
		f.uploads[id] = nil
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprintf(w, `<InitiateMultipartUploadResult><UploadId>%s</UploadId></InitiateMultipartUploadResult>`, id)

	case r.Method == http.MethodPost && len(q["uploadId"]) > 0:
		id := q["uploadId"][0]
		parts := append([]fakePart(nil), f.uploads[id]...)
		sort.Slice(parts, func(i, j int) bool { return parts[i].number < parts[j].number })
		var data []byte
		for _, p := range parts {
			data = append(data, p.data...)
		}
		b.objects[key] = fakeObject{data: data, etag: md5hex(data), lastModified: f.now()}
		f.puts[bucket+"/"+key]++
		delete(f.uploads, id)
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprintf(w, `<CompleteMultipartUploadResult><Key>%s</Key><ETag>"%s"</ETag></CompleteMultipartUploadResult>`, key, md5hex(data))

	case r.Method == http.MethodDelete:
		if len(q["uploadId"]) > 0 {
			delete(f.uploads, q["uploadId"][0])
			w.WriteHeader(http.StatusNoContent)
			return
		}
		delete(b.objects, key)
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "unsupported", http.StatusNotImplemented)
	}
}

func md5hex(b []byte) string {
	sum := md5.Sum(b)
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

func endpoints(t *testing.T, src, tgt *httptest.Server) (Endpoint, Endpoint) {
	t.Helper()
	return Endpoint{Endpoint: src.URL, Region: "us-east-1", AccessKey: "src-ak", SecretKey: "src-sk", UsePathStyle: true},
		Endpoint{Endpoint: tgt.URL, Region: "us-east-1", AccessKey: "tgt-ak", SecretKey: "tgt-sk", UsePathStyle: true}
}

func newTestManager(t *testing.T, dir string, src, tgt *httptest.Server, opts Options) (*Manager, CreateRequest) {
	t.Helper()
	if opts.DataDir == "" {
		opts.DataDir = dir
	}
	opts.MultipartThreshold = 5 << 20
	opts.PartSize = 5 << 20
	opts.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	srcEp, tgtEp := endpoints(t, src, tgt)
	m, err := NewManager(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	return m, CreateRequest{Source: srcEp, Target: tgtEp, Buckets: []string{"src"}}
}

func waitCompleted(t *testing.T, m *Manager, id string) Status {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		st, err := m.Status(id)
		if err != nil {
			t.Fatal(err)
		}
		if st.Status == StatusCompleted {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("bridge did not complete: %+v", st)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func start(t *testing.T, m *Manager, req CreateRequest) string {
	t.Helper()
	st, err := m.Create(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Start(st.BridgeID); err != nil {
		t.Fatal(err)
	}
	return st.BridgeID
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestMigrateCopiesVerifiesDeletesAndCountsFailures(t *testing.T) {
	f := newFakeS3(t)
	src := httptest.NewServer(f)
	defer src.Close()
	tgtF := newFakeS3(t)
	tgt := httptest.NewServer(tgtF)
	defer tgt.Close()

	small := bytes.Repeat([]byte("s"), 1024)
	zero := []byte{}
	large := bytes.Repeat([]byte("L"), 9<<20) // > threshold -> multipart
	f.seed("src", "a/small", small, time.Unix(1000, 0))
	f.seed("src", "a/zero", zero, time.Unix(1000, 0))
	f.seed("src", "b/large", large, time.Unix(1000, 0))
	f.seed("src", "b/failing", bytes.Repeat([]byte("x"), 4096), time.Unix(1000, 0))
	f.failGets["src/b/failing"] = true

	m, req := newTestManager(t, t.TempDir(), src, tgt, Options{Concurrency: 2})
	id := start(t, m, req)
	st := waitCompleted(t, m, id)

	if len(st.Buckets) != 1 || st.Buckets[0].Name != "src" {
		t.Fatalf("buckets = %+v", st.Buckets)
	}
	b := st.Buckets[0]
	if b.ObjectsTotal != 4 || b.Migrated != 3 || b.Failed != 1 {
		t.Fatalf("counts = %+v, want 4 total / 3 migrated / 1 failed", b)
	}
	if b.Bytes < int64(len(small)+len(large)) {
		t.Fatalf("bytes = %d", b.Bytes)
	}
	// Failures never delete the source; successes do.
	if keys := f.keys("src"); len(keys) != 1 || keys[0] != "b/failing" {
		t.Fatalf("source keys after migration = %v, want only b/failing", keys)
	}
	// Target has the exact bytes.
	for key, want := range map[string][]byte{"a/small": small, "a/zero": zero, "b/large": large} {
		got, ok := tgtF.object("src", key)
		if !ok {
			t.Fatalf("target missing %s", key)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("target %s differs (got %d bytes, want %d)", key, len(got), len(want))
		}
	}
	if _, ok := tgtF.object("src", "b/failing"); ok {
		t.Fatal("failed object was copied")
	}
	if got := tgtF.putCount("src", "b/failing"); got != 0 {
		t.Fatalf("failed object PUT count = %d", got)
	}
}

func TestStartIsIdempotentAndResumeDoesNotDuplicate(t *testing.T) {
	f := newFakeS3(t)
	f.getDelay = 15 * time.Millisecond
	src := httptest.NewServer(f)
	defer src.Close()
	tgtF := newFakeS3(t)
	tgt := httptest.NewServer(tgtF)
	defer tgt.Close()
	f.getDelay = 20 * time.Millisecond

	payloads := map[string][]byte{}
	for i := 0; i < 7; i++ {
		key := fmt.Sprintf("o/%d", i)
		data := bytes.Repeat([]byte{byte('a' + i)}, 2048+i)
		payloads[key] = data
		f.seed("src", key, data, time.Unix(1000, 0))
	}

	dir := t.TempDir()
	m, req := newTestManager(t, dir, src, tgt, Options{Concurrency: 2})
	st, err := m.Create(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	// Start twice: the second is a no-op.
	if err := m.Start(st.BridgeID); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(st.BridgeID); err != nil {
		t.Fatal(err)
	}

	// Wait until at least one page (2 objects) has been migrated before simulating
	// a crash, then build a fresh manager over the same journal directory.
	deadline := time.Now().Add(10 * time.Second)
	for {
		cur, _ := m.Status(st.BridgeID)
		if cur.Buckets[0].Migrated >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("did not observe partial progress: %+v", cur.Buckets)
		}
		time.Sleep(2 * time.Millisecond)
	}
	m.Close()
	// Snapshot the durable per-object outcomes so we can prove the resumed run
	// did not re-copy anything that had already been classified.
	js, err := loadJournal(journalPath(dir, st.BridgeID))
	if err != nil {
		t.Fatal(err)
	}
	alreadyDone := map[string]bool{}
	for k, outcome := range js.Buckets[0].Done {
		if outcome == objectMigrated {
			alreadyDone[k] = true
		}
	}
	if len(alreadyDone) == 0 {
		t.Fatal("journal has no migrated objects to test resume against")
	}

	m2, err := NewManager(Options{DataDir: dir, Concurrency: 2, MultipartThreshold: 5 << 20, PartSize: 5 << 20,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	defer m2.Close()
	loaded, err := m2.Status(st.BridgeID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Status == StatusCompleted {
		t.Fatalf("interrupted bridge loaded as %q, want resumable ready", loaded.Status)
	}
	if err := m2.Start(st.BridgeID); err != nil {
		t.Fatal(err)
	}
	final := waitCompleted(t, m2, st.BridgeID)
	if final.Buckets[0].Migrated != int64(len(payloads)) || final.Buckets[0].Failed != 0 {
		t.Fatalf("resumed counts = %+v", final.Buckets[0])
	}
	for key, want := range payloads {
		if got, ok := tgtF.object("src", key); !ok || !bytes.Equal(got, want) {
			t.Fatalf("target %s wrong after resume", key)
		}
		if alreadyDone[key] {
			if got := tgtF.putCount("src", key); got != 1 {
				t.Fatalf("%s copied %d times after resume, want exactly 1 (already migrated before the restart)", key, got)
			}
		} else if got := tgtF.putCount("src", key); got > 2 {
			t.Fatalf("%s copied %d times, want <= 2 (in-flight object may be retried once)", key, got)
		}
	}
	if keys := f.keys("src"); len(keys) != 0 {
		t.Fatalf("source not emptied after resume: %v", keys)
	}
}

func TestVerificationFailureKeepsSourceAndCountsFailed(t *testing.T) {
	f := newFakeS3(t)
	src := httptest.NewServer(f)
	defer src.Close()
	tgtF := newFakeS3(t)
	tgt := httptest.NewServer(tgtF)
	defer tgt.Close()

	good := bytes.Repeat([]byte("g"), 4096)
	corruptTarget := bytes.Repeat([]byte("c"), 4096)
	f.seed("src", "good", good, time.Unix(1000, 0))
	f.seed("src", "corrupt", good, time.Unix(1000, 0))
	// Target silently stores different bytes for one key: read-back verification
	// must catch it, keep the source, and count the object failed.
	tgtF.corrupt["src/corrupt"] = func([]byte) []byte { return corruptTarget }

	m, req := newTestManager(t, t.TempDir(), src, tgt, Options{Concurrency: 1})
	st := waitCompleted(t, m, start(t, m, req))
	b := st.Buckets[0]
	if b.Migrated != 1 || b.Failed != 1 {
		t.Fatalf("counts = %+v, want 1 migrated / 1 failed", b)
	}
	if _, ok := f.object("src", "corrupt"); !ok {
		t.Fatal("verification failure deleted the source copy")
	}
	if _, ok := f.object("src", "good"); ok {
		t.Fatal("verified object was not deleted from source")
	}
	if got, _ := tgtF.object("src", "good"); !bytes.Equal(got, good) {
		t.Fatal("good object content mismatch")
	}
}

func TestConcurrentTargetWriteIsNotOverwrittenByStaleSource(t *testing.T) {
	f := newFakeS3(t)
	src := httptest.NewServer(f)
	defer src.Close()
	tgtF := newFakeS3(t)
	tgt := httptest.NewServer(tgtF)
	defer tgt.Close()

	f.seed("src", "k", []byte("old source"), time.Unix(1000, 0))
	// A writer already pushed a newer version to the target after the migration
	// started; the stale source copy must not clobber it.
	tgtF.seed("src", "k", []byte("new target"), time.Unix(2000, 0))

	m, req := newTestManager(t, t.TempDir(), src, tgt, Options{Concurrency: 1})
	st := waitCompleted(t, m, start(t, m, req))
	b := st.Buckets[0]
	if b.Skipped != 1 || b.Migrated != 0 || b.Failed != 0 {
		t.Fatalf("counts = %+v, want 1 skipped", b)
	}
	if got, _ := tgtF.object("src", "k"); string(got) != "new target" {
		t.Fatalf("target content = %q, stale source overwrote a newer object", got)
	}
	if _, ok := f.object("src", "k"); !ok {
		t.Fatal("skipped object's source copy was deleted")
	}
}

func TestObjectLockSourceIsRefused(t *testing.T) {
	f := newFakeS3(t)
	f.bucketLocked("src").objectLock = true
	src := httptest.NewServer(f)
	defer src.Close()
	tgtF := newFakeS3(t)
	tgt := httptest.NewServer(tgtF)
	defer tgt.Close()
	f.seed("src", "k", []byte("v"), time.Unix(1000, 0))

	m, req := newTestManager(t, t.TempDir(), src, tgt, Options{Concurrency: 1})
	st := waitCompleted(t, m, start(t, m, req))
	if !strings.Contains(st.Error, "Object Lock") {
		t.Fatalf("error = %q, want Object Lock refusal", st.Error)
	}
	if b := st.Buckets[0]; b.Migrated != 0 || b.Failed != 0 {
		t.Fatalf("bucket progressed despite Object Lock: %+v", b)
	}
	if _, ok := f.object("src", "k"); !ok {
		t.Fatal("source object was touched despite Object Lock")
	}
}

func TestSessionCredentialsAreRejected(t *testing.T) {
	f := newFakeS3(t)
	src := httptest.NewServer(f)
	defer src.Close()
	tgt := httptest.NewServer(newFakeS3(t))
	defer tgt.Close()
	m, req := newTestManager(t, t.TempDir(), src, tgt, Options{})
	req.Source.SessionToken = "sts-token"
	if _, err := m.Create(context.Background(), req); err == nil || !strings.Contains(err.Error(), "permanent credentials") {
		t.Fatalf("Create error = %v, want permanent-credentials refusal", err)
	}
}

func TestControlAPIAndDeleteNeverDeletesData(t *testing.T) {
	f := newFakeS3(t)
	src := httptest.NewServer(f)
	defer src.Close()
	tgtF := newFakeS3(t)
	tgt := httptest.NewServer(tgtF)
	defer tgt.Close()
	payload := []byte("api payload")
	f.seed("src", "k", payload, time.Unix(1000, 0))

	m, _ := newTestManager(t, t.TempDir(), src, tgt, Options{Concurrency: 1})
	api := httptest.NewServer(NewHTTPHandler(m))
	defer api.Close()

	srcEp, tgtEp := endpoints(t, src, tgt)
	body := fmt.Sprintf(`{"source":%s,"target":%s,"buckets":["src"]}`, jsonEndpoint(srcEp), jsonEndpoint(tgtEp))
	resp, err := http.Post(api.URL+"/v1/bridges", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var created struct {
		BridgeID string `json:"bridge_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated || created.BridgeID == "" {
		t.Fatalf("create = %d %+v", resp.StatusCode, created)
	}
	// start twice -> 204 both times
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest(http.MethodPost, api.URL+"/v1/bridges/"+created.BridgeID+"/start", nil)
		r2, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r2.Body.Close()
		if r2.StatusCode != http.StatusNoContent {
			t.Fatalf("start %d = %d", i, r2.StatusCode)
		}
	}
	waitCompletedHTTP(t, api.URL, created.BridgeID)
	// DELETE removes tracking but never data (source already emptied by copy, so
	// create a second bridge on a no-copy bucket set and delete it before start).
	req, _ := http.NewRequest(http.MethodDelete, api.URL+"/v1/bridges/"+created.BridgeID, nil)
	r3, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r3.Body.Close()
	if r3.StatusCode != http.StatusNoContent {
		t.Fatalf("delete = %d", r3.StatusCode)
	}
	if got, ok := tgtF.object("src", "k"); !ok || !bytes.Equal(got, payload) {
		t.Fatal("DELETE must never delete migrated data")
	}
}

func jsonEndpoint(e Endpoint) string {
	b, _ := json.Marshal(e)
	return string(b)
}

func waitCompletedHTTP(t *testing.T, base, id string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := http.Get(base + "/v1/bridges/" + id)
		if err != nil {
			t.Fatal(err)
		}
		var st Status
		err = json.NewDecoder(resp.Body).Decode(&st)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if st.Status == StatusCompleted {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("bridge %s did not complete: %+v", id, st)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
