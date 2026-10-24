package gc_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/coord/gc"
	"github.com/fass-storage/fass/internal/coord/id"
	"github.com/fass-storage/fass/internal/coord/meta"
	"github.com/fass-storage/fass/internal/ec"
	"github.com/fass-storage/fass/internal/storage"
)

const chunkSize = 16 << 20

var params = ec.Params{GeoN: 1, GeoK: 0, LocalN: 2, LocalK: 1} // 3 shards/chunk

var endpoints = []string{"10.0.0.1:7101", "10.0.0.2:7101", "10.0.0.3:7101"}

// fakeDeleter records deletes and can fail selected endpoints a fixed number of
// times to exercise the retry path.
type fakeDeleter struct {
	mu       sync.Mutex
	calls    map[string][]contract.ShardSetID
	attempts map[string]int
	fail     map[string]int
}

func newFakeDeleter() *fakeDeleter {
	return &fakeDeleter{
		calls:    make(map[string][]contract.ShardSetID),
		attempts: make(map[string]int),
		fail:     make(map[string]int),
	}
}

func (f *fakeDeleter) DeleteShards(_ context.Context, endpoint string, ids []contract.ShardSetID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts[endpoint]++
	if f.fail[endpoint] > 0 {
		f.fail[endpoint]--
		return fmt.Errorf("injected failure for %s", endpoint)
	}
	f.calls[endpoint] = append(f.calls[endpoint], ids...)
	return nil
}

func (f *fakeDeleter) attemptCount(endpoint string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attempts[endpoint]
}

func (f *fakeDeleter) snapshot() map[string][]contract.ShardSetID {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string][]contract.ShardSetID, len(f.calls))
	for k, v := range f.calls {
		out[k] = append([]contract.ShardSetID(nil), v...)
	}
	return out
}

func (f *fakeDeleter) totalCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, v := range f.calls {
		n += len(v)
	}
	return n
}

type fixture struct {
	db     storage.Store
	m      *meta.Service
	bucket contract.BucketConfig
	now    time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	db, err := storage.Open("")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	f := &fixture{db: db, now: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	t.Cleanup(func() { _ = db.Close() })
	f.m = meta.New(db)
	f.m.SetClock(func() time.Time { return f.now })
	f.bucket = contract.BucketConfig{
		BucketID:  contract.BucketID(id.New()),
		Name:      "gc-bucket",
		TenantID:  "tenant-1",
		ProjectID: "project-1",
		Region:    contract.DefaultRegion,
		Ownership: "ObjectWriter",
	}
	if err := f.m.CreateBucket(context.Background(), f.bucket); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	return f
}

// makeChunks builds a dense chunk table whose slots live on `endpoints`.
func makeChunks(t *testing.T, n int) []contract.ChunkRef {
	t.Helper()
	out := make([]contract.ChunkRef, n)
	for i := 0; i < n; i++ {
		total := params.TotalShards()
		perGroup := params.ShardsPerGroup()
		slots := make([]contract.Slot, total)
		checksums := make([]uint64, total)
		for s := 0; s < total; s++ {
			slots[s] = contract.Slot{
				GeoGroup:   s / perGroup,
				LocalIndex: s % perGroup,
				AgentID:    contract.AgentID(fmt.Sprintf("agent-%d", s)),
				NodeID:     contract.NodeID(fmt.Sprintf("node-%d", s)),
				NexusID:    "nexus-1",
				Endpoint:   endpoints[s%len(endpoints)],
			}
			checksums[s] = uint64(9000 + s)
		}
		out[i] = contract.ChunkRef{
			Index:         i,
			Params:        params,
			CiphertextLen: chunkSize,
			ShardSize:     chunkSize / (params.GeoN * params.LocalN),
			Slots:         slots,
			Checksums:     checksums,
			Generation:    1,
		}
	}
	return out
}

// commitAndDelete commits an object and tombstones it (unversioned delete), which
// enqueues a deletion entry due 24h later.
func (f *fixture) commitAndDelete(t *testing.T, key string, size int64, chunks []contract.ChunkRef) contract.VersionID {
	t.Helper()
	ctx := context.Background()
	versionID := contract.VersionID(id.New())
	_, err := f.m.CommitObject(ctx, contract.CommitRequest{
		VersionID:   versionID,
		BucketID:    f.bucket.BucketID,
		Key:         key,
		Size:        size,
		ETag:        "etag-" + key,
		ChunkSize:   chunkSize,
		Chunks:      chunks,
		ContentType: "application/octet-stream",
		RCID:        "rc-1",
		RingID:      "ring-1",
	})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	deleted, _, err := f.m.DeleteObject(ctx, f.bucket.Name, key, "", false)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if deleted != versionID {
		t.Fatalf("deleted version = %s, want %s", deleted, versionID)
	}
	return versionID
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestGCCollectsOverwrittenObjectShards(t *testing.T) {
	f := newFixture(t)
	deleter := newFakeDeleter()
	executor := gc.New(f.m, deleter, gc.Config{Now: func() time.Time { return f.now }, Logger: quietLogger()})
	ctx := context.Background()

	versionID := f.commitAndDelete(t, "docs/a.bin", 2*chunkSize, makeChunks(t, 2))
	if backlog, err := f.m.DeletionBacklog(ctx); err != nil || backlog != 1 {
		t.Fatalf("deletion backlog = %d, %v", backlog, err)
	}

	// Before the 24h grace period nothing may be deleted.
	res, err := executor.RunOnce(ctx, f.now.Add(time.Hour))
	if err != nil {
		t.Fatalf("RunOnce before grace: %v", err)
	}
	if res.Examined != 0 || deleter.totalCalls() != 0 {
		t.Fatalf("GC ran before grace: %+v, calls=%d", res, deleter.totalCalls())
	}

	// After grace every referenced set is deleted on every endpoint.
	res, err = executor.RunOnce(ctx, f.now.Add(25*time.Hour))
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if res.Examined != 1 || res.Completed != 1 || res.Failed != 0 {
		t.Fatalf("result = %+v", res)
	}
	if res.Sets != 2*len(endpoints) || res.Endpoints != len(endpoints) {
		t.Fatalf("result = %+v, want %d sets over %d endpoints", res, 2*len(endpoints), len(endpoints))
	}
	calls := deleter.snapshot()
	// The executor must derive exactly the ids the gateway wrote shards under:
	// contract.ShardSetIDFor is the single shared definition.
	wantSets := []contract.ShardSetID{
		contract.ShardSetIDFor(f.bucket.BucketID, "docs/a.bin", versionID, 0),
		contract.ShardSetIDFor(f.bucket.BucketID, "docs/a.bin", versionID, 1),
	}
	for _, ep := range endpoints {
		got := calls[ep]
		sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
		want := append([]contract.ShardSetID(nil), wantSets...)
		sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
		if len(got) != len(want) {
			t.Fatalf("endpoint %s got %d set deletes, want %d: %v", ep, len(got), len(want), got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("endpoint %s set %d = %s, want %s", ep, i, got[i], want[i])
			}
		}
	}
	if backlog, _ := f.m.DeletionBacklog(ctx); backlog != 0 {
		t.Fatalf("queue not drained: %d", backlog)
	}

	// Replaying is a no-op.
	res, err = executor.RunOnce(ctx, f.now.Add(48*time.Hour))
	if err != nil || res.Examined != 0 {
		t.Fatalf("replay = %+v, %v", res, err)
	}
	if stats := executor.Stats(); stats["items_completed_total"] != 1 || stats["sets_deleted_total"] != int64(2*len(endpoints)) {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestGCZeroByteObjectHasNoShards(t *testing.T) {
	f := newFixture(t)
	deleter := newFakeDeleter()
	executor := gc.New(f.m, deleter, gc.Config{Now: func() time.Time { return f.now }, Logger: quietLogger()})
	ctx := context.Background()

	f.commitAndDelete(t, "empty.bin", 0, nil)
	res, err := executor.RunOnce(ctx, f.now.Add(25*time.Hour))
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if res.Completed != 1 || res.ZeroByte != 1 || deleter.totalCalls() != 0 {
		t.Fatalf("zero-byte GC = %+v, calls=%d", res, deleter.totalCalls())
	}
	if backlog, _ := f.m.DeletionBacklog(ctx); backlog != 0 {
		t.Fatalf("queue not cleared")
	}
}

func TestGCFailureKeepsEntryForRetry(t *testing.T) {
	f := newFixture(t)
	deleter := newFakeDeleter()
	// One endpoint fails once: the entry must stay queued and be retried.
	deleter.fail[endpoints[1]] = 1
	executor := gc.New(f.m, deleter, gc.Config{Now: func() time.Time { return f.now }, Logger: quietLogger()})
	ctx := context.Background()

	f.commitAndDelete(t, "retry.bin", chunkSize, makeChunks(t, 1))
	res, err := executor.RunOnce(ctx, f.now.Add(25*time.Hour))
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if res.Failed != 1 || res.Completed != 0 {
		t.Fatalf("result = %+v", res)
	}
	if backlog, _ := f.m.DeletionBacklog(ctx); backlog != 1 {
		t.Fatalf("failed entry was dropped from the queue")
	}

	// The healthy endpoints were checkpointed as acknowledged; the retry must
	// touch only the failed one and must not re-delete on the others.
	before := deleter.totalCalls()
	res, err = executor.RunOnce(ctx, f.now.Add(26*time.Hour))
	if err != nil {
		t.Fatalf("retry RunOnce: %v", err)
	}
	if res.Completed != 1 || res.Failed != 0 {
		t.Fatalf("retry result = %+v", res)
	}
	if res.ReplaySkipped != len(endpoints)-1 {
		t.Fatalf("retry skipped %d endpoints, want %d", res.ReplaySkipped, len(endpoints)-1)
	}
	if got := deleter.attemptCount(endpoints[0]); got != 1 {
		t.Fatalf("acknowledged endpoint %s was contacted %d times, want 1", endpoints[0], got)
	}
	if got := deleter.attemptCount(endpoints[1]); got != 2 {
		t.Fatalf("failed endpoint %s was attempted %d times, want 2", endpoints[1], got)
	}
	if got := deleter.attemptCount(endpoints[2]); got != 1 {
		t.Fatalf("acknowledged endpoint %s was contacted %d times, want 1", endpoints[2], got)
	}
	if deleter.totalCalls() <= before {
		t.Fatalf("retry did not finish the failed endpoint")
	}
	// The retry adds exactly the failed endpoint's set ids to the delete count.
	if backlog, _ := f.m.DeletionBacklog(ctx); backlog != 0 {
		t.Fatalf("queue not cleared after retry")
	}
}

func TestGCMissingManifestLeavesEntryQueued(t *testing.T) {
	f := newFixture(t)
	deleter := newFakeDeleter()
	executor := gc.New(f.m, deleter, gc.Config{Now: func() time.Time { return f.now }, Logger: quietLogger()})
	ctx := context.Background()

	versionID := f.commitAndDelete(t, "lost.bin", chunkSize, makeChunks(t, 1))
	items, err := f.m.DrainDeletions(ctx, f.now.Add(25*time.Hour), 10)
	if err != nil || len(items) != 1 {
		t.Fatalf("drain: %v, %v", items, err)
	}
	if items[0].ManifestHash == "" {
		t.Fatalf("manifest hash missing from deletion entry")
	}
	// Simulate metadata damage: the chunk table is gone.
	if err := f.m.DB().Update(ctx, func(tx storage.Writer) error {
		return tx.Delete([]byte("manifest_blobs"), []byte(items[0].ManifestHash))
	}); err != nil {
		t.Fatalf("drop manifest: %v", err)
	}
	res, err := executor.RunOnce(ctx, f.now.Add(25*time.Hour))
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if res.Failed != 1 || deleter.totalCalls() != 0 {
		t.Fatalf("result = %+v, calls=%d", res, deleter.totalCalls())
	}
	if backlog, _ := f.m.DeletionBacklog(ctx); backlog != 1 {
		t.Fatalf("entry with unreadable manifest must stay queued")
	}
	// The version was still tombstoned and is not readable.
	if _, err := f.m.GetManifest(ctx, f.bucket.Name, "lost.bin", versionID); err == nil {
		t.Fatalf("tombstoned version still readable")
	}
}

func TestGCCheapReplayWhenAllEndpointsAcknowledged(t *testing.T) {
	f := newFixture(t)
	deleter := newFakeDeleter()
	executor := gc.New(f.m, deleter, gc.Config{Now: func() time.Time { return f.now }, Logger: quietLogger()})
	ctx := context.Background()

	f.commitAndDelete(t, "crash.bin", 2*chunkSize, makeChunks(t, 2))
	items, err := f.m.DrainDeletions(ctx, f.now.Add(25*time.Hour), 10)
	if err != nil || len(items) != 1 {
		t.Fatalf("drain: %v, %v", items, err)
	}
	// Simulate a crash after every endpoint acknowledged but before the queue
	// entry was removed.
	if _, err := f.m.BeginDeletion(ctx, items[0].ID, f.now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	for _, ep := range endpoints {
		if err := f.m.AckDeletionEndpoint(ctx, items[0].ID, ep); err != nil {
			t.Fatalf("ack %s: %v", ep, err)
		}
	}
	res, err := executor.RunOnce(ctx, f.now.Add(25*time.Hour))
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if res.Completed != 1 || res.Failed != 0 {
		t.Fatalf("result = %+v", res)
	}
	if res.ReplaySkipped != len(endpoints) {
		t.Fatalf("replay skipped %d endpoints, want %d", res.ReplaySkipped, len(endpoints))
	}
	if deleter.totalCalls() != 0 {
		t.Fatalf("cheap replay contacted agents %d times, want 0", deleter.totalCalls())
	}
	if backlog, _ := f.m.DeletionBacklog(ctx); backlog != 0 {
		t.Fatalf("queue not cleared")
	}
}

func TestGCProgressIsPersistedOnEntry(t *testing.T) {
	f := newFixture(t)
	deleter := newFakeDeleter()
	deleter.fail[endpoints[2]] = 1
	executor := gc.New(f.m, deleter, gc.Config{Now: func() time.Time { return f.now }, Logger: quietLogger()})
	ctx := context.Background()

	f.commitAndDelete(t, "progress.bin", chunkSize, makeChunks(t, 1))
	if _, err := executor.RunOnce(ctx, f.now.Add(25*time.Hour)); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	items, err := f.m.DrainDeletions(ctx, f.now.Add(25*time.Hour), 10)
	if err != nil || len(items) != 1 {
		t.Fatalf("drain: %v, %v", items, err)
	}
	item := items[0]
	if item.StartedAt == nil || item.StartedAt.IsZero() {
		t.Fatalf("GC did not persist the in-progress marker: %+v", item)
	}
	if len(item.AckedEndpoints) != len(endpoints)-1 {
		t.Fatalf("acked endpoints = %v, want %d", item.AckedEndpoints, len(endpoints)-1)
	}
	if item.Acks(endpoints[2]) {
		t.Fatalf("failed endpoint was recorded as acknowledged")
	}
	for _, ep := range endpoints[:len(endpoints)-1] {
		if !item.Acks(ep) {
			t.Fatalf("endpoint %s missing from acknowledgements: %v", ep, item.AckedEndpoints)
		}
	}
}

func TestRunUsesIntervalAndCancels(t *testing.T) {
	f := newFixture(t)
	deleter := newFakeDeleter()
	executor := gc.New(f.m, deleter, gc.Config{
		Interval: 20 * time.Millisecond,
		Now:      func() time.Time { return f.now },
		Logger:   quietLogger(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		executor.Run(ctx)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("Run did not return after cancellation")
	}
	// An empty queue is not an error.
	if stats := executor.Stats(); stats["last_run_timestamp_seconds"] == 0 {
		t.Fatalf("Run did not execute a pass: %+v", stats)
	}
}

// chunkWithIdentity customises one chunk ref: the object-wide Index and the
// part-local AAD index differ for multipart objects, and ShardSetID is
// authoritative.
func chunkWithIdentity(t *testing.T, index int, aadIndex int, setID contract.ShardSetID) contract.ChunkRef {
	t.Helper()
	c := makeChunks(t, 1)[0]
	c.Index = index
	c.AADChunkIndex = aadIndex
	c.ShardSetID = setID
	return c
}

// TestGCUsesAuthoritativeMultipartShardSetIDs is the regression test for the
// multipart collision: two parts both start at chunk index 0, so a derived id
// from (bucket,key,version,Index) would collide with the other part's live
// shards — GC must use ChunkRef.ShardSetID, and must target two disjoint sets.
func TestGCUsesAuthoritativeMultipartShardSetIDs(t *testing.T) {
	f := newFixture(t)
	deleter := newFakeDeleter()
	executor := gc.New(f.m, deleter, gc.Config{Now: func() time.Time { return f.now }, Logger: quietLogger()})
	ctx := context.Background()

	versionID := contract.VersionID(id.New())
	const key = "multipart.bin"
	// Both parts were written with part-local AAD index 0.
	part1Set := contract.ShardSetIDForScoped(f.bucket.BucketID, key, versionID, "part/1", 0)
	part2Set := contract.ShardSetIDForScoped(f.bucket.BucketID, key, versionID, "part/2", 0)
	if part1Set == part2Set {
		t.Fatalf("scoped derivation collided: %s", part1Set)
	}
	chunks := []contract.ChunkRef{
		chunkWithIdentity(t, 0, 0, part1Set),
		chunkWithIdentity(t, 1, 0, part2Set),
	}
	if _, err := f.m.CommitObject(ctx, contract.CommitRequest{
		VersionID: versionID, BucketID: f.bucket.BucketID, Key: key,
		Size: 2 * chunkSize, ETag: "etag-multipart", ChunkSize: chunkSize,
		Chunks: chunks, ContentType: "application/octet-stream",
	}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if _, _, err := f.m.DeleteObject(ctx, f.bucket.Name, key, "", false); err != nil {
		t.Fatalf("delete: %v", err)
	}

	res, err := executor.RunOnce(ctx, f.now.Add(25*time.Hour))
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if res.Completed != 1 || res.Failed != 0 {
		t.Fatalf("result = %+v", res)
	}
	for _, ep := range endpoints {
		got := deleter.snapshot()[ep]
		seen := map[contract.ShardSetID]bool{}
		for _, id := range got {
			seen[id] = true
		}
		if !seen[part1Set] || !seen[part2Set] {
			t.Fatalf("endpoint %s did not delete both authoritative sets: %v", ep, got)
		}
		for _, id := range got {
			if id != part1Set && id != part2Set {
				t.Fatalf("endpoint %s deleted unexpected set %s (would be a live part's shards)", ep, id)
			}
		}
		// The collision-prone derived ids must never be targeted here.
		for _, bad := range []contract.ShardSetID{
			contract.ShardSetIDFor(f.bucket.BucketID, key, versionID, 0),
			contract.ShardSetIDFor(f.bucket.BucketID, key, versionID, 1),
		} {
			if seen[bad] {
				t.Fatalf("endpoint %s targeted derived collision id %s", ep, bad)
			}
		}
	}
}

// TestGCFallsBackToDerivationForLegacyManifests: manifests written before
// ChunkRef.ShardSetID existed have an empty field and must still be collectable.
func TestGCFallsBackToDerivationForLegacyManifests(t *testing.T) {
	f := newFixture(t)
	deleter := newFakeDeleter()
	executor := gc.New(f.m, deleter, gc.Config{Now: func() time.Time { return f.now }, Logger: quietLogger()})
	ctx := context.Background()

	versionID := f.commitAndDelete(t, "legacy.bin", chunkSize, makeChunks(t, 1))
	res, err := executor.RunOnce(ctx, f.now.Add(25*time.Hour))
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if res.Completed != 1 {
		t.Fatalf("result = %+v", res)
	}
	want := contract.ShardSetIDFor(f.bucket.BucketID, "legacy.bin", versionID, 0)
	for _, ep := range endpoints {
		found := false
		for _, id := range deleter.snapshot()[ep] {
			if id == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("endpoint %s did not receive derived legacy id %s", ep, want)
		}
	}
}
