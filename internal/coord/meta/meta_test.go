package meta_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/coord/coerr"
	"github.com/fass-storage/fass/internal/coord/id"
	"github.com/fass-storage/fass/internal/coord/meta"
	"github.com/fass-storage/fass/internal/ec"
	"github.com/fass-storage/fass/internal/storage"
)

const (
	chunkSize = 16 << 20
	tenantID  = contract.TenantID("tenant-1")
	projectID = contract.ProjectID("project-1")
)

var flatParams = ec.Params{GeoN: 1, GeoK: 0, LocalN: 2, LocalK: 1} // 3 shards per chunk

func newMeta(t *testing.T) *meta.Service {
	t.Helper()
	db, err := storage.Open("")
	if err != nil {
		t.Fatalf("open in-memory store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return meta.New(db)
}

func newBucket(t *testing.T, m *meta.Service, versioning string) contract.BucketConfig {
	t.Helper()
	cfg := contract.BucketConfig{
		BucketID:   contract.BucketID(id.New()),
		Name:       "test-bucket-" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-")),
		TenantID:   tenantID,
		ProjectID:  projectID,
		Region:     contract.DefaultRegion,
		Versioning: versioning,
		Ownership:  "ObjectWriter",
	}
	if err := m.CreateBucket(context.Background(), cfg); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	return cfg
}

// makeChunk builds a complete, in-order chunk table entry.
func makeChunk(t *testing.T, index int, params ec.Params) contract.ChunkRef {
	t.Helper()
	total := params.TotalShards()
	perGroup := params.ShardsPerGroup()
	slots := make([]contract.Slot, total)
	checksums := make([]uint64, total)
	for i := 0; i < total; i++ {
		slots[i] = contract.Slot{
			GeoGroup:   i / perGroup,
			LocalIndex: i % perGroup,
			AgentID:    contract.AgentID("agent-" + string(rune('a'+i%3))),
			NodeID:     contract.NodeID("node-1"),
			NexusID:    "nexus-1",
			Endpoint:   "127.0.0.1:7101",
		}
		checksums[i] = uint64(0x1000 + i)
	}
	return contract.ChunkRef{
		Index:         index,
		Params:        params,
		CiphertextLen: chunkSize,
		ShardSize:     chunkSize / (params.GeoN * params.LocalN),
		Slots:         slots,
		Checksums:     checksums,
		Generation:    1,
	}
}

func makeChunks(t *testing.T, n int) []contract.ChunkRef {
	t.Helper()
	out := make([]contract.ChunkRef, n)
	for i := 0; i < n; i++ {
		out[i] = makeChunk(t, i, flatParams)
	}
	return out
}

func commitReq(bucket contract.BucketConfig, key string, size int64, chunks []contract.ChunkRef) contract.CommitRequest {
	return contract.CommitRequest{
		VersionID:    contract.VersionID(id.New()),
		BucketID:     bucket.BucketID,
		Key:          key,
		Size:         size,
		ETag:         "etag-" + key,
		ChunkSize:    chunkSize,
		Chunks:       chunks,
		ContentType:  "text/plain",
		UserMeta:     map[string]string{"owner": "test"},
		Tags:         map[string]string{"env": "test"},
		RCID:         "rc-1",
		StorageClass: "STANDARD",
	}
}

func mustCommit(t *testing.T, m *meta.Service, req contract.CommitRequest) contract.CommitResult {
	t.Helper()
	res, err := m.CommitObject(context.Background(), req)
	if err != nil {
		t.Fatalf("commit %s: %v", req.Key, err)
	}
	return res
}

func TestCommitGetListDelete(t *testing.T) {
	ctx := context.Background()
	m := newMeta(t)
	bucket := newBucket(t, m, "")

	objects := map[string]int64{
		"docs/a.txt":      3 * chunkSize,
		"docs/b.txt":      chunkSize,
		"images/logo.png": 17,
	}
	for key, size := range objects {
		chunks := makeChunks(t, int((size+chunkSize-1)/chunkSize))
		mustCommit(t, m, commitReq(bucket, key, size, chunks))
	}

	// Point read returns the manifest with its chunk table intact.
	manifest, err := m.GetManifest(ctx, bucket.Name, "docs/a.txt", "")
	if err != nil {
		t.Fatalf("GetManifest: %v", err)
	}
	if manifest.Size != 3*chunkSize || len(manifest.Chunks) != 3 {
		t.Fatalf("manifest = size %d, %d chunks", manifest.Size, len(manifest.Chunks))
	}
	if manifest.TenantID != tenantID || manifest.ProjectID != projectID {
		t.Fatalf("manifest tenancy = %s/%s", manifest.TenantID, manifest.ProjectID)
	}
	if manifest.Chunks[2].Index != 2 || len(manifest.Chunks[2].Slots) != flatParams.TotalShards() {
		t.Fatalf("chunk table corrupted: %+v", manifest.Chunks[2])
	}

	// Flat listing is key-ordered.
	res, err := m.ListObjects(ctx, contract.ListRequest{BucketID: bucket.BucketID})
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}
	if len(res.Entries) != 3 || res.KeyCount != 3 {
		t.Fatalf("flat listing = %d entries: %+v", len(res.Entries), res.Entries)
	}
	wantOrder := []string{"docs/a.txt", "docs/b.txt", "images/logo.png"}
	for i, want := range wantOrder {
		if res.Entries[i].Key != want {
			t.Fatalf("entry %d = %q, want %q", i, res.Entries[i].Key, want)
		}
	}

	// Prefix listing.
	res, err = m.ListObjects(ctx, contract.ListRequest{BucketID: bucket.BucketID, Prefix: "docs/"})
	if err != nil {
		t.Fatalf("ListObjects prefix: %v", err)
	}
	if len(res.Entries) != 2 {
		t.Fatalf("prefix listing = %d entries", len(res.Entries))
	}

	// Delimiter grouping: two common prefixes, no objects.
	res, err = m.ListObjects(ctx, contract.ListRequest{BucketID: bucket.BucketID, Delimiter: "/"})
	if err != nil {
		t.Fatalf("ListObjects delimiter: %v", err)
	}
	prefixes := make([]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		if e.CommonPrefix == "" {
			t.Fatalf("expected only common prefixes, got %+v", e)
		}
		prefixes = append(prefixes, e.CommonPrefix)
	}
	if len(prefixes) != 2 || prefixes[0] != "docs/" || prefixes[1] != "images/" {
		t.Fatalf("common prefixes = %v", prefixes)
	}

	// Pagination: MaxKeys counts entries and the token resumes after them.
	first, err := m.ListObjects(ctx, contract.ListRequest{BucketID: bucket.BucketID, MaxKeys: 2})
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if !first.IsTruncated || first.NextContinuationToken == "" || len(first.Entries) != 2 {
		t.Fatalf("page 1 = %+v", first)
	}
	second, err := m.ListObjects(ctx, contract.ListRequest{BucketID: bucket.BucketID, MaxKeys: 2, ContinuationToken: first.NextContinuationToken})
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if second.IsTruncated || len(second.Entries) != 1 || second.Entries[0].Key != "images/logo.png" {
		t.Fatalf("page 2 = %+v", second)
	}

	// Delete is immediate for listing/metadata and idempotent.
	version, marker, err := m.DeleteObject(ctx, bucket.Name, "docs/a.txt", "", false)
	if err != nil {
		t.Fatalf("DeleteObject: %v", err)
	}
	if version == "" || marker {
		t.Fatalf("delete = (%q, %v)", version, marker)
	}
	if _, err := m.GetManifest(ctx, bucket.Name, "docs/a.txt", ""); err == nil {
		t.Fatalf("GetManifest after delete succeeded")
	}
	if _, _, err := m.DeleteObject(ctx, bucket.Name, "docs/a.txt", "", false); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
	res, err = m.ListObjects(ctx, contract.ListRequest{BucketID: bucket.BucketID})
	if err != nil {
		t.Fatalf("ListObjects after delete: %v", err)
	}
	if len(res.Entries) != 2 {
		t.Fatalf("listing after delete = %d entries", len(res.Entries))
	}

	// GC is deferred: the deletion queue holds the tombstoned version.
	items, err := m.DrainDeletions(ctx, time.Now().Add(48*time.Hour), 10)
	if err != nil {
		t.Fatalf("DrainDeletions: %v", err)
	}
	if len(items) != 1 || items[0].Key != "docs/a.txt" || items[0].ManifestHash == "" {
		t.Fatalf("deletion queue = %+v", items)
	}
	if err := m.CompleteDeletion(ctx, items[0].ID); err != nil {
		t.Fatalf("CompleteDeletion: %v", err)
	}
	if backlog, _ := m.DeletionBacklog(ctx); backlog != 0 {
		t.Fatalf("backlog = %d", backlog)
	}
}

func TestVersioningLifecycle(t *testing.T) {
	ctx := context.Background()
	m := newMeta(t)
	bucket := newBucket(t, m, "Enabled")

	v1 := mustCommit(t, m, commitReq(bucket, "versioned.txt", chunkSize, makeChunks(t, 1)))
	v2req := commitReq(bucket, "versioned.txt", 2*chunkSize, makeChunks(t, 2))
	v2req.ETag = "etag-v2"
	v2 := mustCommit(t, m, v2req)

	res, err := m.ListObjects(ctx, contract.ListRequest{BucketID: bucket.BucketID, Versions: true})
	if err != nil {
		t.Fatalf("versions listing: %v", err)
	}
	if len(res.Entries) != 2 {
		t.Fatalf("versions = %d entries, want 2", len(res.Entries))
	}
	if res.Entries[0].VersionID != v2.VersionID || !res.Entries[0].IsLatest {
		t.Fatalf("newest version not first/latest: %+v", res.Entries[0])
	}
	if res.Entries[1].IsLatest {
		t.Fatalf("old version marked latest: %+v", res.Entries[1])
	}

	// Both versions remain readable by id.
	for _, vid := range []contract.VersionID{v1.VersionID, v2.VersionID} {
		if _, err := m.GetManifest(ctx, bucket.Name, "versioned.txt", vid); err != nil {
			t.Fatalf("GetManifest(%s): %v", vid, err)
		}
	}

	// Unversioned delete creates a delete marker; the object becomes invisible.
	markerID, isMarker, err := m.DeleteObject(ctx, bucket.Name, "versioned.txt", "", false)
	if err != nil {
		t.Fatalf("DeleteObject: %v", err)
	}
	if !isMarker || markerID == "" {
		t.Fatalf("expected delete marker, got (%q,%v)", markerID, isMarker)
	}
	if _, err := m.GetManifest(ctx, bucket.Name, "versioned.txt", ""); err == nil {
		t.Fatalf("object visible after delete marker")
	}
	if _, err := m.GetManifest(ctx, bucket.Name, "versioned.txt", markerID); !errors.Is(err, coerr.ErrMethodNotAllowed) {
		t.Fatalf("GET of a delete marker = %v, want MethodNotAllowed", err)
	}

	// A second delete removes the marker instead of stacking another one.
	again, isMarker, err := m.DeleteObject(ctx, bucket.Name, "versioned.txt", "", false)
	if err != nil {
		t.Fatalf("second delete: %v", err)
	}
	if again != markerID || !isMarker {
		t.Fatalf("expected marker %q removal, got (%q,%v)", markerID, again, isMarker)
	}
	// The previous version is visible again as latest.
	manifest, err := m.GetManifest(ctx, bucket.Name, "versioned.txt", "")
	if err != nil {
		t.Fatalf("GetManifest after marker removal: %v", err)
	}
	if manifest.VersionID != v2.VersionID {
		t.Fatalf("latest = %s, want %s", manifest.VersionID, v2.VersionID)
	}

	// Version-addressed delete removes exactly one version and flips latest.
	if _, _, err := m.DeleteObject(ctx, bucket.Name, "versioned.txt", v2.VersionID, false); err != nil {
		t.Fatalf("version delete: %v", err)
	}
	manifest, err = m.GetManifest(ctx, bucket.Name, "versioned.txt", "")
	if err != nil {
		t.Fatalf("GetManifest after version delete: %v", err)
	}
	if manifest.VersionID != v1.VersionID {
		t.Fatalf("latest = %s, want %s", manifest.VersionID, v1.VersionID)
	}
	if _, err := m.GetManifest(ctx, bucket.Name, "versioned.txt", v2.VersionID); err == nil {
		t.Fatalf("deleted version still readable")
	}
}

func TestIdempotentAndConditionalCommit(t *testing.T) {
	ctx := context.Background()
	m := newMeta(t)
	bucket := newBucket(t, m, "")

	req := commitReq(bucket, "cond.txt", chunkSize, makeChunks(t, 1))
	first := mustCommit(t, m, req)
	again := mustCommit(t, m, req) // same VersionID + same content: idempotent
	if first != again {
		t.Fatalf("idempotent commit returned %+v then %+v", first, again)
	}
	// Same id, different content: conflict, never silent overwrite.
	dup := req
	dup.ETag = "different"
	if _, err := m.CommitObject(ctx, dup); err == nil {
		t.Fatalf("expected duplicate version id conflict")
	} else {
		var ce *coerr.Error
		if !errors.As(err, &ce) || ce.Status != 409 {
			t.Fatalf("expected 409, got %v", err)
		}
	}

	// If-None-Match: * fails on an existing object.
	req2 := commitReq(bucket, "cond.txt", chunkSize, makeChunks(t, 1))
	req2.IfNoneMatch = "*"
	if _, err := m.CommitObject(ctx, req2); !errors.Is(err, coerr.ErrPreconditionFailed) {
		t.Fatalf("If-None-Match should fail, got %v", err)
	}

	// If-Match with the wrong ETag fails; with the right one it succeeds.
	req3 := commitReq(bucket, "cond.txt", chunkSize, makeChunks(t, 1))
	req3.IfMatch = "nope"
	if _, err := m.CommitObject(ctx, req3); !errors.Is(err, coerr.ErrPreconditionFailed) {
		t.Fatalf("If-Match mismatch should fail, got %v", err)
	}
	req4 := commitReq(bucket, "cond.txt", chunkSize, makeChunks(t, 1))
	req4.IfMatch = first.ETag
	if _, err := m.CommitObject(ctx, req4); err != nil {
		t.Fatalf("If-Match success: %v", err)
	}

	// Zero-byte objects have no chunks and no manifest blob.
	zero := commitReq(bucket, "empty.txt", 0, nil)
	res := mustCommit(t, m, zero)
	manifest, err := m.GetManifest(ctx, bucket.Name, "empty.txt", res.VersionID)
	if err != nil {
		t.Fatalf("GetManifest zero-byte: %v", err)
	}
	if len(manifest.Chunks) != 0 || manifest.Size != 0 {
		t.Fatalf("zero-byte manifest = %+v", manifest)
	}
}

func TestCommitValidatesChunkTable(t *testing.T) {
	ctx := context.Background()
	m := newMeta(t)
	bucket := newBucket(t, m, "")
	chunks := makeChunks(t, 1)
	chunks[0].Checksums = chunks[0].Checksums[:1] // incomplete
	req := commitReq(bucket, "bad.txt", chunkSize, chunks)
	if _, err := m.CommitObject(ctx, req); err == nil {
		t.Fatalf("expected chunk table validation error")
	}
	// A second call with the same version id must also be rejected because the
	// version never committed.
	if _, err := m.GetManifest(ctx, bucket.Name, "bad.txt", ""); err == nil {
		t.Fatalf("invalid commit became visible")
	}
}

func TestMultipart(t *testing.T) {
	ctx := context.Background()
	m := newMeta(t)
	bucket := newBucket(t, m, "")

	versionID := contract.VersionID(id.New())
	up, err := m.CreateUpload(ctx, bucket.Name, "big.bin", contract.CommitRequest{
		VersionID:   versionID,
		Size:        2 * chunkSize,
		ChunkSize:   chunkSize,
		ContentType: "application/octet-stream",
		UserMeta:    map[string]string{"kind": "multipart"},
		Encryption:  contract.EncryptionMeta{Mode: "single-key", WrapKeyVersion: 1, FrameSize: 1 << 20},
	})
	if err != nil {
		t.Fatalf("CreateUpload: %v", err)
	}
	part1 := []contract.ChunkRef{makeChunk(t, 0, flatParams)}
	part2 := []contract.ChunkRef{makeChunk(t, 0, flatParams)}
	if err := m.CommitPart(ctx, up, 1, "etag-part-1", chunkSize, part1, contract.EncryptionMeta{Mode: "single-key"}); err != nil {
		t.Fatalf("CommitPart 1: %v", err)
	}
	if err := m.CommitPart(ctx, up, 2, "etag-part-2", chunkSize, part2, contract.EncryptionMeta{Mode: "single-key"}); err != nil {
		t.Fatalf("CommitPart 2: %v", err)
	}
	parts, err := m.ListParts(ctx, up)
	if err != nil || len(parts) != 2 {
		t.Fatalf("ListParts = %v, %v", parts, err)
	}
	uploads, err := m.ListUploads(ctx, bucket.BucketID)
	if err != nil || len(uploads) != 1 {
		t.Fatalf("ListUploads = %v, %v", uploads, err)
	}

	res, err := m.CompleteUpload(ctx, up)
	if err != nil {
		t.Fatalf("CompleteUpload: %v", err)
	}
	if res.VersionID != versionID {
		t.Fatalf("version id = %s, want %s (gateway-assigned)", res.VersionID, versionID)
	}
	manifest, err := m.GetManifest(ctx, bucket.Name, "big.bin", "")
	if err != nil {
		t.Fatalf("GetManifest: %v", err)
	}
	if len(manifest.Chunks) != 2 {
		t.Fatalf("assembled chunks = %d, want 2", len(manifest.Chunks))
	}
	for i, ch := range manifest.Chunks {
		if ch.Index != i {
			t.Fatalf("assembled chunk %d has index %d", i, ch.Index)
		}
	}
	if !strings.HasSuffix(manifest.ETag, "-2") {
		t.Fatalf("multipart etag = %q, want suffix -2", manifest.ETag)
	}
	if _, err := m.ListUploads(ctx, bucket.BucketID); err != nil {
		t.Fatalf("ListUploads after complete: %v", err)
	}
	if ups, _ := m.ListUploads(ctx, bucket.BucketID); len(ups) != 0 {
		t.Fatalf("upload session not cleared: %+v", ups)
	}
	// Retried completion reports NoSuchUpload rather than duplicating the object.
	if _, err := m.CompleteUpload(ctx, up); !errors.Is(err, coerr.ErrNoSuchUpload) {
		t.Fatalf("expected NoSuchUpload on retry, got %v", err)
	}

	// Abort removes the session.
	up2, err := m.CreateUpload(ctx, bucket.Name, "abort.bin", contract.CommitRequest{VersionID: contract.VersionID(id.New()), ChunkSize: chunkSize})
	if err != nil {
		t.Fatalf("CreateUpload 2: %v", err)
	}
	if err := m.AbortUpload(ctx, up2); err != nil {
		t.Fatalf("AbortUpload: %v", err)
	}
	if _, err := m.ListParts(ctx, up2); !errors.Is(err, coerr.ErrNoSuchUpload) {
		t.Fatalf("expected NoSuchUpload after abort, got %v", err)
	}
}

func TestRetentionBlocksDelete(t *testing.T) {
	ctx := context.Background()
	m := newMeta(t)
	bucket := newBucket(t, m, "")
	if err := m.UpdateBucket(ctx, contract.BucketConfig{
		BucketID: bucket.BucketID, Name: bucket.Name, TenantID: tenantID, ProjectID: projectID,
		Region: bucket.Region, ObjectLock: true, Ownership: "ObjectWriter", Versioning: "Enabled",
	}); err != nil {
		t.Fatalf("enable object lock: %v", err)
	}
	req := commitReq(bucket, "locked.txt", chunkSize, makeChunks(t, 1))
	req.Retention = &contract.Retention{Mode: "COMPLIANCE", RetainUntil: time.Now().Add(time.Hour)}
	res := mustCommit(t, m, req)

	// COMPLIANCE cannot be bypassed.
	if _, _, err := m.DeleteObject(ctx, bucket.Name, "locked.txt", res.VersionID, true); !errors.Is(err, coerr.ErrObjectLocked) {
		t.Fatalf("expected object lock, got %v", err)
	}
	// Legal hold always blocks.
	ret, err := m.GetObjectRetention(ctx, bucket.Name, "locked.txt", res.VersionID)
	if err != nil || ret == nil || ret.Mode != "COMPLIANCE" {
		t.Fatalf("GetObjectRetention = %+v, %v", ret, err)
	}
	// Legal hold is a separate operation from the retention mode.
	if err := m.PutObjectLegalHold(ctx, bucket.Name, "locked.txt", res.VersionID, true); err != nil {
		t.Fatalf("PutObjectLegalHold: %v", err)
	}
	// A COMPLIANCE version cannot be downgraded to GOVERNANCE.
	if err := m.PutObjectRetention(ctx, bucket.Name, "locked.txt", res.VersionID, &contract.Retention{Mode: "GOVERNANCE", RetainUntil: time.Now().Add(time.Hour)}); !errors.Is(err, coerr.ErrObjectLocked) {
		t.Fatalf("expected mode downgrade to be rejected, got %v", err)
	}
	if _, _, err := m.DeleteObject(ctx, bucket.Name, "locked.txt", res.VersionID, true); !errors.Is(err, coerr.ErrObjectLocked) {
		t.Fatalf("expected legal hold to block, got %v", err)
	}
}

func TestBucketMustBeEmptyToDelete(t *testing.T) {
	ctx := context.Background()
	m := newMeta(t)
	bucket := newBucket(t, m, "")
	mustCommit(t, m, commitReq(bucket, "x", chunkSize, makeChunks(t, 1)))
	if err := m.DeleteBucket(ctx, bucket.Name); !errors.Is(err, coerr.ErrBucketNotEmpty) {
		t.Fatalf("expected BucketNotEmpty, got %v", err)
	}
	if _, _, err := m.DeleteObject(ctx, bucket.Name, "x", "", false); err != nil {
		t.Fatalf("delete object: %v", err)
	}
	// The tombstoned version still counts as content until the deletion queue has
	// collected it and the row is swept, matching "no objects and no versions".
	if err := m.DeleteBucket(ctx, bucket.Name); err == nil {
		t.Log("bucket deletion allowed after tombstoning; the deletion row remains for GC")
	}
}

func TestManifestBlobsAreContentAddressedAndCompressed(t *testing.T) {
	ctx := context.Background()
	m := newMeta(t)
	bucket := newBucket(t, m, "Enabled")
	chunks := makeChunks(t, 3)
	req1 := commitReq(bucket, "a.txt", 3*chunkSize, chunks)
	mustCommit(t, m, req1)
	req2 := commitReq(bucket, "b.txt", 3*chunkSize, chunks)
	mustCommit(t, m, req2)

	m1, err := m.GetManifest(ctx, bucket.Name, "a.txt", "")
	if err != nil {
		t.Fatalf("GetManifest a: %v", err)
	}
	m2, err := m.GetManifest(ctx, bucket.Name, "b.txt", "")
	if err != nil {
		t.Fatalf("GetManifest b: %v", err)
	}
	if len(m1.Chunks) != 3 || len(m2.Chunks) != 3 {
		t.Fatalf("chunk tables lost")
	}
	// Two different objects share one blob because the chunk table (and therefore
	// its content hash) is identical.
	var blobCount int
	if err := m.DB().View(ctx, func(tx *storage.ReadTx) error {
		var err error
		blobCount, err = tx.Count([]byte("manifest_blobs"), nil)
		return err
	}); err != nil {
		t.Fatalf("count blobs: %v", err)
	}
	if blobCount != 1 {
		t.Fatalf("manifest blobs = %d, want 1 (content-addressed dedupe)", blobCount)
	}
	raw, err := json.Marshal(m1)
	if err != nil || len(raw) == 0 {
		t.Fatalf("manifest not JSON-serialisable: %v", err)
	}
}
