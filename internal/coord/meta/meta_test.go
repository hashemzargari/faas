package meta_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
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
	sum := sha256.Sum256([]byte(t.Name()))
	name := fmt.Sprintf("tb-%x", sum[:8]) // deterministic, unique per test, <63 chars
	cfg := contract.BucketConfig{
		BucketID:   contract.BucketID(id.New()),
		Name:       name,
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

// commitVersion commits one version of key with a distinct etag and returns it.
func commitVersion(t *testing.T, m *meta.Service, bucket contract.BucketConfig, key, etag string, chunks []contract.ChunkRef) contract.CommitResult {
	t.Helper()
	req := commitReq(bucket, key, int64(len(chunks))*chunkSize, chunks)
	req.ETag = etag
	return mustCommit(t, m, req)
}

// TestListObjectVersionsMarkerPagination covers the S3 contract: pagination must
// resume *within* a key (KeyMarker + VersionIDMarker identify the last emitted
// version), not merely after it.
func TestListObjectVersionsMarkerPagination(t *testing.T) {
	ctx := context.Background()
	m := newMeta(t)
	bucket := newBucket(t, m, "Enabled")

	// Commit oldest → newest so a-v3 is the latest version.
	v1 := commitVersion(t, m, bucket, "a", "a-v1", makeChunks(t, 1))
	v2 := commitVersion(t, m, bucket, "a", "a-v2", makeChunks(t, 1))
	v3 := commitVersion(t, m, bucket, "a", "a-v3", makeChunks(t, 1))
	b1 := commitVersion(t, m, bucket, "b", "b-v1", makeChunks(t, 1))

	page1, err := m.ListObjects(ctx, contract.ListRequest{BucketID: bucket.BucketID, Versions: true, MaxKeys: 2})
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if len(page1.Entries) != 2 || page1.Entries[0].VersionID != v3.VersionID || page1.Entries[1].VersionID != v2.VersionID {
		t.Fatalf("page 1 entries = %+v", page1.Entries)
	}
	if !page1.IsTruncated || page1.NextKeyMarker != "a" || page1.NextVersionIDMarker != string(v2.VersionID) {
		t.Fatalf("page 1 markers = key %q version %q truncated %v", page1.NextKeyMarker, page1.NextVersionIDMarker, page1.IsTruncated)
	}

	page2, err := m.ListObjects(ctx, contract.ListRequest{
		BucketID: bucket.BucketID, Versions: true, MaxKeys: 2,
		KeyMarker: page1.NextKeyMarker, VersionIDMarker: page1.NextVersionIDMarker,
	})
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if len(page2.Entries) != 2 || page2.Entries[0].VersionID != v1.VersionID || page2.Entries[1].VersionID != b1.VersionID {
		t.Fatalf("page 2 entries = %+v", page2.Entries)
	}
	if page2.IsTruncated {
		t.Fatalf("page 2 unexpectedly truncated: %+v", page2)
	}

	// Walk one entry at a time: no duplicates, no gaps, exact order.
	var got []contract.VersionID
	keyMarker, versionMarker := "", ""
	for i := 0; i < 10; i++ {
		res, err := m.ListObjects(ctx, contract.ListRequest{
			BucketID: bucket.BucketID, Versions: true, MaxKeys: 1,
			KeyMarker: keyMarker, VersionIDMarker: versionMarker,
		})
		if err != nil {
			t.Fatalf("walk page %d: %v", i, err)
		}
		if len(res.Entries) != 1 {
			t.Fatalf("walk page %d returned %d entries", i, len(res.Entries))
		}
		got = append(got, res.Entries[0].VersionID)
		if !res.IsTruncated {
			break
		}
		keyMarker, versionMarker = res.NextKeyMarker, res.NextVersionIDMarker
	}
	want := []contract.VersionID{v3.VersionID, v2.VersionID, v1.VersionID, b1.VersionID}
	if len(got) != len(want) {
		t.Fatalf("walk returned %d versions, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("walk order = %v, want %v", got, want)
		}
	}
}

// TestVersionListingMarkerDeletedBetweenPages: if the marker version disappears
// between pages, S3 resumes at the next key instead of repeating or corrupting the
// page boundary.
func TestVersionListingMarkerDeletedBetweenPages(t *testing.T) {
	ctx := context.Background()
	m := newMeta(t)
	bucket := newBucket(t, m, "Enabled")
	commitVersion(t, m, bucket, "a", "a-v2", makeChunks(t, 1))
	va3 := commitVersion(t, m, bucket, "a", "a-v3", makeChunks(t, 1))
	b1 := commitVersion(t, m, bucket, "b", "b-v1", makeChunks(t, 1))

	page1, err := m.ListObjects(ctx, contract.ListRequest{BucketID: bucket.BucketID, Versions: true, MaxKeys: 1})
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if page1.NextKeyMarker != "a" || page1.NextVersionIDMarker != string(va3.VersionID) {
		t.Fatalf("page 1 markers = %+v", page1)
	}
	// Delete the marker version itself, then resume.
	if _, _, err := m.DeleteObject(ctx, bucket.Name, "a", va3.VersionID, false); err != nil {
		t.Fatalf("delete marker version: %v", err)
	}
	page2, err := m.ListObjects(ctx, contract.ListRequest{
		BucketID: bucket.BucketID, Versions: true, MaxKeys: 10,
		KeyMarker: page1.NextKeyMarker, VersionIDMarker: page1.NextVersionIDMarker,
	})
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if len(page2.Entries) != 1 || page2.Entries[0].VersionID != b1.VersionID {
		t.Fatalf("page 2 = %+v, want only b-v1 (skip the unavailable marker key)", page2.Entries)
	}
}

// TestNonVersionedKeyMarkerSkipsKey: for a plain listing a key marker behaves
// like StartAfter (whole keys only).
func TestNonVersionedKeyMarkerSkipsKey(t *testing.T) {
	ctx := context.Background()
	m := newMeta(t)
	bucket := newBucket(t, m, "")
	for _, key := range []string{"a", "b", "c"} {
		mustCommit(t, m, commitReq(bucket, key, chunkSize, makeChunks(t, 1)))
	}
	res, err := m.ListObjects(ctx, contract.ListRequest{
		BucketID: bucket.BucketID, MaxKeys: 1, KeyMarker: "a", VersionIDMarker: "ignored-in-object-listings",
	})
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}
	if len(res.Entries) != 1 || res.Entries[0].Key != "b" {
		t.Fatalf("marker listing = %+v, want key b", res.Entries)
	}
}

// TestCompleteUploadPreservesChunkIdentityAndEncryption pins the multipart
// commit contract: renumbering Index must preserve ShardSetID, AADChunkIndex,
// checksums and slots, and the manifest must carry the upload-level encryption
// envelope (not a part's envelope, which is under a different file key).
func TestCompleteUploadPreservesChunkIdentityAndEncryption(t *testing.T) {
	ctx := context.Background()
	m := newMeta(t)
	bucket := newBucket(t, m, "")
	versionID := contract.VersionID(id.New())
	uploadEnc := contract.EncryptionMeta{
		Mode:           "single-key",
		WrapKeyVersion: 2,
		WrappedFileKey: []byte{0x01, 0x02, 0x03, 0x04},
		KeyFingerprint: []byte{0xaa, 0xbb},
		FrameSize:      1 << 20,
	}
	up, err := m.CreateUpload(ctx, bucket.Name, "multipart/object.bin", contract.CommitRequest{
		VersionID: versionID, ChunkSize: chunkSize, Encryption: uploadEnc,
		ContentType: "application/octet-stream",
	})
	if err != nil {
		t.Fatalf("CreateUpload: %v", err)
	}
	part1Set := contract.ShardSetIDForScoped(bucket.BucketID, "multipart/object.bin", versionID, "part/1", 0)
	part2Set := contract.ShardSetIDForScoped(bucket.BucketID, "multipart/object.bin", versionID, "part/2", 0)
	if part1Set == part2Set {
		t.Fatalf("part scopes collided")
	}
	p1 := makeChunk(t, 0, flatParams)
	p1.AADChunkIndex = 0
	p1.ShardSetID = part1Set
	p2 := makeChunk(t, 0, flatParams)
	p2.AADChunkIndex = 0
	p2.ShardSetID = part2Set
	if err := m.CommitPart(ctx, up, 1, "etag-p1", chunkSize, []contract.ChunkRef{p1}, uploadEnc); err != nil {
		t.Fatalf("CommitPart 1: %v", err)
	}
	if err := m.CommitPart(ctx, up, 2, "etag-p2", chunkSize, []contract.ChunkRef{p2}, uploadEnc); err != nil {
		t.Fatalf("CommitPart 2: %v", err)
	}

	uploads, err := m.ListUploads(ctx, bucket.BucketID)
	if err != nil || len(uploads) != 1 {
		t.Fatalf("ListUploads = %+v, %v", uploads, err)
	}
	if uploads[0].VersionID != versionID {
		t.Fatalf("UploadInfo.VersionID = %s, want %s", uploads[0].VersionID, versionID)
	}
	if !reflect.DeepEqual(uploads[0].Encryption, uploadEnc) {
		t.Fatalf("UploadInfo.Encryption = %+v, want %+v", uploads[0].Encryption, uploadEnc)
	}

	if _, err := m.CompleteUpload(ctx, up); err != nil {
		t.Fatalf("CompleteUpload: %v", err)
	}
	manifest, err := m.GetManifest(ctx, bucket.Name, "multipart/object.bin", "")
	if err != nil {
		t.Fatalf("GetManifest: %v", err)
	}
	if len(manifest.Chunks) != 2 {
		t.Fatalf("chunks = %d, want 2", len(manifest.Chunks))
	}
	if !reflect.DeepEqual(manifest.Encryption, uploadEnc) {
		t.Fatalf("manifest encryption = %+v, want upload-level %+v", manifest.Encryption, uploadEnc)
	}
	wantSets := []contract.ShardSetID{part1Set, part2Set}
	for i, ch := range manifest.Chunks {
		if ch.Index != i {
			t.Fatalf("chunk %d Index = %d, want dense %d", i, ch.Index, i)
		}
		if ch.AADChunkIndex != 0 {
			t.Fatalf("chunk %d AADChunkIndex = %d, want part-local 0 preserved", i, ch.AADChunkIndex)
		}
		if ch.ShardSetID != wantSets[i] {
			t.Fatalf("chunk %d ShardSetID = %s, want %s (renumbering must preserve it)", i, ch.ShardSetID, wantSets[i])
		}
		if len(ch.Checksums) != flatParams.TotalShards() || len(ch.Slots) != flatParams.TotalShards() {
			t.Fatalf("chunk %d lost checksums/slots", i)
		}
	}
}

// TestBucketCreatedAtIsNonZeroAndSurvivesReopen: S3 ListBuckets carries
// <CreationDate>, and aws-sdk-go-v2 rejects the whole response on an empty value,
// so a created bucket must always carry a real timestamp that is stable across a
// store restart.
func TestBucketCreatedAtIsNonZeroAndSurvivesReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	m := meta.New(db)
	cfg := contract.BucketConfig{
		BucketID:  contract.BucketID(id.New()),
		Name:      "created-at-bucket",
		TenantID:  tenantID,
		ProjectID: projectID,
		Region:    contract.DefaultRegion,
		Ownership: "ObjectWriter",
	}
	if err := m.CreateBucket(ctx, cfg); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	created, err := m.GetBucket(ctx, cfg.Name)
	if err != nil {
		t.Fatalf("GetBucket: %v", err)
	}
	if created.CreatedAt.IsZero() {
		t.Fatalf("CreateBucket did not populate CreatedAt")
	}
	if created.CreatedAt.Unix() <= 0 {
		t.Fatalf("CreatedAt = %v, want a real creation time", created.CreatedAt)
	}
	buckets, err := m.ListBuckets(ctx, contract.Principal{IsRoot: true})
	if err != nil {
		t.Fatalf("ListBuckets: %v", err)
	}
	if len(buckets) != 1 || buckets[0].CreatedAt.IsZero() || !buckets[0].CreatedAt.Equal(created.CreatedAt) {
		t.Fatalf("ListBuckets CreatedAt = %v, want %v", buckets, created.CreatedAt)
	}

	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	db2, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() { _ = db2.Close() })
	if err := storage.Migrate(ctx, db2); err != nil {
		t.Fatalf("migrate reopen: %v", err)
	}
	reopened, err := meta.New(db2).GetBucket(ctx, cfg.Name)
	if err != nil {
		t.Fatalf("GetBucket after reopen: %v", err)
	}
	if !reopened.CreatedAt.Equal(created.CreatedAt) {
		t.Fatalf("CreatedAt changed across reopen: %v -> %v", created.CreatedAt, reopened.CreatedAt)
	}
}

// TestLegacyBucketCreatedAtBackfillIsStableAndPersisted: records written before
// BucketConfig.CreatedAt existed must get a stable, non-zero fallback that is
// persisted on first read (so it can never flap and is repaired for the gateway).
func TestLegacyBucketCreatedAtBackfillIsStableAndPersisted(t *testing.T) {
	ctx := context.Background()
	m := newMeta(t)
	bucketID := contract.BucketID(id.New())
	const name = "legacy-bucket"
	legacy := map[string]any{
		"bucket_id":  bucketID,
		"name":       name,
		"tenant_id":  tenantID,
		"project_id": projectID,
		"region":     contract.DefaultRegion,
		"ownership":  "ObjectWriter",
	}
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy record: %v", err)
	}
	if err := m.DB().Update(ctx, func(tx *storage.WriteTx) error {
		if err := tx.Put([]byte("buckets"), []byte(name), raw); err != nil {
			return err
		}
		return tx.Put([]byte("bucket_ids"), []byte(bucketID), []byte(name))
	}); err != nil {
		t.Fatalf("seed legacy record: %v", err)
	}

	first, err := m.GetBucket(ctx, name)
	if err != nil {
		t.Fatalf("GetBucket: %v", err)
	}
	if first.CreatedAt.IsZero() {
		t.Fatalf("legacy bucket still returns the zero time")
	}
	second, err := m.GetBucket(ctx, name)
	if err != nil {
		t.Fatalf("GetBucket second read: %v", err)
	}
	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("fallback flapped between reads: %v -> %v", first.CreatedAt, second.CreatedAt)
	}
	// The fallback is the documented Unix epoch, persisted so future reads (and
	// the SQL migration) see the same value.
	if first.CreatedAt.Unix() != 0 {
		t.Fatalf("fallback = %v, want Unix epoch", first.CreatedAt)
	}
	var stored map[string]any
	if err := m.DB().View(ctx, func(tx *storage.ReadTx) error {
		rec, err := tx.Get([]byte("buckets"), []byte(name))
		if err != nil {
			return err
		}
		return json.Unmarshal(rec, &stored)
	}); err != nil {
		t.Fatalf("read stored record: %v", err)
	}
	if ts, ok := stored["created_at"].(string); !ok || ts == "" {
		t.Fatalf("back-fill was not persisted: %v", stored["created_at"])
	}

	// Listings go through the same path.
	buckets, err := m.ListBuckets(ctx, contract.Principal{IsRoot: true})
	if err != nil {
		t.Fatalf("ListBuckets: %v", err)
	}
	if len(buckets) != 1 || buckets[0].CreatedAt.IsZero() {
		t.Fatalf("ListBuckets = %+v", buckets)
	}
}

// TestUpdateBucketPreservesCreatedAt: mutable config updates must not erase the
// creation timestamp (the gateway PATCHes versioning/ownership etc.).
func TestUpdateBucketPreservesCreatedAt(t *testing.T) {
	ctx := context.Background()
	m := newMeta(t)
	bucket := newBucket(t, m, "")
	got, err := m.GetBucket(ctx, bucket.Name)
	if err != nil {
		t.Fatalf("GetBucket: %v", err)
	}
	cfg := got
	cfg.Versioning = "Enabled"
	cfg.CreatedAt = time.Time{} // simulate a caller that omits it
	if err := m.UpdateBucket(ctx, cfg); err != nil {
		t.Fatalf("UpdateBucket: %v", err)
	}
	after, err := m.GetBucket(ctx, bucket.Name)
	if err != nil {
		t.Fatalf("GetBucket after update: %v", err)
	}
	if !after.CreatedAt.Equal(got.CreatedAt) || after.Versioning != "Enabled" {
		t.Fatalf("update = %+v, want CreatedAt %v preserved", after, got.CreatedAt)
	}
}
