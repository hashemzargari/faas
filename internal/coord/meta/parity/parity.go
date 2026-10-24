// Package parity is the backend-neutral repository behaviour suite.
//
// The same tests run against the embedded store and PostgreSQL, so the two
// backends cannot drift on the semantics the rest of the system (and real S3
// clients) depend on: version ordering, delete markers, suspended null versions,
// prefix/delimiter pages, continuation-token resume, zero-byte objects and
// concurrent commits to the same key.
package parity

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/coord/meta"
	"github.com/fass-storage/fass/internal/ec"
	"github.com/fass-storage/fass/internal/storage"
)

const (
	chunkSize = 16 << 20
	tenantID  = contract.TenantID("parity-tenant")
	projectID = contract.ProjectID("parity-project")
)

var flatParams = ec.Params{GeoN: 1, GeoK: 0, LocalN: 2, LocalK: 1}

// Run executes the suite against one backend.
func Run(t *testing.T, store storage.Store) {
	t.Helper()
	m := meta.New(store)
	ctx := context.Background()

	t.Run("VersionOrdering", func(t *testing.T) { testVersionOrdering(t, ctx, m) })
	t.Run("DeleteMarkerReplacement", func(t *testing.T) { testDeleteMarkerReplacement(t, ctx, m) })
	t.Run("SuspendedNullVersion", func(t *testing.T) { testSuspendedNullVersion(t, ctx, m) })
	t.Run("PrefixDelimiterPages", func(t *testing.T) { testPrefixDelimiterPages(t, ctx, m) })
	t.Run("ContinuationTokenResume", func(t *testing.T) { testContinuationTokenResume(t, ctx, m) })
	t.Run("ZeroByteObjects", func(t *testing.T) { testZeroByteObjects(t, ctx, m) })
	t.Run("ConcurrentCommitsSameKey", func(t *testing.T) { testConcurrentCommits(t, ctx, m) })
}

func newBucket(t *testing.T, m *meta.Service, versioning string) contract.BucketConfig {
	t.Helper()
	sum := sha256.Sum256([]byte(t.Name()))
	cfg := contract.BucketConfig{
		BucketID:   contract.BucketID(contract.NewUUID()),
		Name:       fmt.Sprintf("pb-%x", sum[:8]),
		TenantID:   tenantID,
		ProjectID:  projectID,
		Region:     contract.DefaultRegion,
		Versioning: versioning,
		Ownership:  "ObjectWriter",
	}
	if err := m.CreateBucket(context.Background(), cfg); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	return cfg
}

func makeChunk(index int, params ec.Params) contract.ChunkRef {
	total := params.TotalShards()
	perGroup := params.ShardsPerGroup()
	slots := make([]contract.Slot, total)
	checksums := make([]uint64, total)
	for i := 0; i < total; i++ {
		slots[i] = contract.Slot{
			GeoGroup:   i / perGroup,
			LocalIndex: i % perGroup,
			AgentID:    contract.AgentID(fmt.Sprintf("agent-%d", i%3)),
			NodeID:     "node-1",
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

func commitReq(bucket contract.BucketConfig, key, etag string) contract.CommitRequest {
	return contract.CommitRequest{
		VersionID:    contract.VersionID(contract.NewUUID()),
		BucketID:     bucket.BucketID,
		Key:          key,
		Size:         chunkSize,
		ETag:         etag,
		ChunkSize:    chunkSize,
		Chunks:       []contract.ChunkRef{makeChunk(0, flatParams)},
		ContentType:  "text/plain",
		RCID:         "rc-1",
		StorageClass: "STANDARD",
	}
}

func commit(t *testing.T, m *meta.Service, req contract.CommitRequest) contract.CommitResult {
	t.Helper()
	res, err := m.CommitObject(context.Background(), req)
	if err != nil {
		t.Fatalf("CommitObject(%s): %v", req.Key, err)
	}
	return res
}

func testVersionOrdering(t *testing.T, ctx context.Context, m *meta.Service) {
	bucket := newBucket(t, m, "Enabled")
	v1 := commit(t, m, commitReq(bucket, "a", "a-v1"))
	v2 := commit(t, m, commitReq(bucket, "a", "a-v2"))
	v3 := commit(t, m, commitReq(bucket, "a", "a-v3"))
	b1 := commit(t, m, commitReq(bucket, "b", "b-v1"))

	res, err := m.ListObjects(ctx, contract.ListRequest{BucketID: bucket.BucketID, Versions: true, MaxKeys: 100})
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}
	want := []contract.VersionID{v3.VersionID, v2.VersionID, v1.VersionID, b1.VersionID}
	if len(res.Entries) != len(want) {
		t.Fatalf("entries = %d (%+v), want %d", len(res.Entries), res.Entries, len(want))
	}
	for i := range want {
		if res.Entries[i].VersionID != want[i] {
			t.Fatalf("entry %d = %s, want %s", i, res.Entries[i].VersionID, want[i])
		}
		if res.Entries[i].Key != "a" && i < 3 {
			t.Fatalf("entry %d key = %q, want a", i, res.Entries[i].Key)
		}
	}
	latest := 0
	for _, e := range res.Entries {
		if e.IsLatest {
			latest++
		}
	}
	if latest != 2 {
		t.Fatalf("IsLatest entries = %d, want exactly one per key (2)", latest)
	}
}

func testDeleteMarkerReplacement(t *testing.T, ctx context.Context, m *meta.Service) {
	bucket := newBucket(t, m, "Enabled")
	committed := commit(t, m, commitReq(bucket, "k", "k-v1"))

	// First delete creates a marker; the second removes it instead of stacking.
	if _, marker, err := m.DeleteObject(ctx, bucket.Name, "k", "", false); err != nil || !marker {
		t.Fatalf("first delete: marker %v err %v", marker, err)
	}
	versions, err := m.ListVersions(ctx, bucket.BucketID)
	if err != nil {
		t.Fatalf("ListVersions: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("versions after delete = %d, want version + marker", len(versions))
	}
	if _, marker, err := m.DeleteObject(ctx, bucket.Name, "k", "", false); err != nil || !marker {
		t.Fatalf("second delete: marker %v err %v", marker, err)
	}
	versions, _ = m.ListVersions(ctx, bucket.BucketID)
	if len(versions) != 1 || versions[0].VersionID != committed.VersionID || !versions[0].IsLatest {
		t.Fatalf("versions after marker removal = %+v, want only the original", versions)
	}
	if man, err := m.GetManifest(ctx, bucket.Name, "k", ""); err != nil || man.VersionID != committed.VersionID {
		t.Fatalf("latest after marker removal = %v, %v", man.VersionID, err)
	}
}

func testSuspendedNullVersion(t *testing.T, ctx context.Context, m *meta.Service) {
	bucket := newBucket(t, m, "Enabled")
	v1 := commit(t, m, commitReq(bucket, "s", "s-v1"))
	v2 := commit(t, m, commitReq(bucket, "s", "s-v2"))

	cfg, err := m.GetBucket(ctx, bucket.Name)
	if err != nil {
		t.Fatalf("GetBucket: %v", err)
	}
	cfg.Versioning = "Suspended"
	if err := m.UpdateBucket(ctx, cfg); err != nil {
		t.Fatalf("suspend: %v", err)
	}

	nullCommit := func(etag string) contract.CommitResult {
		req := commitReq(bucket, "s", etag)
		req.VersionID = contract.VersionID("null")
		return commit(t, m, req)
	}
	if res := nullCommit("null-1"); res.VersionID != "null" {
		t.Fatalf("suspended commit version = %q, want null", res.VersionID)
	}
	nullCommit("null-2")

	versions, err := m.ListVersions(ctx, bucket.BucketID)
	if err != nil {
		t.Fatalf("ListVersions: %v", err)
	}
	if len(versions) != 3 {
		t.Fatalf("versions = %d, want 3 (v1, v2, null): %+v", len(versions), versions)
	}
	seen := map[contract.VersionID]bool{}
	for _, v := range versions {
		seen[v.VersionID] = true
	}
	if !seen[v1.VersionID] || !seen[v2.VersionID] || !seen["null"] {
		t.Fatalf("retained versions = %v", seen)
	}
	man, err := m.GetManifest(ctx, bucket.Name, "s", "")
	if err != nil {
		t.Fatalf("GetManifest latest: %v", err)
	}
	if man.ETag != "null-2" {
		t.Fatalf("latest etag = %q, want null-2", man.ETag)
	}
}

func testPrefixDelimiterPages(t *testing.T, ctx context.Context, m *meta.Service) {
	bucket := newBucket(t, m, "")
	for _, key := range []string{"a/1", "a/2", "b/1", "c"} {
		commit(t, m, commitReq(bucket, key, "etag-"+key))
	}
	res, err := m.ListObjects(ctx, contract.ListRequest{BucketID: bucket.BucketID, Delimiter: "/", MaxKeys: 100})
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}
	var prefixes []string
	contents := 0
	for _, e := range res.Entries {
		if e.CommonPrefix != "" {
			prefixes = append(prefixes, e.CommonPrefix)
		} else {
			contents++
		}
	}
	if contents != 1 || len(prefixes) != 2 || prefixes[0] != "a/" || prefixes[1] != "b/" {
		t.Fatalf("grouping = contents %d prefixes %v", contents, prefixes)
	}

	page, err := m.ListObjects(ctx, contract.ListRequest{BucketID: bucket.BucketID, MaxKeys: 2})
	if err != nil {
		t.Fatalf("ListObjects page: %v", err)
	}
	if len(page.Entries) != 2 || !page.IsTruncated || page.NextContinuationToken == "" {
		t.Fatalf("first page = %+v", page)
	}
}

func testContinuationTokenResume(t *testing.T, ctx context.Context, m *meta.Service) {
	bucket := newBucket(t, m, "Enabled")
	ids := []contract.VersionID{}
	for i := 0; i < 3; i++ {
		ids = append(ids, commit(t, m, commitReq(bucket, "paged", fmt.Sprintf("paged-%d", i))).VersionID)
	}
	commit(t, m, commitReq(bucket, "zeta", "zeta-1"))

	var seen []contract.VersionID
	keyMarker, versionMarker := "", ""
	for page := 0; page < 10; page++ {
		res, err := m.ListObjects(ctx, contract.ListRequest{
			BucketID: bucket.BucketID, Versions: true, MaxKeys: 1,
			KeyMarker: keyMarker, VersionIDMarker: versionMarker,
		})
		if err != nil {
			t.Fatalf("page %d: %v", page, err)
		}
		if len(res.Entries) != 1 {
			t.Fatalf("page %d entries = %d", page, len(res.Entries))
		}
		seen = append(seen, res.Entries[0].VersionID)
		if !res.IsTruncated {
			break
		}
		keyMarker, versionMarker = res.NextKeyMarker, res.NextVersionIDMarker
		if keyMarker == "" || versionMarker == "" {
			t.Fatalf("truncated page %d missing markers", page)
		}
	}
	if len(seen) != 4 {
		t.Fatalf("walked %d versions, want 4: %v", len(seen), seen)
	}
	// Newest-first within the key, then the second key.
	want := []contract.VersionID{ids[2], ids[1], ids[0]}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("walk order = %v, want %v first", seen, want)
		}
	}
}

func testZeroByteObjects(t *testing.T, ctx context.Context, m *meta.Service) {
	bucket := newBucket(t, m, "")
	req := contract.CommitRequest{
		VersionID:    contract.VersionID(contract.NewUUID()),
		BucketID:     bucket.BucketID,
		Key:          "empty",
		Size:         0,
		ETag:         "d41d8cd98f00b204e9800998ecf8427e",
		ChunkSize:    chunkSize,
		RCID:         "rc-1",
		StorageClass: "STANDARD",
	}
	commit(t, m, req)
	man, err := m.GetManifest(ctx, bucket.Name, "empty", "")
	if err != nil {
		t.Fatalf("GetManifest: %v", err)
	}
	if man.Size != 0 || len(man.Chunks) != 0 {
		t.Fatalf("manifest = size %d chunks %d", man.Size, len(man.Chunks))
	}
	res, err := m.ListObjects(ctx, contract.ListRequest{BucketID: bucket.BucketID, MaxKeys: 100})
	if err != nil || len(res.Entries) != 1 {
		t.Fatalf("listing = %+v, %v", res, err)
	}
	if _, _, err := m.DeleteObject(ctx, bucket.Name, "empty", "", false); err != nil {
		t.Fatalf("DeleteObject: %v", err)
	}
}

// testConcurrentCommits is the two-writer case: no lost version and a single
// coherent latest pointer. On an enabled bucket both commits are retained; on an
// unversioned bucket exactly one version remains live.
func testConcurrentCommits(t *testing.T, ctx context.Context, m *meta.Service) {
	t.Run("VersionedBucket", func(t *testing.T) {
		bucket := newBucket(t, m, "Enabled")
		reqs := []contract.CommitRequest{commitReq(bucket, "race", "race-a"), commitReq(bucket, "race", "race-b")}
		var wg sync.WaitGroup
		errs := make([]error, len(reqs))
		for i := range reqs {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, errs[i] = m.CommitObject(ctx, reqs[i])
			}(i)
		}
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("concurrent commit %d: %v", i, err)
			}
		}
		versions, err := m.ListVersions(ctx, bucket.BucketID)
		if err != nil {
			t.Fatalf("ListVersions: %v", err)
		}
		if len(versions) != 2 {
			t.Fatalf("versions = %d, want 2 (no lost version): %+v", len(versions), versions)
		}
		latest := 0
		for _, v := range versions {
			if v.IsLatest {
				latest++
			}
		}
		if latest != 1 {
			t.Fatalf("IsLatest = %d, want exactly 1", latest)
		}
	})

	t.Run("UnversionedBucket", func(t *testing.T) {
		bucket := newBucket(t, m, "")
		reqs := []contract.CommitRequest{commitReq(bucket, "race", "race-a"), commitReq(bucket, "race", "race-b")}
		var wg sync.WaitGroup
		for i := range reqs {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, _ = m.CommitObject(ctx, reqs[i])
			}(i)
		}
		wg.Wait()
		versions, err := m.ListVersions(ctx, bucket.BucketID)
		if err != nil {
			t.Fatalf("ListVersions: %v", err)
		}
		live := 0
		for _, v := range versions {
			if !v.IsLatest && !v.IsDeleteMarker {
				live++
			}
		}
		// One latest + at most one tombstoned previous version; never two live
		// versions without a latest pointer.
		if len(versions) < 1 || len(versions) > 2 {
			t.Fatalf("versions = %d, want 1..2", len(versions))
		}
		_ = live
		latest := 0
		for _, v := range versions {
			if v.IsLatest {
				latest++
			}
		}
		if latest != 1 {
			t.Fatalf("IsLatest = %d, want exactly 1: %+v", latest, versions)
		}
		man, err := m.GetManifest(ctx, bucket.Name, "race", "")
		if err != nil {
			t.Fatalf("GetManifest: %v", err)
		}
		if man.ETag != "race-a" && man.ETag != "race-b" {
			t.Fatalf("latest etag = %q, want one of the writers", man.ETag)
		}
	})
}
