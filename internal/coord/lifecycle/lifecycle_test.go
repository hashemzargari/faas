package lifecycle_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/coord/lifecycle"
	"github.com/fass-storage/fass/internal/coord/meta"
	"github.com/fass-storage/fass/internal/storage"
)

type fixture struct {
	m   *meta.Service
	now time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	db, err := storage.Open("")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	f := &fixture{m: meta.New(db), now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	f.m.SetClock(func() time.Time { return f.now })
	return f
}

func (f *fixture) bucket(t *testing.T, name string, versioned, objectLock bool) contract.BucketConfig {
	t.Helper()
	cfg := contract.BucketConfig{
		BucketID:  contract.BucketID(contract.NewUUID()),
		Name:      name,
		TenantID:  contract.TenantID("tenant"),
		ProjectID: contract.ProjectID("project"),
		Region:    contract.DefaultRegion,
		Ownership: "ObjectWriter",
	}
	if versioned {
		cfg.Versioning = "Enabled"
	}
	cfg.ObjectLock = objectLock
	if err := f.m.CreateBucket(context.Background(), cfg); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	return cfg
}

func (f *fixture) put(t *testing.T, bucket contract.BucketConfig, key string) contract.VersionID {
	t.Helper()
	versionID := contract.VersionID(contract.NewUUID())
	_, err := f.m.CommitObject(context.Background(), contract.CommitRequest{
		BucketID:  bucket.BucketID,
		Key:       key,
		VersionID: versionID,
		Size:      0,
		ETag:      "etag-" + string(versionID),
	})
	if err != nil {
		t.Fatalf("CommitObject: %v", err)
	}
	return versionID
}

func (f *fixture) lifecycle(t *testing.T, bucket contract.BucketConfig, doc string) {
	t.Helper()
	if err := f.m.PutBucketLifecycle(context.Background(), bucket.Name, []byte(doc)); err != nil {
		t.Fatalf("PutBucketLifecycle: %v", err)
	}
}

func (f *fixture) run(t *testing.T) lifecycle.Result {
	t.Helper()
	exec := lifecycle.New(f.m, lifecycle.Config{Interval: time.Minute, Logger: slog.Default()})
	res, err := exec.RunOnce(context.Background(), f.now)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	return res
}

// TestNoncurrentVersionExpirationSweep: aged non-current versions are tombstoned,
// the current version is untouched, and a second sweep is a no-op.
func TestNoncurrentVersionExpirationSweep(t *testing.T) {
	f := newFixture(t)
	bucket := f.bucket(t, "life", true, false)
	old1 := f.put(t, bucket, "k")
	f.put(t, bucket, "k")
	current := f.put(t, bucket, "k")
	f.lifecycle(t, bucket, `<LifecycleConfiguration><Rule><ID>r</ID><Status>Enabled</Status>`+
		`<NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration></Rule></LifecycleConfiguration>`)

	// Not due yet.
	if res := f.run(t); res.NoncurrentExpired != 0 {
		t.Fatalf("expired before the rule fired: %+v", res)
	}

	f.now = f.now.Add(48 * time.Hour)
	res := f.run(t)
	if res.NoncurrentExpired != 2 {
		t.Fatalf("expired %d versions, want 2 (%+v)", res.NoncurrentExpired, res)
	}
	versions, err := f.m.ListVersions(context.Background(), bucket.BucketID)
	if err != nil {
		t.Fatalf("ListVersions: %v", err)
	}
	if len(versions) != 1 || versions[0].VersionID != current || !versions[0].IsLatest {
		t.Fatalf("live versions = %+v, want only the current one %s", versions, current)
	}
	if _, err := f.m.GetManifest(context.Background(), bucket.Name, "k", old1); err == nil {
		t.Fatalf("expired version %s is still readable", old1)
	}
	if _, err := f.m.GetManifest(context.Background(), bucket.Name, "k", current); err != nil {
		t.Fatalf("current version vanished: %v", err)
	}
	// Idempotent: another sweep expires nothing.
	if res := f.run(t); res.NoncurrentExpired != 0 {
		t.Fatalf("second sweep re-expired versions: %+v", res)
	}
}

// TestLifecycleNeverExpiresLockedVersions: an active retention or legal hold
// protects a non-current version from expiry; once the retention window passes,
// lifecycle may collect it.
func TestLifecycleNeverExpiresLockedVersions(t *testing.T) {
	f := newFixture(t)
	bucket := f.bucket(t, "locked", true, true)
	retained := f.put(t, bucket, "k")
	held := f.put(t, bucket, "h")
	f.put(t, bucket, "k")
	f.put(t, bucket, "h")

	ctx := context.Background()
	until := f.now.Add(72 * time.Hour)
	if err := f.m.PutObjectRetention(ctx, bucket.Name, "k", retained, &contract.Retention{Mode: "COMPLIANCE", RetainUntil: until}); err != nil {
		t.Fatalf("PutObjectRetention: %v", err)
	}
	if err := f.m.PutObjectLegalHold(ctx, bucket.Name, "h", held, true); err != nil {
		t.Fatalf("PutObjectLegalHold: %v", err)
	}
	f.lifecycle(t, bucket, `<LifecycleConfiguration><Rule><ID>r</ID><Status>Enabled</Status>`+
		`<NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration></Rule></LifecycleConfiguration>`)

	f.now = f.now.Add(48 * time.Hour) // aged past the rule, retention still active
	res := f.run(t)
	if res.NoncurrentExpired != 0 || res.Locked != 2 {
		t.Fatalf("sweep = %+v, want 2 locked and 0 expired", res)
	}
	versions, _ := f.m.ListVersions(ctx, bucket.BucketID)
	if len(versions) != 4 {
		t.Fatalf("live versions = %d, want 4 (both protected non-current versions kept)", len(versions))
	}

	// After the retention window, only the COMPLIANCE version becomes eligible;
	// the legal hold never expires.
	f.now = f.now.Add(48 * time.Hour) // 96h total, past the 72h retention
	res = f.run(t)
	if res.NoncurrentExpired != 1 || res.Locked != 1 {
		t.Fatalf("post-retention sweep = %+v, want 1 expired (retention) and 1 locked (hold)", res)
	}
	versions, _ = f.m.ListVersions(ctx, bucket.BucketID)
	ids := map[contract.VersionID]bool{}
	for _, v := range versions {
		ids[v.VersionID] = true
	}
	if ids[retained] {
		t.Fatalf("version past its retention window was not collected")
	}
	if !ids[held] {
		t.Fatalf("legal-held version was expired")
	}
}

// TestExpirationCreatesDeleteMarkerForCurrentVersion: the Expiration rule on a
// versioned bucket hides the object with a delete marker, retaining the version.
func TestExpirationCreatesDeleteMarkerForCurrentVersion(t *testing.T) {
	f := newFixture(t)
	bucket := f.bucket(t, "expiry", true, false)
	f.put(t, bucket, "k")
	f.lifecycle(t, bucket, `<LifecycleConfiguration><Rule><ID>r</ID><Status>Enabled</Status>`+
		`<Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>`)

	f.now = f.now.Add(48 * time.Hour)
	res := f.run(t)
	if res.CurrentExpired != 1 {
		t.Fatalf("sweep = %+v, want 1 current version expired", res)
	}
	versions, _ := f.m.ListVersions(context.Background(), bucket.BucketID)
	markers, live := 0, 0
	for _, v := range versions {
		if v.IsDeleteMarker {
			markers++
		} else {
			live++
		}
	}
	if markers != 1 || live != 1 {
		t.Fatalf("versions after expiry = %d markers / %d live, want 1/1", markers, live)
	}
	// The data-path GET sees the marker (405), i.e. the object is hidden.
	if _, err := f.m.GetManifest(context.Background(), bucket.Name, "k", ""); err == nil {
		t.Fatalf("object still visible after lifecycle expiry")
	}
}

// TestExpiredObjectDeleteMarkerRemoved: a rule with ExpiredObjectDeleteMarker
// removes a delete marker that is the only remaining version of its key.
func TestExpiredObjectDeleteMarkerRemoved(t *testing.T) {
	f := newFixture(t)
	bucket := f.bucket(t, "markers", true, false)
	version := f.put(t, bucket, "k")
	if _, marker, err := f.m.DeleteObject(context.Background(), bucket.Name, "k", "", false); err != nil || !marker {
		t.Fatalf("create delete marker: marker %v err %v", marker, err)
	}
	// Make the delete marker the only remaining version of the key.
	if _, _, err := f.m.DeleteObject(context.Background(), bucket.Name, "k", version, false); err != nil {
		t.Fatalf("delete object version: %v", err)
	}
	f.lifecycle(t, bucket, `<LifecycleConfiguration><Rule><ID>r</ID><Status>Enabled</Status>`+
		`<Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration></Rule></LifecycleConfiguration>`)
	res := f.run(t)
	if res.MarkersExpired != 1 {
		t.Fatalf("sweep = %+v, want 1 delete marker expired", res)
	}
	versions, _ := f.m.ListVersions(context.Background(), bucket.BucketID)
	if len(versions) != 0 {
		t.Fatalf("versions = %+v, want none (orphaned marker removed)", versions)
	}
}

// TestExpirationNeverDeletesLockedCurrentVersion: the Expiration rule must not
// remove a current version that is still under retention or legal hold.
func TestExpirationNeverDeletesLockedCurrentVersion(t *testing.T) {
	f := newFixture(t)
	bucket := f.bucket(t, "expiry-locked", true, true)
	version := f.put(t, bucket, "k")
	ctx := context.Background()
	if err := f.m.PutObjectLegalHold(ctx, bucket.Name, "k", version, true); err != nil {
		t.Fatalf("PutObjectLegalHold: %v", err)
	}
	f.lifecycle(t, bucket, `<LifecycleConfiguration><Rule><ID>r</ID><Status>Enabled</Status>`+
		`<Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>`)
	f.now = f.now.Add(48 * time.Hour)
	res := f.run(t)
	if res.CurrentExpired != 0 || res.Locked != 1 {
		t.Fatalf("sweep = %+v, want 0 expired and 1 locked", res)
	}
	if _, err := f.m.GetManifest(ctx, bucket.Name, "k", ""); err != nil {
		t.Fatalf("locked current version was expired: %v", err)
	}
}
