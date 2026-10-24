package s3_test

import (
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/gateway/authz"
	"github.com/fass-storage/fass/internal/gateway/offloader"
)

// ---------------------------------------------------------------------------
// Fake coordinator
// ---------------------------------------------------------------------------

type fakeCoord struct {
	mu        sync.Mutex
	buckets   map[string]contract.BucketConfig
	manifests map[string]contract.Manifest  // version id -> manifest
	latest    map[string]contract.VersionID // bucket\x00key -> version
	contents  map[string][]byte             // version id -> payload
	acls      map[string]contract.ACL
	tags      map[string]map[string]string
	retention map[string]*contract.Retention
	lifecycle map[string][]byte
	uploads   map[contract.UploadID]*fakeUpload
	nextID    int
}

type fakeUpload struct {
	bucket string
	key    string
	parts  map[int]contract.PartInfo
}

func newFakeCoord() *fakeCoord {
	return &fakeCoord{
		buckets:   make(map[string]contract.BucketConfig),
		manifests: make(map[string]contract.Manifest),
		latest:    make(map[string]contract.VersionID),
		contents:  make(map[string][]byte),
		acls:      make(map[string]contract.ACL),
		tags:      make(map[string]map[string]string),
		retention: make(map[string]*contract.Retention),
		lifecycle: make(map[string][]byte),
		uploads:   make(map[contract.UploadID]*fakeUpload),
	}
}

func (f *fakeCoord) VerifySignature(ctx context.Context, accessKeyID string) (contract.Principal, []byte, error) {
	return contract.Principal{AccessKeyID: accessKeyID, TenantID: "t1", ProjectID: "p1"}, []byte("secret"), nil
}

func (f *fakeCoord) Authorize(ctx context.Context, rc contract.RequestContext) (contract.Decision, error) {
	return contract.Decision{Allowed: true}, nil
}

func (f *fakeCoord) GetBucket(ctx context.Context, bucket string) (contract.BucketConfig, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.buckets[bucket]
	if !ok {
		return contract.BucketConfig{}, fmt.Errorf("bucket: %w", contract.ErrNotFound)
	}
	return b, nil
}

func (f *fakeCoord) CreateBucket(ctx context.Context, b contract.BucketConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.buckets[b.Name]; ok {
		return fmt.Errorf("bucket: %w", contract.ErrAlreadyExists)
	}
	if b.BucketID == "" {
		f.nextID++
		b.BucketID = contract.BucketID(fmt.Sprintf("bucket-%d", f.nextID))
	}
	if b.Region == "" {
		b.Region = "eu-west-1"
	}
	if b.Ownership == "" {
		b.Ownership = "ObjectWriter"
	}
	f.buckets[b.Name] = b
	return nil
}

func (f *fakeCoord) UpdateBucketConfig(ctx context.Context, b contract.BucketConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.buckets[b.Name]; !ok {
		return contract.ErrNotFound
	}
	f.buckets[b.Name] = b
	return nil
}

func (f *fakeCoord) DeleteBucket(ctx context.Context, bucket string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.buckets[bucket]; !ok {
		return contract.ErrNotFound
	}
	bucketID := string(f.buckets[bucket].BucketID) + "\x00"
	for k := range f.latest {
		if strings.HasPrefix(k, bucketID) {
			return contract.ErrConflict
		}
	}
	delete(f.buckets, bucket)
	return nil
}

func (f *fakeCoord) ListBuckets(ctx context.Context, p contract.Principal) ([]contract.BucketConfig, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []contract.BucketConfig
	for _, b := range f.buckets {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (f *fakeCoord) GetBucketACL(ctx context.Context, bucket string) (contract.ACL, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if acl, ok := f.acls["bucket:"+bucket]; ok {
		return acl, nil
	}
	return contract.ACL{}, contract.ErrNotFound
}

func (f *fakeCoord) PutBucketACL(ctx context.Context, bucket string, acl contract.ACL) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acls["bucket:"+bucket] = acl
	return nil
}

func (f *fakeCoord) GetBucketLifecycle(ctx context.Context, bucket string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, ok := f.lifecycle[bucket]
	if !ok {
		return nil, contract.ErrNotFound
	}
	return body, nil
}

func (f *fakeCoord) PutBucketLifecycle(ctx context.Context, bucket string, xml []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lifecycle[bucket] = xml
	return nil
}

func (f *fakeCoord) DeleteBucketLifecycle(ctx context.Context, bucket string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.lifecycle, bucket)
	return nil
}

func (f *fakeCoord) ResolvePlacement(ctx context.Context, req contract.PlacementRequest) (contract.Placement, error) {
	return contract.Placement{ShardSetID: req.ShardSetID, RingID: "ring-1", Generation: 1}, nil
}

func (f *fakeCoord) CommitObject(ctx context.Context, req contract.CommitRequest) (contract.CommitResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := contract.Manifest{
		TenantID:    "t1",
		ProjectID:   "p1",
		BucketID:    req.BucketID,
		Key:         req.Key,
		VersionID:   req.VersionID,
		Size:        req.Size,
		ETag:        req.ETag,
		ChunkSize:   req.ChunkSize,
		Chunks:      req.Chunks,
		Encryption:  req.Encryption,
		ContentType: req.ContentType,
		UserMeta:    req.UserMeta,
		Tags:        req.Tags,
		CreatedAt:   nowUTC(),
		RCID:        req.RCID,
		Retention:   req.Retention,
	}
	if m.VersionID == "" {
		f.nextID++
		m.VersionID = contract.VersionID(fmt.Sprintf("v-%d", f.nextID))
	}
	f.manifests[string(m.VersionID)] = m
	f.latest[string(req.BucketID)+"\x00"+req.Key] = m.VersionID
	return contract.CommitResult{VersionID: m.VersionID, ETag: req.ETag}, nil
}

func (f *fakeCoord) GetManifest(ctx context.Context, bucket, key string, version contract.VersionID) (contract.Manifest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.buckets[bucket]
	if !ok {
		return contract.Manifest{}, contract.ErrNotFound
	}
	if version == "" {
		version = f.latest[string(b.BucketID)+"\x00"+key]
	}
	m, ok := f.manifests[string(version)]
	if !ok {
		return contract.Manifest{}, contract.ErrNotFound
	}
	return m, nil
}

func (f *fakeCoord) DeleteObject(ctx context.Context, bucket, key string, version contract.VersionID, bypass bool) (contract.VersionID, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.buckets[bucket]
	if !ok {
		return "", false, contract.ErrNotFound
	}
	id := string(b.BucketID) + "\x00" + key
	v, ok := f.latest[id]
	if !ok {
		return "", false, contract.ErrNotFound
	}
	if version != "" {
		v = version
		delete(f.manifests, string(v))
		if f.latest[id] == version {
			delete(f.latest, id)
		}
		return v, false, nil
	}
	delete(f.latest, id)
	marker := b.Versioning == "Enabled"
	return v, marker, nil
}

func (f *fakeCoord) ListObjects(ctx context.Context, req contract.ListRequest) (contract.ListResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	prefix := string(req.BucketID) + "\x00"
	type entry struct {
		key string
		m   contract.Manifest
	}
	var entries []entry
	seen := make(map[string]bool)
	for id, version := range f.latest {
		if !strings.HasPrefix(id, prefix) {
			continue
		}
		key := strings.TrimPrefix(id, prefix)
		if !strings.HasPrefix(key, req.Prefix) || seen[key] {
			continue
		}
		seen[key] = true
		entries = append(entries, entry{key: key, m: f.manifests[string(version)]})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })

	start := req.StartAfter
	if req.ContinuationToken != "" {
		start = req.ContinuationToken
	}
	max := req.MaxKeys
	if max <= 0 {
		max = 1000
	}
	var res contract.ListResult
	commonSeen := make(map[string]bool)
	for _, e := range entries {
		if start != "" && e.key <= start {
			continue
		}
		if req.Delimiter != "" {
			rest := strings.TrimPrefix(e.key, req.Prefix)
			if i := strings.Index(rest, req.Delimiter); i >= 0 {
				cp := req.Prefix + rest[:i+len(req.Delimiter)]
				if commonSeen[cp] {
					continue
				}
				commonSeen[cp] = true
				res.Entries = append(res.Entries, contract.ObjectEntry{CommonPrefix: cp})
				continue
			}
		}
		res.Entries = append(res.Entries, contract.ObjectEntry{
			Key:          e.key,
			Size:         e.m.Size,
			ETag:         e.m.ETag,
			LastModified: e.m.CreatedAt,
			VersionID:    e.m.VersionID,
			IsLatest:     true,
		})
	}
	if len(res.Entries) > max {
		res.Entries = res.Entries[:max]
		res.IsTruncated = true
		last := res.Entries[len(res.Entries)-1]
		if last.CommonPrefix != "" {
			res.NextContinuationToken = last.CommonPrefix
		} else {
			res.NextContinuationToken = last.Key
		}
	}
	res.KeyCount = len(res.Entries)
	return res, nil
}

func (f *fakeCoord) CreateUpload(ctx context.Context, bucket, key string, meta contract.CommitRequest) (contract.UploadID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	id := contract.UploadID(fmt.Sprintf("upload-%d", f.nextID))
	f.uploads[id] = &fakeUpload{bucket: bucket, key: key, parts: make(map[int]contract.PartInfo)}
	return id, nil
}

func (f *fakeCoord) CommitPart(ctx context.Context, up contract.UploadID, partNumber int, etag string, size int64, chunks []contract.ChunkRef, enc contract.EncryptionMeta) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.uploads[up]
	if !ok {
		return contract.ErrNotFound
	}
	u.parts[partNumber] = contract.PartInfo{PartNumber: partNumber, ETag: etag, Size: size, Chunks: chunks, Encryption: enc}
	return nil
}

func (f *fakeCoord) ListParts(ctx context.Context, up contract.UploadID) ([]contract.PartInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.uploads[up]
	if !ok {
		return nil, contract.ErrNotFound
	}
	out := make([]contract.PartInfo, 0, len(u.parts))
	for _, p := range u.parts {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PartNumber < out[j].PartNumber })
	return out, nil
}

func (f *fakeCoord) ListUploads(ctx context.Context, bucketID contract.BucketID) ([]contract.UploadInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []contract.UploadInfo
	for id, u := range f.uploads {
		out = append(out, contract.UploadInfo{UploadID: id, BucketID: bucketID, Key: u.key, Initiated: nowUTC(), StorageClass: "STANDARD"})
	}
	return out, nil
}

func (f *fakeCoord) CompleteUpload(ctx context.Context, up contract.UploadID) (contract.CommitResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.uploads[up]
	if !ok {
		return contract.CommitResult{}, contract.ErrNotFound
	}
	f.nextID++
	version := contract.VersionID(fmt.Sprintf("v-%d", f.nextID))
	b := f.buckets[u.bucket]
	m := contract.Manifest{
		TenantID: "t1", ProjectID: "p1", BucketID: b.BucketID, Key: u.key,
		VersionID: version, Size: 3, ETag: "multipart-etag-2", CreatedAt: nowUTC(),
	}
	f.manifests[string(version)] = m
	f.latest[string(b.BucketID)+"\x00"+u.key] = version
	delete(f.uploads, up)
	return contract.CommitResult{VersionID: version, ETag: m.ETag}, nil
}

func (f *fakeCoord) AbortUpload(ctx context.Context, up contract.UploadID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.uploads[up]; !ok {
		return contract.ErrNotFound
	}
	delete(f.uploads, up)
	return nil
}

func (f *fakeCoord) GetObjectTags(ctx context.Context, bucket, key string, v contract.VersionID) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	tags, ok := f.tags[tagKey(bucket, key, v)]
	if !ok {
		return nil, contract.ErrNotFound
	}
	return tags, nil
}

func (f *fakeCoord) PutObjectTags(ctx context.Context, bucket, key string, v contract.VersionID, tags map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tags[tagKey(bucket, key, v)] = tags
	return nil
}

func (f *fakeCoord) GetObjectRetention(ctx context.Context, bucket, key string, v contract.VersionID) (*contract.Retention, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.retention[tagKey(bucket, key, v)]
	if !ok {
		return nil, contract.ErrNotFound
	}
	return r, nil
}

func (f *fakeCoord) PutObjectRetention(ctx context.Context, bucket, key string, v contract.VersionID, r *contract.Retention) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.retention[tagKey(bucket, key, v)] = r
	return nil
}

func (f *fakeCoord) GetObjectACL(ctx context.Context, bucket, key string, v contract.VersionID) (contract.ACL, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	acl, ok := f.acls["object:"+bucket+"/"+key]
	if !ok {
		return contract.ACL{}, contract.ErrNotFound
	}
	return acl, nil
}

func (f *fakeCoord) PutObjectACL(ctx context.Context, bucket, key string, v contract.VersionID, acl contract.ACL) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acls["object:"+bucket+"/"+key] = acl
	return nil
}

func (f *fakeCoord) Announce(ctx context.Context, a contract.AnnounceRequest) (contract.AnnounceResult, error) {
	return contract.AnnounceResult{}, contract.ErrNotImplemented
}
func (f *fakeCoord) Heartbeat(ctx context.Context, hb contract.Heartbeat) error {
	return contract.ErrNotImplemented
}
func (f *fakeCoord) ReportShardStatus(ctx context.Context, r []contract.ShardStatus) error {
	return contract.ErrNotImplemented
}
func (f *fakeCoord) ClaimRepairJob(ctx context.Context, worker string) (*contract.RepairJob, error) {
	return nil, contract.ErrNotImplemented
}
func (f *fakeCoord) CommitRepair(ctx context.Context, r contract.RepairResult) error {
	return contract.ErrNotImplemented
}

func tagKey(bucket, key string, v contract.VersionID) string {
	return bucket + "\x00" + key + "\x00" + string(v)
}

// ---------------------------------------------------------------------------
// Fake offloader
// ---------------------------------------------------------------------------

type fakeOffloader struct {
	coord *fakeCoord
	mu    sync.Mutex
	next  int
	// failWrites makes Write fail for tests.
	failWrites error
}

func (o *fakeOffloader) Write(ctx context.Context, spec offloader.ObjectSpec, body io.Reader) (contract.CommitResult, error) {
	if o.failWrites != nil {
		return contract.CommitResult{}, o.failWrites
	}
	data, err := io.ReadAll(body)
	if err != nil {
		return contract.CommitResult{}, err
	}
	sum := md5.Sum(data)
	if spec.IfMatch != "" || spec.IfNoneMatch != "" {
		if err := o.checkCondition(ctx, spec); err != nil {
			return contract.CommitResult{}, err
		}
	}
	etag := fmt.Sprintf("%x", sum[:])
	version := spec.VersionID
	if version == "" {
		o.mu.Lock()
		o.next++
		version = contract.VersionID(fmt.Sprintf("auto-%d", o.next))
		o.mu.Unlock()
	}
	req := contract.CommitRequest{
		VersionID:    version,
		BucketID:     spec.BucketID,
		Key:          spec.Key,
		Size:         int64(len(data)),
		ETag:         etag,
		ChunkSize:    spec.ChunkSize,
		Encryption:   contract.EncryptionMeta{Mode: "single-key"},
		ContentType:  spec.ContentType,
		UserMeta:     spec.UserMeta,
		Tags:         spec.Tags,
		RCID:         spec.RCID,
		StorageClass: spec.StorageClass,
		Retention:    spec.Retention,
	}
	// The fake coordinator indexes latest objects by bucket id; resolve it.
	b, err := o.coord.GetBucket(ctx, spec.Bucket)
	if err != nil {
		return contract.CommitResult{}, err
	}
	req.BucketID = b.BucketID
	res, err := o.coord.CommitObject(ctx, req)
	if err != nil {
		return contract.CommitResult{}, err
	}
	o.coord.mu.Lock()
	o.coord.contents[string(res.VersionID)] = data
	o.coord.mu.Unlock()
	return res, nil
}

func (o *fakeOffloader) WritePart(ctx context.Context, spec offloader.ObjectSpec, uploadID contract.UploadID, partNumber int, body io.Reader) (offloader.PartRef, error) {
	data, err := io.ReadAll(body)
	if err != nil {
		return offloader.PartRef{}, err
	}
	sum := md5.Sum(data)
	return offloader.PartRef{
		ETag:       fmt.Sprintf("%x", sum[:]),
		Size:       int64(len(data)),
		Chunks:     []contract.ChunkRef{{Index: 0}},
		Encryption: contract.EncryptionMeta{Mode: "single-key"},
	}, nil
}

func (o *fakeOffloader) Read(ctx context.Context, req offloader.ReadRequest, w io.Writer) error {
	o.coord.mu.Lock()
	data, ok := o.coord.contents[string(req.Manifest.VersionID)]
	o.coord.mu.Unlock()
	if !ok {
		return fmt.Errorf("no content for version %s", req.Manifest.VersionID)
	}
	if req.Range != nil {
		start := req.Range.Start
		end := start + req.Range.Length
		if start > int64(len(data)) {
			start = int64(len(data))
		}
		if end > int64(len(data)) {
			end = int64(len(data))
		}
		_, err := w.Write(data[start:end])
		return err
	}
	_, err := w.Write(data)
	return err
}

// ---------------------------------------------------------------------------
// Fake auth
// ---------------------------------------------------------------------------

type fakeAuthn struct {
	anonymous bool
}

func (a fakeAuthn) Authenticate(ctx context.Context, r *http.Request) (authz.Identity, error) {
	if a.anonymous {
		return authz.Identity{Principal: authz.Anonymous(), Anonymous: true}, nil
	}
	return authz.Identity{
		Principal: contract.Principal{AccessKeyID: "AKIATEST", TenantID: "t1", ProjectID: "p1"},
		AccessKey: "AKIATEST",
	}, nil
}

type fakeAuthz struct {
	deny       error
	last       contract.Resource
	lastAction contract.Action
}

func (a *fakeAuthz) Authorize(ctx context.Context, id authz.Identity, action contract.Action, res contract.Resource, cond map[string]string) error {
	a.last, a.lastAction = res, action
	return a.deny
}

func nowUTC() time.Time { return time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC) }

// checkCondition enforces If-Match / If-None-Match for the fake, mirroring what
// the real coordinator does inside CommitObject.
func (o *fakeOffloader) checkCondition(ctx context.Context, spec offloader.ObjectSpec) error {
	o.coord.mu.Lock()
	defer o.coord.mu.Unlock()
	b, ok := o.coord.buckets[spec.Bucket]
	if !ok {
		return contract.ErrNotFound
	}
	version, ok := o.coord.latest[string(b.BucketID)+"\x00"+spec.Key]
	if !ok {
		if spec.IfMatch != "" {
			return contract.ErrPrecondition
		}
		return nil // If-None-Match: * succeeds
	}
	m := o.coord.manifests[string(version)]
	etag := `"` + m.ETag + `"`
	if spec.IfMatch != "" && spec.IfMatch != etag && spec.IfMatch != m.ETag {
		return contract.ErrPrecondition
	}
	if spec.IfNoneMatch == "*" || spec.IfNoneMatch == etag || spec.IfNoneMatch == m.ETag {
		return contract.ErrPrecondition
	}
	return nil
}
