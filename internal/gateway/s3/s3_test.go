package s3_test

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/ec"
	"github.com/fass-storage/fass/internal/gateway/authz"
	"github.com/fass-storage/fass/internal/gateway/s3"
	"github.com/fass-storage/fass/internal/gateway/sigv4"
)

var errAccessDenied = fmt.Errorf("%w: test policy denies", authz.ErrAccessDenied)

type harness struct {
	coord *fakeCoord
	off   *fakeOffloader
	authz *fakeAuthz
	srv   *s3.Server
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	coord := newFakeCoord()
	off := &fakeOffloader{coord: coord}
	az := &fakeAuthz{}
	cfg := s3.Config{
		Region:            "eu-west-1",
		VirtualHostDomain: "s3.test.local",
		Addressing:        s3.AddressingBoth,
		ServerVersion:     "test",
		Limits:            s3.DefaultLimits(),
		Compat:            s3.DefaultCompat(),
		ChunkSize:         4 << 20,
		DefaultParams:     ec.Params{GeoN: 2, GeoK: 1, LocalN: 4, LocalK: 2},
		DefaultRCID:       "rc-default",
	}
	srv := s3.New(s3.Deps{
		Coord:  coord,
		Authn:  fakeAuthn{},
		Authz:  az,
		Off:    off,
		Config: cfg,
		Now:    nowUTC,
	})
	return &harness{coord: coord, off: off, authz: az, srv: srv}
}

func (h *harness) do(t *testing.T, method, target string, body io.Reader, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, body)
	for k, v := range headers {
		if strings.EqualFold(k, "Host") {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.srv.ServeHTTP(rec, req)
	return rec
}

func (h *harness) mustCreateBucket(t *testing.T, name string) {
	t.Helper()
	rec := h.do(t, http.MethodPut, "/"+name, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("create bucket %s: status %d body %s", name, rec.Code, rec.Body.String())
	}
}

func mustContain(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Fatalf("response does not contain %q\nbody: %s", want, got)
	}
}

func TestListBucketsXML(t *testing.T) {
	h := newHarness(t)
	if err := h.coord.CreateBucket(t.Context(), bucketCfg("alpha")); err != nil {
		t.Fatal(err)
	}
	if err := h.coord.CreateBucket(t.Context(), bucketCfg("beta")); err != nil {
		t.Fatal(err)
	}

	rec := h.do(t, http.MethodGet, "/", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("x-amz-request-id") == "" {
		t.Error("missing x-amz-request-id")
	}
	body := rec.Body.String()
	mustContain(t, body, `<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	mustContain(t, body, `<Name>alpha</Name>`)
	mustContain(t, body, `<Name>beta</Name>`)
	mustContain(t, body, `<Owner><ID>p1</ID>`)

	var doc struct {
		Buckets []struct {
			Name string `xml:"Name"`
		} `xml:"Buckets>Bucket"`
	}
	if err := xml.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Buckets) != 2 || doc.Buckets[0].Name != "alpha" || doc.Buckets[1].Name != "beta" {
		t.Fatalf("buckets = %+v", doc.Buckets)
	}
}

func bucketCfg(name string) contract.BucketConfig {
	return contract.BucketConfig{Name: name, TenantID: "t1", ProjectID: "p1", Region: "eu-west-1"}
}

func TestBucketLifecycleAndErrors(t *testing.T) {
	h := newHarness(t)

	// Create.
	rec := h.do(t, http.MethodPut, "/mybucket", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/mybucket" {
		t.Errorf("Location = %q", loc)
	}
	// Idempotent re-create by the owner.
	rec = h.do(t, http.MethodPut, "/mybucket", nil, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("re-create: %d", rec.Code)
	}
	mustContain(t, rec.Body.String(), "<Code>BucketAlreadyOwnedByYou</Code>")

	// HeadBucket.
	rec = h.do(t, http.MethodHead, "/mybucket", nil, nil)
	if rec.Code != http.StatusOK || rec.Header().Get("x-amz-bucket-region") != "eu-west-1" {
		t.Fatalf("head: %d %v", rec.Code, rec.Header())
	}

	// Location.
	rec = h.do(t, http.MethodGet, "/mybucket?location", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("location: %d", rec.Code)
	}
	mustContain(t, rec.Body.String(), `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">eu-west-1</LocationConstraint>`)

	// Missing bucket: exact error envelope.
	rec = h.do(t, http.MethodGet, "/nobucket?location", nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing bucket: %d", rec.Code)
	}
	body := rec.Body.String()
	mustContain(t, body, `<?xml version="1.0" encoding="UTF-8"?>`)
	mustContain(t, body, `<Error><Code>NoSuchBucket</Code>`)
	mustContain(t, body, "<Message>The specified bucket does not exist.</Message>")
	mustContain(t, body, "<RequestId>")

	// Invalid bucket name.
	rec = h.do(t, http.MethodPut, "/Bad_Name", nil, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid name: %d", rec.Code)
	}
	mustContain(t, rec.Body.String(), "<Code>InvalidBucketName</Code>")

	// Non-empty bucket cannot be deleted.
	rec = h.do(t, http.MethodPut, "/mybucket/key1", strings.NewReader("x"), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	rec = h.do(t, http.MethodDelete, "/mybucket", nil, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("delete non-empty: %d %s", rec.Code, rec.Body.String())
	}
	mustContain(t, rec.Body.String(), "<Code>BucketNotEmpty</Code>")

	// Delete an empty bucket.
	h.mustCreateBucket(t, "empty")
	rec = h.do(t, http.MethodDelete, "/empty", nil, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete bucket: %d", rec.Code)
	}
}

func TestObjectRoundTripRangeAndConditions(t *testing.T) {
	h := newHarness(t)
	h.mustCreateBucket(t, "bkt")
	payload := "hello world"
	rec := h.do(t, http.MethodPut, "/bkt/greeting.txt", strings.NewReader(payload), map[string]string{
		"Content-Type":     "text/plain",
		"x-amz-meta-owner": "gateway-dev",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	const etag = `"5eb63bbbe01eeed093cb22bb8f5acdc3"`
	if got := rec.Header().Get("ETag"); got != etag {
		t.Fatalf("ETag = %q, want %q", got, etag)
	}

	rec = h.do(t, http.MethodGet, "/bkt/greeting.txt", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: %d %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != payload {
		t.Fatalf("body = %q", rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "text/plain" {
		t.Errorf("Content-Type = %q", rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("x-amz-meta-owner") != "gateway-dev" {
		t.Errorf("metadata = %q", rec.Header().Get("x-amz-meta-owner"))
	}
	if rec.Header().Get("Accept-Ranges") != "bytes" {
		t.Errorf("Accept-Ranges = %q", rec.Header().Get("Accept-Ranges"))
	}

	// HEAD must not return a body.
	rec = h.do(t, http.MethodHead, "/bkt/greeting.txt", nil, nil)
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatalf("head: %d body %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Length") != "11" {
		t.Errorf("Content-Length = %q", rec.Header().Get("Content-Length"))
	}

	// Range: 0-4 → "hello", 206 with Content-Range.
	rec = h.do(t, http.MethodGet, "/bkt/greeting.txt", nil, map[string]string{"Range": "bytes=0-4"})
	if rec.Code != http.StatusPartialContent {
		t.Fatalf("range: %d", rec.Code)
	}
	if rec.Body.String() != "hello" {
		t.Fatalf("range body = %q", rec.Body.String())
	}
	if rec.Header().Get("Content-Range") != "bytes 0-4/11" {
		t.Errorf("Content-Range = %q", rec.Header().Get("Content-Range"))
	}
	// Suffix range.
	rec = h.do(t, http.MethodGet, "/bkt/greeting.txt", nil, map[string]string{"Range": "bytes=-5"})
	if rec.Code != http.StatusPartialContent || rec.Body.String() != "world" {
		t.Fatalf("suffix range: %d %q", rec.Code, rec.Body.String())
	}
	// Unsatisfiable range.
	rec = h.do(t, http.MethodGet, "/bkt/greeting.txt", nil, map[string]string{"Range": "bytes=100-200"})
	if rec.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("bad range: %d", rec.Code)
	}
	if rec.Header().Get("Content-Range") != "bytes */11" {
		t.Errorf("416 Content-Range = %q", rec.Header().Get("Content-Range"))
	}

	// Conditional: If-None-Match matches → 304.
	rec = h.do(t, http.MethodGet, "/bkt/greeting.txt", nil, map[string]string{"If-None-Match": etag})
	if rec.Code != http.StatusNotModified {
		t.Fatalf("if-none-match: %d", rec.Code)
	}
	// If-Match mismatch → 412.
	rec = h.do(t, http.MethodPut, "/bkt/greeting.txt", strings.NewReader("new"), map[string]string{"If-Match": `"deadbeef"`})
	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("if-match: %d %s", rec.Code, rec.Body.String())
	}

	// Delete then 404 NoSuchKey.
	rec = h.do(t, http.MethodDelete, "/bkt/greeting.txt", nil, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
	rec = h.do(t, http.MethodGet, "/bkt/greeting.txt", nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get deleted: %d", rec.Code)
	}
	mustContain(t, rec.Body.String(), "<Code>NoSuchKey</Code>")
}

func TestListObjectsV2AndV1(t *testing.T) {
	h := newHarness(t)
	h.mustCreateBucket(t, "bkt")
	for _, key := range []string{"a/one", "a/two", "b/three", "top"} {
		rec := h.do(t, http.MethodPut, "/bkt/"+key, strings.NewReader("12345"), nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("put %s: %d", key, rec.Code)
		}
	}

	rec := h.do(t, http.MethodGet, "/bkt?list-type=2&prefix=a/&delimiter=/", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list v2: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	mustContain(t, body, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	mustContain(t, body, "<KeyCount>2</KeyCount>")
	mustContain(t, body, "<Key>a/one</Key>")
	mustContain(t, body, "<Key>a/two</Key>")
	mustContain(t, body, "<Size>5</Size>")

	var doc struct {
		KeyCount int `xml:"KeyCount"`
		Contents []struct {
			Key  string `xml:"Key"`
			Size int64  `xml:"Size"`
		} `xml:"Contents"`
	}
	if err := xml.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.KeyCount != 2 || len(doc.Contents) != 2 {
		t.Fatalf("v2 doc = %+v", doc)
	}

	// Delimiter grouping.
	rec = h.do(t, http.MethodGet, "/bkt?list-type=2&delimiter=/", nil, nil)
	body = rec.Body.String()
	mustContain(t, body, "<CommonPrefixes><Prefix>a/</Prefix></CommonPrefixes>")
	mustContain(t, body, "<CommonPrefixes><Prefix>b/</Prefix></CommonPrefixes>")
	mustContain(t, body, "<Key>top</Key>")

	// V1 listing.
	rec = h.do(t, http.MethodGet, "/bkt?prefix=top", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list v1: %d", rec.Code)
	}
	mustContain(t, rec.Body.String(), `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	mustContain(t, rec.Body.String(), "<Marker></Marker>")
	mustContain(t, rec.Body.String(), "<Key>top</Key>")

	// max-keys clamps and truncates.
	rec = h.do(t, http.MethodGet, "/bkt?list-type=2&max-keys=1", nil, nil)
	mustContain(t, rec.Body.String(), "<IsTruncated>true</IsTruncated>")
	mustContain(t, rec.Body.String(), "<NextContinuationToken>")
}

func TestDeleteObjects(t *testing.T) {
	h := newHarness(t)
	h.mustCreateBucket(t, "bkt")
	for _, key := range []string{"k1", "k2"} {
		if rec := h.do(t, http.MethodPut, "/bkt/"+key, strings.NewReader("x"), nil); rec.Code != http.StatusOK {
			t.Fatalf("put %s: %d", key, rec.Code)
		}
	}
	body := `<Delete><Object><Key>k1</Key></Object><Object><Key>k2</Key></Object></Delete>`
	rec := h.do(t, http.MethodPost, "/bkt?delete", strings.NewReader(body), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete objects: %d %s", rec.Code, rec.Body.String())
	}
	out := rec.Body.String()
	mustContain(t, out, `<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	mustContain(t, out, "<Deleted><Key>k1</Key></Deleted>")
	mustContain(t, out, "<Deleted><Key>k2</Key></Deleted>")

	// Quiet mode omits successes.
	rec = h.do(t, http.MethodPost, "/bkt?delete", strings.NewReader(
		`<Delete><Object><Key>missing</Key></Object><Quiet>true</Quiet></Delete>`), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("quiet delete: %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "<Deleted>") {
		t.Fatalf("quiet mode returned deletions: %s", rec.Body.String())
	}
}

func TestUnsupportedOperations(t *testing.T) {
	h := newHarness(t)
	h.mustCreateBucket(t, "bkt")
	for _, target := range []string{"/bkt?cors", "/bkt?policy", "/bkt?website", "/bkt?tagging", "/bkt?notification"} {
		rec := h.do(t, http.MethodGet, target, nil, nil)
		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("%s: status = %d, want 501", target, rec.Code)
		}
		mustContain(t, rec.Body.String(), "<Code>NotImplemented</Code>")
	}
	rec := h.do(t, http.MethodPatch, "/bkt", nil, nil)
	if rec.Code != http.StatusMethodNotAllowed && rec.Code != http.StatusNotImplemented {
		t.Fatalf("patch bucket: %d", rec.Code)
	}
}

func TestMultipartFlow(t *testing.T) {
	h := newHarness(t)
	h.mustCreateBucket(t, "bkt")

	rec := h.do(t, http.MethodPost, "/bkt/big.bin?uploads", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("initiate: %d %s", rec.Code, rec.Body.String())
	}
	var initDoc struct {
		Bucket   string `xml:"Bucket"`
		Key      string `xml:"Key"`
		UploadID string `xml:"UploadId"`
	}
	if err := xml.Unmarshal(rec.Body.Bytes(), &initDoc); err != nil || initDoc.UploadID == "" {
		t.Fatalf("initiate xml: %v %s", err, rec.Body.String())
	}
	if initDoc.Bucket != "bkt" || initDoc.Key != "big.bin" {
		t.Fatalf("initiate doc = %+v", initDoc)
	}

	part := bytes.Repeat([]byte("a"), 5<<20) // at the 5 MiB minimum
	rec = h.do(t, http.MethodPut, "/bkt/big.bin?partNumber=1&uploadId="+initDoc.UploadID, bytes.NewReader(part), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload part: %d %s", rec.Code, rec.Body.String())
	}
	partETag := rec.Header().Get("ETag")
	if partETag == "" {
		t.Fatal("missing part ETag")
	}

	rec = h.do(t, http.MethodGet, "/bkt/big.bin?uploadId="+initDoc.UploadID, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list parts: %d", rec.Code)
	}
	mustContain(t, rec.Body.String(), "<PartNumber>1</PartNumber>")
	mustContain(t, rec.Body.String(), "<Size>5242880</Size>")

	complete := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>` +
		strings.ReplaceAll(partETag, `"`, "&quot;") + `</ETag></Part></CompleteMultipartUpload>`
	rec = h.do(t, http.MethodPost, "/bkt/big.bin?uploadId="+initDoc.UploadID, strings.NewReader(complete), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("complete: %d %s", rec.Code, rec.Body.String())
	}
	mustContain(t, rec.Body.String(), "<CompleteMultipartUploadResult")
	mustContain(t, rec.Body.String(), `<ETag>&#34;multipart-etag-2&#34;</ETag>`)

	// After completion the upload is gone.
	rec = h.do(t, http.MethodDelete, "/bkt/big.bin?uploadId="+initDoc.UploadID, nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("abort completed upload: %d", rec.Code)
	}

	// Too-small non-final part is rejected at complete time.
	rec = h.do(t, http.MethodPost, "/bkt/small?uploads", nil, nil)
	var smallInit struct {
		UploadID string `xml:"UploadId"`
	}
	if err := xml.Unmarshal(rec.Body.Bytes(), &smallInit); err != nil || smallInit.UploadID == "" {
		t.Fatalf("init small: %v", err)
	}
	rec = h.do(t, http.MethodPut, "/bkt/small?partNumber=1&uploadId="+smallInit.UploadID, strings.NewReader("tiny"), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload tiny part: %d %s", rec.Code, rec.Body.String())
	}
	tinyETag := rec.Header().Get("ETag")
	rec = h.do(t, http.MethodPut, "/bkt/small?partNumber=2&uploadId="+smallInit.UploadID, strings.NewReader("last"), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload last part: %d", rec.Code)
	}
	lastETag := rec.Header().Get("ETag")
	complete = `<CompleteMultipartUpload>` +
		`<Part><PartNumber>1</PartNumber><ETag>` + tinyETag + `</ETag></Part>` +
		`<Part><PartNumber>2</PartNumber><ETag>` + lastETag + `</ETag></Part>` +
		`</CompleteMultipartUpload>`
	rec = h.do(t, http.MethodPost, "/bkt/small?uploadId="+smallInit.UploadID, strings.NewReader(complete), nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("small part complete: %d %s", rec.Code, rec.Body.String())
	}
	mustContain(t, rec.Body.String(), "<Code>EntityTooSmall</Code>")
}

func TestVersioningTaggingACLAndObjectLock(t *testing.T) {
	h := newHarness(t)
	h.mustCreateBucket(t, "bkt")

	// Versioning.
	rec := h.do(t, http.MethodGet, "/bkt?versioning", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get versioning: %d", rec.Code)
	}
	mustContain(t, rec.Body.String(), `<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	rec = h.do(t, http.MethodPut, "/bkt?versioning",
		strings.NewReader(`<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put versioning: %d %s", rec.Code, rec.Body.String())
	}
	rec = h.do(t, http.MethodGet, "/bkt?versioning", nil, nil)
	mustContain(t, rec.Body.String(), "<Status>Enabled</Status>")

	// Put with tags; version id should be returned now that versioning is on.
	rec = h.do(t, http.MethodPut, "/bkt/k", strings.NewReader("v"), map[string]string{"x-amz-tagging": "colour=blue&env=test"})
	if rec.Code != http.StatusOK {
		t.Fatalf("put tagged: %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("x-amz-version-id") == "" {
		t.Error("missing x-amz-version-id on a versioned bucket")
	}

	// Object tagging round trip.
	rec = h.do(t, http.MethodPut, "/bkt/k?tagging",
		strings.NewReader(`<Tagging><TagSet><Tag><Key>a</Key><Value>1</Value></Tag></TagSet></Tagging>`), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put tagging: %d %s", rec.Code, rec.Body.String())
	}
	rec = h.do(t, http.MethodGet, "/bkt/k?tagging", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get tagging: %d", rec.Code)
	}
	mustContain(t, rec.Body.String(), `<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	mustContain(t, rec.Body.String(), "<Key>a</Key><Value>1</Value>")

	// Bucket ACL default: owner has FULL_CONTROL.
	rec = h.do(t, http.MethodGet, "/bkt?acl", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get acl: %d", rec.Code)
	}
	mustContain(t, rec.Body.String(), "<Permission>FULL_CONTROL</Permission>")
	mustContain(t, rec.Body.String(), `xsi:type="CanonicalUser"`)

	// Switch ownership to BucketOwnerEnforced, then ACL writes are rejected.
	rec = h.do(t, http.MethodPut, "/bkt?ownershipControls",
		strings.NewReader(`<OwnershipControls><Rule><ObjectOwnership>BucketOwnerEnforced</ObjectOwnership></Rule></OwnershipControls>`), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put ownership: %d %s", rec.Code, rec.Body.String())
	}
	rec = h.do(t, http.MethodPut, "/bkt?acl", nil, map[string]string{"x-amz-acl": "public-read"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("acl under enforced ownership: %d", rec.Code)
	}
	mustContain(t, rec.Body.String(), "<Code>AccessControlListNotSupported</Code>")

	// Object lock is not enabled → 404 with the documented code.
	rec = h.do(t, http.MethodGet, "/bkt?object-lock", nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("object-lock: %d", rec.Code)
	}
	mustContain(t, rec.Body.String(), "<Code>ObjectLockConfigurationNotFoundError</Code>")

	// Lifecycle: absent → 404; put → 200; get → raw XML; delete → 204.
	rec = h.do(t, http.MethodGet, "/bkt?lifecycle", nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("lifecycle absent: %d", rec.Code)
	}
	lifecycle := `<LifecycleConfiguration><Rule><ID>expire</ID><Status>Enabled</Status><Expiration><Days>30</Days></Expiration></Rule></LifecycleConfiguration>`
	rec = h.do(t, http.MethodPut, "/bkt?lifecycle", strings.NewReader(lifecycle), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put lifecycle: %d %s", rec.Code, rec.Body.String())
	}
	rec = h.do(t, http.MethodGet, "/bkt?lifecycle", nil, nil)
	if rec.Code != http.StatusOK || rec.Body.String() != lifecycle {
		t.Fatalf("get lifecycle: %d %q", rec.Code, rec.Body.String())
	}
	// Unsupported lifecycle element is rejected.
	bad := `<LifecycleConfiguration><Rule><Status>Enabled</Status><Filter><Prefix>x</Prefix></Filter><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>`
	rec = h.do(t, http.MethodPut, "/bkt?lifecycle", strings.NewReader(bad), nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unsupported lifecycle: %d %s", rec.Code, rec.Body.String())
	}
	rec = h.do(t, http.MethodDelete, "/bkt?lifecycle", nil, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete lifecycle: %d", rec.Code)
	}
}

func TestVirtualHostedAddressing(t *testing.T) {
	h := newHarness(t)
	h.mustCreateBucket(t, "vhbucket")
	rec := h.do(t, http.MethodPut, "/key.txt", strings.NewReader("virtual"), map[string]string{
		"Host": "vhbucket.s3.test.local",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("vhost put: %d %s", rec.Code, rec.Body.String())
	}
	rec = h.do(t, http.MethodGet, "/key.txt", nil, map[string]string{"Host": "vhbucket.s3.test.local"})
	if rec.Code != http.StatusOK || rec.Body.String() != "virtual" {
		t.Fatalf("vhost get: %d %q", rec.Code, rec.Body.String())
	}
	// A non-matching Host falls back to path-style: no bucket.
	rec = h.do(t, http.MethodGet, "/", nil, map[string]string{"Host": "unknown.example.com"})
	if rec.Code != http.StatusOK {
		t.Fatalf("path-style fallback: %d", rec.Code)
	}
}

func TestAnonymousRequestDenied(t *testing.T) {
	h := newHarness(t)
	h.mustCreateBucket(t, "bkt")
	// Rebuild with anonymous authentication and a denying authoriser.
	srv := s3.New(s3.Deps{
		Coord:  h.coord,
		Authn:  fakeAuthn{anonymous: true},
		Authz:  &fakeAuthz{deny: errAccessDenied},
		Off:    h.off,
		Config: s3.Config{Region: "eu-west-1", AllowAnonymous: true, Addressing: s3.AddressingBoth, ServerVersion: "test"},
	})
	req := httptest.NewRequest(http.MethodGet, "/bkt/key", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("anonymous: %d %s", rec.Code, rec.Body.String())
	}
	mustContain(t, rec.Body.String(), "<Code>AccessDenied</Code>")
}

func TestPutRejectsSSECAndBadStorageClass(t *testing.T) {
	h := newHarness(t)
	h.mustCreateBucket(t, "bkt")
	rec := h.do(t, http.MethodPut, "/bkt/k", strings.NewReader("x"), map[string]string{
		"x-amz-server-side-encryption-customer-algorithm": "AES256",
	})
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("sse-c: %d %s", rec.Code, rec.Body.String())
	}
	rec = h.do(t, http.MethodPut, "/bkt/k", strings.NewReader("x"), map[string]string{"x-amz-storage-class": "ARCHIVE"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("storage class: %d", rec.Code)
	}
	mustContain(t, rec.Body.String(), "<Code>InvalidStorageClass</Code>")
}

// TestPutObjectStreamingSignedChunks drives a real STREAMING-AWS4-HMAC-SHA256-
// PAYLOAD body through the complete edge: SigV4 verification, chunked-body
// decoding, the S3 handler and the offloader seam. This is the aws-cli path.
func TestPutObjectStreamingSignedChunks(t *testing.T) {
	coord := newFakeCoord()
	if err := coord.CreateBucket(t.Context(), bucketCfg("streambkt")); err != nil {
		t.Fatal(err)
	}
	off := &fakeOffloader{coord: coord}
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	verifier := authz.New(coord, authz.Options{Now: func() time.Time { return now }})
	srv := s3.New(s3.Deps{
		Coord: coord, Authn: verifier, Authz: verifier, Off: off,
		Config: s3.Config{
			Region: "eu-west-1", Addressing: s3.AddressingBoth, ServerVersion: "test",
			Limits: s3.DefaultLimits(), Compat: s3.DefaultCompat(), ChunkSize: 4 << 20,
		},
		Now: func() time.Time { return now },
	})

	payload := []byte("streamed payload from a chunked-signed client")
	req := httptest.NewRequest(http.MethodPut, "http://s3.test.local/streambkt/streamed.bin", nil)
	if err := sigv4.SignRequest(req, "AKIATEST", "secret", now, sigv4.PayloadStreaming); err != nil {
		t.Fatal(err)
	}
	auth := req.Header.Get("Authorization")
	i := strings.LastIndex(auth, "Signature=")
	if i < 0 {
		t.Fatalf("no signature in %q", auth)
	}
	seed := auth[i+len("Signature="):]

	scope := sigv4.NewScope(now, "eu-west-1", "s3")
	key := sigv4.SigningKey("secret", scope)
	amzDate := now.Format("20060102T150405Z")
	prev := seed
	var body bytes.Buffer
	// Two payload chunks plus the terminating zero chunk.
	for _, part := range [][]byte{payload[:20], payload[20:]} {
		sts := "AWS4-HMAC-SHA256-PAYLOAD\n" + amzDate + "\n" + scope.String() + "\n" +
			prev + "\n" + sigv4.EmptyStringSHA256 + "\n" + sigv4.HashPayload(part)
		sig := sigv4.Sign(key, sts)
		fmt.Fprintf(&body, "%x;chunk-signature=%s\r\n", len(part), sig)
		body.Write(part)
		body.WriteString("\r\n")
		prev = sig
	}
	emptySTS := "AWS4-HMAC-SHA256-PAYLOAD\n" + amzDate + "\n" + scope.String() + "\n" +
		prev + "\n" + sigv4.EmptyStringSHA256 + "\n" + sigv4.EmptyStringSHA256
	fmt.Fprintf(&body, "0;chunk-signature=%s\r\n\r\n", sigv4.Sign(key, emptySTS))

	req.Body = io.NopCloser(bytes.NewReader(body.Bytes()))
	req.ContentLength = int64(body.Len())
	req.Header.Set("x-amz-decoded-content-length", fmt.Sprintf("%d", len(payload)))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("streaming PUT: %d %s", rec.Code, rec.Body.String())
	}

	// The stored object must be the decoded payload.
	getReq := httptest.NewRequest(http.MethodGet, "http://s3.test.local/streambkt/streamed.bin", nil)
	if err := sigv4.SignRequest(getReq, "AKIATEST", "secret", now, sigv4.EmptyStringSHA256); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, getReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET: %d %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != string(payload) {
		t.Fatalf("stored payload = %q, want %q", rec.Body.String(), payload)
	}

	// A tampered chunk signature must be rejected before the object is written.
	bad := bytes.Replace(body.Bytes(), []byte(";chunk-signature="), []byte(";chunk-signature=0"), 1)
	badReq := httptest.NewRequest(http.MethodPut, "http://s3.test.local/streambkt/tampered.bin", nil)
	if err := sigv4.SignRequest(badReq, "AKIATEST", "secret", now, sigv4.PayloadStreaming); err != nil {
		t.Fatal(err)
	}
	badReq.Body = io.NopCloser(bytes.NewReader(bad))
	badReq.ContentLength = int64(len(bad))
	badReq.Header.Set("x-amz-decoded-content-length", fmt.Sprintf("%d", len(payload)))
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, badReq)
	if rec.Code == http.StatusOK {
		t.Fatal("tampered streaming body was accepted")
	}
}
