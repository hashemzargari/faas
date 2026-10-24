package sdk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// newTestClient wires a client to an httptest gateway with a client whose
// transport dials the test server.
func newTestClient(t *testing.T, h http.Handler) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, "eu-west-1", "AKIAEXAMPLE", "secret", WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	return c, srv
}

var authHeaderRE = regexp.MustCompile(
	`^AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/\d{8}/eu-west-1/s3/aws4_request, ` +
		`SignedHeaders=[a-z0-9;-]+, Signature=[0-9a-f]{64}$`)

func TestRequestsAreSigned(t *testing.T) {
	var gotAuth, gotPayloadHash string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPayloadHash = r.Header.Get("X-Amz-Content-Sha256")
		w.Header().Set("Content-Type", "application/xml")
		io.WriteString(w, `<ListAllMyBucketsResult><Buckets></Buckets></ListAllMyBucketsResult>`)
	}))
	if _, err := c.ListBuckets(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !authHeaderRE.MatchString(gotAuth) {
		t.Fatalf("authorization header malformed: %q", gotAuth)
	}
	if gotPayloadHash != emptyPayloadHash {
		t.Fatalf("GET payload hash = %q, want the empty-body hash", gotPayloadHash)
	}
}

func TestPathStyleAndKeyEscaping(t *testing.T) {
	var gotPath string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		w.WriteHeader(200)
	}))
	if err := c.DeleteObject(context.Background(), "my-bucket", "a/b c/d.txt"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/my-bucket/a/b%20c/d.txt" {
		t.Fatalf("path = %q", gotPath)
	}
}

func TestListBucketsParsesXML(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		io.WriteString(w, `<?xml version="1.0"?>
<ListAllMyBucketsResult><Owner><ID>owner</ID></Owner><Buckets>
  <Bucket><Name>alpha</Name><CreationDate>2026-10-24T10:00:00Z</CreationDate></Bucket>
  <Bucket><Name>beta</Name><CreationDate>2026-10-25T11:30:00Z</CreationDate></Bucket>
</Buckets></ListAllMyBucketsResult>`)
	}))
	bs, err := c.ListBuckets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(bs) != 2 || bs[0].Name != "alpha" || bs[1].Name != "beta" {
		t.Fatalf("unexpected buckets %+v", bs)
	}
	if bs[1].CreationDate.Year() != 2026 {
		t.Fatalf("creation date not parsed: %v", bs[1].CreationDate)
	}
}

func TestCreateBucketErrorIsTyped(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusConflict)
		io.WriteString(w, `<Error><Code>BucketAlreadyOwnedByYou</Code>
		  <Message>Your previous request succeeded.</Message><Resource>/b</Resource></Error>`)
	}))
	err := c.CreateBucket(context.Background(), "b")
	var se *Error
	if !errors.As(err, &se) {
		t.Fatalf("want *Error, got %T %v", err, err)
	}
	if se.Code != "BucketAlreadyOwnedByYou" || se.StatusCode != 409 {
		t.Fatalf("unexpected error %+v", se)
	}
}

func TestGetObjectNotFound(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, `<Error><Code>NoSuchKey</Code><Message>nope</Message></Error>`)
	}))
	_, err := c.GetObject(context.Background(), "b", "missing")
	if !IsNoSuchKey(err) {
		t.Fatalf("want NoSuchKey, got %v", err)
	}
}

func TestPutObjectSendsVerifiablePayloadHash(t *testing.T) {
	payload := []byte("hello fass")
	var sent string
	var gotBody []byte
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent = r.Header.Get("X-Amz-Content-Sha256")
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("ETag", `"abc123"`)
		w.WriteHeader(200)
	}))
	etag, err := c.PutObject(context.Background(), "b", "k.txt", bytes.NewReader(payload), int64(len(payload)), "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	if etag != "abc123" {
		t.Fatalf("etag = %q", etag)
	}
	if !bytes.Equal(gotBody, payload) {
		t.Fatalf("body = %q", gotBody)
	}
	sum := sha256.Sum256(payload)
	if want := hex.EncodeToString(sum[:]); sent != want {
		t.Fatalf("payload hash = %q, want %q", sent, want)
	}
}

func TestPutObjectUnsignedPayload(t *testing.T) {
	var sent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent = r.Header.Get("X-Amz-Content-Sha256")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	c, err := New(srv.URL, "eu-west-1", "AK", "SK", WithHTTPClient(srv.Client()), WithUnsignedPayload())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PutObject(context.Background(), "b", "k", strings.NewReader("data"), 4, ""); err != nil {
		t.Fatal(err)
	}
	if sent != "UNSIGNED-PAYLOAD" {
		t.Fatalf("payload hash = %q", sent)
	}
}

func TestListObjectsV2(t *testing.T) {
	var gotQuery string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		io.WriteString(w, `<ListBucketResult><IsTruncated>true</IsTruncated>
		  <Contents><Key>logs/a.log</Key><Size>12</Size><ETag>"e1"</ETag>
		  <LastModified>2026-10-24T12:00:00Z</LastModified></Contents>
		</ListBucketResult>`)
	}))
	objs, trunc, err := c.ListObjectsV2(context.Background(), "b", "logs/", 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !trunc || len(objs) != 1 || objs[0].Key != "logs/a.log" || objs[0].Size != 12 || objs[0].ETag != "e1" {
		t.Fatalf("unexpected listing %+v trunc=%v", objs, trunc)
	}
	if !strings.Contains(gotQuery, "list-type=2") || !strings.Contains(gotQuery, "prefix=logs%2F") {
		t.Fatalf("query = %q", gotQuery)
	}
}

func TestPresignGet(t *testing.T) {
	c, err := New("https://s3.example.test", "eu-west-1", "AK", "SK")
	if err != nil {
		t.Fatal(err)
	}
	u, err := c.PresignGet(context.Background(), "b", "dir/k.txt", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"X-Amz-Algorithm=AWS4-HMAC-SHA256", "X-Amz-Signature=", "X-Amz-Expires=900"} {
		if !strings.Contains(u, want) {
			t.Errorf("presigned URL missing %q: %s", want, u)
		}
	}
}

func TestNewInfersScheme(t *testing.T) {
	c, err := New("localhost:8080", "", "AK", "SK")
	if err != nil {
		t.Fatal(err)
	}
	if c.Endpoint.Scheme != "https" {
		t.Fatalf("scheme = %q", c.Endpoint.Scheme)
	}
	if c.Region != "eu-west-1" {
		t.Fatalf("default region = %q", c.Region)
	}
}
