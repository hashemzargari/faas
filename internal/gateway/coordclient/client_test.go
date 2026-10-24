package coordclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/ec"
)

type recorded struct {
	mu       sync.Mutex
	method   string
	path     string
	query    url.Values
	body     []byte
	requests int
}

func (r *recorded) record(req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests++
	r.method = req.Method
	r.path = req.URL.EscapedPath()
	r.query = req.URL.Query()
	r.body, _ = io.ReadAll(req.Body)
}

func (r *recorded) last() (string, string, url.Values, []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.method, r.path, r.query, append([]byte(nil), r.body...)
}

func newTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *recorded) {
	t.Helper()
	rec := &recorded{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.record(r)
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	c, err := New(Options{BaseURL: srv.URL, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c, rec
}

func TestVerifySignature(t *testing.T) {
	c, rec := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"principal": contract.Principal{AccessKeyID: "AKIATEST", TenantID: "t1", ProjectID: "p1"},
			"hmac_key":  base64.StdEncoding.EncodeToString([]byte("topsecret")),
		})
	})
	principal, secret, err := c.VerifySignature(context.Background(), "AKIATEST")
	if err != nil {
		t.Fatal(err)
	}
	if principal.TenantID != "t1" || string(secret) != "topsecret" {
		t.Fatalf("principal=%+v secret=%q", principal, secret)
	}
	method, path, _, _ := rec.last()
	if method != http.MethodPost || path != "/v1/auth/keys/AKIATEST" {
		t.Fatalf("request = %s %s", method, path)
	}
}

func TestAuthorize(t *testing.T) {
	c, rec := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"allowed": true})
	})
	dec, err := c.Authorize(context.Background(), contract.RequestContext{
		Principal: contract.Principal{AccessKeyID: "AK"},
		Action:    contract.ActionPutObject,
		Resource:  contract.Resource{Kind: "object", Bucket: "b", Key: "k"},
		Condition: map[string]string{"s3:prefix": "x"},
	})
	if err != nil || !dec.Allowed {
		t.Fatalf("decision=%+v err=%v", dec, err)
	}
	_, path, _, body := rec.last()
	if path != "/v1/auth/authorize" {
		t.Fatalf("path = %s", path)
	}
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("body: %v", err)
	}
	if req["action"] != "s3:PutObject" {
		t.Fatalf("action = %v", req["action"])
	}
	res, _ := req["resource"].(map[string]any)
	if res["bucket"] != "b" || res["key"] != "k" {
		t.Fatalf("resource = %v", res)
	}
}

func TestUpdateBucketConfigSendsOnlyMutableFields(t *testing.T) {
	c, rec := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(contract.BucketConfig{})
	})
	err := c.UpdateBucketConfig(context.Background(), contract.BucketConfig{
		BucketID: "bucket-1", Name: "b", TenantID: "t1", ProjectID: "p1",
		Region: "eu-west-1", Versioning: "Enabled", Ownership: "ObjectWriter",
	})
	if err != nil {
		t.Fatal(err)
	}
	method, path, _, body := rec.last()
	if method != http.MethodPatch || path != "/v1/buckets/b" {
		t.Fatalf("request = %s %s", method, path)
	}
	var patch map[string]any
	if err := json.Unmarshal(body, &patch); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"bucket_id", "name", "tenant_id", "project_id", "region"} {
		if _, ok := patch[forbidden]; ok {
			t.Fatalf("PATCH sent immutable/unknown field %q: %s", forbidden, body)
		}
	}
	if patch["versioning"] != "Enabled" {
		t.Fatalf("patch = %v", patch)
	}
}

func TestPlacementUsesSnakeCaseAndExclusions(t *testing.T) {
	c, rec := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(contract.Placement{
			ShardSetID: "set-1", RingID: "ring-1", Generation: 3,
			Slots: []contract.Slot{{GeoGroup: 0, LocalIndex: 0, AgentID: "a1", Endpoint: "127.0.0.1:7100"}},
		})
	})
	p, err := c.ResolvePlacement(context.Background(), contract.PlacementRequest{
		ShardSetID:    "set-1",
		Params:        ecParams(),
		ChunkBytes:    16 << 20,
		TenantID:      "t1",
		ProjectID:     "p1",
		RCID:          "rc",
		ExcludeAgents: []contract.AgentID{"dead-agent"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.Generation != 3 || len(p.Slots) != 1 {
		t.Fatalf("placement = %+v", p)
	}
	_, path, _, body := rec.last()
	if path != "/v1/placement" {
		t.Fatalf("path = %s", path)
	}
	var wire map[string]any
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatal(err)
	}
	if wire["shard_set_id"] != "set-1" || wire["chunk_bytes"] != float64(16<<20) {
		t.Fatalf("wire = %v", wire)
	}
	excl, _ := wire["exclude_agents"].([]any)
	if len(excl) != 1 || excl[0] != "dead-agent" {
		t.Fatalf("exclude_agents = %v", wire["exclude_agents"])
	}
}

func TestCommitObjectWireShape(t *testing.T) {
	c, rec := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"version_id": "v-1", "etag": "etag"})
	})
	res, err := c.CommitObject(context.Background(), contract.CommitRequest{
		VersionID: "v-1", BucketID: "bucket-1", Key: "k", Size: 10, ETag: "etag",
		ChunkSize: 4 << 20, StorageClass: "STANDARD",
	})
	if err != nil || res.VersionID != "v-1" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	_, path, _, body := rec.last()
	if path != "/v1/objects:commit" {
		t.Fatalf("path = %s", path)
	}
	var wire map[string]any
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatal(err)
	}
	if wire["version_id"] != "v-1" || wire["bucket_id"] != "bucket-1" || wire["chunk_size"] != float64(4<<20) {
		t.Fatalf("wire = %v", wire)
	}
	if _, ok := wire["VersionID"]; ok {
		t.Fatalf("CommitRequest serialised a Go field name: %s", body)
	}
}

func TestObjectPathsAndSubresources(t *testing.T) {
	tests := []struct {
		name     string
		call     func(c *Client) error
		wantPath string
	}{
		{
			name: "plain key with slashes",
			call: func(c *Client) error {
				_, err := c.GetManifest(context.Background(), "b", "dir/obj.bin", "")
				return err
			},
			wantPath: "/v1/objects/b/dir/obj.bin",
		},
		{
			name: "tags subresource",
			call: func(c *Client) error {
				_, err := c.GetObjectTags(context.Background(), "b", "dir/obj.bin", "v1")
				return err
			},
			wantPath: "/v1/objects/b/dir/obj.bin/tags",
		},
		{
			name: "key literally ending in /tags stays an object",
			call: func(c *Client) error {
				_, err := c.GetManifest(context.Background(), "b", "dir/obj/tags", "")
				return err
			},
			wantPath: "/v1/objects/b/dir%2Fobj%2Ftags",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, rec := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{"tags": map[string]string{}})
			})
			if err := tc.call(c); err != nil {
				t.Fatalf("call: %v", err)
			}
			_, path, _, _ := rec.last()
			if path != tc.wantPath {
				t.Fatalf("path = %q, want %q", path, tc.wantPath)
			}
		})
	}
}

func TestListObjectsQuery(t *testing.T) {
	c, rec := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(contract.ListResult{KeyCount: 0})
	})
	_, err := c.ListObjects(context.Background(), contract.ListRequest{
		BucketID: "bucket-1", Prefix: "logs/", Delimiter: "/", MaxKeys: 10,
		ContinuationToken: "tok", Versions: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, path, q, _ := rec.last()
	if path != "/v1/objects" {
		t.Fatalf("path = %s", path)
	}
	if q.Get("bucket_id") != "bucket-1" || q.Get("prefix") != "logs/" ||
		q.Get("delimiter") != "/" || q.Get("max_keys") != "10" ||
		q.Get("token") != "tok" || q.Get("versions") != "true" {
		t.Fatalf("query = %v", q)
	}
}

func TestErrorMapping(t *testing.T) {
	tests := []struct {
		status int
		code   string
		want   error
	}{
		{http.StatusNotFound, "NoSuchKey", contract.ErrNotFound},
		{http.StatusConflict, "BucketNotEmpty", contract.ErrConflict},
		{http.StatusForbidden, "AccessDenied", contract.ErrForbidden},
		{http.StatusPreconditionFailed, "PreconditionFailed", contract.ErrPrecondition},
		{http.StatusServiceUnavailable, "SlowDown", contract.ErrUnavailable},
		{http.StatusNotImplemented, "NotImplemented", contract.ErrNotImplemented},
		{http.StatusInsufficientStorage, "InsufficientStorage", contract.ErrInsufficientCap},
	}
	for _, tc := range tests {
		t.Run(tc.code, func(t *testing.T) {
			c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				json.NewEncoder(w).Encode(map[string]any{
					"error": map[string]string{"code": tc.code, "message": "boom"},
				})
			})
			_, err := c.GetBucket(context.Background(), "b")
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			var api *APIError
			if !errors.As(err, &api) || api.HTTPStatus() != tc.status {
				t.Fatalf("APIError = %#v", err)
			}
		})
	}
}

func TestGetBucketNotFoundKeepsStatus(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
		io.WriteString(w, `{"error":{"code":"MethodNotAllowed","message":"delete marker"}}`)
	})
	_, err := c.GetManifest(context.Background(), "b", "k", "v")
	if err == nil {
		t.Fatal("expected an error")
	}
	var api *APIError
	if !errors.As(err, &api) || api.HTTPStatus() != http.StatusMethodNotAllowed {
		t.Fatalf("error = %v", err)
	}
	if !strings.Contains(err.Error(), "delete marker") {
		t.Fatalf("message lost: %v", err)
	}
}

func ecParams() ec.Params { return ec.Params{GeoN: 2, GeoK: 1, LocalN: 4, LocalK: 2} }
