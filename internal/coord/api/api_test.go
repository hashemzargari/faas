package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/coord"
	"github.com/fass-storage/fass/internal/coord/api"
	"github.com/fass-storage/fass/internal/coord/id"
	"github.com/fass-storage/fass/internal/coord/membership"
	"github.com/fass-storage/fass/internal/ec"
)

// harness boots a real coordinator on a random port (httptest) over an embedded
// store in a temp dir — the acceptance test the task asks for.
type harness struct {
	t   *testing.T
	svc *coord.Service
	srv *httptest.Server
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc, err := coord.Open(context.Background(), t.TempDir(), coord.Config{Logger: logger})
	if err != nil {
		t.Fatalf("open coordinator: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	h := &harness{t: t, svc: svc}
	h.srv = httptest.NewServer(api.New(svc, logger).Handler())
	t.Cleanup(h.srv.Close)
	return h
}

func (h *harness) url(path string) string { return h.srv.URL + path }

func (h *harness) do(method, path string, body any) (*http.Response, []byte) {
	h.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			h.t.Fatalf("marshal request body: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, h.url(path), reader)
	if err != nil {
		h.t.Fatalf("build request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatalf("read response: %v", err)
	}
	return resp, raw
}

func (h *harness) doJSON(method, path string, body any, out any) *http.Response {
	h.t.Helper()
	resp, raw := h.do(method, path, body)
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			h.t.Fatalf("%s %s: decode response %s: %v", method, path, raw, err)
		}
	}
	return resp
}

func (h *harness) mustStatus(resp *http.Response, want int) {
	h.t.Helper()
	if resp.StatusCode != want {
		h.t.Fatalf("%s %s: status %d, want %d", resp.Request.Method, resp.Request.URL.Path, resp.StatusCode, want)
	}
}

const chunkSize = 16 << 20

var flatParams = ec.Params{GeoN: 1, GeoK: 0, LocalN: 2, LocalK: 1}

func makeChunks(t *testing.T, n int) []contract.ChunkRef {
	t.Helper()
	out := make([]contract.ChunkRef, n)
	for i := 0; i < n; i++ {
		total := flatParams.TotalShards()
		perGroup := flatParams.ShardsPerGroup()
		slots := make([]contract.Slot, total)
		checksums := make([]uint64, total)
		for s := 0; s < total; s++ {
			slots[s] = contract.Slot{
				GeoGroup:   s / perGroup,
				LocalIndex: s % perGroup,
				AgentID:    contract.AgentID(fmt.Sprintf("agent-%d", s)),
				NodeID:     contract.NodeID("node-1"),
				NexusID:    "nexus-1",
				Endpoint:   "127.0.0.1:7101",
			}
			checksums[s] = uint64(5000 + s)
		}
		out[i] = contract.ChunkRef{
			Index:         i,
			Params:        flatParams,
			CiphertextLen: chunkSize,
			ShardSize:     chunkSize / (flatParams.GeoN * flatParams.LocalN),
			Slots:         slots,
			Checksums:     checksums,
			Generation:    1,
		}
	}
	return out
}

func commitBody(bucketID contract.BucketID, key string, size int64, chunks []contract.ChunkRef) contract.CommitRequest {
	return contract.CommitRequest{
		VersionID:    contract.VersionID(id.New()),
		BucketID:     bucketID,
		Key:          key,
		Size:         size,
		ETag:         "etag-" + key,
		ChunkSize:    chunkSize,
		Chunks:       chunks,
		ContentType:  "text/plain",
		UserMeta:     map[string]string{"k": "v"},
		StorageClass: "STANDARD",
	}
}

// seedTopology creates a synthetic 3-Nexus × 3-Node × 1-Agent topology through
// the real announce/activate flow and returns the nexus ids.
func (h *harness) seedTopology(t *testing.T) []contract.NexusID {
	t.Helper()
	ctx := context.Background()
	sw, err := h.svc.Members.CreateSwarm(ctx, membership.Swarm{Name: "swarm-1", Region: "eu-west-1"})
	if err != nil {
		t.Fatalf("create swarm: %v", err)
	}
	var nexusIDs []contract.NexusID
	for n := 0; n < 3; n++ {
		nx, err := h.svc.Members.CreateNexus(ctx, membership.Nexus{SwarmID: sw.ID, Name: fmt.Sprintf("site-%d", n)})
		if err != nil {
			t.Fatalf("create nexus: %v", err)
		}
		nexusIDs = append(nexusIDs, nx.ID)
		for d := 0; d < 3; d++ {
			node, err := h.svc.Members.CreateNode(ctx, membership.Node{
				NexusID:  nx.ID,
				Hostname: fmt.Sprintf("host-%d-%d", n, d),
				Rack:     fmt.Sprintf("rack-%d", n),
			})
			if err != nil {
				t.Fatalf("create node: %v", err)
			}
			agentID, secret, err := h.svc.Members.RegisterPending(ctx, membership.PendingRegistration{
				NodeID:        node.ID,
				DiskID:        fmt.Sprintf("disk-%d-%d", n, d),
				CapacityBytes: 1 << 40,
			})
			if err != nil {
				t.Fatalf("register pending: %v", err)
			}
			publicKey := []byte(fmt.Sprintf("pubkey-%d-%d", n, d))
			if _, err := h.svc.Members.Announce(ctx, contract.AnnounceRequest{
				PublicKey:     publicKey,
				Secret:        secret,
				NodeID:        node.ID,
				DiskID:        fmt.Sprintf("disk-%d-%d", n, d),
				Port:          7101,
				CapacityBytes: 1 << 40,
				Hostname:      fmt.Sprintf("10.0.%d.%d", n, d),
				Version:       "test",
			}); err != nil {
				t.Fatalf("announce: %v", err)
			}
			if _, err := h.svc.Members.Activate(ctx, agentID); err != nil {
				t.Fatalf("activate: %v", err)
			}
		}
	}
	return nexusIDs
}

func TestCoordinatorEndToEnd(t *testing.T) {
	h := newHarness(t)

	// Health and metrics are up before anything else.
	resp, _ := h.do("GET", "/healthz", nil)
	h.mustStatus(resp, http.StatusOK)
	resp, _ = h.do("GET", "/v1/healthz", nil)
	h.mustStatus(resp, http.StatusOK)
	resp, metrics := h.do("GET", "/metrics", nil)
	h.mustStatus(resp, http.StatusOK)
	if !strings.Contains(string(metrics), "fass_coordinator_http_requests_total") {
		t.Fatalf("metrics output missing request counter:\n%s", metrics)
	}

	// ---- Bucket -----------------------------------------------------------
	var bucket contract.BucketConfig
	resp = h.doJSON("POST", "/v1/buckets", contract.BucketConfig{
		Name:      "e2e-bucket",
		TenantID:  "tenant-1",
		ProjectID: "project-1",
		Region:    "eu-west-1",
		Ownership: "ObjectWriter",
	}, &bucket)
	h.mustStatus(resp, http.StatusCreated)
	if bucket.BucketID == "" {
		t.Fatalf("bucket id not assigned")
	}
	var got contract.BucketConfig
	resp = h.doJSON("GET", "/v1/buckets/e2e-bucket", nil, &got)
	h.mustStatus(resp, http.StatusOK)
	if got.Name != "e2e-bucket" || got.Region != "eu-west-1" {
		t.Fatalf("bucket read back = %+v", got)
	}

	// ---- Commit objects ---------------------------------------------------
	objects := []struct {
		key    string
		size   int64
		nchunk int
	}{
		{"docs/2026/a.txt", 3 * chunkSize, 3},
		{"docs/2026/b.txt", chunkSize, 1},
		{"top.txt", chunkSize, 1},
	}
	committed := make(map[string]contract.VersionID)
	for _, obj := range objects {
		req := commitBody(bucket.BucketID, obj.key, obj.size, makeChunks(t, obj.nchunk))
		var res struct {
			VersionID contract.VersionID `json:"version_id"`
			ETag      string             `json:"etag"`
		}
		resp = h.doJSON("POST", "/v1/objects:commit", req, &res)
		h.mustStatus(resp, http.StatusOK)
		if res.VersionID != req.VersionID {
			t.Fatalf("commit echoed version %s, want %s", res.VersionID, req.VersionID)
		}
		if res.ETag == "" {
			t.Fatalf("commit returned empty etag")
		}
		committed[obj.key] = res.VersionID
	}

	// Manifest round trip: 3 chunks, slot order preserved.
	var manifest contract.Manifest
	resp = h.doJSON("GET", "/v1/objects/e2e-bucket/docs/2026/a.txt", nil, &manifest)
	h.mustStatus(resp, http.StatusOK)
	if manifest.Key != "docs/2026/a.txt" || len(manifest.Chunks) != 3 {
		t.Fatalf("manifest = %+v", manifest)
	}
	for i, ch := range manifest.Chunks {
		if ch.Index != i || len(ch.Slots) != flatParams.TotalShards() {
			t.Fatalf("chunk %d malformed: %+v", i, ch)
		}
	}

	// HEAD returns headers only.
	resp, raw := h.do("HEAD", "/v1/objects/e2e-bucket/docs/2026/a.txt", nil)
	h.mustStatus(resp, http.StatusOK)
	if len(raw) != 0 {
		t.Fatalf("HEAD returned a body")
	}
	if resp.Header.Get("ETag") == "" || resp.Header.Get("X-Fass-Version-Id") == "" {
		t.Fatalf("HEAD missing identity headers: %v", resp.Header)
	}

	// ---- Listing: prefix + delimiter -------------------------------------
	var grouped contract.ListResult
	resp = h.doJSON("GET", "/v1/objects?bucket=e2e-bucket&prefix=docs/&delimiter=/", nil, &grouped)
	h.mustStatus(resp, http.StatusOK)
	if len(grouped.Entries) != 1 || grouped.Entries[0].CommonPrefix != "docs/2026/" {
		t.Fatalf("grouped listing = %+v", grouped)
	}

	var listed contract.ListResult
	resp = h.doJSON("GET", "/v1/objects?bucket=e2e-bucket&prefix=docs/2026/", nil, &listed)
	h.mustStatus(resp, http.StatusOK)
	if len(listed.Entries) != 2 || listed.KeyCount != 2 {
		t.Fatalf("prefix listing = %+v", listed)
	}
	if listed.Entries[0].Key != "docs/2026/a.txt" || listed.Entries[1].Key != "docs/2026/b.txt" {
		t.Fatalf("prefix listing order = %+v", listed.Entries)
	}

	var all contract.ListResult
	resp = h.doJSON("GET", "/v1/objects?bucket=e2e-bucket", nil, &all)
	h.mustStatus(resp, http.StatusOK)
	if len(all.Entries) != 3 {
		t.Fatalf("all listing = %d entries", len(all.Entries))
	}

	// ---- Delete -----------------------------------------------------------
	var del struct {
		VersionID    contract.VersionID `json:"version_id"`
		DeleteMarker bool               `json:"delete_marker"`
	}
	resp = h.doJSON("DELETE", "/v1/objects/e2e-bucket/docs/2026/a.txt", nil, &del)
	h.mustStatus(resp, http.StatusOK)
	if del.VersionID != committed["docs/2026/a.txt"] || del.DeleteMarker {
		t.Fatalf("delete result = %+v", del)
	}
	var errBody struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	resp = h.doJSON("GET", "/v1/objects/e2e-bucket/docs/2026/a.txt", nil, &errBody)
	h.mustStatus(resp, http.StatusNotFound)
	if errBody.Error.Code != "NoSuchKey" {
		t.Fatalf("error code = %q, want NoSuchKey", errBody.Error.Code)
	}
	resp, _ = h.do("GET", "/v1/objects/e2e-bucket/docs/2026/a.txt", nil)
	if resp.Header.Get("X-Fass-Request-Id") == "" {
		t.Fatalf("response missing X-Fass-Request-Id")
	}

	// Non-empty bucket cannot be deleted.
	resp, _ = h.do("DELETE", "/v1/buckets/e2e-bucket", nil)
	h.mustStatus(resp, http.StatusConflict)

	// ---- Versioning, tags, retention over the §1.4b sub-resources ---------
	var vbucket contract.BucketConfig
	resp = h.doJSON("POST", "/v1/buckets", contract.BucketConfig{
		Name:       "versioned-bucket",
		TenantID:   "tenant-1",
		ProjectID:  "project-1",
		ObjectLock: true,
		Versioning: "Enabled",
	}, &vbucket)
	h.mustStatus(resp, http.StatusCreated)

	v1req := commitBody(vbucket.BucketID, "versioned.txt", chunkSize, makeChunks(t, 1))
	var v1 struct {
		VersionID contract.VersionID `json:"version_id"`
	}
	resp = h.doJSON("POST", "/v1/objects:commit", v1req, &v1)
	h.mustStatus(resp, http.StatusOK)
	v2req := commitBody(vbucket.BucketID, "versioned.txt", 2*chunkSize, makeChunks(t, 2))
	var v2 struct {
		VersionID contract.VersionID `json:"version_id"`
	}
	resp = h.doJSON("POST", "/v1/objects:commit", v2req, &v2)
	h.mustStatus(resp, http.StatusOK)

	var versions contract.ListResult
	resp = h.doJSON("GET", "/v1/objects?bucket=versioned-bucket&versions=1", nil, &versions)
	h.mustStatus(resp, http.StatusOK)
	if len(versions.Entries) != 2 {
		t.Fatalf("version listing = %+v", versions)
	}
	if versions.Entries[0].VersionID != v2.VersionID || !versions.Entries[0].IsLatest {
		t.Fatalf("newest version not listed first: %+v", versions.Entries[0])
	}

	// Tags.
	resp, _ = h.do("PUT", "/v1/objects/versioned-bucket/versioned.txt/tags?version="+string(v2.VersionID), map[string]any{
		"tags": map[string]string{"team": "storage"},
	})
	h.mustStatus(resp, http.StatusOK)
	var tagBody struct {
		Tags map[string]string `json:"tags"`
	}
	resp = h.doJSON("GET", "/v1/objects/versioned-bucket/versioned.txt/tags?version="+string(v2.VersionID), nil, &tagBody)
	h.mustStatus(resp, http.StatusOK)
	if tagBody.Tags["team"] != "storage" {
		t.Fatalf("tags = %+v", tagBody.Tags)
	}

	// Object lock: a GOVERNANCE retention blocks deletion unless bypassed.
	retention := contract.Retention{Mode: "GOVERNANCE", RetainUntil: time.Now().Add(time.Hour)}
	resp, _ = h.do("PUT", "/v1/objects/versioned-bucket/versioned.txt/retention?version="+string(v2.VersionID), retention)
	h.mustStatus(resp, http.StatusOK)
	var ret contract.Retention
	resp = h.doJSON("GET", "/v1/objects/versioned-bucket/versioned.txt/retention?version="+string(v2.VersionID), nil, &ret)
	h.mustStatus(resp, http.StatusOK)
	if ret.Mode != "GOVERNANCE" {
		t.Fatalf("retention = %+v", ret)
	}
	resp, _ = h.do("DELETE", "/v1/objects/versioned-bucket/versioned.txt?version="+string(v2.VersionID), nil)
	h.mustStatus(resp, http.StatusForbidden)
	resp, _ = h.do("DELETE", "/v1/objects/versioned-bucket/versioned.txt?version="+string(v2.VersionID)+"&bypass=true", nil)
	h.mustStatus(resp, http.StatusOK)

	// Deleting without a version on a versioned bucket inserts a delete marker.
	var marker struct {
		VersionID    contract.VersionID `json:"version_id"`
		DeleteMarker bool               `json:"delete_marker"`
	}
	resp = h.doJSON("DELETE", "/v1/objects/versioned-bucket/versioned.txt", nil, &marker)
	h.mustStatus(resp, http.StatusOK)
	if !marker.DeleteMarker {
		t.Fatalf("expected delete marker, got %+v", marker)
	}

	// Bucket sub-resources: location, ACL, lifecycle.
	var location map[string]string
	resp = h.doJSON("GET", "/v1/buckets/versioned-bucket/location", nil, &location)
	h.mustStatus(resp, http.StatusOK)
	if location["region"] != "eu-west-1" {
		t.Fatalf("location = %+v", location)
	}
	var currentACL contract.ACL
	resp = h.doJSON("GET", "/v1/buckets/versioned-bucket/acl", nil, &currentACL)
	h.mustStatus(resp, http.StatusOK)
	if currentACL.OwnerID == "" {
		t.Fatalf("bucket ACL has no owner: %+v", currentACL)
	}
	lifecycle := []byte("<LifecycleConfiguration></LifecycleConfiguration>")
	req, err := http.NewRequest("PUT", h.url("/v1/buckets/versioned-bucket/lifecycle"), bytes.NewReader(lifecycle))
	if err != nil {
		t.Fatalf("build lifecycle request: %v", err)
	}
	req.Header.Set("Content-Type", "application/xml")
	lresp, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("put lifecycle: %v", err)
	}
	lresp.Body.Close()
	if lresp.StatusCode != http.StatusOK {
		t.Fatalf("put lifecycle status = %d", lresp.StatusCode)
	}
	resp, rawLifecycle := h.do("GET", "/v1/buckets/versioned-bucket/lifecycle", nil)
	h.mustStatus(resp, http.StatusOK)
	if string(rawLifecycle) != string(lifecycle) {
		t.Fatalf("lifecycle round trip = %q", rawLifecycle)
	}

	// ---- Placement on a synthetic 3-Nexus topology -----------------------
	nexusIDs := h.seedTopology(t)
	var rc membership.RedundancyClass
	resp = h.doJSON("POST", "/v1/redundancy-classes", map[string]any{
		"name":       "geo2+1_local2+1",
		"params":     map[string]int{"geo_n": 2, "geo_k": 1, "local_n": 2, "local_k": 1},
		"aag":        2,
		"chunk_size": chunkSize,
	}, &rc)
	h.mustStatus(resp, http.StatusCreated)
	if rc.ID == "" {
		t.Fatalf("RC id not assigned")
	}
	var ring membership.Ring
	resp = h.doJSON("POST", "/v1/rings", membership.Ring{
		Name:     "ring-e2e",
		RCID:     rc.ID,
		NexusIDs: nexusIDs,
	}, &ring)
	h.mustStatus(resp, http.StatusCreated)

	_, rawPlacement := h.do("POST", "/v1/placement", map[string]any{
		"params":       map[string]int{"geo_n": 2, "geo_k": 1, "local_n": 2, "local_k": 1},
		"shard_set_id": "set-e2e",
		"chunk_bytes":  chunkSize,
		"tenant_id":    "tenant-1",
		"project_id":   "project-1",
		"rc_id":        rc.ID,
	})
	var placement struct {
		ShardSetID string `json:"shard_set_id"`
		RingID     string `json:"ring_id"`
		Generation int    `json:"generation"`
		Slots      []struct {
			GeoGroup   int    `json:"geo_group"`
			LocalIndex int    `json:"local_index"`
			AgentID    string `json:"agent_id"`
			NodeID     string `json:"node_id"`
			NexusID    string `json:"nexus_id"`
			Endpoint   string `json:"endpoint"`
		} `json:"slots"`
	}
	if err := json.Unmarshal(rawPlacement, &placement); err != nil {
		t.Fatalf("decode placement %s: %v", rawPlacement, err)
	}
	perGroup := 3 // local_n+local_k
	if placement.ShardSetID != "set-e2e" || placement.RingID != string(ring.ID) || placement.Generation != 1 {
		t.Fatalf("placement envelope = %+v (raw %s)", placement, rawPlacement)
	}
	if len(placement.Slots) != 9 {
		t.Fatalf("placement returned %d slots, want 9", len(placement.Slots))
	}
	groupNexus := map[int]string{}
	nexusSet := map[string]bool{}
	for i, sl := range placement.Slots {
		if sl.GeoGroup != i/perGroup || sl.LocalIndex != i%perGroup {
			t.Fatalf("slot %d not in shard-index order: %+v", i, sl)
		}
		if prior, ok := groupNexus[sl.GeoGroup]; ok && prior != sl.NexusID {
			t.Fatalf("geo group %d spans two nexuses", sl.GeoGroup)
		}
		groupNexus[sl.GeoGroup] = sl.NexusID
		nexusSet[sl.NexusID] = true
		if sl.AgentID == "" || sl.Endpoint == "" {
			t.Fatalf("slot %d incomplete: %+v", i, sl)
		}
	}
	if len(nexusSet) != 3 {
		t.Fatalf("placement spans %d nexuses, want 3", len(nexusSet))
	}

	// Tenant geo-fencing comes from tenant metadata, not the placement request:
	// a 2-nexus fence cannot satisfy a geo_n+geo_k = 3 code.
	resp = h.doJSON("POST", "/v1/tenants", map[string]any{
		"tenant_id": "tenant-1",
		"name":      "tenant-one",
		"geo_fence": []string{string(nexusIDs[0]), string(nexusIDs[1])},
	}, nil)
	h.mustStatus(resp, http.StatusCreated)
	resp, _ = h.do("POST", "/v1/placement", map[string]any{
		"params":       map[string]int{"geo_n": 2, "geo_k": 1, "local_n": 2, "local_k": 1},
		"shard_set_id": "set-fenced",
		"chunk_bytes":  chunkSize,
		"tenant_id":    "tenant-1",
		"rc_id":        rc.ID,
	})
	h.mustStatus(resp, http.StatusInsufficientStorage)
	// Widening the fence restores placement.
	resp = h.doJSON("POST", "/v1/tenants", map[string]any{
		"tenant_id": "tenant-1",
		"name":      "tenant-one",
		"geo_fence": []string{string(nexusIDs[0]), string(nexusIDs[1]), string(nexusIDs[2])},
	}, nil)
	h.mustStatus(resp, http.StatusCreated)
	resp, _ = h.do("POST", "/v1/placement", map[string]any{
		"params":       map[string]int{"geo_n": 2, "geo_k": 1, "local_n": 2, "local_k": 1},
		"shard_set_id": "set-fenced-ok",
		"chunk_bytes":  chunkSize,
		"tenant_id":    "tenant-1",
		"rc_id":        rc.ID,
	})
	h.mustStatus(resp, http.StatusOK)

	// ---- Auth: access key, local HMAC material, authorize ----------------
	var key struct {
		AccessKeyID string `json:"access_key_id"`
		Secret      string `json:"secret"`
	}
	resp = h.doJSON("POST", "/v1/access-keys", map[string]any{
		"tenant_id":  "tenant-1",
		"project_id": "project-1",
	}, &key)
	h.mustStatus(resp, http.StatusCreated)
	if key.AccessKeyID == "" || key.Secret == "" {
		t.Fatalf("access key not created: %+v", key)
	}
	var verify struct {
		Principal contract.Principal `json:"principal"`
		HMACKey   string             `json:"hmac_key"`
		ExpiresAt time.Time          `json:"expires_at"`
	}
	resp = h.doJSON("POST", "/v1/auth/keys/"+key.AccessKeyID, nil, &verify)
	h.mustStatus(resp, http.StatusOK)
	decoded, err := base64.StdEncoding.DecodeString(verify.HMACKey)
	if err != nil || string(decoded) != key.Secret {
		t.Fatalf("hmac_key does not match the access key secret (err %v)", err)
	}
	if verify.Principal.TenantID != "tenant-1" || verify.ExpiresAt.IsZero() {
		t.Fatalf("verify response = %+v", verify)
	}

	var decision struct {
		Allowed bool   `json:"allowed"`
		Reason  string `json:"reason"`
	}
	resp = h.doJSON("POST", "/v1/auth/authorize", map[string]any{
		"principal": verify.Principal,
		"action":    "s3:GetObject",
		"resource":  contract.Resource{Region: "eu-west-1", Kind: "object", TenantID: "tenant-1", ProjectID: "project-1", Bucket: "e2e-bucket", Key: "docs/2026/b.txt"},
	}, &decision)
	h.mustStatus(resp, http.StatusOK)
	if !decision.Allowed {
		t.Fatalf("bucket owner denied: %+v", decision)
	}

	// ---- Announce taxonomy over HTTP -------------------------------------
	// A fresh node/disk is registered pending with an expected port; announcing a
	// different port must produce the exact Cubbit error taxonomy over the wire.
	taxonomyNode, err := h.svc.Members.CreateNode(context.Background(), membership.Node{NexusID: nexusIDs[0], Hostname: "host-taxonomy"})
	if err != nil {
		t.Fatalf("create taxonomy node: %v", err)
	}
	var pending struct {
		AgentID string `json:"agent_id"`
		Secret  string `json:"secret"`
	}
	resp = h.doJSON("POST", "/v1/agents/pending", map[string]any{
		"node_id":       taxonomyNode.ID,
		"disk_id":       "disk-taxonomy",
		"expected_port": 7101,
	}, &pending)
	h.mustStatus(resp, http.StatusCreated)

	var announceErr struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	resp = h.doJSON("POST", "/v1/agents/announce", map[string]any{
		"public_key": base64.StdEncoding.EncodeToString([]byte("taxonomy-key")),
		"secret":     pending.Secret,
		"node_id":    taxonomyNode.ID,
		"disk_id":    "disk-taxonomy",
		"port":       9999,
		"hostname":   "10.9.9.9",
	}, &announceErr)
	if resp.StatusCode != http.StatusBadRequest || announceErr.Error.Message != "Port mismatch" {
		t.Fatalf("announce taxonomy = %d %+v", resp.StatusCode, announceErr)
	}
}
