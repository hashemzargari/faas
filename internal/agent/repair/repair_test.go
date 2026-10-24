package repair

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/fass-storage/fass/internal/agent/client"
	"github.com/fass-storage/fass/internal/agent/shard"
	"github.com/fass-storage/fass/internal/agent/store"
	"github.com/fass-storage/fass/internal/agent/transport"
	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/ec"
)

var testParams = ec.Params{GeoN: 2, GeoK: 1, LocalN: 16, LocalK: 4}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type node struct {
	st *store.Store
	ts *httptest.Server
}

func (n *node) endpoint() string { return n.ts.URL }

type testCluster struct {
	t       *testing.T
	params  ec.Params
	nodes   []*node
	setID   contract.ShardSetID
	codec   *ec.Codec
	payload []byte
	shards  [][]byte
	geom    ec.Geometry
	client  *client.Client
}

func newTestCluster(t *testing.T, params ec.Params, payloadSize, nodeCount int) *testCluster {
	t.Helper()
	payload := make([]byte, payloadSize)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("random payload: %v", err)
	}
	codec, err := ec.New(params)
	if err != nil {
		t.Fatalf("ec.New: %v", err)
	}
	shards, geom, err := codec.Encode(payload)
	if err != nil {
		t.Fatalf("ec.Encode: %v", err)
	}

	c := &testCluster{
		t:       t,
		params:  params,
		setID:   contract.ShardSetID("550e8400-e29b-41d4-a716-446655440000"),
		codec:   codec,
		payload: payload,
		shards:  shards,
		geom:    geom,
		client:  client.New(client.Options{}),
	}
	for i := 0; i < nodeCount; i++ {
		logger := discardLogger()
		st, err := store.Open(context.Background(), store.Options{Root: t.TempDir(), Logger: logger})
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		srv, err := transport.New(transport.Options{Store: st, Logger: logger, Version: "test"})
		if err != nil {
			t.Fatalf("transport.New: %v", err)
		}
		ts := httptest.NewServer(srv.Handler())
		n := &node{st: st, ts: ts}
		c.nodes = append(c.nodes, n)
		t.Cleanup(func() {
			ts.Close()
			_ = st.Close()
		})
	}
	return c
}

func (c *testCluster) groupSize() int { return c.params.ShardsPerGroup() }

func (c *testCluster) key(group, index int) (slotKey, bool) {
	if group < 0 || group >= c.params.GeoN+c.params.GeoK {
		return slotKey{}, false
	}
	if index < 0 || index >= c.groupSize() {
		return slotKey{}, false
	}
	return slotKey{group: group, index: index}, true
}

// nodeFor deterministically assigns a shard address to a cluster node.
func (c *testCluster) nodeFor(key slotKey) *node {
	idx := (key.group*c.groupSize() + key.index) % len(c.nodes)
	return c.nodes[idx]
}

func (c *testCluster) endpointFor(key slotKey) string { return c.nodeFor(key).endpoint() }

func (c *testCluster) slotFor(key slotKey) contract.Slot {
	return contract.Slot{
		GeoGroup:   key.group,
		LocalIndex: key.index,
		Endpoint:   c.endpointFor(key),
		NexusID:    contract.NexusID(fmt.Sprintf("nexus-%d", key.group)),
	}
}

func (c *testCluster) putAll() {
	c.t.Helper()
	for g := 0; g < c.params.GeoN+c.params.GeoK; g++ {
		for i := 0; i < c.groupSize(); i++ {
			key, _ := c.key(g, i)
			idx := g*c.groupSize() + i
			body := c.shards[idx]
			if err := c.client.PutShard(context.Background(), c.endpointFor(key), contract.PutShardRequest{
				ShardSetID: c.setID,
				GeoGroup:   g,
				LocalIndex: i,
				Params:     c.params,
				PayloadLen: len(body),
				Checksum:   shard.Sum64(body),
				Body:       bytes.NewReader(body),
			}); err != nil {
				c.t.Fatalf("PutShard(%d/%d): %v", g, i, err)
			}
		}
	}
}

func (c *testCluster) destroy(key slotKey) {
	c.t.Helper()
	ok, err := c.nodeFor(key).st.DestroyShard(context.Background(), c.setID, key.group, key.index)
	if err != nil {
		c.t.Fatalf("DestroyShard(%d/%d): %v", key.group, key.index, err)
	}
	if !ok {
		c.t.Fatalf("DestroyShard(%d/%d): shard was not present", key.group, key.index)
	}
}

func (c *testCluster) slotsWhere(pred func(key slotKey) bool) []contract.Slot {
	var out []contract.Slot
	for g := 0; g < c.params.GeoN+c.params.GeoK; g++ {
		for i := 0; i < c.groupSize(); i++ {
			key, _ := c.key(g, i)
			if pred(key) {
				out = append(out, c.slotFor(key))
			}
		}
	}
	return out
}

// readAll reads every shard of the set back over HTTP (all must be present).
func (c *testCluster) readAll() [][]byte {
	c.t.Helper()
	shards := make([][]byte, c.params.TotalShards())
	for g := 0; g < c.params.GeoN+c.params.GeoK; g++ {
		for i := 0; i < c.groupSize(); i++ {
			key, _ := c.key(g, i)
			rc, _, err := c.client.GetShard(context.Background(), c.endpointFor(key), c.setID, g, i)
			if err != nil {
				c.t.Fatalf("GetShard(%d/%d) after repair: %v", g, i, err)
			}
			payload, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				c.t.Fatalf("read shard(%d/%d): %v", g, i, err)
			}
			shards[g*c.groupSize()+i] = payload
		}
	}
	return shards
}

func (c *testCluster) decodeAndCompare(t *testing.T) {
	t.Helper()
	shards := c.readAll()
	decoded, err := c.codec.Decode(shards, c.geom)
	if err != nil {
		t.Fatalf("Decode after repair: %v", err)
	}
	if !bytes.Equal(decoded, c.payload) {
		t.Fatalf("decoded payload differs after repair: got %d bytes, want %d", len(decoded), len(c.payload))
	}
}

func (c *testCluster) newExecutor(coord Coordinator) *Executor {
	c.t.Helper()
	e, err := New(Options{
		Client:      c.client,
		Coordinator: coord,
		Worker:      "test-worker",
		Logger:      discardLogger(),
	})
	if err != nil {
		c.t.Fatalf("repair.New: %v", err)
	}
	return e
}

type fakeCoordinator struct {
	jobs       []*contract.RepairJob
	claimed    []string
	commits    []contract.RepairResult
	commitErr  error
	claimCalls int
}

func (f *fakeCoordinator) ClaimRepairJob(_ context.Context, worker string) (*contract.RepairJob, error) {
	f.claimCalls++
	if len(f.jobs) == 0 {
		return nil, nil
	}
	job := f.jobs[0]
	f.jobs = f.jobs[1:]
	f.claimed = append(f.claimed, worker)
	return job, nil
}

func (f *fakeCoordinator) CommitRepair(_ context.Context, r contract.RepairResult) error {
	f.commits = append(f.commits, r)
	return f.commitErr
}

func TestLocalRepairReconstructsLostInnerShards(t *testing.T) {
	ctx := context.Background()
	c := newTestCluster(t, testParams, 64<<10, 6)
	c.putAll()

	// Lose three shards from geo group 0 (≤ local_k = 4).
	lost := []slotKey{{0, 0}, {0, 3}, {0, 5}}
	for _, key := range lost {
		c.destroy(key)
	}
	lostSet := map[slotKey]bool{}
	for _, key := range lost {
		lostSet[key] = true
	}

	job := &contract.RepairJob{
		JobID:      "job-local-1",
		Type:       "local",
		ShardSetID: c.setID,
		ChunkIndex: 0,
		Generation: 7,
		Params:     c.params,
		Sources:    c.slotsWhere(func(k slotKey) bool { return k.group == 0 && !lostSet[k] }),
		Targets:    c.slotsWhere(func(k slotKey) bool { return k.group == 0 && lostSet[k] }),
	}
	exec := c.newExecutor(nil)
	res := exec.Execute(ctx, job)
	if !res.OK {
		t.Fatalf("local repair failed: %s", res.Err)
	}
	if res.JobID != job.JobID || res.ShardSetID != c.setID || res.Generation != 7 {
		t.Fatalf("result identity = %+v", res)
	}
	if len(res.Checksums) != len(lost) {
		t.Fatalf("checksums = %d, want %d", len(res.Checksums), len(lost))
	}
	for i, key := range lost {
		idx := key.group*c.groupSize() + key.index
		if res.Checksums[i] != shard.Sum64(c.shards[idx]) {
			t.Fatalf("target %d/%d checksum = %016x, want %016x", key.group, key.index,
				res.Checksums[i], shard.Sum64(c.shards[idx]))
		}
	}
	c.decodeAndCompare(t)
}

func TestGeoRepairReconstructsLostGroup(t *testing.T) {
	ctx := context.Background()
	c := newTestCluster(t, testParams, 48<<10, 6)
	c.putAll()

	// Lose the whole geo group 1 (a Nexus outage).
	for i := 0; i < c.groupSize(); i++ {
		c.destroy(slotKey{1, i})
	}

	job := &contract.RepairJob{
		JobID:      "job-geo-1",
		Type:       "geo",
		ShardSetID: c.setID,
		ChunkIndex: 0,
		Generation: 11,
		Params:     c.params,
		Sources:    c.slotsWhere(func(k slotKey) bool { return k.group != 1 }),
		Targets:    c.slotsWhere(func(k slotKey) bool { return k.group == 1 }),
	}
	exec := c.newExecutor(nil)
	res := exec.Execute(ctx, job)
	if !res.OK {
		t.Fatalf("geo repair failed: %s", res.Err)
	}
	if len(res.Checksums) != c.groupSize() {
		t.Fatalf("checksums = %d, want %d", len(res.Checksums), c.groupSize())
	}
	// Every repaired shard must be byte-identical to the original encoding.
	for i := 0; i < c.groupSize(); i++ {
		idx := 1*c.groupSize() + i
		if res.Checksums[i] != shard.Sum64(c.shards[idx]) {
			t.Fatalf("repaired group-1 shard %d checksum mismatch", i)
		}
	}
	c.decodeAndCompare(t)
}

func TestGeoRepairFromTieredSourcesOnly(t *testing.T) {
	// Sources may be exactly local_n shards per surviving group (the read-path
	// minimum), not the full 20.
	ctx := context.Background()
	c := newTestCluster(t, testParams, 32<<10, 6)
	c.putAll()
	for i := 0; i < c.groupSize(); i++ {
		c.destroy(slotKey{2, i})
	}
	job := &contract.RepairJob{
		JobID: "job-geo-min", Type: "geo", ShardSetID: c.setID,
		Generation: 3, Params: c.params,
		Sources: c.slotsWhere(func(k slotKey) bool {
			return k.group != 2 && k.index < c.params.LocalN
		}),
		Targets: c.slotsWhere(func(k slotKey) bool { return k.group == 2 }),
	}
	exec := c.newExecutor(nil)
	res := exec.Execute(ctx, job)
	if !res.OK {
		t.Fatalf("geo repair from minimum sources failed: %s", res.Err)
	}
	c.decodeAndCompare(t)
}

func TestRebalanceCopiesBytesWithoutDecoding(t *testing.T) {
	ctx := context.Background()
	c := newTestCluster(t, testParams, 16<<10, 8)
	c.putAll()

	// Drain three slots onto the two spare nodes (indices 6 and 7).
	keys := []slotKey{{0, 1}, {1, 2}, {2, 3}}
	job := &contract.RepairJob{
		JobID: "job-rebalance", Type: "rebalance", ShardSetID: c.setID,
		Generation: 1, Params: c.params,
	}
	for i, key := range keys {
		src := c.slotFor(key)
		job.Sources = append(job.Sources, src)
		dst := contract.Slot{GeoGroup: key.group, LocalIndex: key.index,
			Endpoint: c.nodes[6+i%2].endpoint()}
		job.Targets = append(job.Targets, dst)
	}
	exec := c.newExecutor(nil)
	res := exec.Execute(ctx, job)
	if !res.OK {
		t.Fatalf("rebalance failed: %s", res.Err)
	}
	for i, key := range keys {
		idx := key.group*c.groupSize() + key.index
		rc, _, err := c.client.GetShard(ctx, job.Targets[i].Endpoint, c.setID, key.group, key.index)
		if err != nil {
			t.Fatalf("read rebalanced shard %d: %v", i, err)
		}
		got, _ := io.ReadAll(rc)
		rc.Close()
		if !bytes.Equal(got, c.shards[idx]) {
			t.Fatalf("rebalanced shard %d bytes differ", i)
		}
	}
}

func TestRunOnceClaimsAndCommits(t *testing.T) {
	ctx := context.Background()
	c := newTestCluster(t, testParams, 8<<10, 4)
	c.putAll()
	lost := []slotKey{{0, 2}}
	c.destroy(lost[0])

	job := &contract.RepairJob{
		JobID: "job-run-1", Type: "local", ShardSetID: c.setID,
		Generation: 9, Params: c.params,
		Sources: c.slotsWhere(func(k slotKey) bool { return k.group == 0 }),
		Targets: c.slotsWhere(func(k slotKey) bool { return k.group == 0 && k.index == 2 }),
	}
	coord := &fakeCoordinator{jobs: []*contract.RepairJob{job}}
	exec := c.newExecutor(coord)

	worked, err := exec.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !worked {
		t.Fatal("RunOnce reported no work")
	}
	if len(coord.claimed) != 1 || coord.claimed[0] != "test-worker" {
		t.Fatalf("claimed = %v", coord.claimed)
	}
	if len(coord.commits) != 1 {
		t.Fatalf("commits = %d, want 1", len(coord.commits))
	}
	commit := coord.commits[0]
	if !commit.OK || commit.JobID != "job-run-1" || commit.Generation != 9 {
		t.Fatalf("commit = %+v", commit)
	}

	// No more jobs → no work, no commit.
	worked, err = exec.RunOnce(ctx)
	if err != nil || worked {
		t.Fatalf("second RunOnce = (%v, %v), want (false, nil)", worked, err)
	}
	if len(coord.commits) != 1 {
		t.Fatalf("commits after no-work claim = %d", len(coord.commits))
	}
}

func TestRunOnceTreatsLostCASAsSuccess(t *testing.T) {
	ctx := context.Background()
	c := newTestCluster(t, testParams, 8<<10, 4)
	c.putAll()
	c.destroy(slotKey{0, 0})

	job := &contract.RepairJob{
		JobID: "job-cas", Type: "local", ShardSetID: c.setID,
		Generation: 5, Params: c.params,
		Sources: c.slotsWhere(func(k slotKey) bool { return k.group == 0 }),
		Targets: c.slotsWhere(func(k slotKey) bool { return k.group == 0 && k.index == 0 }),
	}
	coord := &fakeCoordinator{jobs: []*contract.RepairJob{job}, commitErr: contract.ErrConflict}
	exec := c.newExecutor(coord)

	worked, err := exec.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce with lost CAS returned error: %v", err)
	}
	if !worked {
		t.Fatal("RunOnce reported no work")
	}
	if len(coord.commits) != 1 {
		t.Fatalf("commits = %d, want 1", len(coord.commits))
	}
}

func TestInvalidJobsFailCleanly(t *testing.T) {
	ctx := context.Background()
	c := newTestCluster(t, testParams, 4<<10, 2)
	exec := c.newExecutor(nil)

	cases := []struct {
		name string
		job  *contract.RepairJob
		want error
	}{
		{
			name: "no targets",
			job:  &contract.RepairJob{JobID: "x", Type: "local", ShardSetID: c.setID, Params: c.params, Sources: []contract.Slot{c.slotFor(slotKey{0, 0})}},
			want: ErrNoTargets,
		},
		{
			name: "no sources",
			job:  &contract.RepairJob{JobID: "x", Type: "local", ShardSetID: c.setID, Params: c.params, Targets: []contract.Slot{c.slotFor(slotKey{0, 0})}},
			want: ErrInvalidJob,
		},
		{
			name: "unknown type",
			job: &contract.RepairJob{JobID: "x", Type: "astral-projection", ShardSetID: c.setID, Params: c.params,
				Sources: []contract.Slot{c.slotFor(slotKey{0, 0})}, Targets: []contract.Slot{c.slotFor(slotKey{0, 1})}},
			want: ErrInvalidJob,
		},
		{
			name: "bad params",
			job: &contract.RepairJob{JobID: "x", Type: "local", ShardSetID: c.setID,
				Params:  ec.Params{GeoN: 0},
				Sources: []contract.Slot{c.slotFor(slotKey{0, 0})}, Targets: []contract.Slot{c.slotFor(slotKey{0, 1})}},
			want: ErrInvalidJob,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := exec.Execute(ctx, tc.job)
			if res.OK {
				t.Fatal("invalid job reported OK")
			}
			if res.Err == "" {
				t.Fatal("invalid job has empty Err")
			}
		})
	}
}

func TestTooFewSourcesFails(t *testing.T) {
	ctx := context.Background()
	c := newTestCluster(t, testParams, 4<<10, 3)
	c.putAll()
	// Keep only 5 of the 20 shards in group 0 available.
	job := &contract.RepairJob{
		JobID: "job-starved", Type: "local", ShardSetID: c.setID, Params: c.params,
		Sources: c.slotsWhere(func(k slotKey) bool { return k.group == 0 && k.index < 5 }),
		Targets: c.slotsWhere(func(k slotKey) bool { return k.group == 0 && k.index == 10 }),
	}
	exec := c.newExecutor(nil)
	res := exec.Execute(ctx, job)
	if res.OK {
		t.Fatal("starved repair reported OK")
	}
	if !contains(res.Err, "not enough source shards") && !contains(res.Err, "not enough source") {
		t.Fatalf("unexpected failure message %q", res.Err)
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

// readPackageSources returns the non-test Go sources of this package.
func readPackageSources() (map[string][]byte, error) {
	entries, err := os.ReadDir(".")
	if err != nil {
		return nil, err
	}
	out := make(map[string][]byte)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			return nil, err
		}
		out[name] = src
	}
	return out, nil
}

// TestExecuteNeverNeedsAKey is a structural guard: the repair package must not
// depend on key material. If someone adds such an import this test fails.
func TestExecuteNeverNeedsAKey(t *testing.T) {
	// The check is intentionally simple and self-contained: the repair package
	// source files must not import internal/crypto or key-service packages.
	// (The test lives here so the invariant is enforced by `make test`.)
	blocked := []string{"internal/crypto", "internal/keyservice", "kmip"}
	files, err := readPackageSources()
	if err != nil {
		t.Fatalf("read package sources: %v", err)
	}
	for name, src := range files {
		for _, b := range blocked {
			if bytes.Contains(src, []byte(b)) {
				t.Fatalf("repair package file %s references %q: repair must be key-less", name, b)
			}
		}
	}
}
