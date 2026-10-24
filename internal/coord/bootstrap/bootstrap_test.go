package bootstrap_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/coord/auth"
	"github.com/fass-storage/fass/internal/coord/bootstrap"
	"github.com/fass-storage/fass/internal/coord/membership"
	"github.com/fass-storage/fass/internal/coord/meta"
	"github.com/fass-storage/fass/internal/ec"
	"github.com/fass-storage/fass/internal/storage"
)

type fixture struct {
	db  storage.Store
	m   *meta.Service
	a   *auth.Service
	mem *membership.Service
	now time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	db, err := storage.Open("")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	f := &fixture{db: db, now: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	f.m = meta.New(db)
	f.m.SetClock(func() time.Time { return f.now })
	f.a = auth.New(db, f.m)
	f.a.SetClock(func() time.Time { return f.now })
	f.mem = membership.New(db, membership.Config{Now: func() time.Time { return f.now }})
	return f
}

func (f *fixture) run(t *testing.T, cfg bootstrap.Config) bootstrap.Payload {
	t.Helper()
	payload, err := bootstrap.Run(context.Background(), f.m, f.a, f.mem, cfg)
	if err != nil {
		t.Fatalf("bootstrap.Run: %v", err)
	}
	return payload
}

func TestBootstrapCreatesDevCluster(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	cfg := bootstrap.DevConfig(dir)
	payload := f.run(t, cfg)

	if payload.AccessKeyID != bootstrap.DevAccessKeyID || payload.Secret != bootstrap.DevAccessKeySecret {
		t.Fatalf("payload credentials = %+v", payload)
	}
	if payload.RCID != bootstrap.DevRCID || payload.RingID != bootstrap.DevRingID || payload.Bucket != bootstrap.DevBucket {
		t.Fatalf("payload ids = %+v", payload)
	}
	if payload.Region != "eu-west-1" || payload.TenantID != bootstrap.DevTenantID || payload.ProjectID != bootstrap.DevProjectID {
		t.Fatalf("payload tenant/region = %+v", payload)
	}
	if len(payload.Agents) != 12 {
		t.Fatalf("payload agents = %d, want 12", len(payload.Agents))
	}
	seenSlot := map[string]bool{}
	perNode := map[contract.NodeID]int{}
	for _, ag := range payload.Agents {
		if ag.NodeID == "" || ag.NexusID == "" || ag.DiskID == "" || ag.Secret == "" {
			t.Fatalf("incomplete agent payload: %+v", ag)
		}
		slot := string(ag.NodeID) + "/" + ag.DiskID
		if seenSlot[slot] {
			t.Fatalf("duplicate agent slot %s", slot)
		}
		seenSlot[slot] = true
		perNode[ag.NodeID]++
	}
	for node, n := range perNode {
		if n != 2 {
			t.Fatalf("node %s has %d agents, want 2", node, n)
		}
	}
	// Nexus ordering and composition.
	wantNexus := map[string]int{"nexus-a": 4, "nexus-b": 4, "nexus-c": 4}
	for _, ag := range payload.Agents {
		wantNexus[string(ag.NexusID)]--
	}
	for nx, left := range wantNexus {
		if left != 0 {
			t.Fatalf("nexus %s has an unexpected number of agent slots (left=%d)", nx, left)
		}
	}

	ctx := context.Background()
	rc, err := f.mem.GetRC(ctx, bootstrap.DevRCID)
	if err != nil {
		t.Fatalf("GetRC: %v", err)
	}
	if rc.Params != (ec.Params{GeoN: 2, GeoK: 1, LocalN: 3, LocalK: 1}) || rc.AAG != 2 || rc.ChunkSize != 6<<20 {
		t.Fatalf("dev RC = %+v", rc)
	}
	ring, err := f.mem.GetRing(ctx, bootstrap.DevRingID)
	if err != nil {
		t.Fatalf("GetRing: %v", err)
	}
	if len(ring.AgentIDs) != 12 || len(ring.NexusIDs) != 3 {
		t.Fatalf("ring = %d agents over %d nexuses", len(ring.AgentIDs), len(ring.NexusIDs))
	}
	if ring.Capacity != 12*bootstrap.DevAgentCapacity {
		t.Fatalf("ring capacity = %d", ring.Capacity)
	}
	for _, aid := range ring.AgentIDs {
		ag, err := f.mem.GetAgent(ctx, aid)
		if err != nil {
			t.Fatalf("GetAgent: %v", err)
		}
		if ag.State != membership.StatePending {
			t.Fatalf("agent %s state = %s, want pending", ag.ID, ag.State)
		}
		if len(ag.RingIDs) != 1 || ag.RingIDs[0] != ring.ID {
			t.Fatalf("agent %s ring binding = %v", ag.ID, ag.RingIDs)
		}
	}

	bucket, err := f.m.GetBucket(ctx, bootstrap.DevBucket)
	if err != nil {
		t.Fatalf("GetBucket: %v", err)
	}
	if bucket.TenantID != bootstrap.DevTenantID || bucket.ProjectID != bootstrap.DevProjectID || bucket.DefaultRCID != bootstrap.DevRCID {
		t.Fatalf("bucket = %+v", bucket)
	}
	if bucket.CreatedAt.IsZero() {
		t.Fatalf("dev bucket has no creation time (breaks S3 ListBuckets clients)")
	}
	if _, err := f.m.GetTenant(ctx, bootstrap.DevTenantID); err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if _, err := f.m.GetProject(ctx, bootstrap.DevProjectID); err != nil {
		t.Fatalf("GetProject: %v", err)
	}
	principal, secret, err := f.a.VerifySignature(ctx, bootstrap.DevAccessKeyID)
	if err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	if string(secret) != bootstrap.DevAccessKeySecret || !principal.IsRoot {
		t.Fatalf("dev access key principal/secret mismatch: %+v", principal)
	}

	// The payload file is written for tooling that cannot scrape stdout.
	raw, err := os.ReadFile(filepath.Join(dir, "dev-bootstrap.json"))
	if err != nil {
		t.Fatalf("read payload file: %v", err)
	}
	var filePayload bootstrap.Payload
	if err := json.Unmarshal(raw, &filePayload); err != nil {
		t.Fatalf("decode payload file: %v", err)
	}
	if filePayload.RingID != payload.RingID || len(filePayload.Agents) != len(payload.Agents) {
		t.Fatalf("payload file differs from return value")
	}
}

func TestBootstrapIsIdempotentAndNeverInvalidatesActiveAgents(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	cfg := bootstrap.DevConfig(dir)
	ctx := context.Background()

	first := f.run(t, cfg)
	firstSecrets := map[contract.NodeID]string{}
	for _, ag := range first.Agents {
		firstSecrets[ag.NodeID] = ag.Secret
	}

	// Provision one agent end to end (announce + activate) as the real agent does.
	target := first.Agents[0]
	agentID, secret, minted, err := f.mem.EnsurePending(ctx, membership.PendingRegistration{
		NodeID:        target.NodeID,
		Slot:          target.DiskID,
		CapacityBytes: bootstrap.DevAgentCapacity,
	})
	if err != nil || !minted || secret == "" {
		t.Fatalf("EnsurePending for announce fixture: %v minted=%v", err, minted)
	}
	if _, err := f.mem.Announce(ctx, contract.AnnounceRequest{
		PublicKey:     []byte("ed25519-pubkey-of-" + string(target.NodeID)),
		Secret:        secret,
		NodeID:        target.NodeID,
		DiskID:        "agent-generated-disk-uuid",
		Port:          7101,
		CapacityBytes: bootstrap.DevAgentCapacity,
		Hostname:      "127.0.0.1",
	}); err != nil {
		t.Fatalf("announce: %v", err)
	}
	if _, err := f.mem.Activate(ctx, agentID); err != nil {
		t.Fatalf("activate: %v", err)
	}
	ringBefore, err := f.mem.GetRing(ctx, bootstrap.DevRingID)
	if err != nil {
		t.Fatalf("GetRing: %v", err)
	}

	// Second run: topology identical, ACTIVE agent untouched, pending agents get
	// fresh secrets (the previous ones were never consumed).
	second := f.run(t, cfg)
	if second.RingID != first.RingID || second.RCID != first.RCID || len(second.Agents) != len(first.Agents) {
		t.Fatalf("second run changed topology: %+v", second)
	}
	var activeSecret string
	for _, ag := range second.Agents {
		if ag.NodeID == target.NodeID && ag.DiskID == target.DiskID {
			activeSecret = ag.Secret
			continue
		}
		if ag.Secret == "" || ag.Secret == firstSecrets[ag.NodeID] {
			t.Fatalf("pending agent %s did not get a fresh secret", ag.NodeID)
		}
	}
	if activeSecret != "" {
		t.Fatalf("bootstrap re-minted a secret for an ACTIVE agent: %q", activeSecret)
	}
	active, err := f.mem.GetAgent(ctx, agentID)
	if err != nil {
		t.Fatalf("GetAgent after second bootstrap: %v", err)
	}
	if active.State != membership.StateActive {
		t.Fatalf("ACTIVE agent was invalidated: state=%s", active.State)
	}
	if string(active.PublicKey) != "ed25519-pubkey-of-"+string(target.NodeID) {
		t.Fatalf("ACTIVE agent public key changed: %q", active.PublicKey)
	}
	ringAfter, err := f.mem.GetRing(ctx, bootstrap.DevRingID)
	if err != nil {
		t.Fatalf("GetRing after second bootstrap: %v", err)
	}
	if ringAfter.Epoch != ringBefore.Epoch || len(ringAfter.AgentIDs) != len(ringBefore.AgentIDs) {
		t.Fatalf("ring changed on idempotent re-run: before=%+v after=%+v", ringBefore, ringAfter)
	}
	// The bucket is reused, not recreated under a new id.
	b1, _ := f.m.GetBucket(ctx, bootstrap.DevBucket)
	third := f.run(t, cfg)
	_ = third
	b2, _ := f.m.GetBucket(ctx, bootstrap.DevBucket)
	if b1.BucketID != b2.BucketID {
		t.Fatalf("bucket id changed across bootstrap runs")
	}
}

func TestBootstrapRejectsChangedRC(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.mem.CreateRC(ctx, membership.RedundancyClass{
		ID: "dev-rc", Name: "dev-rc",
		Params:    ec.Params{GeoN: 2, GeoK: 1, LocalN: 4, LocalK: 2},
		AAG:       2,
		ChunkSize: 16 << 20,
	}); err != nil {
		t.Fatalf("seed RC: %v", err)
	}
	if _, err := bootstrap.Run(ctx, f.m, f.a, f.mem, bootstrap.DevConfig(t.TempDir())); err == nil {
		t.Fatalf("expected bootstrap to refuse an incompatible existing RC")
	}
}

func TestDevConfigMatchesDocumentedTopology(t *testing.T) {
	cfg := bootstrap.DevConfig("")
	if cfg.NodesPerNexus != 2 || cfg.AgentsPerNode != 2 || len(cfg.Nexuses) != 3 {
		t.Fatalf("dev topology = %d nexuses × %d nodes × %d agents", len(cfg.Nexuses), cfg.NodesPerNexus, cfg.AgentsPerNode)
	}
	if cfg.Params != (ec.Params{GeoN: 2, GeoK: 1, LocalN: 3, LocalK: 1}) {
		t.Fatalf("dev params = %+v", cfg.Params)
	}
	if cfg.AAG != 2 || cfg.ChunkSize != 6<<20 {
		t.Fatalf("dev aag/chunk = %d/%d", cfg.AAG, cfg.ChunkSize)
	}
}
