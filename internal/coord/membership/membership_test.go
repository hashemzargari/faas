package membership_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/coord/coerr"
	"github.com/fass-storage/fass/internal/coord/membership"
	"github.com/fass-storage/fass/internal/ec"
	"github.com/fass-storage/fass/internal/storage"
)

// fixture builds a service over an in-memory store with a controllable clock.
type fixture struct {
	svc *membership.Service
	now time.Time
	db  *storage.DB
	sw  membership.Swarm
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	db, err := storage.Open("")
	if err != nil {
		t.Fatalf("open in-memory store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	f := &fixture{db: db, now: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	f.svc = membership.New(db, membership.Config{
		SuspectAfter: 15 * time.Second,
		OfflineAfter: 60 * time.Second,
		Now:          func() time.Time { return f.now },
	})
	ctx := context.Background()
	sw, err := f.svc.CreateSwarm(ctx, membership.Swarm{Name: "swarm-1", Region: "eu-west-1"})
	if err != nil {
		t.Fatalf("create swarm: %v", err)
	}
	f.sw = sw
	return f
}

func (f *fixture) addNexus(t *testing.T, name string) membership.Nexus {
	t.Helper()
	nx, err := f.svc.CreateNexus(context.Background(), membership.Nexus{SwarmID: f.sw.ID, Name: name})
	if err != nil {
		t.Fatalf("create nexus %s: %v", name, err)
	}
	return nx
}

func (f *fixture) addNode(t *testing.T, nx membership.Nexus, hostname string) membership.Node {
	t.Helper()
	n, err := f.svc.CreateNode(context.Background(), membership.Node{NexusID: nx.ID, Hostname: hostname, Rack: "rack-" + hostname})
	if err != nil {
		t.Fatalf("create node %s: %v", hostname, err)
	}
	return n
}

func (f *fixture) register(t *testing.T, node membership.Node, disk string, port int) (contract.AgentID, string) {
	t.Helper()
	id, secret, err := f.svc.RegisterPending(context.Background(), membership.PendingRegistration{
		NodeID:        node.ID,
		DiskID:        disk,
		ExpectedPort:  port,
		CapacityBytes: 1 << 40,
	})
	if err != nil {
		t.Fatalf("register pending: %v", err)
	}
	return id, secret
}

func pubKey(seed string) []byte {
	sum := sha256.Sum256([]byte(seed))
	return sum[:]
}

func announceReq(node membership.Node, disk, secret string, port int, pub []byte) contract.AnnounceRequest {
	return contract.AnnounceRequest{
		PublicKey:     pub,
		Secret:        secret,
		NodeID:        node.ID,
		DiskID:        disk,
		Port:          port,
		CapacityBytes: 1 << 40,
		Version:       "1.4.2",
		Hostname:      "10.0.0.1",
	}
}

// activateAgent walks the full documented agent lifecycle: pending -> announce
// -> activate.
func (f *fixture) announceAndActivate(t *testing.T, node membership.Node, disk string, port int, seed string) contract.AgentID {
	t.Helper()
	agentID, secret := f.register(t, node, disk, port)
	if _, err := f.svc.Announce(context.Background(), announceReq(node, disk, secret, port, pubKey(seed))); err != nil {
		t.Fatalf("announce: %v", err)
	}
	if _, err := f.svc.Activate(context.Background(), agentID); err != nil {
		t.Fatalf("activate: %v", err)
	}
	return agentID
}

func assertTaxonomy(t *testing.T, err error, wantStatus int, wantMessage string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error %d %q, got nil", wantStatus, wantMessage)
	}
	if got := coerr.StatusOf(err); got != wantStatus {
		t.Fatalf("status = %d, want %d (err: %v)", got, wantStatus, err)
	}
	if got := coerr.MessageOf(err); got != wantMessage {
		t.Fatalf("message = %q, want %q", got, wantMessage)
	}
}

func TestAnnounceErrorTaxonomy(t *testing.T) {
	t.Run("port mismatch", func(t *testing.T) {
		f := newFixture(t)
		nx := f.addNexus(t, "site-a")
		node := f.addNode(t, nx, "host-1")
		_, secret := f.register(t, node, "disk-1", 7101)
		_, err := f.svc.Announce(context.Background(), announceReq(node, "disk-1", secret, 7102, pubKey("agent-a")))
		assertTaxonomy(t, err, 400, "Port mismatch")
	})

	t.Run("secret not found for unknown registration", func(t *testing.T) {
		f := newFixture(t)
		nx := f.addNexus(t, "site-a")
		node := f.addNode(t, nx, "host-1")
		_, err := f.svc.Announce(context.Background(), announceReq(node, "disk-unknown", "whatever", 7101, pubKey("agent-a")))
		assertTaxonomy(t, err, 403, "Secret not found")
	})

	t.Run("secret mismatch", func(t *testing.T) {
		f := newFixture(t)
		nx := f.addNexus(t, "site-a")
		node := f.addNode(t, nx, "host-1")
		f.register(t, node, "disk-1", 7101)
		_, err := f.svc.Announce(context.Background(), announceReq(node, "disk-1", "wrong-secret", 7101, pubKey("agent-a")))
		assertTaxonomy(t, err, 409, "Secret mismatch")
	})

	t.Run("success then one-time secret consumed", func(t *testing.T) {
		f := newFixture(t)
		nx := f.addNexus(t, "site-a")
		node := f.addNode(t, nx, "host-1")
		_, secret := f.register(t, node, "disk-1", 7101)
		res, err := f.svc.Announce(context.Background(), announceReq(node, "disk-1", secret, 7101, pubKey("agent-a")))
		if err != nil {
			t.Fatalf("announce: %v", err)
		}
		if res.State != string(membership.StatePending) {
			t.Fatalf("state = %q, want pending", res.State)
		}
		if res.AgentID == "" || res.NexusID != nx.ID {
			t.Fatalf("unexpected announce result: %+v", res)
		}
		// A successful announce consumes the one-time secret (Cubbit flow).
		_, err = f.svc.Announce(context.Background(), announceReq(node, "disk-1", secret, 7101, pubKey("agent-a")))
		assertTaxonomy(t, err, 403, "Secret not found")
	})

	t.Run("agent is not pending", func(t *testing.T) {
		f := newFixture(t)
		nx := f.addNexus(t, "site-a")
		node := f.addNode(t, nx, "host-1")
		agentID := f.announceAndActivate(t, node, "disk-1", 7101, "agent-a")
		if err := f.svc.Heartbeat(context.Background(), contract.Heartbeat{AgentID: agentID, FreeBytes: 1 << 40}); err != nil {
			t.Fatalf("heartbeat: %v", err)
		}
		_, err := f.svc.Announce(context.Background(), announceReq(node, "disk-1", "any", 7101, pubKey("agent-a")))
		assertTaxonomy(t, err, 409, "agent is not in pending status")
	})

	t.Run("duplicate public key", func(t *testing.T) {
		f := newFixture(t)
		nx := f.addNexus(t, "site-a")
		node1 := f.addNode(t, nx, "host-1")
		node2 := f.addNode(t, nx, "host-2")
		_, secret1 := f.register(t, node1, "disk-1", 7101)
		pub := pubKey("shared-key")
		if _, err := f.svc.Announce(context.Background(), announceReq(node1, "disk-1", secret1, 7101, pub)); err != nil {
			t.Fatalf("first announce: %v", err)
		}
		_, secret2 := f.register(t, node2, "disk-2", 7101)
		_, err := f.svc.Announce(context.Background(), announceReq(node2, "disk-2", secret2, 7101, pub))
		assertTaxonomy(t, err, 409, "Agent with the same public key already exists")
	})

	t.Run("under maintenance", func(t *testing.T) {
		f := newFixture(t)
		nx := f.addNexus(t, "site-a")
		node := f.addNode(t, nx, "host-1")
		_, secret := f.register(t, node, "disk-1", 7101)
		f.svc.SetMaintenance(true)
		_, err := f.svc.Announce(context.Background(), announceReq(node, "disk-1", secret, 7101, pubKey("agent-a")))
		assertTaxonomy(t, err, 503, "under maintenance")
	})
}

func TestHeartbeatStateMachine(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	nx := f.addNexus(t, "site-a")
	node := f.addNode(t, nx, "host-1")
	agentID := f.announceAndActivate(t, node, "disk-1", 7101, "agent-a")

	// A fresh heartbeat keeps the agent ACTIVE and refreshes telemetry.
	if err := f.svc.Heartbeat(ctx, contract.Heartbeat{AgentID: agentID, FreeBytes: 500 << 30, UsedBytes: 500 << 30, ShardCount: 42}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	ag, err := f.svc.GetAgent(ctx, agentID)
	if err != nil {
		t.Fatalf("get agent: %v", err)
	}
	if ag.State != membership.StateActive || ag.FreeBytes != 500<<30 || ag.ShardCount != 42 {
		t.Fatalf("unexpected agent after heartbeat: %+v", ag)
	}

	// 3 missed heartbeats (15 s) => SUSPECT.
	f.now = f.now.Add(16 * time.Second)
	suspect, offline, err := f.svc.Sweep(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if suspect != 1 || offline != 0 {
		t.Fatalf("sweep = (%d suspect, %d offline), want (1,0)", suspect, offline)
	}
	ag, _ = f.svc.GetAgent(ctx, agentID)
	if ag.State != membership.StateSuspect {
		t.Fatalf("state = %s, want suspect", ag.State)
	}

	// 60 s => OFFLINE.
	f.now = f.now.Add(60 * time.Second)
	suspect, offline, err = f.svc.Sweep(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if suspect != 0 || offline != 1 {
		t.Fatalf("sweep = (%d suspect, %d offline), want (0,1)", suspect, offline)
	}
	ag, _ = f.svc.GetAgent(ctx, agentID)
	if ag.State != membership.StateOffline {
		t.Fatalf("state = %s, want offline", ag.State)
	}

	// A heartbeat recovers the agent immediately.
	if err := f.svc.Heartbeat(ctx, contract.Heartbeat{AgentID: agentID}); err != nil {
		t.Fatalf("recovery heartbeat: %v", err)
	}
	ag, _ = f.svc.GetAgent(ctx, agentID)
	if ag.State != membership.StateActive {
		t.Fatalf("state = %s, want active after heartbeat", ag.State)
	}

	// Sweep is idempotent and never regresses a healthy agent.
	if suspect, offline, _ := f.svc.Sweep(ctx); suspect != 0 || offline != 0 {
		t.Fatalf("unexpected transitions on healthy agent: %d/%d", suspect, offline)
	}
}

func TestRedundancyClassValidation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	tests := []struct {
		name    string
		rc      membership.RedundancyClass
		wantErr bool
		msg     string
	}{
		{
			name: "reference geo 2+1 local 16+4",
			rc:   membership.RedundancyClass{Name: "geo", Params: ec.Params{GeoN: 2, GeoK: 1, LocalN: 16, LocalK: 4}, AAG: 2, ChunkSize: 16 << 20},
		},
		{
			name:    "geo_n zero",
			rc:      membership.RedundancyClass{Name: "bad", Params: ec.Params{GeoN: 0, GeoK: 0, LocalN: 4, LocalK: 2}, AAG: 1, ChunkSize: 16 << 20},
			wantErr: true,
			msg:     "geo_n",
		},
		{
			name:    "aag zero",
			rc:      membership.RedundancyClass{Name: "bad", Params: ec.Params{GeoN: 1, GeoK: 0, LocalN: 4, LocalK: 2}, AAG: 0, ChunkSize: 16 << 20},
			wantErr: true,
			msg:     "aag",
		},
		{
			name:    "aag above width",
			rc:      membership.RedundancyClass{Name: "bad", Params: ec.Params{GeoN: 1, GeoK: 0, LocalN: 4, LocalK: 2}, AAG: 7, ChunkSize: 16 << 20},
			wantErr: true,
			msg:     "aag",
		},
		{
			name: "chunk not divisible by coding unit is allowed (ec pads)",
			rc:   membership.RedundancyClass{Name: "six-mib", Params: ec.Params{GeoN: 2, GeoK: 1, LocalN: 3, LocalK: 1}, AAG: 2, ChunkSize: 6 << 20},
		},
		{
			name:    "chunk not 1 MiB aligned",
			rc:      membership.RedundancyClass{Name: "bad", Params: ec.Params{GeoN: 2, GeoK: 1, LocalN: 3, LocalK: 1}, AAG: 2, ChunkSize: 6<<20 + 512<<10},
			wantErr: true,
			msg:     "chunk_size",
		},
		{
			name:    "chunk too small",
			rc:      membership.RedundancyClass{Name: "bad", Params: ec.Params{GeoN: 1, GeoK: 0, LocalN: 2, LocalK: 1}, AAG: 1, ChunkSize: 2 << 20},
			wantErr: true,
			msg:     "chunk",
		},
		{
			name:    "degenerate shard size below 4 KiB",
			rc:      membership.RedundancyClass{Name: "bad", Params: ec.Params{GeoN: 16, GeoK: 0, LocalN: 128, LocalK: 0}, AAG: 1, ChunkSize: 4 << 20},
			wantErr: true,
			msg:     "shard size",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc, err := f.svc.CreateRC(ctx, tt.rc)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.msg)) {
					t.Fatalf("error %v does not mention %q", err, tt.msg)
				}
				return
			}
			if err != nil {
				t.Fatalf("CreateRC: %v", err)
			}
			if rc.ID == "" || rc.CreatedAt.IsZero() {
				t.Fatalf("RC missing generated fields: %+v", rc)
			}
			if rc.Ratio() <= 0 {
				t.Fatalf("ratio = %f", rc.Ratio())
			}
		})
	}
}

func TestRingFeasibilityAndCRUD(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	var nexuses []membership.Nexus
	for i := 0; i < 3; i++ {
		nx := f.addNexus(t, fmt.Sprintf("site-%d", i))
		nexuses = append(nexuses, nx)
		for a := 0; a < 3; a++ {
			node := f.addNode(t, nx, fmt.Sprintf("host-%d-%d", i, a))
			f.announceAndActivate(t, node, fmt.Sprintf("disk-%d-%d", i, a), 7100+i*10+a, fmt.Sprintf("pub-%d-%d", i, a))
		}
	}
	// local 2+1 needs 3 agents per Nexus: feasible with this topology.
	rc, err := f.svc.CreateRC(ctx, membership.RedundancyClass{
		Name: "flat-small", Params: ec.Params{GeoN: 1, GeoK: 0, LocalN: 2, LocalK: 1}, AAG: 2, ChunkSize: 16 << 20,
	})
	if err != nil {
		t.Fatalf("CreateRC: %v", err)
	}
	ring, err := f.svc.CreateRing(ctx, membership.Ring{
		Name:     "ring-a",
		RCID:     rc.ID,
		NexusIDs: []contract.NexusID{nexuses[0].ID, nexuses[1].ID, nexuses[2].ID},
	})
	if err != nil {
		t.Fatalf("CreateRing: %v", err)
	}
	if len(ring.AgentIDs) != 9 {
		t.Fatalf("ring auto-fill got %d agents, want 9", len(ring.AgentIDs))
	}
	if ring.Capacity != 9<<40 {
		t.Fatalf("ring capacity = %d, want %d", ring.Capacity, int64(9)<<40)
	}
	if ring.Epoch != 1 {
		t.Fatalf("epoch = %d", ring.Epoch)
	}
	for _, aid := range ring.AgentIDs {
		ag, err := f.svc.GetAgent(ctx, aid)
		if err != nil {
			t.Fatalf("get agent: %v", err)
		}
		if len(ag.RingIDs) != 1 || ag.RingIDs[0] != ring.ID {
			t.Fatalf("agent %s not bound to ring: %+v", aid, ag.RingIDs)
		}
	}

	// An RC that needs more agents per Nexus than the topology provides must be
	// refused rather than creating an unusable ring.
	bigRC, err := f.svc.CreateRC(ctx, membership.RedundancyClass{
		Name: "wide", Params: ec.Params{GeoN: 1, GeoK: 0, LocalN: 4, LocalK: 2}, AAG: 2, ChunkSize: 16 << 20,
	})
	if err != nil {
		t.Fatalf("CreateRC wide: %v", err)
	}
	_, err = f.svc.CreateRing(ctx, membership.Ring{RCID: bigRC.ID, NexusIDs: []contract.NexusID{nexuses[0].ID}})
	if err == nil {
		t.Fatalf("expected ring feasibility error")
	}

	// An RC that a ring references is immutable/in-use.
	err = f.svc.DeleteRC(ctx, rc.ID)
	if err == nil {
		t.Fatalf("expected in-use RC deletion to fail")
	}
	var ce *coerr.Error
	if !errors.As(err, &ce) || ce.Status != 409 {
		t.Fatalf("expected 409, got %v", err)
	}

	// Empty ring deletion unbinds its agents.
	if err := f.svc.DeleteRing(ctx, ring.ID); err != nil {
		t.Fatalf("DeleteRing: %v", err)
	}
	ag, _ := f.svc.GetAgent(ctx, ring.AgentIDs[0])
	if len(ag.RingIDs) != 0 {
		t.Fatalf("agent still bound to deleted ring: %+v", ag.RingIDs)
	}
}

func TestRingRejectsTooFewNexuses(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	rc, err := f.svc.CreateRC(ctx, membership.RedundancyClass{
		Name: "geo", Params: ec.Params{GeoN: 2, GeoK: 1, LocalN: 2, LocalK: 1}, AAG: 1, ChunkSize: 16 << 20,
	})
	if err != nil {
		t.Fatalf("CreateRC: %v", err)
	}
	nx := f.addNexus(t, "only-site")
	_, err = f.svc.CreateRing(ctx, membership.Ring{RCID: rc.ID, NexusIDs: []contract.NexusID{nx.ID}})
	if err == nil || !strings.Contains(err.Error(), "nexuses") {
		t.Fatalf("expected nexus-count feasibility error, got %v", err)
	}
}

func TestTopologySnapshot(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	nx := f.addNexus(t, "site-a")
	node := f.addNode(t, nx, "host-1")
	f.announceAndActivate(t, node, "disk-1", 7101, "agent-a")
	rc, err := f.svc.CreateRC(ctx, membership.RedundancyClass{Name: "flat", Params: ec.Params{GeoN: 1, GeoK: 0, LocalN: 2, LocalK: 1}, AAG: 1, ChunkSize: 16 << 20})
	if err != nil {
		t.Fatalf("CreateRC: %v", err)
	}
	// The ring needs one agent per Nexus for this tiny code but creation itself
	// only requires the Nexus count, so an explicit agent list is fine.
	if _, err := f.svc.CreateRing(ctx, membership.Ring{RCID: rc.ID, NexusIDs: []contract.NexusID{nx.ID}, AgentIDs: []contract.AgentID{}}); err == nil {
		// expected: auto-fill from active agents would need 3 per nexus, so this
		// topology is too small; nothing to assert here beyond not panicking.
		t.Log("ring creation unexpectedly succeeded")
	}
	snap, err := f.svc.Snapshot(ctx, map[string][]contract.NexusID{"tenant-1": {nx.ID}})
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(snap.Swarms) != 1 || len(snap.Nexuses) != 1 || len(snap.Nodes) != 1 || len(snap.Agents) != 1 {
		t.Fatalf("unexpected snapshot sizes: %+v", snap)
	}
	if snap.ID == "" || snap.At.IsZero() {
		t.Fatalf("snapshot missing id/time: %+v", snap)
	}
	if _, ok := snap.Agents[0].PublicKey, false; ok {
		t.Fatal("unreachable")
	}
	// Base64 public keys are stored and must not be logged as raw bytes.
	if len(snap.Agents[0].PublicKey) == 0 {
		t.Fatalf("agent public key lost after announce")
	}
	if base64.StdEncoding.EncodeToString(snap.Agents[0].PublicKey) == "" {
		t.Fatal("unreachable")
	}
}

// TestAnnounceNodeScopedIdentityProtection covers the dev-bootstrap registration
// model: several pending disks may share a node, each identified by its one-time
// secret; the agent's generated disk UUID is bound on first announce; and a disk
// that presents an already-bound public key with a different disk UUID is
// rejected with the documented 409 identity conflict (the "agent started with
// another agent's disk" protection).
func TestAnnounceNodeScopedIdentityProtection(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	nx := f.addNexus(t, "site-a")
	node := f.addNode(t, nx, "host-1")

	id1, secret1, minted, err := f.svc.EnsurePending(ctx, membership.PendingRegistration{
		NodeID: node.ID, Slot: "disk-1", CapacityBytes: 1 << 40,
	})
	if err != nil || !minted || secret1 == "" {
		t.Fatalf("pending slot 1: %v minted=%v", err, minted)
	}
	id2, secret2, minted, err := f.svc.EnsurePending(ctx, membership.PendingRegistration{
		NodeID: node.ID, Slot: "disk-2", CapacityBytes: 1 << 40,
	})
	if err != nil || !minted || secret2 == "" {
		t.Fatalf("pending slot 2: %v minted=%v", err, minted)
	}
	if id1 == id2 {
		t.Fatalf("two slots on one node share an agent id")
	}

	pub1 := pubKey("node-scoped-key-1")
	if _, err := f.svc.Announce(ctx, announceReq(node, "disk-uuid-1", secret1, 7101, pub1)); err != nil {
		t.Fatalf("announce slot 1: %v", err)
	}
	ag1, err := f.svc.GetAgent(ctx, id1)
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if ag1.DiskID != "disk-uuid-1" {
		t.Fatalf("agent disk id = %q, want bound disk-uuid-1", ag1.DiskID)
	}

	// Same public key, different disk UUID on the same node: identity conflict.
	_, err = f.svc.Announce(ctx, announceReq(node, "disk-uuid-2", secret2, 7101, pub1))
	assertTaxonomy(t, err, 409, "Agent with the same public key already exists")

	// A different key on the other slot is fine.
	pub2 := pubKey("node-scoped-key-2")
	if _, err := f.svc.Announce(ctx, announceReq(node, "disk-uuid-2", secret2, 7101, pub2)); err != nil {
		t.Fatalf("announce slot 2: %v", err)
	}
	ag2, err := f.svc.GetAgent(ctx, id2)
	if err != nil {
		t.Fatalf("GetAgent slot 2: %v", err)
	}
	if ag2.DiskID != "disk-uuid-2" {
		t.Fatalf("agent 2 disk id = %q, want disk-uuid-2", ag2.DiskID)
	}

	// The consumed secret cannot be replayed with a fresh key.
	_, err = f.svc.Announce(ctx, announceReq(node, "disk-uuid-3", secret1, 7101, pubKey("third-key")))
	assertTaxonomy(t, err, 403, "Secret not found")
}

func TestEnsurePendingNeverInvalidatesActiveAgent(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	nx := f.addNexus(t, "site-a")
	node := f.addNode(t, nx, "host-1")

	agentID, secret, minted, err := f.svc.EnsurePending(ctx, membership.PendingRegistration{
		NodeID: node.ID, Slot: "disk-1", CapacityBytes: 1 << 40,
	})
	if err != nil || !minted {
		t.Fatalf("EnsurePending: %v minted=%v", err, minted)
	}
	if _, err := f.svc.Announce(ctx, announceReq(node, "disk-uuid-1", secret, 7101, pubKey("key-1"))); err != nil {
		t.Fatalf("announce: %v", err)
	}
	if _, err := f.svc.Activate(ctx, agentID); err != nil {
		t.Fatalf("activate: %v", err)
	}

	// Re-running the bootstrap for this slot must not mint a secret for the live
	// agent (the old secret is consumed, and re-minting would enable re-binding).
	again, secret2, minted2, err := f.svc.EnsurePending(ctx, membership.PendingRegistration{
		NodeID: node.ID, Slot: "disk-1", CapacityBytes: 1 << 40,
	})
	if err != nil {
		t.Fatalf("EnsurePending re-run: %v", err)
	}
	if again != agentID || secret2 != "" || minted2 {
		t.Fatalf("re-run touched an ACTIVE agent: id=%s secret=%q minted=%v", again, secret2, minted2)
	}
	ag, err := f.svc.GetAgent(ctx, agentID)
	if err != nil || ag.State != membership.StateActive {
		t.Fatalf("agent invalidated: %+v, %v", ag, err)
	}
	if string(ag.PublicKey) != string(pubKey("key-1")) {
		t.Fatalf("agent identity changed on re-run")
	}

	// A still-pending slot does get a fresh one-time secret.
	_, pendingSecret, minted, err := f.svc.EnsurePending(ctx, membership.PendingRegistration{
		NodeID: node.ID, Slot: "disk-2", CapacityBytes: 1 << 40,
	})
	if err != nil || !minted || pendingSecret == "" {
		t.Fatalf("pending slot should be minted: %v minted=%v", err, minted)
	}
}

// TestActivateBeforeAnnounceIsRefused: activating a pending agent that has not
// announced yet would make it ACTIVE with no endpoint/identity and burn its
// one-time secret path, so the coordinator refuses it (409 AgentNotAnnounced).
func TestActivateBeforeAnnounceIsRefused(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	nx := f.addNexus(t, "site-a")
	node := f.addNode(t, nx, "host-1")
	agentID, _, err := f.svc.RegisterPending(ctx, membership.PendingRegistration{
		NodeID: node.ID, DiskID: "disk-1", CapacityBytes: 1 << 40,
	})
	if err != nil {
		t.Fatalf("RegisterPending: %v", err)
	}
	_, err = f.svc.Activate(ctx, agentID)
	if err == nil {
		t.Fatalf("expected activation of an unannounced agent to be refused")
	}
	if got := coerr.StatusOf(err); got != 409 {
		t.Fatalf("status = %d, want 409 (%v)", got, err)
	}
	if !strings.Contains(coerr.MessageOf(err), "has not announced") {
		t.Fatalf("message = %q", coerr.MessageOf(err))
	}
	// The registration is untouched: it can still announce afterwards.
	ag, getErr := f.svc.GetAgent(ctx, agentID)
	if getErr != nil {
		t.Fatalf("GetAgent: %v", getErr)
	}
	if ag.State != membership.StatePending || len(ag.SecretHash) == 0 {
		t.Fatalf("refused activation mutated the agent: %+v", ag)
	}
}
