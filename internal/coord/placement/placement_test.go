package placement_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/coord/coerr"
	"github.com/fass-storage/fass/internal/coord/membership"
	"github.com/fass-storage/fass/internal/coord/placement"
	"github.com/fass-storage/fass/internal/ec"
)

const tib = int64(1) << 40

// topologySpec describes a synthetic cluster for the invariant suite.
type topologySpec struct {
	Nexuses       int
	NodesPerNexus int
	AgentsPerNode int
	Params        ec.Params
	AAG           int
}

// buildTopology creates a deterministic synthetic Swarm: Nexuses × Nodes × Agents,
// all ACTIVE with identical healthy scores, in one ring implementing one RC.
func buildTopology(t *testing.T, spec topologySpec) (membership.Snapshot, membership.RedundancyClass, membership.Ring) {
	t.Helper()
	rc := membership.RedundancyClass{
		ID:        "rc-ref",
		Name:      "reference geo 2+1 x local 4+2",
		Params:    spec.Params,
		AAG:       spec.AAG,
		ChunkSize: 16 << 20,
	}
	ring := membership.Ring{
		ID:    "ring-1",
		Name:  "ring-1",
		RCID:  rc.ID,
		Epoch: 3,
	}
	snap := membership.Snapshot{
		ID:                "snap-1",
		RedundancyClasses: []membership.RedundancyClass{rc},
	}
	for n := 0; n < spec.Nexuses; n++ {
		nexusID := contract.NexusID(fmt.Sprintf("nx-%d", n))
		snap.Nexuses = append(snap.Nexuses, membership.Nexus{
			ID:      nexusID,
			SwarmID: "swarm-1",
			Name:    string(nexusID),
			Region:  "eu-west-1",
		})
		ring.NexusIDs = append(ring.NexusIDs, nexusID)
		for nd := 0; nd < spec.NodesPerNexus; nd++ {
			nodeID := contract.NodeID(fmt.Sprintf("node-%d-%d", n, nd))
			snap.Nodes = append(snap.Nodes, membership.Node{
				ID:       nodeID,
				NexusID:  nexusID,
				Hostname: string(nodeID),
				Rack:     fmt.Sprintf("rack-%d-%d", n, nd/2),
			})
			for a := 0; a < spec.AgentsPerNode; a++ {
				agentID := contract.AgentID(fmt.Sprintf("agent-%d-%d-%d", n, nd, a))
				ag := membership.Agent{
					ID:            agentID,
					NodeID:        nodeID,
					NexusID:       nexusID,
					DiskID:        fmt.Sprintf("disk-%s", agentID),
					Hostname:      fmt.Sprintf("10.0.%d.%d", n, nd*10+a+1),
					Endpoint:      fmt.Sprintf("10.0.%d.%d:7101", n, nd*10+a+1),
					Port:          7101,
					CapacityBytes: tib,
					FreeBytes:     tib,
					State:         membership.StateActive,
					UptimeScore:   1.0,
					Reputation:    1.0,
					BWHeadroom:    1.0,
					RTTScore:      0.5,
					RingIDs:       []contract.RingID{ring.ID},
				}
				snap.Agents = append(snap.Agents, ag)
				ring.AgentIDs = append(ring.AgentIDs, agentID)
				ring.Capacity += ag.CapacityBytes
			}
		}
	}
	snap.Rings = []membership.Ring{ring}
	return snap, rc, ring
}

func reqRC(shardSet string, params ec.Params, rcID string) contract.PlacementRequest {
	return contract.PlacementRequest{
		ShardSetID: contract.ShardSetID(shardSet),
		Params:     params,
		ChunkBytes: 16 << 20,
		TenantID:   "tenant-1",
		ProjectID:  "project-1",
		RCID:       rcID,
	}
}

// assertInvariants is the shared acceptance function: every returned placement
// must satisfy the documented hard constraints and shard-index order.
func assertInvariants(t *testing.T, p contract.Placement, params ec.Params, aag int, snap membership.Snapshot, ring *membership.Ring) {
	t.Helper()
	perGroup := params.ShardsPerGroup()
	wantSlots := params.TotalShards()
	total := params.GeoN + params.GeoK
	if len(p.Slots) != wantSlots {
		t.Fatalf("slots = %d, want %d", len(p.Slots), wantSlots)
	}

	// 1. Slots are in shard-index order: index = geo_group*perGroup + local_index.
	for i, sl := range p.Slots {
		if sl.GeoGroup != i/perGroup || sl.LocalIndex != i%perGroup {
			t.Fatalf("slot %d is (group %d, index %d), want (%d,%d)", i, sl.GeoGroup, sl.LocalIndex, i/perGroup, i%perGroup)
		}
		if sl.AgentID == "" || sl.NodeID == "" || sl.NexusID == "" || sl.Endpoint == "" {
			t.Fatalf("slot %d is incomplete: %+v", i, sl)
		}
	}

	// 2. Distinct Nexus per geo group, and geo_n+geo_k distinct Nexuses total.
	groupNexus := make(map[int]contract.NexusID)
	nexusSet := make(map[contract.NexusID]bool)
	for _, sl := range p.Slots {
		if existing, ok := groupNexus[sl.GeoGroup]; ok && existing != sl.NexusID {
			t.Fatalf("geo group %d spans nexuses %s and %s", sl.GeoGroup, existing, sl.NexusID)
		}
		groupNexus[sl.GeoGroup] = sl.NexusID
		nexusSet[sl.NexusID] = true
	}
	if len(groupNexus) != total {
		t.Fatalf("got %d geo groups, want %d", len(groupNexus), total)
	}
	if len(nexusSet) != total {
		t.Fatalf("placement spans %d nexuses, want %d distinct", len(nexusSet), total)
	}

	// 3. AAG: at most `aag` shards of this shard set per Node.
	nodeCount := make(map[contract.NodeID]int)
	// 4. One shard per agent per shard set, and every slot's agent is ACTIVE.
	agentSeen := make(map[contract.AgentID]bool)
	for _, sl := range p.Slots {
		nodeCount[sl.NodeID]++
		if nodeCount[sl.NodeID] > aag {
			t.Fatalf("node %s hosts %d shards, AAG is %d", sl.NodeID, nodeCount[sl.NodeID], aag)
		}
		if agentSeen[sl.AgentID] {
			t.Fatalf("agent %s used twice in one shard set", sl.AgentID)
		}
		agentSeen[sl.AgentID] = true
		ag, ok := snap.AgentByID(sl.AgentID)
		if !ok {
			t.Fatalf("slot references unknown agent %s", sl.AgentID)
		}
		if ag.State != membership.StateActive {
			t.Fatalf("slot references agent %s in state %s", ag.ID, ag.State)
		}
		if ag.NodeID != sl.NodeID || ag.NexusID != sl.NexusID {
			t.Fatalf("slot topology does not match agent %s", ag.ID)
		}
		if ring != nil && len(ring.AgentIDs) > 0 {
			found := false
			for _, id := range ring.AgentIDs {
				if id == ag.ID {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("agent %s is not a member of ring %s", ag.ID, ring.ID)
			}
		}
	}
}

func TestPlacementInvariantsOnThreeNexusTopology(t *testing.T) {
	spec := topologySpec{Nexuses: 3, NodesPerNexus: 3, AgentsPerNode: 3, Params: ec.Params{GeoN: 2, GeoK: 1, LocalN: 4, LocalK: 2}, AAG: 2}
	snap, rc, ring := buildTopology(t, spec)
	engine := placement.New(placement.DefaultConfig())

	p, err := engine.Place(context.Background(), reqRC("shard-set-1", ec.Params{}, rc.ID), snap)
	if err != nil {
		t.Fatalf("Place: %v", err)
	}
	if p.RingID != ring.ID {
		t.Fatalf("ring = %s, want %s", p.RingID, ring.ID)
	}
	if p.Generation != ring.Epoch {
		t.Fatalf("generation = %d, want %d", p.Generation, ring.Epoch)
	}
	assertInvariants(t, p, rc.Params, rc.AAG, snap, &ring)
}

func TestPlacementDeterministicReplay(t *testing.T) {
	spec := topologySpec{Nexuses: 3, NodesPerNexus: 3, AgentsPerNode: 3, Params: ec.Params{GeoN: 2, GeoK: 1, LocalN: 4, LocalK: 2}, AAG: 2}
	snap, rc, ring := buildTopology(t, spec)
	engine := placement.New(placement.DefaultConfig())
	req := reqRC("shard-set-replay", ec.Params{}, rc.ID)

	first, err := engine.Place(context.Background(), req, snap)
	if err != nil {
		t.Fatalf("Place: %v", err)
	}
	for i := 0; i < 25; i++ {
		got, err := engine.Place(context.Background(), req, snap)
		if err != nil {
			t.Fatalf("Place iteration %d: %v", i, err)
		}
		if len(got.Slots) != len(first.Slots) {
			t.Fatalf("iteration %d: slot count changed", i)
		}
		for j := range got.Slots {
			if got.Slots[j] != first.Slots[j] {
				t.Fatalf("iteration %d: slot %d changed: %+v != %+v", i, j, got.Slots[j], first.Slots[j])
			}
		}
	}
	// A shuffled copy of the same topology must not change the decision: inputs
	// are a set, not a sequence.
	shuffled := snap
	shuffled.Agents = append([]membership.Agent(nil), snap.Agents...)
	for i := len(shuffled.Agents) - 1; i > 0; i-- {
		j := (i * 7) % (i + 1)
		shuffled.Agents[i], shuffled.Agents[j] = shuffled.Agents[j], shuffled.Agents[i]
	}
	again, err := engine.Place(context.Background(), req, shuffled)
	if err != nil {
		t.Fatalf("Place shuffled: %v", err)
	}
	for j := range again.Slots {
		if again.Slots[j] != first.Slots[j] {
			t.Fatalf("slot %d depends on agent input order: %+v != %+v", j, again.Slots[j], first.Slots[j])
		}
	}
	assertInvariants(t, first, rc.Params, rc.AAG, snap, &ring)
}

func TestPlacementExcludeAgentsDisplacement(t *testing.T) {
	spec := topologySpec{Nexuses: 3, NodesPerNexus: 3, AgentsPerNode: 3, Params: ec.Params{GeoN: 2, GeoK: 1, LocalN: 4, LocalK: 2}, AAG: 2}
	snap, rc, ring := buildTopology(t, spec)
	engine := placement.New(placement.DefaultConfig())

	base, err := engine.Place(context.Background(), reqRC("shard-set-disp", ec.Params{}, rc.ID), snap)
	if err != nil {
		t.Fatalf("Place: %v", err)
	}
	excluded := base.Slots[0].AgentID
	req := reqRC("shard-set-disp", ec.Params{}, rc.ID)
	req.ExcludeAgents = []contract.AgentID{excluded}
	got, err := engine.Place(context.Background(), req, snap)
	if err != nil {
		t.Fatalf("Place with exclusion: %v", err)
	}
	for _, sl := range got.Slots {
		if sl.AgentID == excluded {
			t.Fatalf("excluded agent %s was used", excluded)
		}
	}
	assertInvariants(t, got, rc.Params, rc.AAG, snap, &ring)
}

func TestPlacementAAGCapIsHard(t *testing.T) {
	// local_n+local_k = 6 slots must fit in a nexus with AAG 2 per node.
	okSpec := topologySpec{Nexuses: 3, NodesPerNexus: 3, AgentsPerNode: 3, Params: ec.Params{GeoN: 1, GeoK: 0, LocalN: 4, LocalK: 2}, AAG: 2}
	snap, rc, ring := buildTopology(t, okSpec)
	engine := placement.New(placement.DefaultConfig())
	p, err := engine.Place(context.Background(), reqRC("set-aag-ok", ec.Params{}, rc.ID), snap)
	if err != nil {
		t.Fatalf("Place: %v", err)
	}
	assertInvariants(t, p, rc.Params, rc.AAG, snap, &ring)

	// The same topology with AAG 1 can only host 3 shards per nexus, so a
	// 6-slot group is impossible: placement must refuse, not overcommit.
	tight := okSpec
	tight.AAG = 1
	snapTight, rcTight, _ := buildTopology(t, tight)
	_, err = engine.Place(context.Background(), reqRC("set-aag-tight", ec.Params{}, rcTight.ID), snapTight)
	if err == nil {
		t.Fatalf("expected insufficient-capacity error with AAG=1")
	}
	if coerr.StatusOf(err) != 507 {
		t.Fatalf("status = %d, want 507 (InsufficientStorage): %v", coerr.StatusOf(err), err)
	}
}

func TestPlacementGeoFenceIsAbsolute(t *testing.T) {
	spec := topologySpec{Nexuses: 3, NodesPerNexus: 3, AgentsPerNode: 3, Params: ec.Params{GeoN: 2, GeoK: 1, LocalN: 4, LocalK: 2}, AAG: 2}
	snap, rc, _ := buildTopology(t, spec)
	engine := placement.New(placement.DefaultConfig())

	// The code needs geo_n+geo_k = 3 Nexuses; a fence of 2 can never satisfy it.
	snap.GeoFence = map[string][]contract.NexusID{"tenant-1": {"nx-0", "nx-1"}}
	_, err := engine.Place(context.Background(), reqRC("set-fence-2", ec.Params{}, rc.ID), snap)
	if err == nil {
		t.Fatalf("expected placement to fail inside a 2-nexus geo-fence")
	}
	if coerr.StatusOf(err) != 507 {
		t.Fatalf("status = %d, want 507: %v", coerr.StatusOf(err), err)
	}

	// With a 3-nexus fence the same request succeeds and touches only fenced Nexuses.
	snap.GeoFence = map[string][]contract.NexusID{"tenant-1": {"nx-0", "nx-1", "nx-2"}}
	p, err := engine.Place(context.Background(), reqRC("set-fence-3", ec.Params{}, rc.ID), snap)
	if err != nil {
		t.Fatalf("Place in fence: %v", err)
	}
	for _, sl := range p.Slots {
		switch sl.NexusID {
		case "nx-0", "nx-1", "nx-2":
		default:
			t.Fatalf("slot landed outside the geo-fence: %s", sl.NexusID)
		}
	}

	// A different tenant with no fence is unaffected by another tenant's fence.
	snap.GeoFence = map[string][]contract.NexusID{"tenant-1": {"nx-0", "nx-1", "nx-2"}}
	other := reqRC("set-fence-other", ec.Params{}, rc.ID)
	other.TenantID = "tenant-2"
	if _, err := engine.Place(context.Background(), other, snap); err != nil {
		t.Fatalf("unfenced tenant should place freely: %v", err)
	}
}

func TestPlacementRingFullPctStopsPlacement(t *testing.T) {
	spec := topologySpec{Nexuses: 3, NodesPerNexus: 3, AgentsPerNode: 3, Params: ec.Params{GeoN: 2, GeoK: 1, LocalN: 4, LocalK: 2}, AAG: 2}
	snap, rc, ring := buildTopology(t, spec)
	engine := placement.New(placement.DefaultConfig())
	// 86% full: above ring_full_pct = 85.
	snap.Rings[0].UsedBytes = ring.Capacity * 86 / 100
	_, err := engine.Place(context.Background(), reqRC("set-full", ec.Params{}, rc.ID), snap)
	if err == nil {
		t.Fatalf("expected placement to stop above ring_full_pct")
	}
	if coerr.StatusOf(err) != 507 {
		t.Fatalf("status = %d, want 507: %v", coerr.StatusOf(err), err)
	}
}

func TestPlacementCapacityHeadroom(t *testing.T) {
	spec := topologySpec{Nexuses: 3, NodesPerNexus: 3, AgentsPerNode: 3, Params: ec.Params{GeoN: 1, GeoK: 0, LocalN: 4, LocalK: 2}, AAG: 2}
	snap, rc, _ := buildTopology(t, spec)
	engine := placement.New(placement.DefaultConfig())

	// The required shard is 16 MiB / (1*4) = 4 MiB; with headroom 1.15 an agent
	// needs ~4.6 MiB. Starve nexus nx-2 so it cannot host anything.
	for i := range snap.Agents {
		if snap.Agents[i].NexusID == "nx-2" {
			snap.Agents[i].FreeBytes = 1 << 20 // 1 MiB < 4.6 MiB
		}
	}
	req := reqRC("set-headroom", ec.Params{}, rc.ID)
	req.Params = ec.Params{} // RC provides params
	p, err := engine.Place(context.Background(), req, snap)
	if err != nil {
		t.Fatalf("Place: %v", err)
	}
	assertInvariants(t, p, rc.Params, rc.AAG, snap, nil)
	for _, sl := range p.Slots {
		if sl.NexusID == "nx-2" {
			t.Fatalf("placement used a starved agent: %+v", sl)
		}
	}
}

func TestPlacementDegradedNexusExcluded(t *testing.T) {
	spec := topologySpec{Nexuses: 3, NodesPerNexus: 3, AgentsPerNode: 3, Params: ec.Params{GeoN: 2, GeoK: 1, LocalN: 4, LocalK: 2}, AAG: 2}
	snap, rc, _ := buildTopology(t, spec)
	engine := placement.New(placement.DefaultConfig())
	for i := range snap.Nexuses {
		if snap.Nexuses[i].ID == "nx-1" {
			snap.Nexuses[i].WriteDegraded = true
		}
	}
	_, err := engine.Place(context.Background(), reqRC("set-degraded", ec.Params{}, rc.ID), snap)
	if err == nil {
		t.Fatalf("expected failure: only 2 of 3 required nexuses are writable")
	}
	if coerr.StatusOf(err) != 507 {
		t.Fatalf("status = %d, want 507: %v", coerr.StatusOf(err), err)
	}
}

func TestPlacementRejectsInfeasibleParams(t *testing.T) {
	snap, _, _ := buildTopology(t, topologySpec{Nexuses: 3, NodesPerNexus: 3, AgentsPerNode: 3, Params: ec.Params{GeoN: 1, GeoK: 0, LocalN: 4, LocalK: 2}, AAG: 2})
	engine := placement.New(placement.DefaultConfig())
	tests := []struct {
		name string
		req  contract.PlacementRequest
	}{
		{"empty", contract.PlacementRequest{ShardSetID: "s"}},
		{"bad geo", reqRC("s", ec.Params{GeoN: 0, GeoK: 0, LocalN: 4, LocalK: 2}, "")},
		{"unknown rc", reqRC("s", ec.Params{}, "rc-missing")},
		{"unknown ring", contract.PlacementRequest{ShardSetID: "s", RingID: "ring-missing"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := engine.Place(context.Background(), tt.req, snap); err == nil {
				t.Fatalf("expected an error")
			}
		})
	}
}

func TestPlacementImplicitRingWithoutCatalogue(t *testing.T) {
	spec := topologySpec{Nexuses: 3, NodesPerNexus: 3, AgentsPerNode: 3, Params: ec.Params{GeoN: 1, GeoK: 0, LocalN: 4, LocalK: 2}, AAG: 2}
	snap, _, _ := buildTopology(t, spec)
	snap.Rings = nil // no ring catalogue: dev-mode implicit ring
	engine := placement.New(placement.DefaultConfig())
	p, err := engine.Place(context.Background(), reqRC("set-implicit", ec.Params{GeoN: 1, GeoK: 0, LocalN: 4, LocalK: 2}, ""), snap)
	if err != nil {
		t.Fatalf("Place: %v", err)
	}
	if p.RingID != "" {
		t.Fatalf("implicit ring should have an empty id, got %s", p.RingID)
	}
	assertInvariants(t, p, ec.Params{GeoN: 1, GeoK: 0, LocalN: 4, LocalK: 2}, 2, snap, nil)
}

func TestPlacementErrorsAreTyped(t *testing.T) {
	engine := placement.New(placement.DefaultConfig())
	_, err := engine.Place(context.Background(), reqRC("s", ec.Params{GeoN: 2, GeoK: 1, LocalN: 4, LocalK: 2}, ""), membership.Snapshot{})
	if err == nil {
		t.Fatal("expected error")
	}
	var ce *coerr.Error
	if !errors.As(err, &ce) {
		t.Fatalf("error %v is not a *coerr.Error", err)
	}
	if ce.Status != 507 {
		t.Fatalf("status %d, want 507", ce.Status)
	}
}
