// Package placement is the coordinator's deterministic placement engine.
//
// It implements docs/03-data-plane.md §4: hard constraints first (they are
// filters, never soft penalties), then the published five-axis weighted scorer,
// then a greedy max-min diversity pass. Two properties matter more than the
// score itself:
//
//   - Determinism: the same topology snapshot and shard_set_id always produce
//     the same slots. Ties are broken by HMAC-SHA256(shard_set_id, agent_id), so
//     a decision can be replayed from (shard_set_id, snapshot_id) during an
//     incident (docs/04 §5.3).
//   - Safety: AAG caps shards per Node, geo groups always land on distinct
//     Nexuses, tenant geo-fencing is absolute, and capacity headroom is checked
//     before a slot is handed out.
//
// Slots are returned in shard-index order:
//
//	index = geo_group * (local_n+local_k) + local_index
package placement

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"sort"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/coord/coerr"
	"github.com/fass-storage/fass/internal/coord/membership"
	"github.com/fass-storage/fass/internal/ec"
)

// Config carries the documented placement knobs (docs/04 §5.7).
type Config struct {
	// Headroom multiplies the bytes a slot needs before a candidate qualifies
	// (docs/03 §4.2 #2, default 1.15).
	Headroom float64
	// RingFullPct is the ring occupancy at which placement stops (default 85).
	RingFullPct float64
	// Weights are the five-axis scorer weights (docs/03 §4.3).
	Weights Weights
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Weights is the published scoring vector.
type Weights struct {
	Uptime     float64
	Load       float64
	Bandwidth  float64
	Reputation float64
	Capacity   float64
	RTT        float64
}

// DefaultWeights matches docs/03 §4.3 exactly.
var DefaultWeights = Weights{
	Uptime:     0.25,
	Load:       0.25,
	Bandwidth:  0.15,
	Reputation: 0.15,
	Capacity:   0.10,
	RTT:        0.10,
}

// DefaultConfig returns the documented defaults.
func DefaultConfig() Config {
	return Config{
		Headroom:    1.15,
		RingFullPct: 85,
		Weights:     DefaultWeights,
		Now:         time.Now,
	}
}

func (c Config) withDefaults() Config {
	if c.Headroom <= 0 {
		c.Headroom = 1.15
	}
	if c.RingFullPct <= 0 {
		c.RingFullPct = 85
	}
	if c.Weights == (Weights{}) {
		c.Weights = DefaultWeights
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

// Engine computes placements. It is stateless: all topology input arrives in the
// snapshot, which makes it trivially testable and safe for concurrent use.
type Engine struct {
	cfg Config
}

// New creates a placement engine.
func New(cfg Config) *Engine { return &Engine{cfg: cfg.withDefaults()} }

// Config returns the effective configuration.
func (e *Engine) Config() Config { return e.cfg }

// candidate is an agent that survived the hard constraints.
type candidate struct {
	ag        membership.Agent
	ring      membership.Ring
	baseScore float64
	tieBreak  []byte
}

// Place resolves the shard slots for one chunk.
//
// It returns contract.Placement with slots in shard-index order. RingID is the
// chosen ring (empty when the request carried no RC and the engine used the
// implicit all-topology ring).
func (e *Engine) Place(ctx context.Context, req contract.PlacementRequest, snap membership.Snapshot) (contract.Placement, error) {
	var out contract.Placement
	if err := ctx.Err(); err != nil {
		return out, err
	}
	params, rcID, err := e.resolveParams(req, snap)
	if err != nil {
		return out, err
	}
	if err := params.Validate(); err != nil {
		return out, fmt.Errorf("%w: %v", coerr.ErrInvalidRequest, err)
	}
	if req.ChunkBytes < 0 {
		return out, coerr.Invalidf("chunk_bytes must be >= 0")
	}
	chunkBytes := req.ChunkBytes
	if chunkBytes == 0 {
		chunkBytes = 16 << 20
	}

	ring, explicit, err := e.resolveRing(req, params, rcID, snap)
	if err != nil {
		return out, err
	}

	need := shardBytes(chunkBytes, params)
	totalBytes := int64(need) * int64(params.TotalShards())
	if explicit && ring.Capacity > 0 {
		limit := int64(float64(ring.Capacity) * e.cfg.RingFullPct / 100)
		if ring.UsedBytes+totalBytes > limit {
			return out, coerr.E(507, coerr.CodeInsufficientStorage,
				"ring %s is at %.1f%% (used %d + need %d > %.1f%% of %d)",
				ring.ID, ring.FullPct(), ring.UsedBytes, totalBytes, e.cfg.RingFullPct, ring.Capacity)
		}
	}

	excluded := make(map[contract.AgentID]bool, len(req.ExcludeAgents))
	for _, id := range req.ExcludeAgents {
		excluded[id] = true
	}
	fence := geoFenceFor(snap, req.TenantID)
	ringMembers := make(map[contract.AgentID]bool, len(ring.AgentIDs))
	for _, id := range ring.AgentIDs {
		ringMembers[id] = true
	}

	// 1. Hard filters (docs/03 §4.2). A candidate failing any filter is dropped;
	// no amount of score can rescue it.
	eligible := make([]candidate, 0, len(snap.Agents))
	for _, ag := range snap.Agents {
		if excluded[ag.ID] {
			continue
		}
		if !agentUsable(ag) {
			continue
		}
		if len(fence) > 0 && !containsNexus(fence, ag.NexusID) {
			continue
		}
		if explicit && len(ring.NexusIDs) > 0 && !containsNexus(ring.NexusIDs, ag.NexusID) {
			continue
		}
		if explicit && len(ring.AgentIDs) > 0 && !ringMembers[ag.ID] {
			continue // the agent belongs to another ring
		}
		if nx, ok := snap.NexusByID(ag.NexusID); !ok || nx.WriteDegraded {
			continue // Nexus flagged DEGRADED for writes (constraint #7)
		}
		if float64(ag.FreeBytes) < float64(need)*e.cfg.Headroom {
			continue // capacity headroom (constraint #2)
		}
		eligible = append(eligible, candidate{
			ag:        ag,
			ring:      ring,
			baseScore: e.score(ag),
			tieBreak:  e.tieBreak(req.ShardSetID, string(ag.ID)),
		})
	}
	if len(eligible) == 0 {
		return out, coerr.E(507, coerr.CodeInsufficientStorage, "no eligible agent satisfies the placement constraints")
	}
	sort.Slice(eligible, func(i, j int) bool {
		if eligible[i].baseScore != eligible[j].baseScore {
			return eligible[i].baseScore > eligible[j].baseScore
		}
		return bytes.Compare(eligible[i].tieBreak, eligible[j].tieBreak) < 0
	})

	// Group by Nexus, preserving the score order.
	byNexus := make(map[contract.NexusID][]candidate, len(snap.Nexuses))
	for _, c := range eligible {
		byNexus[c.ag.NexusID] = append(byNexus[c.ag.NexusID], c)
	}
	for nx := range byNexus {
		list := byNexus[nx]
		sort.Slice(list, func(i, j int) bool {
			if list[i].baseScore != list[j].baseScore {
				return list[i].baseScore > list[j].baseScore
			}
			return bytes.Compare(list[i].tieBreak, list[j].tieBreak) < 0
		})
		byNexus[nx] = list
	}

	nexusOrder := e.orderNexuses(req.ShardSetID, snap, byNexus, ring)
	if len(nexusOrder) < params.GeoN+params.GeoK {
		return out, coerr.E(507, coerr.CodeInsufficientStorage,
			"only %d eligible nexuses, code needs geo_n+geo_k = %d (geo-fence and AAG applied)",
			len(nexusOrder), params.GeoN+params.GeoK)
	}

	// 2. Geo-group selection + local greedy diversity, with replacement-nexus
	// retries when a Nexus cannot fill its local_n+local_k slots.
	var groups [][]candidate
	for _, nx := range nexusOrder {
		if len(groups) == params.GeoN+params.GeoK {
			break
		}
		filled, err := e.fillNexus(byNexus[nx], params, rcAAG(snap, ring), rackLookup(snap))
		if err != nil {
			continue // try the next Nexus; a short Nexus is simply unusable
		}
		groups = append(groups, filled)
	}
	if len(groups) < params.GeoN+params.GeoK {
		return out, coerr.E(507, coerr.CodeInsufficientStorage,
			"could only fill %d of %d geo groups (need local_n+local_k slots and AAG headroom per nexus)",
			len(groups), params.GeoN+params.GeoK)
	}

	// 3. Emit slots in shard-index order.
	perGroup := params.ShardsPerGroup()
	slots := make([]contract.Slot, 0, params.TotalShards())
	for g, group := range groups {
		for i := 0; i < perGroup; i++ {
			c := group[i]
			slots = append(slots, contract.Slot{
				GeoGroup:   g,
				LocalIndex: i,
				AgentID:    c.ag.ID,
				NodeID:     c.ag.NodeID,
				NexusID:    c.ag.NexusID,
				Endpoint:   c.ag.EndpointFor(),
			})
		}
	}
	generation := 1
	if explicit && ring.Epoch > 0 {
		generation = ring.Epoch
	}
	out = contract.Placement{
		ShardSetID: req.ShardSetID,
		RingID:     ring.ID,
		Slots:      slots,
		Generation: generation,
	}
	return out, nil
}

// resolveParams determines the effective codec parameters and RC id.
func (e *Engine) resolveParams(req contract.PlacementRequest, snap membership.Snapshot) (ec.Params, string, error) {
	if req.RCID != "" {
		rc, ok := snap.RCByID(req.RCID)
		if !ok {
			return ec.Params{}, "", coerr.E(404, "NoSuchRedundancyClass", "redundancy class %q does not exist", req.RCID)
		}
		if req.Params != (ec.Params{}) && req.Params != rc.Params {
			return ec.Params{}, "", coerr.Invalidf("params %+v do not match redundancy class %q (%+v)", req.Params, req.RCID, rc.Params)
		}
		return rc.Params, rc.ID, nil
	}
	if req.RingID != "" {
		ring, ok := snap.RingByID(req.RingID)
		if !ok {
			return ec.Params{}, "", coerr.E(404, "NoSuchRing", "ring %q does not exist", req.RingID)
		}
		rc, ok := snap.RCByID(ring.RCID)
		if !ok {
			return ec.Params{}, "", coerr.E(404, "NoSuchRedundancyClass", "redundancy class %q does not exist", ring.RCID)
		}
		return rc.Params, rc.ID, nil
	}
	if req.Params == (ec.Params{}) {
		return ec.Params{}, "", coerr.Invalidf("either params or rc_id is required")
	}
	return req.Params, "", nil
}

// resolveRing picks the ring to place into. Without an RC the engine uses an
// implicit ring over the whole eligible topology (dev-mode convenience) and
// reports an empty ring id.
func (e *Engine) resolveRing(req contract.PlacementRequest, params ec.Params, rcID string, snap membership.Snapshot) (membership.Ring, bool, error) {
	if req.RingID != "" {
		ring, ok := snap.RingByID(req.RingID)
		if !ok {
			return membership.Ring{}, true, coerr.E(404, "NoSuchRing", "ring %q does not exist", req.RingID)
		}
		if rcID != "" && ring.RCID != rcID {
			return membership.Ring{}, true, coerr.Invalidf("ring %q implements redundancy class %q, not %q", ring.ID, ring.RCID, rcID)
		}
		return ring, true, nil
	}
	var candidates []membership.Ring
	for _, ring := range snap.Rings {
		if rcID != "" && ring.RCID != rcID {
			continue
		}
		if rcID == "" {
			rc, ok := snap.RCByID(ring.RCID)
			if !ok || rc.Params != params {
				continue
			}
		}
		if ring.FullPct() >= e.cfg.RingFullPct {
			continue // docs/03 §4.6: stop placing at 85%
		}
		candidates = append(candidates, ring)
	}
	if len(candidates) == 0 {
		if rcID != "" || len(snap.Rings) > 0 {
			return membership.Ring{}, true, coerr.E(507, coerr.CodeInsufficientStorage, "no ring below ring_full_pct has capacity for this redundancy class")
		}
		// Implicit topology-wide ring (no ring catalogue configured).
		ring := membership.Ring{Epoch: 1}
		for _, ag := range snap.Agents {
			ring.Capacity += ag.CapacityBytes
		}
		return ring, false, nil
	}
	// Deterministic choice: least loaded, then lowest ring id.
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].FullPct() != candidates[j].FullPct() {
			return candidates[i].FullPct() < candidates[j].FullPct()
		}
		return candidates[i].ID < candidates[j].ID
	})
	return candidates[0], true, nil
}

// orderNexuses deterministically ranks the Nexuses that could host a geo group.
func (e *Engine) orderNexuses(shardSetID contract.ShardSetID, snap membership.Snapshot, byNexus map[contract.NexusID][]candidate, ring membership.Ring) []contract.NexusID {
	type ranked struct {
		id    contract.NexusID
		score float64
		tb    []byte
	}
	list := make([]ranked, 0, len(byNexus))
	for id, agents := range byNexus {
		if len(agents) == 0 {
			continue
		}
		var sum float64
		var free, capacity int64
		for _, c := range agents {
			sum += c.baseScore
			free += c.ag.FreeBytes
			capacity += c.ag.CapacityBytes
		}
		score := sum / float64(len(agents))
		if capacity > 0 {
			// Capacity balance: prefer Nexuses with more free space relative to
			// their size (docs/03 §4.3 "plus capacity balance").
			score += 0.1 * float64(free) / float64(capacity)
		}
		list = append(list, ranked{id: id, score: score, tb: e.tieBreak(shardSetID, "nexus/"+string(id))})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].score != list[j].score {
			return list[i].score > list[j].score
		}
		return bytes.Compare(list[i].tb, list[j].tb) < 0
	})
	out := make([]contract.NexusID, 0, len(list))
	for _, r := range list {
		out = append(out, r.id)
	}
	return out
}

// fillNexus performs the greedy max-min diversity pass inside one Nexus. It
// enforces the AAG cap (≤ aag shards per Node per shard set) and returns
// local_n+local_k distinct candidates in selection order (slot order).
func (e *Engine) fillNexus(cands []candidate, params ec.Params, aag int, rackOf func(contract.NodeID) string) ([]candidate, error) {
	need := params.ShardsPerGroup()
	if len(cands) < need {
		return nil, fmt.Errorf("nexus has %d candidates, need %d", len(cands), need)
	}
	if aag <= 0 {
		aag = 1
	}
	chosen := make([]candidate, 0, need)
	chosenSet := make(map[contract.AgentID]bool, need)
	nodeCount := make(map[contract.NodeID]int)
	for len(chosen) < need {
		best := -1
		bestEff := -1.0
		for i, c := range cands {
			if chosenSet[c.ag.ID] || nodeCount[c.ag.NodeID] >= aag {
				continue
			}
			eff := c.baseScore
			for _, prev := range chosen {
				eff *= 1 - proximity(c.ag, prev.ag, rackOf)
			}
			if eff > bestEff {
				bestEff, best = eff, i
			}
		}
		if best < 0 {
			return nil, fmt.Errorf("aag=%d prevents filling %d slots in nexus", aag, need)
		}
		c := cands[best]
		chosen = append(chosen, c)
		chosenSet[c.ag.ID] = true
		nodeCount[c.ag.NodeID]++
	}
	return chosen, nil
}

// proximity is the diversity penalty from docs/03 §4.3. Nexus-level proximity
// (0.05) never applies inside one geo group because groups span distinct
// Nexuses by construction.
func proximity(a, b membership.Agent, rackOf func(contract.NodeID) string) float64 {
	switch {
	case a.ID == b.ID:
		return 1.0
	case a.NodeID == b.NodeID:
		return 0.6
	case rackOf(a.NodeID) != "" && rackOf(a.NodeID) == rackOf(b.NodeID):
		return 0.2
	}
	return 0
}

// rackLookup builds a node→rack lookup from the snapshot.
func rackLookup(snap membership.Snapshot) func(contract.NodeID) string {
	racks := make(map[contract.NodeID]string, len(snap.Nodes))
	for _, n := range snap.Nodes {
		racks[n.ID] = n.Rack
	}
	return func(id contract.NodeID) string { return racks[id] }
}

// score implements docs/03 §4.3.
func (e *Engine) score(ag membership.Agent) float64 {
	w := e.cfg.Weights
	freeScore := 0.0
	if ag.CapacityBytes > 0 {
		freeScore = clamp01(float64(ag.FreeBytes) / float64(ag.CapacityBytes))
	}
	load := clamp01(ag.LoadEWMA)
	return w.Uptime*clamp01(ag.UptimeScore) +
		w.Load*(1-load) +
		w.Bandwidth*clamp01(ag.BWHeadroom) +
		w.Reputation*clamp01(ag.Reputation) +
		w.Capacity*freeScore +
		w.RTT*clamp01(ag.RTTScore)
}

// tieBreak is HMAC-SHA256(shard_set_id, agent_id): the documented deterministic
// tie-breaker (docs/03 §4.3).
func (e *Engine) tieBreak(shardSetID contract.ShardSetID, id string) []byte {
	mac := hmac.New(sha256.New, []byte(shardSetID))
	mac.Write([]byte(id))
	return mac.Sum(nil)
}

func shardBytes(chunkBytes int, p ec.Params) int {
	unit := p.GeoN * p.LocalN
	if unit <= 0 {
		return chunkBytes
	}
	return (chunkBytes + unit - 1) / unit
}

func agentUsable(ag membership.Agent) bool {
	switch ag.State {
	case membership.StateActive:
		return true
	default:
		return false
	}
}

func geoFenceFor(snap membership.Snapshot, tenant contract.TenantID) []contract.NexusID {
	if len(snap.GeoFence) == 0 {
		return nil
	}
	return snap.GeoFence[string(tenant)]
}

func containsNexus(list []contract.NexusID, id contract.NexusID) bool {
	for _, v := range list {
		if v == id {
			return true
		}
	}
	return false
}

// DefaultAAG is the anti-affinity used when the request carries no redundancy
// class (implicit dev-mode ring). It matches the documented default profile
// (docs/README "aag 2") and can be overridden by an RC.
const DefaultAAG = 2

// rcAAG returns the AAG for the ring's RC.
func rcAAG(snap membership.Snapshot, ring membership.Ring) int {
	if rc, ok := snap.RCByID(ring.RCID); ok && rc.AAG > 0 {
		return rc.AAG
	}
	return DefaultAAG
}

func clamp01(v float64) float64 {
	switch {
	case v < 0:
		return 0
	case v > 1:
		return 1
	}
	return v
}

// NeededBytes is the raw bytes one shard of a chunk occupies, including the 1.15
// headroom. It is exported so the coordinator can report capacity checks.
func NeededBytes(chunkBytes int, p ec.Params) int64 {
	return int64(float64(shardBytes(chunkBytes, p)) * 1.15)
}
