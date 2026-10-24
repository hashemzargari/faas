// Package membership is the coordinator's registry and health service: the
// Swarm → Nexus → Node → Agent topology, agent announce, heartbeats, the
// SUSPECT/OFFLINE state machine, and the Ring / RedundancyClass catalogue.
//
// It implements two published behaviours exactly:
//
//   - the announce error taxonomy of docs/07-wire-api.md §1.7 (status + message
//     strings are frozen; see the Err* values in internal/coord/coerr);
//   - the heartbeat-driven health transitions of docs/03 §5.1 and docs/04 §5.4:
//     three missed heartbeats (15 s) ⇒ SUSPECT, 60 s ⇒ OFFLINE, a heartbeat
//     recovers ACTIVE.
//
// RedundancyClass parameters are validated with ec.Params.Validate plus the
// feasibility rules of docs/03 §2.2 that only the coordinator can check
// (chunk-size divisibility, AAG bound, ring Nexuses ≥ geo_n+geo_k).
package membership

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/coord/coerr"
	"github.com/fass-storage/fass/internal/coord/id"
	"github.com/fass-storage/fass/internal/ec"
	"github.com/fass-storage/fass/internal/storage"
)

// State is an agent's lifecycle/health state.
type State string

const (
	StatePending         State = "pending"
	StateActive          State = "active"
	StateSuspect         State = "suspect"
	StateOffline         State = "offline"
	StateDecommissioning State = "decommissioning"
)

// Defaults from docs/04 §5.4 and docs/03 §5.1.
const (
	DefaultHeartbeatInterval = 5 * time.Second
	DefaultSuspectAfter      = 15 * time.Second
	DefaultOfflineAfter      = 60 * time.Second
	DefaultSecretTTL         = 24 * time.Hour
)

// Config tunes the health state machine. Zero values select the documented
// defaults.
type Config struct {
	HeartbeatInterval time.Duration
	SuspectAfter      time.Duration
	OfflineAfter      time.Duration
	SecretTTL         time.Duration
	// Maintenance makes announce return 503 "under maintenance" (the Cubbit
	// taxonomy has a dedicated code).
	Maintenance bool
	// Certificate is the PEM blob handed to an agent on successful announce.
	// Dev mode runs plaintext and leaves it nil.
	Certificate []byte
	// Now overrides the clock (tests).
	Now func() time.Time
}

func (c Config) withDefaults() Config {
	if c.HeartbeatInterval <= 0 {
		c.HeartbeatInterval = DefaultHeartbeatInterval
	}
	if c.SuspectAfter <= 0 {
		c.SuspectAfter = DefaultSuspectAfter
	}
	if c.OfflineAfter <= 0 {
		c.OfflineAfter = DefaultOfflineAfter
	}
	if c.SecretTTL <= 0 {
		c.SecretTTL = DefaultSecretTTL
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

// Swarm is the federation root.
type Swarm struct {
	ID        string    `json:"swarm_id"`
	Name      string    `json:"name"`
	Region    string    `json:"region"`
	CreatedAt time.Time `json:"created_at"`
}

// Nexus is a site / availability zone. Operator-declared, never inferred
// (docs/03 §7.3).
type Nexus struct {
	ID            contract.NexusID `json:"nexus_id"`
	SwarmID       string           `json:"swarm_id"`
	Name          string           `json:"name"`
	Region        string           `json:"region"`
	WriteDegraded bool             `json:"write_degraded"`
	CreatedAt     time.Time        `json:"created_at"`
}

// Node is a server inside a Nexus. Rack is used by the placement diversity
// pass; an empty rack means "unknown, treat the node as its own rack".
type Node struct {
	ID        contract.NodeID  `json:"node_id"`
	NexusID   contract.NexusID `json:"nexus_id"`
	Hostname  string           `json:"hostname"`
	Rack      string           `json:"rack"`
	CreatedAt time.Time        `json:"created_at"`
}

// Agent is one disk's daemon. Score fields are maintained from heartbeats and
// the repair/scrub feedback loop; they are the placement scorer's inputs.
type Agent struct {
	ID       contract.AgentID `json:"agent_id"`
	NodeID   contract.NodeID  `json:"node_id"`
	NexusID  contract.NexusID `json:"nexus_id"`
	DiskID   string           `json:"disk_id"`
	Hostname string           `json:"hostname"`
	Endpoint string           `json:"endpoint"`
	Port     int              `json:"port"`
	Version  string           `json:"version"`

	PublicKey     []byte    `json:"public_key,omitempty"`
	ExpectedPort  int       `json:"expected_port,omitempty"`
	SecretHash    []byte    `json:"secret_hash,omitempty"`
	SecretExpires time.Time `json:"secret_expires,omitempty"`

	CapacityBytes int64 `json:"capacity_bytes"`
	FreeBytes     int64 `json:"free_bytes"`
	UsedBytes     int64 `json:"used_bytes"`
	ShardCount    int64 `json:"shard_count"`

	State        State     `json:"state"`
	StateChanged time.Time `json:"state_changed"`
	LastSeen     time.Time `json:"last_seen"`
	RegisteredAt time.Time `json:"registered_at"`
	ActivatedAt  time.Time `json:"activated_at"`

	UptimeScore float64 `json:"uptime_score"`
	Reputation  float64 `json:"reputation"`
	LoadEWMA    float64 `json:"load_ewma"`
	BWHeadroom  float64 `json:"bw_headroom"`
	RTTScore    float64 `json:"rtt_score"`

	ScrubCursor     string `json:"scrub_cursor,omitempty"`
	InventoryDigest string `json:"inventory_digest,omitempty"`
	BandwidthBps    int64  `json:"bandwidth_bps,omitempty"`

	RingIDs []contract.RingID `json:"ring_ids,omitempty"`
}

// EndpointFor returns the shard transport endpoint. Callers persist Endpoint on
// announce, so this is only a defensive fallback.
func (a Agent) EndpointFor() string {
	if a.Endpoint != "" {
		return a.Endpoint
	}
	if a.Hostname != "" && a.Port > 0 {
		return fmt.Sprintf("%s:%d", a.Hostname, a.Port)
	}
	return ""
}

// RedundancyClass is an immutable coding profile (docs/03 §2.4: "new RC for
// changes").
type RedundancyClass struct {
	ID        string    `json:"rc_id"`
	Name      string    `json:"name"`
	Params    ec.Params `json:"params"`
	AAG       int       `json:"aag"`
	ChunkSize int       `json:"chunk_size"`
	CreatedAt time.Time `json:"created_at"`
}

// Ratio is the RC's storage overhead.
func (rc RedundancyClass) Ratio() float64 { return rc.Params.Ratio() }

// Ring is a bounded set of agents implementing one RedundancyClass (docs/03
// §4.6). Agents may belong to several rings.
type Ring struct {
	ID        contract.RingID    `json:"ring_id"`
	Name      string             `json:"name"`
	RCID      string             `json:"rc_id"`
	NexusIDs  []contract.NexusID `json:"nexus_ids"`
	AgentIDs  []contract.AgentID `json:"agent_ids"`
	Capacity  int64              `json:"capacity_bytes"`
	UsedBytes int64              `json:"used_bytes"`
	Epoch     int                `json:"epoch"`
	CreatedAt time.Time          `json:"created_at"`
}

// FullPct returns the ring's usage percentage.
func (r Ring) FullPct() float64 {
	if r.Capacity <= 0 {
		return 100
	}
	return 100 * float64(r.UsedBytes) / float64(r.Capacity)
}

// Snapshot is an immutable view of the topology used by the placement engine and
// the /v1/topology endpoint.
type Snapshot struct {
	ID                string                        `json:"snapshot_id"`
	At                time.Time                     `json:"at"`
	Swarms            []Swarm                       `json:"swarms"`
	Nexuses           []Nexus                       `json:"nexuses"`
	Nodes             []Node                        `json:"nodes"`
	Agents            []Agent                       `json:"agents"`
	Rings             []Ring                        `json:"rings"`
	RedundancyClasses []RedundancyClass             `json:"redundancy_classes"`
	GeoFence          map[string][]contract.NexusID `json:"geo_fence,omitempty"`
}

// AgentByID and RingByID are lookups over a snapshot.
func (s *Snapshot) AgentByID(id contract.AgentID) (Agent, bool) {
	for _, a := range s.Agents {
		if a.ID == id {
			return a, true
		}
	}
	return Agent{}, false
}

// RingByID returns a ring from the snapshot.
func (s *Snapshot) RingByID(id contract.RingID) (Ring, bool) {
	for _, r := range s.Rings {
		if r.ID == id {
			return r, true
		}
	}
	return Ring{}, false
}

// RCByID returns a redundancy class from the snapshot.
func (s *Snapshot) RCByID(id string) (RedundancyClass, bool) {
	for _, rc := range s.RedundancyClasses {
		if rc.ID == id {
			return rc, true
		}
	}
	return RedundancyClass{}, false
}

// NexusByID returns a nexus from the snapshot.
func (s *Snapshot) NexusByID(id contract.NexusID) (Nexus, bool) {
	for _, n := range s.Nexuses {
		if n.ID == id {
			return n, true
		}
	}
	return Nexus{}, false
}

// NodeByID returns a node from the snapshot.
func (s *Snapshot) NodeByID(id contract.NodeID) (Node, bool) {
	for _, n := range s.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return Node{}, false
}

var (
	spaceSwarms   = []byte("swarms")
	spaceNexuses  = []byte("nexuses")
	spaceNodes    = []byte("nodes")
	spaceAgents   = []byte("agents")
	spaceAgentPub = []byte("agents_by_pubkey")   // base64(pubkey) -> agent_id
	spaceAgentLoc = []byte("agents_by_location") // node_id,disk_id -> agent_id
	spaceRings    = []byte("rings")
	spaceRCs      = []byte("redundancy_classes")
)

// Service is the membership registry over a storage.DB.
type Service struct {
	db  *storage.DB
	cfg Config
}

// New creates the membership service.
func New(db *storage.DB, cfg Config) *Service {
	return &Service{db: db, cfg: cfg.withDefaults()}
}

// Config returns the effective configuration.
func (s *Service) Config() Config { return s.cfg }

// SetMaintenance toggles announce 503 behaviour at runtime (admin API).
func (s *Service) SetMaintenance(on bool) { s.cfg.Maintenance = on }

// Now returns the service clock.
func (s *Service) Now() time.Time { return s.cfg.Now() }

// ---------------------------------------------------------------------------
// Topology CRUD (swarm / nexus / node)
// ---------------------------------------------------------------------------

// CreateSwarm creates the federation root.
func (s *Service) CreateSwarm(ctx context.Context, sw Swarm) (Swarm, error) {
	if sw.Name == "" {
		return Swarm{}, coerr.Invalidf("swarm name is required")
	}
	if sw.ID == "" {
		sw.ID = id.New()
	}
	sw.CreatedAt = s.now()
	err := s.db.Update(ctx, func(tx *storage.WriteTx) error {
		if tx.Has(spaceSwarms, []byte(sw.ID)) {
			return coerr.E(409, coerr.CodeConflict, "swarm %q already exists", sw.ID)
		}
		return storage.PutJSON(tx, spaceSwarms, []byte(sw.ID), sw)
	})
	return sw, err
}

// CreateNexus registers a Nexus inside a swarm.
func (s *Service) CreateNexus(ctx context.Context, n Nexus) (Nexus, error) {
	if n.SwarmID == "" {
		return Nexus{}, coerr.Invalidf("swarm_id is required")
	}
	if n.Name == "" {
		return Nexus{}, coerr.Invalidf("nexus name is required")
	}
	if n.ID == "" {
		n.ID = contract.NexusID(id.New())
	}
	n.CreatedAt = s.now()
	err := s.db.Update(ctx, func(tx *storage.WriteTx) error {
		if !tx.Has(spaceSwarms, []byte(n.SwarmID)) {
			return coerr.E(404, "NoSuchSwarm", "swarm %q does not exist", n.SwarmID)
		}
		if tx.Has(spaceNexuses, []byte(n.ID)) {
			return coerr.E(409, coerr.CodeConflict, "nexus %q already exists", n.ID)
		}
		return storage.PutJSON(tx, spaceNexuses, []byte(n.ID), n)
	})
	return n, err
}

// CreateNode registers a server inside a Nexus.
func (s *Service) CreateNode(ctx context.Context, n Node) (Node, error) {
	if n.NexusID == "" {
		return Node{}, coerr.Invalidf("nexus_id is required")
	}
	if n.Hostname == "" {
		return Node{}, coerr.Invalidf("hostname is required")
	}
	if n.ID == "" {
		n.ID = contract.NodeID(id.New())
	}
	n.CreatedAt = s.now()
	err := s.db.Update(ctx, func(tx *storage.WriteTx) error {
		if !tx.Has(spaceNexuses, []byte(n.NexusID)) {
			return coerr.E(404, "NoSuchNexus", "nexus %q does not exist", n.NexusID)
		}
		if tx.Has(spaceNodes, []byte(n.ID)) {
			return coerr.E(409, coerr.CodeConflict, "node %q already exists", n.ID)
		}
		return storage.PutJSON(tx, spaceNodes, []byte(n.ID), n)
	})
	return n, err
}

// SetNexusWriteDegraded flags a Nexus as DEGRADED for writes (placement excludes
// it without failing over existing data).
func (s *Service) SetNexusWriteDegraded(ctx context.Context, nexus contract.NexusID, degraded bool) error {
	return s.db.Update(ctx, func(tx *storage.WriteTx) error {
		n, err := storage.GetJSON[Nexus](tx, spaceNexuses, []byte(nexus))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.E(404, "NoSuchNexus", "nexus %q does not exist", nexus)
		}
		if err != nil {
			return err
		}
		n.WriteDegraded = degraded
		return storage.PutJSON(tx, spaceNexuses, []byte(nexus), n)
	})
}

// ---------------------------------------------------------------------------
// Announce
// ---------------------------------------------------------------------------

// PendingRegistration is what the console/operator creates before a disk's
// agent boots: an expected node+disk identity, optionally with a fixed port,
// plus a one-time announce secret.
type PendingRegistration struct {
	AgentID       contract.AgentID
	NodeID        contract.NodeID
	DiskID        string
	ExpectedPort  int
	CapacityBytes int64
}

// RegisterPending creates a pending agent record and returns its one-time
// secret. The secret is stored only as a SHA-256 digest and is consumed by a
// successful announce.
func (s *Service) RegisterPending(ctx context.Context, reg PendingRegistration) (contract.AgentID, string, error) {
	if reg.NodeID == "" || reg.DiskID == "" {
		return "", "", coerr.Invalidf("node_id and disk_id are required")
	}
	if reg.ExpectedPort < 0 || reg.ExpectedPort > 65535 {
		return "", "", coerr.Invalidf("expected_port must be in 0..65535")
	}
	if reg.CapacityBytes < 0 {
		return "", "", coerr.Invalidf("capacity_bytes must be >= 0")
	}
	secret, err := id.NewSecret(32)
	if err != nil {
		return "", "", coerr.Wrap(err, 500, coerr.CodeInternal, coerr.ErrInternal.Message)
	}
	sum := sha256.Sum256([]byte(secret))
	now := s.now()
	agentID := reg.AgentID
	if agentID == "" {
		agentID = contract.AgentID(id.New())
	}
	err = s.db.Update(ctx, func(tx *storage.WriteTx) error {
		node, err := storage.GetJSON[Node](tx, spaceNodes, []byte(reg.NodeID))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.E(404, "NoSuchNode", "node %q does not exist", reg.NodeID)
		}
		if err != nil {
			return err
		}
		locKey := storage.JoinKey(string(reg.NodeID), reg.DiskID)
		if existing, err := tx.Get(spaceAgentLoc, locKey); err == nil {
			return coerr.E(409, coerr.CodeConflict, "agent for node %q disk %q is already registered (%s)", reg.NodeID, reg.DiskID, existing)
		} else if !errors.Is(err, storage.ErrNotFound) {
			return err
		}
		ag := Agent{
			ID:            agentID,
			NodeID:        reg.NodeID,
			NexusID:       node.NexusID,
			DiskID:        reg.DiskID,
			ExpectedPort:  reg.ExpectedPort,
			CapacityBytes: reg.CapacityBytes,
			FreeBytes:     reg.CapacityBytes,
			SecretHash:    sum[:],
			SecretExpires: now.Add(s.cfg.SecretTTL),
			State:         StatePending,
			StateChanged:  now,
			RegisteredAt:  now,
			// Neutral priors: a brand-new disk is treated as fully available with
			// average reputation until telemetry arrives.
			UptimeScore: 1.0,
			Reputation:  1.0,
			BWHeadroom:  1.0,
			RTTScore:    0.5,
		}
		if err := storage.PutJSON(tx, spaceAgents, []byte(ag.ID), ag); err != nil {
			return err
		}
		if err := tx.Put(spaceAgentLoc, locKey, []byte(ag.ID)); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return "", "", err
	}
	return agentID, secret, nil
}

// Announce implements the documented agent join protocol with Cubbit's exact
// error taxonomy (docs/07-wire-api.md §1.7).
//
// Evaluation order is fixed and tested:
//  1. maintenance ⇒ 503 under maintenance
//  2. request shape ⇒ 400 InvalidRequest
//  3. unknown node+disk (no pending registration) ⇒ 403 Secret not found
//  4. public key bound to a different agent ⇒ 409 duplicate public key
//  5. announced port differs from the operator-declared port ⇒ 400 Port mismatch
//  6. agent not pending ⇒ 409 agent is not in pending status
//  7. missing/expired secret ⇒ 403 Secret not found
//  8. wrong secret ⇒ 409 Secret mismatch
func (s *Service) Announce(ctx context.Context, req contract.AnnounceRequest) (contract.AnnounceResult, error) {
	if s.cfg.Maintenance {
		return contract.AnnounceResult{}, coerr.ErrMaintenance
	}
	if len(req.PublicKey) == 0 || req.NodeID == "" || req.DiskID == "" {
		return contract.AnnounceResult{}, coerr.Invalidf("public_key, node_id and disk_id are required")
	}
	if req.Port <= 0 || req.Port > 65535 {
		return contract.AnnounceResult{}, coerr.Invalidf("port must be in 1..65535")
	}
	if req.Secret == "" {
		return contract.AnnounceResult{}, coerr.ErrSecretNotFound
	}
	now := s.now()
	var result contract.AnnounceResult
	err := s.db.Update(ctx, func(tx *storage.WriteTx) error {
		locKey := storage.JoinKey(string(req.NodeID), req.DiskID)
		agentIDRaw, err := tx.Get(spaceAgentLoc, locKey)
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.ErrSecretNotFound
		}
		if err != nil {
			return err
		}
		ag, err := storage.GetJSON[Agent](tx, spaceAgents, agentIDRaw)
		if err != nil {
			return err
		}

		pubKey := base64.StdEncoding.EncodeToString(req.PublicKey)
		if owner, err := tx.Get(spaceAgentPub, []byte(pubKey)); err == nil && string(owner) != string(ag.ID) {
			return coerr.ErrDuplicatePublicKey
		} else if err != nil && !errors.Is(err, storage.ErrNotFound) {
			return err
		}

		if ag.ExpectedPort != 0 && req.Port != ag.ExpectedPort {
			return coerr.ErrPortMismatch
		}
		if ag.State != StatePending {
			return coerr.ErrNotPending
		}
		if len(ag.SecretHash) == 0 || now.After(ag.SecretExpires) {
			return coerr.ErrSecretNotFound
		}
		sum := sha256.Sum256([]byte(req.Secret))
		if subtle.ConstantTimeCompare(sum[:], ag.SecretHash) != 1 {
			return coerr.ErrSecretMismatch
		}

		// Success: bind the identity, consume the one-time secret, keep the agent
		// pending until an operator activates it (Cubbit's documented flow).
		ag.PublicKey = append([]byte(nil), req.PublicKey...)
		ag.Port = req.Port
		ag.Version = req.Version
		if req.Hostname != "" {
			ag.Hostname = req.Hostname
		}
		ag.Endpoint = ag.EndpointFor()
		if req.CapacityBytes > 0 {
			ag.CapacityBytes = req.CapacityBytes
			if ag.FreeBytes == 0 {
				ag.FreeBytes = req.CapacityBytes
			}
		}
		ag.SecretHash = nil
		ag.SecretExpires = time.Time{}
		ag.LastSeen = now
		ag.StateChanged = now
		if err := storage.PutJSON(tx, spaceAgents, []byte(ag.ID), ag); err != nil {
			return err
		}
		if err := tx.Put(spaceAgentPub, []byte(pubKey), []byte(ag.ID)); err != nil {
			return err
		}
		result = contract.AnnounceResult{
			AgentID:     ag.ID,
			Certificate: s.cfg.Certificate,
			RingIDs:     append([]contract.RingID(nil), ag.RingIDs...),
			NexusID:     ag.NexusID,
			State:       string(ag.State),
		}
		return nil
	})
	return result, err
}

// Activate moves a pending agent to ACTIVE and binds it to every ring whose
// Nexus set contains the agent's Nexus and which still has a free slot. Returns
// the ring ids it joined.
func (s *Service) Activate(ctx context.Context, agentID contract.AgentID) ([]contract.RingID, error) {
	var joined []contract.RingID
	err := s.db.Update(ctx, func(tx *storage.WriteTx) error {
		ag, err := storage.GetJSON[Agent](tx, spaceAgents, []byte(agentID))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.E(404, "AgentNotFound", "agent %q does not exist", agentID)
		}
		if err != nil {
			return err
		}
		if ag.State == StateActive {
			return nil
		}
		now := s.now()
		ringIDs := append([]contract.RingID(nil), ag.RingIDs...)
		err = storage.ScanJSON[Ring](tx, spaceRings, nil, func(_ []byte, ring Ring) error {
			if !containsNexus(ring.NexusIDs, ag.NexusID) || containsAgent(ring.AgentIDs, ag.ID) {
				return nil
			}
			rc, err := storage.GetJSON[RedundancyClass](tx, spaceRCs, []byte(ring.RCID))
			if err != nil {
				return err
			}
			// Rings are filled Nexus by Nexus up to local_n+local_k agents; a new
			// agent fills a vacancy before a new ring is created (docs/03 §4.6).
			if countAgentsInNexus(tx, ring.AgentIDs, ag.NexusID) >= rc.Params.ShardsPerGroup() {
				return nil
			}
			ring.AgentIDs = append(ring.AgentIDs, ag.ID)
			ring.Capacity += ag.CapacityBytes
			ring.Epoch++
			if err := storage.PutJSON(tx, spaceRings, []byte(ring.ID), ring); err != nil {
				return err
			}
			ringIDs = append(ringIDs, ring.ID)
			return nil
		})
		if err != nil {
			return err
		}
		ag.State = StateActive
		ag.StateChanged = now
		ag.ActivatedAt = now
		ag.LastSeen = now
		ag.RingIDs = ringIDs
		if err := storage.PutJSON(tx, spaceAgents, []byte(ag.ID), ag); err != nil {
			return err
		}
		joined = ringIDs
		return nil
	})
	return joined, err
}

// SetDecommissioning marks an agent as draining: placement stops sending it new
// shards, but it keeps serving until repair/rebalance moves the data.
func (s *Service) SetDecommissioning(ctx context.Context, agentID contract.AgentID, on bool) error {
	return s.db.Update(ctx, func(tx *storage.WriteTx) error {
		ag, err := storage.GetJSON[Agent](tx, spaceAgents, []byte(agentID))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.E(404, "AgentNotFound", "agent %q does not exist", agentID)
		}
		if err != nil {
			return err
		}
		if on {
			ag.State = StateDecommissioning
		} else {
			ag.State = StateActive
		}
		ag.StateChanged = s.now()
		return storage.PutJSON(tx, spaceAgents, []byte(ag.ID), ag)
	})
}

// Heartbeat applies an agent heartbeat: it refreshes capacity/load telemetry,
// recovers SUSPECT/OFFLINE back to ACTIVE, and never changes a DECOMMISSIONING
// agent.
func (s *Service) Heartbeat(ctx context.Context, hb contract.Heartbeat) error {
	if hb.AgentID == "" {
		return coerr.Invalidf("agent_id is required")
	}
	// LastSeen is the coordinator's clock: an agent clock must never be able to
	// keep itself "fresh" (docs/03 §5.1 detects loss on the coordinator side).
	now := s.now()
	return s.db.Update(ctx, func(tx *storage.WriteTx) error {
		ag, err := storage.GetJSON[Agent](tx, spaceAgents, []byte(hb.AgentID))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.E(404, "AgentNotFound", "agent %q is not registered", hb.AgentID)
		}
		if err != nil {
			return err
		}
		ag.FreeBytes = max(hb.FreeBytes, 0)
		ag.UsedBytes = max(hb.UsedBytes, 0)
		ag.ShardCount = max(hb.ShardCount, 0)
		ag.LoadEWMA = clamp01(hb.LoadEWMA)
		ag.BandwidthBps = hb.BandwidthBps
		if hb.ScrubCursor != "" {
			ag.ScrubCursor = hb.ScrubCursor
		}
		if hb.InventoryDigest != "" {
			ag.InventoryDigest = hb.InventoryDigest
		}
		// A heartbeat is proof of life: recover transient states. Pending agents
		// stay pending until activated; decommissioning agents stay draining.
		switch ag.State {
		case StateSuspect, StateOffline:
			ag.State = StateActive
			ag.StateChanged = now
		}
		ag.LastSeen = now
		// Derive the load score from the free/capacity ratio when the agent did
		// not report one (heartbeat-only deployments).
		if ag.CapacityBytes > 0 && hb.UsedBytes > 0 {
			ag.LoadEWMA = clamp01(float64(hb.UsedBytes) / float64(ag.CapacityBytes))
		}
		return storage.PutJSON(tx, spaceAgents, []byte(ag.ID), ag)
	})
}

// Sweep advances the health state machine for every agent based on heartbeat
// age. It is cheap, idempotent and safe to call from a ticker.
//
//	ACTIVE  --miss > suspectAfter--> SUSPECT --miss > offlineAfter--> OFFLINE
//	any     --heartbeat------------> ACTIVE
func (s *Service) Sweep(ctx context.Context) (suspect, offline int, err error) {
	now := s.now()
	var suspects, offlines int
	err = s.db.Update(ctx, func(tx *storage.WriteTx) error {
		suspects, offlines = 0, 0
		var updates []Agent
		err := storage.ScanJSON[Agent](tx, spaceAgents, nil, func(_ []byte, ag Agent) error {
			if ag.State != StateActive && ag.State != StateSuspect {
				return nil
			}
			if ag.LastSeen.IsZero() {
				return nil
			}
			miss := now.Sub(ag.LastSeen)
			switch {
			case miss > s.cfg.OfflineAfter && ag.State != StateOffline:
				ag.State = StateOffline
				ag.StateChanged = now
				offlines++
				updates = append(updates, ag)
			case miss > s.cfg.SuspectAfter && ag.State == StateActive:
				ag.State = StateSuspect
				ag.StateChanged = now
				suspects++
				updates = append(updates, ag)
			}
			return nil
		})
		if err != nil {
			return err
		}
		for _, ag := range updates {
			if err := storage.PutJSON(tx, spaceAgents, []byte(ag.ID), ag); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	return suspects, offlines, nil
}

// TransitionTo forces a state (operator action / tests).
func (s *Service) TransitionTo(ctx context.Context, agentID contract.AgentID, st State) error {
	switch st {
	case StatePending, StateActive, StateSuspect, StateOffline, StateDecommissioning:
	default:
		return coerr.Invalidf("unknown agent state %q", st)
	}
	return s.db.Update(ctx, func(tx *storage.WriteTx) error {
		ag, err := storage.GetJSON[Agent](tx, spaceAgents, []byte(agentID))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.E(404, "AgentNotFound", "agent %q does not exist", agentID)
		}
		if err != nil {
			return err
		}
		ag.State = st
		ag.StateChanged = s.now()
		return storage.PutJSON(tx, spaceAgents, []byte(ag.ID), ag)
	})
}

// ---------------------------------------------------------------------------
// Redundancy class CRUD
// ---------------------------------------------------------------------------

// CreateRC validates and stores a RedundancyClass.
func (s *Service) CreateRC(ctx context.Context, rc RedundancyClass) (RedundancyClass, error) {
	if rc.Name == "" {
		return RedundancyClass{}, coerr.Invalidf("redundancy class name is required")
	}
	if rc.ID == "" {
		rc.ID = id.New()
	}
	if rc.ChunkSize == 0 {
		rc.ChunkSize = 16 << 20
	}
	if err := ValidateRC(rc); err != nil {
		return RedundancyClass{}, err
	}
	rc.CreatedAt = s.now()
	err := s.db.Update(ctx, func(tx *storage.WriteTx) error {
		if tx.Has(spaceRCs, []byte(rc.ID)) {
			return coerr.E(409, coerr.CodeConflict, "redundancy class %q already exists", rc.ID)
		}
		return storage.PutJSON(tx, spaceRCs, []byte(rc.ID), rc)
	})
	return rc, err
}

// ValidateRC applies ec.Params.Validate plus the coordinator-side feasibility
// rules from docs/03 §2.2.
func ValidateRC(rc RedundancyClass) error {
	if err := rc.Params.Validate(); err != nil {
		return coerr.Invalidf("invalid redundancy parameters: %v", err)
	}
	p := rc.Params
	if rc.AAG < 1 || rc.AAG > p.ShardsPerGroup() {
		return coerr.Invalidf("aag must be in 1..%d (local_n+local_k)", p.ShardsPerGroup())
	}
	switch {
	case rc.ChunkSize < 4<<20 || rc.ChunkSize > 64<<20:
		return coerr.Invalidf("chunk_size must be between 4 MiB and 64 MiB")
	case rc.ChunkSize&(rc.ChunkSize-1) != 0:
		return coerr.Invalidf("chunk_size must be a power of two")
	case rc.ChunkSize%(p.GeoN*p.LocalN) != 0:
		return coerr.Invalidf("chunk_size must be divisible by geo_n*local_n (%d)", p.GeoN*p.LocalN)
	case rc.ChunkSize/(p.GeoN*p.LocalN) < 4096:
		return coerr.Invalidf("shard size must be at least 4 KiB (chunk_size/(geo_n*local_n) = %d)", rc.ChunkSize/(p.GeoN*p.LocalN))
	}
	return nil
}

// GetRC returns a redundancy class.
func (s *Service) GetRC(ctx context.Context, rcID string) (RedundancyClass, error) {
	var out RedundancyClass
	if err := ctx.Err(); err != nil {
		return out, err
	}
	err := s.db.View(ctx, func(tx *storage.ReadTx) error {
		rc, err := storage.GetJSON[RedundancyClass](tx, spaceRCs, []byte(rcID))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.E(404, "NoSuchRedundancyClass", "redundancy class %q does not exist", rcID)
		}
		if err != nil {
			return err
		}
		out = rc
		return nil
	})
	return out, err
}

// ListRCs returns all redundancy classes ordered by id.
func (s *Service) ListRCs(ctx context.Context) ([]RedundancyClass, error) {
	var out []RedundancyClass
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	err := s.db.View(ctx, func(tx *storage.ReadTx) error {
		return storage.ScanJSON[RedundancyClass](tx, spaceRCs, nil, func(_ []byte, rc RedundancyClass) error {
			out = append(out, rc)
			return nil
		})
	})
	return out, err
}

// DeleteRC removes an unreferenced redundancy class. RCs are immutable, so an
// in-use RC can never be changed out from under an object.
func (s *Service) DeleteRC(ctx context.Context, rcID string) error {
	return s.db.Update(ctx, func(tx *storage.WriteTx) error {
		if !tx.Has(spaceRCs, []byte(rcID)) {
			return coerr.E(404, "NoSuchRedundancyClass", "redundancy class %q does not exist", rcID)
		}
		inUse := false
		if err := storage.ScanJSON[Ring](tx, spaceRings, nil, func(_ []byte, r Ring) error {
			if r.RCID == rcID {
				inUse = true
				return storage.StopScan()
			}
			return nil
		}); err != nil {
			return err
		}
		if inUse {
			return coerr.E(409, coerr.CodeConflict, "redundancy class %q is in use by a ring", rcID)
		}
		return tx.Delete(spaceRCs, []byte(rcID))
	})
}

// ---------------------------------------------------------------------------
// Ring CRUD
// ---------------------------------------------------------------------------

// CreateRing creates a ring for an RC over a set of Nexuses. When AgentIDs is
// empty the ring is filled with every ACTIVE agent in those Nexuses.
func (s *Service) CreateRing(ctx context.Context, ring Ring) (Ring, error) {
	if ring.RCID == "" {
		return Ring{}, coerr.Invalidf("rc_id is required")
	}
	if ring.ID == "" {
		ring.ID = contract.RingID(id.New())
	}
	if len(ring.NexusIDs) == 0 {
		return Ring{}, coerr.Invalidf("nexus_ids is required")
	}
	now := s.now()
	err := s.db.Update(ctx, func(tx *storage.WriteTx) error {
		rc, err := storage.GetJSON[RedundancyClass](tx, spaceRCs, []byte(ring.RCID))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.E(404, "NoSuchRedundancyClass", "redundancy class %q does not exist", ring.RCID)
		}
		if err != nil {
			return err
		}
		if len(ring.NexusIDs) < rc.Params.GeoN+rc.Params.GeoK {
			return coerr.Invalidf("ring spans %d nexuses but the code needs geo_n+geo_k = %d", len(ring.NexusIDs), rc.Params.GeoN+rc.Params.GeoK)
		}
		agentIDs := append([]contract.AgentID(nil), ring.AgentIDs...)
		if len(agentIDs) == 0 {
			if err := storage.ScanJSON[Agent](tx, spaceAgents, nil, func(_ []byte, ag Agent) error {
				if ag.State != StateActive || !containsNexus(ring.NexusIDs, ag.NexusID) {
					return nil
				}
				agentIDs = append(agentIDs, ag.ID)
				return nil
			}); err != nil {
				return err
			}
		}
		// Feasibility: every Nexus in the ring must hold local_n+local_k agents
		// (docs/03 §2.2) and every listed agent must exist and be usable.
		perNexus := make(map[contract.NexusID]int, len(ring.NexusIDs))
		var capacity int64
		for _, aid := range agentIDs {
			ag, err := storage.GetJSON[Agent](tx, spaceAgents, []byte(aid))
			if errors.Is(err, storage.ErrNotFound) {
				return coerr.Invalidf("agent %q does not exist", aid)
			}
			if err != nil {
				return err
			}
			if !containsNexus(ring.NexusIDs, ag.NexusID) {
				return coerr.Invalidf("agent %q is not in one of the ring's nexuses", aid)
			}
			perNexus[ag.NexusID]++
			capacity += ag.CapacityBytes
		}
		for _, nx := range ring.NexusIDs {
			if perNexus[nx] < rc.Params.ShardsPerGroup() {
				return coerr.Invalidf("nexus %q has %d agents, need local_n+local_k = %d", nx, perNexus[nx], rc.Params.ShardsPerGroup())
			}
		}
		if tx.Has(spaceRings, []byte(ring.ID)) {
			return coerr.E(409, coerr.CodeConflict, "ring %q already exists", ring.ID)
		}
		ring.AgentIDs = agentIDs
		ring.Capacity = capacity
		ring.Epoch = 1
		ring.CreatedAt = now
		if err := storage.PutJSON(tx, spaceRings, []byte(ring.ID), ring); err != nil {
			return err
		}
		// Denormalise ring membership onto each agent (used by announce/activate
		// and by the topology view).
		for _, aid := range agentIDs {
			ag, err := storage.GetJSON[Agent](tx, spaceAgents, []byte(aid))
			if err != nil {
				return err
			}
			if !containsRing(ag.RingIDs, ring.ID) {
				ag.RingIDs = append(ag.RingIDs, ring.ID)
				if err := storage.PutJSON(tx, spaceAgents, []byte(ag.ID), ag); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return ring, err
}

// GetRing returns a ring.
func (s *Service) GetRing(ctx context.Context, ringID contract.RingID) (Ring, error) {
	var out Ring
	if err := ctx.Err(); err != nil {
		return out, err
	}
	err := s.db.View(ctx, func(tx *storage.ReadTx) error {
		r, err := storage.GetJSON[Ring](tx, spaceRings, []byte(ringID))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.E(404, "NoSuchRing", "ring %q does not exist", ringID)
		}
		if err != nil {
			return err
		}
		out = r
		return nil
	})
	return out, err
}

// ListRings returns all rings.
func (s *Service) ListRings(ctx context.Context) ([]Ring, error) {
	var out []Ring
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	err := s.db.View(ctx, func(tx *storage.ReadTx) error {
		return storage.ScanJSON[Ring](tx, spaceRings, nil, func(_ []byte, r Ring) error {
			out = append(out, r)
			return nil
		})
	})
	return out, err
}

// SetRingUsage updates a ring's used bytes (called by the placement/usage path;
// exposed for tests and the admin API).
func (s *Service) SetRingUsage(ctx context.Context, ringID contract.RingID, used int64) error {
	if used < 0 {
		return coerr.Invalidf("used bytes must be >= 0")
	}
	return s.db.Update(ctx, func(tx *storage.WriteTx) error {
		r, err := storage.GetJSON[Ring](tx, spaceRings, []byte(ringID))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.E(404, "NoSuchRing", "ring %q does not exist", ringID)
		}
		if err != nil {
			return err
		}
		r.UsedBytes = used
		return storage.PutJSON(tx, spaceRings, []byte(ringID), r)
	})
}

// AddRingUsage adjusts a ring's used bytes by delta (raw shard bytes committed or
// reclaimed). Usage is accounting data: a stale value only affects the
// ring_full_pct placement gate, never correctness, so callers log rather than
// fail a commit on error.
func (s *Service) AddRingUsage(ctx context.Context, ringID contract.RingID, delta int64) error {
	return s.db.Update(ctx, func(tx *storage.WriteTx) error {
		r, err := storage.GetJSON[Ring](tx, spaceRings, []byte(ringID))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.E(404, "NoSuchRing", "ring %q does not exist", ringID)
		}
		if err != nil {
			return err
		}
		r.UsedBytes += delta
		if r.UsedBytes < 0 {
			r.UsedBytes = 0
		}
		return storage.PutJSON(tx, spaceRings, []byte(ringID), r)
	})
}

// DeleteRing removes an empty ring and unbinds it from its agents.
func (s *Service) DeleteRing(ctx context.Context, ringID contract.RingID) error {
	return s.db.Update(ctx, func(tx *storage.WriteTx) error {
		r, err := storage.GetJSON[Ring](tx, spaceRings, []byte(ringID))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.E(404, "NoSuchRing", "ring %q does not exist", ringID)
		}
		if err != nil {
			return err
		}
		if r.UsedBytes > 0 {
			return coerr.E(409, coerr.CodeConflict, "ring %q still holds data", ringID)
		}
		for _, aid := range r.AgentIDs {
			ag, err := storage.GetJSON[Agent](tx, spaceAgents, []byte(aid))
			if err != nil {
				continue
			}
			ag.RingIDs = removeRing(ag.RingIDs, ringID)
			if err := storage.PutJSON(tx, spaceAgents, []byte(ag.ID), ag); err != nil {
				return err
			}
		}
		return tx.Delete(spaceRings, []byte(ringID))
	})
}

// ---------------------------------------------------------------------------
// Reads / snapshot
// ---------------------------------------------------------------------------

// GetAgent returns an agent record.
func (s *Service) GetAgent(ctx context.Context, agentID contract.AgentID) (Agent, error) {
	var out Agent
	if err := ctx.Err(); err != nil {
		return out, err
	}
	err := s.db.View(ctx, func(tx *storage.ReadTx) error {
		ag, err := storage.GetJSON[Agent](tx, spaceAgents, []byte(agentID))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.E(404, "AgentNotFound", "agent %q does not exist", agentID)
		}
		if err != nil {
			return err
		}
		out = ag
		return nil
	})
	return out, err
}

// Snapshot returns an immutable topology snapshot. geoFence is supplied by the
// coordinator (it is tenant metadata, not membership state).
func (s *Service) Snapshot(ctx context.Context, geoFence map[string][]contract.NexusID) (Snapshot, error) {
	snap := Snapshot{At: s.now(), GeoFence: geoFence}
	if err := ctx.Err(); err != nil {
		return snap, err
	}
	err := s.db.View(ctx, func(tx *storage.ReadTx) error {
		if err := storage.ScanJSON[Swarm](tx, spaceSwarms, nil, func(_ []byte, v Swarm) error {
			snap.Swarms = append(snap.Swarms, v)
			return nil
		}); err != nil {
			return err
		}
		if err := storage.ScanJSON[Nexus](tx, spaceNexuses, nil, func(_ []byte, v Nexus) error {
			snap.Nexuses = append(snap.Nexuses, v)
			return nil
		}); err != nil {
			return err
		}
		if err := storage.ScanJSON[Node](tx, spaceNodes, nil, func(_ []byte, v Node) error {
			snap.Nodes = append(snap.Nodes, v)
			return nil
		}); err != nil {
			return err
		}
		if err := storage.ScanJSON[Agent](tx, spaceAgents, nil, func(_ []byte, v Agent) error {
			snap.Agents = append(snap.Agents, v)
			return nil
		}); err != nil {
			return err
		}
		if err := storage.ScanJSON[Ring](tx, spaceRings, nil, func(_ []byte, v Ring) error {
			snap.Rings = append(snap.Rings, v)
			return nil
		}); err != nil {
			return err
		}
		if err := storage.ScanJSON[RedundancyClass](tx, spaceRCs, nil, func(_ []byte, v RedundancyClass) error {
			snap.RedundancyClasses = append(snap.RedundancyClasses, v)
			return nil
		}); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return snap, err
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%v/%d", snap.Agents, snap.At.UnixNano())))
	snap.ID = fmt.Sprintf("%x", sum[:8])
	return snap, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (s *Service) now() time.Time { return s.cfg.Now().UTC() }

func clamp01(v float64) float64 {
	switch {
	case v < 0:
		return 0
	case v > 1:
		return 1
	}
	return v
}

func containsNexus(list []contract.NexusID, id contract.NexusID) bool {
	for _, v := range list {
		if v == id {
			return true
		}
	}
	return false
}

func containsAgent(list []contract.AgentID, id contract.AgentID) bool {
	for _, v := range list {
		if v == id {
			return true
		}
	}
	return false
}

func containsRing(list []contract.RingID, id contract.RingID) bool {
	for _, v := range list {
		if v == id {
			return true
		}
	}
	return false
}

func removeRing(list []contract.RingID, id contract.RingID) []contract.RingID {
	out := list[:0]
	for _, v := range list {
		if v != id {
			out = append(out, v)
		}
	}
	return out
}

func countAgentsInNexus(tx storage.Reader, agentIDs []contract.AgentID, nexus contract.NexusID) int {
	n := 0
	for _, aid := range agentIDs {
		ag, err := storage.GetJSON[Agent](tx, spaceAgents, []byte(aid))
		if err == nil && ag.NexusID == nexus {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// Shard status reports (docs/07 §1.6, docs/03 §5.5)
// ---------------------------------------------------------------------------

var spaceShardStatus = []byte("shard_status")

// shardStatusRecord is the coordinator's view of one shard's health as reported
// by its owning agent (OK / MISSING / CORRUPT). Repair scheduling consumes these
// records; v1 only persists them and surfaces CORRUPT agents to the API.
type shardStatusRecord struct {
	AgentID    contract.AgentID    `json:"agent_id"`
	ShardSetID contract.ShardSetID `json:"shard_set_id"`
	Slot       int                 `json:"slot"`
	State      string              `json:"state"`
	UpdatedAt  time.Time           `json:"updated_at"`
}

// RecordShardStatus persists agent shard-health reports. Invalid states are
// rejected; unknown agents are ignored (the agent will re-announce).
func (s *Service) RecordShardStatus(ctx context.Context, items []contract.ShardStatus) error {
	if len(items) == 0 {
		return nil
	}
	now := s.now()
	return s.db.Update(ctx, func(tx *storage.WriteTx) error {
		for _, it := range items {
			switch it.State {
			case "OK", "MISSING", "CORRUPT":
			default:
				return coerr.Invalidf("invalid shard state %q", it.State)
			}
			if it.AgentID == "" || it.ShardSetID == "" || it.Slot < 0 {
				return coerr.Invalidf("shard status needs agent_id, shard_set_id and a non-negative slot")
			}
			if !tx.Has(spaceAgents, []byte(it.AgentID)) {
				continue
			}
			rec := shardStatusRecord{
				AgentID:    it.AgentID,
				ShardSetID: it.ShardSetID,
				Slot:       it.Slot,
				State:      it.State,
				UpdatedAt:  now,
			}
			key := storage.JoinKeyN([]string{string(it.AgentID), string(it.ShardSetID)}, bigEndianSlot(it.Slot))
			if err := storage.PutJSON(tx, spaceShardStatus, key, rec); err != nil {
				return err
			}
		}
		return nil
	})
}

func bigEndianSlot(slot int) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(slot))
	return buf[:]
}
