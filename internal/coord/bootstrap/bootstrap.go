// Package bootstrap creates the deterministic dev cluster used by
// `fass-coordinator --dev-bootstrap` and the 3-Nexus end-to-end test.
//
// It is idempotent by construction: every entity has a fixed id, existing
// entities are reused (and verified) instead of recreated, and live agents are
// never rewritten. That property matters because agent announce secrets are
// one-time: a coordinator restart that re-minted a secret for an ACTIVE agent
// would brick that agent's registration.
//
// Topology (docs/07-wire-api.md §1.8):
//
//	swarm dev-swarm
//	├── nexus-a ── node-a1 … node-aN
//	├── nexus-b ── node-b1 … node-bN
//	└── nexus-c ── node-c1 … node-cN
//
// The number of nodes per Nexus and the redundancy class are configuration, so
// the same bootstrap serves the 6-agent 3-Nexus dev cluster and larger
// integration topologies without code changes.
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/coord/auth"
	"github.com/fass-storage/fass/internal/coord/coerr"
	"github.com/fass-storage/fass/internal/coord/membership"
	"github.com/fass-storage/fass/internal/coord/meta"
	"github.com/fass-storage/fass/internal/ec"
)

// Dev tenant/project/credential identifiers (frozen: the e2e test and the
// documented bootstrap payload depend on them).
const (
	DevSwarmID         = "dev-swarm"
	DevSwarmName       = "dev-swarm"
	DevTenantID        = contract.TenantID("dev-tenant")
	DevTenantName      = "dev-tenant"
	DevProjectID       = contract.ProjectID("dev-project")
	DevProjectName     = "dev-project"
	DevAccessKeyID     = "dev-access-key"
	DevAccessKeySecret = "dev-secret-key"
	DevRCID            = "dev-rc"
	DevRCName          = "dev-rc"
	DevRingID          = contract.RingID("dev-ring")
	DevRingName        = "dev-ring"
	DevBucket          = "dev-bucket"
	DevRegion          = contract.DefaultRegion
	// DevAgentCapacity is the advertised capacity of each dev agent. It only has
	// to hold a handful of 4 MiB objects.
	DevAgentCapacity = int64(2) << 30
)

// Nexus names are part of the payload contract.
var DevNexuses = []string{"nexus-a", "nexus-b", "nexus-c"}

// Config describes the dev cluster to create.
type Config struct {
	// DataDir receives dev-bootstrap.json (empty skips the file).
	DataDir string
	Region  string

	SwarmID   string
	SwarmName string
	Nexuses   []string

	// NodesPerNexus is the number of nodes (and therefore agents) in each Nexus.
	NodesPerNexus int

	TenantID    contract.TenantID
	TenantName  string
	ProjectID   contract.ProjectID
	ProjectName string

	AccessKeyID     string
	AccessKeySecret string

	RCID   string
	RCName string
	Params ec.Params
	AAG    int
	// ChunkSize must match the gateway's --chunk-size for shard sizing to line up.
	ChunkSize int

	RingID   contract.RingID
	RingName string

	Bucket        string
	AgentCapacity int64
}

// DevConfig returns the documented 6-agent, 3-Nexus dev cluster.
//
// Redundancy class: geo 2+1 × local 1+1 at aag 1. Six shards per chunk, two per
// Nexus on two nodes (aag 1 ⇒ one shard per node), so a whole-Nexus loss still
// leaves geo_n = 2 groups and the object stays readable. This topology is the
// smallest one that satisfies every placement invariant while still exercising
// the geo tier.
func DevConfig(dataDir string) Config {
	return Config{
		DataDir:         dataDir,
		Region:          DevRegion,
		SwarmID:         DevSwarmID,
		SwarmName:       DevSwarmName,
		Nexuses:         append([]string(nil), DevNexuses...),
		NodesPerNexus:   2,
		TenantID:        DevTenantID,
		TenantName:      DevTenantName,
		ProjectID:       DevProjectID,
		ProjectName:     DevProjectName,
		AccessKeyID:     DevAccessKeyID,
		AccessKeySecret: DevAccessKeySecret,
		RCID:            DevRCID,
		RCName:          DevRCName,
		Params:          ec.Params{GeoN: 2, GeoK: 1, LocalN: 1, LocalK: 1},
		AAG:             1,
		ChunkSize:       4 << 20,
		RingID:          DevRingID,
		RingName:        DevRingName,
		Bucket:          DevBucket,
		AgentCapacity:   DevAgentCapacity,
	}
}

// Agent is one dev agent slot in the payload.
type Agent struct {
	NodeID  contract.NodeID  `json:"node_id"`
	NexusID contract.NexusID `json:"nexus_id"`
	// DiskID is the operator-facing disk label. The agent generates its real
	// (random) disk UUID from its state file and the coordinator binds it on the
	// first announce; the label is what provisioning uses to address the slot.
	DiskID string `json:"disk_id"`
	// Secret is the one-time announce secret. It is empty for an agent that is
	// already ACTIVE: a re-run never invalidates a live registration.
	Secret string `json:"secret"`
}

// Payload is the single JSON object printed by fass-coordinator --dev-bootstrap.
type Payload struct {
	AccessKeyID string             `json:"access_key_id"`
	Secret      string             `json:"secret"`
	Region      string             `json:"region"`
	RCID        string             `json:"rc_id"`
	RingID      contract.RingID    `json:"ring_id"`
	Bucket      string             `json:"bucket"`
	TenantID    contract.TenantID  `json:"tenant_id"`
	ProjectID   contract.ProjectID `json:"project_id"`
	Agents      []Agent            `json:"agents"`
}

// Run creates (or reconciles) the dev cluster and returns the bootstrap payload.
// It is safe to call on every boot.
func Run(ctx context.Context, m *meta.Service, a *auth.Service, mem *membership.Service, cfg Config) (Payload, error) {
	cfg = cfg.withDefaults()
	if err := ctx.Err(); err != nil {
		return Payload{}, err
	}

	// 1. Topology: swarm, nexuses, nodes. Fixed ids make this idempotent.
	swarm, err := mem.EnsureSwarm(ctx, membership.Swarm{ID: cfg.SwarmID, Name: cfg.SwarmName, Region: cfg.Region})
	if err != nil {
		return Payload{}, fmt.Errorf("bootstrap: swarm: %w", err)
	}
	var nexusIDs []contract.NexusID
	nodeNexus := make(map[contract.NodeID]contract.NexusID)
	type nodeSlot struct {
		node membership.Node
		disk string
	}
	var slots []nodeSlot
	for _, nexusName := range cfg.Nexuses {
		nexusID := contract.NexusID(nexusName)
		if _, err := mem.EnsureNexus(ctx, membership.Nexus{ID: nexusID, SwarmID: swarm.ID, Name: nexusName, Region: cfg.Region}); err != nil {
			return Payload{}, fmt.Errorf("bootstrap: nexus %s: %w", nexusName, err)
		}
		nexusIDs = append(nexusIDs, nexusID)
		// Suffix "a", "b", "c" from the nexus name keeps node ids stable.
		suffix := nexusName[len(nexusName)-1:]
		for i := 1; i <= cfg.NodesPerNexus; i++ {
			nodeID := contract.NodeID(fmt.Sprintf("node-%s%d", suffix, i))
			node, err := mem.EnsureNode(ctx, membership.Node{
				ID:       nodeID,
				NexusID:  nexusID,
				Hostname: string(nodeID),
				Rack:     fmt.Sprintf("rack-%s%d", suffix, i),
			})
			if err != nil {
				return Payload{}, fmt.Errorf("bootstrap: node %s: %w", nodeID, err)
			}
			nodeNexus[nodeID] = nexusID
			slots = append(slots, nodeSlot{node: node, disk: fmt.Sprintf("disk-%s%d", suffix, i)})
		}
	}

	// 2. Tenant and project.
	if err := ensureTenant(ctx, m, cfg); err != nil {
		return Payload{}, err
	}
	if err := m.PutProject(ctx, meta.Project{ProjectID: cfg.ProjectID, TenantID: cfg.TenantID, Name: cfg.ProjectName}); err != nil {
		return Payload{}, fmt.Errorf("bootstrap: project: %w", err)
	}

	// 3. Access key. Reuse an existing key verbatim; never reset its secret.
	if _, err := a.GetAccessKey(ctx, cfg.AccessKeyID); err != nil {
		if !errors.Is(err, coerr.ErrAccessDenied) {
			return Payload{}, fmt.Errorf("bootstrap: access key: %w", err)
		}
		if _, err := a.CreateAccessKey(ctx, auth.AccessKeySpec{
			AccessKeyID: cfg.AccessKeyID,
			Secret:      cfg.AccessKeySecret,
			TenantID:    cfg.TenantID,
			ProjectID:   cfg.ProjectID,
			IsRoot:      true,
			Groups:      []string{"AuthenticatedUsers", "dev"},
		}); err != nil {
			return Payload{}, fmt.Errorf("bootstrap: create access key: %w", err)
		}
	}

	// 4. Redundancy class (immutable: verify, never mutate).
	if existing, err := mem.GetRC(ctx, cfg.RCID); err == nil {
		if existing.Params != cfg.Params || existing.AAG != cfg.AAG || existing.ChunkSize != cfg.ChunkSize {
			return Payload{}, fmt.Errorf("bootstrap: redundancy class %q already exists with different parameters %+v/aag=%d/chunk=%d; use a fresh data dir",
				cfg.RCID, existing.Params, existing.AAG, existing.ChunkSize)
		}
	} else if coerr.CodeOf(err) != "NoSuchRedundancyClass" {
		return Payload{}, fmt.Errorf("bootstrap: redundancy class: %w", err)
	} else {
		if _, err := mem.CreateRC(ctx, membership.RedundancyClass{
			ID:        cfg.RCID,
			Name:      cfg.RCName,
			Params:    cfg.Params,
			AAG:       cfg.AAG,
			ChunkSize: cfg.ChunkSize,
		}); err != nil {
			return Payload{}, fmt.Errorf("bootstrap: create redundancy class: %w", err)
		}
	}

	// 5. Agent slots: node-scoped pending registrations with one-time secrets.
	payload := Payload{
		AccessKeyID: cfg.AccessKeyID,
		Secret:      cfg.AccessKeySecret,
		Region:      cfg.Region,
		RCID:        cfg.RCID,
		RingID:      cfg.RingID,
		Bucket:      cfg.Bucket,
		TenantID:    cfg.TenantID,
		ProjectID:   cfg.ProjectID,
	}
	var agentIDs []contract.AgentID
	for _, slot := range slots {
		agentID, secret, _, err := mem.EnsurePending(ctx, membership.PendingRegistration{
			NodeID: slot.node.ID,
			// Empty disk: bind the agent's generated disk UUID on first announce.
			DiskID:        "",
			CapacityBytes: cfg.AgentCapacity,
		})
		if err != nil {
			return Payload{}, fmt.Errorf("bootstrap: pending agent for %s: %w", slot.node.ID, err)
		}
		agentIDs = append(agentIDs, agentID)
		payload.Agents = append(payload.Agents, Agent{
			NodeID:  slot.node.ID,
			NexusID: nodeNexus[slot.node.ID],
			DiskID:  slot.disk,
			Secret:  secret, // empty when the agent is already ACTIVE
		})
	}

	// 6. Ring over all Nexuses containing every dev agent (pending agents are
	// allowed: the ring records operator intent, placement only uses ACTIVE ones).
	if _, err := mem.GetRing(ctx, cfg.RingID); err != nil {
		if coerr.CodeOf(err) != "NoSuchRing" {
			return Payload{}, fmt.Errorf("bootstrap: ring: %w", err)
		}
		if _, err := mem.CreateRing(ctx, membership.Ring{
			ID:       cfg.RingID,
			Name:     cfg.RingName,
			RCID:     cfg.RCID,
			NexusIDs: nexusIDs,
			AgentIDs: agentIDs,
		}); err != nil {
			return Payload{}, fmt.Errorf("bootstrap: create ring: %w", err)
		}
	} else if _, err := mem.EnsureRingAgents(ctx, cfg.RingID, agentIDs); err != nil {
		return Payload{}, fmt.Errorf("bootstrap: reconcile ring: %w", err)
	}

	// 7. Bucket owned by the dev project, defaulting to the dev RC.
	if existing, err := m.GetBucket(ctx, cfg.Bucket); err != nil {
		if !errors.Is(err, coerr.ErrNoSuchBucket) {
			return Payload{}, fmt.Errorf("bootstrap: bucket: %w", err)
		}
		if err := m.CreateBucket(ctx, contract.BucketConfig{
			Name:        cfg.Bucket,
			TenantID:    cfg.TenantID,
			ProjectID:   cfg.ProjectID,
			Region:      cfg.Region,
			Ownership:   "ObjectWriter",
			DefaultRCID: cfg.RCID,
		}); err != nil {
			return Payload{}, fmt.Errorf("bootstrap: create bucket: %w", err)
		}
	} else if existing.DefaultRCID != cfg.RCID {
		existing.DefaultRCID = cfg.RCID
		if err := m.UpdateBucket(ctx, existing); err != nil {
			return Payload{}, fmt.Errorf("bootstrap: update bucket: %w", err)
		}
	}

	// 8. Persist the payload next to the data so tests/CLI can read it without
	// scraping logs; the caller also prints it on one stdout line.
	if cfg.DataDir != "" {
		if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
			return Payload{}, fmt.Errorf("bootstrap: create data dir: %w", err)
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			return Payload{}, fmt.Errorf("bootstrap: encode payload: %w", err)
		}
		path := filepath.Join(cfg.DataDir, "dev-bootstrap.json")
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, append(raw, '\n'), 0o644); err != nil {
			return Payload{}, fmt.Errorf("bootstrap: write payload: %w", err)
		}
		if err := os.Rename(tmp, path); err != nil {
			return Payload{}, fmt.Errorf("bootstrap: install payload: %w", err)
		}
	}
	return payload, nil
}

func ensureTenant(ctx context.Context, m *meta.Service, cfg Config) error {
	t := meta.Tenant{
		ID:        cfg.TenantID,
		Name:      cfg.TenantName,
		CreatedAt: time.Time{},
	}
	existing, err := m.GetTenant(ctx, cfg.TenantID)
	switch {
	case err == nil:
		// Preserve operator-set geo-fence/seed/creation time; only refresh the name.
		t.GeoFence = existing.GeoFence
		t.DefaultRCID = cfg.RCID
		t.KeySeed = existing.KeySeed
		t.CreatedAt = existing.CreatedAt
	case coerr.CodeOf(err) == "NoSuchTenant":
		t.DefaultRCID = cfg.RCID
	default:
		return fmt.Errorf("bootstrap: tenant: %w", err)
	}
	if err := m.PutTenant(ctx, t); err != nil {
		return fmt.Errorf("bootstrap: put tenant: %w", err)
	}
	return nil
}

func (c Config) withDefaults() Config {
	if c.Region == "" {
		c.Region = DevRegion
	}
	if len(c.Nexuses) == 0 {
		c.Nexuses = append([]string(nil), DevNexuses...)
	}
	if c.NodesPerNexus <= 0 {
		c.NodesPerNexus = 2
	}
	if c.SwarmID == "" {
		c.SwarmID = DevSwarmID
	}
	if c.SwarmName == "" {
		c.SwarmName = DevSwarmName
	}
	if c.TenantID == "" {
		c.TenantID = DevTenantID
	}
	if c.TenantName == "" {
		c.TenantName = DevTenantName
	}
	if c.ProjectID == "" {
		c.ProjectID = DevProjectID
	}
	if c.ProjectName == "" {
		c.ProjectName = DevProjectName
	}
	if c.AccessKeyID == "" {
		c.AccessKeyID = DevAccessKeyID
	}
	if c.AccessKeySecret == "" {
		c.AccessKeySecret = DevAccessKeySecret
	}
	if c.RCID == "" {
		c.RCID = DevRCID
	}
	if c.RCName == "" {
		c.RCName = c.RCID
	}
	if c.Params == (ec.Params{}) {
		c.Params = ec.Params{GeoN: 2, GeoK: 1, LocalN: 1, LocalK: 1}
	}
	if c.AAG <= 0 {
		c.AAG = 1
	}
	if c.ChunkSize <= 0 {
		c.ChunkSize = 4 << 20
	}
	if c.RingID == "" {
		c.RingID = DevRingID
	}
	if c.RingName == "" {
		c.RingName = string(c.RingID)
	}
	if c.Bucket == "" {
		c.Bucket = DevBucket
	}
	if c.AgentCapacity <= 0 {
		c.AgentCapacity = DevAgentCapacity
	}
	return c
}
