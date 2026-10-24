package api

import (
	"net/http"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/coord/coerr"
	"github.com/fass-storage/fass/internal/coord/membership"
	"github.com/fass-storage/fass/internal/coord/meta"
	"github.com/fass-storage/fass/internal/ec"
)

// ---------------------------------------------------------------------------
// §1.3 Placement
// ---------------------------------------------------------------------------

type placementRequestWire struct {
	ShardSetID    contract.ShardSetID `json:"shard_set_id"`
	Params        ec.Params           `json:"params"`
	ChunkBytes    int                 `json:"chunk_bytes"`
	TenantID      contract.TenantID   `json:"tenant_id"`
	ProjectID     contract.ProjectID  `json:"project_id"`
	RCID          string              `json:"rc_id"`
	RingID        contract.RingID     `json:"ring_id"`
	ExcludeAgents []contract.AgentID  `json:"exclude_agents,omitempty"`
}

type slotWire struct {
	GeoGroup   int              `json:"geo_group"`
	LocalIndex int              `json:"local_index"`
	AgentID    contract.AgentID `json:"agent_id"`
	NodeID     contract.NodeID  `json:"node_id"`
	NexusID    contract.NexusID `json:"nexus_id"`
	Endpoint   string           `json:"endpoint"`
}

type placementResponseWire struct {
	ShardSetID contract.ShardSetID `json:"shard_set_id"`
	RingID     contract.RingID     `json:"ring_id"`
	Generation int                 `json:"generation"`
	Slots      []slotWire          `json:"slots"`
}

func (s *Server) handlePlacement(w http.ResponseWriter, r *http.Request) {
	var req placementRequestWire
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	placement, err := s.svc.ResolvePlacement(r.Context(), contract.PlacementRequest{
		ShardSetID:    req.ShardSetID,
		Params:        req.Params,
		ChunkBytes:    req.ChunkBytes,
		TenantID:      req.TenantID,
		ProjectID:     req.ProjectID,
		RCID:          req.RCID,
		RingID:        req.RingID,
		ExcludeAgents: req.ExcludeAgents,
	})
	if err != nil {
		writeError(w, r, err)
		return
	}
	out := placementResponseWire{
		ShardSetID: placement.ShardSetID,
		RingID:     placement.RingID,
		Generation: placement.Generation,
		Slots:      make([]slotWire, 0, len(placement.Slots)),
	}
	for _, sl := range placement.Slots {
		out.Slots = append(out.Slots, slotWire{
			GeoGroup:   sl.GeoGroup,
			LocalIndex: sl.LocalIndex,
			AgentID:    sl.AgentID,
			NodeID:     sl.NodeID,
			NexusID:    sl.NexusID,
			Endpoint:   sl.Endpoint,
		})
	}
	s.metrics.placements.Add(1)
	writeJSON(w, r, http.StatusOK, out)
}

// ---------------------------------------------------------------------------
// §1.6 Agents & repair
// ---------------------------------------------------------------------------

func (s *Server) handleAnnounce(w http.ResponseWriter, r *http.Request) {
	var req contract.AnnounceRequest
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	result, err := s.svc.Announce(r.Context(), req)
	if err != nil {
		s.metrics.announceFailed.Add(1)
		writeError(w, r, err)
		return
	}
	s.metrics.announceOK.Add(1)
	writeJSON(w, r, http.StatusOK, result)
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	var hb contract.Heartbeat
	if err := readJSON(w, r, &hb); err != nil {
		writeError(w, r, err)
		return
	}
	if err := s.svc.Heartbeat(r.Context(), hb); err != nil {
		writeError(w, r, err)
		return
	}
	s.metrics.heartbeats.Add(1)
	w.WriteHeader(http.StatusNoContent)
}

type shardStatusRequest struct {
	Items []contract.ShardStatus `json:"items"`
}

func (s *Server) handleShardStatus(w http.ResponseWriter, r *http.Request) {
	var req shardStatusRequest
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	if err := s.svc.ReportShardStatus(r.Context(), req.Items); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleClaimRepairJob(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Worker string `json:"worker"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	job, err := s.svc.ClaimRepairJob(r.Context(), body.Worker)
	if err != nil {
		writeError(w, r, err)
		return
	}
	if job == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, r, http.StatusOK, job)
}

func (s *Server) handleCommitRepair(w http.ResponseWriter, r *http.Request) {
	var res contract.RepairResult
	if err := readJSON(w, r, &res); err != nil {
		writeError(w, r, err)
		return
	}
	if err := s.svc.CommitRepair(r.Context(), res); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Topology
// ---------------------------------------------------------------------------

func (s *Server) handleTopology(w http.ResponseWriter, r *http.Request) {
	snap, err := s.svc.Topology(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, snap)
}

// ---------------------------------------------------------------------------
// Agent admin (additive)
// ---------------------------------------------------------------------------

func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	snap, err := s.svc.Topology(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	agents := snap.Agents
	if agents == nil {
		agents = []membership.Agent{}
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"agents": agents})
}

func (s *Server) handleGetAgent(w http.ResponseWriter, r *http.Request) {
	ag, err := s.svc.Members.GetAgent(r.Context(), contract.AgentID(r.PathValue("agentID")))
	if err != nil {
		writeError(w, r, err)
		return
	}
	// The announce-secret digest must never leave the coordinator, even though it
	// cannot be inverted for a 32-byte random secret.
	ag.SecretHash = nil
	ag.SecretExpires = time.Time{}
	writeJSON(w, r, http.StatusOK, ag)
}

type registerPendingRequest struct {
	AgentID       contract.AgentID `json:"agent_id,omitempty"`
	NodeID        contract.NodeID  `json:"node_id"`
	DiskID        string           `json:"disk_id"`
	ExpectedPort  int              `json:"expected_port,omitempty"`
	CapacityBytes int64            `json:"capacity_bytes,omitempty"`
}

func (s *Server) handleRegisterPending(w http.ResponseWriter, r *http.Request) {
	var req registerPendingRequest
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	agentID, secret, err := s.svc.Members.RegisterPending(r.Context(), membership.PendingRegistration{
		AgentID:       req.AgentID,
		NodeID:        req.NodeID,
		DiskID:        req.DiskID,
		ExpectedPort:  req.ExpectedPort,
		CapacityBytes: req.CapacityBytes,
	})
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusCreated, map[string]any{
		"agent_id": agentID,
		"secret":   secret,
	})
}

func (s *Server) handleActivateAgent(w http.ResponseWriter, r *http.Request) {
	rings, err := s.svc.Members.Activate(r.Context(), contract.AgentID(r.PathValue("agentID")))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"ring_ids": rings})
}

func (s *Server) handleDecommissionAgent(w http.ResponseWriter, r *http.Request) {
	var body struct {
		On bool `json:"on"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	if err := s.svc.Members.SetDecommissioning(r.Context(), contract.AgentID(r.PathValue("agentID")), body.On); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Redundancy classes and rings (additive CRUD)
// ---------------------------------------------------------------------------

func (s *Server) handleCreateRC(w http.ResponseWriter, r *http.Request) {
	var rc membership.RedundancyClass
	if err := readJSON(w, r, &rc); err != nil {
		writeError(w, r, err)
		return
	}
	saved, err := s.svc.Members.CreateRC(r.Context(), rc)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusCreated, saved)
}

func (s *Server) handleListRCs(w http.ResponseWriter, r *http.Request) {
	rcs, err := s.svc.Members.ListRCs(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	if rcs == nil {
		rcs = []membership.RedundancyClass{}
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"redundancy_classes": rcs})
}

func (s *Server) handleGetRC(w http.ResponseWriter, r *http.Request) {
	rc, err := s.svc.Members.GetRC(r.Context(), r.PathValue("rcID"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, rc)
}

func (s *Server) handleDeleteRC(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.Members.DeleteRC(r.Context(), r.PathValue("rcID")); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleCreateRing(w http.ResponseWriter, r *http.Request) {
	var ring membership.Ring
	if err := readJSON(w, r, &ring); err != nil {
		writeError(w, r, err)
		return
	}
	saved, err := s.svc.Members.CreateRing(r.Context(), ring)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusCreated, saved)
}

func (s *Server) handleListRings(w http.ResponseWriter, r *http.Request) {
	rings, err := s.svc.Members.ListRings(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	if rings == nil {
		rings = []membership.Ring{}
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"rings": rings})
}

func (s *Server) handleGetRing(w http.ResponseWriter, r *http.Request) {
	ring, err := s.svc.Members.GetRing(r.Context(), contract.RingID(r.PathValue("ringID")))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, ring)
}

func (s *Server) handleDeleteRing(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.Members.DeleteRing(r.Context(), contract.RingID(r.PathValue("ringID"))); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSetRingUsage(w http.ResponseWriter, r *http.Request) {
	var body struct {
		UsedBytes int64 `json:"used_bytes"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	if err := s.svc.Members.SetRingUsage(r.Context(), contract.RingID(r.PathValue("ringID")), body.UsedBytes); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Tenants, swarms, nexuses, nodes (additive bootstrap)
// ---------------------------------------------------------------------------

func (s *Server) handlePutTenant(w http.ResponseWriter, r *http.Request) {
	var t meta.Tenant
	if err := readJSON(w, r, &t); err != nil {
		writeError(w, r, err)
		return
	}
	if err := s.svc.Meta.PutTenant(r.Context(), t); err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusCreated, t)
}

func (s *Server) handleListTenants(w http.ResponseWriter, r *http.Request) {
	tenants, err := s.svc.Meta.ListTenants(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	if tenants == nil {
		tenants = []meta.Tenant{}
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"tenants": tenants})
}

func (s *Server) handleGetTenant(w http.ResponseWriter, r *http.Request) {
	t, err := s.svc.Meta.GetTenant(r.Context(), contract.TenantID(r.PathValue("tenantID")))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, t)
}

func (s *Server) handleCreateSwarm(w http.ResponseWriter, r *http.Request) {
	var sw membership.Swarm
	if err := readJSON(w, r, &sw); err != nil {
		writeError(w, r, err)
		return
	}
	saved, err := s.svc.Members.CreateSwarm(r.Context(), sw)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusCreated, saved)
}

func (s *Server) handleCreateNexus(w http.ResponseWriter, r *http.Request) {
	var n membership.Nexus
	if err := readJSON(w, r, &n); err != nil {
		writeError(w, r, err)
		return
	}
	saved, err := s.svc.Members.CreateNexus(r.Context(), n)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusCreated, saved)
}

func (s *Server) handlePatchNexus(w http.ResponseWriter, r *http.Request) {
	var body struct {
		WriteDegraded *bool `json:"write_degraded"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	if body.WriteDegraded == nil {
		writeError(w, r, coerr.Invalidf("write_degraded is required"))
		return
	}
	if err := s.svc.Members.SetNexusWriteDegraded(r.Context(), contract.NexusID(r.PathValue("nexusID")), *body.WriteDegraded); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleCreateNode(w http.ResponseWriter, r *http.Request) {
	var n membership.Node
	if err := readJSON(w, r, &n); err != nil {
		writeError(w, r, err)
		return
	}
	saved, err := s.svc.Members.CreateNode(r.Context(), n)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusCreated, saved)
}
