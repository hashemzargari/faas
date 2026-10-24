package api

import "net/http"

// routes registers docs/07-wire-api.md §1 verbatim, plus a small additive admin
// surface (topology bootstrap, RC/ring/tenant CRUD, access-key and policy
// management) that the console, CLI and tests need. The additive routes are
// grouped at the bottom and are not part of the frozen §1 contract.
func (s *Server) routes() {
	// Health and metrics (also served on :7000 per docs/07 §1.6).
	s.mux.HandleFunc("GET /healthz", s.healthz)
	s.mux.HandleFunc("GET /readyz", s.healthz)
	s.mux.HandleFunc("GET /v1/healthz", s.healthz)
	s.mux.HandleFunc("GET /metrics", s.metricsHandler)

	// §1.1 Identity & authorisation.
	s.mux.HandleFunc("POST /v1/auth/keys/{accessKeyID}", s.handleVerifySignature)
	s.mux.HandleFunc("POST /v1/auth/authorize", s.handleAuthorize)

	// §1.2 Buckets.
	s.mux.HandleFunc("GET /v1/buckets", s.handleListBuckets)
	s.mux.HandleFunc("POST /v1/buckets", s.handleCreateBucket)
	s.mux.HandleFunc("GET /v1/buckets/{bucket}", s.handleGetBucket)
	s.mux.HandleFunc("PATCH /v1/buckets/{bucket}", s.handleUpdateBucket)
	s.mux.HandleFunc("DELETE /v1/buckets/{bucket}", s.handleDeleteBucket)
	s.mux.HandleFunc("GET /v1/buckets/{bucket}/location", s.handleGetBucketLocation)

	// §1.4b Bucket sub-resources.
	s.mux.HandleFunc("GET /v1/buckets/{bucket}/acl", s.handleGetBucketACL)
	s.mux.HandleFunc("PUT /v1/buckets/{bucket}/acl", s.handlePutBucketACL)
	s.mux.HandleFunc("GET /v1/buckets/{bucket}/lifecycle", s.handleGetBucketLifecycle)
	s.mux.HandleFunc("PUT /v1/buckets/{bucket}/lifecycle", s.handlePutBucketLifecycle)
	s.mux.HandleFunc("DELETE /v1/buckets/{bucket}/lifecycle", s.handleDeleteBucketLifecycle)
	s.mux.HandleFunc("GET /v1/buckets/{bucket}/policy", s.handleGetBucketPolicy)
	s.mux.HandleFunc("PUT /v1/buckets/{bucket}/policy", s.handlePutBucketPolicy)
	s.mux.HandleFunc("DELETE /v1/buckets/{bucket}/policy", s.handleDeleteBucketPolicy)

	// §1.3 Placement.
	s.mux.HandleFunc("POST /v1/placement", s.handlePlacement)

	// §1.4 Objects.
	s.mux.HandleFunc("POST /v1/objects:commit", s.handleCommitObject)
	s.mux.HandleFunc("GET /v1/objects", s.handleListObjects)
	s.mux.HandleFunc("GET /v1/objects/{bucket}/{key...}", s.handleGetObject)
	s.mux.HandleFunc("HEAD /v1/objects/{bucket}/{key...}", s.handleHeadObject)
	s.mux.HandleFunc("PUT /v1/objects/{bucket}/{key...}", s.handlePutObjectSubresource)
	s.mux.HandleFunc("DELETE /v1/objects/{bucket}/{key...}", s.handleDeleteObject)

	// §1.5 Multipart.
	s.mux.HandleFunc("POST /v1/uploads", s.handleCreateUpload)
	s.mux.HandleFunc("GET /v1/uploads", s.handleListUploads)
	s.mux.HandleFunc("POST /v1/uploads/{uploadID}", s.handleCompleteUpload)
	s.mux.HandleFunc("DELETE /v1/uploads/{uploadID}", s.handleAbortUpload)
	s.mux.HandleFunc("PUT /v1/uploads/{uploadID}/parts/{partNumber}", s.handleCommitPart)
	s.mux.HandleFunc("GET /v1/uploads/{uploadID}/parts", s.handleListParts)

	// §1.6 Agents & repair.
	s.mux.HandleFunc("POST /v1/agents/announce", s.handleAnnounce)
	s.mux.HandleFunc("POST /v1/agents/heartbeat", s.handleHeartbeat)
	s.mux.HandleFunc("POST /v1/agents/shard-status", s.handleShardStatus)
	s.mux.HandleFunc("POST /v1/repair/claim", s.handleClaimRepairJob)
	s.mux.HandleFunc("POST /v1/repair/commit", s.handleCommitRepair)
	s.mux.HandleFunc("GET /v1/repair/status", s.handleRepairStatus)
	s.mux.HandleFunc("GET /v1/topology", s.handleTopology)

	// Additive admin surface (not part of the frozen §1).
	s.mux.HandleFunc("POST /v1/access-keys", s.handleCreateAccessKey)
	s.mux.HandleFunc("GET /v1/access-keys", s.handleListAccessKeys)
	s.mux.HandleFunc("DELETE /v1/access-keys/{accessKeyID}", s.handleDeleteAccessKey)
	s.mux.HandleFunc("POST /v1/policies", s.handlePutPolicy)
	s.mux.HandleFunc("GET /v1/policies", s.handleListPolicies)
	s.mux.HandleFunc("DELETE /v1/policies/{policyID}", s.handleDeletePolicy)
	s.mux.HandleFunc("GET /v1/agents", s.handleListAgents)
	s.mux.HandleFunc("GET /v1/agents/{agentID}", s.handleGetAgent)
	s.mux.HandleFunc("POST /v1/agents/pending", s.handleRegisterPending)
	s.mux.HandleFunc("POST /v1/agents/{agentID}/activate", s.handleActivateAgent)
	s.mux.HandleFunc("POST /v1/agents/{agentID}/decommission", s.handleDecommissionAgent)
	s.mux.HandleFunc("GET /v1/redundancy-classes", s.handleListRCs)
	s.mux.HandleFunc("POST /v1/redundancy-classes", s.handleCreateRC)
	s.mux.HandleFunc("GET /v1/redundancy-classes/{rcID}", s.handleGetRC)
	s.mux.HandleFunc("DELETE /v1/redundancy-classes/{rcID}", s.handleDeleteRC)
	s.mux.HandleFunc("GET /v1/rings", s.handleListRings)
	s.mux.HandleFunc("POST /v1/rings", s.handleCreateRing)
	s.mux.HandleFunc("GET /v1/rings/{ringID}", s.handleGetRing)
	s.mux.HandleFunc("DELETE /v1/rings/{ringID}", s.handleDeleteRing)
	s.mux.HandleFunc("PUT /v1/rings/{ringID}/usage", s.handleSetRingUsage)
	s.mux.HandleFunc("GET /v1/tenants", s.handleListTenants)
	s.mux.HandleFunc("POST /v1/tenants", s.handlePutTenant)
	s.mux.HandleFunc("GET /v1/tenants/{tenantID}", s.handleGetTenant)
	s.mux.HandleFunc("POST /v1/swarms", s.handleCreateSwarm)
	s.mux.HandleFunc("POST /v1/nexuses", s.handleCreateNexus)
	s.mux.HandleFunc("PATCH /v1/nexuses/{nexusID}", s.handlePatchNexus)
	s.mux.HandleFunc("POST /v1/nodes", s.handleCreateNode)
	s.mux.HandleFunc("POST /v1/maintenance", s.handleMaintenance)
}

// handleMaintenance toggles the announce maintenance mode (admin).
func (s *Server) handleMaintenance(w http.ResponseWriter, r *http.Request) {
	var body struct {
		On bool `json:"on"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	s.svc.SetMaintenance(body.On)
	writeJSON(w, r, http.StatusOK, map[string]bool{"maintenance": body.On})
}
