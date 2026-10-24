package api

import (
	"encoding/base64"
	"net/http"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/coord/auth"
	"github.com/fass-storage/fass/internal/coord/coerr"
)

// ---------------------------------------------------------------------------
// §1.1 Identity & authorisation
// ---------------------------------------------------------------------------

type verifySignatureResponse struct {
	Principal contract.Principal `json:"principal"`
	HMACKey   string             `json:"hmac_key"`
	ExpiresAt time.Time          `json:"expires_at"`
}

// handleVerifySignature resolves an access key and returns the HMAC material the
// gateway needs to verify SigV2/SigV4 locally, with a short cache TTL (≤ 60 s per
// docs/04 §5.1).
func (s *Server) handleVerifySignature(w http.ResponseWriter, r *http.Request) {
	keyID := r.PathValue("accessKeyID")
	principal, secret, err := s.svc.VerifySignature(r.Context(), keyID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, verifySignatureResponse{
		Principal: principal,
		HMACKey:   base64.StdEncoding.EncodeToString(secret),
		ExpiresAt: s.now().UTC().Add(60 * time.Second),
	})
}

type authorizeRequest struct {
	Principal  contract.Principal `json:"principal"`
	Action     contract.Action    `json:"action"`
	Resource   contract.Resource  `json:"resource"`
	SourceIP   string             `json:"source_ip,omitempty"`
	Conditions map[string]string  `json:"conditions,omitempty"`
}

type authorizeResponse struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

// handleAuthorize evaluates the four-stage authorisation chain.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	var req authorizeRequest
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	if req.Action == "" {
		writeError(w, r, coerr.Invalidf("missing action"))
		return
	}
	decision, err := s.svc.Authorize(r.Context(), contract.RequestContext{
		Principal: req.Principal,
		Action:    req.Action,
		Resource:  req.Resource,
		SourceIP:  req.SourceIP,
		Now:       s.now(),
		Condition: req.Conditions,
	})
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, authorizeResponse{Allowed: decision.Allowed, Reason: decision.Reason})
}

// ---------------------------------------------------------------------------
// Access keys (additive admin surface)
// ---------------------------------------------------------------------------

type createAccessKeyRequest struct {
	AccessKeyID string             `json:"access_key_id,omitempty"`
	Secret      string             `json:"secret,omitempty"`
	TenantID    contract.TenantID  `json:"tenant_id"`
	ProjectID   contract.ProjectID `json:"project_id"`
	IsRoot      bool               `json:"is_root"`
	Groups      []string           `json:"groups,omitempty"`
	ExpiresAt   *time.Time         `json:"expires_at,omitempty"`
}

func (s *Server) handleCreateAccessKey(w http.ResponseWriter, r *http.Request) {
	var req createAccessKeyRequest
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	key, err := s.svc.Auth.CreateAccessKey(r.Context(), auth.AccessKeySpec{
		AccessKeyID: req.AccessKeyID,
		Secret:      req.Secret,
		TenantID:    req.TenantID,
		ProjectID:   req.ProjectID,
		IsRoot:      req.IsRoot,
		Groups:      req.Groups,
		ExpiresAt:   req.ExpiresAt,
	})
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusCreated, key)
}

func (s *Server) handleListAccessKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.svc.Auth.ListAccessKeys(r.Context(),
		contract.TenantID(r.URL.Query().Get("tenant_id")),
		contract.ProjectID(r.URL.Query().Get("project_id")))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"access_keys": keys})
}

func (s *Server) handleDeleteAccessKey(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.Auth.DeleteAccessKey(r.Context(), r.PathValue("accessKeyID")); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// IAM and bucket policies (additive admin surface)
// ---------------------------------------------------------------------------

func (s *Server) handlePutPolicy(w http.ResponseWriter, r *http.Request) {
	var p auth.Policy
	if err := readJSON(w, r, &p); err != nil {
		writeError(w, r, err)
		return
	}
	saved, err := s.svc.Auth.PutPolicy(r.Context(), p)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusCreated, saved)
}

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := s.svc.Auth.ListPolicies(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"policies": policies})
}

func (s *Server) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.Auth.DeletePolicy(r.Context(), r.PathValue("policyID")); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetBucketPolicy(w http.ResponseWriter, r *http.Request) {
	bucket, err := cleanBucket(r.PathValue("bucket"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	p, err := s.svc.Auth.GetBucketPolicy(r.Context(), bucket)
	if err != nil {
		writeError(w, r, err)
		return
	}
	if p == nil {
		writeError(w, r, auth.ErrNoBucketPolicy)
		return
	}
	writeJSON(w, r, http.StatusOK, p)
}

func (s *Server) handlePutBucketPolicy(w http.ResponseWriter, r *http.Request) {
	bucket, err := cleanBucket(r.PathValue("bucket"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	var p auth.Policy
	if err := readJSON(w, r, &p); err != nil {
		writeError(w, r, err)
		return
	}
	saved, err := s.svc.Auth.PutBucketPolicy(r.Context(), bucket, p)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, saved)
}

func (s *Server) handleDeleteBucketPolicy(w http.ResponseWriter, r *http.Request) {
	bucket, err := cleanBucket(r.PathValue("bucket"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	if err := s.svc.Auth.DeleteBucketPolicy(r.Context(), bucket); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
