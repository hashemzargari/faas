package s3

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/fass-storage/fass/internal/contract"
)

// ---------------------------------------------------------------------------
// Object tagging
// ---------------------------------------------------------------------------

func (s *Server) loadObjectForConfig(w http.ResponseWriter, r *http.Request, t target, action contract.Action) (contract.BucketConfig, bool) {
	b, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return contract.BucketConfig{}, false
	}
	if err := s.authorizeBucket(r, action, b, t.Key, map[string]string{
		"s3:versionid": r.URL.Query().Get("versionId"),
	}); err != nil {
		s.fail(w, r, err)
		return contract.BucketConfig{}, false
	}
	return b, true
}

func (s *Server) handleGetObjectTagging(w http.ResponseWriter, r *http.Request, t target) {
	if _, ok := s.loadObjectForConfig(w, r, t, contract.ActionGetObjectTag); !ok {
		return
	}
	tags, err := s.coord.GetObjectTags(r.Context(), t.Bucket, t.Key, versionFromQuery(r))
	if err != nil && !errors.Is(err, contract.ErrNotFound) {
		s.fail(w, r, err)
		return
	}
	writeXML(w, http.StatusOK, taggingXMLFromMap(tags))
}

func (s *Server) handlePutObjectTagging(w http.ResponseWriter, r *http.Request, t target) {
	if _, ok := s.loadObjectForConfig(w, r, t, contract.ActionPutObjectTag); !ok {
		return
	}
	body, apiErr := readBody(r, 64<<10)
	if apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	tags, apiErr := parseTaggingXML(body)
	if apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	if apiErr := s.validateTags(tags); apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	if err := s.coord.PutObjectTags(r.Context(), t.Bucket, t.Key, versionFromQuery(r), tags); err != nil {
		s.fail(w, r, err)
		return
	}
	writeEmpty(w, http.StatusOK)
}

func (s *Server) handleDeleteObjectTagging(w http.ResponseWriter, r *http.Request, t target) {
	if _, ok := s.loadObjectForConfig(w, r, t, contract.ActionPutObjectTag); !ok {
		return
	}
	if err := s.coord.PutObjectTags(r.Context(), t.Bucket, t.Key, versionFromQuery(r), map[string]string{}); err != nil {
		s.fail(w, r, err)
		return
	}
	writeEmpty(w, http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Object retention and legal hold
// ---------------------------------------------------------------------------

func (s *Server) handleGetObjectRetention(w http.ResponseWriter, r *http.Request, t target) {
	b, ok := s.loadObjectForConfig(w, r, t, contract.ActionGetObject)
	if !ok {
		return
	}
	if !b.ObjectLock {
		s.fail(w, r, ErrObjectLockConfigFault)
		return
	}
	ret, err := s.coord.GetObjectRetention(r.Context(), t.Bucket, t.Key, versionFromQuery(r))
	if err != nil {
		if errors.Is(err, contract.ErrNotFound) {
			s.fail(w, r, ErrObjectLockConfigFault)
			return
		}
		s.fail(w, r, err)
		return
	}
	if ret == nil || ret.Mode == "" {
		s.fail(w, r, ErrObjectLockConfigFault)
		return
	}
	writeXML(w, http.StatusOK, retentionXML{
		Mode:            ret.Mode,
		RetainUntilDate: ret.RetainUntil.UTC().Format(time.RFC3339),
	})
}

func (s *Server) handlePutObjectRetention(w http.ResponseWriter, r *http.Request, t target) {
	b, ok := s.loadObjectForConfig(w, r, t, contract.ActionPutObject)
	if !ok {
		return
	}
	if !b.ObjectLock {
		s.fail(w, r, ErrObjectLockConfigFault)
		return
	}
	var req retentionXML
	if apiErr := decodeXMLBody(r, 64<<10, &req); apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	mode := strings.ToUpper(strings.TrimSpace(req.Mode))
	if mode != "GOVERNANCE" && mode != "COMPLIANCE" {
		s.fail(w, r, ErrInvalidRetention.withMessage("Invalid retention mode %q.", req.Mode))
		return
	}
	until, err := parseRetainUntil(strings.TrimSpace(req.RetainUntilDate))
	if err != nil || !until.After(s.now()) {
		s.fail(w, r, ErrInvalidRetention.withMessage("The retain-until date must be a valid future ISO-8601 timestamp."))
		return
	}

	existing, _ := s.coord.GetObjectRetention(r.Context(), t.Bucket, t.Key, versionFromQuery(r))
	ret := &contract.Retention{Mode: mode, RetainUntil: until, LegalHold: existing != nil && existing.LegalHold}
	if existing != nil {
		if apiErr := s.checkRetentionExtension(r, b, t.Key, existing, ret); apiErr != nil {
			s.fail(w, r, apiErr)
			return
		}
	}
	if err := s.coord.PutObjectRetention(r.Context(), t.Bucket, t.Key, versionFromQuery(r), ret); err != nil {
		s.fail(w, r, err)
		return
	}
	writeEmpty(w, http.StatusOK)
}

// checkRetentionExtension enforces "retention can only be extended" (docs/05
// §5.2). Shortening a COMPLIANCE retention is never allowed; shortening a
// GOVERNANCE retention needs x-amz-bypass-governance-retention=true and the
// bypass permission.
func (s *Server) checkRetentionExtension(r *http.Request, b contract.BucketConfig, key string, existing, next *contract.Retention) *APIError {
	if existing.Mode == "COMPLIANCE" {
		if !next.RetainUntil.After(existing.RetainUntil) || next.Mode != "COMPLIANCE" {
			return ErrInvalidRetention.withMessage("A COMPLIANCE retention period can only be extended, never shortened or downgraded.")
		}
		return nil
	}
	// GOVERNANCE.
	if next.Mode == "COMPLIANCE" || next.RetainUntil.After(existing.RetainUntil) {
		return nil
	}
	if !isTrueHeader(r, "x-amz-bypass-governance-retention") {
		return ErrAccessDenied.withMessage("Shortening a GOVERNANCE retention period requires x-amz-bypass-governance-retention: true.")
	}
	if err := s.authorizeBucket(r, contract.ActionBypassGovern, b, key, nil); err != nil {
		return mapError(err)
	}
	return nil
}

func (s *Server) handleGetObjectLegalHold(w http.ResponseWriter, r *http.Request, t target) {
	b, ok := s.loadObjectForConfig(w, r, t, contract.ActionGetObject)
	if !ok {
		return
	}
	if !b.ObjectLock {
		s.fail(w, r, ErrObjectLockConfigFault)
		return
	}
	ret, err := s.coord.GetObjectRetention(r.Context(), t.Bucket, t.Key, versionFromQuery(r))
	if err != nil && !errors.Is(err, contract.ErrNotFound) {
		s.fail(w, r, err)
		return
	}
	status := "OFF"
	if ret != nil && ret.LegalHold {
		status = "ON"
	}
	writeXML(w, http.StatusOK, legalHoldXML{Status: status})
}

func (s *Server) handlePutObjectLegalHold(w http.ResponseWriter, r *http.Request, t target) {
	b, ok := s.loadObjectForConfig(w, r, t, contract.ActionPutObject)
	if !ok {
		return
	}
	if !b.ObjectLock {
		s.fail(w, r, ErrObjectLockConfigFault)
		return
	}
	var req legalHoldXML
	if apiErr := decodeXMLBody(r, 64<<10, &req); apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	status := strings.ToUpper(strings.TrimSpace(req.Status))
	if status != "ON" && status != "OFF" {
		s.fail(w, r, ErrMalformedXML)
		return
	}
	existing, err := s.coord.GetObjectRetention(r.Context(), t.Bucket, t.Key, versionFromQuery(r))
	if err != nil && !errors.Is(err, contract.ErrNotFound) {
		s.fail(w, r, err)
		return
	}
	if existing == nil {
		existing = &contract.Retention{}
	}
	existing.LegalHold = status == "ON"
	if err := s.coord.PutObjectRetention(r.Context(), t.Bucket, t.Key, versionFromQuery(r), existing); err != nil {
		s.fail(w, r, err)
		return
	}
	writeEmpty(w, http.StatusOK)
}
