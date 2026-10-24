package s3

import (
	"encoding/xml"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/gateway/authz"
)

// ---------------------------------------------------------------------------
// ListBuckets / CreateBucket / DeleteBucket / HeadBucket / GetBucketLocation
// ---------------------------------------------------------------------------

func (s *Server) handleListBuckets(w http.ResponseWriter, r *http.Request, _ target) {
	id := s.principal(r)
	if err := s.authorize(r, id, contract.ActionListBuckets, nil, "", "", nil); err != nil {
		s.fail(w, r, err)
		return
	}
	buckets, err := s.coord.ListBuckets(r.Context(), id.Principal)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	res := listAllMyBucketsResult{
		Owner: xmlOwner{ID: ownerIDFromIdentity(id), DisplayName: ownerDisplayName(id)},
	}
	for _, b := range buckets {
		res.Buckets.Bucket = append(res.Buckets.Bucket, bucketXML{Name: b.Name})
	}
	writeXML(w, http.StatusOK, res)
}

func (s *Server) handleCreateBucket(w http.ResponseWriter, r *http.Request, t target) {
	id := s.principal(r)
	if err := validateBucketName(t.Bucket); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.authorize(r, id, contract.ActionCreateBucket, nil, t.Bucket, "", nil); err != nil {
		s.fail(w, r, err)
		return
	}

	// The location constraint is accepted and recorded as the bucket region;
	// any region string is legal (docs/05 §1).
	var createCfg struct {
		LocationConstraint string `xml:"LocationConstraint"`
	}
	if contentLength(r) > 0 {
		if apiErr := decodeXMLBody(r, 64<<10, &createCfg); apiErr != nil {
			s.fail(w, r, apiErr)
			return
		}
	}

	existing, err := s.coord.GetBucket(r.Context(), t.Bucket)
	switch {
	case err == nil:
		if existing.ProjectID == id.Principal.ProjectID {
			s.fail(w, r, ErrBucketAlreadyOwned)
		} else {
			s.fail(w, r, ErrBucketAlreadyExists)
		}
		return
	case !errors.Is(err, contract.ErrNotFound):
		s.fail(w, r, err)
		return
	}

	region := s.region()
	if strings.TrimSpace(createCfg.LocationConstraint) != "" {
		region = strings.TrimSpace(createCfg.LocationConstraint)
	}
	cfg := contract.BucketConfig{
		Name:        t.Bucket,
		TenantID:    id.Principal.TenantID,
		ProjectID:   id.Principal.ProjectID,
		Region:      region,
		Ownership:   "ObjectWriter",
		DefaultRCID: s.cfg.DefaultRCID,
	}
	if strings.EqualFold(r.Header.Get("x-amz-bucket-object-lock-enabled"), "true") {
		cfg.ObjectLock = true
		cfg.Versioning = "Enabled"
	}
	if ownership := r.Header.Get("x-amz-object-ownership"); ownership != "" {
		if ownership != "ObjectWriter" && ownership != "BucketOwnerEnforced" {
			s.fail(w, r, ErrInvalidArgument.withMessage("Invalid x-amz-object-ownership %q.", ownership))
			return
		}
		cfg.Ownership = ownership
	}
	if err := s.coord.CreateBucket(r.Context(), cfg); err != nil {
		if errors.Is(err, contract.ErrAlreadyExists) {
			s.fail(w, r, ErrBucketAlreadyExists)
			return
		}
		s.fail(w, r, err)
		return
	}

	// A canned ACL on creation is applied after the bucket exists.
	if canned := r.Header.Get("x-amz-acl"); canned != "" {
		owner := ownerID(cfg)
		acl, apiErr := cannedACL(canned, owner, owner)
		if !apiErr {
			s.fail(w, r, ErrInvalidArgument.withMessage("Unsupported canned ACL %q.", canned))
			return
		}
		if err := s.coord.PutBucketACL(r.Context(), t.Bucket, acl); err != nil {
			s.fail(w, r, err)
			return
		}
	}

	w.Header().Set("Location", "/"+t.Bucket)
	writeEmpty(w, http.StatusOK)
}

func (s *Server) handleDeleteBucket(w http.ResponseWriter, r *http.Request, t target) {
	b, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.authorizeBucket(r, contract.ActionDeleteBucket, b, "", nil); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.coord.DeleteBucket(r.Context(), t.Bucket); err != nil {
		if errors.Is(err, contract.ErrConflict) {
			s.fail(w, r, ErrBucketNotEmpty)
			return
		}
		s.fail(w, r, err)
		return
	}
	writeEmpty(w, http.StatusNoContent)
}

func (s *Server) handleHeadBucket(w http.ResponseWriter, r *http.Request, t target) {
	b, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.authorizeBucket(r, contract.ActionListBucket, b, "", nil); err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("x-amz-bucket-region", s.regionFor(b))
	writeEmpty(w, http.StatusOK)
}

func (s *Server) handleGetBucketLocation(w http.ResponseWriter, r *http.Request, t target) {
	b, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.authorizeBucket(r, contract.ActionGetBucketConf, b, "", nil); err != nil {
		s.fail(w, r, err)
		return
	}
	region := s.regionFor(b)
	// AWS omits the constraint for us-east-1.
	if region == "us-east-1" {
		region = ""
	}
	writeXML(w, http.StatusOK, locationConstraint{Value: region})
}

// ---------------------------------------------------------------------------
// Versioning
// ---------------------------------------------------------------------------

func (s *Server) handleGetBucketVersioning(w http.ResponseWriter, r *http.Request, t target) {
	b, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.authorizeBucket(r, contract.ActionGetBucketConf, b, "", nil); err != nil {
		s.fail(w, r, err)
		return
	}
	writeXML(w, http.StatusOK, versioningConfigurationXML{Status: b.Versioning})
}

func (s *Server) handlePutBucketVersioning(w http.ResponseWriter, r *http.Request, t target) {
	b, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.authorizeBucket(r, contract.ActionPutBucketConf, b, "", nil); err != nil {
		s.fail(w, r, err)
		return
	}
	var req versioningConfigurationXML
	if apiErr := decodeXMLBody(r, 64<<10, &req); apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	if req.MFADelete != "" {
		s.fail(w, r, ErrNotImplemented.withMessage("MFA Delete is not supported."))
		return
	}
	switch req.Status {
	case "Enabled", "Suspended":
	case "":
		s.fail(w, r, ErrMalformedXML)
		return
	default:
		s.fail(w, r, ErrMalformedXML)
		return
	}
	if b.ObjectLock && req.Status == "Suspended" {
		s.fail(w, r, ErrInvalidBucketState.withMessage("An Object Lock bucket cannot have versioning suspended."))
		return
	}
	if b.Versioning == req.Status {
		writeEmpty(w, http.StatusOK)
		return
	}
	updated := b
	updated.Versioning = req.Status
	if err := s.coord.UpdateBucketConfig(r.Context(), updated); err != nil {
		s.fail(w, r, err)
		return
	}
	writeEmpty(w, http.StatusOK)
}

// ---------------------------------------------------------------------------
// Bucket ACL
// ---------------------------------------------------------------------------

func (s *Server) handleGetBucketACL(w http.ResponseWriter, r *http.Request, t target) {
	b, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.authorizeBucket(r, contract.ActionGetBucketAcl, b, "", nil); err != nil {
		s.fail(w, r, err)
		return
	}
	owner := ownerID(b)
	acl, err := s.coord.GetBucketACL(r.Context(), t.Bucket)
	if err != nil {
		if errors.Is(err, contract.ErrNotFound) {
			acl = defaultACL(owner)
		} else {
			s.fail(w, r, err)
			return
		}
	}
	if len(acl.Grants) == 0 {
		acl = defaultACL(owner)
	}
	writeXML(w, http.StatusOK, aclToXML(acl, ownerDisplayName(s.principal(r))))
}

func (s *Server) handlePutBucketACL(w http.ResponseWriter, r *http.Request, t target) {
	b, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.authorizeBucket(r, contract.ActionPutBucketAcl, b, "", nil); err != nil {
		s.fail(w, r, err)
		return
	}
	if b.Ownership == "BucketOwnerEnforced" {
		s.fail(w, r, ErrACLNotSupported)
		return
	}
	owner := ownerID(b)
	acl, apiErr := aclFromRequest(r, owner, owner)
	if apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	if err := s.coord.PutBucketACL(r.Context(), t.Bucket, acl); err != nil {
		s.fail(w, r, err)
		return
	}
	writeEmpty(w, http.StatusOK)
}

// ---------------------------------------------------------------------------
// Ownership controls
// ---------------------------------------------------------------------------

func (s *Server) handleGetOwnershipControls(w http.ResponseWriter, r *http.Request, t target) {
	b, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.authorizeBucket(r, contract.ActionGetBucketConf, b, "", nil); err != nil {
		s.fail(w, r, err)
		return
	}
	ownership := b.Ownership
	if ownership == "" {
		ownership = "ObjectWriter"
	}
	writeXML(w, http.StatusOK, ownershipControlsXML{Rules: []ownershipRule{{ObjectOwnership: ownership}}})
}

func (s *Server) handlePutOwnershipControls(w http.ResponseWriter, r *http.Request, t target) {
	b, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.authorizeBucket(r, contract.ActionPutBucketConf, b, "", nil); err != nil {
		s.fail(w, r, err)
		return
	}
	var req ownershipControlsXML
	if apiErr := decodeXMLBody(r, 64<<10, &req); apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	if len(req.Rules) != 1 {
		s.fail(w, r, ErrMalformedXML)
		return
	}
	ownership := req.Rules[0].ObjectOwnership
	if ownership != "ObjectWriter" && ownership != "BucketOwnerEnforced" {
		s.fail(w, r, ErrInvalidArgument.withMessage("Invalid ObjectOwnership %q.", ownership))
		return
	}
	if ownership == "BucketOwnerEnforced" {
		if acl, err := s.coord.GetBucketACL(r.Context(), t.Bucket); err == nil && aclGrantsOthers(acl) {
			s.fail(w, r, ErrInvalidBucketACL)
			return
		}
	}
	updated := b
	updated.Ownership = ownership
	if err := s.coord.UpdateBucketConfig(r.Context(), updated); err != nil {
		s.fail(w, r, err)
		return
	}
	writeEmpty(w, http.StatusOK)
}

func (s *Server) handleDeleteOwnershipControls(w http.ResponseWriter, r *http.Request, t target) {
	b, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.authorizeBucket(r, contract.ActionPutBucketConf, b, "", nil); err != nil {
		s.fail(w, r, err)
		return
	}
	updated := b
	updated.Ownership = "ObjectWriter"
	if err := s.coord.UpdateBucketConfig(r.Context(), updated); err != nil {
		s.fail(w, r, err)
		return
	}
	writeEmpty(w, http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Object Lock configuration (bucket level)
// ---------------------------------------------------------------------------

func (s *Server) handleGetObjectLockConfig(w http.ResponseWriter, r *http.Request, t target) {
	b, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.authorizeBucket(r, contract.ActionGetBucketConf, b, "", nil); err != nil {
		s.fail(w, r, err)
		return
	}
	if !b.ObjectLock {
		s.fail(w, r, ErrObjectLockConfigFault)
		return
	}
	writeXML(w, http.StatusOK, objectLockConfigurationXML{ObjectLockEnabled: "Enabled"})
}

func (s *Server) handlePutObjectLockConfig(w http.ResponseWriter, r *http.Request, t target) {
	b, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.authorizeBucket(r, contract.ActionPutBucketConf, b, "", nil); err != nil {
		s.fail(w, r, err)
		return
	}
	var req objectLockConfigurationXML
	if apiErr := decodeXMLBody(r, 64<<10, &req); apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	if req.ObjectLockEnabled != "Enabled" {
		s.fail(w, r, ErrMalformedXML)
		return
	}
	// Object Lock can only be enabled at bucket creation (docs/05 §5.2).
	if !b.ObjectLock {
		s.fail(w, r, ErrInvalidRequest.withMessage("Object Lock can only be enabled when the bucket is created."))
		return
	}
	// The contract persists the enable flag, not bucket default retention; fail
	// loudly rather than silently dropping a WORM default.
	if req.Rule != nil && req.Rule.DefaultRetention != nil {
		s.fail(w, r, ErrNotImplemented.withMessage("Bucket default Object Lock retention is not implemented."))
		return
	}
	writeEmpty(w, http.StatusOK)
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

type lifecycleConfigurationXML struct {
	XMLName xml.Name           `xml:"LifecycleConfiguration"`
	Rules   []lifecycleRuleXML `xml:"Rule"`
}

type lifecycleRuleXML struct {
	ID     string `xml:"ID"`
	Status string `xml:"Status"`
	// Supported actions (docs/05 §5.6).
	Expiration *struct {
		Date                      string `xml:"Date"`
		Days                      int    `xml:"Days"`
		ExpiredObjectDeleteMarker *bool  `xml:"ExpiredObjectDeleteMarker"`
	} `xml:"Expiration"`
	NoncurrentVersionExpiration *struct {
		NoncurrentDays int `xml:"NoncurrentDays"`
	} `xml:"NoncurrentVersionExpiration"`
	// Explicitly unsupported elements.
	Filter                         *struct{} `xml:"Filter"`
	Prefix                         *string   `xml:"Prefix"`
	Transition                     *struct{} `xml:"Transition"`
	NoncurrentVersionTransition    *struct{} `xml:"NoncurrentVersionTransition"`
	AbortIncompleteMultipartUpload *struct{} `xml:"AbortIncompleteMultipartUpload"`
}

func (s *Server) handleGetBucketLifecycle(w http.ResponseWriter, r *http.Request, t target) {
	b, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.authorizeBucket(r, contract.ActionGetBucketConf, b, "", nil); err != nil {
		s.fail(w, r, err)
		return
	}
	body, err := s.coord.GetBucketLifecycle(r.Context(), t.Bucket)
	if err != nil {
		if errors.Is(err, contract.ErrNotFound) {
			s.fail(w, r, ErrNoSuchLifecycle)
			return
		}
		s.fail(w, r, err)
		return
	}
	if len(body) == 0 {
		s.fail(w, r, ErrNoSuchLifecycle)
		return
	}
	writeRawXML(w, http.StatusOK, body)
}

func (s *Server) handlePutBucketLifecycle(w http.ResponseWriter, r *http.Request, t target) {
	b, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.authorizeBucket(r, contract.ActionPutBucketConf, b, "", nil); err != nil {
		s.fail(w, r, err)
		return
	}
	body, apiErr := readBody(r, 1<<20)
	if apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	if apiErr := validateLifecycle(body); apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	if err := s.coord.PutBucketLifecycle(r.Context(), t.Bucket, body); err != nil {
		s.fail(w, r, err)
		return
	}
	writeEmpty(w, http.StatusOK)
}

func (s *Server) handleDeleteBucketLifecycle(w http.ResponseWriter, r *http.Request, t target) {
	b, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.authorizeBucket(r, contract.ActionPutBucketConf, b, "", nil); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.coord.DeleteBucketLifecycle(r.Context(), t.Bucket); err != nil {
		s.fail(w, r, err)
		return
	}
	writeEmpty(w, http.StatusNoContent)
}

// validateLifecycle enforces the partial lifecycle surface in docs/05 §5.6.
func validateLifecycle(body []byte) *APIError {
	var doc lifecycleConfigurationXML
	if err := xml.Unmarshal(body, &doc); err != nil {
		return ErrMalformedXML
	}
	if len(doc.Rules) == 0 {
		return ErrMalformedXML
	}
	midnight := func(t time.Time) bool {
		t = t.UTC()
		return t.Hour() == 0 && t.Minute() == 0 && t.Second() == 0 && t.Nanosecond() == 0
	}
	for _, rule := range doc.Rules {
		if rule.Status != "Enabled" && rule.Status != "Disabled" {
			return ErrMalformedXML
		}
		if rule.Filter != nil || rule.Prefix != nil || rule.Transition != nil ||
			rule.NoncurrentVersionTransition != nil || rule.AbortIncompleteMultipartUpload != nil {
			return ErrInvalidRequest.withMessage("This lifecycle configuration uses an unsupported rule element; only Expiration and NoncurrentVersionExpiration are supported.")
		}
		if rule.Expiration == nil && rule.NoncurrentVersionExpiration == nil {
			return ErrInvalidRequest.withMessage("Each lifecycle rule must have an Expiration or NoncurrentVersionExpiration action.")
		}
		if e := rule.Expiration; e != nil {
			hasDate := strings.TrimSpace(e.Date) != ""
			hasDays := e.Days > 0
			hasDeleteMarker := e.ExpiredObjectDeleteMarker != nil && *e.ExpiredObjectDeleteMarker
			if hasDate && hasDays {
				return ErrMalformedXML
			}
			if hasDeleteMarker && (hasDate || hasDays) {
				return ErrInvalidRequest.withMessage("ExpiredObjectDeleteMarker cannot be combined with Date or Days.")
			}
			if !hasDate && !hasDays && !hasDeleteMarker {
				return ErrMalformedXML
			}
			if hasDate {
				t, err := time.Parse(time.RFC3339, e.Date)
				if err != nil || !midnight(t) {
					return ErrInvalidRequest.withMessage("Expiration.Date must be at midnight UTC in ISO-8601 format.")
				}
			}
		}
		if nc := rule.NoncurrentVersionExpiration; nc != nil && nc.NoncurrentDays <= 0 {
			return ErrMalformedXML
		}
	}
	return nil
}

// ownerIDFromIdentity is the owner id used before a bucket exists.
func ownerIDFromIdentity(id authz.Identity) string {
	if id.Principal.ProjectID != "" {
		return string(id.Principal.ProjectID)
	}
	if id.Principal.TenantID != "" {
		return string(id.Principal.TenantID)
	}
	return "anonymous"
}
