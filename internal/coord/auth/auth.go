// Package auth implements the coordinator's identity and policy service and the
// contract.Authorizer the gateway uses.
//
// The division of labour is the documented one (docs/04 §5.1): the gateway
// verifies SigV2/SigV4 signatures locally, the coordinator decides. VerifySignature
// therefore returns the access key's HMAC secret (and the gateway caches it for
// at most 60 s), while Authorize evaluates the four-stage chain:
//
//	access key -> IAM policy (explicit deny wins) -> bucket policy (deny wins)
//	           -> ACL fallback (must explicitly allow for cross-account access)
//
// Every resource is addressed as a CRN (contract.Resource.CRN), so a policy is
// transport-independent and auditable.
//
// Secret storage: the coordinator must hand the HMAC key back to gateways, so a
// verifier cannot store only a hash. The embedded dev engine stores the secret in
// a 0600 file that only the coordinator process can read; the PostgreSQL schema
// makes the column a wrapped ciphertext (docs/schema.sql) and production requires
// the coordinator's KMS to unwrap it.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/coord/coerr"
	"github.com/fass-storage/fass/internal/coord/id"
	"github.com/fass-storage/fass/internal/coord/meta"
	"github.com/fass-storage/fass/internal/storage"
)

var (
	spaceAccessKeys   = []byte("access_keys")
	spacePolicies     = []byte("iam_policies")
	spaceBucketPolicy = []byte("bucket_policies")
)

// AccessKeyStatus values.
const (
	StatusActive   = "Active"
	StatusInactive = "Inactive"
)

// AccessKey is a programmatic credential. Secret is the HMAC material a gateway
// needs to verify SigV4; it is returned exactly once to the caller that creates
// the key and is never logged.
type AccessKey struct {
	AccessKeyID string             `json:"access_key_id"`
	Secret      string             `json:"secret"`
	TenantID    contract.TenantID  `json:"tenant_id"`
	ProjectID   contract.ProjectID `json:"project_id"`
	IsRoot      bool               `json:"is_root"`
	Groups      []string           `json:"groups,omitempty"`
	Status      string             `json:"status"`
	CreatedAt   time.Time          `json:"created_at"`
	ExpiresAt   *time.Time         `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time         `json:"last_used_at,omitempty"`
}

// Principal converts the key to the contract's authenticated principal.
func (k AccessKey) Principal() contract.Principal {
	return contract.Principal{
		AccessKeyID: k.AccessKeyID,
		TenantID:    k.TenantID,
		ProjectID:   k.ProjectID,
		IsRoot:      k.IsRoot,
		Groups:      append([]string(nil), k.Groups...),
	}
}

// ScopeKind says where a policy is attached.
type ScopeKind string

const (
	ScopeTenant    ScopeKind = "tenant"
	ScopeProject   ScopeKind = "project"
	ScopeAccessKey ScopeKind = "access_key"
)

// Policy is an IAM policy document (docs/04 §5.1): an ordered, denied-wins set of
// statements scoped to a tenant, project or access key.
type Policy struct {
	ID          string             `json:"policy_id"`
	Name        string             `json:"name"`
	Scope       ScopeKind          `json:"scope"`
	TenantID    contract.TenantID  `json:"tenant_id,omitempty"`
	ProjectID   contract.ProjectID `json:"project_id,omitempty"`
	AccessKeyID string             `json:"access_key_id,omitempty"`
	Statements  []Statement        `json:"statements"`
	CreatedAt   time.Time          `json:"created_at"`
}

// Statement is one policy statement. Conditions are simple string matches on the
// documented condition keys (s3:prefix, s3:max-keys, s3:versionid, s3:x-amz-acl,
// s3:ExistingObjectTag/*); '*' is a wildcard.
type Statement struct {
	Effect     string            `json:"effect"` // Allow | Deny
	Actions    []string          `json:"actions"`
	Resources  []string          `json:"resources"`
	Conditions map[string]string `json:"conditions,omitempty"`
}

// Service is the auth service.
type Service struct {
	db   *storage.DB
	meta *meta.Service
	now  func() time.Time
}

// New creates the auth service. meta is used for bucket ownership and ACL
// fallback.
func New(db *storage.DB, m *meta.Service) *Service {
	return &Service{db: db, meta: m, now: time.Now}
}

// SetClock overrides the clock (tests).
func (s *Service) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// ---------------------------------------------------------------------------
// Access keys
// ---------------------------------------------------------------------------

// AccessKeySpec is the input for CreateAccessKey. An empty AccessKeyID or Secret
// is generated.
type AccessKeySpec struct {
	AccessKeyID string
	Secret      string
	TenantID    contract.TenantID
	ProjectID   contract.ProjectID
	IsRoot      bool
	Groups      []string
	ExpiresAt   *time.Time
}

// CreateAccessKey creates an access key. The returned record contains the secret,
// which is only available at creation time (subsequent reads also return it
// because the coordinator must answer VerifySignature; callers must not log it).
func (s *Service) CreateAccessKey(ctx context.Context, spec AccessKeySpec) (AccessKey, error) {
	if err := ctx.Err(); err != nil {
		return AccessKey{}, err
	}
	if spec.TenantID == "" || spec.ProjectID == "" {
		return AccessKey{}, coerr.Invalidf("tenant_id and project_id are required")
	}
	keyID := spec.AccessKeyID
	if keyID == "" {
		var err error
		keyID, err = newAccessKeyID()
		if err != nil {
			return AccessKey{}, err
		}
	}
	if len(keyID) < 16 || len(keyID) > 128 {
		return AccessKey{}, coerr.Invalidf("access key id must be 16..128 characters")
	}
	secret := spec.Secret
	if secret == "" {
		var err error
		secret, err = id.NewSecret(32)
		if err != nil {
			return AccessKey{}, coerr.Wrap(err, 500, coerr.CodeInternal, coerr.ErrInternal.Message)
		}
	}
	if len(secret) < 32 {
		return AccessKey{}, coerr.Invalidf("secret must be at least 32 characters")
	}
	rec := AccessKey{
		AccessKeyID: keyID,
		Secret:      secret,
		TenantID:    spec.TenantID,
		ProjectID:   spec.ProjectID,
		IsRoot:      spec.IsRoot,
		Groups:      append([]string(nil), spec.Groups...),
		Status:      StatusActive,
		CreatedAt:   s.now().UTC(),
		ExpiresAt:   spec.ExpiresAt,
	}
	err := s.db.Update(ctx, func(tx *storage.WriteTx) error {
		if tx.Has(spaceAccessKeys, []byte(keyID)) {
			return coerr.E(409, coerr.CodeConflict, "access key %q already exists", keyID)
		}
		return storage.PutJSON(tx, spaceAccessKeys, []byte(keyID), rec)
	})
	if err != nil {
		return AccessKey{}, err
	}
	return rec, nil
}

// GetAccessKey returns the stored access key (including its secret). Callers must
// treat the secret as sensitive.
func (s *Service) GetAccessKey(ctx context.Context, keyID string) (AccessKey, error) {
	var out AccessKey
	if err := ctx.Err(); err != nil {
		return out, err
	}
	err := s.db.View(ctx, func(tx *storage.ReadTx) error {
		rec, err := storage.GetJSON[AccessKey](tx, spaceAccessKeys, []byte(keyID))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.ErrAccessDenied
		}
		if err != nil {
			return err
		}
		out = rec
		return nil
	})
	return out, err
}

// ListAccessKeys returns access keys, filtered to a tenant/project when given.
func (s *Service) ListAccessKeys(ctx context.Context, tenant contract.TenantID, project contract.ProjectID) ([]AccessKey, error) {
	var out []AccessKey
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	err := s.db.View(ctx, func(tx *storage.ReadTx) error {
		return storage.ScanJSON[AccessKey](tx, spaceAccessKeys, nil, func(_ []byte, k AccessKey) error {
			if tenant != "" && k.TenantID != tenant {
				return nil
			}
			if project != "" && k.ProjectID != project {
				return nil
			}
			out = append(out, k)
			return nil
		})
	})
	return out, err
}

// SetAccessKeyStatus activates or deactivates a key.
func (s *Service) SetAccessKeyStatus(ctx context.Context, keyID, status string) error {
	if status != StatusActive && status != StatusInactive {
		return coerr.Invalidf("status must be Active or Inactive")
	}
	return s.db.Update(ctx, func(tx *storage.WriteTx) error {
		rec, err := storage.GetJSON[AccessKey](tx, spaceAccessKeys, []byte(keyID))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.ErrAccessDenied
		}
		if err != nil {
			return err
		}
		rec.Status = status
		return storage.PutJSON(tx, spaceAccessKeys, []byte(keyID), rec)
	})
}

// DeleteAccessKey removes a key.
func (s *Service) DeleteAccessKey(ctx context.Context, keyID string) error {
	return s.db.Update(ctx, func(tx *storage.WriteTx) error {
		if !tx.Has(spaceAccessKeys, []byte(keyID)) {
			return coerr.ErrAccessDenied
		}
		return tx.Delete(spaceAccessKeys, []byte(keyID))
	})
}

func newAccessKeyID() (string, error) {
	var b [10]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("auth: generate access key id: %w", err)
	}
	return "FASS" + strings.ToUpper(hex.EncodeToString(b[:8])), nil
}

// ---------------------------------------------------------------------------
// contract.Authorizer
// ---------------------------------------------------------------------------

// VerifySignature resolves an access key to a principal and the HMAC secret the
// gateway needs for local SigV2/SigV4 verification.
func (s *Service) VerifySignature(ctx context.Context, accessKeyID string) (contract.Principal, []byte, error) {
	if accessKeyID == "" {
		return contract.Principal{}, nil, fmt.Errorf("auth: empty access key: %w", contract.ErrForbidden)
	}
	key, err := s.GetAccessKey(ctx, accessKeyID)
	if err != nil {
		return contract.Principal{}, nil, fmt.Errorf("auth: unknown access key %q: %w", accessKeyID, contract.ErrForbidden)
	}
	if key.Status != StatusActive {
		return contract.Principal{}, nil, fmt.Errorf("auth: access key %q is %s: %w", accessKeyID, key.Status, contract.ErrForbidden)
	}
	now := s.now()
	if key.ExpiresAt != nil && now.After(*key.ExpiresAt) {
		return contract.Principal{}, nil, fmt.Errorf("auth: access key %q has expired: %w", accessKeyID, contract.ErrForbidden)
	}
	secret := []byte(key.Secret)
	return key.Principal(), secret, nil
}

// Authorize evaluates the documented four-stage chain.
func (s *Service) Authorize(ctx context.Context, rc contract.RequestContext) (contract.Decision, error) {
	if err := ctx.Err(); err != nil {
		return contract.Decision{}, err
	}
	if rc.Now.IsZero() {
		rc.Now = s.now()
	}
	key, err := s.GetAccessKey(ctx, rc.Principal.AccessKeyID)
	if err != nil {
		// A principal without a resolvable access key is denied, never allowed.
		return contract.Decision{Allowed: false, Reason: "unknown access key"}, nil
	}
	if key.Status != StatusActive {
		return contract.Decision{Allowed: false, Reason: "access key is " + key.Status}, nil
	}
	if key.ExpiresAt != nil && rc.Now.After(*key.ExpiresAt) {
		return contract.Decision{Allowed: false, Reason: "access key expired"}, nil
	}
	// Use the key's authoritative principal: a caller cannot claim a tenant or
	// root flag its key does not have.
	rc.Principal = key.Principal()

	// Normalise resource tenancy from the bucket itself. A CRN names the bucket
	// owner's tenant/project, not the caller's, which is what makes a bucket
	// policy or ACL grant from another account addressable at all.
	if rc.Resource.Bucket != "" {
		if b, err := s.meta.GetBucket(ctx, rc.Resource.Bucket); err == nil {
			rc.Resource.TenantID = b.TenantID
			rc.Resource.ProjectID = b.ProjectID
			if rc.Resource.Region == "" {
				rc.Resource.Region = b.Region
			}
		}
	}

	// Stage 1: IAM policies (deny wins, then any allow).
	policies, err := s.policiesFor(ctx, key)
	if err != nil {
		return contract.Decision{}, err
	}
	if d, matched := evalPolicies(policies, rc); matched {
		return d, nil
	}

	// Stage 2: bucket policy (deny wins, then any allow).
	if rc.Resource.Bucket != "" {
		bp, err := s.GetBucketPolicy(ctx, rc.Resource.Bucket)
		if err != nil && !errors.Is(err, storage.ErrNotFound) && coerr.CodeOf(err) != "NoSuchBucketPolicy" {
			return contract.Decision{}, err
		}
		if bp != nil {
			if d, matched := evalPolicies([]Policy{*bp}, rc); matched {
				return d, nil
			}
		}
	}

	// Stage 3: ACL fallback. The owning project's keys are implicitly allowed;
	// anyone else needs an explicit grant on the bucket (or object) ACL.
	return s.authorizeByACL(ctx, key, rc)
}

// policiesFor returns the IAM policies applying to a key: access-key-scoped,
// project-scoped and tenant-scoped, in that order.
func (s *Service) policiesFor(ctx context.Context, key AccessKey) ([]Policy, error) {
	var out []Policy
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	err := s.db.View(ctx, func(tx *storage.ReadTx) error {
		return storage.ScanJSON[Policy](tx, spacePolicies, nil, func(_ []byte, p Policy) error {
			switch p.Scope {
			case ScopeAccessKey:
				if p.AccessKeyID == key.AccessKeyID {
					out = append(out, p)
				}
			case ScopeProject:
				if p.TenantID == key.TenantID && p.ProjectID == key.ProjectID {
					out = append(out, p)
				}
			case ScopeTenant:
				if p.TenantID == key.TenantID {
					out = append(out, p)
				}
			}
			return nil
		})
	})
	return out, err
}

// evalPolicies applies deny-wins over a policy set. matched is false when no
// statement applied, which lets the chain fall through to the next stage.
func evalPolicies(policies []Policy, rc contract.RequestContext) (contract.Decision, bool) {
	var allowReason string
	matched := false
	for _, p := range policies {
		for _, st := range p.Statements {
			if !statementMatches(st, rc) {
				continue
			}
			matched = true
			if strings.EqualFold(st.Effect, "Deny") {
				return contract.Decision{Allowed: false, Reason: fmt.Sprintf("explicit deny in policy %s", p.ID)}, true
			}
			if allowReason == "" {
				allowReason = fmt.Sprintf("allowed by policy %s", p.ID)
			}
		}
	}
	if matched && allowReason != "" {
		return contract.Decision{Allowed: true, Reason: allowReason}, true
	}
	return contract.Decision{}, false
}

func statementMatches(st Statement, rc contract.RequestContext) bool {
	for _, action := range st.Actions {
		if !matchWildcard(string(rc.Action), action) {
			continue
		}
		for _, res := range st.Resources {
			if !rc.Resource.Matches(res) {
				continue
			}
			if conditionsMatch(st.Conditions, rc.Condition) {
				return true
			}
		}
	}
	return false
}

func conditionsMatch(conds, actual map[string]string) bool {
	for k, want := range conds {
		got, ok := actual[k]
		if !ok {
			return false
		}
		if !matchWildcard(got, want) {
			return false
		}
	}
	return true
}

// matchWildcard supports '*' (any run) and '?' (one byte) in actions, condition
// values and resource patterns.
func matchWildcard(s, pattern string) bool {
	if pattern == "*" {
		return true
	}
	// Iterative glob match; linear in practice for policy-sized inputs.
	var si, pi int
	star, mark := -1, 0
	for si < len(s) {
		switch {
		case pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]):
			si++
			pi++
		case pi < len(pattern) && pattern[pi] == '*':
			star = pi
			mark = si
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

// ---------------------------------------------------------------------------
// Policies (IAM and bucket)
// ---------------------------------------------------------------------------

// PutPolicy stores an IAM policy.
func (s *Service) PutPolicy(ctx context.Context, p Policy) (Policy, error) {
	if err := validatePolicy(p); err != nil {
		return Policy{}, err
	}
	if p.ID == "" {
		p.ID = id.New()
	}
	p.CreatedAt = s.now().UTC()
	err := s.db.Update(ctx, func(tx *storage.WriteTx) error {
		return storage.PutJSON(tx, spacePolicies, []byte(p.ID), p)
	})
	return p, err
}

// GetPolicy returns one IAM policy.
func (s *Service) GetPolicy(ctx context.Context, policyID string) (Policy, error) {
	var out Policy
	if err := ctx.Err(); err != nil {
		return out, err
	}
	err := s.db.View(ctx, func(tx *storage.ReadTx) error {
		rec, err := storage.GetJSON[Policy](tx, spacePolicies, []byte(policyID))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.E(404, "NoSuchPolicy", "policy %q does not exist", policyID)
		}
		if err != nil {
			return err
		}
		out = rec
		return nil
	})
	return out, err
}

// ListPolicies returns all IAM policies.
func (s *Service) ListPolicies(ctx context.Context) ([]Policy, error) {
	var out []Policy
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	err := s.db.View(ctx, func(tx *storage.ReadTx) error {
		return storage.ScanJSON[Policy](tx, spacePolicies, nil, func(_ []byte, p Policy) error {
			out = append(out, p)
			return nil
		})
	})
	return out, err
}

// DeletePolicy removes an IAM policy.
func (s *Service) DeletePolicy(ctx context.Context, policyID string) error {
	return s.db.Update(ctx, func(tx *storage.WriteTx) error {
		if !tx.Has(spacePolicies, []byte(policyID)) {
			return coerr.E(404, "NoSuchPolicy", "policy %q does not exist", policyID)
		}
		return tx.Delete(spacePolicies, []byte(policyID))
	})
}

func validatePolicy(p Policy) error {
	if p.Name == "" {
		return coerr.Invalidf("policy name is required")
	}
	switch p.Scope {
	case ScopeTenant:
		if p.TenantID == "" {
			return coerr.Invalidf("tenant-scoped policies need tenant_id")
		}
	case ScopeProject:
		if p.TenantID == "" || p.ProjectID == "" {
			return coerr.Invalidf("project-scoped policies need tenant_id and project_id")
		}
	case ScopeAccessKey:
		if p.AccessKeyID == "" {
			return coerr.Invalidf("access-key-scoped policies need access_key_id")
		}
	default:
		return coerr.Invalidf("policy scope must be tenant, project or access_key")
	}
	if len(p.Statements) == 0 {
		return coerr.Invalidf("policy has no statements")
	}
	for i, st := range p.Statements {
		if !strings.EqualFold(st.Effect, "Allow") && !strings.EqualFold(st.Effect, "Deny") {
			return coerr.Invalidf("statement %d: effect must be Allow or Deny", i)
		}
		if len(st.Actions) == 0 || len(st.Resources) == 0 {
			return coerr.Invalidf("statement %d: actions and resources are required", i)
		}
	}
	return nil
}

// ErrNoBucketPolicy is returned when a bucket has no policy attached.
var ErrNoBucketPolicy = &coerr.Error{Status: 404, Code: "NoSuchBucketPolicy", Message: "The bucket policy does not exist"}

// PutBucketPolicy attaches a bucket policy.
func (s *Service) PutBucketPolicy(ctx context.Context, bucket string, p Policy) (Policy, error) {
	if err := validatePolicy(p); err != nil {
		return Policy{}, err
	}
	if _, err := s.meta.GetBucket(ctx, bucket); err != nil {
		return Policy{}, err
	}
	if p.ID == "" {
		p.ID = id.New()
	}
	p.CreatedAt = s.now().UTC()
	err := s.db.Update(ctx, func(tx *storage.WriteTx) error {
		return storage.PutJSON(tx, spaceBucketPolicy, []byte(bucket), p)
	})
	return p, err
}

// GetBucketPolicy returns a bucket policy, or nil when none is attached.
func (s *Service) GetBucketPolicy(ctx context.Context, bucket string) (*Policy, error) {
	var out *Policy
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	err := s.db.View(ctx, func(tx *storage.ReadTx) error {
		rec, err := storage.GetJSON[Policy](tx, spaceBucketPolicy, []byte(bucket))
		if errors.Is(err, storage.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		out = &rec
		return nil
	})
	return out, err
}

// DeleteBucketPolicy removes a bucket policy.
func (s *Service) DeleteBucketPolicy(ctx context.Context, bucket string) error {
	return s.db.Update(ctx, func(tx *storage.WriteTx) error {
		if !tx.Has(spaceBucketPolicy, []byte(bucket)) {
			return ErrNoBucketPolicy
		}
		return tx.Delete(spaceBucketPolicy, []byte(bucket))
	})
}

// ---------------------------------------------------------------------------
// ACL fallback
// ---------------------------------------------------------------------------

// authorizeByACL implements the final chain stage: the owner project is allowed,
// everyone else needs an explicit grant carrying the required permission. The
// bucket ACL is checked first, then (for object actions) the object ACL.
func (s *Service) authorizeByACL(ctx context.Context, key AccessKey, rc contract.RequestContext) (contract.Decision, error) {
	if rc.Resource.Bucket == "" {
		// Tenant/project-level actions: only the owning project (or root) may act.
		if key.IsRoot {
			return contract.Decision{Allowed: true, Reason: "root access key"}, nil
		}
		return contract.Decision{Allowed: false, Reason: "no policy allows this action"}, nil
	}
	bucket, err := s.meta.GetBucket(ctx, rc.Resource.Bucket)
	if err != nil {
		return contract.Decision{Allowed: false, Reason: "bucket does not exist"}, nil
	}
	if key.IsRoot || (key.TenantID == bucket.TenantID && key.ProjectID == bucket.ProjectID) {
		return contract.Decision{Allowed: true, Reason: "bucket owner"}, nil
	}
	needed := requiredPermissions(rc.Action)
	if len(needed) == 0 {
		return contract.Decision{Allowed: false, Reason: "no ACL permission maps to this action"}, nil
	}
	bucketACL, err := s.meta.GetBucketACL(ctx, bucket.Name)
	if err != nil {
		return contract.Decision{}, err
	}
	if aclAllows(bucketACL, key, needed) {
		return contract.Decision{Allowed: true, Reason: "bucket ACL grant"}, nil
	}
	if isObjectAction(rc.Action) && rc.Resource.Key != "" {
		objectACL, err := s.meta.GetObjectACL(ctx, bucket.Name, rc.Resource.Key, "")
		if err == nil && aclAllows(objectACL, key, needed) {
			return contract.Decision{Allowed: true, Reason: "object ACL grant"}, nil
		}
	}
	return contract.Decision{Allowed: false, Reason: "no matching ACL grant"}, nil
}

// requiredPermissions maps an S3 action to the ACL permission that grants it.
func requiredPermissions(a contract.Action) []string {
	switch a {
	case contract.ActionGetObject, contract.ActionListBucket, contract.ActionListBuckets,
		contract.ActionGetObjectTag:
		return []string{"READ"}
	case contract.ActionPutObject, contract.ActionDeleteObject, contract.ActionCreateBucket,
		contract.ActionDeleteBucket, contract.ActionCreateMultipart, contract.ActionAbortMultipart,
		contract.ActionPutObjectTag:
		return []string{"WRITE"}
	case contract.ActionGetBucketAcl, contract.ActionGetObjectAcl:
		return []string{"READ_ACP"}
	case contract.ActionPutBucketAcl, contract.ActionPutObjectAcl:
		return []string{"WRITE_ACP"}
	case contract.ActionBypassGovern:
		return []string{"WRITE_ACP"}
	}
	return nil
}

func isObjectAction(a contract.Action) bool {
	switch a {
	case contract.ActionGetObject, contract.ActionPutObject, contract.ActionDeleteObject,
		contract.ActionGetObjectAcl, contract.ActionPutObjectAcl, contract.ActionGetObjectTag,
		contract.ActionPutObjectTag:
		return true
	}
	return false
}

// aclAllows reports whether the ACL grants one of needed permissions to the key.
func aclAllows(acl contract.ACL, key AccessKey, needed []string) bool {
	if acl.OwnerID != "" && acl.OwnerID == canonicalOwner(key.TenantID, key.ProjectID) {
		return true
	}
	for _, g := range acl.Grants {
		if !granteeMatches(g.Grantee, key) {
			continue
		}
		if g.Permission == "FULL_CONTROL" {
			return true
		}
		for _, want := range needed {
			if g.Permission == want {
				return true
			}
		}
	}
	return false
}

func granteeMatches(grantee string, key AccessKey) bool {
	if grantee == key.AccessKeyID {
		return true
	}
	if grantee == canonicalOwner(key.TenantID, key.ProjectID) {
		return true
	}
	if grantee == "tenant_"+string(key.TenantID) || grantee == "project_"+string(key.ProjectID) {
		return true
	}
	for _, g := range key.Groups {
		if grantee == g {
			return true
		}
	}
	return false
}

func canonicalOwner(tenant contract.TenantID, project contract.ProjectID) string {
	return fmt.Sprintf("tenant_%s/project_%s", tenant, project)
}
