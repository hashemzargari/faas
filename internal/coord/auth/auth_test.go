package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/coord/auth"
	"github.com/fass-storage/fass/internal/coord/id"
	"github.com/fass-storage/fass/internal/coord/meta"
	"github.com/fass-storage/fass/internal/storage"
)

func newAuth(t *testing.T) (*auth.Service, *meta.Service) {
	t.Helper()
	db, err := storage.Open("")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	m := meta.New(db)
	a := auth.New(db, m)
	a.SetClock(func() time.Time { return time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC) })
	return a, m
}

func createKey(t *testing.T, a *auth.Service, tenant contract.TenantID, project contract.ProjectID, root bool) auth.AccessKey {
	t.Helper()
	key, err := a.CreateAccessKey(context.Background(), auth.AccessKeySpec{
		TenantID:  tenant,
		ProjectID: project,
		IsRoot:    root,
		Groups:    []string{"AuthenticatedUsers"},
	})
	if err != nil {
		t.Fatalf("create access key: %v", err)
	}
	return key
}

func createBucket(t *testing.T, m *meta.Service, name string, tenant contract.TenantID, project contract.ProjectID) contract.BucketConfig {
	t.Helper()
	cfg := contract.BucketConfig{
		BucketID:  contract.BucketID(id.New()),
		Name:      name,
		TenantID:  tenant,
		ProjectID: project,
		Region:    contract.DefaultRegion,
		Ownership: "ObjectWriter",
	}
	if err := m.CreateBucket(context.Background(), cfg); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	return cfg
}

func TestVerifySignatureReturnsHMACMaterial(t *testing.T) {
	a, _ := newAuth(t)
	ctx := context.Background()
	key := createKey(t, a, "tenant-1", "project-1", false)
	if len(key.Secret) < 32 {
		t.Fatalf("secret too short: %d", len(key.Secret))
	}

	principal, secret, err := a.VerifySignature(ctx, key.AccessKeyID)
	if err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	if principal.TenantID != "tenant-1" || principal.ProjectID != "project-1" || principal.AccessKeyID != key.AccessKeyID {
		t.Fatalf("principal = %+v", principal)
	}
	if string(secret) != key.Secret {
		t.Fatalf("HMAC secret mismatch")
	}

	if _, _, err := a.VerifySignature(ctx, "FASSUNKNOWN0000000"); !errors.Is(err, contract.ErrForbidden) {
		t.Fatalf("unknown key error = %v, want contract.ErrForbidden", err)
	}
	if err := a.SetAccessKeyStatus(ctx, key.AccessKeyID, auth.StatusInactive); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if _, _, err := a.VerifySignature(ctx, key.AccessKeyID); !errors.Is(err, contract.ErrForbidden) {
		t.Fatalf("inactive key error = %v, want contract.ErrForbidden", err)
	}
}

func TestExpiredKeyIsRejected(t *testing.T) {
	a, _ := newAuth(t)
	ctx := context.Background()
	past := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	key, err := a.CreateAccessKey(ctx, auth.AccessKeySpec{TenantID: "t", ProjectID: "p", ExpiresAt: &past})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, _, err := a.VerifySignature(ctx, key.AccessKeyID); !errors.Is(err, contract.ErrForbidden) {
		t.Fatalf("expected expired key rejection, got %v", err)
	}
	dc, err := a.Authorize(ctx, contract.RequestContext{
		Principal: key.Principal(),
		Action:    contract.ActionListBuckets,
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if dc.Allowed {
		t.Fatalf("expired key was allowed")
	}
}

func TestAuthorizeExplicitDenyWins(t *testing.T) {
	a, m := newAuth(t)
	ctx := context.Background()
	key := createKey(t, a, "tenant-1", "project-1", false)
	createBucket(t, m, "public-data", "tenant-1", "project-1")

	allow := auth.Policy{
		Name:      "allow-read",
		Scope:     auth.ScopeProject,
		TenantID:  "tenant-1",
		ProjectID: "project-1",
		Statements: []auth.Statement{{
			Effect:    "Allow",
			Actions:   []string{"s3:Get*", "s3:List*"},
			Resources: []string{"*"},
		}},
	}
	deny := auth.Policy{
		Name:      "deny-secret",
		Scope:     auth.ScopeProject,
		TenantID:  "tenant-1",
		ProjectID: "project-1",
		Statements: []auth.Statement{{
			Effect:    "Deny",
			Actions:   []string{"s3:GetObject"},
			Resources: []string{"crn:eu-west-1:s3:object:tenant_tenant-1/project_project-1/public-data/secret/*"},
		}},
	}
	if _, err := a.PutPolicy(ctx, allow); err != nil {
		t.Fatalf("put allow: %v", err)
	}
	if _, err := a.PutPolicy(ctx, deny); err != nil {
		t.Fatalf("put deny: %v", err)
	}

	base := contract.RequestContext{
		Principal: key.Principal(),
		Action:    contract.ActionGetObject,
		Resource:  contract.Resource{Region: "eu-west-1", Kind: "object", TenantID: "tenant-1", ProjectID: "project-1", Bucket: "public-data", Key: "secret/creds.txt"},
	}
	dc, err := a.Authorize(ctx, base)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if dc.Allowed {
		t.Fatalf("explicit deny did not win: %+v", dc)
	}
	if dc.Reason == "" {
		t.Fatalf("deny decision has no audit reason")
	}

	base.Resource.Key = "public/readme.txt"
	dc, err = a.Authorize(ctx, base)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if !dc.Allowed {
		t.Fatalf("allowed action was denied: %+v", dc)
	}
}

func TestAuthorizeConditions(t *testing.T) {
	a, _ := newAuth(t)
	ctx := context.Background()
	key := createKey(t, a, "tenant-1", "project-1", false)
	if _, err := a.PutPolicy(ctx, auth.Policy{
		Name:      "prefix-only",
		Scope:     auth.ScopeProject,
		TenantID:  "tenant-1",
		ProjectID: "project-1",
		Statements: []auth.Statement{{
			Effect:     "Allow",
			Actions:    []string{"s3:ListBucket"},
			Resources:  []string{"crn:eu-west-1:s3:bucket:tenant_tenant-1/project_project-1/bucket-1"},
			Conditions: map[string]string{"s3:prefix": "home/*"},
		}},
	}); err != nil {
		t.Fatalf("put policy: %v", err)
	}
	rc := contract.RequestContext{
		Principal: key.Principal(),
		Action:    contract.ActionListBucket,
		Resource:  contract.Resource{Region: "eu-west-1", Kind: "bucket", TenantID: "tenant-1", ProjectID: "project-1", Bucket: "bucket-1"},
		Condition: map[string]string{"s3:prefix": "home/alice/"},
	}
	if dc, _ := a.Authorize(ctx, rc); !dc.Allowed {
		t.Fatalf("expected condition match to allow")
	}
	rc.Condition["s3:prefix"] = "other/"
	if dc, _ := a.Authorize(ctx, rc); dc.Allowed {
		t.Fatalf("expected condition mismatch to fall through to deny")
	}
	rc.Condition = nil
	if dc, _ := a.Authorize(ctx, rc); dc.Allowed {
		t.Fatalf("missing condition key must not match")
	}
}

func TestACLFallbackCrossAccount(t *testing.T) {
	a, m := newAuth(t)
	ctx := context.Background()
	bucket := createBucket(t, m, "shared-bucket", "tenant-1", "project-1")
	ownerKey := createKey(t, a, "tenant-1", "project-1", false)
	otherKey := createKey(t, a, "tenant-2", "project-2", false)

	get := contract.RequestContext{
		Principal: otherKey.Principal(),
		Action:    contract.ActionGetObject,
		Resource:  contract.Resource{Region: "eu-west-1", Kind: "object", TenantID: "tenant-2", ProjectID: "project-2", Bucket: bucket.Name, Key: "data.bin"},
	}
	// No grant: denied.
	if dc, _ := a.Authorize(ctx, get); dc.Allowed {
		t.Fatalf("cross-account access without a grant was allowed")
	}

	// Grant READ to the other project: GET allowed, PUT still denied.
	if err := m.PutBucketACL(ctx, bucket.Name, contract.ACL{
		OwnerID: "tenant_tenant-1/project_project-1",
		Grants: []contract.Grant{
			{Grantee: "tenant_tenant-1/project_project-1", GranteeType: "CanonicalUser", Permission: "FULL_CONTROL"},
			{Grantee: "tenant_tenant-2/project_project-2", GranteeType: "CanonicalUser", Permission: "READ"},
		},
	}); err != nil {
		t.Fatalf("put bucket acl: %v", err)
	}
	if dc, _ := a.Authorize(ctx, get); !dc.Allowed {
		t.Fatalf("expected bucket ACL READ grant to allow GET: %+v", dc)
	}
	put := get
	put.Action = contract.ActionPutObject
	if dc, _ := a.Authorize(ctx, put); dc.Allowed {
		t.Fatalf("READ grant must not allow PUT")
	}

	// The bucket owner is always allowed without a grant.
	ownerGet := get
	ownerGet.Principal = ownerKey.Principal()
	ownerGet.Resource.TenantID = "tenant-1"
	ownerGet.Resource.ProjectID = "project-1"
	if dc, _ := a.Authorize(ctx, ownerGet); !dc.Allowed {
		t.Fatalf("bucket owner denied: %+v", dc)
	}

	// A root key bypasses ACL checks entirely.
	rootKey := createKey(t, a, "tenant-9", "project-9", true)
	rootGet := get
	rootGet.Principal = rootKey.Principal()
	if dc, _ := a.Authorize(ctx, rootGet); !dc.Allowed {
		t.Fatalf("root key denied: %+v", dc)
	}
}

func TestBucketPolicyEvaluation(t *testing.T) {
	a, m := newAuth(t)
	ctx := context.Background()
	bucket := createBucket(t, m, "policy-bucket", "tenant-1", "project-1")
	otherKey := createKey(t, a, "tenant-2", "project-2", false)
	rc := contract.RequestContext{
		Principal: otherKey.Principal(),
		Action:    contract.ActionGetObject,
		Resource:  contract.Resource{Region: "eu-west-1", Kind: "object", TenantID: "tenant-2", ProjectID: "project-2", Bucket: bucket.Name, Key: "public/x"},
	}
	if _, err := a.PutBucketPolicy(ctx, bucket.Name, auth.Policy{
		Name:     "public-read",
		Scope:    auth.ScopeTenant,
		TenantID: "tenant-1",
		Statements: []auth.Statement{{
			Effect:    "Allow",
			Actions:   []string{"s3:GetObject"},
			Resources: []string{"crn:eu-west-1:s3:object:tenant_tenant-1/project_project-1/policy-bucket/public/*"},
		}},
	}); err != nil {
		t.Fatalf("put bucket policy: %v", err)
	}
	if dc, _ := a.Authorize(ctx, rc); !dc.Allowed {
		t.Fatalf("bucket policy allow did not apply: %+v", dc)
	}
	// A bucket policy deny also wins over a would-be ACL grant.
	if err := m.PutBucketACL(ctx, bucket.Name, contract.ACL{OwnerID: "x", Grants: []contract.Grant{
		{Grantee: "tenant_tenant-2/project_project-2", GranteeType: "CanonicalUser", Permission: "FULL_CONTROL"},
	}}); err != nil {
		t.Fatalf("put acl: %v", err)
	}
	if _, err := a.PutBucketPolicy(ctx, bucket.Name, auth.Policy{
		Name:     "deny-all",
		Scope:    auth.ScopeTenant,
		TenantID: "tenant-1",
		Statements: []auth.Statement{{
			Effect:    "Deny",
			Actions:   []string{"s3:*"},
			Resources: []string{"*"},
		}},
	}); err != nil {
		t.Fatalf("put deny policy: %v", err)
	}
	if dc, _ := a.Authorize(ctx, rc); dc.Allowed {
		t.Fatalf("bucket policy deny did not win: %+v", dc)
	}
}

func TestPolicyValidation(t *testing.T) {
	a, _ := newAuth(t)
	ctx := context.Background()
	tests := []struct {
		name string
		p    auth.Policy
	}{
		{"no name", auth.Policy{Scope: auth.ScopeTenant, TenantID: "t", Statements: []auth.Statement{{Effect: "Allow", Actions: []string{"*"}, Resources: []string{"*"}}}}},
		{"bad scope", auth.Policy{Name: "x", Scope: "galaxy", Statements: []auth.Statement{{Effect: "Allow", Actions: []string{"*"}, Resources: []string{"*"}}}}},
		{"bad effect", auth.Policy{Name: "x", Scope: auth.ScopeTenant, TenantID: "t", Statements: []auth.Statement{{Effect: "Maybe", Actions: []string{"*"}, Resources: []string{"*"}}}}},
		{"no actions", auth.Policy{Name: "x", Scope: auth.ScopeTenant, TenantID: "t", Statements: []auth.Statement{{Effect: "Allow", Resources: []string{"*"}}}}},
		{"project without id", auth.Policy{Name: "x", Scope: auth.ScopeProject, TenantID: "t", Statements: []auth.Statement{{Effect: "Allow", Actions: []string{"*"}, Resources: []string{"*"}}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := a.PutPolicy(ctx, tt.p); err == nil {
				t.Fatalf("expected validation error")
			}
		})
	}
}

func TestBucketOwnerEnforcedRejectsACLWrites(t *testing.T) {
	a, m := newAuth(t)
	ctx := context.Background()
	bucket := createBucket(t, m, "enforced-bucket", "tenant-1", "project-1")
	if err := m.UpdateBucket(ctx, contract.BucketConfig{
		BucketID: bucket.BucketID, Name: bucket.Name, TenantID: "tenant-1", ProjectID: "project-1",
		Region: bucket.Region, Ownership: "BucketOwnerEnforced",
	}); err != nil {
		t.Fatalf("update bucket: %v", err)
	}
	err := m.PutBucketACL(ctx, bucket.Name, contract.ACL{Grants: []contract.Grant{}})
	if err == nil {
		t.Fatalf("expected ACL write rejection")
	}
	_ = a
}

// TestAuthorizeMissingBucketMatrix is the regression guard for the bug the
// gateway hit: the ACL stage must not be consulted for a bucket that does not
// exist. Bucket existence is a handler concern (404); authorisation is IAM,
// bucket policy and ACLs on existing buckets only.
func TestAuthorizeMissingBucketMatrix(t *testing.T) {
	const (
		missingBucket  = "smoke-bucket"
		existingBucket = "dev-bucket"
	)
	allowCreate := auth.Policy{
		Name:      "allow-create-bucket",
		Scope:     auth.ScopeProject,
		TenantID:  "tenant-1",
		ProjectID: "project-1",
		Statements: []auth.Statement{{
			Effect:    "Allow",
			Actions:   []string{"s3:CreateBucket"},
			Resources: []string{"crn:eu-west-1:s3:bucket:tenant_tenant-1/project_project-1/*"},
		}},
	}
	denyAll := auth.Policy{
		Name:      "deny-all",
		Scope:     auth.ScopeProject,
		TenantID:  "tenant-1",
		ProjectID: "project-1",
		Statements: []auth.Statement{{
			Effect:    "Deny",
			Actions:   []string{"s3:*"},
			Resources: []string{"*"},
		}},
	}

	tests := []struct {
		name       string
		root       bool
		policies   []auth.Policy
		action     contract.Action
		bucket     string
		withBucket bool
		wantAllow  bool
	}{
		{
			name:      "root may create a bucket that does not exist",
			root:      true,
			action:    contract.ActionCreateBucket,
			bucket:    missingBucket,
			wantAllow: true,
		},
		{
			name:      "non-root with IAM grant may create a bucket that does not exist",
			policies:  []auth.Policy{allowCreate},
			action:    contract.ActionCreateBucket,
			bucket:    missingBucket,
			wantAllow: true,
		},
		{
			name:      "non-root without IAM grant may not create a bucket",
			action:    contract.ActionCreateBucket,
			bucket:    missingBucket,
			wantAllow: false,
		},
		{
			name:      "root gets the IAM decision then the handler 404s",
			root:      true,
			action:    contract.ActionGetObject,
			bucket:    missingBucket,
			wantAllow: true,
		},
		{
			name:      "explicit IAM deny wins even for root on a missing bucket",
			root:      true,
			policies:  []auth.Policy{denyAll},
			action:    contract.ActionCreateBucket,
			bucket:    missingBucket,
			wantAllow: false,
		},
		{
			name:       "explicit IAM deny wins on an existing bucket",
			root:       true,
			policies:   []auth.Policy{denyAll},
			action:     contract.ActionGetObject,
			bucket:     existingBucket,
			withBucket: true,
			wantAllow:  false,
		},
		{
			name:       "root may read an existing bucket",
			root:       true,
			action:     contract.ActionGetObject,
			bucket:     existingBucket,
			withBucket: true,
			wantAllow:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, m := newAuth(t)
			ctx := context.Background()
			if tt.withBucket {
				createBucket(t, m, existingBucket, "tenant-1", "project-1")
			}
			for _, p := range tt.policies {
				if _, err := a.PutPolicy(ctx, p); err != nil {
					t.Fatalf("put policy: %v", err)
				}
			}
			key := createKey(t, a, "tenant-1", "project-1", tt.root)
			dc, err := a.Authorize(ctx, contract.RequestContext{
				Principal: key.Principal(),
				Action:    tt.action,
				Resource: contract.Resource{
					Region:    "eu-west-1",
					Kind:      "bucket",
					TenantID:  "tenant-1",
					ProjectID: "project-1",
					Bucket:    tt.bucket,
				},
			})
			if err != nil {
				t.Fatalf("Authorize: %v", err)
			}
			if dc.Allowed != tt.wantAllow {
				t.Fatalf("allowed = %v (reason %q), want %v", dc.Allowed, dc.Reason, tt.wantAllow)
			}
		})
	}
}
