package meta

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/coord/coerr"
	"github.com/fass-storage/fass/internal/storage"
)

// ---------------------------------------------------------------------------
// Bucket ACL / lifecycle
// ---------------------------------------------------------------------------

// CanonicalOwner is the canonical-user id the coordinator uses for a bucket's
// owning project. The gateway maps it to an S3 canonical id in its XML envelope.
func CanonicalOwner(b contract.BucketConfig) string {
	return fmt.Sprintf("tenant_%s/project_%s", b.TenantID, b.ProjectID)
}

// defaultBucketACL gives the owning project FULL_CONTROL, matching S3's default
// private ACL.
func defaultBucketACL(b contract.BucketConfig) contract.ACL {
	return contract.ACL{
		OwnerID: CanonicalOwner(b),
		Grants: []contract.Grant{{
			Grantee:     CanonicalOwner(b),
			GranteeType: "CanonicalUser",
			Permission:  "FULL_CONTROL",
		}},
	}
}

// GetBucketACL returns a bucket's ACL.
func (s *Service) GetBucketACL(ctx context.Context, bucket string) (contract.ACL, error) {
	var out contract.ACL
	if err := ctx.Err(); err != nil {
		return out, err
	}
	err := s.db.View(ctx, func(tx storage.Reader) error {
		rec, err := storage.GetJSON[Bucket](tx, spaceBuckets, []byte(bucket))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.ErrNoSuchBucket
		}
		if err != nil {
			return err
		}
		out = rec.ACL
		if out.OwnerID == "" {
			out = defaultBucketACL(rec.BucketConfig)
		}
		return nil
	})
	return out, err
}

// PutBucketACL replaces a bucket's ACL. Buckets with BucketOwnerEnforced
// ownership reject ACL writes (Cubbit/AWS behaviour, docs/04 §5.1).
func (s *Service) PutBucketACL(ctx context.Context, bucket string, acl contract.ACL) error {
	if err := validateACL(acl); err != nil {
		return err
	}
	return s.db.Update(ctx, func(tx storage.Writer) error {
		rec, err := storage.GetJSON[Bucket](tx, spaceBuckets, []byte(bucket))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.ErrNoSuchBucket
		}
		if err != nil {
			return err
		}
		if rec.Ownership == "BucketOwnerEnforced" {
			return coerr.E(400, "AccessControlListNotSupported", "The bucket does not allow ACLs")
		}
		if acl.OwnerID == "" {
			acl.OwnerID = CanonicalOwner(rec.BucketConfig)
		}
		rec.ACL = acl
		return storage.PutJSON(tx, spaceBuckets, []byte(bucket), rec)
	})
}

// GetBucketLifecycle returns the stored lifecycle document (opaque XML).
func (s *Service) GetBucketLifecycle(ctx context.Context, bucket string) ([]byte, error) {
	var out []byte
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	err := s.db.View(ctx, func(tx storage.Reader) error {
		rec, err := storage.GetJSON[Bucket](tx, spaceBuckets, []byte(bucket))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.ErrNoSuchBucket
		}
		if err != nil {
			return err
		}
		if len(rec.Lifecycle) == 0 {
			return coerr.E(404, "NoSuchLifecycleConfiguration", "The lifecycle configuration does not exist")
		}
		out = append([]byte(nil), rec.Lifecycle...)
		return nil
	})
	return out, err
}

// PutBucketLifecycle stores a lifecycle document. The gateway owns its XML
// validation; the coordinator bounds its size.
func (s *Service) PutBucketLifecycle(ctx context.Context, bucket string, xml []byte) error {
	if len(xml) == 0 {
		return coerr.Invalidf("lifecycle document is empty")
	}
	if len(xml) > 1<<20 {
		return coerr.Invalidf("lifecycle document exceeds 1 MiB")
	}
	return s.db.Update(ctx, func(tx storage.Writer) error {
		rec, err := storage.GetJSON[Bucket](tx, spaceBuckets, []byte(bucket))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.ErrNoSuchBucket
		}
		if err != nil {
			return err
		}
		rec.Lifecycle = append([]byte(nil), xml...)
		return storage.PutJSON(tx, spaceBuckets, []byte(bucket), rec)
	})
}

// DeleteBucketLifecycle removes a lifecycle document (idempotent).
func (s *Service) DeleteBucketLifecycle(ctx context.Context, bucket string) error {
	return s.db.Update(ctx, func(tx storage.Writer) error {
		rec, err := storage.GetJSON[Bucket](tx, spaceBuckets, []byte(bucket))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.ErrNoSuchBucket
		}
		if err != nil {
			return err
		}
		rec.Lifecycle = nil
		return storage.PutJSON(tx, spaceBuckets, []byte(bucket), rec)
	})
}

// ---------------------------------------------------------------------------
// Object tags / retention / ACL
// ---------------------------------------------------------------------------

// GetObjectTags returns the tag set of a version (empty map when untagged).
func (s *Service) GetObjectTags(ctx context.Context, bucket, key string, v contract.VersionID) (map[string]string, error) {
	out := map[string]string{}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	err := s.db.View(ctx, func(tx storage.Reader) error {
		cfg, err := s.bucketConfigTx(tx, bucket)
		if err != nil {
			return err
		}
		rec, err := resolveVersion(tx, cfg.BucketID, key, v)
		if err != nil {
			return err
		}
		if rec.IsDeleteMarker {
			return coerr.ErrMethodNotAllowed
		}
		out = copyMap(rec.Tags)
		return nil
	})
	return out, err
}

// PutObjectTags replaces the tag set of one version.
func (s *Service) PutObjectTags(ctx context.Context, bucket, key string, v contract.VersionID, tags map[string]string) error {
	if len(tags) > 10 {
		return coerr.Invalidf("an object may have at most 10 tags")
	}
	for k, val := range tags {
		if k == "" || len(k) > 128 || len(val) > 256 {
			return coerr.Invalidf("invalid tag %q", k)
		}
	}
	return s.db.Update(ctx, func(tx storage.Writer) error {
		cfg, err := s.bucketConfigTx(tx, bucket)
		if err != nil {
			return err
		}
		rec, err := resolveVersion(tx, cfg.BucketID, key, v)
		if err != nil {
			return err
		}
		rec.Tags = copyMap(tags)
		return s.putVersionRecord(tx, rec)
	})
}

// GetObjectRetention returns the version's object-lock state (nil when none).
func (s *Service) GetObjectRetention(ctx context.Context, bucket, key string, v contract.VersionID) (*contract.Retention, error) {
	var out *contract.Retention
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	err := s.db.View(ctx, func(tx storage.Reader) error {
		cfg, err := s.bucketConfigTx(tx, bucket)
		if err != nil {
			return err
		}
		rec, err := resolveVersion(tx, cfg.BucketID, key, v)
		if err != nil {
			return err
		}
		if rec.Retention != nil {
			r := *rec.Retention
			out = &r
		}
		return nil
	})
	return out, err
}

// PutObjectRetention applies object lock to one version. COMPLIANCE retention can
// only be extended, never shortened or bypassed (docs/05 object-lock semantics).
func (s *Service) PutObjectRetention(ctx context.Context, bucket, key string, v contract.VersionID, r *contract.Retention) error {
	if r == nil {
		return coerr.Invalidf("retention is required")
	}
	if r.Mode != "" && r.Mode != "GOVERNANCE" && r.Mode != "COMPLIANCE" {
		return coerr.Invalidf("retention mode must be GOVERNANCE or COMPLIANCE")
	}
	return s.db.Update(ctx, func(tx storage.Writer) error {
		cfg, err := s.bucketConfigTx(tx, bucket)
		if err != nil {
			return err
		}
		if !cfg.ObjectLock {
			return coerr.E(400, "InvalidRequest", "Object Lock is not enabled for this bucket")
		}
		rec, err := resolveVersion(tx, cfg.BucketID, key, v)
		if err != nil {
			return err
		}
		if rec.Retention != nil && rec.Retention.Mode == "COMPLIANCE" {
			if r.Mode != "COMPLIANCE" || r.RetainUntil.Before(rec.Retention.RetainUntil) {
				return coerr.ErrObjectLocked
			}
		}
		nr := *r
		rec.Retention = &nr
		return s.putVersionRecord(tx, rec)
	})
}

// PutObjectLegalHold toggles the legal hold independently of the retention mode
// (S3 treats them as separate operations).
func (s *Service) PutObjectLegalHold(ctx context.Context, bucket, key string, v contract.VersionID, hold bool) error {
	return s.db.Update(ctx, func(tx storage.Writer) error {
		cfg, err := s.bucketConfigTx(tx, bucket)
		if err != nil {
			return err
		}
		if !cfg.ObjectLock {
			return coerr.E(400, "InvalidRequest", "Object Lock is not enabled for this bucket")
		}
		rec, err := resolveVersion(tx, cfg.BucketID, key, v)
		if err != nil {
			return err
		}
		if rec.Retention == nil {
			rec.Retention = &contract.Retention{}
		}
		rec.Retention.LegalHold = hold
		return s.putVersionRecord(tx, rec)
	})
}

// GetObjectACL returns the ACL of a version, falling back to the bucket default.
func (s *Service) GetObjectACL(ctx context.Context, bucket, key string, v contract.VersionID) (contract.ACL, error) {
	var out contract.ACL
	if err := ctx.Err(); err != nil {
		return out, err
	}
	err := s.db.View(ctx, func(tx storage.Reader) error {
		cfg, err := s.bucketConfigTx(tx, bucket)
		if err != nil {
			return err
		}
		rec, err := resolveVersion(tx, cfg.BucketID, key, v)
		if err != nil {
			return err
		}
		if rec.ACL != nil {
			out = *rec.ACL
			return nil
		}
		out = defaultBucketACL(cfg)
		return nil
	})
	return out, err
}

// PutObjectACL replaces the ACL of one version.
func (s *Service) PutObjectACL(ctx context.Context, bucket, key string, v contract.VersionID, acl contract.ACL) error {
	if err := validateACL(acl); err != nil {
		return err
	}
	return s.db.Update(ctx, func(tx storage.Writer) error {
		cfg, err := s.bucketConfigTx(tx, bucket)
		if err != nil {
			return err
		}
		if cfg.Ownership == "BucketOwnerEnforced" {
			return coerr.E(400, "AccessControlListNotSupported", "The bucket does not allow ACLs")
		}
		rec, err := resolveVersion(tx, cfg.BucketID, key, v)
		if err != nil {
			return err
		}
		if acl.OwnerID == "" {
			acl.OwnerID = CanonicalOwner(cfg)
		}
		cp := acl
		rec.ACL = &cp
		return s.putVersionRecord(tx, rec)
	})
}

func (s *Service) bucketConfigTx(tx storage.Reader, bucket string) (contract.BucketConfig, error) {
	rec, err := storage.GetJSON[Bucket](tx, spaceBuckets, []byte(bucket))
	if errors.Is(err, storage.ErrNotFound) {
		return contract.BucketConfig{}, coerr.ErrNoSuchBucket
	}
	if err != nil {
		return contract.BucketConfig{}, err
	}
	return rec.BucketConfig, nil
}

func (s *Service) putVersionRecord(tx storage.Writer, rec versionRecord) error {
	if err := storage.PutJSON(tx, spaceVersions, versionKey(rec.BucketID, rec.Key, rec.Seq), rec); err != nil {
		return err
	}
	return storage.PutJSON(tx, spaceVersionIDs, versionIDKey(rec.BucketID, rec.Key, rec.VersionID), rec)
}

func validateACL(acl contract.ACL) error {
	if len(acl.Grants) > 100 {
		return coerr.Invalidf("an ACL may contain at most 100 grants")
	}
	for _, g := range acl.Grants {
		switch g.Permission {
		case "READ", "WRITE", "READ_ACP", "WRITE_ACP", "FULL_CONTROL":
		default:
			return coerr.Invalidf("invalid ACL permission %q", g.Permission)
		}
		switch g.GranteeType {
		case "CanonicalUser", "Group", "AmazonCustomerByEmail":
		default:
			return coerr.Invalidf("invalid ACL grantee type %q", g.GranteeType)
		}
		if g.Grantee == "" {
			return coerr.Invalidf("ACL grant is missing a grantee")
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Deletion queue (docs/03 §6)
// ---------------------------------------------------------------------------

// DeletionItem is one pending shard-GC entry. Deletion is metadata-first: the
// tombstone is committed immediately, the shards are collected after DueAt.
type DeletionItem struct {
	ID           uint64             `json:"deletion_id"`
	BucketID     contract.BucketID  `json:"bucket_id"`
	Key          string             `json:"key"`
	VersionID    contract.VersionID `json:"version_id"`
	ManifestHash string             `json:"manifest_hash,omitempty"`
	Reason       string             `json:"reason"`
	CreatedAt    time.Time          `json:"created_at"`
	DueAt        time.Time          `json:"due_at"`
	// GC progress. StartedAt is set once a collector picks the entry up;
	// AckedEndpoints records which agent endpoints have confirmed deletion. Both
	// make a retry after a crash cheap: acknowledged endpoints are skipped
	// instead of being deleted again.
	StartedAt      *time.Time `json:"started_at,omitempty"`
	AckedEndpoints []string   `json:"acked_endpoints,omitempty"`
}

// Acks reports whether an endpoint has already acknowledged deletion.
func (d DeletionItem) Acks(endpoint string) bool {
	for _, ep := range d.AckedEndpoints {
		if ep == endpoint {
			return true
		}
	}
	return false
}

func (s *Service) enqueueDeletion(tx storage.Writer, item DeletionItem) error {
	seq, err := nextSeq(tx, "deletion")
	if err != nil {
		return err
	}
	item.ID = seq
	if item.DueAt.IsZero() {
		item.DueAt = item.CreatedAt
	}
	return storage.PutJSON(tx, spaceDeletions, seqKey(nil, seq), item)
}

// DrainDeletions returns up to limit due deletion entries. The caller deletes the
// referenced shards and then calls CompleteDeletion. It is safe to call
// concurrently: entries are not removed until completion, so a crash re-runs the
// (idempotent) shard delete.
func (s *Service) DrainDeletions(ctx context.Context, now time.Time, limit int) ([]DeletionItem, error) {
	if limit <= 0 {
		limit = 100
	}
	out := make([]DeletionItem, 0, limit)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	err := s.db.View(ctx, func(tx storage.Reader) error {
		return storage.ScanJSON[DeletionItem](tx, spaceDeletions, nil, func(_ []byte, item DeletionItem) error {
			if now.Before(item.DueAt) {
				return nil
			}
			out = append(out, item)
			if len(out) >= limit {
				return storage.StopScan()
			}
			return nil
		})
	})
	return out, err
}

// BeginDeletion marks a queue entry as in progress and returns its current
// progress (including acknowledgements from an earlier pass). The marker is
// written in the same transaction as the read, so two collectors cannot start
// the same entry from a stale view.
func (s *Service) BeginDeletion(ctx context.Context, deletionID uint64, now time.Time) (DeletionItem, error) {
	var out DeletionItem
	if err := ctx.Err(); err != nil {
		return out, err
	}
	err := s.db.Update(ctx, func(tx storage.Writer) error {
		rec, err := storage.GetJSON[DeletionItem](tx, spaceDeletions, seqKey(nil, deletionID))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.E(404, "NoSuchDeletion", "deletion entry %d does not exist", deletionID)
		}
		if err != nil {
			return err
		}
		if rec.StartedAt == nil {
			t := now.UTC()
			rec.StartedAt = &t
			if err := storage.PutJSON(tx, spaceDeletions, seqKey(nil, deletionID), rec); err != nil {
				return err
			}
		}
		out = rec
		return nil
	})
	return out, err
}

// AckDeletionEndpoint records one endpoint's successful deletion for an entry.
// It is idempotent and survives a crash before the final queue removal.
func (s *Service) AckDeletionEndpoint(ctx context.Context, deletionID uint64, endpoint string) error {
	if endpoint == "" {
		return coerr.Invalidf("endpoint is required")
	}
	return s.db.Update(ctx, func(tx storage.Writer) error {
		rec, err := storage.GetJSON[DeletionItem](tx, spaceDeletions, seqKey(nil, deletionID))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.E(404, "NoSuchDeletion", "deletion entry %d does not exist", deletionID)
		}
		if err != nil {
			return err
		}
		for _, ep := range rec.AckedEndpoints {
			if ep == endpoint {
				return nil
			}
		}
		rec.AckedEndpoints = append(rec.AckedEndpoints, endpoint)
		if rec.StartedAt == nil {
			t := s.now().UTC()
			rec.StartedAt = &t
		}
		return storage.PutJSON(tx, spaceDeletions, seqKey(nil, deletionID), rec)
	})
}

// CompleteDeletion removes a drained entry.
func (s *Service) CompleteDeletion(ctx context.Context, deletionID uint64) error {
	return s.db.Update(ctx, func(tx storage.Writer) error {
		return tx.Delete(spaceDeletions, seqKey(nil, deletionID))
	})
}

// DeletionBacklog counts queued deletions.
func (s *Service) DeletionBacklog(ctx context.Context) (int, error) {
	var n int
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	err := s.db.View(ctx, func(tx storage.Reader) error {
		var err error
		n, err = tx.Count(spaceDeletions, nil)
		return err
	})
	return n, err
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

func copyMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
