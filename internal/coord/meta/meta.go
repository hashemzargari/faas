// Package meta is the coordinator's metadata service: buckets, object versions,
// manifests, multipart uploads, retention and the deletion queue.
//
// It is the system of record. The invariants it owns are the ones the data path
// depends on:
//
//   - metadata is the only source of truth; unreferenced shards are always safe
//     to delete (docs/02 §5.1);
//   - shards are written before the commit, and the commit is a single atomic
//     transaction (docs/02 §4.1);
//   - version flips and delete markers are atomic with the object row update;
//   - payload rows are never deleted synchronously: a deletion is queued so an
//     in-flight reader can finish (docs/03 §6).
//
// Chunk tables are stored as content-addressed, compressed blobs (docs/04
// §5.2): a manifest row stays small and hot while the chunk table — which is
// what grows with object size — lives in a separate manifest_blobs record.
package meta

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/coord/coerr"
	"github.com/fass-storage/fass/internal/coord/id"
	"github.com/fass-storage/fass/internal/storage"
)

// Storage defaults and limits (docs/02 §1.2, docs/03 §1.2).
const (
	DefaultChunkSize = 16 << 20       // 16 MiB
	MaxObjectSize    = 5 << 40        // 5 TiB
	MaxKeyLength     = 1024           // S3 limit for an object key, in bytes
	DeletionGrace    = 24 * time.Hour // overwrite / version-delete grace (docs/03 §6)
	UploadExpiry     = 7 * 24 * time.Hour
)

// Key spaces of the embedded engine. The PostgreSQL DDL in docs/schema.sql
// defines the equivalent tables; every key layout is documented there too.
var (
	spaceBuckets     = []byte("buckets")            // name                     -> bucketRecord
	spaceBucketIDs   = []byte("bucket_ids")         // bucket_id                -> name
	spaceLatest      = []byte("objects_latest")     // bucket_id,key            -> latestRecord
	spaceVersions    = []byte("objects_versions")   // bucket_id,key,seq      -> versionRecord
	spaceVersionIDs  = []byte("object_version_ids") // bucket_id,key,version_id -> versionRecord
	spaceManifests   = []byte("manifest_blobs")     // manifest_hash            -> compressed manifest
	spaceUploads     = []byte("uploads")            // upload_id                -> uploadRecord
	spaceUploadIndex = []byte("uploads_index")      // bucket_id,upload_id      -> uploadRecord
	spaceParts       = []byte("upload_parts")       // upload_id,part_number    -> partRecord
	spaceDeletions   = []byte("deletions")          // seq                      -> deletionItem
	spaceCounters    = []byte("counters")           // name                     -> uint64 BE
	spaceTenants     = []byte("tenants")            // tenant_id                -> Tenant
)

// Service implements the metadata service over a storage.DB.
type Service struct {
	db  *storage.DB
	now func() time.Time
}

// New creates a metadata service. The caller owns the DB lifetime.
func New(db *storage.DB) *Service {
	return &Service{db: db, now: time.Now}
}

// SetClock overrides the clock (tests only).
func (s *Service) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// DB exposes the underlying store for the sibling coordinator services. It is
// deliberately not part of the public data path.
func (s *Service) DB() *storage.DB { return s.db }

// ---------------------------------------------------------------------------
// Buckets
// ---------------------------------------------------------------------------

// Bucket is the stored form of a bucket: the wire BucketConfig plus ownership
// metadata that never leaves the coordinator.
type Bucket struct {
	contract.BucketConfig
	CreatedAt time.Time    `json:"created_at"`
	ACL       contract.ACL `json:"acl"`
	Lifecycle []byte       `json:"lifecycle,omitempty"`
}

// CreateBucket creates a bucket. Creating an existing bucket owned by the same
// tenant/project is idempotent (S3 semantics); a name owned by someone else is a
// conflict.
func (s *Service) CreateBucket(ctx context.Context, cfg contract.BucketConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ValidateBucketName(cfg.Name); err != nil {
		return err
	}
	if cfg.BucketID == "" {
		cfg.BucketID = contract.BucketID(newID())
	}
	if cfg.Region == "" {
		cfg.Region = contract.DefaultRegion
	}
	if cfg.Ownership == "" {
		cfg.Ownership = "ObjectWriter"
	}
	switch cfg.Versioning {
	case "", "Enabled", "Suspended":
	default:
		return coerr.Invalidf("invalid versioning state %q", cfg.Versioning)
	}
	if cfg.QuotaBytes < 0 {
		return coerr.Invalidf("quota_bytes must be >= 0")
	}

	return s.db.Update(ctx, func(tx *storage.WriteTx) error {
		key := []byte(cfg.Name)
		rec, getErr := storage.GetJSON[Bucket](tx, spaceBuckets, key)
		switch {
		case getErr == nil:
			if rec.TenantID != cfg.TenantID || rec.ProjectID != cfg.ProjectID {
				return coerr.E(409, "BucketAlreadyExists", "The requested bucket name is not available")
			}
			// Idempotent create: keep the existing bucket ID and creation time.
			return nil
		case !errors.Is(getErr, storage.ErrNotFound):
			return getErr
		}
		rec = Bucket{BucketConfig: cfg, CreatedAt: s.now().UTC()}
		if err := storage.PutJSON(tx, spaceBuckets, key, rec); err != nil {
			return err
		}
		return tx.Put(spaceBucketIDs, []byte(cfg.BucketID), []byte(cfg.Name))
	})
}

// GetBucket returns a bucket by name.
func (s *Service) GetBucket(ctx context.Context, name string) (contract.BucketConfig, error) {
	var out contract.BucketConfig
	if err := ctx.Err(); err != nil {
		return out, err
	}
	err := s.db.View(ctx, func(tx *storage.ReadTx) error {
		rec, err := storage.GetJSON[Bucket](tx, spaceBuckets, []byte(name))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.ErrNoSuchBucket
		}
		if err != nil {
			return err
		}
		out = rec.BucketConfig
		return nil
	})
	return out, err
}

// GetBucketByID returns a bucket by its opaque ID (the data path uses IDs).
func (s *Service) GetBucketByID(ctx context.Context, id contract.BucketID) (contract.BucketConfig, error) {
	var out contract.BucketConfig
	if err := ctx.Err(); err != nil {
		return out, err
	}
	err := s.db.View(ctx, func(tx *storage.ReadTx) error {
		name, err := tx.Get(spaceBucketIDs, []byte(id))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.ErrNoSuchBucket
		}
		if err != nil {
			return err
		}
		rec, err := storage.GetJSON[Bucket](tx, spaceBuckets, name)
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.ErrNoSuchBucket
		}
		if err != nil {
			return err
		}
		out = rec.BucketConfig
		return nil
	})
	return out, err
}

// ListBuckets returns the buckets visible to a principal.
func (s *Service) ListBuckets(ctx context.Context, p contract.Principal) ([]contract.BucketConfig, error) {
	var out []contract.BucketConfig
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	err := s.db.View(ctx, func(tx *storage.ReadTx) error {
		return storage.ScanJSON[Bucket](tx, spaceBuckets, nil, func(_ []byte, rec Bucket) error {
			if !p.IsRoot && (rec.TenantID != p.TenantID || rec.ProjectID != p.ProjectID) {
				return nil
			}
			out = append(out, rec.BucketConfig)
			return nil
		})
	})
	return out, err
}

// UpdateBucket applies a mutable bucket configuration change (versioning,
// ownership, object lock, quota, default RC).
func (s *Service) UpdateBucket(ctx context.Context, cfg contract.BucketConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if cfg.Name == "" {
		return coerr.Invalidf("bucket name is required")
	}
	switch cfg.Versioning {
	case "", "Enabled", "Suspended":
	default:
		return coerr.Invalidf("invalid versioning state %q", cfg.Versioning)
	}
	return s.db.Update(ctx, func(tx *storage.WriteTx) error {
		rec, err := storage.GetJSON[Bucket](tx, spaceBuckets, []byte(cfg.Name))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.ErrNoSuchBucket
		}
		if err != nil {
			return err
		}
		if cfg.BucketID == "" {
			cfg.BucketID = rec.BucketID
		}
		if cfg.BucketID != rec.BucketID {
			return coerr.Invalidf("bucket_id is immutable")
		}
		if cfg.Region == "" {
			cfg.Region = rec.Region
		}
		if cfg.Ownership == "" {
			cfg.Ownership = rec.Ownership
		}
		rec.BucketConfig = cfg
		return storage.PutJSON(tx, spaceBuckets, []byte(cfg.Name), rec)
	})
}

// DeleteBucket deletes an empty bucket. A bucket that still holds objects or
// versions is refused (docs/03 §6: "bucket delete requires no objects AND no
// versions").
func (s *Service) DeleteBucket(ctx context.Context, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.db.Update(ctx, func(tx *storage.WriteTx) error {
		rec, err := storage.GetJSON[Bucket](tx, spaceBuckets, []byte(name))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.ErrNoSuchBucket
		}
		if err != nil {
			return err
		}
		nonEmpty, err := bucketHasObjects(tx, rec.BucketID)
		if err != nil {
			return err
		}
		if nonEmpty {
			return coerr.ErrBucketNotEmpty
		}
		if err := tx.Delete(spaceBuckets, []byte(name)); err != nil {
			return err
		}
		return tx.Delete(spaceBucketIDs, []byte(rec.BucketID))
	})
}

func bucketHasObjects(tx storage.Reader, bucketID contract.BucketID) (bool, error) {
	found := false
	prefix := storage.JoinKey(string(bucketID))
	err := tx.Scan(spaceVersions, prefix, func(_, raw []byte) error {
		var rec versionRecord
		if err := decode(raw, &rec); err != nil {
			return err
		}
		if !rec.Deleted {
			found = true
			return storage.StopScan()
		}
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("meta: scan versions: %w", err)
	}
	if found {
		return true, nil
	}
	// Delete markers live in the version space too, so this also catches a
	// bucket whose only content is a marker.
	err = tx.Scan(spaceLatest, prefix, func(_, raw []byte) error {
		found = true
		return storage.StopScan()
	})
	return found, err
}

// ---------------------------------------------------------------------------
// Tenants (minimal registry: geo-fence + key seed reference)
// ---------------------------------------------------------------------------

// Tenant is the coordinator's tenant record. The key seed is opaque bytes: the
// coordinator never derives object keys from it (docs/03 §3.5).
type Tenant struct {
	ID          contract.TenantID  `json:"tenant_id"`
	Name        string             `json:"name"`
	GeoFence    []contract.NexusID `json:"geo_fence"` // empty = no restriction
	DefaultRCID string             `json:"default_rc_id"`
	KeySeed     []byte             `json:"key_seed,omitempty"`
	CreatedAt   time.Time          `json:"created_at"`
}

// PutTenant creates or replaces a tenant record.
func (s *Service) PutTenant(ctx context.Context, t Tenant) error {
	if t.ID == "" {
		return coerr.Invalidf("tenant_id is required")
	}
	if t.Name == "" {
		return coerr.Invalidf("tenant name is required")
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = s.now().UTC()
	}
	return s.db.Update(ctx, func(tx *storage.WriteTx) error {
		return storage.PutJSON(tx, spaceTenants, []byte(t.ID), t)
	})
}

// GetTenant returns a tenant record.
func (s *Service) GetTenant(ctx context.Context, id contract.TenantID) (Tenant, error) {
	var out Tenant
	if err := ctx.Err(); err != nil {
		return out, err
	}
	err := s.db.View(ctx, func(tx *storage.ReadTx) error {
		rec, err := storage.GetJSON[Tenant](tx, spaceTenants, []byte(id))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.E(404, "NoSuchTenant", "The specified tenant does not exist")
		}
		if err != nil {
			return err
		}
		out = rec
		return nil
	})
	return out, err
}

// ListTenants returns all tenant records.
func (s *Service) ListTenants(ctx context.Context) ([]Tenant, error) {
	var out []Tenant
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	err := s.db.View(ctx, func(tx *storage.ReadTx) error {
		return storage.ScanJSON[Tenant](tx, spaceTenants, nil, func(_ []byte, t Tenant) error {
			out = append(out, t)
			return nil
		})
	})
	return out, err
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

// ValidateBucketName applies the S3 bucket-naming rules the gateway also
// enforces, so a direct coordinator caller cannot create an unreachable bucket.
func ValidateBucketName(name string) error {
	switch {
	case len(name) < 3 || len(name) > 63:
		return coerr.Invalidf("bucket name must be between 3 and 63 characters")
	case strings.HasPrefix(name, ".") || strings.HasPrefix(name, "-") ||
		strings.HasSuffix(name, ".") || strings.HasSuffix(name, "-"):
		return coerr.Invalidf("bucket name must begin and end with a letter or digit")
	case strings.Contains(name, ".."):
		return coerr.Invalidf("bucket name must not contain two adjacent periods")
	}
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.':
		default:
			return coerr.Invalidf("bucket name contains invalid character %q", c)
		}
	}
	return nil
}

// ValidateKey applies the object-key rules (non-empty, valid UTF-8, bounded).
func ValidateKey(key string) error {
	switch {
	case key == "":
		return coerr.Invalidf("object key must not be empty")
	case len(key) > MaxKeyLength:
		return coerr.Invalidf("object key exceeds %d bytes", MaxKeyLength)
	case !utf8.ValidString(key):
		return coerr.Invalidf("object key must be valid UTF-8")
	case strings.IndexByte(key, 0) >= 0:
		return coerr.Invalidf("object key must not contain NUL")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

// newID is indirected so tests can make identifiers predictable if ever needed.
var newID = func() string { return id.New() }

// nextSeq allocates the next value of a named monotonic counter inside tx.
func nextSeq(tx *storage.WriteTx, name string) (uint64, error) {
	raw, err := tx.Get(spaceCounters, []byte(name))
	switch {
	case errors.Is(err, storage.ErrNotFound):
		// start at 1
	case err != nil:
		return 0, err
	}
	var cur uint64
	if len(raw) == 8 {
		cur = binary.BigEndian.Uint64(raw)
	}
	next := cur + 1
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], next)
	if err := tx.Put(spaceCounters, []byte(name), buf[:]); err != nil {
		return 0, err
	}
	return next, nil
}

// seqKey appends an 8-byte big-endian sequence number to a composite key so the
// store's byte ordering matches numeric ordering.
func seqKey(parts []string, seq uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], seq)
	return storage.JoinKeyN(parts, buf[:])
}

// decode is json.Unmarshal with a wrapped error.
func decode(raw []byte, v any) error {
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("meta: decode record: %w", err)
	}
	return nil
}
