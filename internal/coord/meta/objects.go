package meta

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/coord/coerr"
	"github.com/fass-storage/fass/internal/coord/id"
	"github.com/fass-storage/fass/internal/storage"
)

// latestRecord is the small hot pointer from (bucket, key) to the current
// version. It exists so GetObject and ListObjects never touch the version table
// unless they need a non-current version.
type latestRecord struct {
	Key          string             `json:"key"`
	VersionID    contract.VersionID `json:"version_id"`
	Seq          uint64             `json:"seq"`
	DeleteMarker bool               `json:"delete_marker"`
	Size         int64              `json:"size"`
	ETag         string             `json:"etag"`
	LastModified time.Time          `json:"last_modified"`
	StorageClass string             `json:"storage_class,omitempty"`
}

// versionRecord is one immutable object version (plus its tombstone state).
type versionRecord struct {
	BucketID       contract.BucketID   `json:"bucket_id"`
	Key            string              `json:"key"`
	VersionID      contract.VersionID  `json:"version_id"`
	Seq            uint64              `json:"seq"`
	IsDeleteMarker bool                `json:"is_delete_marker,omitempty"`
	Deleted        bool                `json:"deleted,omitempty"`
	DeletedAt      *time.Time          `json:"deleted_at,omitempty"`
	Size           int64               `json:"size"`
	ETag           string              `json:"etag"`
	ManifestHash   string              `json:"manifest_hash,omitempty"`
	ChunkSize      int                 `json:"chunk_size,omitempty"`
	ContentType    string              `json:"content_type,omitempty"`
	UserMeta       map[string]string   `json:"user_meta,omitempty"`
	Tags           map[string]string   `json:"tags,omitempty"`
	ACL            *contract.ACL       `json:"acl,omitempty"`
	RCID           string              `json:"rc_id,omitempty"`
	RingID         contract.RingID     `json:"ring_id,omitempty"`
	StorageClass   string              `json:"storage_class,omitempty"`
	CreatedAt      time.Time           `json:"created_at"`
	Retention      *contract.Retention `json:"retention,omitempty"`
}

// key layout helpers. Every composite key is NUL-separated and ends with a
// separator, so prefix scans cannot collide across buckets or keys.
func bucketPrefix(bucketID contract.BucketID) []byte { return []byte(string(bucketID) + "\x00") }

func latestKey(bucketID contract.BucketID, key string) []byte {
	return storage.JoinKeyN([]string{string(bucketID), key}, nil)
}

func versionPrefix(bucketID contract.BucketID, key string) []byte {
	return []byte(string(bucketID) + "\x00" + key + "\x00")
}

func versionKey(bucketID contract.BucketID, key string, seq uint64) []byte {
	return seqKey([]string{string(bucketID), key}, seq)
}

func versionIDKey(bucketID contract.BucketID, key string, v contract.VersionID) []byte {
	return storage.JoinKeyN([]string{string(bucketID), key, string(v)}, nil)
}

func bucketInTx(tx storage.Reader, bucketID contract.BucketID) (Bucket, error) {
	name, err := tx.Get(spaceBucketIDs, []byte(bucketID))
	if errors.Is(err, storage.ErrNotFound) {
		return Bucket{}, coerr.ErrNoSuchBucket
	}
	if err != nil {
		return Bucket{}, err
	}
	rec, err := storage.GetJSON[Bucket](tx, spaceBuckets, name)
	if errors.Is(err, storage.ErrNotFound) {
		return Bucket{}, coerr.ErrNoSuchBucket
	}
	if err != nil {
		return Bucket{}, err
	}
	return rec, nil
}

// getLatest returns the latest-version pointer, or nil when the key has no
// versions.
func getLatest(tx storage.Reader, bucketID contract.BucketID, key string) (*latestRecord, error) {
	rec, err := storage.GetJSON[latestRecord](tx, spaceLatest, latestKey(bucketID, key))
	if errors.Is(err, storage.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

// resolveVersion returns a version record for (bucket, key, version). An empty
// version id resolves the latest version. Deleted and missing versions are
// NoSuchKey.
func resolveVersion(tx storage.Reader, bucketID contract.BucketID, key string, version contract.VersionID) (versionRecord, error) {
	var v contract.VersionID
	if version == "" {
		latest, err := getLatest(tx, bucketID, key)
		if err != nil {
			return versionRecord{}, err
		}
		if latest == nil {
			return versionRecord{}, coerr.ErrNoSuchKey
		}
		v = latest.VersionID
	} else {
		v = version
	}
	rec, err := storage.GetJSON[versionRecord](tx, spaceVersionIDs, versionIDKey(bucketID, key, v))
	if errors.Is(err, storage.ErrNotFound) {
		return versionRecord{}, coerr.ErrNoSuchKey
	}
	if err != nil {
		return versionRecord{}, err
	}
	if rec.Deleted {
		return versionRecord{}, coerr.ErrNoSuchKey
	}
	return rec, nil
}

// CommitObject persists one object version atomically. It is the single
// transactional commit the write path depends on (docs/02 §4.1, §5).
//
// req.VersionID is assigned by the gateway before encryption; a retried commit
// with the same id and identical content is idempotent, while a different body
// with an already-used id is a conflict.
func (s *Service) CommitObject(ctx context.Context, req contract.CommitRequest) (contract.CommitResult, error) {
	var result contract.CommitResult
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if err := ValidateKey(req.Key); err != nil {
		return result, err
	}
	if req.BucketID == "" {
		return result, coerr.Invalidf("bucket_id is required")
	}
	if req.VersionID == "" {
		return result, coerr.Invalidf("version_id is required (the gateway assigns it before encryption)")
	}
	if err := id.Validate(string(req.VersionID)); err != nil {
		return result, coerr.Invalidf("version_id must be a UUIDv4: %v", err)
	}
	if req.Size < 0 || req.Size > MaxObjectSize {
		return result, coerr.ErrEntityTooLarge
	}
	if err := validateChunkTable(req.Chunks); err != nil {
		return result, err
	}
	chunkSize := req.ChunkSize
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	if req.StorageClass == "" {
		req.StorageClass = "STANDARD"
	}

	err := s.db.Update(ctx, func(tx *storage.WriteTx) error {
		bucket, err := bucketInTx(tx, req.BucketID)
		if err != nil {
			return err
		}
		now := s.now()

		// Idempotent retry: the version id is already committed.
		if existing, err := storage.GetJSON[versionRecord](tx, spaceVersionIDs, versionIDKey(req.BucketID, req.Key, req.VersionID)); err == nil {
			if existing.Key == req.Key && existing.Size == req.Size && existing.ETag == req.ETag && !existing.Deleted && !existing.IsDeleteMarker {
				result = contract.CommitResult{VersionID: existing.VersionID, ETag: existing.ETag}
				return nil
			}
			return coerr.E(409, coerr.CodeConflict, "version_id %s already exists for a different object version", req.VersionID)
		} else if !errors.Is(err, storage.ErrNotFound) {
			return err
		}

		latest, err := getLatest(tx, req.BucketID, req.Key)
		if err != nil {
			return err
		}
		if err := checkConditions(latest, req.IfMatch, req.IfNoneMatch); err != nil {
			return err
		}

		seq, err := nextSeq(tx, "version")
		if err != nil {
			return err
		}

		etag := req.ETag
		if etag == "" {
			sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s", req.BucketID, req.Key, req.VersionID)))
			etag = hex.EncodeToString(sum[:16])
		}

		// Build and store the content-addressed manifest blob.
		manifestHash := ""
		if len(req.Chunks) > 0 {
			m := contract.Manifest{
				TenantID:    bucket.TenantID,
				ProjectID:   bucket.ProjectID,
				BucketID:    req.BucketID,
				Key:         req.Key,
				VersionID:   req.VersionID,
				Size:        req.Size,
				ETag:        etag,
				ChunkSize:   chunkSize,
				Chunks:      req.Chunks,
				Encryption:  req.Encryption,
				ContentType: req.ContentType,
				UserMeta:    req.UserMeta,
				Tags:        req.Tags,
				CreatedAt:   now,
				RCID:        req.RCID,
				RingID:      req.RingID,
				Retention:   req.Retention,
			}
			hash, blob, err := encodeManifest(m)
			if err != nil {
				return err
			}
			if err := putManifestBlob(tx, hash, blob); err != nil {
				return err
			}
			manifestHash = hash
		}

		rec := versionRecord{
			BucketID:     req.BucketID,
			Key:          req.Key,
			VersionID:    req.VersionID,
			Seq:          seq,
			Size:         req.Size,
			ETag:         etag,
			ManifestHash: manifestHash,
			ChunkSize:    chunkSize,
			ContentType:  req.ContentType,
			UserMeta:     copyMap(req.UserMeta),
			Tags:         copyMap(req.Tags),
			RCID:         req.RCID,
			RingID:       req.RingID,
			StorageClass: req.StorageClass,
			CreatedAt:    now,
			Retention:    req.Retention,
		}

		// Unversioned (and Suspended, v1 simplification) buckets keep one live
		// version: the previous one becomes a tombstone waiting for shard GC.
		versioned := bucket.Versioning == "Enabled"
		if !versioned && latest != nil {
			if err := s.tombstoneVersion(tx, bucket, latest, now, "overwrite"); err != nil {
				return err
			}
		}
		if err := storage.PutJSON(tx, spaceVersions, versionKey(req.BucketID, req.Key, seq), rec); err != nil {
			return err
		}
		if err := storage.PutJSON(tx, spaceVersionIDs, versionIDKey(req.BucketID, req.Key, req.VersionID), rec); err != nil {
			return err
		}
		latestRec := latestRecord{
			Key:          req.Key,
			VersionID:    req.VersionID,
			Seq:          seq,
			Size:         req.Size,
			ETag:         etag,
			LastModified: now,
			StorageClass: req.StorageClass,
		}
		if err := storage.PutJSON(tx, spaceLatest, latestKey(req.BucketID, req.Key), latestRec); err != nil {
			return err
		}
		result = contract.CommitResult{VersionID: req.VersionID, ETag: etag}
		return nil
	})
	return result, err
}

// checkConditions evaluates S3 conditional-write headers. A delete marker counts
// as "not present" for If-None-Match: *.
func checkConditions(latest *latestRecord, ifMatch, ifNoneMatch string) error {
	exists := latest != nil && !latest.DeleteMarker
	switch ifNoneMatch {
	case "":
	case "*":
		if exists {
			return coerr.ErrPreconditionFailed
		}
	default:
		if exists && latest.ETag == trimQuotes(ifNoneMatch) {
			return coerr.ErrPreconditionFailed
		}
	}
	switch ifMatch {
	case "":
	case "*":
		if !exists {
			return coerr.ErrPreconditionFailed
		}
	default:
		if !exists || latest.ETag != trimQuotes(ifMatch) {
			return coerr.ErrPreconditionFailed
		}
	}
	return nil
}

func trimQuotes(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// tombstoneVersion marks a version row deleted and queues its shards for GC.
// Tombstones are kept (not hard-deleted) so the deletion queue can reference the
// exact manifest until the GC worker has run.
func (s *Service) tombstoneVersion(tx *storage.WriteTx, bucket Bucket, latest *latestRecord, now time.Time, reason string) error {
	rec, err := storage.GetJSON[versionRecord](tx, spaceVersionIDs, versionIDKey(bucket.BucketID, latest.Key, latest.VersionID))
	if err != nil {
		return fmt.Errorf("meta: load version for tombstone: %w", err)
	}
	rec.Deleted = true
	rec.DeletedAt = &now
	if err := storage.PutJSON(tx, spaceVersionIDs, versionIDKey(rec.BucketID, rec.Key, rec.VersionID), rec); err != nil {
		return err
	}
	if err := storage.PutJSON(tx, spaceVersions, versionKey(rec.BucketID, rec.Key, rec.Seq), rec); err != nil {
		return err
	}
	return s.enqueueDeletion(tx, DeletionItem{
		BucketID:     rec.BucketID,
		Key:          rec.Key,
		VersionID:    rec.VersionID,
		ManifestHash: rec.ManifestHash,
		Reason:       reason,
		CreatedAt:    now,
		DueAt:        now.Add(DeletionGrace),
	})
}

// GetManifest returns the manifest of one object version.
func (s *Service) GetManifest(ctx context.Context, bucket, key string, version contract.VersionID) (contract.Manifest, error) {
	var out contract.Manifest
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if err := ValidateKey(key); err != nil {
		return out, err
	}
	err := s.db.View(ctx, func(tx *storage.ReadTx) error {
		cfg, err := s.bucketConfigTx(tx, bucket)
		if err != nil {
			return err
		}
		resolved, err := resolveVersion(tx, cfg.BucketID, key, version)
		if err != nil {
			return err
		}
		// An explicit GET of a delete marker is 405 MethodNotAllowed (S3
		// semantics), while a missing/latest-tombstoned key is NoSuchKey.
		if resolved.IsDeleteMarker {
			return coerr.ErrMethodNotAllowed
		}
		m, err := loadManifest(tx, resolved, cfg)
		if err != nil {
			return err
		}
		out = m
		return nil
	})
	return out, err
}

// DeleteObject implements S3 delete semantics for versioned and unversioned
// buckets. It returns the version id affected and whether that version is a
// delete marker.
func (s *Service) DeleteObject(ctx context.Context, bucket, key string, version contract.VersionID, bypassGovernance bool) (contract.VersionID, bool, error) {
	if err := ctx.Err(); err != nil {
		return "", false, err
	}
	if err := ValidateKey(key); err != nil {
		return "", false, err
	}
	var (
		outVersion contract.VersionID
		marker     bool
	)
	err := s.db.Update(ctx, func(tx *storage.WriteTx) error {
		cfg, err := s.bucketConfigTx(tx, bucket)
		if err != nil {
			return err
		}
		now := s.now()
		latest, err := getLatest(tx, cfg.BucketID, key)
		if err != nil {
			return err
		}

		// Version-addressed delete: remove exactly that version.
		if version != "" {
			rec, err := resolveVersion(tx, cfg.BucketID, key, version)
			if err != nil {
				return err
			}
			if err := checkRetention(rec, now, bypassGovernance); err != nil {
				return err
			}
			rec.Deleted = true
			rec.DeletedAt = &now
			if err := storage.PutJSON(tx, spaceVersionIDs, versionIDKey(rec.BucketID, rec.Key, rec.VersionID), rec); err != nil {
				return err
			}
			if err := storage.PutJSON(tx, spaceVersions, versionKey(rec.BucketID, rec.Key, rec.Seq), rec); err != nil {
				return err
			}
			if err := s.enqueueDeletion(tx, DeletionItem{
				BucketID:     rec.BucketID,
				Key:          rec.Key,
				VersionID:    rec.VersionID,
				ManifestHash: rec.ManifestHash,
				Reason:       "version delete",
				CreatedAt:    now,
				DueAt:        now.Add(DeletionGrace),
			}); err != nil {
				return err
			}
			if latest != nil && latest.VersionID == rec.VersionID {
				if err := s.recomputeLatest(tx, cfg.BucketID, key, now); err != nil {
					return err
				}
			}
			outVersion, marker = rec.VersionID, rec.IsDeleteMarker
			return nil
		}

		if latest == nil {
			// Deleting a missing key is idempotent in S3.
			return nil
		}

		if cfg.Versioning == "Enabled" {
			// Deleting an object that already has a delete marker as its latest
			// version removes that marker instead of stacking another one.
			if latest.DeleteMarker {
				rec, err := resolveVersion(tx, cfg.BucketID, key, latest.VersionID)
				if err != nil {
					return err
				}
				rec.Deleted = true
				rec.DeletedAt = &now
				if err := storage.PutJSON(tx, spaceVersionIDs, versionIDKey(rec.BucketID, rec.Key, rec.VersionID), rec); err != nil {
					return err
				}
				if err := storage.PutJSON(tx, spaceVersions, versionKey(rec.BucketID, rec.Key, rec.Seq), rec); err != nil {
					return err
				}
				if err := s.recomputeLatest(tx, cfg.BucketID, key, now); err != nil {
					return err
				}
				outVersion, marker = rec.VersionID, true
				return nil
			}
			// Otherwise insert a delete marker as the new latest version.
			seq, err := nextSeq(tx, "version")
			if err != nil {
				return err
			}
			markerID := contract.VersionID(id.New())
			rec := versionRecord{
				BucketID:       cfg.BucketID,
				Key:            key,
				VersionID:      markerID,
				Seq:            seq,
				IsDeleteMarker: true,
				CreatedAt:      now,
				StorageClass:   "STANDARD",
			}
			if err := storage.PutJSON(tx, spaceVersions, versionKey(cfg.BucketID, key, seq), rec); err != nil {
				return err
			}
			if err := storage.PutJSON(tx, spaceVersionIDs, versionIDKey(cfg.BucketID, key, markerID), rec); err != nil {
				return err
			}
			latestRec := latestRecord{Key: key, VersionID: markerID, Seq: seq, DeleteMarker: true, LastModified: now, StorageClass: "STANDARD"}
			if err := storage.PutJSON(tx, spaceLatest, latestKey(cfg.BucketID, key), latestRec); err != nil {
				return err
			}
			outVersion, marker = markerID, true
			return nil
		}

		// Unversioned: tombstone the live version.
		rec, err := resolveVersion(tx, cfg.BucketID, key, latest.VersionID)
		if err != nil {
			return err
		}
		if err := checkRetention(rec, now, bypassGovernance); err != nil {
			return err
		}
		rec.Deleted = true
		rec.DeletedAt = &now
		if err := storage.PutJSON(tx, spaceVersionIDs, versionIDKey(rec.BucketID, rec.Key, rec.VersionID), rec); err != nil {
			return err
		}
		if err := storage.PutJSON(tx, spaceVersions, versionKey(rec.BucketID, rec.Key, rec.Seq), rec); err != nil {
			return err
		}
		if err := s.enqueueDeletion(tx, DeletionItem{
			BucketID:     rec.BucketID,
			Key:          rec.Key,
			VersionID:    rec.VersionID,
			ManifestHash: rec.ManifestHash,
			Reason:       "delete",
			CreatedAt:    now,
			DueAt:        now.Add(DeletionGrace),
		}); err != nil {
			return err
		}
		if err := tx.Delete(spaceLatest, latestKey(cfg.BucketID, key)); err != nil {
			return err
		}
		outVersion, marker = rec.VersionID, false
		return nil
	})
	return outVersion, marker, err
}

// recomputeLatest flips (bucket, key)'s latest pointer to the highest-sequence
// non-deleted version, or removes it when no live version remains.
func (s *Service) recomputeLatest(tx *storage.WriteTx, bucketID contract.BucketID, key string, now time.Time) error {
	prefix := versionPrefix(bucketID, key)
	var best *versionRecord
	err := tx.Scan(spaceVersions, prefix, func(_, raw []byte) error {
		var rec versionRecord
		if err := decode(raw, &rec); err != nil {
			return err
		}
		if rec.Deleted {
			return nil
		}
		if best == nil || rec.Seq > best.Seq {
			c := rec
			best = &c
		}
		return nil
	})
	if err != nil {
		return err
	}
	if best == nil {
		return tx.Delete(spaceLatest, latestKey(bucketID, key))
	}
	rec := latestRecord{
		Key:          best.Key,
		VersionID:    best.VersionID,
		Seq:          best.Seq,
		DeleteMarker: best.IsDeleteMarker,
		Size:         best.Size,
		ETag:         best.ETag,
		LastModified: best.CreatedAt,
		StorageClass: best.StorageClass,
	}
	if rec.LastModified.IsZero() {
		rec.LastModified = now
	}
	return storage.PutJSON(tx, spaceLatest, latestKey(bucketID, key), rec)
}

// checkRetention enforces object lock: legal hold always blocks, COMPLIANCE
// cannot be bypassed, GOVERNANCE can with the bypass permission.
func checkRetention(rec versionRecord, now time.Time, bypassGovernance bool) error {
	if rec.Retention == nil {
		return nil
	}
	if rec.Retention.LegalHold {
		return coerr.ErrObjectLocked
	}
	if rec.Retention.RetainUntil.IsZero() || now.After(rec.Retention.RetainUntil) {
		return nil
	}
	switch rec.Retention.Mode {
	case "COMPLIANCE":
		return coerr.ErrObjectLocked
	case "GOVERNANCE":
		if !bypassGovernance {
			return coerr.ErrObjectLocked
		}
	}
	return nil
}
