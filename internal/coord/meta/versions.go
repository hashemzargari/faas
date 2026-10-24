package meta

import (
	"context"
	"errors"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/coord/coerr"
	"github.com/fass-storage/fass/internal/storage"
)

// VersionInfo is a lifecycle/administration view of one object version. It is
// deliberately separate from the internal versionRecord so callers cannot mutate
// storage behind the service's invariants.
type VersionInfo struct {
	BucketID       contract.BucketID
	Key            string
	VersionID      contract.VersionID
	Seq            uint64
	IsLatest       bool
	IsDeleteMarker bool
	Size           int64
	CreatedAt      time.Time
	Retention      *contract.Retention
}

// ListVersions returns every live (non-tombstoned) version of a bucket, in key
// order and newest-first within a key. It is used by the lifecycle executor and
// the repair/usage services; normal data-path reads never scan buckets.
func (s *Service) ListVersions(ctx context.Context, bucketID contract.BucketID) ([]VersionInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out []VersionInfo
	err := s.db.View(ctx, func(tx *storage.ReadTx) error {
		latest := make(map[string]uint64)
		if err := storage.ScanJSON[latestRecord](tx, spaceLatest, bucketPrefix(bucketID), func(_ []byte, rec latestRecord) error {
			latest[rec.Key] = rec.Seq
			return nil
		}); err != nil {
			return err
		}
		return storage.ScanJSON[versionRecord](tx, spaceVersions, bucketPrefix(bucketID), func(_ []byte, rec versionRecord) error {
			if rec.Deleted {
				return nil
			}
			info := VersionInfo{
				BucketID:       rec.BucketID,
				Key:            rec.Key,
				VersionID:      rec.VersionID,
				Seq:            rec.Seq,
				IsLatest:       latest[rec.Key] == rec.Seq,
				IsDeleteMarker: rec.IsDeleteMarker,
				Size:           rec.Size,
				CreatedAt:      rec.CreatedAt,
				Retention:      rec.Retention,
			}
			if rec.Retention != nil {
				r := *rec.Retention
				info.Retention = &r
			}
			out = append(out, info)
			return nil
		})
	})
	return out, err
}

// ExpireVersion applies lifecycle expiry to one version: it is idempotent,
// refuses to touch any version protected by retention or legal hold, tombstones
// the version (metadata-first) and enqueues its shards for the GC executor. It
// returns false when the version was already gone or protected.
//
// The latest pointer is recomputed when the expired version was the latest, so a
// system expiry can never leave a dangling latest reference.
func (s *Service) ExpireVersion(ctx context.Context, bucketID contract.BucketID, key string, versionID contract.VersionID) (bool, error) {
	if bucketID == "" || key == "" || versionID == "" {
		return false, coerr.Invalidf("bucket_id, key and version_id are required")
	}
	var expired bool
	err := s.db.Update(ctx, func(tx *storage.WriteTx) error {
		rec, err := storage.GetJSON[versionRecord](tx, spaceVersionIDs, versionIDKey(bucketID, key, versionID))
		if errors.Is(err, storage.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if rec.Deleted {
			return nil
		}
		if err := checkRetention(rec, s.now(), true); err != nil {
			// GOVERNANCE + bypass is irrelevant for lifecycle: S3 lifecycle never
			// deletes a retained version, bypass or not.
			return nil
		}
		now := s.now()
		rec.Deleted = true
		rec.DeletedAt = &now
		if err := s.putVersionRecord(tx, rec); err != nil {
			return err
		}
		if err := s.enqueueDeletion(tx, DeletionItem{
			BucketID:     rec.BucketID,
			Key:          rec.Key,
			VersionID:    rec.VersionID,
			ManifestHash: rec.ManifestHash,
			Reason:       "lifecycle",
			CreatedAt:    now,
			DueAt:        now.Add(DeletionGrace),
		}); err != nil {
			return err
		}
		// If this was the latest version, move the pointer to the next live one.
		latest, err := getLatest(tx, bucketID, key)
		if err != nil {
			return err
		}
		if latest != nil && latest.VersionID == rec.VersionID {
			if err := s.recomputeLatest(tx, bucketID, key, now); err != nil {
				return err
			}
		}
		expired = true
		return nil
	})
	return expired, err
}
