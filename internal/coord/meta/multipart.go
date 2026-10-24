package meta

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/coord/coerr"
	"github.com/fass-storage/fass/internal/coord/id"
	"github.com/fass-storage/fass/internal/storage"
)

// uploadRecord is the multipart session. Meta is the CommitRequest template the
// gateway supplied at CreateMultipartUpload; completion merges it with the parts.
type uploadRecord struct {
	UploadID  contract.UploadID `json:"upload_id"`
	BucketID  contract.BucketID `json:"bucket_id"`
	Key       string            `json:"key"`
	Meta      CommitTemplate    `json:"meta"`
	CreatedAt time.Time         `json:"created_at"`
}

// CommitTemplate is the subset of CommitRequest that is known before the parts
// exist (JSON-friendly, independent of contract's wire types).
type CommitTemplate struct {
	VersionID    contract.VersionID      `json:"version_id,omitempty"`
	ChunkSize    int                     `json:"chunk_size,omitempty"`
	Encryption   contract.EncryptionMeta `json:"encryption"`
	ContentType  string                  `json:"content_type,omitempty"`
	UserMeta     map[string]string       `json:"user_meta,omitempty"`
	Tags         map[string]string       `json:"tags,omitempty"`
	RCID         string                  `json:"rc_id,omitempty"`
	RingID       contract.RingID         `json:"ring_id,omitempty"`
	StorageClass string                  `json:"storage_class,omitempty"`
	Retention    *contract.Retention     `json:"retention,omitempty"`
}

type partRecord struct {
	PartNumber int                     `json:"part_number"`
	ETag       string                  `json:"etag"`
	Size       int64                   `json:"size"`
	Chunks     []contract.ChunkRef     `json:"chunks"`
	Encryption contract.EncryptionMeta `json:"encryption"`
	UpdatedAt  time.Time               `json:"updated_at"`
}

func partPrefix(up contract.UploadID) []byte { return []byte(string(up) + "\x00") }

func partKey(up contract.UploadID, n int) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(n))
	return storage.JoinKeyN([]string{string(up)}, buf[:])
}

func uploadIndexKey(bucketID contract.BucketID, up contract.UploadID) []byte {
	return storage.JoinKeyN([]string{string(bucketID)}, []byte(up))
}

// CreateUpload starts a multipart upload. The gateway passes the encryption
// metadata and the version id it will bind the chunk AAD to.
func (s *Service) CreateUpload(ctx context.Context, bucket, key string, meta contract.CommitRequest) (contract.UploadID, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := ValidateKey(key); err != nil {
		return "", err
	}
	uploadID := contract.UploadID(id.New())
	err := s.db.Update(ctx, func(tx *storage.WriteTx) error {
		cfg, err := s.bucketConfigTx(tx, bucket)
		if err != nil {
			return err
		}
		if meta.VersionID != "" {
			if err := id.Validate(string(meta.VersionID)); err != nil {
				return coerr.Invalidf("meta.version_id must be a UUIDv4: %v", err)
			}
			if tx.Has(spaceVersionIDs, versionIDKey(cfg.BucketID, key, meta.VersionID)) {
				return coerr.E(409, coerr.CodeConflict, "version_id %s is already committed", meta.VersionID)
			}
		}
		if meta.ChunkSize == 0 {
			meta.ChunkSize = DefaultChunkSize
		}
		if meta.StorageClass == "" {
			meta.StorageClass = "STANDARD"
		}
		rec := uploadRecord{
			UploadID:  uploadID,
			BucketID:  cfg.BucketID,
			Key:       key,
			CreatedAt: s.now(),
			Meta: CommitTemplate{
				VersionID:    meta.VersionID,
				ChunkSize:    meta.ChunkSize,
				Encryption:   meta.Encryption,
				ContentType:  meta.ContentType,
				UserMeta:     copyMap(meta.UserMeta),
				Tags:         copyMap(meta.Tags),
				RCID:         meta.RCID,
				RingID:       meta.RingID,
				StorageClass: meta.StorageClass,
				Retention:    meta.Retention,
			},
		}
		if err := storage.PutJSON(tx, spaceUploads, []byte(uploadID), rec); err != nil {
			return err
		}
		return storage.PutJSON(tx, spaceUploadIndex, uploadIndexKey(cfg.BucketID, uploadID), rec)
	})
	return uploadID, err
}

// CommitPart records one uploaded part idempotently: re-uploading the same part
// number replaces it.
func (s *Service) CommitPart(ctx context.Context, up contract.UploadID, partNumber int, etag string, size int64, chunks []contract.ChunkRef, enc contract.EncryptionMeta) error {
	if partNumber < 1 || partNumber > 10000 {
		return coerr.Invalidf("part number must be in 1..10000")
	}
	if size < 0 {
		return coerr.Invalidf("part size must be >= 0")
	}
	if err := validatePartChunks(chunks); err != nil {
		return err
	}
	return s.db.Update(ctx, func(tx *storage.WriteTx) error {
		if !tx.Has(spaceUploads, []byte(up)) {
			return coerr.ErrNoSuchUpload
		}
		rec := partRecord{
			PartNumber: partNumber,
			ETag:       strings.Trim(etag, "\""),
			Size:       size,
			Chunks:     chunks,
			Encryption: enc,
			UpdatedAt:  s.now(),
		}
		return storage.PutJSON(tx, spaceParts, partKey(up, partNumber), rec)
	})
}

// ListParts returns the uploaded parts in ascending part-number order.
func (s *Service) ListParts(ctx context.Context, up contract.UploadID) ([]contract.PartInfo, error) {
	out := []contract.PartInfo{}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	err := s.db.View(ctx, func(tx *storage.ReadTx) error {
		if !tx.Has(spaceUploads, []byte(up)) {
			return coerr.ErrNoSuchUpload
		}
		return storage.ScanJSON[partRecord](tx, spaceParts, partPrefix(up), func(_ []byte, p partRecord) error {
			out = append(out, contract.PartInfo{
				PartNumber: p.PartNumber,
				ETag:       p.ETag,
				Size:       p.Size,
				Chunks:     p.Chunks,
				Encryption: p.Encryption,
			})
			return nil
		})
	})
	return out, err
}

// ListUploads lists in-progress uploads for a bucket.
func (s *Service) ListUploads(ctx context.Context, bucketID contract.BucketID) ([]contract.UploadInfo, error) {
	out := []contract.UploadInfo{}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	err := s.db.View(ctx, func(tx *storage.ReadTx) error {
		return storage.ScanJSON[uploadRecord](tx, spaceUploadIndex, bucketPrefix(bucketID), func(_ []byte, rec uploadRecord) error {
			out = append(out, contract.UploadInfo{
				UploadID:     rec.UploadID,
				BucketID:     rec.BucketID,
				Key:          rec.Key,
				Initiated:    rec.CreatedAt,
				StorageClass: rec.Meta.StorageClass,
			})
			return nil
		})
	})
	return out, err
}

// CompleteUpload assembles the parts into a single object version. The commit is
// idempotent because the version id was fixed at CreateMultipartUpload; a retry
// after a crash returns the same version and then clears the upload.
func (s *Service) CompleteUpload(ctx context.Context, up contract.UploadID) (contract.CommitResult, error) {
	var result contract.CommitResult
	if err := ctx.Err(); err != nil {
		return result, err
	}
	var upload uploadRecord
	var parts []partRecord
	if err := s.db.View(ctx, func(tx *storage.ReadTx) error {
		rec, err := storage.GetJSON[uploadRecord](tx, spaceUploads, []byte(up))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.ErrNoSuchUpload
		}
		if err != nil {
			return err
		}
		upload = rec
		return storage.ScanJSON[partRecord](tx, spaceParts, partPrefix(up), func(_ []byte, p partRecord) error {
			parts = append(parts, p)
			return nil
		})
	}); err != nil {
		return result, err
	}
	if len(parts) == 0 {
		return result, coerr.ErrInvalidPart
	}
	for i, p := range parts {
		if p.PartNumber != i+1 {
			return result, coerr.ErrInvalidPart
		}
	}
	// Re-number chunk indices globally across parts so the object manifest is a
	// flat, dense chunk table.
	var chunks []contract.ChunkRef
	for _, p := range parts {
		for _, c := range p.Chunks {
			c.Index = len(chunks)
			chunks = append(chunks, c)
		}
	}
	var total int64
	etags := make([]string, 0, len(parts))
	for _, p := range parts {
		total += p.Size
		etags = append(etags, p.ETag)
	}
	versionID := upload.Meta.VersionID
	if versionID == "" {
		versionID = contract.VersionID(id.New())
	}
	req := contract.CommitRequest{
		VersionID:    versionID,
		BucketID:     upload.BucketID,
		Key:          upload.Key,
		Size:         total,
		ETag:         multipartETag(etags),
		ChunkSize:    upload.Meta.ChunkSize,
		Chunks:       chunks,
		Encryption:   upload.Meta.Encryption,
		ContentType:  upload.Meta.ContentType,
		UserMeta:     upload.Meta.UserMeta,
		Tags:         upload.Meta.Tags,
		RCID:         upload.Meta.RCID,
		RingID:       upload.Meta.RingID,
		StorageClass: upload.Meta.StorageClass,
		Retention:    upload.Meta.Retention,
	}
	if req.Encryption.Mode == "" && len(parts) > 0 {
		req.Encryption = parts[0].Encryption
	}
	// The chunks are globally renumbered above, so the dense-table check that
	// CommitObject applies would reject nothing; validate the per-chunk shape
	// that part uploads established.
	if err := validatePartChunks(req.Chunks); err != nil {
		return result, err
	}
	result, err := s.CommitObject(ctx, req)
	if err != nil {
		return result, err
	}
	// The object is visible; clearing the session is best-effort and idempotent.
	if err := s.AbortUpload(ctx, up); err != nil && !errors.Is(err, coerr.ErrNoSuchUpload) {
		return result, fmt.Errorf("meta: complete upload %s committed but cleanup failed: %w", up, err)
	}
	return result, nil
}

// AbortUpload removes the session and its parts.
func (s *Service) AbortUpload(ctx context.Context, up contract.UploadID) error {
	return s.db.Update(ctx, func(tx *storage.WriteTx) error {
		rec, err := storage.GetJSON[uploadRecord](tx, spaceUploads, []byte(up))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.ErrNoSuchUpload
		}
		if err != nil {
			return err
		}
		if err := tx.Delete(spaceUploads, []byte(up)); err != nil {
			return err
		}
		if err := tx.Delete(spaceUploadIndex, uploadIndexKey(rec.BucketID, up)); err != nil {
			return err
		}
		return tx.Scan(spaceParts, partPrefix(up), func(k, _ []byte) error {
			return tx.Delete(spaceParts, k)
		})
	})
}

// multipartETag computes the S3 multipart ETag shape: md5 over the concatenated
// part digests, suffixed with the part count.
func multipartETag(etags []string) string {
	h := md5.New() //nolint:gosec // compatibility checksum, not a security primitive
	for _, e := range etags {
		raw, err := hex.DecodeString(strings.Trim(e, "\""))
		if err != nil {
			h.Write([]byte(e))
			continue
		}
		h.Write(raw)
	}
	return fmt.Sprintf("%x-%d", h.Sum(nil), len(etags))
}

// validatePartChunks validates a part's chunk table. Unlike a committed object,
// part chunks are not required to start at index 0 or be dense; everything the
// read path needs is per-chunk.
func validatePartChunks(chunks []contract.ChunkRef) error {
	for i, c := range chunks {
		if err := c.Params.Validate(); err != nil {
			return coerr.Invalidf("part chunk %d: invalid params: %v", i, err)
		}
		total := c.Params.TotalShards()
		if len(c.Slots) != total || len(c.Checksums) != total {
			return coerr.Invalidf("part chunk %d: expected %d slots and checksums, got %d/%d",
				i, total, len(c.Slots), len(c.Checksums))
		}
		perGroup := c.Params.ShardsPerGroup()
		for s, slot := range c.Slots {
			if slot.AgentID == "" {
				return coerr.Invalidf("part chunk %d: slot %d has no agent", i, s)
			}
			if slot.GeoGroup != s/perGroup || slot.LocalIndex != s%perGroup {
				return coerr.Invalidf("part chunk %d: slot %d is not in shard-index order", i, s)
			}
		}
	}
	return nil
}
