package meta

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/coord/coerr"
	"github.com/fass-storage/fass/internal/storage"
)

// Manifest blobs (docs/04 §5.2).
//
// The chunk table is what grows with object size (60 slots per 16 MiB chunk for
// the reference RC), so it is not stored inline in the hot version row. A
// manifest is serialised to canonical JSON, content-addressed by SHA-256 and
// compressed with stdlib flate at BestSpeed. Identical chunk tables (retried
// commits, copies) deduplicate because the key is the content hash.
//
// Blob layout:
//
//	byte   version (1)
//	uint64 uncompressed length, big-endian
//	bytes  flate-compressed JSON(contract.Manifest)
const (
	manifestBlobVersion = 1
	// MaxManifestBlob bounds a single manifest (5 TiB / 16 MiB chunks = 327 680
	// chunks; the 1 MiB page ceiling from docs/04 §5.2 is enforced here).
	MaxManifestBlob = 1 << 20
)

// manifestBlob is the content-addressed part of a manifest: exactly the chunk
// table (the part that grows with object size) plus the encryption envelope.
// Identity fields live in the version row, so two objects with identical chunk
// tables share one blob.
type manifestBlob struct {
	Chunks     []contract.ChunkRef     `json:"chunks"`
	Encryption contract.EncryptionMeta `json:"encryption"`
}

func encodeManifest(m contract.Manifest) (string, []byte, error) {
	raw, err := json.Marshal(manifestBlob{Chunks: m.Chunks, Encryption: m.Encryption})
	if err != nil {
		return "", nil, fmt.Errorf("meta: encode manifest: %w", err)
	}
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])

	var buf bytes.Buffer
	buf.WriteByte(manifestBlobVersion)
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(raw)))
	buf.Write(lenBuf[:])
	w, err := flate.NewWriter(&buf, flate.BestSpeed)
	if err != nil {
		return "", nil, fmt.Errorf("meta: flate manifest: %w", err)
	}
	if _, err := w.Write(raw); err != nil {
		return "", nil, fmt.Errorf("meta: compress manifest: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", nil, fmt.Errorf("meta: close manifest compressor: %w", err)
	}
	return hash, buf.Bytes(), nil
}

func decodeManifestBlob(blob []byte) (contract.Manifest, error) {
	var m contract.Manifest
	var payload manifestBlob
	if len(blob) < 9 {
		return m, fmt.Errorf("meta: manifest blob too short")
	}
	if blob[0] != manifestBlobVersion {
		return m, fmt.Errorf("meta: unsupported manifest blob version %d", blob[0])
	}
	size := binary.BigEndian.Uint64(blob[1:9])
	if size > 64<<20 {
		return m, fmt.Errorf("meta: manifest blob declares absurd size %d", size)
	}
	r := flate.NewReader(bytes.NewReader(blob[9:]))
	defer r.Close()
	raw, err := io.ReadAll(io.LimitReader(r, int64(size)+1))
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return m, fmt.Errorf("meta: decompress manifest: %w", err)
	}
	if uint64(len(raw)) != size {
		return m, fmt.Errorf("meta: manifest length mismatch: got %d want %d", len(raw), size)
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return m, fmt.Errorf("meta: decode manifest: %w", err)
	}
	m.Chunks = payload.Chunks
	m.Encryption = payload.Encryption
	return m, nil
}

// putManifestBlob stores a manifest blob unless the identical content is
// already present (content addressing makes that a no-op).
func putManifestBlob(tx storage.Writer, hash string, blob []byte) error {
	if len(blob) > MaxManifestBlob {
		return coerr.Invalidf("manifest blob is %d bytes, exceeding the %d-byte page limit", len(blob), MaxManifestBlob)
	}
	if tx.Has(spaceManifests, []byte(hash)) {
		return nil
	}
	return tx.Put(spaceManifests, []byte(hash), blob)
}

// loadManifest reconstructs a manifest from a version record and its blob.
func loadManifest(tx storage.Reader, rec versionRecord, bucket contract.BucketConfig) (contract.Manifest, error) {
	var m contract.Manifest
	if rec.ManifestHash != "" {
		blob, err := tx.Get(spaceManifests, []byte(rec.ManifestHash))
		if errors.Is(err, storage.ErrNotFound) {
			return m, fmt.Errorf("meta: manifest blob %s for %s/%s@%s is missing", rec.ManifestHash, rec.BucketID, rec.Key, rec.VersionID)
		}
		if err != nil {
			return m, err
		}
		decoded, err := decodeManifestBlob(blob)
		if err != nil {
			return m, err
		}
		m = decoded
	}
	// Identity/lifecycle fields are authoritative in the version row: the blob
	// is content-addressed, so two commits with identical chunk tables would
	// otherwise share identity.
	m.TenantID = bucket.TenantID
	m.ProjectID = bucket.ProjectID
	m.BucketID = rec.BucketID
	m.Key = rec.Key
	m.VersionID = rec.VersionID
	m.Size = rec.Size
	m.ETag = rec.ETag
	m.ChunkSize = rec.ChunkSize
	m.ContentType = rec.ContentType
	m.UserMeta = rec.UserMeta
	m.Tags = rec.Tags
	m.CreatedAt = rec.CreatedAt
	m.RCID = rec.RCID
	m.RingID = rec.RingID
	if rec.Retention != nil {
		r := *rec.Retention
		m.Retention = &r
	}
	return m, nil
}

// validateChunkTable enforces the gateway/coordinator boundary invariant: a
// chunk table must be complete and self-consistent before it becomes metadata,
// because the read path trusts it.
func validateChunkTable(chunks []contract.ChunkRef) error {
	for i, c := range chunks {
		if c.Index != i {
			return coerr.Invalidf("chunk table is not dense: chunk %d has index %d", i, c.Index)
		}
		if err := c.Params.Validate(); err != nil {
			return coerr.Invalidf("chunk %d: invalid params: %v", i, err)
		}
		total := c.Params.TotalShards()
		if len(c.Slots) != total {
			return coerr.Invalidf("chunk %d: %d slots, code needs %d", i, len(c.Slots), total)
		}
		if len(c.Checksums) != total {
			return coerr.Invalidf("chunk %d: %d checksums, code needs %d", i, len(c.Checksums), total)
		}
		if c.ShardSize < 0 || c.CiphertextLen < 0 {
			return coerr.Invalidf("chunk %d: negative size", i)
		}
		perGroup := c.Params.ShardsPerGroup()
		for s, slot := range c.Slots {
			if slot.AgentID == "" {
				return coerr.Invalidf("chunk %d: slot %d has no agent", i, s)
			}
			wantGroup, wantIndex := s/perGroup, s%perGroup
			if slot.GeoGroup != wantGroup || slot.LocalIndex != wantIndex {
				return coerr.Invalidf("chunk %d: slot %d is (%d,%d), expected (%d,%d) for shard-index order",
					i, s, slot.GeoGroup, slot.LocalIndex, wantGroup, wantIndex)
			}
		}
	}
	return nil
}

// ChunkTable returns the chunk table stored under a manifest hash. The deletion
// queue and the repair orchestrator use it to recover shard addresses from a
// tombstoned version without loading the whole manifest.
func (s *Service) ChunkTable(ctx context.Context, manifestHash string) ([]contract.ChunkRef, error) {
	if manifestHash == "" {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var chunks []contract.ChunkRef
	err := s.db.View(ctx, func(tx storage.Reader) error {
		blob, err := tx.Get(spaceManifests, []byte(manifestHash))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.E(404, "NoSuchManifest", "manifest blob %s does not exist", manifestHash)
		}
		if err != nil {
			return err
		}
		m, err := decodeManifestBlob(blob)
		if err != nil {
			return err
		}
		chunks = m.Chunks
		return nil
	})
	return chunks, err
}
