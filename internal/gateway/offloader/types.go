// Package offloader is the gateway's data-plane engine: it turns an object
// stream into encrypted, erasure-coded shards placed on agents, and reverses the
// process for reads.
//
// The pipeline is, per chunk (docs/03 §2.1):
//
//	plaintext → encrypt (AES-256-GCM, internal/crypto) → outer RS(geo) →
//	inner RS(local) → ResolvePlacement → parallel shard PUTs → next chunk
//
// and the object becomes visible only through the single CommitObject call at
// the end, so a crash leaves orphan shards (garbage) but never a dangling
// manifest (docs/02 §5.1).
package offloader

import (
	"context"
	"errors"
	"io"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/ec"
)

// Sentinel errors. The S3 layer maps these onto the XML error taxonomy.
var (
	ErrBadDigest      = errors.New("offloader: payload digest mismatch")
	ErrTooLarge       = errors.New("offloader: object exceeds the maximum allowed size")
	ErrIncompleteBody = errors.New("offloader: body shorter than the declared length")
	ErrNoSuchUpload   = errors.New("offloader: no such multipart upload")
	ErrNotImplemented = errors.New("offloader: not implemented")
	ErrPlacement      = errors.New("offloader: placement failed")
	ErrShardWrite     = errors.New("offloader: shard write failed")
	ErrDecode         = errors.New("offloader: shard decode failed")
	ErrManifest       = errors.New("offloader: manifest unusable")
)

// ChecksumAlgorithm names the payload checksum algorithms the gateway verifies.
type ChecksumAlgorithm string

const (
	ChecksumMD5       ChecksumAlgorithm = "md5"
	ChecksumSHA1      ChecksumAlgorithm = "sha1"
	ChecksumSHA256    ChecksumAlgorithm = "sha256"
	ChecksumCRC32     ChecksumAlgorithm = "crc32"
	ChecksumCRC32C    ChecksumAlgorithm = "crc32c"
	ChecksumCRC64NVME ChecksumAlgorithm = "crc64nvme"
)

// ExpectedChecksum is a checksum the client declared for the payload. Value is
// the decoded digest (not base64).
type ExpectedChecksum struct {
	Algorithm ChecksumAlgorithm
	Value     []byte
}

// ObjectSpec describes one object (or multipart part) write.
type ObjectSpec struct {
	BucketID     contract.BucketID
	Bucket       string
	Key          string
	TenantID     contract.TenantID
	ProjectID    contract.ProjectID
	VersionID    contract.VersionID
	Size         int64 // declared size, -1 when unknown (chunked transfer)
	MaxBytes     int64 // hard limit enforced while streaming; 0 = default
	ContentType  string
	UserMeta     map[string]string
	Tags         map[string]string
	StorageClass string
	RCID         string
	RingID       contract.RingID
	Params       ec.Params
	ChunkSize    int
	Retention    *contract.Retention
	// Conditional write support (deliberate improvement over Cubbit, docs/05 §4).
	IfMatch     string
	IfNoneMatch string
	// Checksums must verify before the commit; a mismatch aborts the upload so
	// the object never becomes visible with wrong bytes.
	Checksums []ExpectedChecksum
	// DeferredChecksums is evaluated after the body reaches EOF and before the
	// commit. It exists because aws-chunked trailers are only materialised once
	// the body has been fully consumed.
	DeferredChecksums func() []ExpectedChecksum
}

// ByteRange is an inclusive-resolved byte range of an object: [Start,
// Start+Length).
type ByteRange struct {
	Start  int64
	Length int64
}

// ReadRequest describes one object read.
type ReadRequest struct {
	Bucket    string
	Key       string
	TenantID  contract.TenantID
	ProjectID contract.ProjectID
	Manifest  contract.Manifest
	// Range is nil for a whole-object read.
	Range *ByteRange
}

// PartRef is the result of writing one multipart part.
type PartRef struct {
	ETag       string
	Size       int64
	Chunks     []contract.ChunkRef
	Encryption contract.EncryptionMeta
}

// Offloader is the data-plane interface consumed by the S3 frontend.
type Offloader interface {
	Write(ctx context.Context, spec ObjectSpec, body io.Reader) (contract.CommitResult, error)
	Read(ctx context.Context, req ReadRequest, w io.Writer) error
	WritePart(ctx context.Context, spec ObjectSpec, uploadID contract.UploadID, partNumber int, body io.Reader) (PartRef, error)
}
