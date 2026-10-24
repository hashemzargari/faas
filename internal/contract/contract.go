// Package contract holds the cross-service interfaces shared by the gateway,
// the coordinator and the agents.
//
// The rule is: this package is FROZEN. The gateway, coordinator and agent may
// depend on it; it may not depend on any of them. Changes are additive and go
// through the Lead (see docs/06-delivery-plan.md §3).
//
// Transport note: v1 wires these interfaces over HTTP/2 + mTLS (JSON control,
// streaming shard bodies). The interfaces are transport-agnostic so gRPC/proto
// and QUIC shard streams can replace the transport without touching callers.
package contract

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/fass-storage/fass/internal/ec"
)

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

type TenantID string
type ProjectID string
type BucketID string
type NodeID string
type AgentID string
type NexusID string
type RingID string
type ShardSetID string
type UploadID string
type VersionID string

// Principal is an authenticated caller.
type Principal struct {
	AccessKeyID string    `json:"access_key_id"`
	TenantID    TenantID  `json:"tenant_id"`
	ProjectID   ProjectID `json:"project_id"`
	IsRoot      bool      `json:"is_root"`
	Groups      []string  `json:"groups"` // e.g. "AllUsers", "AuthenticatedUsers"
}

// ---------------------------------------------------------------------------
// Authorisation (mirrors the documented four-stage chain)
// ---------------------------------------------------------------------------

type Action string

const (
	ActionListBuckets     Action = "s3:ListAllMyBuckets"
	ActionCreateBucket    Action = "s3:CreateBucket"
	ActionDeleteBucket    Action = "s3:DeleteBucket"
	ActionListBucket      Action = "s3:ListBucket"
	ActionGetBucketAcl    Action = "s3:GetBucketAcl"
	ActionPutBucketAcl    Action = "s3:PutBucketAcl"
	ActionPutBucketConf   Action = "s3:PutBucketConfiguration"
	ActionGetBucketConf   Action = "s3:GetBucketConfiguration"
	ActionGetObject       Action = "s3:GetObject"
	ActionPutObject       Action = "s3:PutObject"
	ActionDeleteObject    Action = "s3:DeleteObject"
	ActionGetObjectAcl    Action = "s3:GetObjectAcl"
	ActionPutObjectAcl    Action = "s3:PutObjectAcl"
	ActionGetObjectTag    Action = "s3:GetObjectTagging"
	ActionPutObjectTag    Action = "s3:PutObjectTagging"
	ActionBypassGovern    Action = "s3:BypassGovernanceRetention"
	ActionCreateMultipart Action = "s3:CreateMultipartUpload"
	ActionAbortMultipart  Action = "s3:AbortMultipartUpload"
)

// Resource is a CRN addressable object.
type Resource struct {
	Region    string    `json:"region"`
	Kind      string    `json:"kind"` // "bucket" | "object" | "project" | "tenant" | "swarm"
	TenantID  TenantID  `json:"tenant_id"`
	ProjectID ProjectID `json:"project_id"`
	Bucket    string    `json:"bucket"`
	Key       string    `json:"key"`
}

// RequestContext carries the facts an authorisation decision may depend on.
type RequestContext struct {
	Principal Principal
	Action    Action
	Resource  Resource
	SourceIP  string
	Now       time.Time
	Condition map[string]string // s3:prefix, s3:max-keys, s3:x-amz-acl, ...
}

type Decision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"` // deny reason, for audit
}

// Authorizer evaluates IAM policy -> bucket policy -> ACL, in that order.
type Authorizer interface {
	Authorize(ctx context.Context, rc RequestContext) (Decision, error)
	// VerifySignature resolves an access key to a principal and the HMAC
	// material the gateway needs to verify SigV2/SigV4 locally.
	VerifySignature(ctx context.Context, accessKeyID string) (Principal, []byte, error)
}

// ---------------------------------------------------------------------------
// Metadata / object model
// ---------------------------------------------------------------------------

// EncryptionMeta describes how one object version's payload is encrypted.
// Keys are always wrapped; the coordinator never sees plaintext key material.
type EncryptionMeta struct {
	Mode           string `json:"mode"` // single-key | local-multi-keys | remote-multi-keys | zero-knowledge
	WrapKeyVersion int    `json:"wrap_key_version"`
	WrappedFileKey []byte `json:"wrapped_file_key"`
	KeyFingerprint []byte `json:"key_fingerprint"`
	FrameSize      int    `json:"frame_size"`
}

// ChunkRef is everything needed to read one chunk, minus the bytes.
type ChunkRef struct {
	Index int `json:"index"`
	// ShardSetID is authoritative when non-empty. Multipart parts derive
	// different ids for the same chunk index (see ShardSetIDForScoped), so
	// recomputing it from (bucket, key, version, index) alone is valid only for
	// single-PUT objects and for manifests written before this field existed.
	ShardSetID    ShardSetID `json:"shard_set_id,omitempty"`
	Params        ec.Params  `json:"params"`
	CiphertextLen int        `json:"ciphertext_len"`
	ShardSize     int        `json:"shard_size"`
	Slots         []Slot     `json:"slots"`
	// AADChunkIndex is the chunk index that was bound in the chunk AAD at write
	// time. For multipart it is part-local (0..n-1 per part); Index is the
	// object-wide position used for ordering. Read must use this value, never a
	// re-derived one, or GCM authentication fails.
	AADChunkIndex int `json:"aad_chunk_index,omitempty"`
	// Checksums[i] is BigEndian(SHA-256(shard i)[:8]), aligned with shard index.
	Checksums  []uint64 `json:"checksums"`
	Generation int      `json:"generation"`
}

// Slot is the placement of one shard.
type Slot struct {
	GeoGroup   int     `json:"geo_group"`
	LocalIndex int     `json:"local_index"`
	AgentID    AgentID `json:"agent_id"`
	NodeID     NodeID  `json:"node_id"`
	NexusID    NexusID `json:"nexus_id"`
	Endpoint   string  `json:"endpoint"` // host:port for shard transport
}

// Manifest is the committed description of one object version.
type Manifest struct {
	TenantID    TenantID          `json:"tenant_id"`
	ProjectID   ProjectID         `json:"project_id"`
	BucketID    BucketID          `json:"bucket_id"`
	Key         string            `json:"key"`
	VersionID   VersionID         `json:"version_id"`
	Size        int64             `json:"size"`
	ETag        string            `json:"etag"`
	ChunkSize   int               `json:"chunk_size"`
	Chunks      []ChunkRef        `json:"chunks"`
	Encryption  EncryptionMeta    `json:"encryption"`
	ContentType string            `json:"content_type"`
	UserMeta    map[string]string `json:"user_meta"`
	Tags        map[string]string `json:"tags"`
	CreatedAt   time.Time         `json:"created_at"`
	RCID        string            `json:"rc_id"`
	RingID      RingID            `json:"ring_id"`
	// Retention is nil when the object version is not locked.
	Retention *Retention `json:"retention,omitempty"`
}

// Bucket config is the per-bucket policy surface the data path consults.
type BucketConfig struct {
	BucketID    BucketID  `json:"bucket_id"`
	Name        string    `json:"name"`
	TenantID    TenantID  `json:"tenant_id"`
	ProjectID   ProjectID `json:"project_id"`
	Region      string    `json:"region"`
	Versioning  string    `json:"versioning"` // "", "Enabled", "Suspended"
	ObjectLock  bool      `json:"object_lock"`
	Ownership   string    `json:"ownership"` // ObjectWriter | BucketOwnerEnforced
	DefaultRCID string    `json:"default_rc_id"`
	QuotaBytes  int64     `json:"quota_bytes"`
	// CreatedAt is required on the wire: S3 ListBuckets carries <CreationDate>
	// per bucket, and aws-sdk-go-v2 (hence rclone, Terraform, many SDKs) fails
	// the entire response when it cannot parse it as RFC3339. Never emit empty.
	CreatedAt time.Time `json:"created_at"`
}

// ---------------------------------------------------------------------------
// Placement
// ---------------------------------------------------------------------------

type PlacementRequest struct {
	ShardSetID ShardSetID `json:"shard_set_id"`
	Params     ec.Params  `json:"params"`
	ChunkBytes int        `json:"chunk_bytes"`
	TenantID   TenantID   `json:"tenant_id"`
	ProjectID  ProjectID  `json:"project_id"`
	RCID       string     `json:"rc_id"`
	RingID     RingID     `json:"ring_id"` // optional hint
	// ExcludeAgents removes candidates that already failed for this shard set,
	// implementing the displacement path (docs/03 §4.4).
	ExcludeAgents []AgentID `json:"exclude_agents"`
}

type Placement struct {
	ShardSetID ShardSetID `json:"shard_set_id"`
	RingID     RingID     `json:"ring_id"`
	Slots      []Slot     `json:"slots"`
	Generation int        `json:"generation"`
}

// ---------------------------------------------------------------------------
// Coordinator: the control-plane contract
// ---------------------------------------------------------------------------

// CommitRequest is the single transactional commit that makes an object visible.
type CommitRequest struct {
	// VersionID is generated by the GATEWAY before the payload is encrypted, so
	// the chunk AAD can bind to it. The coordinator persists it verbatim and
	// rejects duplicates. This also makes retried commits idempotent.
	VersionID    VersionID         `json:"version_id"`
	BucketID     BucketID          `json:"bucket_id"`
	Key          string            `json:"key"`
	Size         int64             `json:"size"`
	ETag         string            `json:"etag"`
	ChunkSize    int               `json:"chunk_size"`
	Chunks       []ChunkRef        `json:"chunks"`
	Encryption   EncryptionMeta    `json:"encryption"`
	ContentType  string            `json:"content_type"`
	UserMeta     map[string]string `json:"user_meta"`
	Tags         map[string]string `json:"tags"`
	RCID         string            `json:"rc_id"`
	RingID       RingID            `json:"ring_id"`
	StorageClass string            `json:"storage_class"`
	// Conditional write support (deliberate improvement over Cubbit).
	IfMatch     string     `json:"if_match"`
	IfNoneMatch string     `json:"if_none_match"`
	Retention   *Retention `json:"retention"`
}

type Retention struct {
	Mode        string    `json:"mode"` // GOVERNANCE | COMPLIANCE
	RetainUntil time.Time `json:"retain_until"`
	LegalHold   bool      `json:"legal_hold"`
}

type CommitResult struct {
	VersionID VersionID `json:"version_id"`
	ETag      string    `json:"etag"`
}

type ListRequest struct {
	BucketID          BucketID `json:"bucket_id"`
	Prefix            string   `json:"prefix"`
	Delimiter         string   `json:"delimiter"`
	MaxKeys           int      `json:"max_keys"`
	StartAfter        string   `json:"start_after"`
	ContinuationToken string   `json:"continuation_token"`
	// KeyMarker/VersionIDMarker are the S3 ListObjectVersions markers. They are
	// distinct from StartAfter: a version listing must resume *within* a key.
	KeyMarker       string `json:"key_marker,omitempty"`
	VersionIDMarker string `json:"version_id_marker,omitempty"`
	Versions        bool   `json:"versions"`
}

type ObjectEntry struct {
	Key            string    `json:"key"`
	Size           int64     `json:"size"`
	ETag           string    `json:"etag"`
	LastModified   time.Time `json:"last_modified"`
	VersionID      VersionID `json:"version_id"`
	IsLatest       bool      `json:"is_latest"`
	IsDeleteMarker bool      `json:"is_delete_marker"`
	CommonPrefix   string    `json:"common_prefix"`
	StorageClass   string    `json:"storage_class"`
}

type ListResult struct {
	Entries               []ObjectEntry `json:"entries"`
	IsTruncated           bool          `json:"is_truncated"`
	NextContinuationToken string        `json:"next_continuation_token"`
	NextKeyMarker         string        `json:"next_key_marker"`
	NextVersionIDMarker   string        `json:"next_version_id_marker"`
	KeyCount              int           `json:"key_count"`
}

// Coordinator is implemented by fass-coordinator and consumed by the gateway.
type Coordinator interface {
	Authorizer

	GetBucket(ctx context.Context, bucket string) (BucketConfig, error)
	CreateBucket(ctx context.Context, b BucketConfig) error
	UpdateBucketConfig(ctx context.Context, b BucketConfig) error
	DeleteBucket(ctx context.Context, bucket string) error
	ListBuckets(ctx context.Context, p Principal) ([]BucketConfig, error)

	// Bucket sub-resources: ACL, lifecycle, and the object-lock configuration.
	// Lifecycle is stored opaquely; the gateway validates its shape.
	GetBucketACL(ctx context.Context, bucket string) (ACL, error)
	PutBucketACL(ctx context.Context, bucket string, acl ACL) error
	GetBucketLifecycle(ctx context.Context, bucket string) ([]byte, error)
	PutBucketLifecycle(ctx context.Context, bucket string, xml []byte) error
	DeleteBucketLifecycle(ctx context.Context, bucket string) error

	// Per-object-version sub-resources.
	GetObjectTags(ctx context.Context, bucket, key string, v VersionID) (map[string]string, error)
	PutObjectTags(ctx context.Context, bucket, key string, v VersionID, tags map[string]string) error
	GetObjectRetention(ctx context.Context, bucket, key string, v VersionID) (*Retention, error)
	PutObjectRetention(ctx context.Context, bucket, key string, v VersionID, r *Retention) error
	GetObjectACL(ctx context.Context, bucket, key string, v VersionID) (ACL, error)
	PutObjectACL(ctx context.Context, bucket, key string, v VersionID, acl ACL) error

	ResolvePlacement(ctx context.Context, req PlacementRequest) (Placement, error)
	CommitObject(ctx context.Context, req CommitRequest) (CommitResult, error)
	GetManifest(ctx context.Context, bucket, key string, version VersionID) (Manifest, error)
	DeleteObject(ctx context.Context, bucket, key string, version VersionID, bypassGovernance bool) (VersionID, bool, error)
	ListObjects(ctx context.Context, req ListRequest) (ListResult, error)

	// Multipart
	CreateUpload(ctx context.Context, bucket, key string, meta CommitRequest) (UploadID, error)
	CommitPart(ctx context.Context, up UploadID, partNumber int, etag string, size int64, chunks []ChunkRef, enc EncryptionMeta) error
	ListParts(ctx context.Context, up UploadID) ([]PartInfo, error)
	ListUploads(ctx context.Context, bucketID BucketID) ([]UploadInfo, error)
	CompleteUpload(ctx context.Context, up UploadID) (CommitResult, error)
	AbortUpload(ctx context.Context, up UploadID) error

	// Agents
	Announce(ctx context.Context, a AnnounceRequest) (AnnounceResult, error)
	Heartbeat(ctx context.Context, hb Heartbeat) error
	ReportShardStatus(ctx context.Context, r []ShardStatus) error

	// Repair
	ClaimRepairJob(ctx context.Context, worker string) (*RepairJob, error)
	CommitRepair(ctx context.Context, r RepairResult) error
}

// Grant is one ACL entry. Grantee is a canonical id, an email, or a group name
// ("AllUsers", "AuthenticatedUsers").
type Grant struct {
	Grantee     string `json:"grantee"`
	GranteeType string `json:"grantee_type"` // CanonicalUser | Group | AmazonCustomerByEmail
	Permission  string `json:"permission"`   // READ | WRITE | READ_ACP | WRITE_ACP | FULL_CONTROL
}

type ACL struct {
	OwnerID string  `json:"owner_id"`
	Grants  []Grant `json:"grants"`
}

type UploadInfo struct {
	UploadID UploadID `json:"upload_id"`
	BucketID BucketID `json:"bucket_id"`
	Key      string   `json:"key"`
	// VersionID is the version id the gateway minted at CreateMultipartUpload.
	// UploadPart binds it in the chunk AAD, and CompleteUpload promotes it to the
	// manifest, so parts can never be spliced across object versions.
	VersionID VersionID `json:"version_id"`
	// Encryption is the object-level encryption metadata created with the
	// upload. Every part must be encrypted under this FileKey; a per-part key
	// would make all but one part undecryptable from the committed manifest.
	Encryption   EncryptionMeta `json:"encryption"`
	Initiated    time.Time      `json:"initiated"`
	StorageClass string         `json:"storage_class"`
}

type PartInfo struct {
	PartNumber int            `json:"part_number"`
	ETag       string         `json:"etag"`
	Size       int64          `json:"size"`
	Chunks     []ChunkRef     `json:"chunks"`
	Encryption EncryptionMeta `json:"encryption"`
}

type AnnounceRequest struct {
	PublicKey     []byte `json:"public_key"`
	Secret        string `json:"secret"`
	NodeID        NodeID `json:"node_id"`
	DiskID        string `json:"disk_id"`
	Port          int    `json:"port"`
	CapacityBytes int64  `json:"capacity_bytes"`
	Version       string `json:"version"`
	Hostname      string `json:"hostname"`
}

type AnnounceResult struct {
	AgentID     AgentID  `json:"agent_id"`
	Certificate []byte   `json:"certificate"`
	RingIDs     []RingID `json:"ring_ids"`
	NexusID     NexusID  `json:"nexus_id"`
	State       string   `json:"state"`
}

type Heartbeat struct {
	AgentID AgentID `json:"agent_id"`
	// DiskID is the physical disk UUID the agent bound at first announce. It is
	// reported on every heartbeat so the control plane can reconcile a replaced
	// disk against the agent identity that owns the slot (docs/04 §5.4).
	DiskID          string    `json:"disk_id"`
	FreeBytes       int64     `json:"free_bytes"`
	UsedBytes       int64     `json:"used_bytes"`
	ShardCount      int64     `json:"shard_count"`
	LoadEWMA        float64   `json:"load_ewma"`
	BandwidthBps    int64     `json:"bandwidth_bps"`
	ScrubCursor     string    `json:"scrub_cursor"`
	InventoryDigest string    `json:"inventory_digest"`
	Time            time.Time `json:"time"`
}

type ShardStatus struct {
	AgentID    AgentID    `json:"agent_id"`
	ShardSetID ShardSetID `json:"shard_set_id"`
	Slot       int        `json:"slot"`
	State      string     `json:"state"` // OK | MISSING | CORRUPT
}

type RepairJob struct {
	JobID      string     `json:"job_id"`
	Type       string     `json:"type"` // local | geo | corruption | rebalance
	ShardSetID ShardSetID `json:"shard_set_id"`
	ChunkIndex int        `json:"chunk_index"`
	Generation int        `json:"generation"`
	Params     ec.Params  `json:"params"`
	Sources    []Slot     `json:"sources"`
	Targets    []Slot     `json:"targets"`
	MaxMbps    int        `json:"max_mbps"`
	Deadline   time.Time  `json:"deadline"`
}

type RepairResult struct {
	JobID      string     `json:"job_id"`
	ShardSetID ShardSetID `json:"shard_set_id"`
	Generation int        `json:"generation"`
	OK         bool       `json:"ok"`
	Err        string     `json:"error,omitempty"`
	Checksums  []uint64   `json:"checksums"`
}

// ---------------------------------------------------------------------------
// Agent: the data-plane shard contract
// ---------------------------------------------------------------------------

type PutShardRequest struct {
	ShardSetID ShardSetID `json:"shard_set_id"`
	GeoGroup   int        `json:"geo_group"`
	LocalIndex int        `json:"local_index"`
	Params     ec.Params  `json:"params"`
	ChunkIndex int        `json:"chunk_index"`
	PayloadLen int        `json:"payload_len"`
	Checksum   uint64     `json:"checksum"`
	Body       io.Reader  `json:"body"`
}

type ShardHeader struct {
	ShardSetID ShardSetID `json:"shard_set_id"`
	GeoGroup   int        `json:"geo_group"`
	LocalIndex int        `json:"local_index"`
	Params     ec.Params  `json:"params"`
	ChunkIndex int        `json:"chunk_index"`
	PayloadLen int        `json:"payload_len"`
	// Checksum is BigEndian(SHA-256(shard payload)[:8]).
	Checksum  uint64    `json:"checksum"`
	CreatedAt time.Time `json:"created_at"`
}

type ShardInfo struct {
	ShardSetID ShardSetID `json:"shard_set_id"`
	GeoGroup   int        `json:"geo_group"`
	LocalIndex int        `json:"local_index"`
	Size       int64      `json:"size"`
	Checksum   uint64     `json:"checksum"`
	CreatedAt  time.Time  `json:"created_at"`
}

// AgentClient is how gateways (and repairers) talk to a storage agent.
// (The package is named "contract", so the concrete client lives in
// internal/agent/client and implements this interface.)
type AgentClient interface {
	PutShard(ctx context.Context, endpoint string, req PutShardRequest) error
	GetShard(ctx context.Context, endpoint string, id ShardSetID, group, index int) (io.ReadCloser, ShardInfo, error)
	DeleteShards(ctx context.Context, endpoint string, ids []ShardSetID) error
	HasShards(ctx context.Context, endpoint string, ids []ShardSetID) ([]bool, error)
	Health(ctx context.Context, endpoint string) error
}

// ---------------------------------------------------------------------------
// Errors shared across the boundary
// ---------------------------------------------------------------------------

var (
	ErrNotFound        = errors.New("contract: not found")
	ErrAlreadyExists   = errors.New("contract: already exists")
	ErrConflict        = errors.New("contract: conflict")
	ErrForbidden       = errors.New("contract: forbidden")
	ErrPrecondition    = errors.New("contract: precondition failed")
	ErrNotImplemented  = errors.New("contract: not implemented")
	ErrUnavailable     = errors.New("contract: unavailable")
	ErrInsufficientCap = errors.New("contract: insufficient capacity")
)
