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
	AccessKeyID string
	TenantID    TenantID
	ProjectID   ProjectID
	IsRoot      bool
	Groups      []string // e.g. "AllUsers", "AuthenticatedUsers"
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
	Region    string
	Kind      string // "bucket" | "object" | "project" | "tenant" | "swarm"
	TenantID  TenantID
	ProjectID ProjectID
	Bucket    string
	Key       string
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
	Allowed bool
	Reason  string // deny reason, for audit
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
	Index         int       `json:"index"`
	Params        ec.Params `json:"params"`
	CiphertextLen int       `json:"ciphertext_len"`
	ShardSize     int       `json:"shard_size"`
	Slots         []Slot    `json:"slots"`
	// Checksums[i] is the truncated BLAKE2b-64 of shard i, in slot order.
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
}

// ---------------------------------------------------------------------------
// Placement
// ---------------------------------------------------------------------------

type PlacementRequest struct {
	ShardSetID ShardSetID
	Params     ec.Params
	ChunkBytes int
	TenantID   TenantID
	ProjectID  ProjectID
	RCID       string
	RingID     RingID // optional hint
	// ExcludeAgents removes candidates that already failed for this shard set,
	// implementing the displacement path (docs/03 §4.4).
	ExcludeAgents []AgentID
}

type Placement struct {
	ShardSetID ShardSetID
	RingID     RingID
	Slots      []Slot
	Generation int
}

// ---------------------------------------------------------------------------
// Coordinator: the control-plane contract
// ---------------------------------------------------------------------------

// CommitRequest is the single transactional commit that makes an object visible.
type CommitRequest struct {
	BucketID     BucketID
	Key          string
	Size         int64
	ETag         string
	ChunkSize    int
	Chunks       []ChunkRef
	Encryption   EncryptionMeta
	ContentType  string
	UserMeta     map[string]string
	Tags         map[string]string
	RCID         string
	RingID       RingID
	StorageClass string
	// Conditional write support (deliberate improvement over Cubbit).
	IfMatch     string
	IfNoneMatch string
	Retention   *Retention
}

type Retention struct {
	Mode        string // GOVERNANCE | COMPLIANCE
	RetainUntil time.Time
	LegalHold   bool
}

type CommitResult struct {
	VersionID VersionID
	ETag      string
}

type ListRequest struct {
	BucketID          BucketID
	Prefix            string
	Delimiter         string
	MaxKeys           int
	StartAfter        string
	ContinuationToken string
	Versions          bool
}

type ObjectEntry struct {
	Key            string
	Size           int64
	ETag           string
	LastModified   time.Time
	VersionID      VersionID
	IsLatest       bool
	IsDeleteMarker bool
	CommonPrefix   string
	StorageClass   string
}

type ListResult struct {
	Entries               []ObjectEntry
	IsTruncated           bool
	NextContinuationToken string
	NextKeyMarker         string
	NextVersionIDMarker   string
	KeyCount              int
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
	UploadID     UploadID  `json:"upload_id"`
	BucketID     BucketID  `json:"bucket_id"`
	Key          string    `json:"key"`
	Initiated    time.Time `json:"initiated"`
	StorageClass string    `json:"storage_class"`
}

type PartInfo struct {
	PartNumber int
	ETag       string
	Size       int64
	Chunks     []ChunkRef
	Encryption EncryptionMeta
}

type AnnounceRequest struct {
	PublicKey     []byte
	Secret        string
	NodeID        NodeID
	DiskID        string
	Port          int
	CapacityBytes int64
	Version       string
	Hostname      string
}

type AnnounceResult struct {
	AgentID     AgentID
	Certificate []byte
	RingIDs     []RingID
	NexusID     NexusID
	State       string
}

type Heartbeat struct {
	AgentID         AgentID
	FreeBytes       int64
	UsedBytes       int64
	ShardCount      int64
	LoadEWMA        float64
	BandwidthBps    int64
	ScrubCursor     string
	InventoryDigest string
	Time            time.Time
}

type ShardStatus struct {
	AgentID    AgentID
	ShardSetID ShardSetID
	Slot       int
	State      string // OK | MISSING | CORRUPT
}

type RepairJob struct {
	JobID      string
	Type       string // local | geo | corruption | rebalance
	ShardSetID ShardSetID
	ChunkIndex int
	Generation int
	Params     ec.Params
	Sources    []Slot
	Targets    []Slot
	MaxMbps    int
	Deadline   time.Time
}

type RepairResult struct {
	JobID      string
	ShardSetID ShardSetID
	Generation int
	OK         bool
	Err        string
	Checksums  []uint64
}

// ---------------------------------------------------------------------------
// Agent: the data-plane shard contract
// ---------------------------------------------------------------------------

type PutShardRequest struct {
	ShardSetID ShardSetID
	GeoGroup   int
	LocalIndex int
	Params     ec.Params
	ChunkIndex int
	PayloadLen int
	Checksum   uint64
	Body       io.Reader
}

type ShardHeader struct {
	ShardSetID ShardSetID `json:"shard_set_id"`
	GeoGroup   int        `json:"geo_group"`
	LocalIndex int        `json:"local_index"`
	Params     ec.Params  `json:"params"`
	ChunkIndex int        `json:"chunk_index"`
	PayloadLen int        `json:"payload_len"`
	Checksum   uint64     `json:"checksum"`
	CreatedAt  time.Time  `json:"created_at"`
}

type ShardInfo struct {
	ShardSetID ShardSetID
	GeoGroup   int
	LocalIndex int
	Size       int64
	Checksum   uint64
	CreatedAt  time.Time
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
