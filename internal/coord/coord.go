// Package coord wires the coordinator's sub-services into the single
// contract.Coordinator implementation the gateway and agents talk to.
//
// It contains almost no logic of its own: metadata lives in meta, identity in
// auth, topology and health in membership, and the placement decision in
// placement. The two things it does own are the tenant geo-fence lookup (a
// placement input that is tenant metadata) and lifecycle of the store.
package coord

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/coord/auth"
	"github.com/fass-storage/fass/internal/coord/coerr"
	"github.com/fass-storage/fass/internal/coord/membership"
	"github.com/fass-storage/fass/internal/coord/meta"
	"github.com/fass-storage/fass/internal/coord/placement"
	"github.com/fass-storage/fass/internal/storage"
)

// Config configures the coordinator service.
type Config struct {
	// Maintenance makes announce return 503 "under maintenance".
	Maintenance bool
	// Membership carries heartbeat/health timings.
	Membership membership.Config
	// Placement carries the documented placement knobs.
	Placement placement.Config
	// Now overrides the clock in every sub-service (tests).
	Now func() time.Time
	// Logger receives background-worker logs; defaults to slog.Default().
	Logger *slog.Logger
}

// Service is the coordinator: it implements contract.Coordinator.
type Service struct {
	DB      *storage.DB
	Meta    *meta.Service
	Auth    *auth.Service
	Members *membership.Service
	Place   *placement.Engine
	Logger  *slog.Logger
	now     func() time.Time
	ownsDB  bool
}

var _ contract.Coordinator = (*Service)(nil)

// New wires a coordinator over an already-open store. The caller owns the DB.
func New(db *storage.DB, cfg Config) *Service {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	m := meta.New(db)
	m.SetClock(now)
	memCfg := cfg.Membership
	if memCfg.Now == nil {
		memCfg.Now = now
	}
	memCfg.Maintenance = memCfg.Maintenance || cfg.Maintenance
	mem := membership.New(db, memCfg)
	a := auth.New(db, m)
	a.SetClock(now)
	plCfg := cfg.Placement
	if plCfg.Now == nil {
		plCfg.Now = now
	}
	return &Service{
		DB:      db,
		Meta:    m,
		Auth:    a,
		Members: mem,
		Place:   placement.New(plCfg),
		Logger:  logger,
		now:     now,
	}
}

// Open opens (or creates) a coordinator data directory, applies migrations and
// returns a ready service. An empty dataDir selects the in-memory store (tests).
func Open(ctx context.Context, dataDir string, cfg Config) (*Service, error) {
	db, err := storage.Open(dataDir)
	if err != nil {
		return nil, err
	}
	if err := storage.Migrate(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	svc := New(db, cfg)
	svc.ownsDB = true
	return svc, nil
}

// Close releases the store.
func (s *Service) Close() error {
	if s == nil || s.DB == nil || !s.ownsDB {
		return nil
	}
	return s.DB.Close()
}

// SetMaintenance toggles the announce maintenance response.
func (s *Service) SetMaintenance(on bool) { s.Members.SetMaintenance(on) }

// RunMaintenance runs the coordinator's background loops until ctx is cancelled:
// the membership health sweep and a deletion-queue observation loop. The GC
// executor itself is owned by the recovery service (not part of this slice), so
// this loop only reports backlog; it never drops a queue entry without deleting
// the shards.
func (s *Service) RunMaintenance(ctx context.Context) {
	interval := s.Members.Config().HeartbeatInterval
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	gcTicker := time.NewTicker(time.Minute)
	defer gcTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			suspect, offline, err := s.Members.Sweep(ctx)
			if err != nil {
				s.Logger.Warn("membership sweep failed", "err", err)
				continue
			}
			if suspect > 0 || offline > 0 {
				s.Logger.Info("agent health changed", "suspect", suspect, "offline", offline)
			}
		case <-gcTicker.C:
			backlog, err := s.Meta.DeletionBacklog(ctx)
			if err != nil {
				s.Logger.Warn("deletion backlog check failed", "err", err)
				continue
			}
			if backlog > 0 {
				s.Logger.Info("deletion queue depth", "pending", backlog)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// contract.Coordinator: authorisation
// ---------------------------------------------------------------------------

// Authorize delegates to the auth service.
func (s *Service) Authorize(ctx context.Context, rc contract.RequestContext) (contract.Decision, error) {
	return s.Auth.Authorize(ctx, rc)
}

// VerifySignature delegates to the auth service.
func (s *Service) VerifySignature(ctx context.Context, accessKeyID string) (contract.Principal, []byte, error) {
	return s.Auth.VerifySignature(ctx, accessKeyID)
}

// ---------------------------------------------------------------------------
// contract.Coordinator: buckets and sub-resources
// ---------------------------------------------------------------------------

func (s *Service) GetBucket(ctx context.Context, bucket string) (contract.BucketConfig, error) {
	return s.Meta.GetBucket(ctx, bucket)
}

func (s *Service) CreateBucket(ctx context.Context, b contract.BucketConfig) error {
	return s.Meta.CreateBucket(ctx, b)
}

func (s *Service) UpdateBucketConfig(ctx context.Context, b contract.BucketConfig) error {
	return s.Meta.UpdateBucket(ctx, b)
}

func (s *Service) DeleteBucket(ctx context.Context, bucket string) error {
	return s.Meta.DeleteBucket(ctx, bucket)
}

func (s *Service) ListBuckets(ctx context.Context, p contract.Principal) ([]contract.BucketConfig, error) {
	return s.Meta.ListBuckets(ctx, p)
}

func (s *Service) GetBucketACL(ctx context.Context, bucket string) (contract.ACL, error) {
	return s.Meta.GetBucketACL(ctx, bucket)
}

func (s *Service) PutBucketACL(ctx context.Context, bucket string, acl contract.ACL) error {
	return s.Meta.PutBucketACL(ctx, bucket, acl)
}

func (s *Service) GetBucketLifecycle(ctx context.Context, bucket string) ([]byte, error) {
	return s.Meta.GetBucketLifecycle(ctx, bucket)
}

func (s *Service) PutBucketLifecycle(ctx context.Context, bucket string, xml []byte) error {
	return s.Meta.PutBucketLifecycle(ctx, bucket, xml)
}

func (s *Service) DeleteBucketLifecycle(ctx context.Context, bucket string) error {
	return s.Meta.DeleteBucketLifecycle(ctx, bucket)
}

func (s *Service) GetObjectTags(ctx context.Context, bucket, key string, v contract.VersionID) (map[string]string, error) {
	return s.Meta.GetObjectTags(ctx, bucket, key, v)
}

func (s *Service) PutObjectTags(ctx context.Context, bucket, key string, v contract.VersionID, tags map[string]string) error {
	return s.Meta.PutObjectTags(ctx, bucket, key, v, tags)
}

func (s *Service) GetObjectRetention(ctx context.Context, bucket, key string, v contract.VersionID) (*contract.Retention, error) {
	return s.Meta.GetObjectRetention(ctx, bucket, key, v)
}

func (s *Service) PutObjectRetention(ctx context.Context, bucket, key string, v contract.VersionID, r *contract.Retention) error {
	return s.Meta.PutObjectRetention(ctx, bucket, key, v, r)
}

func (s *Service) GetObjectACL(ctx context.Context, bucket, key string, v contract.VersionID) (contract.ACL, error) {
	return s.Meta.GetObjectACL(ctx, bucket, key, v)
}

func (s *Service) PutObjectACL(ctx context.Context, bucket, key string, v contract.VersionID, acl contract.ACL) error {
	return s.Meta.PutObjectACL(ctx, bucket, key, v, acl)
}

// ---------------------------------------------------------------------------
// contract.Coordinator: placement, objects, multipart
// ---------------------------------------------------------------------------

// ResolvePlacement resolves the tenant geo-fence and delegates the decision to
// the pure placement engine.
func (s *Service) ResolvePlacement(ctx context.Context, req contract.PlacementRequest) (contract.Placement, error) {
	fence := map[string][]contract.NexusID{}
	if req.TenantID != "" {
		t, err := s.Meta.GetTenant(ctx, req.TenantID)
		switch {
		case err == nil:
			if len(t.GeoFence) > 0 {
				fence[string(t.ID)] = t.GeoFence
			}
		case errors.Is(err, coerr.ErrNotFound) || coerr.CodeOf(err) == "NoSuchTenant":
			// No tenant record means no fence; the RC still bounds the Nexuses.
		default:
			return contract.Placement{}, err
		}
	}
	snap, err := s.Members.Snapshot(ctx, fence)
	if err != nil {
		return contract.Placement{}, err
	}
	return s.Place.Place(ctx, req, snap)
}

func (s *Service) CommitObject(ctx context.Context, req contract.CommitRequest) (contract.CommitResult, error) {
	res, err := s.Meta.CommitObject(ctx, req)
	if err != nil {
		return res, err
	}
	// Account the raw shard bytes to the ring so the ring_full_pct placement gate
	// reflects real occupancy (docs/03 §4.6). Reclamation on delete/GC belongs to
	// the usage/GC services; a stale counter only loosens or tightens placement,
	// never corrupts data, so a failure here is logged rather than failing the
	// already-durable commit.
	if req.RingID != "" {
		var stored int64
		for _, c := range req.Chunks {
			stored += int64(len(c.Slots)) * int64(c.ShardSize)
		}
		if stored > 0 {
			if err := s.Members.AddRingUsage(ctx, req.RingID, stored); err != nil {
				s.Logger.Warn("ring usage accounting failed", "ring_id", req.RingID, "bytes", stored, "err", err)
			}
		}
	}
	return res, nil
}

func (s *Service) GetManifest(ctx context.Context, bucket, key string, version contract.VersionID) (contract.Manifest, error) {
	return s.Meta.GetManifest(ctx, bucket, key, version)
}

func (s *Service) DeleteObject(ctx context.Context, bucket, key string, version contract.VersionID, bypassGovernance bool) (contract.VersionID, bool, error) {
	return s.Meta.DeleteObject(ctx, bucket, key, version, bypassGovernance)
}

func (s *Service) ListObjects(ctx context.Context, req contract.ListRequest) (contract.ListResult, error) {
	return s.Meta.ListObjects(ctx, req)
}

func (s *Service) CreateUpload(ctx context.Context, bucket, key string, m contract.CommitRequest) (contract.UploadID, error) {
	return s.Meta.CreateUpload(ctx, bucket, key, m)
}

func (s *Service) CommitPart(ctx context.Context, up contract.UploadID, partNumber int, etag string, size int64, chunks []contract.ChunkRef, enc contract.EncryptionMeta) error {
	return s.Meta.CommitPart(ctx, up, partNumber, etag, size, chunks, enc)
}

func (s *Service) ListParts(ctx context.Context, up contract.UploadID) ([]contract.PartInfo, error) {
	return s.Meta.ListParts(ctx, up)
}

func (s *Service) ListUploads(ctx context.Context, bucketID contract.BucketID) ([]contract.UploadInfo, error) {
	return s.Meta.ListUploads(ctx, bucketID)
}

func (s *Service) CompleteUpload(ctx context.Context, up contract.UploadID) (contract.CommitResult, error) {
	return s.Meta.CompleteUpload(ctx, up)
}

func (s *Service) AbortUpload(ctx context.Context, up contract.UploadID) error {
	return s.Meta.AbortUpload(ctx, up)
}

// ---------------------------------------------------------------------------
// contract.Coordinator: agents and repair
// ---------------------------------------------------------------------------

func (s *Service) Announce(ctx context.Context, a contract.AnnounceRequest) (contract.AnnounceResult, error) {
	return s.Members.Announce(ctx, a)
}

func (s *Service) Heartbeat(ctx context.Context, hb contract.Heartbeat) error {
	return s.Members.Heartbeat(ctx, hb)
}

func (s *Service) ReportShardStatus(ctx context.Context, r []contract.ShardStatus) error {
	return s.Members.RecordShardStatus(ctx, r)
}

// ClaimRepairJob returns no work: the recovery orchestrator (docs/04 §5.5) is a
// separate deliverable. The endpoint exists and is well-formed so agent repair
// workers can poll without special-casing the dev server.
func (s *Service) ClaimRepairJob(ctx context.Context, worker string) (*contract.RepairJob, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, nil
}

// CommitRepair acknowledges a repair result. No jobs are produced in this slice,
// so a commit is a no-op that validates its shape.
func (s *Service) CommitRepair(ctx context.Context, r contract.RepairResult) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.JobID == "" {
		return coerr.Invalidf("job_id is required")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Topology / admin surface (used by the REST layer and the console)
// ---------------------------------------------------------------------------

// Topology returns the full topology snapshot including every tenant's geo-fence.
func (s *Service) Topology(ctx context.Context) (membership.Snapshot, error) {
	fence := map[string][]contract.NexusID{}
	tenants, err := s.Meta.ListTenants(ctx)
	if err != nil {
		return membership.Snapshot{}, err
	}
	for _, t := range tenants {
		if len(t.GeoFence) > 0 {
			fence[string(t.ID)] = t.GeoFence
		}
	}
	return s.Members.Snapshot(ctx, fence)
}

// Health is the /v1/healthz body.
func (s *Service) Health(ctx context.Context) (map[string]any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	version, err := storage.SchemaVersionOf(ctx, s.DB)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"status":         "ok",
		"schema_version": version,
		"time":           s.now().UTC().Format(time.RFC3339),
	}, nil
}
