// Package gc is the coordinator's deletion-queue executor.
//
// It closes the loop on the durability invariant of docs/02 §5.1: metadata is the
// only source of truth, so once a version is tombstoned and its grace period has
// elapsed, the shards it referenced are unreferenced garbage and must be
// collected. Until this loop runs, an overwrite doubles raw usage and the
// reported storage ratio is wrong (docs/03 §6).
//
// The executor is deliberately narrow and crash-safe:
//
//  1. Drain due entries from the deletion queue (metadata-first; the entry stays
//     until every write has been acknowledged).
//  2. Load the tombstoned version's content-addressed chunk table.
//  3. Derive each chunk's shard-set id, group the ids by agent endpoint.
//  4. Call DeleteShards per endpoint (DELETE is idempotent; a missing set is not
//     an error), then CompleteDeletion.
//
// A failed endpoint leaves the whole entry queued for the next tick. Deleting
// some shards twice is safe (shards are immutable and addressed by set id), so a
// crash between steps 4 and CompleteDeletion only costs a retry.
package gc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync/atomic"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/coord/meta"
)

// Defaults for the background loop.
const (
	DefaultInterval = time.Minute
	DefaultBatch    = 100
)

// ShardDeleter is the subset of contract.AgentClient the collector needs.
type ShardDeleter interface {
	DeleteShards(ctx context.Context, endpoint string, ids []contract.ShardSetID) error
}

// SetIDFunc derives the shard-set id for one chunk of one object version.
type SetIDFunc func(bucketID contract.BucketID, key string, versionID contract.VersionID, chunkIndex int) contract.ShardSetID

// Config configures the executor.
type Config struct {
	// Interval between passes (default 1 minute).
	Interval time.Duration
	// Batch is the maximum number of deletion entries per pass (default 100).
	Batch int
	// Now overrides the clock (tests).
	Now func() time.Time
	// Logger defaults to slog.Default().
	Logger *slog.Logger
	// SetID defaults to ShardSetIDFor.
	SetID SetIDFunc
}

func (c Config) withDefaults() Config {
	if c.Interval <= 0 {
		c.Interval = DefaultInterval
	}
	if c.Batch <= 0 {
		c.Batch = DefaultBatch
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.SetID == nil {
		c.SetID = contract.ShardSetIDFor
	}
	return c
}

// Result reports what one pass did.
type Result struct {
	Examined      int // due entries inspected
	Completed     int // entries fully collected and removed
	Failed        int // entries left queued because at least one endpoint failed
	Sets          int // shard-set deletes acknowledged
	Endpoints     int // agent endpoints contacted successfully
	ZeroByte      int // tombstoned objects with no shards (nothing to collect)
	ReplaySkipped int // endpoints already acknowledged by an earlier pass
}

// Executor drains the deletion queue. It is safe to call RunOnce concurrently
// with itself (entries are not claimed; idempotent deletes absorb double work),
// but the coordinator runs a single loop.
type Executor struct {
	meta    *meta.Service
	deleter ShardDeleter
	cfg     Config

	completed       atomic.Int64
	failed          atomic.Int64
	setsDeleted     atomic.Int64
	endpointsCalled atomic.Int64
	lastRunUnix     atomic.Int64
}

// New creates the executor.
func New(m *meta.Service, deleter ShardDeleter, cfg Config) *Executor {
	return &Executor{meta: m, deleter: deleter, cfg: cfg.withDefaults()}
}

// Run drives RunOnce until ctx is cancelled. It runs one pass immediately so a
// restarted coordinator resumes GC without waiting for the first tick.
func (e *Executor) Run(ctx context.Context) {
	ticker := time.NewTicker(e.cfg.Interval)
	defer ticker.Stop()
	for {
		if _, err := e.RunOnce(ctx, e.cfg.Now()); err != nil && !errors.Is(err, context.Canceled) {
			e.cfg.Logger.Warn("deletion GC pass failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// RunOnce executes one GC pass. Per-entry failures are counted in Result and do
// not abort the pass; the returned error is reserved for store-level failures.
func (e *Executor) RunOnce(ctx context.Context, now time.Time) (Result, error) {
	var res Result
	items, err := e.meta.DrainDeletions(ctx, now, e.cfg.Batch)
	if err != nil {
		return res, fmt.Errorf("gc: drain deletion queue: %w", err)
	}
	for _, item := range items {
		res.Examined++
		// Persist the in-progress marker and read any acknowledgements from an
		// earlier pass. A crash between an agent acknowledgement and the final
		// queue removal therefore replays only the endpoints that were not yet
		// acknowledged — the replay path is provably cheap.
		progress, err := e.meta.BeginDeletion(ctx, item.ID, now)
		if err != nil {
			res.Failed++
			e.failed.Add(1)
			e.cfg.Logger.Warn("deletion GC could not begin entry; will retry", "deletion_id", item.ID, "err", err)
			continue
		}
		zeroByte, err := e.process(ctx, progress, now, &res)
		if err != nil {
			res.Failed++
			e.failed.Add(1)
			e.cfg.Logger.Warn("deletion GC entry failed; will retry",
				"deletion_id", item.ID, "bucket_id", item.BucketID, "key", item.Key,
				"version_id", item.VersionID, "err", err)
			continue
		}
		if err := e.meta.CompleteDeletion(ctx, item.ID); err != nil {
			res.Failed++
			e.failed.Add(1)
			e.cfg.Logger.Warn("deletion GC could not clear queue entry; will retry", "deletion_id", item.ID, "err", err)
			continue
		}
		if zeroByte {
			res.ZeroByte++
		}
		res.Completed++
		e.completed.Add(1)
	}
	e.lastRunUnix.Store(now.Unix())
	return res, nil
}

// process deletes every shard referenced by one tombstoned version. Progress is
// checkpointed per agent endpoint, so a retry after a partial failure or a crash
// only re-contacts endpoints that have not acknowledged yet.
func (e *Executor) process(ctx context.Context, item meta.DeletionItem, now time.Time, res *Result) (zeroByte bool, err error) {
	if item.ManifestHash == "" {
		// Zero-byte object: metadata only, nothing to collect.
		return true, nil
	}
	chunks, err := e.meta.ChunkTable(ctx, item.ManifestHash)
	if err != nil {
		return false, fmt.Errorf("load chunk table: %w", err)
	}
	if len(chunks) == 0 {
		return true, nil
	}

	// Group shard-set ids by the agent endpoint that stores the corresponding
	// slot. One endpoint can hold slots from several geo groups, so each set id
	// appears once per endpoint that owns part of it.
	perEndpoint := make(map[string][]contract.ShardSetID)
	for _, chunk := range chunks {
		setID := e.cfg.SetID(item.BucketID, item.Key, item.VersionID, chunk.Index)
		for slotIndex, slot := range chunk.Slots {
			if slot.Endpoint == "" {
				return false, fmt.Errorf("chunk %d slot %d has no endpoint", chunk.Index, slotIndex)
			}
			perEndpoint[slot.Endpoint] = append(perEndpoint[slot.Endpoint], setID)
		}
	}
	if len(perEndpoint) == 0 {
		return true, nil
	}
	endpoints := make([]string, 0, len(perEndpoint))
	for ep := range perEndpoint {
		endpoints = append(endpoints, ep)
	}
	sort.Strings(endpoints) // deterministic pass order and log output

	acked := make(map[string]bool, len(item.AckedEndpoints))
	for _, ep := range item.AckedEndpoints {
		acked[ep] = true
	}

	var errs []error
	for _, ep := range endpoints {
		if acked[ep] {
			res.ReplaySkipped++
			continue
		}
		ids := dedupe(perEndpoint[ep])
		if err := e.deleter.DeleteShards(ctx, ep, ids); err != nil {
			errs = append(errs, fmt.Errorf("endpoint %s: %w", ep, err))
			continue
		}
		// Checkpoint before moving on: if this write fails the endpoint is simply
		// retried (DELETE is idempotent).
		if err := e.meta.AckDeletionEndpoint(ctx, item.ID, ep); err != nil {
			errs = append(errs, fmt.Errorf("record ack for endpoint %s: %w", ep, err))
			continue
		}
		res.Sets += len(ids)
		res.Endpoints++
		e.setsDeleted.Add(int64(len(ids)))
		e.endpointsCalled.Add(1)
	}
	if len(errs) > 0 {
		return false, errors.Join(errs...)
	}
	return false, nil
}

// Stats returns the GC counters for the /metrics handler.
func (e *Executor) Stats() map[string]int64 {
	return map[string]int64{
		"items_completed_total":      e.completed.Load(),
		"items_failed_total":         e.failed.Load(),
		"sets_deleted_total":         e.setsDeleted.Load(),
		"endpoints_called_total":     e.endpointsCalled.Load(),
		"last_run_timestamp_seconds": e.lastRunUnix.Load(),
	}
}

func dedupe(ids []contract.ShardSetID) []contract.ShardSetID {
	if len(ids) < 2 {
		return ids
	}
	seen := make(map[contract.ShardSetID]bool, len(ids))
	out := ids[:0]
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}
