// Package repair executes repair jobs for a FASS agent.
//
// A repair job arrives from the coordinator (docs/07-wire-api.md §1.6). The
// worker fetches surviving shards from peer agents over HTTP, reconstructs the
// missing shards with Reed–Solomon, writes them to the target agents, and
// reports the outcome. Because FASS is encrypt-then-code, every byte handled
// here is ciphertext: the worker needs no key and must never import key
// material (docs/03-data-plane.md §5.3).
package repair

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/fass-storage/fass/internal/agent/client"
	"github.com/fass-storage/fass/internal/agent/shard"
	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/ec"
	"github.com/klauspost/reedsolomon"
)

// Sentinel configuration errors.
var (
	ErrInvalidJob       = errors.New("repair: invalid job")
	ErrTooFewSources    = errors.New("repair: not enough source shards")
	ErrInconsistentSize = errors.New("repair: source shards have inconsistent sizes")
	ErrNoTargets        = errors.New("repair: job has no targets")
)

// Coordinator is the control-plane surface the repair worker needs. It is
// satisfied by coordclient.Client.
type Coordinator interface {
	ClaimRepairJob(ctx context.Context, worker string) (*contract.RepairJob, error)
	CommitRepair(ctx context.Context, r contract.RepairResult) error
}

// Options configures an Executor.
type Options struct {
	// Client is the agent shard transport client (required).
	Client *client.Client
	// Coordinator claims and commits repair jobs (required for Run; optional
	// when only Execute is used).
	Coordinator Coordinator
	// Worker is the identity sent with ClaimRepairJob.
	Worker string
	// Workers is the number of concurrent claim loops in Run (default 1).
	Workers int
	// FetchConcurrency bounds parallel shard GETs per job (default 8).
	FetchConcurrency int
	// RetryBackoff is the initial idle/error backoff (default 1s, capped 30s).
	RetryBackoff time.Duration
	// Logger defaults to slog.Default().
	Logger *slog.Logger
	// Now is a test hook for deadlines.
	Now func() time.Time
}

// Executor runs repair jobs.
type Executor struct {
	client    *client.Client
	coord     Coordinator
	worker    string
	workers   int
	fetchConc int
	backoff   time.Duration
	log       *slog.Logger
	now       func() time.Time
}

// New validates options and returns an Executor.
func New(opts Options) (*Executor, error) {
	if opts.Client == nil {
		return nil, errors.New("repair: nil agent client")
	}
	if opts.Workers <= 0 {
		opts.Workers = 1
	}
	if opts.FetchConcurrency <= 0 {
		opts.FetchConcurrency = 8
	}
	if opts.RetryBackoff <= 0 {
		opts.RetryBackoff = time.Second
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	worker := opts.Worker
	if worker == "" {
		worker = "agent"
	}
	return &Executor{
		client:    opts.Client,
		coord:     opts.Coordinator,
		worker:    worker,
		workers:   opts.Workers,
		fetchConc: opts.FetchConcurrency,
		backoff:   opts.RetryBackoff,
		log:       opts.Logger.With("component", "repair", "worker", worker),
		now:       opts.Now,
	}, nil
}

// Run starts Workers claim loops and blocks until ctx is cancelled.
func (e *Executor) Run(ctx context.Context) error {
	if e.coord == nil {
		return errors.New("repair: Run requires a Coordinator")
	}
	var wg sync.WaitGroup
	for i := 0; i < e.workers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			e.workerLoop(ctx, n)
		}(i)
	}
	<-ctx.Done()
	wg.Wait()
	return nil
}

// workerLoop claims and executes jobs until the context is done.
func (e *Executor) workerLoop(ctx context.Context, n int) {
	backoff := e.backoff
	const maxBackoff = 30 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		worked, err := e.RunOnce(ctx)
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return
			}
			e.log.Warn("repair claim loop error", "worker_index", n, "err", err, "retry_in", backoff)
		case worked:
			backoff = e.backoff
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// RunOnce claims at most one job, executes it and commits the result. It
// returns false when the coordinator has no work. A lost generation CAS on
// commit is not an error: the written shards are immutable orphans for GC.
func (e *Executor) RunOnce(ctx context.Context) (bool, error) {
	job, err := e.coord.ClaimRepairJob(ctx, e.worker)
	if err != nil {
		return false, err
	}
	if job == nil {
		return false, nil
	}
	res := e.Execute(ctx, job)
	if err := e.coord.CommitRepair(ctx, res); err != nil {
		if errors.Is(err, contract.ErrConflict) {
			e.log.Warn("repair lost the generation CAS race; written shards are GC orphans",
				"job_id", job.JobID, "shard_set_id", job.ShardSetID, "generation", job.Generation)
			return true, nil
		}
		return true, err
	}
	return true, nil
}

// Execute runs one repair job and returns the result to report. It never
// panics: any failure is folded into RepairResult.OK/Err.
func (e *Executor) Execute(ctx context.Context, job *contract.RepairJob) (res contract.RepairResult) {
	res = contract.RepairResult{
		JobID:      job.JobID,
		ShardSetID: job.ShardSetID,
		Generation: job.Generation,
	}
	defer func() {
		if rec := recover(); rec != nil {
			res.OK = false
			res.Err = fmt.Sprintf("panic: %v", rec)
			e.log.Error("repair job panicked", "job_id", job.JobID, "panic", rec)
		}
	}()

	jobCtx := ctx
	if !job.Deadline.IsZero() {
		var cancel context.CancelFunc
		jobCtx, cancel = context.WithDeadline(ctx, job.Deadline)
		defer cancel()
	}

	start := e.now()
	checksums, err := e.execute(jobCtx, job)
	if err != nil {
		res.OK = false
		res.Err = err.Error()
		e.log.Warn("repair job failed", "job_id", job.JobID, "type", job.Type,
			"shard_set_id", job.ShardSetID, "err", err)
		return res
	}
	res.OK = true
	res.Checksums = checksums
	e.log.Info("repair job completed", "job_id", job.JobID, "type", job.Type,
		"shard_set_id", job.ShardSetID, "generation", job.Generation,
		"targets", len(job.Targets), "duration_ms", e.now().Sub(start).Milliseconds())
	return res
}

func (e *Executor) execute(ctx context.Context, job *contract.RepairJob) ([]uint64, error) {
	if job == nil {
		return nil, fmt.Errorf("%w: nil job", ErrInvalidJob)
	}
	if len(job.Targets) == 0 {
		return nil, ErrNoTargets
	}
	if len(job.Sources) == 0 {
		return nil, fmt.Errorf("%w: no sources", ErrInvalidJob)
	}
	if err := job.Params.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidJob, err)
	}
	switch job.Type {
	case "rebalance":
		return e.rebalance(ctx, job)
	case "geo":
		return e.geoRepair(ctx, job)
	case "local", "corruption", "":
		if sameGeoGroup(job.Sources) && sameGeoGroup(job.Targets) {
			return e.localRepair(ctx, job)
		}
		return e.geoRepair(ctx, job)
	default:
		return nil, fmt.Errorf("%w: unknown job type %q", ErrInvalidJob, job.Type)
	}
}

// slotKey identifies one shard within a chunk.
type slotKey struct {
	group int
	index int
}

func keyOf(s contract.Slot) slotKey { return slotKey{group: s.GeoGroup, index: s.LocalIndex} }

func sameGeoGroup(slots []contract.Slot) bool {
	for i := 1; i < len(slots); i++ {
		if slots[i].GeoGroup != slots[0].GeoGroup {
			return false
		}
	}
	return true
}

// localRepair reconstructs missing shards inside one geo group using the inner
// RS(local_n, local_k) code. It runs entirely on ciphertext.
func (e *Executor) localRepair(ctx context.Context, job *contract.RepairJob) ([]uint64, error) {
	params := job.Params
	if params.LocalK == 0 {
		return nil, fmt.Errorf("%w: local repair needs local_k > 0", ErrInvalidJob)
	}
	group := job.Sources[0].GeoGroup
	for _, s := range job.Sources {
		if s.GeoGroup != group {
			return nil, fmt.Errorf("%w: source slot %d is outside geo group %d", ErrInvalidJob, s.LocalIndex, group)
		}
	}
	for _, t := range job.Targets {
		if t.GeoGroup != group {
			return nil, fmt.Errorf("%w: target slot %d is outside geo group %d", ErrInvalidJob, t.LocalIndex, group)
		}
	}

	fetched, fetchErrs := e.fetch(ctx, job, job.Sources)
	if len(fetchErrs) > 0 {
		e.log.Warn("some source shards could not be fetched", "job_id", job.JobID, "failures", len(fetchErrs), "err", fetchErrs[0])
	}

	groupShards := make([][]byte, params.ShardsPerGroup())
	shardSize := -1
	for _, s := range job.Sources {
		payload, ok := fetched[keyOf(s)]
		if !ok {
			continue
		}
		if s.LocalIndex < 0 || s.LocalIndex >= params.ShardsPerGroup() {
			continue
		}
		if shardSize < 0 {
			shardSize = len(payload)
		} else if len(payload) != shardSize {
			return nil, fmt.Errorf("%w: %d vs %d bytes", ErrInconsistentSize, len(payload), shardSize)
		}
		groupShards[s.LocalIndex] = payload
	}
	if shardSize <= 0 {
		return nil, fmt.Errorf("%w: no usable source shards", ErrTooFewSources)
	}
	have := 0
	for _, s := range groupShards {
		if s != nil {
			have++
		}
	}
	if have < params.LocalN {
		return nil, fmt.Errorf("%w: have %d of local_n=%d in group %d", ErrTooFewSources, have, params.LocalN, group)
	}

	enc, err := reedsolomon.New(params.LocalN, params.LocalK)
	if err != nil {
		return nil, fmt.Errorf("repair: inner codec: %w", err)
	}
	if err := enc.Reconstruct(groupShards); err != nil {
		return nil, fmt.Errorf("repair: inner reconstruct: %w", err)
	}
	// Re-encode to make parity deterministic even when it was reconstructed.
	if err := enc.Encode(groupShards); err != nil {
		return nil, fmt.Errorf("repair: inner encode: %w", err)
	}

	targets := make(map[slotKey][]byte, len(job.Targets))
	for _, t := range job.Targets {
		if t.LocalIndex < 0 || t.LocalIndex >= params.ShardsPerGroup() {
			return nil, fmt.Errorf("%w: target local_index %d out of range", ErrInvalidJob, t.LocalIndex)
		}
		if groupShards[t.LocalIndex] == nil {
			return nil, fmt.Errorf("%w: could not reconstruct target slot %d", ErrTooFewSources, t.LocalIndex)
		}
		targets[keyOf(t)] = groupShards[t.LocalIndex]
	}
	return e.writeTargets(ctx, job, targets)
}

// geoRepair reconstructs a whole lost geo group: it needs geo_n groups' worth of
// local shards, decodes the chunk, re-encodes it and writes the replacement
// shards. It runs entirely on ciphertext.
func (e *Executor) geoRepair(ctx context.Context, job *contract.RepairJob) ([]uint64, error) {
	params := job.Params
	fetched, fetchErrs := e.fetch(ctx, job, job.Sources)
	if len(fetchErrs) > 0 {
		e.log.Warn("some source shards could not be fetched", "job_id", job.JobID, "failures", len(fetchErrs), "err", fetchErrs[0])
	}

	shardSize := -1
	for _, payload := range fetched {
		if shardSize < 0 {
			shardSize = len(payload)
		} else if len(payload) != shardSize {
			return nil, fmt.Errorf("%w: %d vs %d bytes", ErrInconsistentSize, len(payload), shardSize)
		}
	}
	if shardSize <= 0 {
		return nil, fmt.Errorf("%w: no usable source shards", ErrTooFewSources)
	}

	codec, err := ec.New(params)
	if err != nil {
		return nil, fmt.Errorf("repair: codec: %w", err)
	}
	shards := make([][]byte, params.TotalShards())
	groupSize := params.ShardsPerGroup()
	for key, payload := range fetched {
		if key.group < 0 || key.group >= params.GeoN+params.GeoK {
			continue
		}
		if key.index < 0 || key.index >= groupSize {
			continue
		}
		shards[key.group*groupSize+key.index] = payload
	}

	// We do not know the object's original ciphertext length, but we do not need
	// it: decode the full padded payload, then re-encode it with the same shard
	// size, which reproduces every shard bit-for-bit.
	fullLen := shardSize * params.GeoN * params.LocalN
	geom := codec.Geometry(fullLen)
	decoded, err := codec.Decode(shards, geom)
	if err != nil {
		return nil, fmt.Errorf("repair: decode chunk: %w", err)
	}
	reencoded, newGeom, err := codec.Encode(decoded)
	if err != nil {
		return nil, fmt.Errorf("repair: re-encode chunk: %w", err)
	}
	if newGeom.ShardSize != shardSize {
		return nil, fmt.Errorf("repair: re-encoded shard size %d, want %d", newGeom.ShardSize, shardSize)
	}

	targets := make(map[slotKey][]byte, len(job.Targets))
	for _, t := range job.Targets {
		if t.GeoGroup < 0 || t.GeoGroup >= params.GeoN+params.GeoK ||
			t.LocalIndex < 0 || t.LocalIndex >= groupSize {
			return nil, fmt.Errorf("%w: target slot %d/%d out of range", ErrInvalidJob, t.GeoGroup, t.LocalIndex)
		}
		idx := t.GeoGroup*groupSize + t.LocalIndex
		targets[keyOf(t)] = reencoded[idx]
	}
	return e.writeTargets(ctx, job, targets)
}

// rebalance copies existing shard bytes to new agents: no decode, no encode, no
// key (docs/03 §6).
func (e *Executor) rebalance(ctx context.Context, job *contract.RepairJob) ([]uint64, error) {
	if len(job.Sources) != len(job.Targets) {
		return nil, fmt.Errorf("%w: rebalance needs one source per target (%d vs %d)",
			ErrInvalidJob, len(job.Sources), len(job.Targets))
	}
	// Fetch only the paired sources.
	fetched, fetchErrs := e.fetch(ctx, job, job.Sources)
	if len(fetchErrs) > 0 {
		return nil, fmt.Errorf("%w: %d source shard(s) unavailable: %v", ErrTooFewSources, len(fetchErrs), fetchErrs[0])
	}
	targets := make(map[slotKey][]byte, len(job.Targets))
	for i, t := range job.Targets {
		payload, ok := fetched[keyOf(job.Sources[i])]
		if !ok {
			return nil, fmt.Errorf("%w: source slot %d/%d unavailable",
				ErrTooFewSources, job.Sources[i].GeoGroup, job.Sources[i].LocalIndex)
		}
		targets[keyOf(t)] = payload
	}
	return e.writeTargets(ctx, job, targets)
}

// fetch downloads source shards with bounded concurrency. Individual failures
// are returned (not fatal) because a repair can still succeed with quorum.
func (e *Executor) fetch(ctx context.Context, job *contract.RepairJob, sources []contract.Slot) (map[slotKey][]byte, []error) {
	out := make(map[slotKey][]byte, len(sources))
	var mu sync.Mutex
	var errs []error

	sem := make(chan struct{}, e.fetchConc)
	var wg sync.WaitGroup
	for _, slot := range sources {
		slot := slot
		if slot.Endpoint == "" {
			mu.Lock()
			errs = append(errs, fmt.Errorf("source slot %d/%d has no endpoint", slot.GeoGroup, slot.LocalIndex))
			mu.Unlock()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				mu.Lock()
				errs = append(errs, ctx.Err())
				mu.Unlock()
				return
			}
			defer func() { <-sem }()

			rc, _, err := e.client.GetShard(ctx, slot.Endpoint, job.ShardSetID, slot.GeoGroup, slot.LocalIndex)
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("get %d/%d from %s: %w", slot.GeoGroup, slot.LocalIndex, slot.Endpoint, err))
				mu.Unlock()
				return
			}
			payload, readErr := io.ReadAll(rc)
			closeErr := rc.Close()
			if readErr != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("read %d/%d from %s: %w", slot.GeoGroup, slot.LocalIndex, slot.Endpoint, readErr))
				mu.Unlock()
				return
			}
			if closeErr != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("close %d/%d from %s: %w", slot.GeoGroup, slot.LocalIndex, slot.Endpoint, closeErr))
				mu.Unlock()
				return
			}
			if err := e.throttle(ctx, int64(len(payload)), job.MaxMbps); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
				return
			}
			mu.Lock()
			out[keyOf(slot)] = payload
			mu.Unlock()
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		errs = append(errs, ctx.Err())
	}
	return out, errs
}

// writeTargets PUTs the reconstructed shard bytes to the target agents and
// returns their checksums in Targets order.
func (e *Executor) writeTargets(ctx context.Context, job *contract.RepairJob, targets map[slotKey][]byte) ([]uint64, error) {
	checksums := make([]uint64, 0, len(job.Targets))
	for _, t := range job.Targets {
		if err := ctx.Err(); err != nil {
			return checksums, err
		}
		if t.Endpoint == "" {
			return checksums, fmt.Errorf("%w: target slot %d/%d has no endpoint",
				ErrInvalidJob, t.GeoGroup, t.LocalIndex)
		}
		payload, ok := targets[keyOf(t)]
		if !ok {
			return checksums, fmt.Errorf("%w: no payload for target slot %d/%d",
				ErrInvalidJob, t.GeoGroup, t.LocalIndex)
		}
		checksum := shard.Sum64(payload)
		err := e.client.PutShard(ctx, t.Endpoint, contract.PutShardRequest{
			ShardSetID: job.ShardSetID,
			GeoGroup:   t.GeoGroup,
			LocalIndex: t.LocalIndex,
			Params:     job.Params,
			ChunkIndex: job.ChunkIndex,
			PayloadLen: len(payload),
			Checksum:   checksum,
			Body:       bytes.NewReader(payload),
		})
		if err != nil {
			return checksums, fmt.Errorf("put target %d/%d to %s: %w", t.GeoGroup, t.LocalIndex, t.Endpoint, err)
		}
		if err := e.throttle(ctx, int64(len(payload)), job.MaxMbps); err != nil {
			return checksums, err
		}
		checksums = append(checksums, checksum)
	}
	return checksums, nil
}

// throttle sleeps so the job stays within its bandwidth budget. MaxMbps is in
// megabits per second; 0 disables throttling.
func (e *Executor) throttle(ctx context.Context, n int64, maxMbps int) error {
	if maxMbps <= 0 || n <= 0 {
		return nil
	}
	bytesPerSec := float64(maxMbps) * 1024 * 1024 / 8
	if bytesPerSec <= 0 {
		return nil
	}
	d := time.Duration(float64(n) / bytesPerSec * float64(time.Second))
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
