// Package recovery is the coordinator's repair-state authority.
//
// The recovery orchestrator (docs/04 §5.5, docs/03-data-plane.md §5) enqueues
// repair jobs, hands them to agents, and commits their results. Operators need to
// see that state directly: inferring repair health from topology (suspect agents,
// ring fullness) is guesswork exactly when it matters.
//
// This package keeps the state the status endpoint reports:
//
//   - queue counters, updated by the job lifecycle — never by scanning on read;
//   - a rolling 24 h window of repaired bytes and repair durations (for MTTR);
//   - the last error, so an operator can see *why* the queue is stuck;
//   - the redundancy deficit of every tracked shard set, computed against the
//     current membership snapshot (reachable shards per geo group) so the three
//     distinct severities stay distinct.
//
// Honesty rule: counters the service does not track are reported as nil (JSON
// null) instead of zero, so a console can render "unknown" rather than "all
// good". `unrecoverable` in particular means data loss; it must never be
// conflated with the benign deficits.
package recovery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/ec"
)

// DefaultRetention is the window for the repaired-bytes and MTTR figures.
const DefaultRetention = 24 * time.Hour

// maxFailedJobs bounds the retained failure history exposed through the status
// endpoint (old failures are folded into the counter only).
const maxFailedJobs = 1000

// Job is one unit of repair work tracked by the service.
type Job struct {
	ID         string
	ShardSetID contract.ShardSetID
	Type       string
	// Bytes is the expected number of shard bytes a successful repair restores.
	// It is accumulated into bytes_repaired_last_24h on commit.
	Bytes int64
	// TenantID is used for per-tenant budgets (kept for the orchestrator).
	TenantID contract.TenantID
}

type pendingJob struct {
	Job
	enqueuedAt time.Time
}

type runningJob struct {
	Job
	startedAt time.Time
	worker    string
}

type failedJob struct {
	Job
	failedAt time.Time
	reason   string
}

type byteRecord struct {
	at    time.Time
	bytes int64
}

type durationRecord struct {
	at       time.Time
	duration time.Duration
}

// ShardSetState is the redundancy-relevant view of one shard set: the coding
// parameters and, per geo group, the agents that hold its shards. Only the
// presence of agents matters for reachability, not the shard bytes.
type ShardSetState struct {
	ID     contract.ShardSetID
	Params ec.Params
	// Groups maps a geo group index to the agent ids expected to hold a shard
	// there. Every entry is one shard of that group.
	Groups map[int][]contract.AgentID
}

// Reachability reports whether an agent is currently reachable. The API layer
// derives it from the membership snapshot (a SUSPECT agent is still reachable for
// repair; an OFFLINE one is not).
type Reachability func(contract.AgentID) bool

// ShardSetSource produces the shard-set inventory used for the deficit counters.
// It is refreshed in the background; the status endpoint never scans the store.
type ShardSetSource interface {
	ShardSets(ctx context.Context) ([]ShardSetState, error)
}

// Deficits is the redundancy-deficit block of the status document. All three
// numbers are distinct severities and must not be merged:
//
//	below_threshold        usable geo groups < geo_n + floor(geo_k/2)  → queue work
//	below_repair_watermark usable geo groups == geo_n                   → next loss is fatal
//	unrecoverable          usable geo groups < geo_n                    → data loss, page
type Deficits struct {
	BelowThreshold       int `json:"below_threshold"`
	BelowRepairWatermark int `json:"below_repair_watermark"`
	Unrecoverable        int `json:"unrecoverable"`
}

// Queue is the job-counter block.
type Queue struct {
	Pending int `json:"pending"`
	Running int `json:"running"`
	Failed  int `json:"failed"`
}

// Status is the wire document for GET /v1/repair/status (docs/07 §1.6).
type Status struct {
	Queue                  Queue     `json:"queue"`
	OldestPendingAgeSecond *int64    `json:"oldest_pending_age_seconds"`
	BytesRepairedLast24h   *int64    `json:"bytes_repaired_last_24h"`
	Throttled              *bool     `json:"throttled"`
	PerSiteBudgetMbps      *int      `json:"per_site_budget_mbps"`
	LastError              *string   `json:"last_error"`
	GeneratedAt            time.Time `json:"generated_at"`
	ShardSets              *Deficits `json:"shardsets"`
}

// Config configures the service.
type Config struct {
	// PerSiteBudgetMBps is the inter-site repair bandwidth budget. Zero means
	// "not configured" and is reported as null, not as an implicit zero.
	PerSiteBudgetMBps int
	// Retention overrides the rolling window (tests use short windows).
	Retention time.Duration
	// Now overrides the clock (tests).
	Now    func() time.Time
	Logger *slog.Logger
}

func (c Config) withDefaults() Config {
	if c.Retention <= 0 {
		c.Retention = DefaultRetention
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return c
}

// Service tracks repair state. All methods are safe for concurrent use.
type Service struct {
	cfg Config

	mu sync.Mutex

	pending []*pendingJob
	running map[string]*runningJob
	failed  []failedJob

	completed []byteRecord
	durations []durationRecord

	lastError     *string
	throttled     bool
	throttleKnown bool

	shardSets      map[contract.ShardSetID]ShardSetState
	shardSetsKnown bool

	enqueuedTotal int64
	completedTo   int64
	failedTotal   int64
}

// New creates an empty service.
func New(cfg Config) *Service {
	return &Service{cfg: cfg.withDefaults(), running: make(map[string]*runningJob)}
}

// Now returns the service clock.
func (s *Service) Now() time.Time { return s.cfg.Now() }

// Enqueue adds a job to the tail of the queue.
func (s *Service) Enqueue(job Job) error {
	if job.ID == "" {
		return errors.New("recovery: job id is required")
	}
	now := s.cfg.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.pending {
		if p.ID == job.ID {
			return fmt.Errorf("recovery: job %s is already queued", job.ID)
		}
	}
	if _, ok := s.running[job.ID]; ok {
		return fmt.Errorf("recovery: job %s is already running", job.ID)
	}
	s.pending = append(s.pending, &pendingJob{Job: job, enqueuedAt: now})
	s.enqueuedTotal++
	return nil
}

// Claim takes the oldest pending job for a worker. It reports false when the
// queue is empty.
func (s *Service) Claim(worker string) (*Job, bool) {
	now := s.cfg.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) == 0 {
		return nil, false
	}
	p := s.pending[0]
	s.pending = s.pending[1:]
	s.running[p.ID] = &runningJob{Job: p.Job, startedAt: now, worker: worker}
	job := p.Job
	return &job, true
}

// Complete records a successful repair: the running job leaves the queue, its
// bytes enter the rolling window and its duration feeds MTTR.
func (s *Service) Complete(jobID string) error {
	now := s.cfg.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.running[jobID]
	if !ok {
		return fmt.Errorf("recovery: job %s is not running", jobID)
	}
	delete(s.running, jobID)
	s.completed = append(s.completed, byteRecord{at: now, bytes: r.Bytes})
	s.durations = append(s.durations, durationRecord{at: now, duration: now.Sub(r.startedAt)})
	s.completedTo++
	s.pruneLocked(now)
	return nil
}

// Fail records a failed repair. The job leaves the running set, the failure is
// retained for display and the last error is recorded verbatim.
func (s *Service) Fail(jobID, reason string) error {
	now := s.cfg.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.running[jobID]
	if !ok {
		return fmt.Errorf("recovery: job %s is not running", jobID)
	}
	delete(s.running, jobID)
	if reason == "" {
		reason = "repair failed"
	}
	s.failed = append(s.failed, failedJob{Job: r.Job, failedAt: now, reason: reason})
	if len(s.failed) > maxFailedJobs {
		s.failed = s.failed[len(s.failed)-maxFailedJobs:]
	}
	errCopy := reason
	s.lastError = &errCopy
	s.failedTotal++
	return nil
}

// Retry requeues a failed job (the orchestrator may do this after backoff).
func (s *Service) Retry(jobID string) error {
	now := s.cfg.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, f := range s.failed {
		if f.ID != jobID {
			continue
		}
		s.failed = append(s.failed[:i], s.failed[i+1:]...)
		s.pending = append(s.pending, &pendingJob{Job: f.Job, enqueuedAt: now})
		return nil
	}
	return fmt.Errorf("recovery: job %s has not failed", jobID)
}

// SetThrottled records whether the per-site budget is currently suppressing
// jobs. Until the orchestrator reports it, the value is unknown and the status
// document reports null.
func (s *Service) SetThrottled(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.throttled = v
	s.throttleKnown = true
}

// UpdateShardSets replaces the shard-set inventory used for deficits. It is
// called by the background refresher, never by the HTTP handler.
func (s *Service) UpdateShardSets(states []ShardSetState) {
	m := make(map[contract.ShardSetID]ShardSetState, len(states))
	for _, st := range states {
		if st.ID == "" || st.Params.Validate() != nil {
			continue
		}
		m[st.ID] = st
	}
	s.mu.Lock()
	s.shardSets = m
	s.shardSetsKnown = true
	s.mu.Unlock()
}

// RunRefresher periodically rebuilds the shard-set inventory. The HTTP status
// path is a pure read of the last snapshot.
func (s *Service) RunRefresher(ctx context.Context, src ShardSetSource, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	refresh := func() {
		states, err := src.ShardSets(ctx)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				s.cfg.Logger.Warn("repair status: shard-set refresh failed", "err", err)
			}
			return
		}
		s.UpdateShardSets(states)
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		refresh()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// pruneLocked drops windowed records outside the retention horizon.
func (s *Service) pruneLocked(now time.Time) {
	cutoff := now.Add(-s.cfg.Retention)
	i := 0
	for i < len(s.completed) && !s.completed[i].at.After(cutoff) {
		i++
	}
	if i > 0 {
		s.completed = append(s.completed[:0], s.completed[i:]...)
	}
	j := 0
	for j < len(s.durations) && !s.durations[j].at.After(cutoff) {
		j++
	}
	if j > 0 {
		s.durations = append(s.durations[:0], s.durations[j:]...)
	}
}

// Status builds the status document. reachable may be nil, which means every
// agent is considered reachable.
func (s *Service) Status(now time.Time, reachable Reachability) Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)

	out := Status{}
	out.Queue.Pending = len(s.pending)
	out.Queue.Running = len(s.running)
	out.Queue.Failed = len(s.failed)
	out.GeneratedAt = now.UTC()

	if len(s.pending) > 0 {
		oldest := s.pending[0].enqueuedAt
		for _, p := range s.pending[1:] {
			if p.enqueuedAt.Before(oldest) {
				oldest = p.enqueuedAt
			}
		}
		age := int64(now.Sub(oldest).Seconds())
		if age < 0 {
			age = 0
		}
		out.OldestPendingAgeSecond = &age
	}

	var bytes int64
	for _, r := range s.completed {
		bytes += r.bytes
	}
	out.BytesRepairedLast24h = &bytes

	if s.cfg.PerSiteBudgetMBps > 0 {
		budget := s.cfg.PerSiteBudgetMBps
		out.PerSiteBudgetMbps = &budget
		known := s.throttleKnown
		throttled := s.throttled
		if !known {
			// Budget configured but no live scheduler reporting yet: the honest
			// answer is null, not "not throttled".
			out.Throttled = nil
		} else {
			out.Throttled = &throttled
		}
	} else {
		out.PerSiteBudgetMbps = nil
		out.Throttled = nil
	}
	if s.lastError != nil {
		e := *s.lastError
		out.LastError = &e
	}
	if s.shardSetsKnown {
		d := s.deficitsLocked(reachable)
		out.ShardSets = &d
	}
	return out
}

// deficitsLocked computes the three severities from reachable shard counts. A geo
// group is usable when enough of its local shards are reachable to reconstruct its
// geo piece (local_n shards; with local_k parity that is the local decode
// threshold). Unusable groups are the same thing as lost nexus groups.
func (s *Service) deficitsLocked(reachable Reachability) Deficits {
	var d Deficits
	if reachable == nil {
		reachable = func(contract.AgentID) bool { return true }
	}
	for _, st := range s.shardSets {
		usable := 0
		for _, agents := range st.Groups {
			live := 0
			for _, id := range agents {
				if reachable(id) {
					live++
				}
			}
			if live >= st.Params.LocalN {
				usable++
			}
		}
		threshold := st.Params.GeoN + st.Params.GeoK/2
		if usable < threshold {
			d.BelowThreshold++
		}
		if usable == st.Params.GeoN {
			d.BelowRepairWatermark++
		}
		if usable < st.Params.GeoN {
			d.Unrecoverable++
		}
	}
	return d
}

// Metrics returns the same source of truth the Prometheus endpoint exposes, so
// the status document and the metrics cannot drift.
func (s *Service) Metrics() map[string]float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.cfg.Now()
	s.pruneLocked(now)
	var bytes int64
	for _, r := range s.completed {
		bytes += r.bytes
	}
	var mttr float64
	if n := len(s.durations); n > 0 {
		var total time.Duration
		for _, d := range s.durations {
			total += d.duration
		}
		mttr = total.Seconds() / float64(n)
	}
	return map[string]float64{
		"queue_pending":           float64(len(s.pending)),
		"queue_running":           float64(len(s.running)),
		"queue_failed":            float64(len(s.failed)),
		"bytes_repaired_last_24h": float64(bytes),
		"mttr_seconds":            mttr,
		"enqueued_total":          float64(s.enqueuedTotal),
		"completed_total":         float64(s.completedTo),
		"failed_total":            float64(s.failedTotal),
	}
}

// SortedShardSetIDs is a small helper for deterministic logging/tests.
func SortedShardSetIDs(states []ShardSetState) []contract.ShardSetID {
	ids := make([]contract.ShardSetID, 0, len(states))
	for _, st := range states {
		ids = append(ids, st.ID)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}
