// Package scrub implements the agent-side rolling checksum verification
// (docs/03-data-plane.md §5.5, docs/04-services.md §6).
//
// The scrubber walks the shard inventory at a configurable rate (default
// 50 MiB/s, only when the disk is otherwise idle — the agent runs it as a low
// priority background loop), re-reads every shard, verifies its checksum and
// reports CORRUPT shards so the coordinator can repair them from peers. A
// corrupt shard is quarantined by the store, never served again.
package scrub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fass-storage/fass/internal/agent/store"
	"github.com/fass-storage/fass/internal/contract"
)

// Defaults from docs/04-services.md §6.4.
const (
	defaultPeriod      = 168 * time.Hour
	defaultBytesPerSec = 50 << 20 // 50 MiB/s
	defaultPageSize    = 256
	cursorFilename     = "scrub_cursor.json"
)

// StatusReporter reports shard health to the coordinator. coordclient.Client
// satisfies it. Reporting is best-effort: scrub progress must not stall because
// the coordinator is unavailable.
type StatusReporter interface {
	ReportShardStatus(ctx context.Context, items []contract.ShardStatus) error
}

// Options configures the scrubber.
type Options struct {
	Store *store.Store
	// Period between automatic full passes (default 168h).
	Period time.Duration
	// BytesPerSec rate limit (default 50 MiB/s).
	BytesPerSec int64
	// PageSize is the inventory page size (default 256).
	PageSize int
	// Reporter is optional; corrupt shards are reported as CORRUPT.
	Reporter StatusReporter
	// Logger defaults to slog.Default().
	Logger *slog.Logger
	// Now is a test hook.
	Now func() time.Time
}

// Report summarises one scrub pass.
type Report struct {
	StartedAt  time.Time
	Duration   time.Duration
	Checked    int
	Verified   int
	Corrupt    int
	Missing    int
	Bytes      int64
	NextCursor string
	Wrapped    bool
}

// Scrubber runs rolling scrub passes.
type Scrubber struct {
	st       *store.Store
	period   time.Duration
	bytesSec int64
	pageSize int
	reporter StatusReporter
	log      *slog.Logger
	now      func() time.Time
	cursorF  string

	trigger chan struct{}
	passMu  sync.Mutex

	mu     sync.Mutex
	cursor string
	runs   atomic.Int64
}

// New builds a scrubber.
func New(opts Options) (*Scrubber, error) {
	if opts.Store == nil {
		return nil, errors.New("scrub: nil store")
	}
	if opts.Period <= 0 {
		opts.Period = defaultPeriod
	}
	if opts.BytesPerSec <= 0 {
		opts.BytesPerSec = defaultBytesPerSec
	}
	if opts.PageSize <= 0 {
		opts.PageSize = defaultPageSize
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	s := &Scrubber{
		st:       opts.Store,
		period:   opts.Period,
		bytesSec: opts.BytesPerSec,
		pageSize: opts.PageSize,
		reporter: opts.Reporter,
		log:      opts.Logger.With("component", "scrub"),
		now:      opts.Now,
		cursorF:  filepath.Join(opts.Store.Root(), cursorFilename),
		trigger:  make(chan struct{}, 1),
	}
	if saved, ok := s.loadCursor(); ok {
		s.cursor = saved
	}
	return s, nil
}

// Trigger requests a scrub pass without blocking. Concurrent triggers coalesce.
func (s *Scrubber) Trigger() {
	select {
	case s.trigger <- struct{}{}:
	default:
	}
}

// Cursor reports the rolling scrub position (the last shard id scanned).
func (s *Scrubber) Cursor() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cursor
}

// Run loops: an explicit Trigger or the period timer starts a pass. It blocks
// until ctx is cancelled.
func (s *Scrubber) Run(ctx context.Context) error {
	s.log.Info("scrub loop started", "period", s.period.String(), "bytes_per_sec", s.bytesSec)
	timer := time.NewTimer(s.period)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-s.trigger:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-timer.C:
		}
		s.runs.Add(1)
		report, err := s.Pass(ctx)
		if err != nil && ctx.Err() == nil {
			s.log.Warn("scrub pass failed", "err", err)
		} else {
			s.log.Info("scrub pass complete",
				"checked", report.Checked, "verified", report.Verified,
				"corrupt", report.Corrupt, "missing", report.Missing,
				"bytes", report.Bytes, "duration_ms", report.Duration.Milliseconds(),
				"wrapped", report.Wrapped)
		}
		timer.Reset(s.period)
	}
}

// Pass verifies shards from the rolling cursor to the end of the inventory. If
// it reaches the end, it wraps to the beginning for the next pass.
func (s *Scrubber) Pass(ctx context.Context) (Report, error) {
	s.passMu.Lock()
	defer s.passMu.Unlock()

	report := Report{StartedAt: s.now()}
	limiter := newRateLimiter(s.bytesSec)

	start := s.Cursor()
	cursor := start
	for {
		if err := ctx.Err(); err != nil {
			report.Duration = s.now().Sub(report.StartedAt)
			return report, err
		}
		page, next, err := s.st.Inventory(ctx, cursor, s.pageSize)
		if err != nil {
			report.Duration = s.now().Sub(report.StartedAt)
			return report, fmt.Errorf("scrub: inventory: %w", err)
		}
		for _, info := range page {
			if err := ctx.Err(); err != nil {
				report.Duration = s.now().Sub(report.StartedAt)
				return report, err
			}
			report.Checked++
			_, verr := s.st.Verify(ctx, info.ShardSetID, info.GeoGroup, info.LocalIndex)
			switch {
			case verr == nil:
				report.Verified++
			case errors.Is(verr, contract.ErrNotFound):
				report.Missing++
			case errors.Is(verr, store.ErrCorrupt):
				report.Corrupt++
				s.reportCorrupt(ctx, info)
			default:
				// Transient I/O error: count as unverified, keep going. A real
				// disk problem will surface repeatedly and be reported by the
				// heartbeat/inventory digest divergence.
				s.log.Warn("scrub could not verify shard", "set_id", info.ShardSetID,
					"geo_group", info.GeoGroup, "local_index", info.LocalIndex, "err", verr)
			}
			report.Bytes += info.Size
			if err := limiter.Wait(ctx, info.Size); err != nil {
				report.Duration = s.now().Sub(report.StartedAt)
				return report, err
			}
		}
		if next == "" || len(page) == 0 {
			s.mu.Lock()
			s.cursor = ""
			s.mu.Unlock()
			report.Wrapped = start != ""
			break
		}
		cursor = next
		s.mu.Lock()
		s.cursor = next
		s.mu.Unlock()
		s.persistCursor()
	}
	report.NextCursor = s.Cursor()
	report.Duration = s.now().Sub(report.StartedAt)
	s.persistCursor()
	return report, nil
}

func (s *Scrubber) reportCorrupt(ctx context.Context, info contract.ShardInfo) {
	slot := info.LocalIndex
	if params, ok := s.st.Params(info.ShardSetID, info.GeoGroup, info.LocalIndex); ok {
		slot = info.GeoGroup*params.ShardsPerGroup() + info.LocalIndex
	}
	status := []contract.ShardStatus{{
		ShardSetID: info.ShardSetID,
		Slot:       slot,
		State:      "CORRUPT",
	}}
	if s.reporter == nil {
		return
	}
	// Best-effort with a short timeout; the coordinator may be down.
	reportCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.reporter.ReportShardStatus(reportCtx, status); err != nil {
		s.log.Warn("reporting CORRUPT shard failed", "set_id", info.ShardSetID, "err", err)
	}
}

func (s *Scrubber) persistCursor() {
	state := struct {
		Cursor string    `json:"cursor"`
		Saved  time.Time `json:"saved_at"`
	}{Cursor: s.Cursor(), Saved: s.now().UTC()}
	b, err := json.Marshal(state)
	if err != nil {
		s.log.Warn("marshal scrub cursor", "err", err)
		return
	}
	tmp := s.cursorF + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		s.log.Warn("write scrub cursor", "err", err)
		return
	}
	if err := os.Rename(tmp, s.cursorF); err != nil {
		s.log.Warn("rename scrub cursor", "err", err)
	}
}

func (s *Scrubber) loadCursor() (string, bool) {
	b, err := os.ReadFile(s.cursorF)
	if err != nil {
		return "", false
	}
	var state struct {
		Cursor string `json:"cursor"`
	}
	if err := json.Unmarshal(b, &state); err != nil {
		return "", false
	}
	return state.Cursor, state.Cursor != ""
}

// rateLimiter delays reads so the scrub pass stays under BytesPerSec.
type rateLimiter struct {
	rate  float64
	start time.Time
	bytes int64
}

func newRateLimiter(bytesPerSec int64) *rateLimiter {
	return &rateLimiter{rate: float64(bytesPerSec), start: time.Now()}
}

// Wait sleeps until the cumulative bytes fit the configured rate.
func (l *rateLimiter) Wait(ctx context.Context, n int64) error {
	if l.rate <= 0 || n <= 0 {
		return nil
	}
	l.bytes += n
	due := time.Duration(float64(l.bytes) / l.rate * float64(time.Second))
	lag := due - time.Since(l.start)
	if lag <= 0 {
		return nil
	}
	timer := time.NewTimer(lag)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
