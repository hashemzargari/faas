package postgres

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// TimingStats aggregates statement-level timings for the PostgreSQL adapter. It
// exists for load-test attribution only (enabled with --db-debug-timings) and is
// nil-cheap when disabled.
type TimingStats struct {
	mu        sync.Mutex
	stmtSum   map[string]time.Duration
	stmtCnt   map[string]int64
	beginSum  time.Duration
	beginCnt  int64
	commitSum time.Duration
	commitCnt int64
}

// NewTimingStats returns an empty collector.
func NewTimingStats() *TimingStats {
	return &TimingStats{stmtSum: map[string]time.Duration{}, stmtCnt: map[string]int64{}}
}

func (t *TimingStats) recordStmt(label string, d time.Duration) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.stmtSum[label] += d
	t.stmtCnt[label]++
	t.mu.Unlock()
}

func (t *TimingStats) recordBegin(d time.Duration) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.beginSum += d
	t.beginCnt++
	t.mu.Unlock()
}

func (t *TimingStats) recordCommit(d time.Duration) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.commitSum += d
	t.commitCnt++
	t.mu.Unlock()
}

// Metric is one aggregated timing series.
type Metric struct {
	SumSeconds float64 `json:"sum_seconds"`
	Count      int64   `json:"count"`
	AvgMillis  float64 `json:"avg_ms"`
}

// Snapshot returns the current aggregates keyed by statement label, plus the
// transaction begin (pool acquire + BEGIN) and commit series.
func (t *TimingStats) Snapshot() map[string]Metric {
	out := map[string]Metric{}
	if t == nil {
		return out
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for label, sum := range t.stmtSum {
		n := t.stmtCnt[label]
		out[label] = metricFrom(sum, n)
	}
	out["tx_begin_pool_acquire"] = metricFrom(t.beginSum, t.beginCnt)
	out["tx_commit"] = metricFrom(t.commitSum, t.commitCnt)
	return out
}

func metricFrom(sum time.Duration, n int64) Metric {
	m := Metric{SumSeconds: sum.Seconds(), Count: n}
	if n > 0 {
		m.AvgMillis = sum.Seconds() * 1000 / float64(n)
	}
	return m
}

// Labels returns metric keys sorted (deterministic output).
func (t *TimingStats) Labels() []string {
	snap := t.Snapshot()
	out := make([]string, 0, len(snap))
	for k := range snap {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (t *TimingStats) tracer() pgx.QueryTracer { return &timingTracer{stats: t} }

type timingTracer struct{ stats *TimingStats }

type timingKey struct {
	start time.Time
	label string
}

func (tt *timingTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, timingKey{}, timingKey{start: time.Now(), label: classifySQL(data.SQL)})
}

func (tt *timingTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryEndData) {
	key, ok := ctx.Value(timingKey{}).(timingKey)
	if !ok {
		return
	}
	tt.stats.recordStmt(key.label, time.Since(key.start))
}

// classifySQL maps a statement to a stable low-cardinality label.
func classifySQL(q string) string {
	u := strings.ToUpper(strings.TrimSpace(q))
	frag := func(s string) bool { return strings.Contains(u, s) }
	switch {
	case strings.HasPrefix(u, "INSERT INTO BLOBS"):
		return "blob_put"
	case strings.HasPrefix(u, "SELECT DATA FROM BLOBS"):
		return "blob_get"
	case strings.HasPrefix(u, "DELETE FROM BLOBS"):
		return "blob_delete"
	case strings.HasPrefix(u, "INSERT INTO KV"):
		return "kv_put"
	case strings.HasPrefix(u, "DELETE FROM KV"):
		return "kv_delete"
	case strings.HasPrefix(u, "SELECT VALUE FROM KV"):
		if frag("FOR UPDATE") {
			return "kv_get_for_update"
		}
		return "kv_get"
	case strings.HasPrefix(u, "SELECT KEY"):
		if frag("ORDER BY KEY") {
			if frag("KEY >= ") || frag("KEY < ") {
				return "kv_scan_range"
			}
			return "kv_scan_space"
		}
		return "kv_select"
	case strings.HasPrefix(u, "ANALYZE"):
		return "analyze"
	default:
		return "other"
	}
}
