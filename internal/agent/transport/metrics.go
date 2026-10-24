package transport

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/fass-storage/fass/internal/agent/store"
)

// metrics is a tiny dependency-free Prometheus text exposition. The agent has
// no metrics dependency in this module (no Prometheus client is vendored), so
// the handful of counters that matter are hand-rendered in the 0.0.4 format.
type metrics struct {
	mu       sync.RWMutex
	counters map[string]*atomic.Int64
	inflight atomic.Int64
}

func newMetrics() *metrics {
	return &metrics{counters: make(map[string]*atomic.Int64)}
}

func (m *metrics) ctr(name string) *atomic.Int64 {
	m.mu.RLock()
	c, ok := m.counters[name]
	m.mu.RUnlock()
	if ok {
		return c
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok = m.counters[name]; ok {
		return c
	}
	c = &atomic.Int64{}
	m.counters[name] = c
	return c
}

func (m *metrics) inc(name string)             { m.ctr(name).Add(1) }
func (m *metrics) add(name string, delta int64) { m.ctr(name).Add(delta) }

// render writes the Prometheus text format. It never fails on a request path:
// metric rendering errors are ignored because the HTTP status is already 200.
func (m *metrics) render(w io.Writer, st store.Stats, load float64) {
	m.mu.RLock()
	names := make([]string, 0, len(m.counters))
	for name := range m.counters {
		names = append(names, name)
	}
	values := make(map[string]int64, len(names))
	for _, name := range names {
		values[name] = m.counters[name].Load()
	}
	m.mu.RUnlock()
	sort.Strings(names)

	for _, name := range names {
		fmt.Fprintf(w, "# TYPE fass_agent_%s counter\n", name)
		fmt.Fprintf(w, "fass_agent_%s %d\n", name, values[name])
	}

	gauges := []struct {
		name  string
		help  string
		value float64
	}{
		{"fass_agent_inflight_requests", "Agent HTTP requests currently in flight", float64(m.inflight.Load())},
		{"fass_agent_load_ewma", "Agent request-latency EWMA in seconds", load},
		{"fass_agent_shard_count", "Number of shards stored on this disk", float64(st.ShardCount)},
		{"fass_agent_set_count", "Number of shard sets stored on this disk", float64(st.SetCount)},
		{"fass_agent_used_bytes", "Bytes used by shard files plus headers", float64(st.UsedBytes)},
		{"fass_agent_payload_bytes", "Shard payload bytes (excluding headers)", float64(st.PayloadBytes)},
		{"fass_agent_free_bytes", "Free bytes net of the configured reservation", float64(st.FreeBytes)},
		{"fass_agent_reserved_bytes", "Bytes reserved so the disk cannot fill", float64(st.ReservedBytes)},
		{"fass_agent_total_bytes", "Filesystem size in bytes", float64(st.TotalBytes)},
	}
	for _, g := range gauges {
		fmt.Fprintf(w, "# HELP %s %s\n", g.name, g.help)
		fmt.Fprintf(w, "# TYPE %s gauge\n", g.name)
		fmt.Fprintf(w, "%s %g\n", g.name, g.value)
	}
}
