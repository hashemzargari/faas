package api

import (
	"fmt"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// metrics is a dependency-free Prometheus exposition (docs/04 §5.8 SLOs need
// request latency, placement rate, commit rate and agent health). It deliberately
// avoids a client library: the coordinator only needs counters, a latency summary
// and a handful of gauges.
type metrics struct {
	start time.Time

	mu       sync.Mutex
	requests map[requestKey]int64
	latency  map[string]*latencySummary

	commits        atomic.Int64
	placements     atomic.Int64
	parts          atomic.Int64
	heartbeats     atomic.Int64
	announceOK     atomic.Int64
	announceFailed atomic.Int64
}

type requestKey struct {
	method, route string
	status        int
}

type latencySummary struct {
	count int64
	sum   float64
	max   float64
}

func newMetrics() *metrics {
	return &metrics{
		start:    time.Now(),
		requests: make(map[requestKey]int64),
		latency:  make(map[string]*latencySummary),
	}
}

func (m *metrics) observe(route, method string, status int, d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests[requestKey{method: method, route: route, status: status}]++
	sum := m.latency[route]
	if sum == nil {
		sum = &latencySummary{}
		m.latency[route] = sum
	}
	secs := d.Seconds()
	sum.count++
	sum.sum += secs
	if secs > sum.max {
		sum.max = secs
	}
}

func (s *Server) metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	m := s.metrics

	m.mu.Lock()
	keys := make([]requestKey, 0, len(m.requests))
	for k := range m.requests {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].route != keys[j].route {
			return keys[i].route < keys[j].route
		}
		if keys[i].method != keys[j].method {
			return keys[i].method < keys[j].method
		}
		return keys[i].status < keys[j].status
	})
	fmt.Fprintln(w, "# HELP fass_coordinator_http_requests_total Control-plane HTTP requests.")
	fmt.Fprintln(w, "# TYPE fass_coordinator_http_requests_total counter")
	for _, k := range keys {
		fmt.Fprintf(w, "fass_coordinator_http_requests_total{method=%q,route=%q,status=%q} %d\n",
			k.method, k.route, strconv.Itoa(k.status), m.requests[k])
	}
	routes := make([]string, 0, len(m.latency))
	for route := range m.latency {
		routes = append(routes, route)
	}
	sort.Strings(routes)
	fmt.Fprintln(w, "# HELP fass_coordinator_http_request_duration_seconds Control-plane request latency.")
	fmt.Fprintln(w, "# TYPE fass_coordinator_http_request_duration_seconds summary")
	for _, route := range routes {
		l := m.latency[route]
		fmt.Fprintf(w, "fass_coordinator_http_request_duration_seconds_sum{route=%q} %s\n", route, fmtFloat(l.sum))
		fmt.Fprintf(w, "fass_coordinator_http_request_duration_seconds_count{route=%q} %d\n", route, l.count)
		fmt.Fprintf(w, "fass_coordinator_http_request_duration_seconds_max{route=%q} %s\n", route, fmtFloat(l.max))
	}
	m.mu.Unlock()

	fmt.Fprintln(w, "# HELP fass_coordinator_objects_committed_total Object versions committed.")
	fmt.Fprintln(w, "# TYPE fass_coordinator_objects_committed_total counter")
	fmt.Fprintf(w, "fass_coordinator_objects_committed_total %d\n", m.commits.Load())
	fmt.Fprintln(w, "# HELP fass_coordinator_placements_total Placement decisions served.")
	fmt.Fprintln(w, "# TYPE fass_coordinator_placements_total counter")
	fmt.Fprintf(w, "fass_coordinator_placements_total %d\n", m.placements.Load())
	fmt.Fprintln(w, "# HELP fass_coordinator_parts_committed_total Multipart parts committed.")
	fmt.Fprintln(w, "# TYPE fass_coordinator_parts_committed_total counter")
	fmt.Fprintf(w, "fass_coordinator_parts_committed_total %d\n", m.parts.Load())
	fmt.Fprintln(w, "# HELP fass_coordinator_heartbeats_total Agent heartbeats accepted.")
	fmt.Fprintln(w, "# TYPE fass_coordinator_heartbeats_total counter")
	fmt.Fprintf(w, "fass_coordinator_heartbeats_total %d\n", m.heartbeats.Load())
	fmt.Fprintln(w, "# HELP fass_coordinator_announce_total Agent announce attempts by outcome.")
	fmt.Fprintln(w, "# TYPE fass_coordinator_announce_total counter")
	fmt.Fprintf(w, "fass_coordinator_announce_total{outcome=%q} %d\n", "ok", m.announceOK.Load())
	fmt.Fprintf(w, "fass_coordinator_announce_total{outcome=%q} %d\n", "rejected", m.announceFailed.Load())

	// Gauges derived from the topology. A scrape is not on the data path, so a
	// snapshot read is acceptable (and gives the console a consistent view).
	if snap, err := s.svc.Topology(r.Context()); err == nil {
		states := make(map[string]int)
		for _, ag := range snap.Agents {
			states[string(ag.State)]++
		}
		fmt.Fprintln(w, "# HELP fass_coordinator_agents Agents by state.")
		fmt.Fprintln(w, "# TYPE fass_coordinator_agents gauge")
		stateNames := make([]string, 0, len(states))
		for st := range states {
			stateNames = append(stateNames, st)
		}
		sort.Strings(stateNames)
		for _, st := range stateNames {
			fmt.Fprintf(w, "fass_coordinator_agents{state=%q} %d\n", st, states[st])
		}
		fmt.Fprintln(w, "# HELP fass_coordinator_rings Number of rings.")
		fmt.Fprintln(w, "# TYPE fass_coordinator_rings gauge")
		fmt.Fprintf(w, "fass_coordinator_rings %d\n", len(snap.Rings))
		fmt.Fprintln(w, "# HELP fass_coordinator_nexuses Number of nexuses.")
		fmt.Fprintln(w, "# TYPE fass_coordinator_nexuses gauge")
		fmt.Fprintf(w, "fass_coordinator_nexuses %d\n", len(snap.Nexuses))
	}
	if s.gcStats != nil {
		stats := s.gcStats()
		names := make([]string, 0, len(stats))
		for name := range stats {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Fprintf(w, "# HELP fass_coordinator_gc_%s Deletion GC %s.\n", name, strings.ReplaceAll(name, "_", " "))
			fmt.Fprintf(w, "# TYPE fass_coordinator_gc_%s gauge\n", name)
			fmt.Fprintf(w, "fass_coordinator_gc_%s %d\n", name, stats[name])
		}
	}
	if backlog, err := s.svc.Meta.DeletionBacklog(r.Context()); err == nil {
		fmt.Fprintln(w, "# HELP fass_coordinator_deletion_queue_depth Pending shard-GC entries.")
		fmt.Fprintln(w, "# TYPE fass_coordinator_deletion_queue_depth gauge")
		fmt.Fprintf(w, "fass_coordinator_deletion_queue_depth %d\n", backlog)
	}

	fmt.Fprintln(w, "# HELP fass_coordinator_uptime_seconds Process uptime.")
	fmt.Fprintln(w, "# TYPE fass_coordinator_uptime_seconds gauge")
	fmt.Fprintf(w, "fass_coordinator_uptime_seconds %s\n", fmtFloat(time.Since(s.metrics.start).Seconds()))
	fmt.Fprintln(w, "# HELP fass_coordinator_goroutines Goroutines.")
	fmt.Fprintln(w, "# TYPE fass_coordinator_goroutines gauge")
	fmt.Fprintf(w, "fass_coordinator_goroutines %d\n", runtime.NumGoroutine())
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	fmt.Fprintln(w, "# HELP fass_coordinator_heap_alloc_bytes Heap bytes allocated and in use.")
	fmt.Fprintln(w, "# TYPE fass_coordinator_heap_alloc_bytes gauge")
	fmt.Fprintf(w, "fass_coordinator_heap_alloc_bytes %d\n", ms.HeapAlloc)
}

func fmtFloat(v float64) string {
	return strconv.FormatFloat(v, 'g', -1, 64)
}
