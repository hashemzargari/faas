// Package metrics is a small, dependency-free Prometheus exposition registry.
//
// The gateway is deliberately built on the standard library only (the project
// vendors no Prometheus client), so this package tracks the counters and gauges
// the gateway's SLOs need and renders them in the Prometheus text format.
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Registry holds counters and gauges.
type Registry struct {
	mu       sync.Mutex
	counters map[string]*counter
	gauges   map[string]gauge
}

type counter struct {
	name   string
	help   string
	labels string
	value  atomic.Uint64
}

type gauge struct {
	name   string
	help   string
	labels string
	value  float64
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{
		counters: make(map[string]*counter),
		gauges:   make(map[string]gauge),
	}
}

// Inc increments a counter by one. A nil registry is a no-op so call sites do
// not need nil checks.
func (r *Registry) Inc(name string, labels map[string]string) {
	r.Add(name, labels, 1)
}

// Add increments a counter by n.
func (r *Registry) Add(name string, labels map[string]string, n uint64) {
	if r == nil || n == 0 {
		return
	}
	key := name + "{" + labelString(labels) + "}"
	r.mu.Lock()
	c, ok := r.counters[key]
	if !ok {
		c = &counter{name: sanitize(name), labels: labelString(labels)}
		r.counters[key] = c
	}
	r.mu.Unlock()
	c.value.Add(n)
}

// SetGauge sets a gauge value.
func (r *Registry) SetGauge(name string, labels map[string]string, v float64) {
	if r == nil {
		return
	}
	key := name + "{" + labelString(labels) + "}"
	r.mu.Lock()
	r.gauges[key] = gauge{name: sanitize(name), labels: labelString(labels), value: v}
	r.mu.Unlock()
}

// WritePrometheus renders the registry in Prometheus text exposition format.
func (r *Registry) WritePrometheus(w io.Writer) error {
	r.mu.Lock()
	counters := make([]*counter, 0, len(r.counters))
	for _, c := range r.counters {
		counters = append(counters, c)
	}
	gauges := make([]gauge, 0, len(r.gauges))
	for _, g := range r.gauges {
		gauges = append(gauges, g)
	}
	r.mu.Unlock()

	sort.Slice(counters, func(i, j int) bool { return counters[i].name < counters[j].name })
	sort.Slice(gauges, func(i, j int) bool { return gauges[i].name < gauges[j].name })

	for _, c := range counters {
		if _, err := fmt.Fprintf(w, "# TYPE %s counter\n%s %d\n", c.name, series(c.name, c.labels), c.value.Load()); err != nil {
			return err
		}
	}
	for _, g := range gauges {
		if _, err := fmt.Fprintf(w, "# TYPE %s gauge\n%s %g\n", g.name, series(g.name, g.labels), g.value); err != nil {
			return err
		}
	}
	return nil
}

// Handler returns an http.Handler serving the registry.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_ = r.WritePrometheus(w)
	})
}

// series renders "name{labels}" (or just the name when unlabelled).
func series(name, labels string) string {
	if labels == "" {
		return name
	}
	return name + "{" + labels + "}"
}

// labelString renders labels deterministically for map keys and exposition.
func labelString(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(sanitize(k))
		b.WriteString(`="`)
		b.WriteString(escape(labels[k]))
		b.WriteByte('"')
	}
	return b.String()
}

func escape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return strings.ReplaceAll(s, "\n", `\n`)
}

// sanitize converts a metric name to the Prometheus character set.
func sanitize(s string) string {
	var b strings.Builder
	for i, c := range s {
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == ':' || (i > 0 && c >= '0' && c <= '9')
		if ok {
			b.WriteRune(c)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}
