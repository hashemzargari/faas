//go:build load

package load

import (
	"encoding/json"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// phaseSample is one request taken from a service log.
type phaseSample struct {
	at  time.Time
	dur time.Duration
}

// parseRequestLine extracts (method, path, duration, time) from either slog text
// (`key=value`, the coordinator) or slog JSON (the agents) request lines.
func parseRequestLine(line string) (method, path string, dur time.Duration, at time.Time, ok bool) {
	var fields map[string]any
	if strings.HasPrefix(strings.TrimSpace(line), "{") {
		if err := json.Unmarshal([]byte(line), &fields); err == nil {
			m, _ := fields["method"].(string)
			p, _ := fields["path"].(string)
			d, _ := fields["duration_ms"].(float64)
			if t, ok := fields["time"].(string); ok {
				at, _ = time.Parse(time.RFC3339Nano, t)
			}
			if m != "" && p != "" {
				return m, p, time.Duration(d * float64(time.Millisecond)), at, true
			}
			return "", "", 0, time.Time{}, false
		}
	}
	method, path = "", ""
	var durMS float64
	for _, tok := range strings.Fields(line) {
		kv := strings.SplitN(tok, "=", 2)
		if len(kv) != 2 {
			continue
		}
		v := strings.Trim(kv[1], `"`)
		switch kv[0] {
		case "method":
			method = v
		case "path":
			path = v
		case "duration_ms":
			durMS, _ = strconv.ParseFloat(v, 64)
		case "time":
			at, _ = time.Parse(time.RFC3339Nano, v)
		}
	}
	if method == "" || path == "" {
		return "", "", 0, time.Time{}, false
	}
	return method, path, time.Duration(durMS * float64(time.Millisecond)), at, true
}

// analyzeLogs attributes a PUT's latency using the services' own request timings:
// coordinator /v1/placement, coordinator /v1/objects:commit, and every agent-side
// shard PUT (which includes the disk fsync, since it is the transport handler's
// wall time). No product instrumentation is required.
func analyzeLogs(s *stack, from, to time.Time) phaseReport {
	var place, commit, shard []phaseSample
	for _, p := range s.procs {
		raw, err := os.ReadFile(p.path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			method, path, dur, at, ok := parseRequestLine(line)
			if !ok {
				continue
			}
			if !at.IsZero() && (at.Before(from) || at.After(to)) {
				continue
			}
			switch {
			case method == "POST" && path == "/v1/placement":
				place = append(place, phaseSample{at, dur})
			case method == "POST" && path == "/v1/objects:commit":
				commit = append(commit, phaseSample{at, dur})
			case method == "PUT" && strings.HasPrefix(path, "/v1/shards/"):
				shard = append(shard, phaseSample{at, dur})
			}
		}
	}
	pick := func(samples []phaseSample) (p50, p95, p99, max float64) {
		if len(samples) == 0 {
			return 0, 0, 0, 0
		}
		vals := make([]float64, 0, len(samples))
		for _, sm := range samples {
			vals = append(vals, float64(sm.dur.Microseconds())/1000.0)
		}
		sort.Float64s(vals)
		at := func(p float64) float64 { return vals[int(float64(len(vals)-1)*p)] }
		return at(0.5), at(0.95), at(0.99), vals[len(vals)-1]
	}
	pl50, _, _, _ := pick(place)
	cl50, _, _, _ := pick(commit)
	sh50, sh95, sh99, shMax := pick(shard)
	window := to.Sub(from).Seconds()
	var busy time.Duration
	for _, sm := range shard {
		busy += sm.dur
	}
	report := phaseReport{
		PlacementMS:    pl50,
		PlacementCount: len(place),
		CommitMS:       cl50,
		CommitCount:    len(commit),
		ShardPutCount:  len(shard),
		ShardPutP50MS:  sh50,
		ShardPutP95MS:  sh95,
		ShardPutP99MS:  sh99,
		ShardPutMaxMS:  shMax,
		ShardBusyMS:    float64(busy.Microseconds()) / 1000.0,
	}
	if window > 0 && len(shard) > 0 {
		report.ShardWritesPerAgentS = float64(len(shard)) / window / 12.0
	}
	return report
}
