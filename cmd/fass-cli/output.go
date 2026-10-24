package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// table is a minimal aligned-text table. The CLI intentionally does not pull in
// a table library: human output only needs stable columns for operators and
// grep-friendly text.
type table struct {
	headers []string
	rows    [][]string
}

func newTable(headers ...string) *table { return &table{headers: headers} }

func (t *table) add(cells ...string) {
	if len(cells) != len(t.headers) {
		panic(fmt.Sprintf("table: %d cells for %d headers", len(cells), len(t.headers)))
	}
	t.rows = append(t.rows, cells)
}

func (t *table) empty() bool { return len(t.rows) == 0 }

func (t *table) render(w io.Writer) {
	if len(t.headers) == 0 {
		return
	}
	widths := make([]int, len(t.headers))
	for i, h := range t.headers {
		widths[i] = len(h)
	}
	for _, row := range t.rows {
		for i, c := range row {
			if n := len(c); n > widths[i] {
				widths[i] = n
			}
		}
	}
	writeRow := func(cells []string) {
		var b strings.Builder
		for i, c := range cells {
			if i > 0 {
				b.WriteString("  ")
			}
			b.WriteString(c)
			if i < len(cells)-1 {
				b.WriteString(strings.Repeat(" ", widths[i]-len(c)))
			}
		}
		fmt.Fprintln(w, strings.TrimRight(b.String(), " "))
	}
	writeRow(t.headers)
	for _, row := range t.rows {
		writeRow(row)
	}
}

// writeJSON pretty-prints v. JSON goes to stdout so `fass ... --json | jq` works
// with no stderr noise mixed in.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return servicef(err, "encode JSON output")
	}
	return nil
}

// humanBytes renders 20 MiB instead of 20971520 (123 B, 4.0 KiB, 1.5 GiB).
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit && exp < 5; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// humanTime renders an RFC3339-ish timestamp without sub-second noise, and a
// dash for the zero time (which is what the coordinator returns for unknown
// fields such as last_seen on a pending agent).
func humanTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04:05")
}

// durationSince renders uptime-like durations compactly.
func durationSince(t time.Time, now time.Time) string {
	if t.IsZero() {
		return "-"
	}
	d := now.Sub(t)
	if d < 0 {
		return "0s"
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dd%dh", int(d.Hours())/24, int(d.Hours())%24)
	}
}

func pct(part, total int64) string {
	if total <= 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f%%", 100*float64(part)/float64(total))
}

// joinIDs is a compact rendering for lists such as ring ids or nexus ids.
func joinIDs(ids []string) string {
	if len(ids) == 0 {
		return "-"
	}
	return strings.Join(ids, ",")
}

// countByState groups agents by state, always returning every documented state
// so the table shape does not depend on the data.
func countByState(states []string) map[string]int {
	out := map[string]int{
		"active": 0, "pending": 0, "suspect": 0, "offline": 0, "decommissioning": 0,
	}
	for _, s := range states {
		out[strings.ToLower(s)]++
	}
	return out
}

// sortedStateKeys keeps state output deterministic for tests and humans.
var documentedStates = []string{"active", "pending", "suspect", "offline", "decommissioning", "unknown"}
