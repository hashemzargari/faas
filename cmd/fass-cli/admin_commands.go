package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// cluster status
// ---------------------------------------------------------------------------

func runCluster(ctx context.Context, g *globalOpts, args []string, stdout, stderr io.Writer) error {
	pos, err := parseCommandFlags(g, "cluster", args, stderr, func(fs *flag.FlagSet) {})
	if err != nil {
		return err
	}
	if g.help {
		printCommandUsage(stdout, "cluster")
		return nil
	}
	if len(pos) == 0 || pos[0] != "status" {
		return usagef("usage: fass cluster status (got %q)", strings.Join(pos, " "))
	}
	if len(pos) > 1 {
		return usagef("cluster status takes no arguments")
	}

	client, err := newAdminClient(g)
	if err != nil {
		return err
	}
	snap, err := client.topology(ctx)
	if err != nil {
		return err
	}
	health, healthErr := client.health(ctx)

	states := make(map[string]int)
	for _, a := range snap.Agents {
		states[strings.ToLower(a.State)]++
	}
	status := "ok"
	if healthErr != nil {
		status = "degraded"
	} else if len(snap.Agents) == 0 {
		status = "degraded"
	} else {
		for st, n := range states {
			if n > 0 && st != "active" {
				status = "degraded"
			}
		}
	}

	if g.jsonOut {
		out := clusterStatusJSON{
			Status:            status,
			Health:            health,
			Swarms:            nonNil(snap.Swarms),
			Nexuses:           nonNil(snap.Nexuses),
			Nodes:             nonNil(snap.Nodes),
			Agents:            clusterAgentsJSON{Total: len(snap.Agents), ByState: states, Items: nonNil(snap.Agents)},
			Rings:             nonNil(snap.Rings),
			RedundancyClasses: nonNil(snap.RedundancyClasses),
			SnapshotAt:        snap.At,
		}
		if healthErr != nil {
			out.HealthError = healthErr.Error()
		}
		return writeJSON(stdout, out)
	}

	name := "(no swarm)"
	for _, sw := range snap.Swarms {
		name = sw.Name
		if name == "" {
			name = sw.ID
		}
		break
	}
	fmt.Fprintf(stdout, "Cluster: %s\n", name)
	if healthErr != nil {
		fmt.Fprintf(stdout, "Health:  DEGRADED (%v)\n", healthErr)
	} else {
		detail := ""
		if v, ok := health["schema_version"]; ok {
			detail = fmt.Sprintf(" (schema_version=%v)", v)
		}
		fmt.Fprintf(stdout, "Health:  %s%s\n", firstNonEmpty(fmt.Sprint(health["status"]), "ok"), detail)
	}
	fmt.Fprintf(stdout, "Agents:  %d total, %d ACTIVE, %d SUSPECT, %d OFFLINE, %d PENDING, %d DECOMMISSIONING\n",
		len(snap.Agents), states["active"], states["suspect"], states["offline"], states["pending"], states["decommissioning"])
	fmt.Fprintf(stdout, "Nexuses: %d  Nodes: %d  Rings: %d  Redundancy classes: %d  (snapshot %s)\n\n",
		len(snap.Nexuses), len(snap.Nodes), len(snap.Rings), len(snap.RedundancyClasses), humanTime(snap.At))

	// Agent state matrix per nexus: the first thing an operator wants to see.
	nexusOrder := make([]string, 0, len(snap.Nexuses))
	for _, n := range snap.Nexuses {
		nexusOrder = append(nexusOrder, n.ID)
	}
	perNexus := map[string]map[string]int{}
	for _, a := range snap.Agents {
		if perNexus[a.NexusID] == nil {
			perNexus[a.NexusID] = map[string]int{}
		}
		perNexus[a.NexusID][strings.ToLower(a.State)]++
	}
	tbl := newTable("NEXUS", "AGENTS", "ACTIVE", "SUSPECT", "OFFLINE", "PENDING", "WRITE_DEGRADED")
	seen := map[string]bool{}
	appendNexus := func(id string) {
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		counts := perNexus[id]
		total := 0
		for _, n := range counts {
			total += n
		}
		degraded := ""
		for _, n := range snap.Nexuses {
			if n.ID == id && n.WriteDegraded {
				degraded = "yes"
			}
		}
		tbl.add(id, strconv.Itoa(total), strconv.Itoa(counts["active"]), strconv.Itoa(counts["suspect"]),
			strconv.Itoa(counts["offline"]), strconv.Itoa(counts["pending"]), degraded)
	}
	for _, id := range nexusOrder {
		appendNexus(id)
	}
	for id := range perNexus {
		appendNexus(id)
	}
	tbl.render(stdout)
	fmt.Fprintln(stdout)

	if len(snap.Rings) > 0 {
		rt := newTable("RING", "NAME", "RC", "NEXUSES", "CAPACITY", "USED", "FULL")
		for _, r := range snap.Rings {
			rt.add(r.ID, r.Name, r.RCID, strconv.Itoa(len(r.NexusIDs)),
				humanBytes(r.Capacity), humanBytes(r.UsedBytes), ringFullPct(r))
		}
		rt.render(stdout)
		fmt.Fprintln(stdout)
	}
	if len(snap.RedundancyClasses) > 0 {
		rcTable(stdout, snap.RedundancyClasses)
	}
	return nil
}

func ringFullPct(r ringInfo) string {
	if r.Capacity <= 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f%%", 100*float64(r.UsedBytes)/float64(r.Capacity))
}

func rcTable(w io.Writer, rcs []rcInfo) {
	t := newTable("RC", "NAME", "GEO", "LOCAL", "AAG", "CHUNK", "RATIO")
	for _, rc := range rcs {
		t.add(rc.ID, rc.Name,
			fmt.Sprintf("%d+%d", rc.Params.GeoN, rc.Params.GeoK),
			fmt.Sprintf("%d+%d", rc.Params.LocalN, rc.Params.LocalK),
			strconv.Itoa(rc.AAG), humanBytes(int64(rc.ChunkSize)),
			fmt.Sprintf("%.2fx", rc.ratio()))
	}
	t.render(w)
}

// nonNil makes JSON emit [] rather than null for empty topology sections; jq
// users (and the console) should not need null checks.
func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// ---------------------------------------------------------------------------
// node ls
// ---------------------------------------------------------------------------

type nodeJSON struct {
	NodeID   string `json:"node_id"`
	NexusID  string `json:"nexus_id"`
	Hostname string `json:"hostname"`
	Rack     string `json:"rack"`
	Agents   int    `json:"agents"`
	Active   int    `json:"active_agents"`
}

func runNode(ctx context.Context, g *globalOpts, args []string, stdout, stderr io.Writer) error {
	pos, err := parseCommandFlags(g, "node", args, stderr, func(fs *flag.FlagSet) {})
	if err != nil {
		return err
	}
	if g.help {
		printCommandUsage(stdout, "node")
		return nil
	}
	if len(pos) == 0 || pos[0] != "ls" {
		return usagef("usage: fass node ls")
	}
	if len(pos) > 1 {
		return usagef("node ls takes no arguments")
	}
	client, err := newAdminClient(g)
	if err != nil {
		return err
	}
	snap, err := client.topology(ctx)
	if err != nil {
		return err
	}
	perNode := map[string]int{}
	active := map[string]int{}
	for _, a := range snap.Agents {
		perNode[a.NodeID]++
		if strings.EqualFold(a.State, "active") {
			active[a.NodeID]++
		}
	}
	nodes := make([]nodeJSON, 0, len(snap.Nodes))
	for _, n := range snap.Nodes {
		nodes = append(nodes, nodeJSON{
			NodeID: n.ID, NexusID: n.NexusID, Hostname: n.Hostname, Rack: n.Rack,
			Agents: perNode[n.ID], Active: active[n.ID],
		})
	}
	// Nodes with agents but no node record should not disappear from `node ls`.
	seen := map[string]bool{}
	for _, n := range nodes {
		seen[n.NodeID] = true
	}
	for id := range perNode {
		if !seen[id] {
			nodes = append(nodes, nodeJSON{NodeID: id, Agents: perNode[id], Active: active[id]})
		}
	}
	if g.jsonOut {
		return writeJSON(stdout, nodes)
	}
	t := newTable("NODE", "NEXUS", "HOSTNAME", "RACK", "AGENTS", "ACTIVE")
	for _, n := range nodes {
		t.add(n.NodeID, n.NexusID, dash(n.Hostname), dash(n.Rack), strconv.Itoa(n.Agents), strconv.Itoa(n.Active))
	}
	t.render(stdout)
	return nil
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// ---------------------------------------------------------------------------
// rc ls
// ---------------------------------------------------------------------------

func runRC(ctx context.Context, g *globalOpts, args []string, stdout, stderr io.Writer) error {
	pos, err := parseCommandFlags(g, "rc", args, stderr, func(fs *flag.FlagSet) {})
	if err != nil {
		return err
	}
	if g.help {
		printCommandUsage(stdout, "rc")
		return nil
	}
	if len(pos) == 0 || pos[0] != "ls" {
		return usagef("usage: fass rc ls")
	}
	if len(pos) > 1 {
		return usagef("rc ls takes no arguments")
	}
	client, err := newAdminClient(g)
	if err != nil {
		return err
	}
	var resp struct {
		RCs []rcInfo `json:"redundancy_classes"`
	}
	if err := client.getJSON(ctx, "/v1/redundancy-classes", &resp); err != nil {
		return err
	}
	if g.jsonOut {
		return writeJSON(stdout, nonNil(resp.RCs))
	}
	rcTable(stdout, resp.RCs)
	return nil
}

// ---------------------------------------------------------------------------
// repair status
// ---------------------------------------------------------------------------

type repairRiskJSON struct {
	Source               string         `json:"source"`
	AgentsTotal          int            `json:"agents_total"`
	AgentsActive         int            `json:"agents_active"`
	AgentsSuspect        int            `json:"agents_suspect"`
	AgentsOffline        int            `json:"agents_offline"`
	OfflineAgents        []string       `json:"offline_agents"`
	SuspectAgents        []string       `json:"suspect_agents"`
	WriteDegradedNexuses []string       `json:"write_degraded_nexuses"`
	RingsNearFull        []ringInfofull `json:"rings_near_full"`
	Note                 string         `json:"note,omitempty"`
}

type ringInfofull struct {
	ID      string  `json:"ring_id"`
	FullPct float64 `json:"full_pct"`
}

func runRepair(ctx context.Context, g *globalOpts, args []string, stdout, stderr io.Writer) error {
	pos, err := parseCommandFlags(g, "repair", args, stderr, func(fs *flag.FlagSet) {})
	if err != nil {
		return err
	}
	if g.help {
		printCommandUsage(stdout, "repair")
		return nil
	}
	if len(pos) == 0 || pos[0] != "status" {
		return usagef("usage: fass repair status")
	}
	if len(pos) > 1 {
		return usagef("repair status takes no arguments")
	}
	client, err := newAdminClient(g)
	if err != nil {
		return err
	}

	// Prefer the coordinator's repair-queue endpoint when it exists. An older
	// coordinator answers 404 and we fall back to the topology-derived view, so
	// the command never breaks against a mixed-version deployment.
	if raw, gerr := client.getRaw(ctx, "/v1/repair/status"); gerr == nil {
		if strings.TrimSpace(raw) != "" {
			status, derr := parseRepairStatus(raw)
			if derr != nil {
				return servicef(derr, "decode coordinator /v1/repair/status")
			}
			return printRepairStatus(stdout, g, status)
		}
		// 204/empty: treat like "not implemented" and derive from topology.
	} else if !isNotFound(gerr) {
		return gerr
	}

	snap, err := client.topology(ctx)
	if err != nil {
		return err
	}
	risk := repairRiskJSON{Source: "derived from /v1/topology"}
	nexusDegraded := map[string]bool{}
	for _, n := range snap.Nexuses {
		if n.WriteDegraded {
			risk.WriteDegradedNexuses = append(risk.WriteDegradedNexuses, n.ID)
			nexusDegraded[n.ID] = true
		}
	}
	for _, a := range snap.Agents {
		risk.AgentsTotal++
		switch strings.ToLower(a.State) {
		case "active":
			risk.AgentsActive++
		case "suspect":
			risk.AgentsSuspect++
			risk.SuspectAgents = append(risk.SuspectAgents, a.ID)
		case "offline":
			risk.AgentsOffline++
			risk.OfflineAgents = append(risk.OfflineAgents, a.ID)
		}
	}
	for _, r := range snap.Rings {
		if r.Capacity > 0 {
			pct := 100 * float64(r.UsedBytes) / float64(r.Capacity)
			if pct >= 80 {
				risk.RingsNearFull = append(risk.RingsNearFull, ringInfofull{ID: r.ID, FullPct: pct})
			}
		}
	}
	risk.Note = "the coordinator exposes no repair-queue introspection endpoint yet; this is a risk summary derived from topology (see docs/08-operations.md)"
	if risk.OfflineAgents == nil {
		risk.OfflineAgents = []string{}
	}
	if risk.SuspectAgents == nil {
		risk.SuspectAgents = []string{}
	}
	if risk.WriteDegradedNexuses == nil {
		risk.WriteDegradedNexuses = []string{}
	}
	if risk.RingsNearFull == nil {
		risk.RingsNearFull = []ringInfofull{}
	}

	if g.jsonOut {
		return writeJSON(stdout, risk)
	}
	t := newTable("METRIC", "VALUE")
	t.add("Agents total", strconv.Itoa(risk.AgentsTotal))
	t.add("Agents ACTIVE", strconv.Itoa(risk.AgentsActive))
	t.add("Agents SUSPECT", strconv.Itoa(risk.AgentsSuspect))
	t.add("Agents OFFLINE", strconv.Itoa(risk.AgentsOffline))
	t.add("Write-degraded nexuses", strconv.Itoa(len(risk.WriteDegradedNexuses)))
	t.add("Rings >= 80% full", strconv.Itoa(len(risk.RingsNearFull)))
	t.render(stdout)
	if len(risk.OfflineAgents) > 0 {
		fmt.Fprintf(stdout, "offline: %s\n", strings.Join(risk.OfflineAgents, ", "))
	}
	if len(risk.SuspectAgents) > 0 {
		fmt.Fprintf(stdout, "suspect: %s\n", strings.Join(risk.SuspectAgents, ", "))
	}
	if len(risk.WriteDegradedNexuses) > 0 {
		fmt.Fprintf(stdout, "write-degraded: %s\n", strings.Join(risk.WriteDegradedNexuses, ", "))
	}
	fmt.Fprintf(stdout, "note: %s\n", risk.Note)
	return nil
}

// ---------------------------------------------------------------------------
// gc status
// ---------------------------------------------------------------------------

// The coordinator's live shape (task-9) is:
//
//	{"queue":{"pending":0,"running":0,"failed":0},
//	 "oldest_pending_age_seconds":null,"bytes_repaired_last_24h":0,
//	 "throttled":null,"per_site_budget_mbps":200,"last_error":null,
//	 "shardsets":{"below_threshold":0,"below_repair_watermark":0,"unrecoverable":0}}
//
// pending and running are disjoint. Several fields are legitimately null
// ("unknown"), which must never be rendered as 0 or "no": during an incident
// "we don't know" and "all good" must not look the same.

// parseRepairStatus decodes the coordinator response into a generic map so an
// additive field from a newer coordinator is still shown, not dropped.
func parseRepairStatus(raw string) (map[string]any, error) {
	var status map[string]any
	if err := json.Unmarshal([]byte(raw), &status); err != nil {
		return nil, err
	}
	if status == nil {
		return nil, fmt.Errorf("empty body")
	}
	return status, nil
}

func printRepairStatus(w io.Writer, g *globalOpts, status map[string]any) error {
	if g.jsonOut {
		return writeJSON(w, status)
	}

	t := newTable("METRIC", "VALUE")
	shown := map[string]bool{}

	queue, _ := mapValue(status["queue"])
	shown["queue"] = true
	pending := queueField(queue, "pending")
	running := queueField(queue, "running")
	failed := queueField(queue, "failed")
	t.add("queue pending", fmtCount(pending))
	t.add("queue running", fmtCount(running))
	t.add("queue failed", fmtCount(failed))
	if n, ok := countSum(pending, running); ok {
		t.add("queue backlog (pending+running)", strconv.FormatInt(n, 10))
	} else {
		t.add("queue backlog (pending+running)", "unknown")
	}

	top := []struct {
		key   string
		label string
		fmt   func(any) string
	}{
		{"oldest_pending_age_seconds", "oldest_pending_age_seconds", fmtAgeSeconds},
		{"bytes_repaired_last_24h", "bytes_repaired_last_24h", fmtBytes},
		{"throttled", "throttled", fmtBool},
		{"per_site_budget_mbps", "per_site_budget_mbps", fmtCount},
		{"last_error", "last_error", fmtTextDash},
	}
	for _, f := range top {
		t.add(f.label, f.fmt(status[f.key]))
		shown[f.key] = true
	}

	shardsets, _ := mapValue(status["shardsets"])
	shown["shardsets"] = true
	unrecoverable := queueField(shardsets, "unrecoverable")
	t.add("shardsets.below_threshold", fmtCount(queueField(shardsets, "below_threshold")))
	t.add("shardsets.below_repair_watermark", fmtCount(queueField(shardsets, "below_repair_watermark")))
	t.add("shardsets.unrecoverable", fmtCount(unrecoverable))

	// Unknown top-level fields from a newer coordinator are still shown.
	var extra []string
	for key := range status {
		if !shown[key] {
			extra = append(extra, key)
		}
	}
	sortStrings(extra)
	for _, key := range extra {
		t.add(key, fmtRepairUnknown(status[key]))
	}

	fmt.Fprintln(w, "source: coordinator /v1/repair/status")
	t.render(w)

	// shardsets.unrecoverable is the only number that means data loss has
	// already happened (fewer than geo_n reachable groups). Make it impossible
	// to mistake for another counter.
	if n, ok := countValue(unrecoverable); ok && n > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "DATA LOSS: %d shard set(s) are UNRECOVERABLE (fewer than geo_n reachable groups). Escalate immediately: those objects cannot be reconstructed by repair.\n", n)
	}
	if n, ok := countValue(failed); ok && n > 0 {
		fmt.Fprintf(w, "WARNING: %d repair job(s) have failed; see last_error.\n", n)
	}
	return nil
}

// mapValue returns a JSON object field only when it is actually present and an
// object; null is treated as absent.
func mapValue(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok && m != nil
}

// queueField returns a nested field; missing keys and null both yield nil, and
// nil is rendered as "unknown".
func queueField(m map[string]any, key string) any {
	if m == nil {
		return nil
	}
	return m[key]
}

func fmtCount(v any) string {
	if v == nil {
		return "unknown"
	}
	switch n := v.(type) {
	case float64:
		if n == float64(int64(n)) {
			return strconv.FormatInt(int64(n), 10)
		}
		return strconv.FormatFloat(n, 'f', 2, 64)
	case int:
		return strconv.Itoa(n)
	case int64:
		return strconv.FormatInt(n, 10)
	case json.Number:
		return n.String()
	case string:
		return n
	default:
		return fmtRepairUnknown(v)
	}
}

// countValue extracts an integer when the field is known.
func countValue(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		if n == float64(int64(n)) {
			return int64(n), true
		}
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i, true
		}
	}
	return 0, false
}

// countSum adds two integer fields, reporting "unknown" when either null.
func countSum(a, b any) (int64, bool) {
	av, ok := countValue(a)
	if !ok {
		return 0, false
	}
	bv, ok := countValue(b)
	if !ok {
		return 0, false
	}
	return av + bv, true
}

// fmtAgeSeconds renders a *_seconds field as a duration; null is "unknown".
// ISO-8601-style duration strings are accepted too, for forward compatibility.
func fmtAgeSeconds(v any) string {
	if v == nil {
		return "unknown"
	}
	switch age := v.(type) {
	case string:
		if d, err := time.ParseDuration(age); err == nil {
			return d.String()
		}
		return age
	case float64:
		if age < 0 {
			return "unknown"
		}
		return (time.Duration(age * float64(time.Second))).Round(time.Second).String()
	case json.Number:
		if f, err := age.Float64(); err == nil && f >= 0 {
			return (time.Duration(f * float64(time.Second))).Round(time.Second).String()
		}
	}
	return fmtCount(v)
}

// fmtBytes renders a byte counter; null is "unknown".
func fmtBytes(v any) string {
	if v == nil {
		return "unknown"
	}
	if n, ok := countValue(v); ok {
		return humanBytes(n)
	}
	return fmtCount(v)
}

// fmtBool renders a tri-state flag: true=yes, false=no, null=unknown. A null
// must never read as "no".
func fmtBool(v any) string {
	if v == nil {
		return "unknown"
	}
	if b, ok := v.(bool); ok {
		if b {
			return "yes"
		}
		return "no"
	}
	return fmtCount(v)
}

// fmtTextDash renders free text; null means "nothing recorded" and prints "-".
func fmtTextDash(v any) string {
	if v == nil {
		return "-"
	}
	if s, ok := v.(string); ok {
		if strings.TrimSpace(s) == "" {
			return "-"
		}
		return s
	}
	return fmtRepairUnknown(v)
}

// fmtRepairUnknown renders an unexpected value (a future nested object, etc.)
// compactly instead of Go's map[...] formatting.
func fmtRepairUnknown(v any) string {
	if v == nil {
		return "unknown"
	}
	switch v.(type) {
	case map[string]any, []any:
		raw, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprint(v)
		}
		return string(raw)
	default:
		return fmt.Sprint(v)
	}
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func runGC(ctx context.Context, g *globalOpts, args []string, stdout, stderr io.Writer) error {
	pos, err := parseCommandFlags(g, "gc", args, stderr, func(fs *flag.FlagSet) {})
	if err != nil {
		return err
	}
	if g.help {
		printCommandUsage(stdout, "gc")
		return nil
	}
	if len(pos) == 0 || pos[0] != "status" {
		return usagef("usage: fass gc status")
	}
	if len(pos) > 1 {
		return usagef("gc status takes no arguments")
	}
	client, err := newAdminClient(g)
	if err != nil {
		return err
	}
	raw, err := client.getRaw(ctx, "/metrics")
	if err != nil {
		return err
	}
	counters := parseGCMetrics(raw)
	if g.jsonOut {
		return writeJSON(stdout, counters)
	}
	if len(counters) == 0 {
		fmt.Fprintln(stdout, "no deletion-GC counters exposed (start the coordinator with --gc=true); other metrics are on /metrics")
		return nil
	}
	t := newTable("METRIC", "VALUE")
	for _, name := range sortedKeys(counters) {
		t.add(strings.TrimPrefix(name, "fass_coordinator_gc_"), formatGCMetric(name, counters[name]))
	}
	t.render(stdout)
	return nil
}

// parseGCMetrics extracts the coordinator's deletion-GC counters from the
// Prometheus exposition. The coordinator registers them only when the GC
// executor is enabled, so an empty result is meaningful.
func parseGCMetrics(raw string) map[string]float64 {
	out := map[string]float64{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		if !strings.HasPrefix(name, "fass_coordinator_gc_") {
			continue
		}
		v, err := strconv.ParseFloat(fields[len(fields)-1], 64)
		if err != nil {
			continue
		}
		out[name] = v
	}
	return out
}

func sortedKeys(m map[string]float64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// insertion sort keeps the import list tiny for a handful of counters
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

// formatGCMetric renders the one timestamp-valued GC counter as a wall clock
// time and the rest as plain counts.
func formatGCMetric(name string, v float64) string {
	if strings.HasSuffix(name, "timestamp_seconds") && v > 0 {
		return humanTime(time.Unix(int64(v), 0))
	}
	return formatMetricValue(v)
}

func formatMetricValue(v float64) string {
	if v == float64(int64(v)) {
		// A timestamp is the only GC counter that is not a small integer; render
		// it as a time for humans.
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'f', 2, 64)
}
