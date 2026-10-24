package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// devTopology mirrors what `--dev-bootstrap` produces: 1 swarm, 3 nexuses,
// 6 nodes, 12 active agents, 1 ring, 1 RC (geo 2+1, local 3+1 = 2.0x).
func devTopology() topologySnapshot {
	snap := topologySnapshot{
		SnapshotID: "snap-1",
		At:         time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC),
		Swarms:     []swarmInfo{{ID: "dev-swarm", Name: "dev-swarm", Region: "eu-west-1"}},
	}
	for _, n := range []string{"nexus-a", "nexus-b", "nexus-c"} {
		snap.Nexuses = append(snap.Nexuses, nexusInfo{ID: n, Name: n, Region: "eu-west-1"})
	}
	for _, n := range []string{"node-a1", "node-a2", "node-b1", "node-b2", "node-c1", "node-c2"} {
		snap.Nodes = append(snap.Nodes, nodeInfo{ID: n, NexusID: "nexus-" + n[5:6], Hostname: n})
	}
	for i := 0; i < 12; i++ {
		nexus := fmt.Sprintf("nexus-%c", 'a'+i/4)
		node := fmt.Sprintf("node-%c%d", 'a'+i/4, i%4/2+1)
		snap.Agents = append(snap.Agents, agentInfo{
			ID:         fmt.Sprintf("agent-%02d", i),
			NodeID:     node,
			NexusID:    nexus,
			DiskID:     fmt.Sprintf("disk-%02d", i),
			State:      "active",
			Endpoint:   fmt.Sprintf("127.0.0.1:71%02d", i),
			LastSeen:   snap.At,
			RingIDs:    []string{"dev-ring"},
			ShardCount: int64(i),
		})
	}
	snap.Rings = []ringInfo{{
		ID: "dev-ring", Name: "dev-ring", RCID: "dev-rc",
		NexusIDs: []string{"nexus-a", "nexus-b", "nexus-c"},
		Capacity: 1 << 30, UsedBytes: 1 << 28, Epoch: 1,
	}}
	snap.RedundancyClasses = []rcInfo{{
		ID: "dev-rc", Name: "dev-rc",
		Params:    rcParams{GeoN: 2, GeoK: 1, LocalN: 3, LocalK: 1},
		AAG:       2,
		ChunkSize: 6 << 20,
		CreatedAt: snap.At,
	}}
	return snap
}

func newCoordinatorServer(t *testing.T, snap topologySnapshot, metrics string) *httptest.Server {
	t.Helper()
	if metrics == "" {
		metrics = "fass_coordinator_objects_committed_total 3\n" +
			"fass_coordinator_gc_items_completed_total 7\n" +
			"fass_coordinator_gc_sets_deleted_total 2\n"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSONForTest(w, map[string]any{"status": "ok", "schema_version": 7, "time": snap.At})
	})
	mux.HandleFunc("/v1/topology", func(w http.ResponseWriter, r *http.Request) {
		writeJSONForTest(w, snap)
	})
	mux.HandleFunc("/v1/redundancy-classes", func(w http.ResponseWriter, r *http.Request) {
		writeJSONForTest(w, map[string]any{"redundancy_classes": snap.RedundancyClasses})
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, metrics)
	})
	return httptest.NewServer(mux)
}

func writeJSONForTest(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func adminEnv(t *testing.T, coordinator string) {
	t.Helper()
	isolateEnv(t)
	t.Setenv("FASS_COORDINATOR_URL", coordinator)
}

func TestClusterStatusJSON(t *testing.T) {
	snap := devTopology()
	srv := newCoordinatorServer(t, snap, "")
	defer srv.Close()
	adminEnv(t, srv.URL)

	out, stderr, code := runCLI(t, "cluster", "status", "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var got clusterStatusJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if got.Agents.Total != 12 {
		t.Errorf("agents.total = %d, want 12", got.Agents.Total)
	}
	if got.Agents.ByState["active"] != 12 {
		t.Errorf("agents.by_state.active = %d, want 12 (%v)", got.Agents.ByState["active"], got.Agents.ByState)
	}
	if got.Status != "ok" {
		t.Errorf("status = %q, want ok", got.Status)
	}
	if len(got.RedundancyClasses) != 1 || got.RedundancyClasses[0].ratio() != 2.0 {
		t.Errorf("RC ratio = %+v", got.RedundancyClasses)
	}
	if len(got.Rings) != 1 || got.Rings[0].Capacity != 1<<30 {
		t.Errorf("rings = %+v", got.Rings)
	}
}

func TestClusterStatusHumanShowsActiveAgents(t *testing.T) {
	srv := newCoordinatorServer(t, devTopology(), "")
	defer srv.Close()
	adminEnv(t, srv.URL)

	out, stderr, code := runCLI(t, "cluster", "status")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	for _, want := range []string{"Cluster: dev-swarm", "12 total, 12 ACTIVE", "nexus-a", "dev-rc", "2.00x"} {
		if !strings.Contains(out, want) {
			t.Errorf("cluster status output missing %q\n%s", want, out)
		}
	}
}

func TestNodeLS(t *testing.T) {
	srv := newCoordinatorServer(t, devTopology(), "")
	defer srv.Close()
	adminEnv(t, srv.URL)

	out, stderr, code := runCLI(t, "node", "ls", "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var nodes []nodeJSON
	if err := json.Unmarshal([]byte(out), &nodes); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if len(nodes) != 6 {
		t.Fatalf("nodes = %d, want 6", len(nodes))
	}
	for _, n := range nodes {
		if n.Agents != 2 || n.Active != 2 {
			t.Errorf("node %s = %d agents / %d active, want 2/2", n.NodeID, n.Agents, n.Active)
		}
	}
}

func TestRCLS(t *testing.T) {
	srv := newCoordinatorServer(t, devTopology(), "")
	defer srv.Close()
	adminEnv(t, srv.URL)

	out, stderr, code := runCLI(t, "rc", "ls")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	for _, want := range []string{"dev-rc", "2+1", "3+1", "6.0 MiB", "2.00x"} {
		if !strings.Contains(out, want) {
			t.Errorf("rc ls missing %q:\n%s", want, out)
		}
	}
}

func TestHealthOK(t *testing.T) {
	srv := newCoordinatorServer(t, devTopology(), "")
	defer srv.Close()
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSONForTest(w, map[string]string{"status": "ok"})
	}))
	defer gateway.Close()
	adminEnv(t, srv.URL)

	out, stderr, code := runCLI(t, "health", "--json", "--endpoint", gateway.URL)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var got struct {
		OK      bool           `json:"ok"`
		Targets []healthTarget `json:"targets"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if !got.OK || len(got.Targets) != 2 {
		t.Fatalf("health = %+v", got)
	}
	for _, target := range got.Targets {
		if !target.OK || target.LatencyMS < 0 {
			t.Errorf("target %+v not ok", target)
		}
	}
}

func TestHealthGatewayDown(t *testing.T) {
	srv := newCoordinatorServer(t, devTopology(), "")
	defer srv.Close()
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	gwURL := gateway.URL
	gateway.Close()
	adminEnv(t, srv.URL)

	_, stderr, code := runCLI(t, "health", "--endpoint", gwURL)
	if code != 2 {
		t.Fatalf("health with a down gateway: exit %d (want 2), stderr %q", code, stderr)
	}
}

func TestRepairStatusFromCoordinator(t *testing.T) {
	snap := devTopology()
	coord := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/topology":
			writeJSONForTest(w, snap)
		case "/v1/repair/status":
			writeJSONForTest(w, map[string]any{
				"queue":                      map[string]any{"pending": 3, "running": 1, "failed": 2},
				"oldest_pending_age_seconds": 45,
				"bytes_repaired_last_24h":    3 << 20,
				"throttled":                  true,
				"per_site_budget_mbps":       200,
				"last_error":                 "shard fetch timeout: agent 3f2a",
				"shardsets":                  map[string]any{"below_threshold": 17, "below_repair_watermark": 3, "unrecoverable": 0},
				"future_field":               "kept",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer coord.Close()
	adminEnv(t, coord.URL)

	out, stderr, code := runCLI(t, "repair", "status", "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	queue, ok := got["queue"].(map[string]any)
	if !ok || queue["pending"] != 3.0 || queue["running"] != 1.0 || queue["failed"] != 2.0 {
		t.Fatalf("queue = %v", got["queue"])
	}
	if got["throttled"] != true || got["future_field"] != "kept" {
		t.Fatalf("fields dropped: %v", got)
	}

	human, _, code := runCLI(t, "repair", "status")
	if code != 0 {
		t.Fatalf("human exit %d", code)
	}
	for _, want := range []string{
		"source: coordinator /v1/repair/status",
		"queue pending", "3",
		"queue running", "1",
		"queue failed", "2",
		"queue backlog (pending+running)", "4",
		"oldest_pending_age_seconds", "45s",
		"3.0 MiB",
		"throttled", "yes",
		"shardsets.below_threshold", "17",
		"shardsets.unrecoverable", "0",
		"future_field",
	} {
		if !strings.Contains(human, want) {
			t.Errorf("human repair status missing %q:\n%s", want, human)
		}
	}
	if strings.Contains(human, "DATA LOSS") {
		t.Errorf("unexpected data-loss warning when unrecoverable=0:\n%s", human)
	}
}

func TestRepairStatusNullsAndUnrecoverable(t *testing.T) {
	coord := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/topology":
			writeJSONForTest(w, devTopology())
		case "/v1/repair/status":
			// Fresh coordinator: several fields are honestly unknown (null).
			fmt.Fprint(w, `{"queue":{"pending":0,"running":0,"failed":0},`+
				`"oldest_pending_age_seconds":null,"bytes_repaired_last_24h":0,`+
				`"throttled":null,"per_site_budget_mbps":200,"last_error":null,`+
				`"shardsets":{"below_threshold":0,"below_repair_watermark":0,"unrecoverable":2}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer coord.Close()
	adminEnv(t, coord.URL)

	human, _, code := runCLI(t, "repair", "status")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	// null must render as unknown/- — never as 0 or "no".
	line := func(prefix string) string {
		for _, l := range strings.Split(human, "\n") {
			if strings.HasPrefix(strings.TrimSpace(l), prefix) {
				return l
			}
		}
		return ""
	}
	if l := line("throttled"); !strings.Contains(l, "unknown") {
		t.Errorf("null throttled should render as unknown, got %q:\n%s", l, human)
	}
	if l := line("throttled"); strings.Contains(l, " no") {
		t.Errorf("null throttled must not render as 'no', got %q", l)
	}
	if l := line("oldest_pending_age_seconds"); !strings.Contains(l, "unknown") {
		t.Errorf("null oldest_pending_age_seconds should render as unknown, got %q", l)
	}
	if l := line("last_error"); l == "" || !strings.HasSuffix(strings.TrimSpace(l), "-") {
		t.Errorf("null last_error should render as '-', got %q", l)
	}
	if !strings.Contains(human, "DATA LOSS") || !strings.Contains(human, "2 shard set(s)") {
		t.Errorf("unrecoverable shard sets must be surfaced prominently:\n%s", human)
	}
}

func TestRepairStatusEmptyResponseFallsBack(t *testing.T) {
	snap := devTopology()
	coord := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/topology":
			writeJSONForTest(w, snap)
		case "/v1/repair/status":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer coord.Close()
	adminEnv(t, coord.URL)

	out, stderr, code := runCLI(t, "repair", "status", "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var got repairRiskJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("expected the derived fallback, got %q: %v", out, err)
	}
	if got.Source != "derived from /v1/topology" || got.AgentsTotal != 12 {
		t.Fatalf("fallback = %+v", got)
	}
}

func TestRepairStatusDerived(t *testing.T) {
	snap := devTopology()
	snap.Agents[0].State = "offline"
	snap.Agents[1].State = "suspect"
	snap.Nexuses[2].WriteDegraded = true
	snap.Rings[0].UsedBytes = snap.Rings[0].Capacity * 9 / 10
	srv := newCoordinatorServer(t, snap, "")
	defer srv.Close()
	adminEnv(t, srv.URL)

	out, stderr, code := runCLI(t, "repair", "status", "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var got repairRiskJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if got.AgentsOffline != 1 || len(got.OfflineAgents) != 1 {
		t.Errorf("offline = %d %v", got.AgentsOffline, got.OfflineAgents)
	}
	if got.AgentsSuspect != 1 {
		t.Errorf("suspect = %d", got.AgentsSuspect)
	}
	if len(got.WriteDegradedNexuses) != 1 || got.WriteDegradedNexuses[0] != "nexus-c" {
		t.Errorf("write-degraded = %v", got.WriteDegradedNexuses)
	}
	if len(got.RingsNearFull) != 1 || got.RingsNearFull[0].FullPct < 89 {
		t.Errorf("rings near full = %+v", got.RingsNearFull)
	}
}

func TestGCStatus(t *testing.T) {
	srv := newCoordinatorServer(t, devTopology(), "")
	defer srv.Close()
	adminEnv(t, srv.URL)

	out, stderr, code := runCLI(t, "gc", "status", "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var got map[string]float64
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if got["fass_coordinator_gc_items_completed_total"] != 7 {
		t.Fatalf("gc counters = %v", got)
	}
	if _, ok := got["fass_coordinator_objects_committed_total"]; ok {
		t.Fatalf("non-GC metric leaked into gc status: %v", got)
	}
}

func TestCoordinatorDownExitCode(t *testing.T) {
	isolateEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()
	t.Setenv("FASS_COORDINATOR_URL", url)

	for _, args := range [][]string{
		{"cluster", "status"},
		{"node", "ls"},
		{"rc", "ls"},
		{"repair", "status"},
		{"gc", "status"},
		{"health"},
	} {
		var stdout, stderr bytes.Buffer
		code := run(context.Background(), args, &stdout, &stderr)
		if code != 2 {
			t.Errorf("%v: exit %d, want 2 (stderr %q)", args, code, stderr.String())
		}
	}
}

func TestAdminSubcommandUsageErrors(t *testing.T) {
	srv := newCoordinatorServer(t, devTopology(), "")
	defer srv.Close()
	adminEnv(t, srv.URL)

	for _, args := range [][]string{
		{"cluster"},
		{"cluster", "bogus"},
		{"node"},
		{"node", "bogus"},
		{"rc"},
		{"repair"},
		{"gc"},
	} {
		var stdout, stderr bytes.Buffer
		code := run(context.Background(), args, &stdout, &stderr)
		if code != 1 {
			t.Errorf("%v: exit %d, want 1 (stderr %q)", args, code, stderr.String())
		}
	}
}

func TestHumanFormattingHelpers(t *testing.T) {
	if got := humanBytes(20 << 20); got != "20.0 MiB" {
		t.Errorf("humanBytes(20MiB) = %q", got)
	}
	if got := humanBytes(1536); got != "1.5 KiB" {
		t.Errorf("humanBytes(1536) = %q", got)
	}
	if got := humanBytes(42); got != "42 B" {
		t.Errorf("humanBytes(42) = %q", got)
	}
	if got := humanTime(time.Time{}); got != "-" {
		t.Errorf("zero time = %q", got)
	}
	if got := ringFullPct(ringInfo{Capacity: 100, UsedBytes: 25}); got != "25.0%" {
		t.Errorf("ringFullPct = %q", got)
	}
}

func TestFormatGCMetricTimestamp(t *testing.T) {
	got := formatGCMetric("fass_coordinator_gc_last_run_timestamp_seconds", 1760000000)
	if strings.Contains(got, "1760000000") || len(got) < 10 {
		t.Fatalf("timestamp metric not rendered as a time: %q", got)
	}
	if got := formatGCMetric("fass_coordinator_gc_items_completed_total", 7); got != "7" {
		t.Fatalf("counter metric = %q", got)
	}
}

func TestFormatMetricValue(t *testing.T) {
	if got := formatMetricValue(7); got != "7" {
		t.Errorf("integer metric = %q", got)
	}
	if got := formatMetricValue(1.5); got != "1.50" {
		t.Errorf("float metric = %q", got)
	}
}
