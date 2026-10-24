package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// The coordinator's admin surface is HTTP+JSON (docs/07-wire-api.md §1). The CLI
// intentionally mirrors the wire structs locally instead of importing
// internal/coord: an operator CLI must keep working against a coordinator built
// from a different commit, and the wire format is the contract.

// ---------------------------------------------------------------------------
// Wire types (subset of the coordinator's JSON)
// ---------------------------------------------------------------------------

type swarmInfo struct {
	ID        string    `json:"swarm_id"`
	Name      string    `json:"name"`
	Region    string    `json:"region"`
	CreatedAt time.Time `json:"created_at"`
}

type nexusInfo struct {
	ID            string    `json:"nexus_id"`
	SwarmID       string    `json:"swarm_id"`
	Name          string    `json:"name"`
	Region        string    `json:"region"`
	WriteDegraded bool      `json:"write_degraded"`
	CreatedAt     time.Time `json:"created_at"`
}

type nodeInfo struct {
	ID        string    `json:"node_id"`
	NexusID   string    `json:"nexus_id"`
	Hostname  string    `json:"hostname"`
	Rack      string    `json:"rack"`
	CreatedAt time.Time `json:"created_at"`
}

type agentInfo struct {
	ID              string    `json:"agent_id"`
	NodeID          string    `json:"node_id"`
	NexusID         string    `json:"nexus_id"`
	DiskID          string    `json:"disk_id"`
	Hostname        string    `json:"hostname"`
	Endpoint        string    `json:"endpoint"`
	Port            int       `json:"port"`
	Version         string    `json:"version"`
	CapacityBytes   int64     `json:"capacity_bytes"`
	FreeBytes       int64     `json:"free_bytes"`
	UsedBytes       int64     `json:"used_bytes"`
	ShardCount      int64     `json:"shard_count"`
	State           string    `json:"state"`
	StateChanged    time.Time `json:"state_changed"`
	LastSeen        time.Time `json:"last_seen"`
	RegisteredAt    time.Time `json:"registered_at"`
	ActivatedAt     time.Time `json:"activated_at"`
	UptimeScore     float64   `json:"uptime_score"`
	Reputation      float64   `json:"reputation"`
	LoadEWMA        float64   `json:"load_ewma"`
	BwHeadroom      float64   `json:"bw_headroom"`
	ScrubCursor     string    `json:"scrub_cursor"`
	InventoryDigest string    `json:"inventory_digest"`
	BandwidthBps    int64     `json:"bandwidth_bps"`
	RingIDs         []string  `json:"ring_ids"`
}

type ringInfo struct {
	ID        string    `json:"ring_id"`
	Name      string    `json:"name"`
	RCID      string    `json:"rc_id"`
	NexusIDs  []string  `json:"nexus_ids"`
	AgentIDs  []string  `json:"agent_ids"`
	Capacity  int64     `json:"capacity_bytes"`
	UsedBytes int64     `json:"used_bytes"`
	Epoch     int       `json:"epoch"`
	CreatedAt time.Time `json:"created_at"`
}

type rcParams struct {
	GeoN   int `json:"geo_n"`
	GeoK   int `json:"geo_k"`
	LocalN int `json:"local_n"`
	LocalK int `json:"local_k"`
}

type rcInfo struct {
	ID        string    `json:"rc_id"`
	Name      string    `json:"name"`
	Params    rcParams  `json:"params"`
	AAG       int       `json:"aag"`
	ChunkSize int       `json:"chunk_size"`
	CreatedAt time.Time `json:"created_at"`
}

// ratio is the storage overhead: (geo·local) shards stored per (geo_n·local_n)
// data shards. Flat codes are geo 1+0.
func (rc rcInfo) ratio() float64 {
	if rc.Params.GeoN <= 0 || rc.Params.LocalN <= 0 {
		return 0
	}
	return float64((rc.Params.GeoN+rc.Params.GeoK)*(rc.Params.LocalN+rc.Params.LocalK)) /
		float64(rc.Params.GeoN*rc.Params.LocalN)
}

type topologySnapshot struct {
	SnapshotID        string      `json:"snapshot_id"`
	At                time.Time   `json:"at"`
	Swarms            []swarmInfo `json:"swarms"`
	Nexuses           []nexusInfo `json:"nexuses"`
	Nodes             []nodeInfo  `json:"nodes"`
	Agents            []agentInfo `json:"agents"`
	Rings             []ringInfo  `json:"rings"`
	RedundancyClasses []rcInfo    `json:"redundancy_classes"`
}

// ---------------------------------------------------------------------------
// Admin HTTP client
// ---------------------------------------------------------------------------

type adminClient struct {
	base string
	hc   *http.Client
}

func newAdminClient(g *globalOpts) (*adminClient, error) {
	if err := validateCoordinatorURL(g.coordinator); err != nil {
		return nil, err
	}
	return &adminClient{base: strings.TrimRight(g.coordinator, "/"), hc: &http.Client{Timeout: g.timeout}}, nil
}

// apiError is a coordinator error envelope (docs/07 §1).
type apiError struct {
	Status  int
	Code    string
	Message string
}

func (e *apiError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("coordinator %d %s: %s", e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("coordinator status %d", e.Status)
}

func (c *adminClient) getJSON(ctx context.Context, path string, out any) error {
	status, body, err := c.get(ctx, path)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return decodeAPIError(status, body)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return servicef(err, "decode %s", path)
	}
	return nil
}

// getRaw returns the raw body for text endpoints (/metrics).
func (c *adminClient) getRaw(ctx context.Context, path string) (string, error) {
	status, body, err := c.get(ctx, path)
	if err != nil {
		return "", err
	}
	if status < 200 || status >= 300 {
		return "", decodeAPIError(status, body)
	}
	return string(body), nil
}

func (c *adminClient) get(ctx context.Context, path string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return 0, nil, usagef("bad coordinator URL: %v", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "fass-cli/"+version)
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, nil, servicef(err, "coordinator %s unreachable", c.base)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return 0, nil, servicef(err, "read coordinator response")
	}
	return resp.StatusCode, body, nil
}

// isNotFound reports a coordinator 404/405/501, used to fall back to derived
// views when an older coordinator does not implement an additive endpoint.
func isNotFound(err error) bool {
	var ae *apiError
	return errors.As(err, &ae) && (ae.Status == http.StatusNotFound || ae.Status == http.StatusMethodNotAllowed || ae.Status == http.StatusNotImplemented)
}

func decodeAPIError(status int, body []byte) error {
	var env struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &env) == nil && env.Error.Code != "" {
		return &apiError{Status: status, Code: env.Error.Code, Message: env.Error.Message}
	}
	msg := strings.TrimSpace(string(body))
	if len(msg) > 200 {
		msg = msg[:200] + "…"
	}
	return &apiError{Status: status, Message: msg}
}

func (c *adminClient) topology(ctx context.Context) (topologySnapshot, error) {
	var snap topologySnapshot
	if err := c.getJSON(ctx, "/v1/topology", &snap); err != nil {
		return topologySnapshot{}, err
	}
	return snap, nil
}

func (c *adminClient) health(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	if err := c.getJSON(ctx, "/healthz", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// healthcheck pings a URL and reports latency, without reusing the admin client
// (the gateway is a different service).
func healthcheck(ctx context.Context, hc *http.Client, url string) (bool, int, string) {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, 0, err.Error()
	}
	req.Header.Set("User-Agent", "fass-cli/"+version)
	resp, err := hc.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return false, 0, fmt.Sprintf("unreachable (%s)", elapsed.Round(time.Millisecond))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	detail := strings.TrimSpace(string(body))
	// Extract a status/schema hint when the service returns JSON.
	var probe map[string]any
	if json.Unmarshal(body, &probe) == nil {
		var parts []string
		for _, k := range []string{"status", "schema_version", "version", "state"} {
			if v, ok := probe[k]; ok && v != nil && v != "" {
				parts = append(parts, fmt.Sprintf("%s=%v", k, v))
			}
		}
		if len(parts) > 0 {
			detail = strings.Join(parts, " ")
		}
	}
	if len(detail) > 160 {
		detail = detail[:160] + "…"
	}
	return resp.StatusCode/100 == 2, resp.StatusCode, detail
}

// ---------------------------------------------------------------------------
// health
// ---------------------------------------------------------------------------

type healthTarget struct {
	Name      string  `json:"name"`
	URL       string  `json:"url"`
	OK        bool    `json:"ok"`
	Status    int     `json:"status_code,omitempty"`
	Detail    string  `json:"detail,omitempty"`
	LatencyMS float64 `json:"latency_ms,omitempty"`
}

func runHealth(ctx context.Context, g *globalOpts, args []string, stdout io.Writer) error {
	if len(args) != 0 {
		return usagef("health takes no arguments")
	}
	hc := &http.Client{Timeout: 5 * time.Second}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	targets := []healthTarget{}
	add := func(name, url, path string) {
		var t healthTarget
		t.Name, t.URL = name, url
		start := time.Now()
		ok, status, detail := healthcheck(ctx, hc, strings.TrimRight(url, "/")+path)
		t.OK, t.Status, t.Detail = ok, status, detail
		t.LatencyMS = float64(time.Since(start).Microseconds()) / 1000.0
		targets = append(targets, t)
	}
	add("coordinator", g.coordinator, "/healthz")
	// Probe the gateway only when the operator configured one (explicit
	// --endpoint, FASS_ENDPOINT or a profile); the built-in localhost default
	// would otherwise make `fass health` fail on coordinator-only hosts.
	if g.endpointExplicit {
		add("gateway", g.endpoint, "/healthz")
	}

	unhealthy := 0
	for _, t := range targets {
		if !t.OK {
			unhealthy++
		}
	}
	if g.jsonOut {
		if err := writeJSON(stdout, map[string]any{"ok": unhealthy == 0, "targets": targets}); err != nil {
			return err
		}
	} else {
		tbl := newTable("TARGET", "URL", "STATUS", "DETAIL", "LATENCY")
		for _, t := range targets {
			status := "ok"
			if !t.OK {
				status = "FAIL"
			} else if t.Status != 0 {
				status = fmt.Sprintf("ok (%d)", t.Status)
			}
			tbl.add(t.Name, t.URL, status, t.Detail, fmt.Sprintf("%.1fms", t.LatencyMS))
		}
		tbl.render(stdout)
	}
	if unhealthy > 0 {
		return servicef(nil, "%d of %d health target(s) unhealthy", unhealthy, len(targets))
	}
	return nil
}

// ---------------------------------------------------------------------------
// cluster status
// ---------------------------------------------------------------------------

type clusterAgentsJSON struct {
	Total   int            `json:"total"`
	ByState map[string]int `json:"by_state"`
	Items   []agentInfo    `json:"items"`
}

type clusterStatusJSON struct {
	Status            string            `json:"status"`
	Health            map[string]any    `json:"health,omitempty"`
	HealthError       string            `json:"health_error,omitempty"`
	Swarms            []swarmInfo       `json:"swarms"`
	Nexuses           []nexusInfo       `json:"nexuses"`
	Nodes             []nodeInfo        `json:"nodes"`
	Agents            clusterAgentsJSON `json:"agents"`
	Rings             []ringInfo        `json:"rings"`
	RedundancyClasses []rcInfo          `json:"redundancy_classes"`
	SnapshotAt        time.Time         `json:"snapshot_at"`
}
