package console

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/fass-storage/fass/internal/contract"
)

// CoordinatorClient is the console's only dependency on the control plane: the
// documented HTTP+JSON API (docs/07-wire-api.md §1). The console is a separate
// process and may run on an operator laptop against a remote coordinator, so it
// must never import internal/coord or internal/gateway.
type CoordinatorClient struct {
	Base string
	HTTP *http.Client
}

// NewCoordinatorClient validates the base URL and applies a bounded timeout.
func NewCoordinatorClient(base string, hc *http.Client) (*CoordinatorClient, error) {
	if base == "" {
		return nil, fmt.Errorf("console: coordinator URL is empty")
	}
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		return nil, fmt.Errorf("console: coordinator URL %q must start with http:// or https://", base)
	}
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}
	return &CoordinatorClient{Base: strings.TrimRight(base, "/"), HTTP: hc}, nil
}

// ---------------------------------------------------------------------------
// Wire types mirrored locally (the coordinator's JSON is the contract)
// ---------------------------------------------------------------------------

type Swarm struct {
	ID        string    `json:"swarm_id"`
	Name      string    `json:"name"`
	Region    string    `json:"region"`
	CreatedAt time.Time `json:"created_at"`
}

type Nexus struct {
	ID            string    `json:"nexus_id"`
	SwarmID       string    `json:"swarm_id"`
	Name          string    `json:"name"`
	Region        string    `json:"region"`
	WriteDegraded bool      `json:"write_degraded"`
	CreatedAt     time.Time `json:"created_at"`
}

type Node struct {
	ID        string    `json:"node_id"`
	NexusID   string    `json:"nexus_id"`
	Hostname  string    `json:"hostname"`
	Rack      string    `json:"rack"`
	CreatedAt time.Time `json:"created_at"`
}

// Agent mirrors the coordinator's membership.Agent wire representation. Only
// fields the console renders are declared; unknown fields are ignored.
type Agent struct {
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
	BWHeadroom      float64   `json:"bw_headroom"`
	ScrubCursor     string    `json:"scrub_cursor"`
	InventoryDigest string    `json:"inventory_digest"`
	BandwidthBps    int64     `json:"bandwidth_bps"`
	RingIDs         []string  `json:"ring_ids"`
}

type Params struct {
	GeoN   int `json:"geo_n"`
	GeoK   int `json:"geo_k"`
	LocalN int `json:"local_n"`
	LocalK int `json:"local_k"`
}

type RedundancyClass struct {
	ID        string    `json:"rc_id"`
	Name      string    `json:"name"`
	Params    Params    `json:"params"`
	AAG       int       `json:"aag"`
	ChunkSize int       `json:"chunk_size"`
	CreatedAt time.Time `json:"created_at"`
}

// Ratio is the storage overhead of the coding profile.
func (rc RedundancyClass) Ratio() float64 {
	if rc.Params.GeoN <= 0 || rc.Params.LocalN <= 0 {
		return 0
	}
	return float64((rc.Params.GeoN+rc.Params.GeoK)*(rc.Params.LocalN+rc.Params.LocalK)) /
		float64(rc.Params.GeoN*rc.Params.LocalN)
}

type Ring struct {
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

// FullPct is the ring's used percentage (0 when capacity is unknown).
func (r Ring) FullPct() float64 {
	if r.Capacity <= 0 {
		return 0
	}
	return 100 * float64(r.UsedBytes) / float64(r.Capacity)
}

type Topology struct {
	SnapshotID        string            `json:"snapshot_id"`
	At                time.Time         `json:"at"`
	Swarms            []Swarm           `json:"swarms"`
	Nexuses           []Nexus           `json:"nexuses"`
	Nodes             []Node            `json:"nodes"`
	Agents            []Agent           `json:"agents"`
	Rings             []Ring            `json:"rings"`
	RedundancyClasses []RedundancyClass `json:"redundancy_classes"`
}

// AgentByID returns the agent with the given id.
func (t Topology) AgentByID(id string) (Agent, bool) {
	for _, a := range t.Agents {
		if a.ID == id {
			return a, true
		}
	}
	return Agent{}, false
}

// CountByState groups agents by state.
func (t Topology) CountByState() map[string]int {
	out := map[string]int{}
	for _, a := range t.Agents {
		out[strings.ToLower(a.State)]++
	}
	return out
}

// Capacity sums capacity and usage over agents that report it.
func (t Topology) Capacity() (used, total int64) {
	for _, a := range t.Agents {
		total += a.CapacityBytes
		used += a.UsedBytes
	}
	return used, total
}

// Agent returns one agent from the additive admin endpoint.
func (c *CoordinatorClient) Agent(ctx context.Context, id string) (Agent, error) {
	var ag Agent
	if err := c.getJSON(ctx, "/v1/agents/"+url.PathEscape(id), &ag); err != nil {
		return Agent{}, err
	}
	return ag, nil
}

// ---------------------------------------------------------------------------
// Endpoint methods
// ---------------------------------------------------------------------------

func (c *CoordinatorClient) Topology(ctx context.Context) (Topology, error) {
	var t Topology
	if err := c.getJSON(ctx, "/v1/topology", &t); err != nil {
		return Topology{}, err
	}
	return t, nil
}

func (c *CoordinatorClient) Health(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	if err := c.getJSON(ctx, "/healthz", &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *CoordinatorClient) Buckets(ctx context.Context) ([]contract.BucketConfig, error) {
	var out struct {
		Buckets []contract.BucketConfig `json:"buckets"`
	}
	if err := c.getJSON(ctx, "/v1/buckets", &out); err != nil {
		return nil, err
	}
	return out.Buckets, nil
}

func (c *CoordinatorClient) Bucket(ctx context.Context, bucket string) (contract.BucketConfig, error) {
	var cfg contract.BucketConfig
	if err := c.getJSON(ctx, "/v1/buckets/"+url.PathEscape(bucket), &cfg); err != nil {
		return contract.BucketConfig{}, err
	}
	return cfg, nil
}

func (c *CoordinatorClient) ListObjects(ctx context.Context, bucket, prefix, token string, maxKeys int) (contract.ListResult, error) {
	q := url.Values{}
	q.Set("bucket", bucket)
	if prefix != "" {
		q.Set("prefix", prefix)
	}
	if token != "" {
		q.Set("token", token)
	}
	if maxKeys > 0 {
		q.Set("max_keys", fmt.Sprint(maxKeys))
	}
	var result contract.ListResult
	if err := c.getJSON(ctx, "/v1/objects?"+q.Encode(), &result); err != nil {
		return contract.ListResult{}, err
	}
	return result, nil
}

func (c *CoordinatorClient) Manifest(ctx context.Context, bucket, key, version string) (contract.Manifest, error) {
	path := "/v1/objects/" + escapeBucket(bucket) + "/" + escapeKey(key)
	if version != "" {
		path += "?version=" + url.QueryEscape(version)
	}
	var m contract.Manifest
	if err := c.getJSON(ctx, path, &m); err != nil {
		return contract.Manifest{}, err
	}
	return m, nil
}

func (c *CoordinatorClient) ActivateAgent(ctx context.Context, id string) error {
	return c.postJSON(ctx, "/v1/agents/"+url.PathEscape(id)+"/activate", nil, nil)
}

func (c *CoordinatorClient) DecommissionAgent(ctx context.Context, id string, on bool) error {
	return c.postJSON(ctx, "/v1/agents/"+url.PathEscape(id)+"/decommission", map[string]bool{"on": on}, nil)
}

// Metrics fetches the Prometheus exposition (used for the "recent errors" card).
func (c *CoordinatorClient) Metrics(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Base+"/metrics", nil)
	if err != nil {
		return "", err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("coordinator: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("coordinator: /metrics returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

// APIError is a coordinator error envelope.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("coordinator %d %s: %s", e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("coordinator status %d", e.Status)
}

func (c *CoordinatorClient) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("coordinator unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return decodeAPIError(resp.StatusCode, body)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("coordinator: decode %s: %w", path, err)
	}
	return nil
}

func (c *CoordinatorClient) postJSON(ctx context.Context, path string, in, out any) error {
	var buf bytes.Buffer
	if in != nil {
		if err := json.NewEncoder(&buf).Encode(in); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Base+path, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("coordinator unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return decodeAPIError(resp.StatusCode, body)
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("coordinator: decode response: %w", err)
		}
	}
	return nil
}

func decodeAPIError(status int, body []byte) error {
	var env struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &env) == nil && env.Error.Code != "" {
		return &APIError{Status: status, Code: env.Error.Code, Message: env.Error.Message}
	}
	msg := strings.TrimSpace(string(body))
	if len(msg) > 200 {
		msg = msg[:200] + "…"
	}
	return &APIError{Status: status, Message: msg}
}

// escapeBucket path-escapes a bucket name (bucket names are DNS-safe, but be
// defensive against a malformed config coming from the coordinator).
func escapeBucket(bucket string) string { return url.PathEscape(bucket) }

// escapeKey builds a URL path for an object key while preserving "/" as the
// separator; url.URL.String then escapes spaces and control characters. The
// coordinator accepts both raw and %2F-escaped slashes (docs/07 §1.4).
func escapeKey(key string) string {
	// Escape each segment but keep slashes: path segments with '?' or '#' must
	// not change the query/fragment interpretation.
	parts := strings.Split(key, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

// sortedAgents returns agents ordered by nexus, node, then id for stable tables.
func sortedAgents(agents []Agent) []Agent {
	out := append([]Agent(nil), agents...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].NexusID != out[j].NexusID {
			return out[i].NexusID < out[j].NexusID
		}
		if out[i].NodeID != out[j].NodeID {
			return out[i].NodeID < out[j].NodeID
		}
		return out[i].ID < out[j].ID
	})
	return out
}
