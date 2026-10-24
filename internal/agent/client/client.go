// Package client is the HTTP client for the agent shard API
// (docs/07-wire-api.md §2). It implements contract.AgentClient and adds the
// inventory/stats/scrub calls used by repair, scrub auditing and the console.
//
// Endpoints are accepted either as "host:port" (the form stored in
// contract.Slot.Endpoint) or as an explicit "http://"/"https://" URL.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/fass-storage/fass/internal/agent/shard"
	"github.com/fass-storage/fass/internal/contract"
)

// ErrChecksumMismatch is returned when a shard's payload does not match the
// checksum the agent reported for it.
var ErrChecksumMismatch = errors.New("client: shard checksum mismatch")

// Options configures the agent client.
type Options struct {
	// HTTPClient defaults to a client with a 30s timeout.
	HTTPClient *http.Client
	// Scheme is used when an endpoint is given as "host:port" (default http).
	Scheme string
	// UserAgent is sent on every request.
	UserAgent string
	// Timeout applies when HTTPClient is nil.
	Timeout time.Duration
}

// Client talks to agent shard servers over HTTP.
type Client struct {
	hc     *http.Client
	scheme string
	ua     string
}

// New returns a client with sensible defaults.
func New(opts Options) *Client {
	hc := opts.HTTPClient
	if hc == nil {
		timeout := opts.Timeout
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		hc = &http.Client{Timeout: timeout}
	}
	scheme := opts.Scheme
	if scheme == "" {
		scheme = "http"
	}
	ua := opts.UserAgent
	if ua == "" {
		ua = "fass-agent-client/1"
	}
	return &Client{hc: hc, scheme: scheme, ua: ua}
}

// PutShard implements contract.AgentClient.
func (c *Client) PutShard(ctx context.Context, endpoint string, req contract.PutShardRequest) error {
	if req.PayloadLen < 0 {
		return fmt.Errorf("client: put shard: payload length must be known on the wire")
	}
	if req.Body == nil {
		return fmt.Errorf("client: put shard: nil body")
	}
	u, err := c.shardURL(endpoint, req.ShardSetID, req.GeoGroup, req.LocalIndex)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, u, req.Body)
	if err != nil {
		return fmt.Errorf("client: build put shard request: %w", err)
	}
	httpReq.ContentLength = int64(req.PayloadLen)
	httpReq.Header.Set("Content-Type", "application/octet-stream")
	httpReq.Header.Set("X-Fass-Params", shard.ParamsHeader(req.Params))
	httpReq.Header.Set("X-Fass-Chunk-Index", strconv.Itoa(req.ChunkIndex))
	httpReq.Header.Set("X-Fass-Checksum", strconv.FormatUint(req.Checksum, 10))
	c.setCommon(httpReq)

	resp, err := c.hc.Do(httpReq)
	if err != nil {
		return fmt.Errorf("client: put shard %s/%d/%d: %w", req.ShardSetID, req.GeoGroup, req.LocalIndex, err)
	}
	defer drainClose(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return c.statusError("put shard", resp)
	}
	return nil
}

// GetShard implements contract.AgentClient. The returned reader verifies the
// payload checksum at EOF and returns ErrChecksumMismatch on mismatch.
func (c *Client) GetShard(ctx context.Context, endpoint string, id contract.ShardSetID, group, index int) (io.ReadCloser, contract.ShardInfo, error) {
	u, err := c.shardURL(endpoint, id, group, index)
	if err != nil {
		return nil, contract.ShardInfo{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, contract.ShardInfo{}, fmt.Errorf("client: build get shard request: %w", err)
	}
	c.setCommon(httpReq)

	resp, err := c.hc.Do(httpReq)
	if err != nil {
		return nil, contract.ShardInfo{}, fmt.Errorf("client: get shard %s/%d/%d: %w", id, group, index, err)
	}
	if resp.StatusCode != http.StatusOK {
		defer drainClose(resp.Body)
		return nil, contract.ShardInfo{}, c.statusError("get shard", resp)
	}

	info := contract.ShardInfo{
		ShardSetID: id,
		GeoGroup:   group,
		LocalIndex: index,
		Size:       resp.ContentLength,
	}
	var wantChecksum uint64
	verify := false
	if raw := resp.Header.Get("X-Fass-Checksum"); raw != "" {
		if v, err := strconv.ParseUint(raw, 10, 64); err == nil {
			wantChecksum, verify = v, true
			info.Checksum = v
		}
	}
	if raw := resp.Header.Get("X-Fass-Created-At"); raw != "" {
		if ts, err := time.Parse(time.RFC3339, raw); err == nil {
			info.CreatedAt = ts
		}
	}
	var body io.ReadCloser = resp.Body
	if verify {
		body = &verifyingReader{rc: resp.Body, want: wantChecksum}
	}
	return body, info, nil
}

// DeleteShards implements contract.AgentClient. Deleting an absent shard set is
// idempotent and therefore not an error.
func (c *Client) DeleteShards(ctx context.Context, endpoint string, ids []contract.ShardSetID) error {
	for _, id := range ids {
		u, err := c.shardSetURL(endpoint, id)
		if err != nil {
			return err
		}
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
		if err != nil {
			return fmt.Errorf("client: build delete shard request: %w", err)
		}
		c.setCommon(httpReq)
		resp, err := c.hc.Do(httpReq)
		if err != nil {
			return fmt.Errorf("client: delete shard set %s: %w", id, err)
		}
		drainClose(resp.Body)
		switch resp.StatusCode {
		case http.StatusNoContent, http.StatusNotFound:
			continue
		default:
			return c.statusError("delete shard set", resp)
		}
	}
	return nil
}

// HasShards implements contract.AgentClient.
func (c *Client) HasShards(ctx context.Context, endpoint string, ids []contract.ShardSetID) ([]bool, error) {
	if len(ids) == 0 {
		return []bool{}, nil
	}
	base, err := c.baseURL(endpoint)
	if err != nil {
		return nil, err
	}
	body := struct {
		IDs []string `json:"ids"`
	}{IDs: make([]string, len(ids))}
	for i, id := range ids {
		body.IDs[i] = string(id)
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("client: encode has request: %w", err)
	}
	u := base + "/v1/shards:has"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("client: build has request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	c.setCommon(httpReq)

	resp, err := c.hc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("client: has shards: %w", err)
	}
	defer drainClose(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, c.statusError("has shards", resp)
	}
	var out struct {
		Present []bool `json:"present"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("client: decode has response: %w", err)
	}
	if len(out.Present) != len(ids) {
		return nil, fmt.Errorf("client: has response length %d, want %d", len(out.Present), len(ids))
	}
	return out.Present, nil
}

// Health implements contract.AgentClient.
func (c *Client) Health(ctx context.Context, endpoint string) error {
	base, err := c.baseURL(endpoint)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/healthz", nil)
	if err != nil {
		return fmt.Errorf("client: build health request: %w", err)
	}
	c.setCommon(httpReq)
	resp, err := c.hc.Do(httpReq)
	if err != nil {
		return fmt.Errorf("client: health %s: %w", endpoint, err)
	}
	defer drainClose(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return c.statusError("health", resp)
	}
	var out struct {
		State string `json:"state"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJSON)).Decode(&out); err != nil {
		return fmt.Errorf("client: decode health response: %w", err)
	}
	if out.State != "ready" {
		return fmt.Errorf("client: agent %s state=%q", endpoint, out.State)
	}
	return nil
}

// Inventory fetches one inventory page.
func (c *Client) Inventory(ctx context.Context, endpoint, after string, limit int) ([]contract.ShardInfo, string, error) {
	base, err := c.baseURL(endpoint)
	if err != nil {
		return nil, "", err
	}
	q := url.Values{}
	if after != "" {
		q.Set("after", after)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	u := base + "/v1/inventory"
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, "", fmt.Errorf("client: build inventory request: %w", err)
	}
	c.setCommon(httpReq)
	resp, err := c.hc.Do(httpReq)
	if err != nil {
		return nil, "", fmt.Errorf("client: inventory: %w", err)
	}
	defer drainClose(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, "", c.statusError("inventory", resp)
	}
	var out struct {
		Entries []contract.ShardInfo `json:"entries"`
		Next    string               `json:"next"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&out); err != nil {
		return nil, "", fmt.Errorf("client: decode inventory response: %w", err)
	}
	return out.Entries, out.Next, nil
}

// AgentStats mirrors the agent /v1/stats payload.
type AgentStats struct {
	FreeBytes     int64   `json:"free_bytes"`
	UsedBytes     int64   `json:"used_bytes"`
	TotalBytes    int64   `json:"total_bytes"`
	ReservedBytes int64   `json:"reserved_bytes"`
	ShardCount    int64   `json:"shard_count"`
	SetCount      int64   `json:"set_count"`
	LoadEWMA      float64 `json:"load_ewma"`
	DiskID        string  `json:"disk_id"`
	NodeID        string  `json:"node_id"`
	Version       string  `json:"version"`
	ScrubCursor   string  `json:"scrub_cursor"`
}

// Stats fetches /v1/stats from an agent.
func (c *Client) Stats(ctx context.Context, endpoint string) (AgentStats, error) {
	base, err := c.baseURL(endpoint)
	if err != nil {
		return AgentStats{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/stats", nil)
	if err != nil {
		return AgentStats{}, fmt.Errorf("client: build stats request: %w", err)
	}
	c.setCommon(httpReq)
	resp, err := c.hc.Do(httpReq)
	if err != nil {
		return AgentStats{}, fmt.Errorf("client: stats: %w", err)
	}
	defer drainClose(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return AgentStats{}, c.statusError("stats", resp)
	}
	var out AgentStats
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJSON)).Decode(&out); err != nil {
		return AgentStats{}, fmt.Errorf("client: decode stats response: %w", err)
	}
	return out, nil
}

// Scrub asks an agent to start a scrub pass (202 Accepted).
func (c *Client) Scrub(ctx context.Context, endpoint string) error {
	base, err := c.baseURL(endpoint)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/scrub", nil)
	if err != nil {
		return fmt.Errorf("client: build scrub request: %w", err)
	}
	c.setCommon(httpReq)
	resp, err := c.hc.Do(httpReq)
	if err != nil {
		return fmt.Errorf("client: scrub: %w", err)
	}
	defer drainClose(resp.Body)
	if resp.StatusCode != http.StatusAccepted {
		return c.statusError("scrub", resp)
	}
	return nil
}

// ---------------------------------------------------------------------------
// URL and error helpers
// ---------------------------------------------------------------------------

const maxJSON = 1 << 20

func (c *Client) baseURL(endpoint string) (string, error) {
	if endpoint == "" {
		return "", fmt.Errorf("client: empty endpoint")
	}
	if strings.Contains(endpoint, "://") {
		return strings.TrimRight(endpoint, "/"), nil
	}
	return c.scheme + "://" + strings.TrimRight(endpoint, "/"), nil
}

func (c *Client) shardURL(endpoint string, id contract.ShardSetID, group, index int) (string, error) {
	base, err := c.baseURL(endpoint)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/v1/shards/%s/%d/%d", base, url.PathEscape(string(id)), group, index), nil
}

func (c *Client) shardSetURL(endpoint string, id contract.ShardSetID) (string, error) {
	base, err := c.baseURL(endpoint)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/v1/shards/%s", base, url.PathEscape(string(id))), nil
}

func (c *Client) setCommon(req *http.Request) {
	req.Header.Set("User-Agent", c.ua)
	req.Header.Set("Accept", "application/json, application/octet-stream")
}

// statusError converts a non-success agent response into an error, translating
// the documented status classes into shared contract sentinels.
func (c *Client) statusError(op string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	msg := extractError(body)
	if msg == "" {
		msg = strings.TrimSpace(string(body))
	}
	if msg == "" {
		msg = http.StatusText(resp.StatusCode)
	}
	var sentinel error
	switch resp.StatusCode {
	case http.StatusNotFound:
		sentinel = contract.ErrNotFound
	case http.StatusConflict:
		sentinel = contract.ErrConflict
	case http.StatusInsufficientStorage:
		sentinel = contract.ErrInsufficientCap
	case http.StatusForbidden, http.StatusUnauthorized:
		sentinel = contract.ErrForbidden
	case http.StatusServiceUnavailable:
		sentinel = contract.ErrUnavailable
	}
	if sentinel != nil {
		return fmt.Errorf("client: %s: %s: %w", op, msg, sentinel)
	}
	return fmt.Errorf("client: %s: agent returned %d: %s", op, resp.StatusCode, msg)
}

func extractError(body []byte) string {
	var env struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return ""
	}
	if env.Error.Code == "" && env.Error.Message == "" {
		return ""
	}
	return env.Error.Code + ": " + env.Error.Message
}

func drainClose(rc io.ReadCloser) {
	if rc == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(rc, 4<<10))
	_ = rc.Close()
}

// verifyingReader checks the FASS 64-bit shard checksum when the stream ends.
type verifyingReader struct {
	rc   io.ReadCloser
	h    *shard.Hasher
	want uint64
	done bool
}

func (v *verifyingReader) Read(p []byte) (int, error) {
	if v.h == nil {
		v.h = shard.NewHasher()
	}
	n, err := v.rc.Read(p)
	if n > 0 {
		_, _ = v.h.Write(p[:n])
	}
	if err == io.EOF && !v.done {
		v.done = true
		if v.h.Sum64() != v.want {
			return n, fmt.Errorf("%w: expected %016x, computed %016x", ErrChecksumMismatch, v.want, v.h.Sum64())
		}
	}
	return n, err
}

func (v *verifyingReader) Close() error { return v.rc.Close() }

// Compile-time assertion that the client satisfies the frozen contract.
var _ contract.AgentClient = (*Client)(nil)
