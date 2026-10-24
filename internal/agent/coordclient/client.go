// Package coordclient is a small HTTP client for the coordinator control-plane
// endpoints an agent needs: announce, heartbeat, shard-status reporting and the
// repair job queue (docs/07-wire-api.md §1.6). It uses the frozen contract
// types directly as the wire format — they carry the snake_case JSON tags.
package coordclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fass-storage/fass/internal/agent/uid"
	"github.com/fass-storage/fass/internal/contract"
)

// Options configures the coordinator client.
type Options struct {
	// HTTPClient defaults to a client with a 10s timeout.
	HTTPClient *http.Client
	Timeout    time.Duration
	UserAgent  string
	Logger     *slog.Logger
}

// Client is an HTTP coordinator client.
type Client struct {
	base string
	hc   *http.Client
	ua   string
	log  *slog.Logger
}

// New builds a client for baseURL, which may be "host:port" or a full URL.
func New(baseURL string, opts Options) (*Client, error) {
	base, err := normalizeBase(baseURL, opts)
	if err != nil {
		return nil, err
	}
	hc := opts.HTTPClient
	if hc == nil {
		timeout := opts.Timeout
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		hc = &http.Client{Timeout: timeout}
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	ua := opts.UserAgent
	if ua == "" {
		ua = "fass-agent-coordclient/1"
	}
	return &Client{base: base, hc: hc, ua: ua, log: logger.With("component", "coordclient")}, nil
}

func normalizeBase(baseURL string, opts Options) (string, error) {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		return "", errors.New("coordclient: empty coordinator url")
	}
	if !strings.Contains(baseURL, "://") {
		scheme := "http"
		baseURL = scheme + "://" + baseURL
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("coordclient: invalid coordinator url %q", baseURL)
	}
	return strings.TrimRight(u.String(), "/"), nil
}

// Announce registers this agent (docs/04-services.md §5.4).
func (c *Client) Announce(ctx context.Context, req contract.AnnounceRequest) (contract.AnnounceResult, error) {
	var out contract.AnnounceResult
	if err := c.doJSON(ctx, http.MethodPost, "/v1/agents/announce", req, &out, http.StatusOK); err != nil {
		return contract.AnnounceResult{}, fmt.Errorf("coordclient: announce: %w", err)
	}
	return out, nil
}

// Heartbeat reports agent liveness and capacity usage.
func (c *Client) Heartbeat(ctx context.Context, hb contract.Heartbeat) error {
	if err := c.doJSON(ctx, http.MethodPost, "/v1/agents/heartbeat", hb, nil, http.StatusNoContent); err != nil {
		return fmt.Errorf("coordclient: heartbeat: %w", err)
	}
	return nil
}

// ReportShardStatus reports shards as OK, MISSING or CORRUPT.
func (c *Client) ReportShardStatus(ctx context.Context, items []contract.ShardStatus) error {
	if len(items) == 0 {
		return nil
	}
	body := struct {
		Items []contract.ShardStatus `json:"items"`
	}{Items: items}
	if err := c.doJSON(ctx, http.MethodPost, "/v1/agents/shard-status", body, nil, http.StatusNoContent); err != nil {
		return fmt.Errorf("coordclient: report shard status: %w", err)
	}
	return nil
}

// ClaimRepairJob claims one repair job. It returns (nil, nil) when the
// coordinator has no work (HTTP 204).
func (c *Client) ClaimRepairJob(ctx context.Context, worker string) (*contract.RepairJob, error) {
	body := struct {
		Worker string `json:"worker"`
	}{Worker: worker}
	var job contract.RepairJob
	err := c.doJSON(ctx, http.MethodPost, "/v1/repair/claim", body, &job, http.StatusOK)
	if errors.Is(err, errNoContent) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("coordclient: claim repair job: %w", err)
	}
	if job.JobID == "" {
		return nil, fmt.Errorf("coordclient: claim repair job: coordinator returned an empty job")
	}
	return &job, nil
}

// CommitRepair reports the outcome of a repair job. A 409 means the shard set
// generation moved and another repairer won the CAS race; the caller's written
// shards become GC orphans (docs/03 §5.4), which is not an error.
func (c *Client) CommitRepair(ctx context.Context, result contract.RepairResult) error {
	err := c.doJSON(ctx, http.MethodPost, "/v1/repair/commit", result, nil, http.StatusNoContent)
	if errors.Is(err, contract.ErrConflict) {
		return fmt.Errorf("coordclient: commit repair: %w", contract.ErrConflict)
	}
	if err != nil {
		return fmt.Errorf("coordclient: commit repair: %w", err)
	}
	return nil
}

var errNoContent = errors.New("coordclient: no content")

func (c *Client) doJSON(ctx context.Context, method, path string, in, out any, wantStatuses ...int) error {
	var reader io.Reader
	if in != nil {
		buf, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", c.ua)
	req.Header.Set("X-Fass-Request-Id", uid.New())
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("request %s %s: %w", method, path, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
	}()

	for _, want := range wantStatuses {
		if resp.StatusCode == want {
			if out != nil && resp.StatusCode != http.StatusNoContent {
				if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out); err != nil {
					return fmt.Errorf("decode response: %w", err)
				}
			}
			return nil
		}
	}
	if resp.StatusCode == http.StatusNoContent {
		return errNoContent
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	msg := strings.TrimSpace(string(body))
	if msg == "" {
		msg = http.StatusText(resp.StatusCode)
	}
	switch resp.StatusCode {
	case http.StatusNotFound:
		return fmt.Errorf("coordinator returned 404: %s: %w", msg, contract.ErrNotFound)
	case http.StatusConflict:
		return fmt.Errorf("coordinator returned 409: %s: %w", msg, contract.ErrConflict)
	case http.StatusForbidden, http.StatusUnauthorized:
		return fmt.Errorf("coordinator returned %d: %s: %w", resp.StatusCode, msg, contract.ErrForbidden)
	case http.StatusServiceUnavailable:
		return fmt.Errorf("coordinator returned 503: %s: %w", msg, contract.ErrUnavailable)
	default:
		return fmt.Errorf("coordinator returned %d: %s", resp.StatusCode, msg)
	}
}
