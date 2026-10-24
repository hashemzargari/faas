package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// bridgeCommand implements `fass bridge create|start|status|rm`: a thin client
// over the DS3 Bridge control API (docs/04 §10). The bridge carries S3
// credentials in the create body, so the endpoint is separate from --endpoint
// (which is the S3 gateway) and defaults to the local control port.
type bridgeCommand struct {
	url string
}

type bridgeClient struct {
	base string
	hc   *http.Client
}

type bridgeStatus struct {
	BridgeID  string              `json:"bridge_id"`
	Status    string              `json:"status"`
	CreatedAt time.Time           `json:"created_at"`
	Buckets   []bridgeBucketState `json:"buckets"`
	Error     string              `json:"error,omitempty"`
}

type bridgeBucketState struct {
	Name          string `json:"name"`
	ObjectsTotal  int64  `json:"objects_total"`
	Migrated      int64  `json:"migrated"`
	Failed        int64  `json:"failed"`
	Skipped       int64  `json:"skipped"`
	Bytes         int64  `json:"bytes"`
	Completed     bool   `json:"completed"`
	ListingSource string `json:"listing_source,omitempty"`
}

func runBridge(ctx context.Context, g *globalOpts, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return usagef("bridge: expected create|start|status|rm")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "create":
		return bridgeRunCreate(ctx, g, rest, stdout)
	case "start":
		return bridgeRunStart(ctx, g, rest, stdout)
	case "status":
		return bridgeRunStatus(ctx, g, rest, stdout)
	case "rm":
		return bridgeRunRemove(ctx, g, rest, stdout)
	default:
		return usagef("bridge: unknown subcommand %q (want create|start|status|rm)", sub)
	}
}

func bridgeClientFor(g *globalOpts, url string) (*bridgeClient, error) {
	if url == "" {
		url = os.Getenv("FASS_BRIDGE_URL")
	}
	if url == "" {
		url = "http://127.0.0.1:8082"
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}
	timeout := g.timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &bridgeClient{base: strings.TrimRight(url, "/"), hc: &http.Client{Timeout: timeout}}, nil
}

func (c *bridgeClient) do(ctx context.Context, method, path string, body any, out any) (int, error) {
	var rdr io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rdr = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, fmt.Errorf("bridge control API: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return resp.StatusCode, fmt.Errorf("bridge control API: %s", e.Error)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp.StatusCode, fmt.Errorf("bridge control API: decode response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

func bridgeRunCreate(ctx context.Context, g *globalOpts, args []string, stdout io.Writer) error {
	var cfg createBridgeFlags
	pos, err := parseCommandFlags(g, "bridge", args, io.Discard, func(fs *flag.FlagSet) {
		fs.StringVar(&cfg.bridgeURL, "bridge", "", "bridge control API base URL (env FASS_BRIDGE_URL)")
		fs.StringVar(&cfg.sourceEndpoint, "source-endpoint", "", "source S3 endpoint")
		fs.StringVar(&cfg.sourceRegion, "source-region", "", "source S3 region (default us-east-1)")
		fs.StringVar(&cfg.sourceAccessKey, "source-access-key", "", "source access key id")
		fs.StringVar(&cfg.sourceSecretKey, "source-secret-key", "", "source secret access key")
		fs.BoolVar(&cfg.sourcePathStyle, "source-path-style", true, "use path-style addressing for the source")
		fs.StringVar(&cfg.targetEndpoint, "target-endpoint", "", "target S3 endpoint")
		fs.StringVar(&cfg.targetRegion, "target-region", "", "target S3 region")
		fs.StringVar(&cfg.targetAccessKey, "target-access-key", "", "target access key id")
		fs.StringVar(&cfg.targetSecretKey, "target-secret-key", "", "target secret access key")
		fs.BoolVar(&cfg.targetPathStyle, "target-path-style", true, "use path-style addressing for the target")
		fs.Var(&cfg.buckets, "bucket", "bucket to migrate (repeatable)")
		fs.BoolVar(&cfg.all, "all", false, "migrate every bucket in the source account")
	})
	if err != nil {
		return err
	}
	if g.help {
		printBridgeUsage(stdout)
		return nil
	}
	_ = pos
	if cfg.all == (len(cfg.buckets) > 0) {
		return usagef("bridge create: pass either --bucket (repeatable) or --all, not both/neither")
	}
	body := map[string]any{
		"source": map[string]any{
			"endpoint": cfg.sourceEndpoint, "region": cfg.sourceRegion,
			"access_key": cfg.sourceAccessKey, "secret_key": cfg.sourceSecretKey,
			"use_path_style": cfg.sourcePathStyle,
		},
		"target": map[string]any{
			"endpoint": cfg.targetEndpoint, "region": cfg.targetRegion,
			"access_key": cfg.targetAccessKey, "secret_key": cfg.targetSecretKey,
			"use_path_style": cfg.targetPathStyle,
		},
	}
	if cfg.all {
		body["all"] = true
	} else {
		body["buckets"] = []string(cfg.buckets)
	}
	client, err := bridgeClientFor(g, cfg.bridgeURL)
	if err != nil {
		return err
	}
	var created struct {
		BridgeID string `json:"bridge_id"`
		Status   string `json:"status"`
	}
	if _, err := client.do(ctx, http.MethodPost, "/v1/bridges", body, &created); err != nil {
		return err
	}
	if g.jsonOut {
		return writeJSON(stdout, created)
	}
	fmt.Fprintf(stdout, "created bridge %s (status %s)\n", created.BridgeID, created.Status)
	return nil
}

func bridgeRunStart(ctx context.Context, g *globalOpts, args []string, stdout io.Writer) error {
	var bridgeURL string
	pos, err := parseCommandFlags(g, "bridge", args, io.Discard, func(fs *flag.FlagSet) {
		fs.StringVar(&bridgeURL, "bridge", "", "bridge control API base URL (env FASS_BRIDGE_URL)")
	})
	if err != nil {
		return err
	}
	if g.help || len(pos) != 1 {
		printBridgeUsage(stdout)
		return usagef("bridge start <bridge-id>")
	}
	client, err := bridgeClientFor(g, bridgeURL)
	if err != nil {
		return err
	}
	if _, err := client.do(ctx, http.MethodPost, "/v1/bridges/"+pos[0]+"/start", nil, nil); err != nil {
		return err
	}
	if !g.jsonOut {
		fmt.Fprintf(stdout, "bridge %s started (idempotent; poll with `fass bridge status %s`)\n", pos[0], pos[0])
	}
	return nil
}

func bridgeRunStatus(ctx context.Context, g *globalOpts, args []string, stdout io.Writer) error {
	var bridgeURL string
	pos, err := parseCommandFlags(g, "bridge", args, io.Discard, func(fs *flag.FlagSet) {
		fs.StringVar(&bridgeURL, "bridge", "", "bridge control API base URL (env FASS_BRIDGE_URL)")
	})
	if err != nil {
		return err
	}
	if g.help || len(pos) != 1 {
		printBridgeUsage(stdout)
		return usagef("bridge status <bridge-id>")
	}
	client, err := bridgeClientFor(g, bridgeURL)
	if err != nil {
		return err
	}
	var st bridgeStatus
	if _, err := client.do(ctx, http.MethodGet, "/v1/bridges/"+pos[0], nil, &st); err != nil {
		return err
	}
	if g.jsonOut {
		return writeJSON(stdout, st)
	}
	fmt.Fprintf(stdout, "bridge %s  status=%s  created=%s\n", st.BridgeID, st.Status, st.CreatedAt.UTC().Format(time.RFC3339))
	if st.Error != "" {
		fmt.Fprintf(stdout, "error: %s\n", st.Error)
	}
	fmt.Fprintf(stdout, "%-32s %8s %10s %8s %9s %14s %-10s %s\n", "BUCKET", "TOTAL", "MIGRATED", "FAILED", "SKIPPED", "BYTES", "COMPLETED", "LISTING")
	for _, b := range st.Buckets {
		fmt.Fprintf(stdout, "%-32s %8d %10d %8d %9d %14d %-10t %s\n", b.Name, b.ObjectsTotal, b.Migrated, b.Failed, b.Skipped, b.Bytes, b.Completed, b.ListingSource)
	}
	return nil
}

func bridgeRunRemove(ctx context.Context, g *globalOpts, args []string, stdout io.Writer) error {
	var bridgeURL string
	pos, err := parseCommandFlags(g, "bridge", args, io.Discard, func(fs *flag.FlagSet) {
		fs.StringVar(&bridgeURL, "bridge", "", "bridge control API base URL (env FASS_BRIDGE_URL)")
	})
	if err != nil {
		return err
	}
	if g.help || len(pos) != 1 {
		printBridgeUsage(stdout)
		return usagef("bridge rm <bridge-id>")
	}
	client, err := bridgeClientFor(g, bridgeURL)
	if err != nil {
		return err
	}
	if _, err := client.do(ctx, http.MethodDelete, "/v1/bridges/"+pos[0], nil, nil); err != nil {
		return err
	}
	if !g.jsonOut {
		fmt.Fprintf(stdout, "removed bridge %s (data on both sides untouched)\n", pos[0])
	}
	return nil
}

type createBridgeFlags struct {
	bridgeURL                        string
	sourceEndpoint, sourceRegion     string
	sourceAccessKey, sourceSecretKey string
	sourcePathStyle                  bool
	targetEndpoint, targetRegion     string
	targetAccessKey, targetSecretKey string
	targetPathStyle                  bool
	buckets                          listFlag
	all                              bool
}

type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error {
	*l = append(*l, v)
	return nil
}

func printBridgeUsage(w io.Writer) {
	fmt.Fprint(w, `usage: fass bridge <create|start|status|rm> [flags]

  create   create destination buckets and a bridge (no copy yet)
  start    begin/resume migration (idempotent)
  status   show per-bucket progress
  rm       stop tracking a bridge (never deletes data)

create flags:
  --bridge URL                 control API (env FASS_BRIDGE_URL, default :8082)
  --source-endpoint URL        source S3 endpoint
  --source-region REGION       source region (default us-east-1)
  --source-access-key ID       source access key
  --source-secret-key KEY      source secret
  --source-path-style[=true]   path-style addressing for the source
  --target-endpoint URL        target S3 endpoint
  --target-region REGION       target region
  --target-access-key ID       target access key
  --target-secret-key KEY      target secret
  --target-path-style[=true]   path-style addressing for the target
  --bucket NAME                bucket to migrate (repeatable)
  --all                        migrate every bucket in the source account
`)
}
