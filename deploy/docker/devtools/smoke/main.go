// Command fass-dev-smoke is the acceptance check for the docker-compose dev
// cluster: it waits for the twelve agents to announce, activates them through
// the coordinator API (the same explicit operator step as production), waits
// for the gateway to be ready, then does one PUT/HEAD/GET/DELETE round trip and
// compares the bytes.
//
// It is intentionally a real end-to-end check (S3 over SigV4 via pkg/sdk), not
// a "the container started" check.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fass-storage/fass/pkg/sdk"
)

type agentInfo struct {
	AgentID string `json:"agent_id"`
	State   string `json:"state"`
}

func main() {
	var (
		coordinator = flag.String("coordinator", envOr("FASS_COORDINATOR_URL", "http://coordinator:7000"), "coordinator URL")
		endpoint    = flag.String("endpoint", envOr("FASS_S3_ENDPOINT", "http://gateway:8080"), "S3 gateway endpoint")
		accessKey   = flag.String("access-key", envOr("FASS_ACCESS_KEY_ID", "dev-access-key"), "access key id")
		secretKey   = flag.String("secret-key", envOr("FASS_SECRET_ACCESS_KEY", "dev-secret-key"), "secret access key")
		region      = flag.String("region", envOr("FASS_REGION", "eu-west-1"), "region")
		bucket      = flag.String("bucket", "dev-bucket", "bucket created by --dev-bootstrap")
		wantAgents  = flag.Int("agents", 12, "expected number of agents")
		timeout     = flag.Duration("timeout", 180*time.Second, "overall timeout")
	)
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if err := runSmoke(ctx, *coordinator, *endpoint, *accessKey, *secretKey, *region, *bucket, *wantAgents); err != nil {
		fmt.Fprintf(os.Stderr, "fass-dev-smoke: FAIL: %v\n", err)
		os.Exit(1)
	}
}

func runSmoke(ctx context.Context, coordinator, endpoint, ak, sk, region, bucket string, wantAgents int) error {
	coord := strings.TrimRight(coordinator, "/")
	if err := waitHealthy(ctx, coord+"/healthz"); err != nil {
		return fmt.Errorf("coordinator not healthy: %w", err)
	}

	// 1. Activate every announced agent. Pending registrations exist in the
	//    topology before an agent process has announced, and activating one of
	//    those is a 409 AgentNotAnnounced by design: retry it on the next pass
	//    instead of failing the smoke check on a startup race.
	deadline := time.Now().Add(120 * time.Second)
	active := 0
	for {
		agents, err := fetchAgents(ctx, coord)
		if err != nil {
			return err
		}
		active = 0
		for _, a := range agents {
			if a.State == "active" {
				active++
				continue
			}
			retryable, aerr := activateAgent(ctx, coord, a.AgentID)
			if aerr != nil && !retryable {
				return fmt.Errorf("activate %s: %w", a.AgentID, aerr)
			}
		}
		if active >= wantAgents {
			fmt.Printf("smoke: %d/%d agents ACTIVE\n", active, wantAgents)
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%d/%d agents ACTIVE after timeout (declared=%d); is an agent container crashing? check `docker compose logs agent-*`",
				active, wantAgents, len(agents))
		}
		time.Sleep(time.Second)
	}

	// 3. Gateway readiness (it reports not-ready until it can reach the coordinator).
	if err := waitHealthy(ctx, strings.TrimRight(endpoint, "/")+"/healthz"); err != nil {
		return fmt.Errorf("gateway not healthy: %w", err)
	}

	// 4. One real round trip through the S3 API.
	client, err := sdk.New(endpoint, region, ak, sk, sdk.WithHTTPClient(&http.Client{Timeout: 2 * time.Minute}))
	if err != nil {
		return err
	}
	payload := make([]byte, 1<<20)
	if _, err := rand.Read(payload); err != nil {
		return err
	}
	key := "dev/smoke.bin"
	etag, err := client.PutObject(ctx, bucket, key, bytes.NewReader(payload), int64(len(payload)), "application/octet-stream")
	if err != nil {
		return fmt.Errorf("PUT s3://%s/%s: %w", bucket, key, err)
	}
	size, headETag, err := client.HeadObject(ctx, bucket, key)
	if err != nil {
		return fmt.Errorf("HEAD s3://%s/%s: %w", bucket, key, err)
	}
	if size != int64(len(payload)) {
		return fmt.Errorf("HEAD size = %d, want %d", size, len(payload))
	}
	body, err := client.GetObject(ctx, bucket, key)
	if err != nil {
		return fmt.Errorf("GET s3://%s/%s: %w", bucket, key, err)
	}
	got, readErr := io.ReadAll(body)
	_ = body.Close()
	if readErr != nil {
		return fmt.Errorf("read GET body: %w", readErr)
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("GET body differs from PUT payload (%d vs %d bytes)", len(got), len(payload))
	}
	if err := client.DeleteObject(ctx, bucket, key); err != nil {
		return fmt.Errorf("DELETE s3://%s/%s: %w", bucket, key, err)
	}
	fmt.Printf("smoke: PUT/HEAD/GET/DELETE s3://%s/%s: %d bytes byte-identical (etag %s)\n",
		bucket, key, len(payload), headETag)
	fmt.Printf("SMOKE OK: %d agents ACTIVE, S3 round trip verified (etag %s)\n", wantAgents, etag)
	return nil
}

func fetchAgents(ctx context.Context, coord string) ([]agentInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, coord+"/v1/agents", nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list agents: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("list agents: %d %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out struct {
		Agents []agentInfo `json:"agents"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode agents: %w", err)
	}
	return out.Agents, nil
}

// activateAgent activates one agent. A 409 AgentNotAnnounced is retryable: the
// pending registration exists but the agent process has not announced yet.
func activateAgent(ctx context.Context, coord, id string) (retryable bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, coord+"/v1/agents/"+id+"/activate", nil)
	if err != nil {
		return false, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return false, nil
	}
	body := strings.TrimSpace(string(raw))
	if resp.StatusCode == http.StatusConflict && strings.Contains(body, "AgentNotAnnounced") {
		return true, nil
	}
	return false, fmt.Errorf("%d %s", resp.StatusCode, body)
}

func postJSON(ctx context.Context, url string, body any) error {
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%d %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return nil
}

func waitHealthy(ctx context.Context, url string) error {
	deadline := time.Now().Add(60 * time.Second)
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s did not become healthy", url)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
