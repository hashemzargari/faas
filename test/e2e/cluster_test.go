//go:build e2e

// Package e2e boots the real FASS stack as subprocesses and exercises the S3
// data path through pkg/sdk: coordinator (--dev-bootstrap) → 12 agents in 3
// Nexuses → gateway → agents.
//
// The headline assertion is that an object written with geo 2+1 / local 3+1
// survives the loss of a whole Nexus: after SIGKILLing every agent in nexus-c the
// object must still be readable byte-for-byte via the two surviving geo groups.
// Nothing is stubbed, faked or retried at the assertion layer.
package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/fass-storage/fass/pkg/sdk"
)

const (
	objectKey  = "e2e/object.bin"
	objectSize = 4 << 20 // 4 MiB, smaller than the 6 MiB dev chunk
	// devKeySeed is a fixed 32-byte hex seed, valid only for this test cluster.
	devKeySeed = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
)

// bootstrapPayload mirrors fass-coordinator's FASS_DEV_BOOTSTRAP JSON.
type bootstrapPayload struct {
	AccessKeyID string `json:"access_key_id"`
	Secret      string `json:"secret"`
	Region      string `json:"region"`
	RCID        string `json:"rc_id"`
	RingID      string `json:"ring_id"`
	Bucket      string `json:"bucket"`
	TenantID    string `json:"tenant_id"`
	ProjectID   string `json:"project_id"`
	Agents      []struct {
		NodeID  string `json:"node_id"`
		NexusID string `json:"nexus_id"`
		DiskID  string `json:"disk_id"`
		Secret  string `json:"secret"`
	} `json:"agents"`
}

// agentView is the coordinator's GET /v1/agents projection.
type agentView struct {
	AgentID  string `json:"agent_id"`
	NodeID   string `json:"node_id"`
	NexusID  string `json:"nexus_id"`
	DiskID   string `json:"disk_id"`
	State    string `json:"state"`
	Port     int    `json:"port"`
	Endpoint string `json:"endpoint"`
}

type process struct {
	name   string
	cmd    *exec.Cmd
	log    *os.File
	path   string
	done   chan error
	killed bool
}

type cluster struct {
	t        *testing.T
	root     string
	bin      string
	dir      string
	procs    []*process
	coordURL string
	gwURL    string
	payload  bootstrapPayload
}

// TestThreeNexusEndToEnd is the acceptance test: real processes, real S3 path,
// real Nexus loss.
func TestThreeNexusEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e boots 14 subprocesses; skipped in -short mode")
	}
	root := repoRoot(t)
	c := &cluster{t: t, root: root, dir: t.TempDir(), bin: filepath.Join(t.TempDir(), "bin")}
	c.buildBinaries()
	t.Cleanup(c.shutdown)

	coordPort := freePort(t)
	c.coordURL = fmt.Sprintf("http://127.0.0.1:%d", coordPort)
	dataDir := filepath.Join(c.dir, "coordinator")
	c.start("coordinator", filepath.Join(c.bin, "fass-coordinator"),
		"--listen", fmt.Sprintf("127.0.0.1:%d", coordPort),
		"--data-dir", dataDir,
		"--dev-bootstrap",
		"--heartbeat-interval", "1s",
		"--suspect-after", "3s",
		"--offline-after", "6s",
		"--gc-interval", "1h",
		"--log-format", "text",
	)
	c.waitHTTP("coordinator", c.coordURL+"/healthz", 30*time.Second)
	c.payload = c.readBootstrap(dataDir)
	if len(c.payload.Agents) != 12 {
		c.failf("bootstrap advertised %d agents, want 12 (D' topology)", len(c.payload.Agents))
	}
	if c.payload.RCID != "dev-rc" || c.payload.Bucket != "dev-bucket" || c.payload.AccessKeyID == "" {
		c.failf("unexpected bootstrap payload: rc=%q bucket=%q key=%q", c.payload.RCID, c.payload.Bucket, c.payload.AccessKeyID)
	}

	// Start the 12 agents (6 nodes × 2 disks).
	agentProcs := make(map[string]*process)
	for i, slot := range c.payload.Agents {
		if slot.Secret == "" {
			c.failf("bootstrap returned no announce secret for fresh agent slot %s/%s", slot.NodeID, slot.DiskID)
		}
		port := freePort(t)
		name := fmt.Sprintf("agent-%02d-%s", i, slot.DiskID)
		p := c.start(name, filepath.Join(c.bin, "fass-agent"),
			"--disk", filepath.Join(c.dir, "disks", slot.DiskID),
			"--port", fmt.Sprintf("%d", port),
			"--nexus-id", slot.NexusID,
			"--node-id", slot.NodeID,
			"--coordinator-url", c.coordURL,
			"--secret", slot.Secret,
			"--hostname", "127.0.0.1",
			"--heartbeat-interval", "1s",
			"--repair=false",
			"--scrub=false",
			"--log-level", "info",
		)
		agentProcs[slot.NodeID+"/"+slot.DiskID] = p
	}

	// All twelve must announce (each records its endpoint and identity); only
	// then is activation legal — activating an unannounced agent is refused by the
	// coordinator because it would brick the one-time secret.
	c.waitUntil("all 12 agents announced", 60*time.Second, func() (bool, string) {
		agents := c.listAgents()
		announced := 0
		for _, ag := range agents {
			if ag.Endpoint != "" {
				announced++
			}
		}
		return announced == 12, fmt.Sprintf("coordinator sees %d/12 announced agents (%d records)", announced, len(agents))
	})
	for _, ag := range c.listAgents() {
		if ag.State != "pending" || ag.Endpoint == "" {
			continue
		}
		c.postJSON(c.coordURL+"/v1/agents/"+ag.AgentID+"/activate", map[string]any{})
	}
	c.waitUntil("all 12 agents ACTIVE", 30*time.Second, func() (bool, string) {
		active := 0
		for _, ag := range c.listAgents() {
			if ag.State == "active" {
				active++
			}
		}
		return active == 12, fmt.Sprintf("%d/12 agents active", active)
	})

	// Gateway.
	gwPort, adminPort := freePort(t), freePort(t)
	c.gwURL = fmt.Sprintf("http://127.0.0.1:%d", gwPort)
	c.start("gateway", filepath.Join(c.bin, "fass-gateway"),
		"--listen", fmt.Sprintf("127.0.0.1:%d", gwPort),
		"--admin-listen", fmt.Sprintf("127.0.0.1:%d", adminPort),
		"--coordinator", c.coordURL,
		"--region", "eu-west-1",
		"--chunk-size", "6291456",
		"--geo-n", "2",
		"--geo-k", "1",
		"--local-n", "3",
		"--local-k", "1",
		"--default-redundancy-class", "dev-rc",
		// Deterministic dev-only tenant key seed: the gateway requires one outside
		// its own --dev mode, and a fixed seed keeps reads reproducible.
		"--key-seed", devKeySeed,
		"--log-level", "info",
		"--log-format", "text",
	)
	c.waitHTTP("gateway", fmt.Sprintf("http://127.0.0.1:%d/healthz", adminPort), 30*time.Second)

	// ---- Real S3 path through the SDK -----------------------------------
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	client, err := sdk.New(c.gwURL, c.payload.Region, c.payload.AccessKeyID, c.payload.Secret)
	if err != nil {
		c.failf("sdk.New: %v", err)
	}
	if err := client.CreateBucket(ctx, c.payload.Bucket); err != nil {
		// The bootstrap already created the bucket; an idempotent create is fine.
		if se := sdkError(err); se == nil || (se.Code != "BucketAlreadyOwnedByYou" && se.Code != "BucketAlreadyExists") {
			c.failf("CreateBucket %s: %v", c.payload.Bucket, err)
		}
	}

	payload := deterministicBytes(t, objectSize, 42)
	etag, err := client.PutObject(ctx, c.payload.Bucket, objectKey, bytes.NewReader(payload), int64(len(payload)), "application/octet-stream")
	if err != nil {
		c.dumpPlacementDiagnostics()
		c.failf("PutObject: %v", err)
	}
	if etag == "" {
		c.failf("PutObject returned an empty ETag")
	}
	t.Logf("PUT %d bytes → etag %s", len(payload), etag)

	size, headETag, err := client.HeadObject(ctx, c.payload.Bucket, objectKey)
	if err != nil {
		c.failf("HeadObject: %v", err)
	}
	if size != int64(len(payload)) || headETag == "" || strings.Trim(headETag, "\"") != strings.Trim(etag, "\"") {
		c.failf("HeadObject size/etag = %d/%q, want %d/%q", size, headETag, len(payload), etag)
	}
	c.assertObjectBytes(client, ctx, payload, "initial GET")

	objs, _, err := client.ListObjectsV2(ctx, c.payload.Bucket, "e2e/", 100)
	if err != nil {
		c.failf("ListObjectsV2: %v", err)
	}
	found := false
	for _, o := range objs {
		if o.Key == objectKey {
			found = true
			if o.Size != int64(len(payload)) {
				c.failf("listed size = %d, want %d", o.Size, len(payload))
			}
		}
	}
	if !found {
		c.failf("ListObjectsV2 did not return %s (got %d objects)", objectKey, len(objs))
	}

	rangeBody, err := client.GetObjectRange(ctx, c.payload.Bucket, objectKey, 1000, 2000)
	if err != nil {
		c.failf("GetObjectRange: %v", err)
	}
	rangeBytes, err := io.ReadAll(rangeBody)
	rangeBody.Close()
	if err != nil {
		c.failf("read range body: %v", err)
	}
	wantRange := payload[1000:2001]
	if !bytes.Equal(rangeBytes, wantRange) {
		c.failf("range GET mismatch: got %d bytes, want %d (sha256 %x vs %x)",
			len(rangeBytes), len(wantRange), sha256.Sum256(rangeBytes), sha256.Sum256(wantRange))
	}
	t.Logf("GET/HEAD/list/range all match (%d bytes, range 1000-2000)", len(payload))

	// ---- Nexus loss: SIGKILL every agent in nexus-c ----------------------
	var killed []*process
	for _, slot := range c.payload.Agents {
		if slot.NexusID != "nexus-c" {
			continue
		}
		p := agentProcs[slot.NodeID+"/"+slot.DiskID]
		if p == nil {
			c.failf("no process recorded for nexus-c slot %s/%s", slot.NodeID, slot.DiskID)
		}
		if err := p.cmd.Process.Kill(); err != nil {
			c.failf("kill %s: %v", p.name, err)
		}
		p.killed = true
		killed = append(killed, p)
	}
	if len(killed) != 4 {
		c.failf("killed %d nexus-c agents, want 4 (2 nodes × 2 disks)", len(killed))
	}
	c.waitUntil("nexus-c agents OFFLINE", 30*time.Second, func() (bool, string) {
		offline := 0
		for _, ag := range c.listAgents() {
			if ag.NexusID == "nexus-c" && ag.State == "offline" {
				offline++
			}
		}
		return offline == 4, fmt.Sprintf("%d/4 nexus-c agents offline", offline)
	})
	t.Logf("nexus-c lost: 4 agents SIGKILLed and marked OFFLINE")

	// The read must succeed through the two surviving geo groups (geo_n=2). No
	// retry loop here: a single GET is the assertion.
	c.assertObjectBytes(client, ctx, payload, "GET after whole-Nexus loss")

	// A fresh SDK client (no local state) must also agree.
	client2, err := sdk.New(c.gwURL, c.payload.Region, c.payload.AccessKeyID, c.payload.Secret)
	if err != nil {
		c.failf("second sdk.New: %v", err)
	}
	c.assertObjectBytes(client2, ctx, payload, "GET after Nexus loss via fresh client")
	t.Log("object survived whole-Nexus loss (2 of 3 geo groups)")
}

// dumpPlacementDiagnostics prints the coordinator's agent view and a raw
// placement decision; it is only called on failure to keep normal output small.
func (c *cluster) dumpPlacementDiagnostics() {
	c.t.Helper()
	if resp, err := http.Get(c.coordURL + "/v1/agents"); err == nil {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if len(raw) > 4000 {
			raw = raw[:4000]
		}
		c.t.Logf("diagnostics GET /v1/agents: %s", raw)
	}
	body, _ := json.Marshal(map[string]any{
		"shard_set_id": "diag",
		"params":       map[string]int{"geo_n": 2, "geo_k": 1, "local_n": 3, "local_k": 1},
		"chunk_bytes":  6291456,
		"tenant_id":    c.payload.TenantID,
		"project_id":   c.payload.ProjectID,
		"rc_id":        c.payload.RCID,
	})
	resp, err := http.Post(c.coordURL+"/v1/placement", "application/json", bytes.NewReader(body))
	if err != nil {
		c.t.Logf("diagnostics POST /v1/placement: %v", err)
		return
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	c.t.Logf("diagnostics POST /v1/placement status=%d body=%s", resp.StatusCode, raw)
}

// assertObjectBytes GETs the object once and requires byte-identical content.
func (c *cluster) assertObjectBytes(client *sdk.Client, ctx context.Context, want []byte, what string) {
	c.t.Helper()
	body, err := client.GetObject(ctx, c.payload.Bucket, objectKey)
	if err != nil {
		c.failf("%s: GetObject: %v", what, err)
	}
	defer body.Close()
	got, err := io.ReadAll(body)
	if err != nil {
		c.failf("%s: read body: %v", what, err)
	}
	if !bytes.Equal(got, want) {
		c.failf("%s: body mismatch: got %d bytes sha256 %x, want %d bytes sha256 %x",
			what, len(got), sha256.Sum256(got), len(want), sha256.Sum256(want))
	}
}

// ---------------------------------------------------------------------------
// Build / process plumbing
// ---------------------------------------------------------------------------

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find go.mod above %s", wd)
		}
		dir = parent
	}
}

func (c *cluster) buildEnv() []string {
	// Reproduce scripts/env.sh: the sandbox only guarantees workspace-local
	// writes, so the Go caches must live inside the repository.
	env := append([]string(nil), os.Environ()...)
	env = append(env,
		"GOPATH="+filepath.Join(c.root, ".gopath"),
		"GOMODCACHE="+filepath.Join(c.root, ".gopath", "pkg", "mod"),
		"GOCACHE="+filepath.Join(c.root, ".gocache"),
		"GOFLAGS=-mod=vendor",
	)
	return env
}

func (c *cluster) buildBinaries() {
	c.t.Helper()
	if err := os.MkdirAll(c.bin, 0o755); err != nil {
		c.t.Fatalf("mkdir bin: %v", err)
	}
	for _, name := range []string{"fass-coordinator", "fass-agent", "fass-gateway"} {
		out := filepath.Join(c.bin, name)
		cmd := exec.Command("go", "build", "-trimpath", "-o", out, "./cmd/"+name)
		cmd.Dir = c.root
		cmd.Env = c.buildEnv()
		combined, err := cmd.CombinedOutput()
		if err != nil {
			c.t.Fatalf("build %s: %v\n%s", name, err, combined)
		}
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// start launches a child process with its stdout/stderr captured to a log file.
func (c *cluster) start(name, bin string, args ...string) *process {
	c.t.Helper()
	logPath := filepath.Join(c.dir, "logs", name+".log")
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		c.t.Fatalf("mkdir logs: %v", err)
	}
	f, err := os.Create(logPath)
	if err != nil {
		c.t.Fatalf("create log %s: %v", logPath, err)
	}
	cmd := exec.Command(bin, args...)
	cmd.Dir = c.dir
	cmd.Stdout = f
	cmd.Stderr = f
	cmd.Env = c.buildEnv()
	if err := cmd.Start(); err != nil {
		f.Close()
		c.t.Fatalf("start %s: %v", name, err)
	}
	p := &process{name: name, cmd: cmd, log: f, path: logPath, done: make(chan error, 1)}
	c.procs = append(c.procs, p)
	go func() { p.done <- cmd.Wait() }()
	c.t.Logf("started %s (pid %d)", name, cmd.Process.Pid)
	return p
}

// waitHTTP polls an endpoint until it returns 200; a child exit is reported
// immediately with its log tail.
func (c *cluster) waitHTTP(name, url string, timeout time.Duration) {
	c.t.Helper()
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}
	var last string
	for time.Now().Before(deadline) {
		c.assertAlive(name)
		resp, err := client.Get(url)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
			last = fmt.Sprintf("status %d", resp.StatusCode)
		} else {
			last = err.Error()
		}
		time.Sleep(100 * time.Millisecond)
	}
	c.failf("%s did not become healthy at %s within %s (last: %s)", name, url, timeout, last)
}

// waitUntil polls cond until it reports done or the timeout expires.
func (c *cluster) waitUntil(what string, timeout time.Duration, cond func() (bool, string)) {
	c.t.Helper()
	deadline := time.Now().Add(timeout)
	last := ""
	for time.Now().Before(deadline) {
		ok, detail := cond()
		if ok {
			return
		}
		last = detail
		time.Sleep(250 * time.Millisecond)
	}
	c.failf("timed out waiting for %s: %s", what, last)
}

// assertAlive fails fast when a child process died during startup.
func (c *cluster) assertAlive(name string) {
	c.t.Helper()
	for _, p := range c.procs {
		if p.name != name {
			continue
		}
		select {
		case err := <-p.done:
			p.done <- err // restore for shutdown
			if !p.killed {
				c.failf("%s exited during startup: %v", name, err)
			}
		default:
		}
	}
}

func (c *cluster) listAgents() []agentView {
	c.t.Helper()
	resp, err := http.Get(c.coordURL + "/v1/agents")
	if err != nil {
		c.failf("GET /v1/agents: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		c.failf("read /v1/agents: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		c.failf("GET /v1/agents: status %d: %s", resp.StatusCode, raw)
	}
	var out struct {
		Agents []agentView `json:"agents"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		c.failf("decode /v1/agents: %v (%s)", err, raw)
	}
	return out.Agents
}

func (c *cluster) postJSON(url string, body any) {
	c.t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		c.failf("encode POST %s: %v", url, err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		c.failf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusCreated {
		c.failf("POST %s: status %d", url, resp.StatusCode)
	}
}

func (c *cluster) readBootstrap(dataDir string) bootstrapPayload {
	c.t.Helper()
	path := filepath.Join(dataDir, "dev-bootstrap.json")
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(path)
		if err == nil {
			var p bootstrapPayload
			if err := json.Unmarshal(raw, &p); err != nil {
				c.failf("decode %s: %v", path, err)
			}
			return p
		}
		time.Sleep(50 * time.Millisecond)
	}
	c.failf("coordinator did not write %s", path)
	return bootstrapPayload{}
}

// shutdown terminates every child, then prints the last log lines of anything
// that failed. It is registered with t.Cleanup so it runs even on t.Fatal.
func (c *cluster) shutdown() {
	for i := len(c.procs) - 1; i >= 0; i-- {
		p := c.procs[i]
		if p.cmd.Process == nil || p.killed {
			p.log.Close()
			continue
		}
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
	}
	deadline := time.Now().Add(8 * time.Second)
	for _, p := range c.procs {
		if p.cmd.Process == nil {
			continue
		}
		select {
		case <-p.done:
		case <-time.After(time.Until(deadline)):
			_ = p.cmd.Process.Kill()
			select {
			case <-p.done:
			case <-time.After(2 * time.Second):
			}
		}
	}
	if c.t.Failed() {
		for _, p := range c.procs {
			c.t.Logf("---- %s (last 50 lines) ----\n%s", p.name, tail(p.path, 50))
		}
	}
	for _, p := range c.procs {
		p.log.Close()
	}
}

// failf dumps every child's log tail and fails the test: the output names the
// service and shows why it died.
func (c *cluster) failf(format string, args ...any) {
	c.t.Helper()
	msg := fmt.Sprintf(format, args...)
	var b strings.Builder
	b.WriteString(msg)
	b.WriteString("\n")
	for _, p := range c.procs {
		fmt.Fprintf(&b, "\n---- %s (pid %v, last 50 lines) ----\n%s", p.name, pidOf(p), tail(p.path, 50))
	}
	c.t.Fatal(b.String())
}

func pidOf(p *process) any {
	if p.cmd.Process == nil {
		return "n/a"
	}
	return p.cmd.Process.Pid
}

func tail(path string, lines int) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("(cannot read %s: %v)", path, err)
	}
	all := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	return strings.Join(all, "\n")
}

func deterministicBytes(t *testing.T, n int, seed int64) []byte {
	t.Helper()
	out := make([]byte, n)
	r := rand.New(rand.NewSource(seed)) //nolint:gosec // deterministic test payload
	if _, err := io.ReadFull(r, out); err != nil {
		t.Fatalf("generate payload: %v", err)
	}
	return out
}

func sdkError(err error) *sdk.Error {
	var se *sdk.Error
	if errors.As(err, &se) {
		return se
	}
	return nil
}
