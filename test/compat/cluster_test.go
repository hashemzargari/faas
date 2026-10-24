//go:build compat

// Package compat is the S3 conformance suite for the semantics real backup
// clients depend on: listing (prefix/delimiter/encoding/pagination), versioning
// and delete markers, object lock, lifecycle expiry, tagging/ACL/ownership.
//
// It boots the real stack — coordinator (--dev-bootstrap) + 12 agents + gateway
// as subprocesses — and speaks S3 over HTTP with a SigV4 client, so every
// assertion is what a third-party SDK would observe. Run with:
//
//	go test -tags=compat -count=1 ./test/compat/
package compat

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	devKeySeed = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	region     = "eu-west-1"
)

type bootstrapPayload struct {
	AccessKeyID string `json:"access_key_id"`
	Secret      string `json:"secret"`
	Region      string `json:"region"`
	RCID        string `json:"rc_id"`
	RingID      string `json:"ring_id"`
	Bucket      string `json:"bucket"`
	Agents      []struct {
		NodeID  string `json:"node_id"`
		NexusID string `json:"nexus_id"`
		DiskID  string `json:"disk_id"`
		Secret  string `json:"secret"`
	} `json:"agents"`
}

type childProcess struct {
	name string
	cmd  *exec.Cmd
	log  *os.File
	path string
	done chan error
	mu   sync.Mutex
	dead bool
}

type cluster struct {
	t        *testing.T
	root     string
	bin      string
	dir      string
	logDir   string
	procs    []*childProcess
	coord    *childProcess
	coordURL string
	gwURL    string
	payload  bootstrapPayload
	client   *s3client
	seq      int
	// dbArgs select the persistence backend for the coordinator (empty means the
	// embedded dev store). With a PostgreSQL DSN the suite runs against a fresh
	// database created for this run, then drops it.
	dbArgs []string
}

var live *cluster

func TestMain(m *testing.M) {
	root, err := findRepoRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, "compat:", err)
		os.Exit(1)
	}
	dir, err := os.MkdirTemp("", "fass-compat-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, "compat: tempdir:", err)
		os.Exit(1)
	}
	c := &cluster{root: root, bin: filepath.Join(dir, "bin"), dir: dir, logDir: filepath.Join(dir, "logs")}
	if dsn, cleanup, err := compatPostgresDSN(); err != nil {
		fmt.Fprintln(os.Stderr, "compat: postgres:", err)
		os.Exit(1)
	} else if dsn != "" {
		defer cleanup()
		c.dbArgs = []string{"--db-driver=postgres", "--db-dsn=" + dsn, "--db-migrate-on-start=true"}
		fmt.Fprintln(os.Stderr, "compat: coordinator on PostgreSQL")
	}
	code := func() int {
		if err := c.boot(); err != nil {
			c.dumpLogs("", 60)
			fmt.Fprintln(os.Stderr, "compat: boot failed:", err)
			return 1
		}
		defer c.shutdown()
		return m.Run()
	}()
	os.RemoveAll(dir)
	os.Exit(code)
}

func findRepoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not find go.mod above %s", wd)
		}
		dir = parent
	}
}

func (c *cluster) buildEnv() []string {
	env := append([]string(nil), os.Environ()...)
	return append(env,
		"GOPATH="+filepath.Join(c.root, ".gopath"),
		"GOMODCACHE="+filepath.Join(c.root, ".gopath", "pkg", "mod"),
		"GOCACHE="+filepath.Join(c.root, ".gocache"),
		"GOFLAGS=-mod=vendor",
	)
}

func (c *cluster) buildBinaries() error {
	if err := os.MkdirAll(c.bin, 0o755); err != nil {
		return err
	}
	for _, name := range []string{"fass-coordinator", "fass-agent", "fass-gateway"} {
		cmd := exec.Command("go", "build", "-trimpath", "-o", filepath.Join(c.bin, name), "./cmd/"+name)
		cmd.Dir = c.root
		cmd.Env = c.buildEnv()
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("build %s: %w\n%s", name, err, out)
		}
	}
	return nil
}

func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// freePorts allocates n ports that are free *simultaneously*, eliminating the
// bind race where two short-lived reservations can pick the same port.
func freePorts(n int) ([]int, error) {
	listeners := make([]net.Listener, 0, n)
	ports := make([]int, 0, n)
	defer func() {
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}()
	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, ln)
		ports = append(ports, ln.Addr().(*net.TCPAddr).Port)
	}
	return ports, nil
}

func (c *cluster) boot() error {
	if err := c.buildBinaries(); err != nil {
		return err
	}
	if err := os.MkdirAll(c.logDir, 0o755); err != nil {
		return err
	}
	ports, err := freePorts(16)
	if err != nil {
		return err
	}
	coordPort := ports[0]
	agentPorts := ports[1:13]
	gwPort, adminPort := ports[13], ports[14]
	c.coordURL = fmt.Sprintf("http://127.0.0.1:%d", coordPort)
	if err := c.startCoordinatorAt(fmt.Sprintf("127.0.0.1:%d", coordPort), 0); err != nil {
		return err
	}
	if err := c.waitHTTP(c.coordURL+"/healthz", 30*time.Second); err != nil {
		return fmt.Errorf("coordinator health: %w", err)
	}
	payloadPath := filepath.Join(c.dir, "coordinator", "dev-bootstrap.json")
	raw, err := readEventually(payloadPath, 10*time.Second)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &c.payload); err != nil {
		return fmt.Errorf("decode bootstrap payload: %w", err)
	}

	// Start the 12 agents.
	for i, slot := range c.payload.Agents {
		port := agentPorts[i]
		name := fmt.Sprintf("agent-%02d", i)
		if err := c.start(name, filepath.Join(c.bin, "fass-agent"),
			"--disk", filepath.Join(c.dir, "disks", slot.DiskID),
			"--port", fmt.Sprintf("%d", port),
			"--nexus-id", slot.NexusID,
			"--node-id", slot.NodeID,
			"--coordinator-url", c.coordURL,
			"--secret", slot.Secret,
			"--insecure",
			"--hostname", "127.0.0.1",
			"--heartbeat-interval", "1s",
			"--repair=false",
			"--scrub=false",
			"--log-level", "info",
		); err != nil {
			return err
		}
	}
	if err := c.waitUntil("all 12 agents announced", 60*time.Second, func() (bool, string) {
		agents := c.agents()
		n := 0
		for _, a := range agents {
			if a.Endpoint != "" {
				n++
			}
		}
		return n == 12, fmt.Sprintf("%d/12 announced", n)
	}); err != nil {
		return err
	}
	for _, a := range c.agents() {
		if a.State == "pending" && a.Endpoint != "" {
			resp, err := http.Post(c.coordURL+"/v1/agents/"+a.AgentID+"/activate", "application/json", bytes.NewReader([]byte("{}")))
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}
	}
	if err := c.waitUntil("all 12 agents active", 30*time.Second, func() (bool, string) {
		n := 0
		for _, a := range c.agents() {
			if a.State == "active" {
				n++
			}
		}
		return n == 12, fmt.Sprintf("%d/12 active", n)
	}); err != nil {
		return err
	}

	// Gateway.
	c.gwURL = fmt.Sprintf("http://127.0.0.1:%d", gwPort)
	if err := c.start("gateway", filepath.Join(c.bin, "fass-gateway"),
		"--listen", fmt.Sprintf("127.0.0.1:%d", gwPort),
		"--admin-listen", fmt.Sprintf("127.0.0.1:%d", adminPort),
		"--coordinator", c.coordURL,
		"--region", region,
		"--chunk-size", "6291456",
		"--geo-n", "2", "--geo-k", "1",
		"--local-n", "3", "--local-k", "1",
		"--default-redundancy-class", "dev-rc",
		"--key-seed", devKeySeed,
		// Plaintext loopback listener must be requested explicitly (data-plane
		// TLS is fail-closed outside a gateway's own dev mode).
		"--insecure",
		"--log-level", "info",
		"--log-format", "text",
	); err != nil {
		return err
	}
	if err := c.waitHTTP(fmt.Sprintf("http://127.0.0.1:%d/healthz", adminPort), 30*time.Second); err != nil {
		return fmt.Errorf("gateway health: %w", err)
	}
	c.client = newS3Client(c.gwURL, c.payload.Region, c.payload.AccessKeyID, c.payload.Secret)
	live = c
	return nil
}

func (c *cluster) startCoordinatorAt(addr string, clockOffset time.Duration) error {
	args := []string{
		"--listen", addr,
		"--data-dir", filepath.Join(c.dir, "coordinator"),
		"--dev-bootstrap",
		"--heartbeat-interval", "1s",
		"--suspect-after", "3s",
		"--offline-after", "6s",
		"--gc-interval", "1h",
		"--lifecycle-interval", "200ms",
		"--log-format", "text",
	}
	args = append(args, c.dbArgs...)
	if clockOffset != 0 {
		args = append(args, "--dev-clock-offset", clockOffset.String())
	}
	p, err := c.startReturning("coordinator", filepath.Join(c.bin, "fass-coordinator"), args...)
	if err != nil {
		return err
	}
	c.coord = p
	return nil
}

// restartCoordinator stops the coordinator and starts a new one on the same data
// dir with a shifted dev clock. Dev-only by construction: --dev-clock-offset is
// ignored unless --dev-bootstrap is set (see cmd/fass-coordinator).
func (c *cluster) restartCoordinator(clockOffset time.Duration) error {
	if c.coord != nil {
		c.coord.stop()
		// Wait for the port to be released.
		for i := 0; i < 100; i++ {
			resp, err := http.Get(c.coordURL + "/healthz")
			if err != nil {
				break
			}
			resp.Body.Close()
			time.Sleep(50 * time.Millisecond)
		}
	}
	addr := strings.TrimPrefix(c.coordURL, "http://")
	if err := c.startCoordinatorAt(addr, clockOffset); err != nil {
		return err
	}
	return c.waitHTTP(c.coordURL+"/healthz", 30*time.Second)
}

// start launches a child and records it for cleanup.
func (c *cluster) start(name, bin string, args ...string) error {
	_, err := c.startReturning(name, bin, args...)
	return err
}

func (c *cluster) startReturning(name, bin string, args ...string) (*childProcess, error) {
	if err := os.MkdirAll(c.logDir, 0o755); err != nil {
		return nil, err
	}
	c.seq++
	path := filepath.Join(c.logDir, fmt.Sprintf("%s-%d.log", name, c.seq))
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(bin, args...)
	cmd.Dir = c.dir
	cmd.Stdout = f
	cmd.Stderr = f
	cmd.Env = c.buildEnv()
	if err := cmd.Start(); err != nil {
		f.Close()
		return nil, err
	}
	p := &childProcess{name: name, cmd: cmd, log: f, path: path, done: make(chan error, 1)}
	go func() { p.done <- cmd.Wait() }()
	c.procs = append(c.procs, p)
	return p, nil
}

func (p *childProcess) stop() {
	p.mu.Lock()
	if p.dead {
		p.mu.Unlock()
		return
	}
	p.dead = true
	p.mu.Unlock()
	if p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(8 * time.Second):
		_ = p.cmd.Process.Kill()
		select {
		case <-p.done:
		case <-time.After(2 * time.Second):
		}
	}
	p.log.Close()
}

func (c *cluster) shutdown() {
	for i := len(c.procs) - 1; i >= 0; i-- {
		c.procs[i].stop()
	}
}

func (c *cluster) waitHTTP(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	hc := &http.Client{Timeout: 2 * time.Second}
	var last error
	for time.Now().Before(deadline) {
		resp, err := hc.Get(url)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			last = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			last = err
		}
		for _, p := range c.procs {
			p.mu.Lock()
			dead := p.dead
			state := p.cmd.ProcessState
			p.mu.Unlock()
			if !dead && state != nil && state.Exited() {
				return fmt.Errorf("%s exited: %v", p.name, state)
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s: %v", url, last)
}

func (c *cluster) waitUntil(what string, timeout time.Duration, cond func() (bool, string)) error {
	deadline := time.Now().Add(timeout)
	last := ""
	for time.Now().Before(deadline) {
		ok, detail := cond()
		if ok {
			return nil
		}
		last = detail
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s: %s", what, last)
}

type agentRecord struct {
	AgentID  string `json:"agent_id"`
	NodeID   string `json:"node_id"`
	NexusID  string `json:"nexus_id"`
	State    string `json:"state"`
	Endpoint string `json:"endpoint"`
}

func (c *cluster) agents() []agentRecord {
	resp, err := http.Get(c.coordURL + "/v1/agents")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var out struct {
		Agents []agentRecord `json:"agents"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil
	}
	return out.Agents
}

func readEventually(path string, timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(path)
		if err == nil && len(raw) > 0 {
			return raw, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil, fmt.Errorf("file %s did not appear", path)
}

// dumpLogs prints the tail of every child log (or a single named service).
func (c *cluster) dumpLogs(only string, lines int) {
	for _, p := range c.procs {
		if only != "" && p.name != only {
			continue
		}
		fmt.Fprintf(os.Stderr, "\n---- %s (last %d lines) ----\n%s\n", p.name, lines, tailFile(p.path, lines))
	}
}

func tailFile(path string, lines int) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "(no log: " + err.Error() + ")"
	}
	all := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	return strings.Join(all, "\n")
}

// failS3 fails the test with the request id and the affected service logs.
func (c *cluster) failS3(resp *s3response, format string, args ...any) {
	c.t.Helper()
	msg := fmt.Sprintf(format, args...)
	var b strings.Builder
	b.WriteString(msg)
	if resp != nil {
		fmt.Fprintf(&b, "\n  request: %s %s -> %d (request-id %s)", resp.Method, resp.URL, resp.Status, resp.RequestID)
		if len(resp.Body) > 0 {
			fmt.Fprintf(&b, "\n  body: %s", truncate(resp.Body, 600))
		}
	}
	fmt.Fprintf(&b, "\n  gateway log tail:\n%s", tailFile(c.gatewayLogPath(), 30))
	fmt.Fprintf(&b, "\n  coordinator log tail:\n%s", tailFile(c.coordinatorLogPath(), 30))
	c.t.Fatal(b.String())
}

func (c *cluster) gatewayLogPath() string {
	for i := len(c.procs) - 1; i >= 0; i-- {
		if c.procs[i].name == "gateway" {
			return c.procs[i].path
		}
	}
	return ""
}

func (c *cluster) coordinatorLogPath() string {
	for i := len(c.procs) - 1; i >= 0; i-- {
		if c.procs[i].name == "coordinator" {
			return c.procs[i].path
		}
	}
	return ""
}

// uniqueBucketName returns a short S3-legal bucket name unique to the test.
func uniqueBucketName(t *testing.T) string {
	t.Helper()
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s/%d", t.Name(), time.Now().UnixNano())))
	return fmt.Sprintf("compat-%x", sum[:8])
}

// mustStatus asserts an HTTP status and includes the S3 error body + logs.
func (c *cluster) mustStatus(resp *s3response, want int, rule string) {
	c.t.Helper()
	if resp.Status == want {
		return
	}
	var e xmlError
	_ = xmlDecode(resp.Body, &e)
	c.failS3(resp, "%s: expected HTTP %d, got %d (%s: %s)", rule, want, resp.Status, e.Code, e.Message)
}

func (c *cluster) mustErr(resp *s3response, wantStatus int, wantCode, rule string) {
	c.t.Helper()
	if resp.Status == wantStatus {
		var e xmlError
		if xmlDecode(resp.Body, &e) == nil && e.Code == wantCode {
			return
		}
	}
	var e xmlError
	_ = xmlDecode(resp.Body, &e)
	c.failS3(resp, "%s: expected %d %s, got %d %s", rule, wantStatus, wantCode, resp.Status, e.Code)
}

// compatPostgresDSN returns a DSN for a fresh database when the operator asked
// for the PostgreSQL backend (FASS_TEST_POSTGRES_DSN / FASS_COMPAT_POSTGRES_DSN).
// A fresh database per run prevents stale agents/rings from a previous run from
// polluting the topology, and is dropped afterwards.
func compatPostgresDSN() (dsn string, cleanup func(), err error) {
	base := os.Getenv("FASS_TEST_POSTGRES_DSN")
	if base == "" {
		base = os.Getenv("FASS_COMPAT_POSTGRES_DSN")
	}
	if base == "" {
		return "", func() {}, nil
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", nil, fmt.Errorf("invalid PostgreSQL DSN %q", base)
	}
	admin := *u
	admin.Path = "/postgres"
	adminDB, err := sql.Open("pgx", admin.String())
	if err != nil {
		return "", nil, fmt.Errorf("connect admin database: %w", err)
	}
	defer adminDB.Close()
	name := fmt.Sprintf("fass_compat_%d", time.Now().UnixNano())
	if _, err := adminDB.Exec("CREATE DATABASE " + name); err != nil {
		return "", nil, fmt.Errorf("create database %s: %w", name, err)
	}
	cleanup = func() {
		if db, err := sql.Open("pgx", admin.String()); err == nil {
			defer db.Close()
			_, _ = db.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)")
		}
	}
	fresh := *u
	fresh.Path = "/" + name
	return fresh.String(), cleanup, nil
}
