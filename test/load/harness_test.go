//go:build load

// Package load is the mixed-workload load test for the PostgreSQL-backed
// coordinator. It is not part of the default suite: it starts a disposable
// PostgreSQL container, a coordinator, 12 agents and (usually) 2 gateways, then
// drives the real S3 API through pkg/sdk for ~2 minutes.
//
//	go test -tags=load -count=1 ./test/load/ -v -timeout 15m
//
// It skips cleanly when docker is unavailable or free memory is too low.
package load

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/fass-storage/fass/pkg/sdk"
)

const (
	pgContainer = "fass-load-pg"
	pgImage     = "postgres:16"
	pgPass      = "fass"
	keySeed     = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	region      = "eu-west-1"
)

type stack struct {
	t         *testing.T
	bin       string
	dir       string
	logDir    string
	dsn       string
	coordURL  string
	gateways  []string
	clients   []*sdk.Client
	procs     []*proc
	pg        *sql.DB
	memAtBoot int64
}

type proc struct {
	name string
	cmd  *exec.Cmd
	log  *os.File
	path string
}

var (
	root       string
	binDir     string
	skipReason string
)

func TestMain(m *testing.M) {
	var err error
	root, err = findRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, "load:", err)
		os.Exit(1)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		skipReason = "docker is not installed"
		os.Exit(m.Run())
	}
	if err := exec.Command("docker", "image", "inspect", pgImage).Run(); err != nil {
		if out, err := exec.Command("docker", "pull", pgImage).CombinedOutput(); err != nil {
			skipReason = "cannot use postgres:16: " + strings.TrimSpace(string(out))
			os.Exit(m.Run())
		}
	}
	tmp, err := os.MkdirTemp("", "fass-load-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, "load:", err)
		os.Exit(1)
	}
	binDir = filepath.Join(tmp, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "load:", err)
		os.Exit(1)
	}
	for _, name := range []string{"fass-coordinator", "fass-agent", "fass-gateway"} {
		cmd := exec.Command("go", "build", "-trimpath", "-o", filepath.Join(binDir, name), "./cmd/"+name)
		cmd.Dir = root
		cmd.Env = buildEnv()
		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "load: build %s: %v\n%s", name, err, out)
			os.Exit(1)
		}
	}
	code := m.Run()
	_ = exec.Command("docker", "rm", "-f", pgContainer).Run()
	_ = os.RemoveAll(tmp)
	os.Exit(code)
}

func findRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found")
		}
		dir = parent
	}
}

func buildEnv() []string {
	return append(os.Environ(),
		"GOPATH="+filepath.Join(root, ".gopath"),
		"GOMODCACHE="+filepath.Join(root, ".gopath", "pkg", "mod"),
		"GOCACHE="+filepath.Join(root, ".gocache"),
		"GOFLAGS=-mod=vendor",
	)
}

// memAvailableMB reads MemAvailable from /proc/meminfo.
func memAvailableMB() int64 {
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 1 << 20
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "MemAvailable:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if kb, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
					return kb / 1024
				}
			}
		}
	}
	return 1 << 20
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitHTTP(t *testing.T, what, url string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s (%s)", what, url)
}

func (s *stack) start(name, bin string, args ...string) {
	s.t.Helper()
	path := filepath.Join(s.logDir, name+".log")
	f, err := os.Create(path)
	if err != nil {
		s.t.Fatalf("log: %v", err)
	}
	cmd := exec.Command(bin, args...)
	cmd.Dir = s.dir
	cmd.Env = buildEnv()
	cmd.Stdout = f
	cmd.Stderr = f
	if err := cmd.Start(); err != nil {
		s.t.Fatalf("start %s: %v", name, err)
	}
	s.procs = append(s.procs, &proc{name: name, cmd: cmd, log: f, path: path})
}

func (s *stack) stop(name string) {
	for _, p := range s.procs {
		if p.name != name || p.cmd.Process == nil {
			continue
		}
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _ = p.cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(8 * time.Second):
			_ = p.cmd.Process.Kill()
			<-done
		}
		p.log.Close()
	}
}

func (s *stack) shutdown() {
	for i := len(s.procs) - 1; i >= 0; i-- {
		p := s.procs[i]
		if p.cmd.Process != nil {
			_ = p.cmd.Process.Signal(syscall.SIGTERM)
			done := make(chan struct{})
			go func() { _ = p.cmd.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(8 * time.Second):
				_ = p.cmd.Process.Kill()
				<-done
			}
			p.log.Close()
		}
	}
}

func (s *stack) tail(name string, lines int) string {
	for _, p := range s.procs {
		if p.name != name {
			continue
		}
		raw, _ := os.ReadFile(p.path)
		all := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
		if len(all) > lines {
			all = all[len(all)-lines:]
		}
		return strings.Join(all, "\n")
	}
	return "(no log)"
}

// boot starts PostgreSQL (if not already), the coordinator, 12 agents and the
// gateways, and returns the stack.
func boot(s *stack) error {
	s.t.Helper()
	if skipReason != "" {
		s.t.Skip(skipReason)
	}
	s.memAtBoot = memAvailableMB()
	if s.memAtBoot < 1500 {
		s.t.Skipf("free memory is %d MB: too low to start the load cluster without swapping", s.memAtBoot)
	}
	gatewayCount := 2
	if s.memAtBoot < 3000 {
		gatewayCount = 1
	}
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return fmt.Errorf("work dir: %w", err)
	}

	// disposable PostgreSQL with a modest footprint (task-17 capacity note).
	_ = exec.Command("docker", "rm", "-f", pgContainer).Run()
	pgPort := freePort(s.t)
	pgArgs := []string{"run", "-d", "--name", pgContainer,
		"-p", fmt.Sprintf("127.0.0.1:%d:5432", pgPort),
		"-e", "POSTGRES_PASSWORD=" + pgPass, "-e", "POSTGRES_DB=fass",
		// Server settings must come *after* the image, or docker parses them as
		// docker flags (-c is --cpu-shares).
		pgImage,
		"-c", "shared_buffers=256MB",
		"-c", "max_connections=200",
		"-c", "autovacuum_naptime=5s",
		"-c", "log_min_duration_statement=2000"}
	if out, err := exec.Command("docker", pgArgs...).CombinedOutput(); err != nil {
		s.t.Fatalf("start postgres: %v\n%s", err, out)
	}
	s.dsn = fmt.Sprintf("postgres://postgres:%s@127.0.0.1:%d/fass?sslmode=disable", pgPass, pgPort)
	deadline := time.Now().Add(90 * time.Second)
	for {
		db, err := sql.Open("pgx", s.dsn)
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			err = db.PingContext(ctx)
			cancel()
			db.Close()
			if err == nil {
				break
			}
		}
		if time.Now().After(deadline) {
			s.t.Fatalf("postgres did not start: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	pg, err := sql.Open("pgx", s.dsn)
	if err != nil {
		s.t.Fatalf("open pg: %v", err)
	}
	s.pg = pg

	coordPort := freePort(s.t)
	s.coordURL = fmt.Sprintf("http://127.0.0.1:%d", coordPort)
	s.start("coordinator", filepath.Join(s.bin, "fass-coordinator"),
		"--listen", fmt.Sprintf("127.0.0.1:%d", coordPort),
		"--data-dir", filepath.Join(s.dir, "coord-data"),
		"--dev-bootstrap",
		"--db-driver=postgres", "--db-dsn="+s.dsn, "--db-migrate-on-start=true",
		"--gc-interval=1h", "--lifecycle-interval=1h",
		"--repair-refresh-interval=1h",
		"--log-format=text",
	)
	waitHTTP(s.t, "coordinator", s.coordURL+"/healthz", 60*time.Second)
	payload, err := waitBootstrap(filepath.Join(s.dir, "coord-data", "dev-bootstrap.json"))
	if err != nil {
		return err
	}

	agentPorts := make([]int, len(payload.Agents))
	for i := range payload.Agents {
		agentPorts[i] = freePort(s.t)
	}
	for i, slot := range payload.Agents {
		s.start(fmt.Sprintf("agent-%02d", i), filepath.Join(s.bin, "fass-agent"),
			"--disk", filepath.Join(s.dir, "disks", slot.DiskID),
			"--port", fmt.Sprintf("%d", agentPorts[i]),
			"--nexus-id", slot.NexusID, "--node-id", slot.NodeID,
			"--coordinator-url", s.coordURL,
			"--secret", slot.Secret, "--insecure",
			"--hostname", "127.0.0.1",
			"--heartbeat-interval", "1s",
			"--repair=false", "--scrub=false",
			"--log-level", "warn",
		)
	}
	deadline = time.Now().Add(90 * time.Second)
	for {
		agents := s.agents()
		announced, active := 0, 0
		for _, a := range agents {
			if a.Endpoint != "" {
				announced++
			}
			if a.State == "active" {
				active++
			}
		}
		if announced == len(payload.Agents) {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("only %d/%d agents announced", announced, len(payload.Agents))
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, a := range s.agents() {
		if a.State == "pending" && a.Endpoint != "" {
			resp, err := http.Post(s.coordURL+"/v1/agents/"+a.AgentID+"/activate", "application/json", strings.NewReader("{}"))
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}
	}
	deadline = time.Now().Add(60 * time.Second)
	for {
		active := 0
		for _, a := range s.agents() {
			if a.State == "active" {
				active++
			}
		}
		if active == len(payload.Agents) {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("only %d/%d agents active", active, len(payload.Agents))
		}
		time.Sleep(100 * time.Millisecond)
	}

	for i := 0; i < gatewayCount; i++ {
		port := freePort(s.t)
		admin := freePort(s.t)
		name := fmt.Sprintf("gateway-%d", i)
		s.start(name, filepath.Join(s.bin, "fass-gateway"),
			"--listen", fmt.Sprintf("127.0.0.1:%d", port),
			"--admin-listen", fmt.Sprintf("127.0.0.1:%d", admin),
			"--coordinator", s.coordURL,
			"--region", region,
			"--chunk-size", "6291456",
			"--geo-n", "2", "--geo-k", "1", "--local-n", "3", "--local-k", "1",
			"--default-redundancy-class", "dev-rc",
			"--key-seed", keySeed,
			"--insecure",
			"--log-level", "warn", "--log-format", "text",
		)
		waitHTTP(s.t, name, fmt.Sprintf("http://127.0.0.1:%d/healthz", admin), 60*time.Second)
		endpoint := fmt.Sprintf("http://127.0.0.1:%d", port)
		s.gateways = append(s.gateways, endpoint)
		client, err := sdk.New(endpoint, region, payload.AccessKeyID, payload.Secret)
		if err != nil {
			return fmt.Errorf("sdk %s: %w", endpoint, err)
		}
		s.clients = append(s.clients, client)
	}
	return nil
}

type bootstrap struct {
	AccessKeyID string `json:"access_key_id"`
	Secret      string `json:"secret"`
	Agents      []struct {
		NexusID string `json:"nexus_id"`
		NodeID  string `json:"node_id"`
		DiskID  string `json:"disk_id"`
		Secret  string `json:"secret"`
	}
}

func waitBootstrap(path string) (bootstrap, error) {
	deadline := time.Now().Add(20 * time.Second)
	for {
		raw, err := os.ReadFile(path)
		if err == nil && len(raw) > 0 {
			var b bootstrap
			if err := json.Unmarshal(raw, &b); err != nil {
				return b, err
			}
			return b, nil
		}
		if time.Now().After(deadline) {
			return bootstrap{}, fmt.Errorf("bootstrap payload did not appear at %s", path)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

type agentRecord struct {
	AgentID  string `json:"agent_id"`
	State    string `json:"state"`
	Endpoint string `json:"endpoint"`
}

func (s *stack) agents() []agentRecord {
	resp, err := http.Get(s.coordURL + "/v1/agents")
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

// bucketConfig is the small subset needed to create/read buckets.
type bucketConfig struct {
	BucketID   string `json:"bucket_id"`
	Name       string `json:"name"`
	TenantID   string `json:"tenant_id"`
	ProjectID  string `json:"project_id"`
	Region     string `json:"region"`
	Versioning string `json:"versioning"`
	Ownership  string `json:"ownership"`
}

func (s *stack) createBucket(name string) {
	s.t.Helper()
	cfg := bucketConfig{
		Name: name, TenantID: "load-tenant", ProjectID: "load-project",
		Region: region, Ownership: "ObjectWriter",
	}
	code, body := s.coordJSON("POST", "/v1/buckets", cfg)
	if code != http.StatusCreated {
		s.t.Fatalf("create bucket %s: %d %s", name, code, body)
	}
}

// setVersioning patches a bucket to Enabled through the coordinator API.
func (s *stack) setVersioning(name string) {
	s.t.Helper()
	code, body := s.coordJSON("GET", "/v1/buckets/"+name, nil)
	if code != http.StatusOK {
		s.t.Fatalf("get bucket: %d %s", code, body)
	}
	var cfg bucketConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		s.t.Fatalf("decode bucket: %v", err)
	}
	code, body = s.coordJSON("PATCH", "/v1/buckets/"+name, map[string]string{"versioning": "Enabled"})
	if code != http.StatusOK {
		s.t.Fatalf("patch bucket: %d %s", code, body)
	}
}

func (s *stack) coordJSON(method, path string, body any) (int, []byte) {
	s.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			s.t.Fatalf("marshal: %v", err)
		}
		reader = strings.NewReader(string(raw))
	}
	req, err := http.NewRequest(method, s.coordURL+path, reader)
	if err != nil {
		s.t.Fatalf("request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		s.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

// coordMetric scrapes a single numeric value from the coordinator /metrics text.
func (s *stack) coordMetricUnused(name string) float64 {
	resp, err := http.Get(s.coordURL + "/metrics")
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var total float64 = -1
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.HasPrefix(fields[0], name) {
			if v, err := strconv.ParseFloat(fields[len(fields)-1], 64); err == nil {
				if total < 0 {
					total = 0
				}
				total += v
			}
		}
	}
	return total
}

var _ = sync.Mutex{}
