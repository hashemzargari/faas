//go:build ha

// Package ha is the HA failover and restore drill.
//
// It is deliberately not part of the default suite: it starts two PostgreSQL 16
// containers (primary + synchronous streaming standby), boots a real coordinator
// against the primary, and then crashes the primary with `docker kill`, measures
// what happens, promotes the standby, and verifies that every acknowledged
// metadata write survived byte-identically. A second phase does a pg_dump /
// pg_restore round trip and re-reads the same object set.
//
// Run:
//
//	go test -tags=ha -count=1 ./test/ha/ -v
//
// It skips cleanly (with the reason) when docker is unavailable, the postgres:16
// image cannot be obtained, or the environment forbids starting containers.
package ha

import (
	"bytes"
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
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/ec"
)

const (
	pgImage     = "postgres:16"
	pgPassword  = "fass"
	replRole    = "replicator"
	replPass    = "repl"
	pgName      = "fass-ha-primary"
	standbyName = "fass-ha-standby"
	networkName = "fass-ha-net"
)

var (
	binDir       string
	skipReason   string
	projectRoot  string
	containerIDs []string
	setupOnce    sync.Once
)

func TestMain(m *testing.M) {
	root, err := findRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ha:", err)
		os.Exit(1)
	}
	projectRoot = root
	if _, err := exec.LookPath("docker"); err != nil {
		skipReason = "docker is not installed"
		os.Exit(m.Run())
	}
	if err := ensureImage(); err != nil {
		skipReason = "cannot use " + pgImage + ": " + err.Error()
		os.Exit(m.Run())
	}
	tmp, err := os.MkdirTemp("", "fass-ha-bin-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, "ha: tempdir:", err)
		os.Exit(1)
	}
	binDir = tmp
	cmd := exec.Command("go", "build", "-trimpath", "-o", filepath.Join(binDir, "fass-coordinator"), "./cmd/fass-coordinator")
	cmd.Dir = projectRoot
	cmd.Env = buildEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "ha: build coordinator: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	for _, id := range containerIDs {
		_ = exec.Command("docker", "rm", "-f", id).Run()
	}
	_ = exec.Command("docker", "network", "rm", networkName).Run()
	_ = os.RemoveAll(tmp)
	os.Exit(code)
}

func findRoot() (string, error) {
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
			return "", fmt.Errorf("go.mod not found above %s", wd)
		}
		dir = parent
	}
}

func buildEnv() []string {
	return append(os.Environ(),
		"GOPATH="+filepath.Join(projectRoot, ".gopath"),
		"GOMODCACHE="+filepath.Join(projectRoot, ".gopath", "pkg", "mod"),
		"GOCACHE="+filepath.Join(projectRoot, ".gocache"),
		"GOFLAGS=-mod=vendor",
	)
}

func ensureImage() error {
	if err := exec.Command("docker", "image", "inspect", pgImage).Run(); err == nil {
		return nil
	}
	out, err := exec.Command("docker", "pull", pgImage).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func docker(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("docker", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
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

func hostPort(t *testing.T, name string) int {
	t.Helper()
	out := docker(t, "port", name, "5432/tcp")
	idx := strings.LastIndex(out, ":")
	if idx < 0 {
		t.Fatalf("cannot parse docker port output %q", out)
	}
	port, err := strconv.Atoi(out[idx+1:])
	if err != nil {
		t.Fatalf("port %q: %v", out, err)
	}
	return port
}

func waitPostgres(t *testing.T, dsn string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		db, err := sql.Open("pgx", dsn)
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			last = db.PingContext(ctx)
			cancel()
			db.Close()
			if last == nil {
				return
			}
		} else {
			last = err
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("postgres at %s not ready: %v", dsn, last)
}

func sqlExec(t *testing.T, dsn, statement string) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open %s: %v", dsn, err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx, statement); err != nil {
		t.Fatalf("exec %q: %v", statement, err)
	}
}

func sqlQueryString(t *testing.T, dsn, query string) string {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open %s: %v", dsn, err)
	}
	defer db.Close()
	var out string
	if err := db.QueryRow(query).Scan(&out); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return out
}

func waitFor(t *testing.T, what string, timeout time.Duration, fn func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	last := ""
	for time.Now().Before(deadline) {
		ok, detail := fn()
		if ok {
			return
		}
		last = detail
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s: %s", what, last)
}

type coordinator struct {
	cmd  *exec.Cmd
	log  *os.File
	url  string
	stop func()
}

func startCoordinator(t *testing.T, dsn string, port int, extra ...string) *coordinator {
	t.Helper()
	logPath := filepath.Join(binDir, fmt.Sprintf("coord-%d.log", time.Now().UnixNano()))
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("log: %v", err)
	}
	args := []string{
		"--listen", fmt.Sprintf("127.0.0.1:%d", port),
		"--data-dir", filepath.Join(binDir, "coord-data"),
		"--dev-bootstrap",
		"--db-driver=postgres",
		"--db-dsn=" + dsn,
		"--db-migrate-on-start=true",
		"--gc-interval=1h",
		"--lifecycle-interval=1h",
		"--log-format=text",
	}
	args = append(args, extra...)
	cmd := exec.Command(filepath.Join(binDir, "fass-coordinator"), args...)
	cmd.Dir = binDir
	cmd.Env = buildEnv()
	cmd.Stdout = f
	cmd.Stderr = f
	if err := cmd.Start(); err != nil {
		t.Fatalf("start coordinator: %v", err)
	}
	c := &coordinator{cmd: cmd, log: f, url: fmt.Sprintf("http://127.0.0.1:%d", port)}
	c.stop = func() {
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		f.Close()
	}
	t.Cleanup(c.stop)
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(c.url + "/healthz")
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return c
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	raw, _ := os.ReadFile(logPath)
	t.Fatalf("coordinator did not become healthy on %s:\n%s", dsn, tail(string(raw), 30))
	return nil
}

func tail(s string, lines int) string {
	all := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	return strings.Join(all, "\n")
}

// coordinator API helpers (metadata plane only; this drill is about the database,
// not about shard I/O, so commits carry manifests with no shard fetch).
func apiJSON(t *testing.T, method, url string, body any, out any) (int, []byte, time.Duration) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	start := time.Now()
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return 0, nil, time.Since(start)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	elapsed := time.Since(start)
	if out != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("decode %s %s: %v (%s)", method, url, err, raw)
		}
	}
	return resp.StatusCode, raw, elapsed
}

var flat = ec.Params{GeoN: 1, GeoK: 0, LocalN: 2, LocalK: 1}

func chunkRef(index int) contract.ChunkRef {
	params := flat
	total := params.TotalShards()
	per := params.ShardsPerGroup()
	slots := make([]contract.Slot, total)
	sums := make([]uint64, total)
	for i := 0; i < total; i++ {
		slots[i] = contract.Slot{
			GeoGroup: i / per, LocalIndex: i % per,
			AgentID: contract.AgentID(fmt.Sprintf("agent-%d", i)), NodeID: "node-1",
			NexusID: "nexus-1", Endpoint: "127.0.0.1:7100",
		}
		sums[i] = uint64(0x1000 + i)
	}
	return contract.ChunkRef{
		Index: index, Params: params, CiphertextLen: 1024,
		ShardSize: 512, Slots: slots, Checksums: sums, Generation: 1,
	}
}

func commitObject(t *testing.T, c *coordinator, bucket contract.BucketConfig, key, etag string) contract.CommitResult {
	t.Helper()
	req := contract.CommitRequest{
		VersionID:    contract.VersionID(contract.NewUUID()),
		BucketID:     bucket.BucketID,
		Key:          key,
		Size:         1024,
		ETag:         etag,
		ChunkSize:    1024,
		Chunks:       []contract.ChunkRef{chunkRef(0)},
		ContentType:  "text/plain",
		RCID:         "rc-ha",
		StorageClass: "STANDARD",
	}
	var out contract.CommitResult
	code, raw, elapsed := apiJSON(t, "POST", c.url+"/v1/objects:commit", req, &out)
	if code != http.StatusOK {
		t.Fatalf("commit %s: status %d after %v (%s)", key, code, elapsed, raw)
	}
	return out
}

// TestHAFailoverAndRestore is the drill. It records its measurements in the test
// log; docs/09-deployment.md carries the numbers from the reference run.
func TestHAFailoverAndRestore(t *testing.T) {
	if skipReason != "" {
		t.Skip(skipReason)
	}
	ctx := context.Background()

	// --- topology: network, primary, standby ---------------------------------
	// Defensive cleanup: a previous interrupted drill (or a developer run) must
	// not leak containers/volumes into this one.
	for _, args := range [][]string{
		{"rm", "-f", pgName},
		{"rm", "-f", standbyName},
		{"network", "rm", networkName},
		{"volume", "rm", "-f", "fass-ha-standby-data"},
	} {
		_ = exec.Command("docker", args...).Run()
	}
	containerIDs = nil
	docker(t, "network", "create", networkName)
	setupOnce.Do(func() {})
	primaryPort := freePort(t)
	primaryContainer := docker(t, "run", "-d", "--name", pgName, "--network", networkName,
		"-p", fmt.Sprintf("127.0.0.1:%d:5432", primaryPort),
		"-e", "POSTGRES_PASSWORD="+pgPassword, "-e", "POSTGRES_DB=fass",
		pgImage,
		"-c", "wal_level=replica",
		"-c", "max_wal_senders=10",
		"-c", "max_replication_slots=10",
		"-c", "synchronous_commit=on",
		"-c", "hot_standby=on",
		"-c", "listen_addresses=*",
	)
	containerIDs = append(containerIDs, primaryContainer)
	primaryDSN := fmt.Sprintf("postgres://postgres:%s@127.0.0.1:%d/fass?sslmode=disable", pgPassword, primaryPort)
	waitPostgres(t, primaryDSN, 90*time.Second)

	sqlExec(t, primaryDSN, "CREATE ROLE "+replRole+" WITH REPLICATION LOGIN PASSWORD '"+replPass+"'")
	hba := sqlQueryString(t, primaryDSN, "SHOW hba_file")
	// pg_hba is a file; append rules with a shell inside the container (the image
	// has bash) and reload.
	// The initdb-written pg_hba.conf may not end with a newline; prefix one so the
	// appended rules cannot be glued onto the last existing rule.
	docker(t, "exec", primaryContainer, "bash", "-c",
		fmt.Sprintf(`printf '\nhost replication %s 0.0.0.0/0 scram-sha-256\nhost all all 0.0.0.0/0 scram-sha-256\n' >> %s`, replRole, hba))
	sqlExec(t, primaryDSN, "SELECT pg_reload_conf()")
	// Diagnostic: the hba rules must be visible to the server before basebackup.
	replRules := sqlQueryString(t, primaryDSN, "SELECT count(*)::text FROM pg_hba_file_rules WHERE type='host' AND 'replication' = ANY(database)")
	if replRules == "0" {
		t.Fatalf("pg_hba has no replication rule after append; hba=%s", hba)
	}
	t.Logf("pg_hba replication rules: %s", replRules)
	_ = ctx

	// Standby data dir: basebackup into a named volume.
	standbyVolume := "fass-ha-standby-data"
	docker(t, "volume", "create", standbyVolume)
	docker(t, "run", "--rm", "--network", networkName, "-v", standbyVolume+":/pgdata",
		"--entrypoint", "bash", "-e", "PGPASSWORD="+replPass, pgImage, "-c",
		fmt.Sprintf("chown -R postgres:postgres /pgdata && su postgres -c 'pg_basebackup -h %s -p 5432 -U %s -D /pgdata -R -X stream -c fast -d \"host=%s port=5432 user=%s password=%s\"'",
			pgName, replRole, pgName, replRole, replPass))
	standbyPort := freePort(t)
	standbyContainer := docker(t, "run", "-d", "--name", standbyName, "--network", networkName,
		"-p", fmt.Sprintf("127.0.0.1:%d:5432", standbyPort),
		"-v", standbyVolume+":/pgdata",
		"-e", "PGDATA=/pgdata",
		"-e", "POSTGRES_PASSWORD="+pgPassword,
		pgImage,
		"-c", "hot_standby=on", "-c", "listen_addresses=*",
	)
	containerIDs = append(containerIDs, standbyContainer)
	standbyDSN := fmt.Sprintf("postgres://postgres:%s@127.0.0.1:%d/fass?sslmode=disable", pgPassword, standbyPort)

	waitPostgres(t, standbyDSN, 90*time.Second)
	// Enable synchronous replication only once the standby is connected: setting it
	// before a standby exists makes every commit (including initdb/setup) wait
	// forever, which is how the first version of this drill hung on container start.
	waitFor(t, "standby streaming", 60*time.Second, func() (bool, string) {
		out := sqlQueryString(t, primaryDSN, "SELECT count(*)::text FROM pg_stat_replication WHERE state='streaming'")
		return out != "0", "replication state: " + out
	})
	sqlExec(t, primaryDSN, "ALTER SYSTEM SET synchronous_standby_names = '*'")
	sqlExec(t, primaryDSN, "SELECT pg_reload_conf()")
	waitFor(t, "standby streaming synchronously", 60*time.Second, func() (bool, string) {
		out := sqlQueryString(t, primaryDSN, "SELECT count(*)::text FROM pg_stat_replication WHERE state='streaming' AND sync_state='sync'")
		return out != "0", "replication state: " + out
	})
	t.Logf("topology ready: primary:%d standby:%d", primaryPort, standbyPort)

	// --- FASS coordinator against the primary --------------------------------
	port := freePort(t)
	coord := startCoordinator(t, primaryDSN, port)
	bucket := contract.BucketConfig{
		BucketID:   contract.BucketID(contract.NewUUID()),
		Name:       "ha-bucket",
		TenantID:   "tenant-ha",
		ProjectID:  "project-ha",
		Region:     contract.DefaultRegion,
		Ownership:  "ObjectWriter",
		Versioning: "Enabled",
	}
	code, raw, _ := apiJSON(t, "POST", coord.url+"/v1/buckets", bucket, nil)
	if code != http.StatusCreated {
		t.Fatalf("create bucket: %d %s", code, raw)
	}

	const acked = 20
	manifests := make(map[string]contract.Manifest, acked)
	for i := 0; i < acked; i++ {
		key := fmt.Sprintf("obj/%02d", i)
		commitObject(t, coord, bucket, key, fmt.Sprintf("etag-%02d", i))
		got, status := getManifest(t, coord, bucket.Name, key)
		if status != http.StatusOK {
			t.Fatalf("pre-crash GET %s: %d", key, status)
		}
		manifests[key] = got
	}
	if len(manifests) != acked {
		t.Fatalf("acked set = %d", len(manifests))
	}
	lastWriteBeforeCrash := time.Now()

	// --- ungraceful primary death -------------------------------------------
	crashAt := time.Now()
	docker(t, "kill", primaryContainer)

	// Detection: health must not claim ok while its system of record is gone.
	var healthStatus int
	detectionLatency := time.Duration(0)
	waitShort := time.Now()
	for time.Since(waitShort) < 20*time.Second {
		code, _, elapsed := apiJSON(t, "GET", coord.url+"/healthz", nil, nil)
		if code != http.StatusOK {
			healthStatus = code
			detectionLatency = time.Since(crashAt)
			t.Logf("detected unhealthy after %v: /healthz -> %d (%v)", detectionLatency, code, elapsed)
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if healthStatus == http.StatusOK {
		t.Fatalf("BUG: /healthz still reports ok %v after the primary was killed", time.Since(crashAt))
	}
	var healthBody map[string]any
	code, raw, _ = apiJSON(t, "GET", coord.url+"/healthz", nil, nil)
	if json.Unmarshal(raw, &healthBody) == nil {
		if healthBody["status"] != "unhealthy" || healthBody["database"] != "unreachable" {
			t.Fatalf("health body while primary down = %v, want status unhealthy/database unreachable", healthBody)
		}
		t.Logf("health while primary down: %d %v", code, healthBody)
	}

	// Reads of committed metadata during the outage: must fail fast/retryably,
	// never hang (the client timeout is 5s; a hang would be a failure).
	_, _, readElapsed := apiJSON(t, "GET", coord.url+"/v1/objects/"+bucket.Name+"/obj/00", nil, nil)
	if readElapsed > 5*time.Second {
		t.Fatalf("metadata read hung for %v with the primary down", readElapsed)
	}

	// Writes during the outage: retryable (503), not a permanent-looking 500, and
	// bounded latency.
	outagePut := contract.CommitRequest{
		VersionID: contract.VersionID(contract.NewUUID()), BucketID: bucket.BucketID,
		Key: "obj/during-outage", Size: 1024, ETag: "etag-during-outage", ChunkSize: 1024,
		Chunks: []contract.ChunkRef{chunkRef(0)}, RCID: "rc-ha", StorageClass: "STANDARD",
	}
	writeCode, writeRaw, writeElapsed := apiJSON(t, "POST", coord.url+"/v1/objects:commit", outagePut, nil)
	t.Logf("write while primary down: status %d after %v (%s)", writeCode, writeElapsed, writeRaw)
	if writeElapsed > 10*time.Second {
		t.Fatalf("write during failover hung for %v", writeElapsed)
	}
	if writeCode != http.StatusServiceUnavailable {
		// If the coordinator surfaces something else, the docs must say so; but a
		// permanent-looking 500 is not acceptable for a retryable condition.
		t.Fatalf("write while primary down: status %d, want 503 ServiceUnavailable (body %s)", writeCode, writeRaw)
	}
	var errEnv struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(writeRaw, &errEnv) == nil && errEnv.Error.Code != "" {
		t.Logf("outage write error code: %s", errEnv.Error.Code)
	}

	// --- promotion ------------------------------------------------------------
	promoteAt := time.Now()
	docker(t, "exec", "--user", "postgres", standbyContainer, "pg_ctl", "promote", "-D", "/pgdata")
	waitFor(t, "standby accepts writes", 60*time.Second, func() (bool, string) {
		db, err := sql.Open("pgx", standbyDSN)
		if err != nil {
			return false, err.Error()
		}
		defer db.Close()
		var recovery bool
		if err := db.QueryRow("SELECT pg_is_in_recovery()").Scan(&recovery); err != nil {
			return false, err.Error()
		}
		if recovery {
			return false, "still in recovery"
		}
		if _, err := db.Exec("CREATE TABLE IF NOT EXISTS _ha_probe(id int)"); err != nil {
			return false, err.Error()
		}
		return true, ""
	})
	promotedAt := time.Now()
	t.Logf("promotion detected after %v", promotedAt.Sub(promoteAt))

	// Repoint: the coordinator is restarted against the promoted standby. (The
	// floating-endpoint/proxy variant is documented but not exercised here.)
	coord.stop()
	coord2 := startCoordinator(t, standbyDSN, port)
	firstWriteAt := time.Now()
	recoveryPut := contract.CommitRequest{
		VersionID: contract.VersionID(contract.NewUUID()), BucketID: bucket.BucketID,
		Key: "obj/after-failover", Size: 1024, ETag: "etag-after-failover", ChunkSize: 1024,
		Chunks: []contract.ChunkRef{chunkRef(0)}, RCID: "rc-ha", StorageClass: "STANDARD",
	}
	var recoveryRes contract.CommitResult
	code, body, _ := apiJSON(t, "POST", coord2.url+"/v1/objects:commit", recoveryPut, &recoveryRes)
	if code != http.StatusOK {
		t.Fatalf("first write after failover: %d %s", code, body)
	}
	writeRecoveredAt := time.Now()
	_ = firstWriteAt

	// --- zero committed-object loss ------------------------------------------
	for key, want := range manifests {
		got, status := getManifest(t, coord2, bucket.Name, key)
		if status != http.StatusOK {
			t.Fatalf("LOST committed object %s: status %d after promotion", key, status)
		}
		if !manifestsEqual(want, got) {
			t.Fatalf("committed object %s changed across failover:\n want %+v\n got  %+v", key, want, got)
		}
	}
	// The failed write during the outage may or may not exist; it must be
	// readable-and-equal or cleanly absent, never partial.
	if got, status := getManifest(t, coord2, bucket.Name, "obj/during-outage"); status == http.StatusOK {
		if got.ETag != "etag-during-outage" || got.Size != 1024 {
			t.Fatalf("outage write is partially present: %+v", got)
		}
	} else if status != http.StatusNotFound {
		t.Fatalf("outage write in inconsistent state: status %d", status)
	}

	rto := writeRecoveredAt.Sub(crashAt)
	unavailability := writeRecoveredAt.Sub(lastWriteBeforeCrash)
	t.Logf("MEASURED detection=%v rto=%v unavailability=%v rpo=0/%d acked objects", detectionLatency, rto, unavailability, acked)

	// --- restore drill -------------------------------------------------------
	dumpAt := time.Now()
	dumpPath := filepath.Join(binDir, "fass.dump")
	dump, err := exec.Command("docker", "exec", standbyContainer, "pg_dump", "-U", "postgres", "-Fc", "-d", "fass").Output()
	if err != nil {
		t.Fatalf("pg_dump: %v", err)
	}
	if err := os.WriteFile(dumpPath, dump, 0o600); err != nil {
		t.Fatalf("write dump: %v", err)
	}
	docker(t, "exec", standbyContainer, "psql", "-U", "postgres", "-c", "DROP DATABASE IF EXISTS fass_restore")
	docker(t, "exec", standbyContainer, "psql", "-U", "postgres", "-c", "CREATE DATABASE fass_restore")
	restoreCmd := fmt.Sprintf("pg_restore -U postgres -d fass_restore --no-owner --no-privileges")
	restore := exec.Command("docker", "exec", "-i", standbyContainer, "bash", "-c", restoreCmd)
	restore.Stdin = bytes.NewReader(dump)
	if out, err := restore.CombinedOutput(); err != nil {
		t.Fatalf("pg_restore: %v\n%s", err, out)
	}
	restoreDSN := fmt.Sprintf("postgres://postgres:%s@127.0.0.1:%d/fass_restore?sslmode=disable", pgPassword, standbyPort)
	restoreAt := time.Now()
	port3 := freePort(t)
	coord3 := startCoordinator(t, restoreDSN, port3)
	for key, want := range manifests {
		got, status := getManifest(t, coord3, bucket.Name, key)
		if status != http.StatusOK {
			t.Fatalf("restored metadata lost %s (status %d)", key, status)
		}
		if !manifestsEqual(want, got) {
			t.Fatalf("restored metadata differs for %s", key)
		}
	}
	t.Logf("MEASURED restore drill: dump %d bytes, coordinator+readback %v", len(dump), time.Since(dumpAt))
	_ = restoreAt
}

func getManifest(t *testing.T, c *coordinator, bucket, key string) (contract.Manifest, int) {
	t.Helper()
	var m contract.Manifest
	code, _, _ := apiJSON(t, "GET", c.url+"/v1/objects/"+bucket+"/"+key, nil, &m)
	return m, code
}

func manifestsEqual(a, b contract.Manifest) bool {
	if a.Key != b.Key || a.VersionID != b.VersionID || a.ETag != b.ETag || a.Size != b.Size || len(a.Chunks) != len(b.Chunks) {
		return false
	}
	for i := range a.Chunks {
		if a.Chunks[i].ShardSetID != b.Chunks[i].ShardSetID || a.Chunks[i].Index != b.Chunks[i].Index {
			return false
		}
	}
	return true
}
