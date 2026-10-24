package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fass-storage/fass/internal/agent/store"
	"github.com/fass-storage/fass/internal/contract"
)

func emptyEnv() envLookup {
	return func(string) (string, bool) { return "", false }
}

func mapEnv(m map[string]string) envLookup {
	return func(name string) (string, bool) {
		v, ok := m[name]
		return v, ok
	}
}

func TestParseFlagsDefaults(t *testing.T) {
	cfg, err := parseFlagsWithEnv(nil, emptyEnv())
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if cfg.disk != "./data" || cfg.port != 7100 {
		t.Fatalf("disk/port defaults = %q/%d", cfg.disk, cfg.port)
	}
	if cfg.coordURL != "http://127.0.0.1:7000" {
		t.Fatalf("coordinator default = %q", cfg.coordURL)
	}
	if !cfg.scrub || !cfg.repair {
		t.Fatalf("scrub/repair defaults = %v/%v", cfg.scrub, cfg.repair)
	}
	if cfg.heartbeat != 5*time.Second || cfg.shutdown != 15*time.Second {
		t.Fatalf("interval defaults = %v/%v", cfg.heartbeat, cfg.shutdown)
	}
	if cfg.reservePct != 5 || cfg.maxShard != 32<<20 {
		t.Fatalf("capacity defaults = %v/%d", cfg.reservePct, cfg.maxShard)
	}
	if cfg.scrubPeriod != 168*time.Hour || cfg.scrubRate != 50<<20 {
		t.Fatalf("scrub defaults = %v/%d", cfg.scrubPeriod, cfg.scrubRate)
	}
	if cfg.secret != "" || cfg.secretFile != "" || cfg.secretSource != "" {
		t.Fatalf("secret defaults = %q/%q/%q, want dev mode", cfg.secret, cfg.secretFile, cfg.secretSource)
	}
}

func TestParseFlagsValues(t *testing.T) {
	cfg, err := parseFlagsWithEnv([]string{
		"--disk", "/data",
		"--disk-id", "disk-explicit-1",
		"--port", "7200",
		"--nexus-id", "nexus-a",
		"--node-id", "node-1",
		"--coordinator-url", "coord:7000",
		"--secret", "abc",
		"--reserve-pct", "7.5",
		"--max-shard-bytes", "8388608",
		"--scrub=false",
		"--repair=false",
		"--heartbeat-interval", "2s",
		"--log-level", "debug",
	}, emptyEnv())
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if cfg.disk != "/data" || cfg.diskID != "disk-explicit-1" || cfg.port != 7200 || cfg.nexusID != "nexus-a" ||
		cfg.nodeID != "node-1" || cfg.coordURL != "coord:7000" || cfg.secret != "abc" ||
		cfg.reservePct != 7.5 || cfg.maxShard != 8388608 ||
		cfg.scrub || cfg.repair || cfg.heartbeat != 2*time.Second || cfg.logLevel != "debug" {
		t.Fatalf("parsed config = %+v", cfg)
	}
	if cfg.secretSource != "flag" {
		t.Fatalf("secretSource = %q, want flag", cfg.secretSource)
	}
}

func TestParseFlagsErrors(t *testing.T) {
	cases := [][]string{
		{"--port", "-1"},
		{"--port", "70000"},
		{"--reserve-pct", "-1"},
		{"--reserve-pct", "100"},
		{"--max-shard-bytes", "0"},
		{"--heartbeat-interval", "0s"},
		{"unexpected"},
		{"--not-a-flag"},
	}
	for _, args := range cases {
		if _, err := parseFlagsWithEnv(args, emptyEnv()); err == nil {
			t.Fatalf("parseFlags(%v) succeeded, want error", args)
		}
	}
}

func TestParseFlagsVersion(t *testing.T) {
	cfg, err := parseFlagsWithEnv([]string{"--version"}, emptyEnv())
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if !cfg.showVersion {
		t.Fatal("--version not honoured")
	}
}

func TestEnvironmentPrecedence(t *testing.T) {
	t.Run("env supplies values", func(t *testing.T) {
		cfg, err := parseFlagsWithEnv(nil, mapEnv(map[string]string{
			"FASS_AGENT_DISK":                     "/env-disk",
			"FASS_AGENT_DISK_ID":                  "disk-from-env",
			"FASS_AGENT_PORT":                     "7200",
			"FASS_AGENT_NEXUS_ID":                 "nexus-env",
			"FASS_AGENT_NODE_ID":                  "node-env",
			"FASS_AGENT_COORDINATOR_URL":          "http://coordinator:7000",
			"FASS_AGENT_SECRET":                   "env-secret",
			"FASS_AGENT_HOSTNAME":                 "host-env",
			"FASS_AGENT_RESERVE_PCT":              "7.5",
			"FASS_AGENT_MAX_SHARD_BYTES":          "1048576",
			"FASS_AGENT_SCRUB":                    "false",
			"FASS_AGENT_SCRUB_PERIOD":             "1h",
			"FASS_AGENT_SCRUB_RATE":               "1048576",
			"FASS_AGENT_REPAIR":                   "false",
			"FASS_AGENT_REPAIR_WORKERS":           "3",
			"FASS_AGENT_REPAIR_FETCH_CONCURRENCY": "4",
			"FASS_AGENT_HEARTBEAT_INTERVAL":       "2s",
			"FASS_AGENT_SHUTDOWN_TIMEOUT":         "9s",
			"FASS_AGENT_LOG_LEVEL":                "debug",
		}))
		if err != nil {
			t.Fatalf("parseFlagsWithEnv: %v", err)
		}
		if cfg.disk != "/env-disk" || cfg.diskID != "disk-from-env" || cfg.port != 7200 ||
			cfg.nexusID != "nexus-env" || cfg.nodeID != "node-env" ||
			cfg.coordURL != "http://coordinator:7000" || cfg.secret != "env-secret" ||
			cfg.hostname != "host-env" || cfg.reservePct != 7.5 || cfg.maxShard != 1048576 ||
			cfg.scrub || cfg.scrubPeriod != time.Hour || cfg.scrubRate != 1048576 ||
			cfg.repair || cfg.repairWork != 3 || cfg.repairFetch != 4 ||
			cfg.heartbeat != 2*time.Second || cfg.shutdown != 9*time.Second || cfg.logLevel != "debug" {
			t.Fatalf("env-supplied config = %+v", cfg)
		}
		if cfg.secretSource != "env" {
			t.Fatalf("secretSource = %q, want env", cfg.secretSource)
		}
	})

	t.Run("explicit flag beats env", func(t *testing.T) {
		cfg, err := parseFlagsWithEnv([]string{
			"--port", "7300",
			"--scrub=true",
			"--log-level", "warn",
		}, mapEnv(map[string]string{
			"FASS_AGENT_PORT":      "7200",
			"FASS_AGENT_SCRUB":     "false",
			"FASS_AGENT_LOG_LEVEL": "debug",
		}))
		if err != nil {
			t.Fatalf("parseFlagsWithEnv: %v", err)
		}
		if cfg.port != 7300 || !cfg.scrub || cfg.logLevel != "warn" {
			t.Fatalf("flag did not override env: %+v", cfg)
		}
	})

	t.Run("env beats default", func(t *testing.T) {
		cfg, err := parseFlagsWithEnv(nil, mapEnv(map[string]string{"FASS_AGENT_PORT": "7400"}))
		if err != nil {
			t.Fatalf("parseFlagsWithEnv: %v", err)
		}
		if cfg.port != 7400 {
			t.Fatalf("port = %d, want env value 7400", cfg.port)
		}
	})

	t.Run("no env keeps defaults", func(t *testing.T) {
		cfg, err := parseFlagsWithEnv(nil, emptyEnv())
		if err != nil {
			t.Fatalf("parseFlagsWithEnv: %v", err)
		}
		if cfg.port != 7100 || !cfg.scrub || cfg.heartbeat != 5*time.Second {
			t.Fatalf("defaults changed: %+v", cfg)
		}
	})
}

func TestEnvironmentInvalidValueFailsClosed(t *testing.T) {
	cases := []struct {
		env  string
		want string
	}{
		{"FASS_AGENT_PORT", "abc"},
		{"FASS_AGENT_SCRUB", "maybe"},
		{"FASS_AGENT_HEARTBEAT_INTERVAL", "soon"},
		{"FASS_AGENT_RESERVE_PCT", "lots"},
	}
	for _, tc := range cases {
		t.Run(tc.env, func(t *testing.T) {
			_, err := parseFlagsWithEnv(nil, mapEnv(map[string]string{tc.env: tc.want}))
			if err == nil {
				t.Fatalf("invalid %s accepted", tc.env)
			}
			if !strings.Contains(err.Error(), tc.env) {
				t.Fatalf("error does not name %s: %v", tc.env, err)
			}
		})
	}
}

// TestEveryFlagHasEnvironmentSupport is structural: environment support is
// derived from the flag table, so a newly added flag must automatically map to
// FASS_AGENT_<NAME> and parse from env with no code change.
func TestEveryFlagHasEnvironmentSupport(t *testing.T) {
	cfg := config{}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	registerFlags(fs, &cfg)

	env := map[string]string{}
	fs.VisitAll(func(f *flag.Flag) {
		if f.Name == "version" {
			return // action, not configuration
		}
		want := envPrefix + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		if got := envVarName(f.Name); got != want {
			t.Errorf("envVarName(%q) = %q, want %q", f.Name, got, want)
		}
		// The secret pair is mutually exclusive and covered by its own tests.
		if f.Name == "secret" || f.Name == "secret-file" {
			return
		}
		env[want] = f.DefValue
	})
	if _, err := parseFlagsWithEnv(nil, mapEnv(env)); err != nil {
		t.Fatalf("every flag's default value rejected via env: %v", err)
	}
}

func TestVersionIsNotConfigurableThroughEnvironment(t *testing.T) {
	cfg, err := parseFlagsWithEnv(nil, mapEnv(map[string]string{"FASS_AGENT_VERSION": "true"}))
	if err != nil {
		t.Fatalf("parseFlagsWithEnv: %v", err)
	}
	if cfg.showVersion {
		t.Fatal("FASS_AGENT_VERSION turned --version on; environment must not trigger actions")
	}
}

func TestSecretFromEnv(t *testing.T) {
	cfg, err := parseFlagsWithEnv(nil, mapEnv(map[string]string{"FASS_AGENT_SECRET": "env-secret"}))
	if err != nil {
		t.Fatalf("parseFlagsWithEnv: %v", err)
	}
	if cfg.secret != "env-secret" || cfg.secretSource != "env" {
		t.Fatalf("secret = %q, source = %q", cfg.secret, cfg.secretSource)
	}

	// An explicit flag beats the environment (same source kind, no ambiguity).
	cfg, err = parseFlagsWithEnv([]string{"--secret", "flag-secret"},
		mapEnv(map[string]string{"FASS_AGENT_SECRET": "env-secret"}))
	if err != nil {
		t.Fatalf("parseFlagsWithEnv: %v", err)
	}
	if cfg.secret != "flag-secret" || cfg.secretSource != "flag" {
		t.Fatalf("flag did not override env secret: %q (%q)", cfg.secret, cfg.secretSource)
	}
}

func TestSecretFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return path
	}

	cases := []struct {
		name    string
		content string
		want    string
		wantErr string
	}{
		{"no trailing newline", "file-secret-1", "file-secret-1", ""},
		{"one trailing lf", "file-secret-2\n", "file-secret-2", ""},
		{"one trailing crlf", "file-secret-3\r\n", "file-secret-3", ""},
		{"empty", "", "", "empty"},
		{"only newline", "\n", "", "empty"},
		{"only whitespace", "   \n", "", "empty"},
		{"two lines", "first\nsecond\n", "", "exactly one line"},
		{"extra blank line", "file-secret-4\n\n", "", "exactly one line"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := write(strings.ReplaceAll(tc.name, " ", "-")+".secret", tc.content)
			cfg, err := parseFlagsWithEnv([]string{"--secret-file", path}, emptyEnv())
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("secret file %q accepted (%q)", tc.name, cfg.secret)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseFlagsWithEnv: %v", err)
			}
			if cfg.secret != tc.want {
				t.Fatalf("secret = %q, want %q", cfg.secret, tc.want)
			}
			if cfg.secretSource != "file" {
				t.Fatalf("secretSource = %q, want file", cfg.secretSource)
			}
		})
	}

	t.Run("env secret file", func(t *testing.T) {
		path := write("env-file.secret", "env-file-secret\n")
		cfg, err := parseFlagsWithEnv(nil, mapEnv(map[string]string{"FASS_AGENT_SECRET_FILE": path}))
		if err != nil {
			t.Fatalf("parseFlagsWithEnv: %v", err)
		}
		if cfg.secret != "env-file-secret" || cfg.secretSource != "file" {
			t.Fatalf("secret = %q, source = %q", cfg.secret, cfg.secretSource)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := parseFlagsWithEnv([]string{"--secret-file", filepath.Join(dir, "does-not-exist")}, emptyEnv())
		if err == nil || !strings.Contains(err.Error(), "read secret file") {
			t.Fatalf("err = %v, want read failure", err)
		}
	})

	t.Run("explicitly empty flag", func(t *testing.T) {
		_, err := parseFlagsWithEnv([]string{"--secret-file", ""}, emptyEnv())
		if err == nil || !strings.Contains(err.Error(), "set but empty") {
			t.Fatalf("err = %v, want empty-secret-file error", err)
		}
	})
}

func TestConflictingSecretSourcesFailClosed(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "announce.secret")
	if err := os.WriteFile(secretFile, []byte("file-secret-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		args []string
		env  map[string]string
	}{
		{"both flags", []string{"--secret", "argv-secret-value", "--secret-file", secretFile}, nil},
		{"env secret plus flag file", []string{"--secret-file", secretFile},
			map[string]string{"FASS_AGENT_SECRET": "env-secret-value"}},
		{"flag secret plus env file", []string{"--secret", "argv-secret-value"},
			map[string]string{"FASS_AGENT_SECRET_FILE": secretFile}},
		{"both env", nil, map[string]string{
			"FASS_AGENT_SECRET":      "env-secret-value",
			"FASS_AGENT_SECRET_FILE": secretFile,
		}},
		{"flag secret plus env secret file", []string{"--secret", "argv-secret-value"},
			map[string]string{"FASS_AGENT_SECRET_FILE": ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := tc.env
			if env == nil {
				env = map[string]string{}
			}
			_, err := parseFlagsWithEnv(tc.args, mapEnv(env))
			if err == nil {
				t.Fatal("ambiguous secret configuration was accepted")
			}
			if !strings.Contains(err.Error(), "conflicting secret sources") {
				t.Fatalf("err = %v, want conflicting-secret-sources", err)
			}
			// The error must never leak the credential values.
			for _, leak := range []string{"argv-secret-value", "env-secret-value", "file-secret-value"} {
				if strings.Contains(err.Error(), leak) {
					t.Fatalf("error leaked a secret value: %v", err)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// End-to-end configuration tests: a real run() against a fake coordinator.
// ---------------------------------------------------------------------------

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

type fakeCoordinator struct {
	mu         sync.Mutex
	announces  []contract.AnnounceRequest
	heartbeats int
	announceCh chan contract.AnnounceRequest
}

func newFakeCoordinator(t *testing.T) (*fakeCoordinator, *httptest.Server) {
	t.Helper()
	f := &fakeCoordinator{announceCh: make(chan contract.AnnounceRequest, 8)}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/agents/announce", func(w http.ResponseWriter, r *http.Request) {
		var req contract.AnnounceRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode announce: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.announces = append(f.announces, req)
		f.mu.Unlock()
		select {
		case f.announceCh <- req:
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(contract.AnnounceResult{
			AgentID: "agent-from-coordinator",
			NexusID: "nexus-from-coordinator",
			State:   "active",
		})
	})
	mux.HandleFunc("POST /v1/agents/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		f.mu.Lock()
		f.heartbeats++
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return f, ts
}

func (f *fakeCoordinator) heartbeatCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.heartbeats
}

// runAgentForTest starts run() with a capture logger, waits for the announce
// and at least one heartbeat, then shuts the agent down cleanly, returning all
// captured log output.
func runAgentForTest(t *testing.T, cfg config, coord *fakeCoordinator) string {
	t.Helper()
	var buf lockedBuffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg, logger) }()

	select {
	case <-coord.announceCh:
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("agent did not announce")
	}

	deadline := time.Now().Add(10 * time.Second)
	for coord.heartbeatCount() == 0 {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("agent did not heartbeat")
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("agent did not shut down")
	}
	return buf.String()
}

func baseEnv(t *testing.T, coordURL string) map[string]string {
	t.Helper()
	return map[string]string{
		"FASS_AGENT_DISK":               t.TempDir(),
		"FASS_AGENT_PORT":               "0",
		"FASS_AGENT_NODE_ID":            "node-env",
		"FASS_AGENT_NEXUS_ID":           "nexus-env",
		"FASS_AGENT_COORDINATOR_URL":    coordURL,
		"FASS_AGENT_HEARTBEAT_INTERVAL": "25ms",
		"FASS_AGENT_SHUTDOWN_TIMEOUT":   "2s",
		"FASS_AGENT_SCRUB":              "false",
		"FASS_AGENT_REPAIR":             "false",
		"FASS_AGENT_LOG_LEVEL":          "debug",
	}
}

func TestRunAnnouncesWithOnlyEnvironmentVariables(t *testing.T) {
	coord, srv := newFakeCoordinator(t)
	const secret = "SUPER-SECRET-ENV-9f3a-do-not-log"

	env := baseEnv(t, srv.URL)
	env["FASS_AGENT_SECRET"] = secret
	// No argv at all: configuration comes exclusively from the environment.
	cfg, err := parseFlagsWithEnv(nil, mapEnv(env))
	if err != nil {
		t.Fatalf("parseFlagsWithEnv: %v", err)
	}
	if cfg.secretSource != "env" || cfg.port != 0 {
		t.Fatalf("cfg secretSource=%q port=%d", cfg.secretSource, cfg.port)
	}

	logs := runAgentForTest(t, cfg, coord)

	coord.mu.Lock()
	defer coord.mu.Unlock()
	if len(coord.announces) == 0 {
		t.Fatal("no announce reached the fake coordinator")
	}
	announce := coord.announces[0]
	if announce.Secret != secret {
		t.Fatalf("announced secret = %q, want the env secret", announce.Secret)
	}
	if announce.NodeID != "node-env" || announce.DiskID == "" || announce.Port == 0 {
		t.Fatalf("announce = %+v", announce)
	}
	if coord.heartbeats == 0 {
		t.Fatal("no heartbeats sent")
	}

	if strings.Contains(logs, secret) {
		t.Fatalf("secret value leaked into logs:\n%s", logs)
	}
	for _, want := range []string{"agent announced", `"secret_source":"env"`} {
		if !strings.Contains(logs, want) {
			t.Fatalf("logs missing %q:\n%s", want, logs)
		}
	}
}

func TestRunAnnouncesWithSecretFile(t *testing.T) {
	coord, srv := newFakeCoordinator(t)
	const secret = "SUPER-SECRET-FILE-4b7c-do-not-log"
	secretPath := filepath.Join(t.TempDir(), "announce.secret")
	if err := os.WriteFile(secretPath, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	env := baseEnv(t, srv.URL)
	// The secret comes from a file named on the command line; argv never holds it.
	cfg, err := parseFlagsWithEnv([]string{"--secret-file", secretPath}, mapEnv(env))
	if err != nil {
		t.Fatalf("parseFlagsWithEnv: %v", err)
	}
	if cfg.secretSource != "file" || cfg.secret != secret {
		t.Fatalf("cfg secretSource=%q secret=%q", cfg.secretSource, cfg.secret)
	}

	logs := runAgentForTest(t, cfg, coord)

	coord.mu.Lock()
	defer coord.mu.Unlock()
	if len(coord.announces) == 0 {
		t.Fatal("no announce reached the fake coordinator")
	}
	if got := coord.announces[0].Secret; got != secret {
		t.Fatalf("announced secret = %q, want the secret-file value (newline trimmed)", got)
	}
	if coord.heartbeats == 0 {
		t.Fatal("no heartbeats sent")
	}
	if strings.Contains(logs, secret) {
		t.Fatalf("secret value leaked into logs:\n%s", logs)
	}
	if !strings.Contains(logs, `"secret_source":"file"`) {
		t.Fatalf("logs missing secret source:\n%s", logs)
	}
}

func TestRunWarnsWhenSecretComesFromArgv(t *testing.T) {
	coord, srv := newFakeCoordinator(t)
	const secret = "ARGV-SECRET-77aa-do-not-log"
	env := baseEnv(t, srv.URL)

	cfg, err := parseFlagsWithEnv([]string{"--secret", secret}, mapEnv(env))
	if err != nil {
		t.Fatalf("parseFlagsWithEnv: %v", err)
	}
	logs := runAgentForTest(t, cfg, coord)
	if strings.Contains(logs, secret) {
		t.Fatalf("secret value leaked into logs:\n%s", logs)
	}
	if !strings.Contains(logs, "visible to local users") {
		t.Fatalf("no argv-visibility warning in logs:\n%s", logs)
	}
}

// TestBuildHeartbeatReportsBoundDiskID / FailsLoudlyOnDivergence: unchanged
// identity guarantees from the previous task.

func TestBuildHeartbeatReportsBoundDiskID(t *testing.T) {
	stats := store.Stats{FreeBytes: 100, UsedBytes: 200, ShardCount: 3, SetCount: 1}
	now := time.Unix(1_726_000_000, 0).UTC()

	hb, err := buildHeartbeat("agent-1", "disk-bound", "", stats, 0.25, "cursor-1", now)
	if err != nil {
		t.Fatalf("buildHeartbeat: %v", err)
	}
	if hb.DiskID != "disk-bound" {
		t.Fatalf("DiskID = %q, want the bound id", hb.DiskID)
	}
	if hb.AgentID != "agent-1" || hb.FreeBytes != 100 || hb.UsedBytes != 200 ||
		hb.ShardCount != 3 || hb.LoadEWMA != 0.25 || hb.ScrubCursor != "cursor-1" ||
		!hb.Time.Equal(now) {
		t.Fatalf("heartbeat = %+v", hb)
	}
	if hb.InventoryDigest == "" {
		t.Fatal("empty inventory digest")
	}

	hb, err = buildHeartbeat("agent-1", "disk-bound", "disk-bound", stats, 0, "", now)
	if err != nil {
		t.Fatalf("matching flag: %v", err)
	}
	if hb.DiskID != "disk-bound" {
		t.Fatalf("DiskID with matching flag = %q", hb.DiskID)
	}
}

func TestBuildHeartbeatFailsLoudlyOnDivergence(t *testing.T) {
	stats := store.Stats{}
	now := time.Now().UTC()

	_, err := buildHeartbeat(contract.AgentID("agent-1"), "disk-bound", "disk-flag", stats, 0, "", now)
	if err == nil {
		t.Fatal("divergent disk identity did not fail")
	}
	if !strings.Contains(err.Error(), "disk-bound") || !strings.Contains(err.Error(), "disk-flag") {
		t.Fatalf("error does not name both identities: %v", err)
	}

	if _, err := buildHeartbeat("agent-1", "", "", stats, 0, "", now); err == nil {
		t.Fatal("heartbeat with empty bound disk id succeeded")
	}
}
