package postgres_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fass-storage/fass/internal/coord/meta/parity"
	"github.com/fass-storage/fass/internal/storage"
	"github.com/fass-storage/fass/internal/storage/postgres"
)

// The Postgres matrix starts an ephemeral postgres:16 container when
// FASS_TEST_POSTGRES_DSN is unset and docker is available, and skips cleanly
// otherwise (CI without docker must not fail).
var (
	pgOnce       sync.Once
	pgDSN        string
	pgSkipReason string
	pgContainer  string
)

func TestMain(m *testing.M) {
	pgDSN = os.Getenv("FASS_TEST_POSTGRES_DSN")
	if pgDSN == "" {
		pgOnce.Do(startContainer)
	}
	code := m.Run()
	if pgContainer != "" {
		_ = exec.Command("docker", "rm", "-f", pgContainer).Run()
	}
	os.Exit(code)
}

func startContainer() {
	pgSkipReason = "no FASS_TEST_POSTGRES_DSN"
	if _, err := exec.LookPath("docker"); err != nil {
		pgSkipReason += " and docker is not installed"
		return
	}
	name := fmt.Sprintf("fass-pg-parity-%d", time.Now().UnixNano())
	out, err := exec.Command("docker", "run", "-d", "--rm", "--name", name,
		"-e", "POSTGRES_PASSWORD=fass", "-e", "POSTGRES_DB=fass",
		"-p", "127.0.0.1::5432", "postgres:16").CombinedOutput()
	if err != nil {
		pgSkipReason = "docker postgres:16 unavailable: " + truncate(string(out), 200)
		return
	}
	pgContainer = name

	port := ""
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		out, err := exec.Command("docker", "port", name, "5432/tcp").CombinedOutput()
		if err == nil {
			// 127.0.0.1:PORT
			if idx := strings.LastIndex(strings.TrimSpace(string(out)), ":"); idx >= 0 {
				port = strings.TrimSpace(string(out))[idx+1:]
			}
		}
		if port != "" {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if port == "" {
		pgSkipReason = "docker postgres:16 did not publish a port"
		return
	}
	candidate := fmt.Sprintf("postgres://postgres:fass@127.0.0.1:%s/fass?sslmode=disable", port)
	// Wait until the server accepts connections.
	deadline = time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		db, err := postgres.Open(ctx, postgres.Config{DSN: candidate, StatementTime: 2 * time.Second})
		cancel()
		if err == nil {
			_ = db.Close()
			pgDSN = candidate
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	pgSkipReason = "docker postgres:16 did not become ready"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// openTestDB returns a migrated, empty PostgreSQL backend or skips.
func openTestDB(t *testing.T) *postgres.KV {
	t.Helper()
	if pgDSN == "" {
		t.Skipf("PostgreSQL parity skipped: %s", pgSkipReason)
	}
	ctx := context.Background()
	db, err := postgres.Open(ctx, postgres.Config{DSN: pgDSN, StatementTime: 10 * time.Second})
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := db.ExecContext(ctx, "TRUNCATE kv, blobs"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return postgres.NewKV(db)
}

// TestPostgresParity runs the same behaviour suite as the embedded backend.
func TestPostgresParity(t *testing.T) {
	parity.Run(t, openTestDB(t))
}

// TestPostgresIndexUsage asserts the three hot access paths are index scans.
// A sequential scan on a 50M-row metadata table is a production outage waiting
// for enough data, so the plan is part of the contract.
func TestPostgresIndexUsage(t *testing.T) {
	kv := openTestDB(t)
	ctx := context.Background()
	db := kv.DB()

	// Populate enough rows that the planner has a real choice, then ANALYZE.
	const rows = 4000
	for start := 0; start < rows; start += 500 {
		batch := start
		if err := kv.Update(ctx, func(w storage.Writer) error {
			for i := batch; i < batch+500 && i < rows; i++ {
				key := []byte(fmt.Sprintf("bucket-%04d\x00key-%06d", i%20, i))
				if err := w.Put([]byte("objects_versions"), key, []byte(`{"seq":1}`)); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatalf("seed kv: %v", err)
		}
	}
	if _, err := db.ExecContext(ctx, "ANALYZE kv"); err != nil {
		t.Fatalf("analyze: %v", err)
	}

	cases := []struct {
		name  string
		query string
		args  []any
	}{
		{"point-get", "SELECT value FROM kv WHERE space = $1 AND key = $2", []any{"objects_versions", []byte("bucket-0007\x00key-002007")}},
		{"version-range-scan", "SELECT key, value FROM kv WHERE space = $1 AND key >= $2 AND key < $3 ORDER BY key", []any{"objects_versions", []byte("bucket-0007\x00key-002000"), []byte("bucket-0007\x00key-002100")}},
		{"prefix-list", "SELECT key, value FROM kv WHERE space = $1 AND key >= $2 AND key < $3 ORDER BY key", []any{"objects_versions", []byte("bucket-0007\x00"), []byte("bucket-0007\x01")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := db.QueryContext(ctx, "EXPLAIN "+tc.query, tc.args...)
			if err != nil {
				t.Fatalf("EXPLAIN: %v", err)
			}
			defer rows.Close()
			var plan []string
			for rows.Next() {
				var line string
				if err := rows.Scan(&line); err != nil {
					t.Fatalf("scan plan: %v", err)
				}
				plan = append(plan, line)
			}
			joined := strings.Join(plan, "\n")
			if strings.Contains(joined, "Seq Scan") {
				t.Fatalf("%s uses a sequential scan:\n%s", tc.name, joined)
			}
			if !strings.Contains(joined, "Index") {
				t.Fatalf("%s does not use an index:\n%s", tc.name, joined)
			}
		})
	}
}

// maxMetadataKey mirrors the longest composite key the coordinator constructs.
func maxMetadataKey() []byte {
	return []byte("versions\x00" + strings.Repeat("b", 36) + "\x00" + strings.Repeat("k", 1024) + "\x00" + strings.Repeat("9", 19))
}

// TestMetadataKeyWithinBtreeLimit: B-tree entries must stay well under the ~2704
// byte limit; this is the guard against a future key-encoding change silently
// exceeding it.
func TestMetadataKeyWithinBtreeLimit(t *testing.T) {
	key := maxMetadataKey()
	const btreeMax = 2704
	const indexEntryOverhead = 200 // tuple header + space + pointer + alignment
	if len(key)+indexEntryOverhead >= btreeMax {
		t.Fatalf("max composite key %d bytes + overhead exceeds the B-tree limit %d", len(key), btreeMax)
	}
	if len(key) > 2048 {
		t.Fatalf("max composite key = %d bytes, want < 2048", len(key))
	}
}

// TestListingProjectionCost measures the listing access path: the current adapter
// scans the whole prefix range with no LIMIT and transfers/decodes full JSONB
// records, while a bounded narrow projection only needs key+size+etag+timestamp.
func TestListingProjectionCost(t *testing.T) {
	kv := openTestDB(t)
	ctx := context.Background()
	db := kv.DB()
	const rows = 20000
	// Seed rows that look like version records (only the projected fields matter).
	for start := 0; start < rows; start += 1000 {
		if err := kv.Update(ctx, func(w storage.Writer) error {
			for i := start; i < start+1000 && i < rows; i++ {
				key := []byte(fmt.Sprintf("bucket-1\x00key-%06d\x00\x00\x00\x00\x00\x00\x00\x01", i))
				val := []byte(fmt.Sprintf(`{"key":"key-%06d","size":1024,"etag":"etag-%06d","created_at":"2026-01-01T00:00:00Z","manifest_hash":"h","user_meta":{"a":"b"},"tags":{"x":"y"}}`, i, i))
				if err := w.Put([]byte("objects_versions"), key, val); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	if _, err := db.ExecContext(ctx, "ANALYZE kv"); err != nil {
		t.Fatalf("analyze: %v", err)
	}
	prefix := []byte("bucket-1\x00key-")
	end := []byte("bucket-1\x00key0") // '0' > '-' so the range covers key-000000..
	timeQuery := func(name, q string) {
		start := time.Now()
		raw, err := db.QueryContext(ctx, q, string("objects_versions"), prefix, end)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		n := 0
		for raw.Next() {
			n++
		}
		raw.Close()
		t.Logf("%s: %d rows in %v", name, n, time.Since(start))
	}
	// Current adapter shape: full range, full JSONB value transfer.
	timeQuery("full-jsonb-20000", "SELECT key, value FROM kv WHERE space=$1 AND key >= $2 AND key < $3 ORDER BY key")
	// Bounded page: what a listing actually needs (max-keys=1000).
	timeQuery("limited-jsonb-1000", "SELECT key, value FROM kv WHERE space=$1 AND key >= $2 AND key < $3 ORDER BY key LIMIT 1000")
	// Narrow projection: only the fields a listing renders, pushed down to SQL.
	timeQuery("limited-projection-1000", "SELECT key, (value->>'size')::bigint, value->>'etag', value->>'created_at' FROM kv WHERE space=$1 AND key >= $2 AND key < $3 ORDER BY key LIMIT 1000")
}
