package storage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

var (
	spacesTest = []byte("test")
	metaTest   = []byte("meta")
)

func mustOpen(t *testing.T, dir string) *DB {
	t.Helper()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("open %q: %v", dir, err)
	}
	return db
}

func put(t *testing.T, db *DB, key, val string) {
	t.Helper()
	err := db.Update(context.Background(), func(tx Writer) error {
		return tx.Put(spacesTest, []byte(key), []byte(val))
	})
	if err != nil {
		t.Fatalf("put %q: %v", key, err)
	}
}

func get(t *testing.T, db *DB, key string) (string, error) {
	t.Helper()
	var out string
	err := db.View(context.Background(), func(tx Reader) error {
		raw, err := tx.Get(spacesTest, []byte(key))
		if err != nil {
			return err
		}
		out = string(raw)
		return nil
	})
	return out, err
}

func TestDurabilityAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	db := mustOpen(t, dir)
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	put(t, db, "alpha", "one")
	put(t, db, "beta", "two")
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	db = mustOpen(t, dir)
	defer db.Close()
	for key, want := range map[string]string{"alpha": "one", "beta": "two"} {
		got, err := get(t, db, key)
		if err != nil || got != want {
			t.Fatalf("after reopen %q = %q, %v; want %q", key, got, err, want)
		}
	}
	version, err := SchemaVersionOf(context.Background(), db)
	if err != nil || version != SchemaVersion {
		t.Fatalf("schema version = %d, %v", version, err)
	}
}

func TestTornTailIsTruncatedOnOpen(t *testing.T) {
	dir := t.TempDir()
	db := mustOpen(t, dir)
	put(t, db, "stable", "value")
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	journal := filepath.Join(dir, journalName)
	f, err := os.OpenFile(journal, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open journal: %v", err)
	}
	// A torn commit: a frame header promising 1 KiB that is not there, plus junk.
	if _, err := f.Write([]byte{0xff, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02}); err != nil {
		t.Fatalf("append torn frame: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close journal: %v", err)
	}

	db = mustOpen(t, dir)
	defer db.Close()
	got, err := get(t, db, "stable")
	if err != nil || got != "value" {
		t.Fatalf("data lost after torn tail: %q, %v", got, err)
	}
	// The torn tail must be truncated so subsequent appends stay valid.
	put(t, db, "after", "recovery")
	info, err := os.Stat(journal)
	if err != nil {
		t.Fatalf("stat journal: %v", err)
	}
	if info.Size() > 4096 {
		t.Fatalf("journal was not truncated (size %d)", info.Size())
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	db = mustOpen(t, dir)
	defer db.Close()
	if got, err := get(t, db, "after"); err != nil || got != "recovery" {
		t.Fatalf("post-recovery write lost: %q, %v", got, err)
	}
}

func TestCompactionPreservesState(t *testing.T) {
	dir := t.TempDir()
	db := mustOpen(t, dir)
	for i := 0; i < 50; i++ {
		put(t, db, fmt.Sprintf("key-%02d", i), fmt.Sprintf("value-%d", i))
	}
	if err := db.Update(context.Background(), func(tx Writer) error {
		return tx.Delete(spacesTest, []byte("key-00"))
	}); err != nil {
		t.Fatalf("delete: %v", err)
	}

	db.wmu.Lock()
	err := db.compactLocked()
	db.wmu.Unlock()
	if err != nil {
		t.Fatalf("compact: %v", err)
	}
	if info, err := os.Stat(filepath.Join(dir, journalName)); err != nil || info.Size() != int64(len(journalMagic)) {
		t.Fatalf("journal not truncated after compaction: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	db = mustOpen(t, dir)
	defer db.Close()
	for i := 1; i < 50; i++ {
		got, err := get(t, db, fmt.Sprintf("key-%02d", i))
		if err != nil || got != fmt.Sprintf("value-%d", i) {
			t.Fatalf("key-%02d after compaction = %q, %v", i, got, err)
		}
	}
	if _, err := get(t, db, "key-00"); err != ErrNotFound {
		t.Fatalf("deleted key resurrected: %v", err)
	}
}

func TestMigrateRefusesNewerSchema(t *testing.T) {
	db := mustOpen(t, t.TempDir())
	defer db.Close()
	if err := db.Update(context.Background(), func(tx Writer) error {
		return tx.Put(metaTest, schemaVersionKey, []byte("99"))
	}); err != nil {
		t.Fatalf("seed version: %v", err)
	}
	if err := Migrate(context.Background(), db); err == nil {
		t.Fatalf("expected migration to refuse a newer schema")
	}
}

func TestSingleProcessLock(t *testing.T) {
	dir := t.TempDir()
	db := mustOpen(t, dir)
	if _, err := Open(dir); err == nil {
		t.Fatalf("second Open on the same directory succeeded")
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	db2 := mustOpen(t, dir)
	if err := db2.Close(); err != nil {
		t.Fatalf("reopen after close: %v", err)
	}
}

func TestScanOrderingAndDelete(t *testing.T) {
	db := mustOpen(t, t.TempDir())
	defer db.Close()
	for _, k := range []string{"b", "a", "c", "aa"} {
		put(t, db, k, "v-"+k)
	}
	var order []string
	err := db.View(context.Background(), func(tx Reader) error {
		return tx.Scan(spacesTest, nil, func(k, _ []byte) error {
			order = append(order, string(k))
			return nil
		})
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	want := []string{"a", "aa", "b", "c"}
	if len(order) != len(want) {
		t.Fatalf("scan = %v", order)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("scan order = %v, want %v", order, want)
		}
	}

	// Prefix scans and early stop.
	var prefixed int
	if err := db.View(context.Background(), func(tx Reader) error {
		return tx.Scan(spacesTest, []byte("a"), func(_, _ []byte) error {
			prefixed++
			return nil
		})
	}); err != nil || prefixed != 2 {
		t.Fatalf("prefix scan = %d, %v", prefixed, err)
	}
	if err := db.View(context.Background(), func(tx Reader) error {
		return tx.Scan(spacesTest, nil, func(_, _ []byte) error { return StopScan() })
	}); err != nil {
		t.Fatalf("stop scan: %v", err)
	}

	// Read-your-writes inside a transaction and rollback on error.
	err = db.Update(context.Background(), func(tx Writer) error {
		if err := tx.Put(spacesTest, []byte("inside"), []byte("1")); err != nil {
			return err
		}
		raw, err := tx.Get(spacesTest, []byte("inside"))
		if err != nil || string(raw) != "1" {
			t.Fatalf("read-your-writes failed: %q %v", raw, err)
		}
		return fmt.Errorf("deliberate rollback")
	})
	if err == nil {
		t.Fatalf("expected rollback error")
	}
	if _, err := get(t, db, "inside"); err != ErrNotFound {
		t.Fatalf("rolled-back write visible: %v", err)
	}
}

func TestConcurrentReadersWithWriter(t *testing.T) {
	db := mustOpen(t, t.TempDir())
	defer db.Close()
	for i := 0; i < 100; i++ {
		put(t, db, fmt.Sprintf("k%03d", i), "v")
	}
	ctx := context.Background()
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = db.View(ctx, func(tx Reader) error {
					return tx.Scan(spacesTest, nil, func(_, _ []byte) error { return nil })
				})
			}
		}()
	}
	for i := 0; i < 40; i++ {
		put(t, db, fmt.Sprintf("w%03d", i), "v")
	}
	close(stop)
	wg.Wait()
}

func TestJoinKey(t *testing.T) {
	if got := string(JoinKey("bucket", "key")); got != "bucket\x00key" {
		t.Fatalf("JoinKey = %q", got)
	}
	if got := string(JoinKeyN([]string{"bucket", "key"}, []byte{1, 2})); got != "bucket\x00key\x00\x01\x02" {
		t.Fatalf("JoinKeyN = %q", got)
	}
}
