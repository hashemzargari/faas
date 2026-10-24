package scrub

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/fass-storage/fass/internal/agent/shard"
	"github.com/fass-storage/fass/internal/agent/store"
	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/ec"
)

var params = ec.Params{GeoN: 2, GeoK: 1, LocalN: 16, LocalK: 4}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), store.Options{
		Root:   t.TempDir(),
		Logger: discardLogger(),
	})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func putShard(t *testing.T, st *store.Store, setID contract.ShardSetID, group, index int, payload []byte) {
	t.Helper()
	_, err := st.Put(context.Background(), store.PutRequest{
		ShardSetID: setID,
		GeoGroup:   group,
		LocalIndex: index,
		Params:     params,
		PayloadLen: int64(len(payload)),
		Checksum:   shard.Sum64(payload),
	}, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
}

type fakeReporter struct {
	mu       sync.Mutex
	statuses []contract.ShardStatus
	calls    int
	ch       chan struct{}
}

func (f *fakeReporter) ReportShardStatus(_ context.Context, items []contract.ShardStatus) error {
	f.mu.Lock()
	f.statuses = append(f.statuses, items...)
	f.calls++
	f.mu.Unlock()
	if f.ch != nil {
		select {
		case f.ch <- struct{}{}:
		default:
		}
	}
	return nil
}

func (f *fakeReporter) snapshot() []contract.ShardStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]contract.ShardStatus(nil), f.statuses...)
}

func newTestScrubber(t *testing.T, st *store.Store, reporter StatusReporter) *Scrubber {
	t.Helper()
	s, err := New(Options{Store: st, Reporter: reporter, Logger: discardLogger()})
	if err != nil {
		t.Fatalf("scrub.New: %v", err)
	}
	return s
}

func TestScrubCleanStore(t *testing.T) {
	st := newTestStore(t)
	setID := contract.ShardSetID("11111111-1111-4111-8111-111111111111")
	for i := 0; i < 5; i++ {
		putShard(t, st, setID, 0, i, []byte{byte(i), 'a', 'b', 'c'})
	}
	rep := &fakeReporter{}
	s := newTestScrubber(t, st, rep)

	report, err := s.Pass(context.Background())
	if err != nil {
		t.Fatalf("Pass: %v", err)
	}
	if report.Checked != 5 || report.Verified != 5 || report.Corrupt != 0 || report.Bytes == 0 {
		t.Fatalf("report = %+v", report)
	}
	if report.Wrapped {
		t.Fatal("first pass should not report wrapped before reaching the end twice")
	}
	if len(rep.snapshot()) != 0 {
		t.Fatalf("clean store reported statuses: %+v", rep.snapshot())
	}
	if st.Stats().ShardCount != 5 {
		t.Fatalf("shard count = %d", st.Stats().ShardCount)
	}
}

func TestScrubDetectsCorruptionAndReports(t *testing.T) {
	st := newTestStore(t)
	setID := contract.ShardSetID("22222222-2222-4222-8222-222222222222")
	healthy := bytes.Repeat([]byte("healthy"), 8)
	putShard(t, st, setID, 0, 0, healthy)
	putShard(t, st, setID, 0, 3, bytes.Repeat([]byte("victim"), 8))

	// Corrupt the payload of group 0 / index 3.
	id := shard.ID(setID, 0, 3)
	path := st.Root() + "/shards/" + id[0:2] + "/" + id[2:4] + "/" + id + ".shard"
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := f.Stat()
	if _, err := f.WriteAt([]byte{0x00}, fi.Size()-1); err != nil {
		t.Fatal(err)
	}
	f.Close()

	rep := &fakeReporter{}
	s := newTestScrubber(t, st, rep)
	report, err := s.Pass(context.Background())
	if err != nil {
		t.Fatalf("Pass: %v", err)
	}
	if report.Checked != 2 || report.Verified != 1 || report.Corrupt != 1 {
		t.Fatalf("report = %+v", report)
	}
	statuses := rep.snapshot()
	if len(statuses) != 1 {
		t.Fatalf("reported statuses = %+v", statuses)
	}
	if statuses[0].State != "CORRUPT" || statuses[0].ShardSetID != setID {
		t.Fatalf("status = %+v", statuses[0])
	}
	if want := 0*params.ShardsPerGroup() + 3; statuses[0].Slot != want {
		t.Fatalf("status slot = %d, want %d", statuses[0].Slot, want)
	}
	if st.Stats().ShardCount != 1 {
		t.Fatalf("corrupt shard not quarantined: count = %d", st.Stats().ShardCount)
	}
}

func TestScrubResumesFromCursor(t *testing.T) {
	st := newTestStore(t)
	setID := contract.ShardSetID("33333333-3333-4333-8333-333333333333")
	for i := 0; i < 6; i++ {
		putShard(t, st, setID, 0, i, []byte{byte(i), 1, 2, 3})
	}
	sortedIDs := sortedShardIDs(t, st)
	if len(sortedIDs) != 6 {
		t.Fatalf("inventory returned %d shards, want 6", len(sortedIDs))
	}

	cases := []struct {
		name       string
		cursor     string
		wantChecked int
	}{
		{"from start", "", 6},
		{"after 3rd", sortedIDs[2], 3},
		{"after 5th", sortedIDs[4], 1},
		{"after last", sortedIDs[5], 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestScrubber(t, st, nil)
			s.cursor = tc.cursor
			rep, err := s.Pass(context.Background())
			if err != nil {
				t.Fatalf("Pass: %v", err)
			}
			if rep.Checked != tc.wantChecked {
				t.Fatalf("checked %d, want %d", rep.Checked, tc.wantChecked)
			}
		})
	}
}

func sortedShardIDs(t *testing.T, st *store.Store) []string {
	t.Helper()
	var ids []string
	infos, _, err := st.Inventory(context.Background(), "", 100)
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	for _, info := range infos {
		ids = append(ids, shard.ID(info.ShardSetID, info.GeoGroup, info.LocalIndex))
	}
	// Inventory is already ordered by shard id; verify and return.
	for i := 1; i < len(ids); i++ {
		if ids[i-1] >= ids[i] {
			t.Fatalf("inventory not sorted at %d: %q >= %q", i, ids[i-1], ids[i])
		}
	}
	return ids
}

func TestScrubTriggerAndRun(t *testing.T) {
	st := newTestStore(t)
	setID := contract.ShardSetID("44444444-4444-4444-8444-444444444444")
	putShard(t, st, setID, 0, 0, bytes.Repeat([]byte("run"), 4))

	// Corrupt so the reporter signals progress.
	id := shard.ID(setID, 0, 0)
	path := st.Root() + "/shards/" + id[0:2] + "/" + id[2:4] + "/" + id + ".shard"
	f, _ := os.OpenFile(path, os.O_RDWR, 0)
	fi, _ := f.Stat()
	_, _ = f.WriteAt([]byte{0x00}, fi.Size()-1)
	f.Close()

	rep := &fakeReporter{ch: make(chan struct{}, 1)}
	s := newTestScrubber(t, st, rep)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	s.Trigger()
	select {
	case <-rep.ch:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("triggered scrub pass did not report corruption")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop after cancel")
	}
}

func TestRateLimiterEnforcesRate(t *testing.T) {
	lim := newRateLimiter(100_000) // 100 kB/s
	start := time.Now()
	if err := lim.Wait(context.Background(), 5_000); err != nil { // ~50ms
		t.Fatalf("Wait: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < 30*time.Millisecond {
		t.Fatalf("rate limiter slept only %v for 5kB at 100kB/s", elapsed)
	}

	// Cancellation while waiting is honoured.
	lim2 := newRateLimiter(1_000)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := lim2.Wait(ctx, 1_000_000); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait err = %v, want context.Canceled", err)
	}
}
