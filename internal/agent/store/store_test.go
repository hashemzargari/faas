package store

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/fass-storage/fass/internal/agent/shard"
	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/ec"
)

var (
	testParams     = ec.Params{GeoN: 2, GeoK: 1, LocalN: 16, LocalK: 4}
	testFlatParams = ec.Params{GeoN: 1, GeoK: 0, LocalN: 16, LocalK: 4}
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func openTestStore(t *testing.T, opts Options) *Store {
	t.Helper()
	if opts.Root == "" {
		opts.Root = t.TempDir()
	}
	if opts.Logger == nil {
		opts.Logger = testLogger()
	}
	s, err := Open(context.Background(), opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

func putShard(t *testing.T, s *Store, setID contract.ShardSetID, group, index int, p ec.Params, payload []byte) PutResult {
	t.Helper()
	res, err := s.Put(context.Background(), PutRequest{
		ShardSetID: setID,
		GeoGroup:   group,
		LocalIndex: index,
		Params:     p,
		ChunkIndex: 0,
		PayloadLen: int64(len(payload)),
		Checksum:   shard.Sum64(payload),
	}, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("Put(%s/%d/%d): %v", setID, group, index, err)
	}
	return res
}

func TestPutGetRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t, Options{})
	payload := bytes.Repeat([]byte("fass-shard-payload"), 97)
	setID := contract.ShardSetID("11111111-1111-4111-8111-111111111111")

	res := putShard(t, s, setID, 1, 7, testParams, payload)
	if res.Stored != int64(len(payload)) {
		t.Fatalf("Stored = %d, want %d", res.Stored, len(payload))
	}
	if res.Checksum != shard.Sum64(payload) {
		t.Fatalf("Checksum = %016x, want %016x", res.Checksum, shard.Sum64(payload))
	}

	rd, err := s.Get(ctx, setID, 1, 7)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, err := io.ReadAll(rd)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if err := rd.Close(); err != nil {
		t.Fatalf("Close reader: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", len(got), len(payload))
	}
	if rd.Info.Checksum != shard.Sum64(payload) {
		t.Fatalf("Info.Checksum mismatch")
	}
	if rd.Info.Size != int64(headerFixedLen+len(setID))+int64(len(payload)) {
		t.Fatalf("Info.Size = %d", rd.Info.Size)
	}

	// The header must be self-describing.
	f, err := os.Open(s.pathFor(shard.ID(setID, 1, 7)))
	if err != nil {
		t.Fatalf("open shard file: %v", err)
	}
	defer f.Close()
	hdr, hdrLen, err := readHeaderAt(f)
	if err != nil {
		t.Fatalf("readHeaderAt: %v", err)
	}
	if hdr.SetID != setID || hdr.GeoGroup != 1 || hdr.LocalIndex != 7 {
		t.Fatalf("header address = %s/%d/%d", hdr.SetID, hdr.GeoGroup, hdr.LocalIndex)
	}
	if hdr.Params != testParams {
		t.Fatalf("header params = %+v", hdr.Params)
	}
	if hdr.PayloadLen != int64(len(payload)) || hdr.Checksum != shard.Sum256(payload) {
		t.Fatalf("header payload metadata mismatch")
	}
	if hdrLen != headerFixedLen+len(setID) {
		t.Fatalf("headerLen = %d", hdrLen)
	}
}

func TestPutIdempotentRewrite(t *testing.T) {
	s := openTestStore(t, Options{})
	setID := contract.ShardSetID("22222222-2222-4222-8222-222222222222")
	payload := []byte("idempotent shard bytes")

	first := putShard(t, s, setID, 0, 3, testParams, payload)
	if first.Idempotent {
		t.Fatal("first put reported idempotent")
	}
	before := s.Stats()

	second := putShard(t, s, setID, 0, 3, testParams, payload)
	if !second.Idempotent {
		t.Fatal("second put of identical bytes should be idempotent")
	}
	if second.Stored != 0 {
		t.Fatalf("idempotent put Stored = %d, want 0", second.Stored)
	}
	after := s.Stats()
	if after.ShardCount != before.ShardCount || after.UsedBytes != before.UsedBytes {
		t.Fatalf("idempotent put changed stats: %+v -> %+v", before, after)
	}

	// The payload is still exactly one copy and still readable.
	rd, err := s.Get(context.Background(), setID, 0, 3)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, err := io.ReadAll(rd)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	rd.Close()
	if !bytes.Equal(got, payload) {
		t.Fatal("payload changed after idempotent rewrite")
	}
}

func TestPutImmutabilityConflict(t *testing.T) {
	s := openTestStore(t, Options{})
	setID := contract.ShardSetID("33333333-3333-4333-8333-333333333333")
	original := []byte("original immutable bytes")
	other := []byte("different bytes!!!!!!")

	putShard(t, s, setID, 2, 1, testParams, original)
	_, err := s.Put(context.Background(), PutRequest{
		ShardSetID: setID,
		GeoGroup:   2,
		LocalIndex: 1,
		Params:     testParams,
		PayloadLen: int64(len(other)),
		Checksum:   shard.Sum64(other),
	}, bytes.NewReader(other))
	if !errors.Is(err, contract.ErrConflict) {
		t.Fatalf("conflicting put err = %v, want contract.ErrConflict", err)
	}

	// Original must be untouched.
	rd, err := s.Get(context.Background(), setID, 2, 1)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, _ := io.ReadAll(rd)
	rd.Close()
	if !bytes.Equal(got, original) {
		t.Fatal("immutability violated: original shard bytes changed")
	}
}

func TestPutChecksumAndLengthValidation(t *testing.T) {
	s := openTestStore(t, Options{MaxShardBytes: 64})
	setID := contract.ShardSetID("44444444-4444-4444-8444-444444444444")

	cases := []struct {
		name    string
		req     PutRequest
		payload []byte
		want    error
	}{
		{
			name: "bad checksum",
			req: PutRequest{ShardSetID: setID, Params: testParams, PayloadLen: 3,
				Checksum: 0xdeadbeef},
			payload: []byte("abc"),
			want:    ErrChecksumMismatch,
		},
		{
			name: "length mismatch",
			req: PutRequest{ShardSetID: setID, Params: testParams, PayloadLen: 10,
				Checksum: shard.Sum64([]byte("abc"))},
			payload: []byte("abc"),
			want:    ErrLengthMismatch,
		},
		{
			name: "too large",
			req: PutRequest{ShardSetID: setID, Params: testParams, PayloadLen: 100,
				Checksum: shard.Sum64([]byte("abc"))},
			payload: []byte("abc"),
			want:    ErrTooLarge,
		},
		{
			name: "bad group",
			req: PutRequest{ShardSetID: setID, Params: testParams, GeoGroup: 3,
				Checksum: shard.Sum64([]byte("abc"))},
			payload: []byte("abc"),
			want:    ErrBadRequest,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.Put(context.Background(), tc.req, bytes.NewReader(tc.payload))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}

	// Nothing failed should have left payload shards behind; only swept temp
	// files are allowed to have existed.
	entries, err := os.ReadDir(s.incomingDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("incoming/ not empty after failed puts: %v", entries)
	}
}

func TestCrashSafetySweepAndIndexRecovery(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()

	st := openTestStore(t, Options{Root: root})
	payload := []byte("survives a crash")
	putShard(t, st, contract.ShardSetID("55555555-5555-4555-8555-555555555555"), 1, 2, testParams, payload)

	// Simulate a crash mid-write: leave an incoming .partial file.
	partial := filepath.Join(root, "incoming", "deadbeef.partial")
	if err := os.WriteFile(partial, []byte("half written shard"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Simulate a lost index: remove the append log entirely. The orphan shard
	// files must be re-adopted from their self-describing headers on boot.
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "index", indexFilename)); err != nil {
		t.Fatal(err)
	}

	s2 := openTestStore(t, Options{Root: root})

	if _, err := os.Stat(partial); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial file was not swept on boot: %v", err)
	}
	infos, next, err := s2.Inventory(ctx, "", 10)
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	if len(infos) != 1 || next != "" {
		t.Fatalf("recovered inventory = %v, next=%q", infos, next)
	}
	rd, err := s2.Get(ctx, contract.ShardSetID("55555555-5555-4555-8555-555555555555"), 1, 2)
	if err != nil {
		t.Fatalf("Get recovered shard: %v", err)
	}
	got, _ := io.ReadAll(rd)
	rd.Close()
	if !bytes.Equal(got, payload) {
		t.Fatalf("recovered shard payload mismatch: %q", got)
	}
}

func TestTornIndexTailIsTruncated(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	s := openTestStore(t, Options{Root: root})
	setID := contract.ShardSetID("66666666-6666-4666-8666-666666666666")
	putShard(t, s, setID, 0, 0, testParams, []byte("shard zero"))
	putShard(t, s, setID, 0, 1, testParams, []byte("shard one"))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Append a torn record: plausible length, truncated body.
	idxPath := filepath.Join(root, "index", indexFilename)
	f, err := os.OpenFile(idxPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], 100)
	if _, err := f.Write(lenBuf[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("only-a-few-bytes")); err != nil {
		t.Fatal(err)
	}
	f.Close()

	s2 := openTestStore(t, Options{Root: root})
	infos, _, err := s2.Inventory(ctx, "", 10)
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	if len(infos) != 2 {
		t.Fatalf("after torn tail: %d shards, want 2", len(infos))
	}

	// The store must remain usable: appending after truncation still replays.
	putShard(t, s2, setID, 0, 2, testParams, []byte("shard two"))
	if err := s2.Close(); err != nil {
		t.Fatal(err)
	}
	s3 := openTestStore(t, Options{Root: root})
	infos, _, err = s3.Inventory(ctx, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 3 {
		t.Fatalf("after append following truncation: %d shards, want 3", len(infos))
	}
}

func TestCapacityReservation(t *testing.T) {
	// total 10000, reserve 5% => 500 reserved. Static capacity is enough to
	// prove the admission rule.
	const total = 10000
	capFn := func(string) (int64, int64, error) { return total, total, nil }
	s := openTestStore(t, Options{ReservePct: 5, CapacityFunc: capFn})

	stats := s.Stats()
	if stats.ReservedBytes != 500 {
		t.Fatalf("ReservedBytes = %d, want 500", stats.ReservedBytes)
	}
	if stats.FreeBytes != 9500 {
		t.Fatalf("FreeBytes = %d, want 9500", stats.FreeBytes)
	}

	payload := bytes.Repeat([]byte("x"), 9600)
	_, err := s.Put(context.Background(), PutRequest{
		ShardSetID: "77777777-7777-4777-8777-777777777777",
		Params:     testParams,
		PayloadLen: int64(len(payload)),
		Checksum:   shard.Sum64(payload),
	}, bytes.NewReader(payload))
	if !errors.Is(err, ErrInsufficientCapacity) {
		t.Fatalf("err = %v, want ErrInsufficientCapacity", err)
	}

	small := bytes.Repeat([]byte("y"), 9000)
	res, err := s.Put(context.Background(), PutRequest{
		ShardSetID: "88888888-8888-4888-8888-888888888888",
		Params:     testParams,
		PayloadLen: int64(len(small)),
		Checksum:   shard.Sum64(small),
	}, bytes.NewReader(small))
	if err != nil {
		t.Fatalf("put within reservation: %v", err)
	}
	if res.Stored != 9000 {
		t.Fatalf("Stored = %d", res.Stored)
	}
}

func TestInventoryPagination(t *testing.T) {
	s := openTestStore(t, Options{})
	const n = 7
	for i := 0; i < n; i++ {
		setID := contract.ShardSetID("9a9a9a9a-9a9a-4a9a-8a9a-00000000000" + string(rune('0'+i)))
		putShard(t, s, setID, 0, i%testParams.ShardsPerGroup(), testParams, []byte{byte(i)})
	}

	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		infos, next, err := s.Inventory(context.Background(), cursor, 3)
		if err != nil {
			t.Fatalf("Inventory page: %v", err)
		}
		pages++
		for _, info := range infos {
			key := string(info.ShardSetID)
			if seen[key] {
				t.Fatalf("duplicate shard in inventory: %s", key)
			}
			seen[key] = true
		}
		if next == "" {
			break
		}
		cursor = next
		if pages > 10 {
			t.Fatal("inventory pagination did not terminate")
		}
	}
	if len(seen) != n {
		t.Fatalf("saw %d shards, want %d", len(seen), n)
	}
	if pages != 3 {
		t.Fatalf("pages = %d, want 3 (3+3+1)", pages)
	}

	// Out-of-range cursor returns an empty last page.
	infos, next, err := s.Inventory(context.Background(), "zzzz", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 0 || next != "" {
		t.Fatalf("after-last page = %v, next=%q", infos, next)
	}
}

func TestDeleteSetAndHas(t *testing.T) {
	s := openTestStore(t, Options{})
	setA := contract.ShardSetID("aaaa")
	setB := contract.ShardSetID("bbbb")
	for i := 0; i < 3; i++ {
		putShard(t, s, setA, 0, i, testFlatParams, []byte{byte(i)})
	}
	putShard(t, s, setB, 0, 0, testFlatParams, []byte("b"))

	has, err := s.Has(context.Background(), []contract.ShardSetID{setA, setB, "cccc"})
	if err != nil {
		t.Fatal(err)
	}
	if !has[0] || !has[1] || has[2] {
		t.Fatalf("Has = %v", has)
	}

	removed, err := s.DeleteSet(context.Background(), setA)
	if err != nil {
		t.Fatalf("DeleteSet: %v", err)
	}
	if removed != 3 {
		t.Fatalf("removed = %d, want 3", removed)
	}
	if _, err := s.Get(context.Background(), setA, 0, 0); !errors.Is(err, contract.ErrNotFound) {
		t.Fatalf("Get deleted shard err = %v, want ErrNotFound", err)
	}
	has, _ = s.Has(context.Background(), []contract.ShardSetID{setA, setB})
	if has[0] || !has[1] {
		t.Fatalf("Has after delete = %v", has)
	}
	if st := s.Stats(); st.ShardCount != 1 {
		t.Fatalf("ShardCount = %d, want 1", st.ShardCount)
	}
}

func TestCorruptShardIsQuarantinedAndNeverServed(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()

	var reported []contract.ShardStatus
	var mu sync.Mutex
	s := openTestStore(t, Options{
		Root: root,
		OnCorrupt: func(st contract.ShardStatus) {
			mu.Lock()
			reported = append(reported, st)
			mu.Unlock()
		},
	})
	setID := contract.ShardSetID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
	payload := bytes.Repeat([]byte("corruption-target"), 32)
	putShard(t, s, setID, 0, 5, testParams, payload)

	id := shard.ID(setID, 0, 5)
	path := s.pathFor(id)
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := f.Stat()
	if _, err := f.WriteAt([]byte{0xff}, fi.Size()-1); err != nil {
		t.Fatal(err)
	}
	f.Close()

	if _, err := s.Get(ctx, setID, 0, 5); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Get corrupt shard err = %v, want ErrCorrupt", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("corrupt shard file still in place: %v", err)
	}
	quarantined, err := os.ReadDir(s.quarantineDir)
	if err != nil || len(quarantined) != 1 {
		t.Fatalf("quarantine dir = %v, err = %v", quarantined, err)
	}
	if has, _ := s.Has(ctx, []contract.ShardSetID{setID}); has[0] {
		t.Fatal("quarantined shard still reported present")
	}
	mu.Lock()
	n := len(reported)
	mu.Unlock()
	if n != 1 {
		t.Fatalf("OnCorrupt reports = %d, want 1", n)
	}
	if reported[0].State != "CORRUPT" || reported[0].Slot != 0*testParams.ShardsPerGroup()+5 {
		t.Fatalf("reported status = %+v", reported[0])
	}
}

func TestVerifyDetectsCorruption(t *testing.T) {
	s := openTestStore(t, Options{})
	setID := contract.ShardSetID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
	payload := []byte("verify-me-please")
	putShard(t, s, setID, 1, 1, testParams, payload)

	info, err := s.Verify(context.Background(), setID, 1, 1)
	if err != nil {
		t.Fatalf("Verify healthy shard: %v", err)
	}
	if info.Checksum != shard.Sum64(payload) {
		t.Fatalf("Verify checksum = %016x", info.Checksum)
	}

	if _, err := s.Verify(context.Background(), setID, 1, 2); !errors.Is(err, contract.ErrNotFound) {
		t.Fatalf("Verify missing shard err = %v", err)
	}
}

func TestWalkVisitsEveryShard(t *testing.T) {
	s := openTestStore(t, Options{})
	for i := 0; i < 5; i++ {
		putShard(t, s, contract.ShardSetID("dddd"+strings.Repeat("0", 32)), 0, i, testFlatParams, []byte{byte(i)})
	}
	count := 0
	if err := s.Walk(context.Background(), 2, func(contract.ShardInfo) error {
		count++
		return nil
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if count != 5 {
		t.Fatalf("Walk visited %d shards, want 5", count)
	}
}

func TestOpenIsPersistentAcrossRestart(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	s := openTestStore(t, Options{Root: root})
	setID := contract.ShardSetID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
	payload := []byte("persisted across restart")
	putShard(t, s, setID, 2, 2, testParams, payload)
	diskID := s.DiskID()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2 := openTestStore(t, Options{Root: root})
	if s2.DiskID() != diskID {
		t.Fatalf("disk id changed across restart: %s -> %s", diskID, s2.DiskID())
	}
	rd, err := s2.Get(ctx, setID, 2, 2)
	if err != nil {
		t.Fatalf("Get after restart: %v", err)
	}
	got, _ := io.ReadAll(rd)
	rd.Close()
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch after restart")
	}
}

func TestCompactionKeepsIndexCorrect(t *testing.T) {
	// Force many records so the append log compacts, then prove a replay of the
	// compacted file still yields the same live set.
	s := openTestStore(t, Options{})
	for round := 0; round < 40; round++ {
		setID := contract.ShardSetID(fmt.Sprintf("set-%d", round))
		for i := 0; i < 8; i++ {
			putShard(t, s, setID, 0, i, testParams, []byte{byte(round), byte(i)})
		}
	}
	// Delete and re-add enough to push records past the compaction floor.
	live := len(s.idx)
	s.ix.records = indexCompactionMin + 1
	s.mu.Lock()
	s.maybeCompactLocked()
	s.mu.Unlock()
	if s.ix.records != live {
		t.Fatalf("after compaction records = %d, want %d", s.ix.records, live)
	}
	root := s.Root()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2 := openTestStore(t, Options{Root: root})
	if len(s2.idx) != live {
		t.Fatalf("after replay inside = %d, want %d", len(s2.idx), live)
	}
}

func TestDiskIDFlagOnFreshDisk(t *testing.T) {
	const want = "disk-authoritative-0001"
	root := t.TempDir()

	s := openTestStore(t, Options{Root: root, DiskID: want})
	if got := s.DiskID(); got != want {
		t.Fatalf("DiskID = %q, want %q", got, want)
	}

	// The explicit identity must be persisted, not regenerated.
	raw, err := os.ReadFile(filepath.Join(root, "state.json"))
	if err != nil {
		t.Fatalf("read state.json: %v", err)
	}
	var persisted State
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatalf("parse state.json: %v", err)
	}
	if persisted.DiskID != want {
		t.Fatalf("persisted disk id = %q, want %q", persisted.DiskID, want)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// A restart without the flag keeps the identity...
	s2 := openTestStore(t, Options{Root: root})
	if got := s2.DiskID(); got != want {
		t.Fatalf("after restart without flag: DiskID = %q, want %q", got, want)
	}
	if err := s2.Close(); err != nil {
		t.Fatal(err)
	}

	// ...and so does a restart with the same flag.
	s3 := openTestStore(t, Options{Root: root, DiskID: want})
	if got := s3.DiskID(); got != want {
		t.Fatalf("after restart with matching flag: DiskID = %q, want %q", got, want)
	}
}

func TestDiskIDFlagConflictFailsClosed(t *testing.T) {
	root := t.TempDir()
	const persistedID = "disk-alpha"
	const otherID = "disk-beta"

	s := openTestStore(t, Options{Root: root, DiskID: persistedID})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	_, err := Open(context.Background(), Options{
		Root:   root,
		DiskID: otherID,
		Logger: testLogger(),
	})
	if err == nil {
		t.Fatal("Open with conflicting --disk-id succeeded; must fail closed")
	}
	if !errors.Is(err, ErrDiskIDMismatch) {
		t.Fatalf("err = %v, want ErrDiskIDMismatch", err)
	}
	if !strings.Contains(err.Error(), persistedID) || !strings.Contains(err.Error(), otherID) {
		t.Fatalf("error does not name both ids: %v", err)
	}

	// The persisted identity must not have been overridden by the flag.
	raw, err := os.ReadFile(filepath.Join(root, "state.json"))
	if err != nil {
		t.Fatalf("read state.json: %v", err)
	}
	var persisted State
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.DiskID != persistedID {
		t.Fatalf("state.json was changed to %q by the rejected flag", persisted.DiskID)
	}

	// The disk is still usable under its real identity.
	s2 := openTestStore(t, Options{Root: root})
	if got := s2.DiskID(); got != persistedID {
		t.Fatalf("DiskID after rejected override = %q, want %q", got, persistedID)
	}
}

func TestDiskIDValidation(t *testing.T) {
	cases := []string{
		" leading-space",
		"trailing-space ",
		strings.Repeat("x", maxDiskIDLen+1),
		"control\x00char",
		"line\nbreak",
	}
	for _, bad := range cases {
		t.Run(bad, func(t *testing.T) {
			_, err := Open(context.Background(), Options{
				Root:   t.TempDir(),
				DiskID: bad,
				Logger: testLogger(),
			})
			if !errors.Is(err, ErrBadRequest) {
				t.Fatalf("Open(disk_id=%q) err = %v, want ErrBadRequest", bad, err)
			}
		})
	}
}
