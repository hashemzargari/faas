package offloader

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/ec"
)

// ---------------------------------------------------------------------------
// Fake coordinator
// ---------------------------------------------------------------------------

type fakeCoord struct {
	contract.Coordinator // embedded nil: unused methods panic if called

	mu          sync.Mutex
	slots       []contract.Slot
	replacement []contract.Slot
	calls       int
	excluded    []contract.AgentID
	committed   *contract.CommitRequest
}

func (f *fakeCoord) ResolvePlacement(ctx context.Context, req contract.PlacementRequest) (contract.Placement, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if len(req.ExcludeAgents) > 0 {
		f.excluded = append([]contract.AgentID(nil), req.ExcludeAgents...)
		return contract.Placement{
			ShardSetID: req.ShardSetID,
			RingID:     "ring-1",
			Generation: 2,
			Slots:      append([]contract.Slot(nil), f.replacement...),
		}, nil
	}
	return contract.Placement{
		ShardSetID: req.ShardSetID,
		RingID:     "ring-1",
		Generation: 1,
		Slots:      append([]contract.Slot(nil), f.slots...),
	}, nil
}

func (f *fakeCoord) CommitObject(ctx context.Context, req contract.CommitRequest) (contract.CommitResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := req
	f.committed = &cp
	return contract.CommitResult{VersionID: req.VersionID, ETag: req.ETag}, nil
}

func (f *fakeCoord) lastCommit() contract.CommitRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.committed == nil {
		return contract.CommitRequest{}
	}
	return *f.committed
}

// ---------------------------------------------------------------------------
// Fake agents
// ---------------------------------------------------------------------------

type fakeAgents struct {
	mu      sync.Mutex
	shards  map[string][]byte // endpoint|set|group|index -> payload
	failPut map[string]bool   // endpoint -> fail every PUT
	corrupt map[string]bool   // endpoint -> return corrupted bytes
	gets    int
	puts    int
}

func newFakeAgents() *fakeAgents {
	return &fakeAgents{
		shards:  make(map[string][]byte),
		failPut: make(map[string]bool),
		corrupt: make(map[string]bool),
	}
}

func shardKey(endpoint string, id contract.ShardSetID, group, index int) string {
	return fmt.Sprintf("%s|%s|%d|%d", endpoint, id, group, index)
}

func (a *fakeAgents) PutShard(ctx context.Context, endpoint string, req contract.PutShardRequest) error {
	a.mu.Lock()
	a.puts++
	fail := a.failPut[endpoint]
	a.mu.Unlock()
	if fail {
		return contract.ErrInsufficientCap
	}
	data, err := io.ReadAll(req.Body)
	if err != nil {
		return err
	}
	if len(data) != req.PayloadLen {
		return fmt.Errorf("payload length %d != declared %d", len(data), req.PayloadLen)
	}
	if got := Checksum64(data); got != req.Checksum {
		return fmt.Errorf("checksum %d != declared %d", got, req.Checksum)
	}
	a.mu.Lock()
	a.shards[shardKey(endpoint, req.ShardSetID, req.GeoGroup, req.LocalIndex)] = data
	a.mu.Unlock()
	return nil
}

func (a *fakeAgents) GetShard(ctx context.Context, endpoint string, id contract.ShardSetID, group, index int) (io.ReadCloser, contract.ShardInfo, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.gets++
	data, ok := a.shards[shardKey(endpoint, id, group, index)]
	if !ok {
		return nil, contract.ShardInfo{}, contract.ErrNotFound
	}
	out := append([]byte(nil), data...)
	if a.corrupt[endpoint] {
		if len(out) > 0 {
			out[0] ^= 0xff
		}
	}
	return io.NopCloser(bytes.NewReader(out)), contract.ShardInfo{
		ShardSetID: id,
		GeoGroup:   group,
		LocalIndex: index,
		Size:       int64(len(out)),
		Checksum:   Checksum64(out),
		CreatedAt:  time.Now(),
	}, nil
}

func (a *fakeAgents) DeleteShards(ctx context.Context, endpoint string, ids []contract.ShardSetID) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	for k := range a.shards {
		for _, id := range ids {
			if strings.Contains(k, "|"+string(id)+"|") && strings.HasPrefix(k, endpoint+"|") {
				delete(a.shards, k)
			}
		}
	}
	return nil
}

func (a *fakeAgents) HasShards(ctx context.Context, endpoint string, ids []contract.ShardSetID) ([]bool, error) {
	return make([]bool, len(ids)), nil
}

func (a *fakeAgents) Health(ctx context.Context, endpoint string) error { return nil }

// ---------------------------------------------------------------------------
// Test environment
// ---------------------------------------------------------------------------

var testParams = ec.Params{GeoN: 2, GeoK: 1, LocalN: 4, LocalK: 2}

type env struct {
	off    *Offloader
	coord  *fakeCoord
	agents *fakeAgents
	spec   ObjectSpec
}

func newEnv(t *testing.T) *env {
	t.Helper()
	agents := newFakeAgents()
	slots := make([]contract.Slot, 0, testParams.TotalShards())
	for g := 0; g < testParams.GeoN+testParams.GeoK; g++ {
		for i := 0; i < testParams.ShardsPerGroup(); i++ {
			endpoint := fmt.Sprintf("agent-%d-%d:7100", g, i)
			slots = append(slots, contract.Slot{
				GeoGroup: g, LocalIndex: i,
				AgentID:  contract.AgentID(fmt.Sprintf("agent-%d-%d", g, i)),
				NodeID:   contract.NodeID(fmt.Sprintf("node-%d", g)),
				NexusID:  contract.NexusID(fmt.Sprintf("nexus-%d", g)),
				Endpoint: endpoint,
			})
		}
	}
	coord := &fakeCoord{slots: slots}
	seed := bytes.Repeat([]byte{0x42}, 32)
	keyrings, err := NewStaticKeyrings(seed, nil)
	if err != nil {
		t.Fatal(err)
	}
	off, err := New(Deps{
		Coord:    coord,
		Shards:   agents,
		Keyrings: keyrings,
		Config: Config{
			ChunkSize:           4 << 20,
			MaxConcurrentChunks: 2,
			ShardPutParallel:    8,
			ShardPutTimeout:     time.Second,
			ShardPutRetries:     1,
			ShardReadParallel:   16,
			ShardReadTimeout:    time.Second,
			HedgeAfter:          10 * time.Millisecond,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	spec := ObjectSpec{
		BucketID:     "bucket-1",
		Bucket:       "bkt",
		Key:          "dir/object.bin",
		TenantID:     "t1",
		ProjectID:    "p1",
		VersionID:    "v-1",
		Size:         -1, // streamed: length unknown up front
		ContentType:  "application/octet-stream",
		RCID:         "rc-1",
		Params:       testParams,
		ChunkSize:    4 << 20,
		StorageClass: "STANDARD",
	}
	return &env{off: off, coord: coord, agents: agents, spec: spec}
}

func (e *env) write(t *testing.T, payload []byte) contract.Manifest {
	t.Helper()
	res, err := e.off.Write(context.Background(), e.spec, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	commit := e.coord.lastCommit()
	if commit.VersionID != e.spec.VersionID {
		t.Fatalf("committed version = %q", commit.VersionID)
	}
	sum := md5.Sum(payload)
	if res.ETag != fmt.Sprintf("%x", sum) {
		t.Fatalf("etag = %q", res.ETag)
	}
	return contract.Manifest{
		TenantID:    e.spec.TenantID,
		ProjectID:   e.spec.ProjectID,
		BucketID:    e.spec.BucketID,
		Key:         e.spec.Key,
		VersionID:   commit.VersionID,
		Size:        commit.Size,
		ETag:        commit.ETag,
		ChunkSize:   commit.ChunkSize,
		Chunks:      commit.Chunks,
		Encryption:  commit.Encryption,
		ContentType: commit.ContentType,
		CreatedAt:   time.Now(),
	}
}

func randomPayload(t *testing.T, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	r := rand.New(rand.NewSource(42))
	if _, err := r.Read(buf); err != nil {
		t.Fatal(err)
	}
	return buf
}

func (e *env) read(t *testing.T, m contract.Manifest, rng *ByteRange) []byte {
	t.Helper()
	var buf bytes.Buffer
	err := e.off.Read(context.Background(), ReadRequest{
		Bucket:   e.spec.Bucket,
		Key:      e.spec.Key,
		TenantID: e.spec.TenantID,
		Manifest: m,
		Range:    rng,
	}, &buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return buf.Bytes()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestTwoTierRoundTrip(t *testing.T) {
	e := newEnv(t)
	payload := randomPayload(t, 10<<20+123) // 3 chunks
	m := e.write(t, payload)
	if len(m.Chunks) != 3 {
		t.Fatalf("chunks = %d, want 3", len(m.Chunks))
	}
	for _, ch := range m.Chunks {
		if len(ch.Slots) != testParams.TotalShards() {
			t.Fatalf("chunk %d slots = %d", ch.Index, len(ch.Slots))
		}
		if len(ch.Checksums) != testParams.TotalShards() {
			t.Fatalf("chunk %d checksums = %d", ch.Index, len(ch.Checksums))
		}
		if ch.CiphertextLen <= 0 || ch.ShardSize <= 0 {
			t.Fatalf("chunk %d geometry: ct=%d shard=%d", ch.Index, ch.CiphertextLen, ch.ShardSize)
		}
	}
	if got := e.read(t, m, nil); !bytes.Equal(got, payload) {
		t.Fatalf("round trip mismatch: got %d bytes, want %d", len(got), len(payload))
	}

	// Ranged read spanning a chunk boundary.
	rng := &ByteRange{Start: 4<<20 - 100, Length: 300}
	want := payload[rng.Start : rng.Start+rng.Length]
	if got := e.read(t, m, rng); !bytes.Equal(got, want) {
		t.Fatalf("range mismatch: got %d bytes", len(got))
	}
}

func TestLostShardsStillReadable(t *testing.T) {
	e := newEnv(t)
	payload := randomPayload(t, 4<<20)
	m := e.write(t, payload)

	// Lose local_k shards in every geo group: the group still has local_n.
	for g := 0; g < testParams.GeoN+testParams.GeoK; g++ {
		for i := 0; i < testParams.LocalK; i++ {
			slot := m.Chunks[0].Slots[g*testParams.ShardsPerGroup()+i]
			id := contract.ShardSetIDFor(m.BucketID, m.Key, m.VersionID, 0)
			e.agents.mu.Lock()
			delete(e.agents.shards, shardKey(slot.Endpoint, id, g, i))
			e.agents.mu.Unlock()
		}
	}
	if got := e.read(t, m, nil); !bytes.Equal(got, payload) {
		t.Fatalf("read with %d lost shards failed", testParams.LocalK*(testParams.GeoN+testParams.GeoK))
	}
}

func TestWholeGeoGroupLostStillReadable(t *testing.T) {
	e := newEnv(t)
	payload := randomPayload(t, 2<<20)
	m := e.write(t, payload)

	id := contract.ShardSetIDFor(m.BucketID, m.Key, m.VersionID, 0)
	// Lose the parity geo group entirely (group 2).
	for i := 0; i < testParams.ShardsPerGroup(); i++ {
		slot := m.Chunks[0].Slots[2*testParams.ShardsPerGroup()+i]
		e.agents.mu.Lock()
		delete(e.agents.shards, shardKey(slot.Endpoint, id, 2, i))
		e.agents.mu.Unlock()
	}
	if got := e.read(t, m, nil); !bytes.Equal(got, payload) {
		t.Fatal("read failed after losing a whole geo group")
	}
}

func TestCorruptionBeyondToleranceFails(t *testing.T) {
	e := newEnv(t)
	payload := randomPayload(t, 1<<20)
	m := e.write(t, payload)
	// Corrupt every shard in groups 0 and 2; only group 1 remains, which is
	// below geo_n=2, so the chunk is unreadable.
	for g := 0; g < testParams.GeoN+testParams.GeoK; g++ {
		if g == 1 {
			continue
		}
		for i := 0; i < testParams.ShardsPerGroup(); i++ {
			e.agents.mu.Lock()
			e.agents.corrupt[m.Chunks[0].Slots[g*testParams.ShardsPerGroup()+i].Endpoint] = true
			e.agents.mu.Unlock()
		}
	}
	var buf bytes.Buffer
	err := e.off.Read(context.Background(), ReadRequest{Manifest: m, Bucket: "bkt", Key: m.Key, TenantID: "t1"}, &buf)
	if !errors.Is(err, ErrMissingShards) {
		t.Fatalf("error = %v, want ErrMissingShards", err)
	}
}

func TestDisplacementOnShardFailure(t *testing.T) {
	e := newEnv(t)
	// The agent holding slot 5 always fails its PUT with insufficient capacity.
	failing := e.coord.slots[5]
	e.agents.failPut[failing.Endpoint] = true
	e.coord.replacement = append([]contract.Slot(nil), e.coord.slots...)
	e.coord.replacement[5] = contract.Slot{
		GeoGroup: failing.GeoGroup, LocalIndex: failing.LocalIndex,
		AgentID: "agent-replacement", NodeID: "node-r", NexusID: "nexus-r",
		Endpoint: "agent-replacement:7100",
	}

	payload := randomPayload(t, 1<<20)
	m := e.write(t, payload)

	e.coord.mu.Lock()
	excluded := e.coord.excluded
	e.coord.mu.Unlock()
	found := false
	for _, id := range excluded {
		if id == failing.AgentID {
			found = true
		}
	}
	if !found {
		t.Fatalf("failed agent %q was not excluded from re-placement (excluded=%v)", failing.AgentID, excluded)
	}
	for _, chunk := range m.Chunks {
		if got := chunk.Slots[5].Endpoint; got != "agent-replacement:7100" {
			t.Fatalf("slot 5 endpoint = %q, want replacement", got)
		}
	}
	if got := e.read(t, m, nil); !bytes.Equal(got, payload) {
		t.Fatal("read after displacement failed")
	}
}

func TestChecksumMismatchAbortsBeforeCommit(t *testing.T) {
	e := newEnv(t)
	payload := []byte("checksum me")
	e.spec.Checksums = []ExpectedChecksum{{Algorithm: ChecksumSHA256, Value: bytes.Repeat([]byte{0x00}, 32)}}
	_, err := e.off.Write(context.Background(), e.spec, bytes.NewReader(payload))
	if !errors.Is(err, ErrBadDigest) {
		t.Fatalf("error = %v, want ErrBadDigest", err)
	}
	e.coord.mu.Lock()
	committed := e.coord.committed
	e.coord.mu.Unlock()
	if committed != nil {
		t.Fatal("object was committed despite a checksum mismatch")
	}
}

func TestKeyFingerprintMismatch(t *testing.T) {
	e := newEnv(t)
	m := e.write(t, []byte("fingerprint"))
	m.Encryption.KeyFingerprint = bytes.Repeat([]byte{0xab}, 8)
	var buf bytes.Buffer
	err := e.off.Read(context.Background(), ReadRequest{Manifest: m, Bucket: "bkt", Key: m.Key, TenantID: "t1"}, &buf)
	if !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("error = %v, want ErrKeyMismatch", err)
	}
}

func TestWritePartThenReadBack(t *testing.T) {
	e := newEnv(t)
	payload := randomPayload(t, 300<<10)
	// Multipart parts bind the upload's gateway-minted version id in the AAD and
	// in the derived shard-set id, so a part can never be spliced into another
	// version.
	part, err := e.off.WritePart(context.Background(), e.spec, "upload-1", 1, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("WritePart: %v", err)
	}
	sum := md5.Sum(payload)
	if part.ETag != fmt.Sprintf("%x", sum) {
		t.Fatalf("part etag = %q", part.ETag)
	}
	if part.Size != int64(len(payload)) || len(part.Chunks) != 1 {
		t.Fatalf("part = %+v", part)
	}
	m := contract.Manifest{
		TenantID: "t1", ProjectID: "p1", BucketID: "bucket-1", Key: e.spec.Key,
		VersionID: e.spec.VersionID, Size: part.Size, ChunkSize: 4 << 20,
		Chunks: part.Chunks, Encryption: part.Encryption,
	}
	if got := e.read(t, m, nil); !bytes.Equal(got, payload) {
		t.Fatal("part round trip failed")
	}
}

// TestDeferredChecksums covers aws-chunked trailers, whose values only exist
// after the body has been consumed but which must still be verified before the
// object is committed.
func TestDeferredChecksums(t *testing.T) {
	e := newEnv(t)
	payload := []byte("trailer checksum payload")

	// Correct deferred checksum: commit succeeds.
	good := sha256.Sum256(payload)
	e.spec.Checksums = nil
	e.spec.DeferredChecksums = func() []ExpectedChecksum {
		return []ExpectedChecksum{{Algorithm: ChecksumSHA256, Value: good[:]}}
	}
	if _, err := e.off.Write(context.Background(), e.spec, bytes.NewReader(payload)); err != nil {
		t.Fatalf("write with correct trailer: %v", err)
	}

	// Wrong deferred checksum: abort before commit.
	e2 := newEnv(t)
	e2.spec.DeferredChecksums = func() []ExpectedChecksum {
		return []ExpectedChecksum{{Algorithm: ChecksumSHA256, Value: bytes.Repeat([]byte{0}, 32)}}
	}
	if _, err := e2.off.Write(context.Background(), e2.spec, bytes.NewReader(payload)); !errors.Is(err, ErrBadDigest) {
		t.Fatalf("error = %v, want ErrBadDigest", err)
	}
	if e2.coord.lastCommit().VersionID != "" {
		t.Fatal("object was committed despite a bad deferred checksum")
	}
}

// TestSinglePutStampsGoldenShardSetID pins the single-PUT derivation: the
// stamped id must stay byte-identical to contract.ShardSetIDFor (no scope), so
// objects written before the field existed still resolve.
func TestSinglePutStampsGoldenShardSetID(t *testing.T) {
	e := newEnv(t)
	m := e.write(t, randomPayload(t, 1<<20))
	for _, ch := range m.Chunks {
		want := contract.ShardSetIDFor(m.BucketID, m.Key, m.VersionID, ch.Index)
		if ch.ShardSetID != want {
			t.Fatalf("chunk %d stamped id = %s, want %s", ch.Index, ch.ShardSetID, want)
		}
	}
}

// TestMultipartPartsHaveDisjointShardSets is the regression for the aws-cli
// failure: two parts with identical payloads must not derive the same shard-set
// ids (they would collide on immutable shard addresses and fail with 409).
func TestMultipartPartsHaveDisjointShardSets(t *testing.T) {
	e := newEnv(t)
	payload := randomPayload(t, 1<<20)

	part1, err := e.off.WritePart(context.Background(), e.spec, "upload-1", 1, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("part 1: %v", err)
	}
	spec2 := e.spec
	spec2.Encryption = &part1.Encryption // all parts share the object's file key
	part2, err := e.off.WritePart(context.Background(), spec2, "upload-1", 2, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("part 2: %v", err)
	}

	seen := make(map[contract.ShardSetID]bool)
	for _, ch := range append(append([]contract.ChunkRef(nil), part1.Chunks...), part2.Chunks...) {
		if ch.ShardSetID == "" {
			t.Fatalf("chunk %d has no stamped shard-set id", ch.Index)
		}
		if seen[ch.ShardSetID] {
			t.Fatalf("shard-set id %s reused across parts/chunks", ch.ShardSetID)
		}
		seen[ch.ShardSetID] = true
	}
	if part1.Chunks[0].ShardSetID == part2.Chunks[0].ShardSetID {
		t.Fatal("part 2 chunk 0 reused part 1's shard-set id")
	}
	// The scoped derivation is exactly what distinguishes them.
	if want := contract.ShardSetIDForScoped(e.spec.BucketID, e.spec.Key, e.spec.VersionID, "part/2", 0); part2.Chunks[0].ShardSetID != want {
		t.Fatalf("part 2 chunk 0 = %s, want %s", part2.Chunks[0].ShardSetID, want)
	}
}

// TestMultipartRoundTrip completes a two-part upload the way the coordinator
// assembles it (chunk indices renumbered globally, one shared encryption meta)
// and reads the object back. Before the scoping fix this was impossible.
func TestMultipartRoundTrip(t *testing.T) {
	e := newEnv(t)
	part1Payload := randomPayload(t, 1<<20+11)
	part2Payload := randomPayload(t, 700<<10)

	part1, err := e.off.WritePart(context.Background(), e.spec, "upload-1", 1, bytes.NewReader(part1Payload))
	if err != nil {
		t.Fatalf("part 1: %v", err)
	}
	spec2 := e.spec
	spec2.Encryption = &part1.Encryption
	part2, err := e.off.WritePart(context.Background(), spec2, "upload-1", 2, bytes.NewReader(part2Payload))
	if err != nil {
		t.Fatalf("part 2: %v", err)
	}

	// Simulate coord/meta.CompleteUpload: flat dense chunk table, Index
	// renumbered globally while AADChunkIndex and ShardSetID travel unchanged,
	// encryption from the upload (part 1).
	var chunks []contract.ChunkRef
	for _, c := range append(append([]contract.ChunkRef(nil), part1.Chunks...), part2.Chunks...) {
		c.Index = len(chunks)
		chunks = append(chunks, c)
	}
	m := contract.Manifest{
		TenantID: e.spec.TenantID, ProjectID: e.spec.ProjectID,
		BucketID: e.spec.BucketID, Key: e.spec.Key, VersionID: e.spec.VersionID,
		Size: part1.Size + part2.Size, ChunkSize: 4 << 20,
		Chunks: chunks, Encryption: part1.Encryption,
	}
	want := append(append([]byte(nil), part1Payload...), part2Payload...)
	if got := e.read(t, m, nil); !bytes.Equal(got, want) {
		t.Fatalf("multipart round trip mismatch: got %d bytes, want %d", len(got), len(want))
	}
	// Ranged read across the part boundary also works.
	rng := &ByteRange{Start: int64(len(part1Payload)) - 100, Length: 200}
	if got := e.read(t, m, rng); !bytes.Equal(got, want[rng.Start:rng.Start+rng.Length]) {
		t.Fatalf("ranged multipart read mismatch")
	}
}
