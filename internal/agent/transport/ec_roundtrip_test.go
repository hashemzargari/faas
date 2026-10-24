package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/fass-storage/fass/internal/agent/client"
	"github.com/fass-storage/fass/internal/agent/shard"
	"github.com/fass-storage/fass/internal/agent/store"
	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/ec"
)

// TestECTwoTierRoundTripThroughStoreAndHTTP is the load-bearing data-plane
// test: encode with the recommended RC, store every shard through the real
// store over the real HTTP transport, lose up to local_k shards in every geo
// group, read the survivors back over HTTP, and decode the original payload
// byte-for-byte.
func TestECTwoTierRoundTripThroughStoreAndHTTP(t *testing.T) {
	ecRoundTrip(t, ec.Params{GeoN: 2, GeoK: 1, LocalN: 16, LocalK: 4}, 64<<10)
}

// TestECFlatDegenerateRoundTripThroughStoreAndHTTP proves the flat single-tier
// form (Cubbit DS3-Cloud's 20+40 expressed as geo 1+0) works through the same
// store and transport.
func TestECFlatDegenerateRoundTripThroughStoreAndHTTP(t *testing.T) {
	ecRoundTrip(t, ec.Params{GeoN: 1, GeoK: 0, LocalN: 16, LocalK: 4}, 32<<10)
}

func ecRoundTrip(t *testing.T, params ec.Params, payloadSize int) {
	t.Helper()
	ctx := context.Background()

	payload := make([]byte, payloadSize)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("random payload: %v", err)
	}

	codec, err := ec.New(params)
	if err != nil {
		t.Fatalf("ec.New: %v", err)
	}
	shards, geom, err := codec.Encode(payload)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if geom.TotalShards != params.TotalShards() {
		t.Fatalf("geometry total shards = %d, want %d", geom.TotalShards, params.TotalShards())
	}

	st := newTestStore(t, store.Options{})
	srv, err := New(Options{Store: st, Logger: discardLogger(), Version: "test"})
	if err != nil {
		t.Fatalf("transport.New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	c := client.New(client.Options{})
	setID := contract.ShardSetID("b0b0b0b0-1234-4abc-8def-0123456789ab")

	// Store every shard through HTTP → transport → store.
	for g := 0; g < params.GeoN+params.GeoK; g++ {
		for i := 0; i < params.ShardsPerGroup(); i++ {
			idx := g*params.ShardsPerGroup() + i
			body := shards[idx]
			if err := c.PutShard(ctx, ts.URL, contract.PutShardRequest{
				ShardSetID: setID,
				GeoGroup:   g,
				LocalIndex: i,
				Params:     params,
				ChunkIndex: 0,
				PayloadLen: len(body),
				Checksum:   shard.Sum64(body),
				Body:       bytes.NewReader(body),
			}); err != nil {
				t.Fatalf("PutShard(g=%d,i=%d): %v", g, i, err)
			}
		}
	}
	if got := st.Stats().ShardCount; got != int64(geom.TotalShards) {
		t.Fatalf("stored %d shards, want %d", got, geom.TotalShards)
	}

	// Lose up to local_k shards in every geo group (the worst case a local-tier
	// repair must survive).
	deleted := map[int]bool{}
	for g := 0; g < params.GeoN+params.GeoK; g++ {
		for i := 0; i < params.LocalK; i++ {
			if _, err := st.DestroyShard(ctx, setID, g, i); err != nil {
				t.Fatalf("DestroyShard(g=%d,i=%d): %v", g, i, err)
			}
			deleted[g*params.ShardsPerGroup()+i] = true
		}
	}

	// Read the survivors back over HTTP, verifying each returned checksum.
	read := make([][]byte, geom.TotalShards)
	for g := 0; g < params.GeoN+params.GeoK; g++ {
		for i := 0; i < params.ShardsPerGroup(); i++ {
			idx := g*params.ShardsPerGroup() + i
			if deleted[idx] {
				continue
			}
			rc, info, err := c.GetShard(ctx, ts.URL, setID, g, i)
			if err != nil {
				t.Fatalf("GetShard(g=%d,i=%d): %v", g, i, err)
			}
			got, err := io.ReadAll(rc)
			if err != nil {
				rc.Close()
				t.Fatalf("read shard(g=%d,i=%d): %v", g, i, err)
			}
			if err := rc.Close(); err != nil {
				t.Fatalf("close shard(g=%d,i=%d): %v", g, i, err)
			}
			if !bytes.Equal(got, shards[idx]) {
				t.Fatalf("shard(g=%d,i=%d) bytes differ from encoder output", g, i)
			}
			if info.Checksum != shard.Sum64(got) {
				t.Fatalf("shard(g=%d,i=%d) checksum header mismatch", g, i)
			}
			read[idx] = got
		}
	}

	decoded, err := codec.Decode(read, geom)
	if err != nil {
		t.Fatalf("Decode with %d lost shards: %v", len(deleted), err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("decoded payload differs from original: got %d bytes, want %d", len(decoded), len(payload))
	}
}

// TestECTwoTierSurvivesNexusLossAcrossThreeStores is the strongest data-plane
// test in this package: it uses three independent store instances + three real
// HTTP transports standing in for the three Nexuses of a geo 2+1 deployment,
// then deletes a whole group's worth of shards to simulate one Nexus being
// lost, and decodes the object from the surviving Nexuses.
//
// It proves the two-tier property against real on-disk shard layouts and real
// HTTP, not just in-memory shard slices:
//
//  1. baseline: all shards present on their Nexus -> decode matches payload
//  2. Nexus 1 lost entirely (all 20 shards of geo group 1) -> decode from
//     groups 0 and 2 (outer reconstruct) still matches byte-for-byte
//  3. Nexus 1 lost AND local_k=4 disks lost in surviving Nexus 0 -> inner
//     reconstruct in group 0 + outer reconstruct -> still matches
//  4. Nexus 2 lost as well (only 1 of geo_n=2 groups left) -> decode must fail,
//     which proves the test is not silently passing on fewer shards than the
//     code requires
func TestECTwoTierSurvivesNexusLossAcrossThreeStores(t *testing.T) {
	ctx := context.Background()
	params := ec.Params{GeoN: 2, GeoK: 1, LocalN: 16, LocalK: 4}
	groupSize := params.ShardsPerGroup()
	groups := params.GeoN + params.GeoK
	setID := contract.ShardSetID("3c0ffee0-1111-4222-8333-444455556666")

	payload := make([]byte, 96<<10)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("random payload: %v", err)
	}
	codec, err := ec.New(params)
	if err != nil {
		t.Fatalf("ec.New: %v", err)
	}
	shards, geom, err := codec.Encode(payload)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Three independent stores, one per Nexus, each behind its own HTTP transport.
	type nexus struct {
		store *store.Store
		srv   *httptest.Server
	}
	nexuses := make([]nexus, groups)
	for i := range nexuses {
		st := newTestStore(t, store.Options{})
		srv, err := New(Options{Store: st, Logger: discardLogger(), Version: "test"})
		if err != nil {
			t.Fatalf("transport.New(nexus %d): %v", i, err)
		}
		ts := httptest.NewServer(srv.Handler())
		t.Cleanup(ts.Close)
		nexuses[i] = nexus{store: st, srv: ts}
	}
	c := client.New(client.Options{})

	// Write every shard of group g to Nexus g, through HTTP.
	for g := 0; g < groups; g++ {
		for i := 0; i < groupSize; i++ {
			body := shards[g*groupSize+i]
			if err := c.PutShard(ctx, nexuses[g].srv.URL, contract.PutShardRequest{
				ShardSetID: setID,
				GeoGroup:   g,
				LocalIndex: i,
				Params:     params,
				PayloadLen: len(body),
				Checksum:   shard.Sum64(body),
				Body:       bytes.NewReader(body),
			}); err != nil {
				t.Fatalf("PutShard(nexus=%d,local=%d): %v", g, i, err)
			}
		}
		if got := nexuses[g].store.Stats().ShardCount; got != int64(groupSize) {
			t.Fatalf("nexus %d holds %d shards, want %d", g, got, groupSize)
		}
	}

	type key struct{ group, index int }

	// readSurvivors gathers every shard that is still present on its Nexus over
	// real HTTP; missing shards stay nil.
	readSurvivors := func(lost map[key]bool) [][]byte {
		t.Helper()
		out := make([][]byte, geom.TotalShards)
		for g := 0; g < groups; g++ {
			for i := 0; i < groupSize; i++ {
				if lost[key{g, i}] {
					continue
				}
				rc, info, err := c.GetShard(ctx, nexuses[g].srv.URL, setID, g, i)
				if err != nil {
					t.Fatalf("GetShard(nexus=%d,local=%d): %v", g, i, err)
				}
				got, err := io.ReadAll(rc)
				rc.Close()
				if err != nil {
					t.Fatalf("read shard(nexus=%d,local=%d): %v", g, i, err)
				}
				idx := g*groupSize + i
				if !bytes.Equal(got, shards[idx]) {
					t.Fatalf("shard(nexus=%d,local=%d) bytes differ from encoder output", g, i)
				}
				if info.Checksum != shard.Sum64(got) {
					t.Fatalf("shard(nexus=%d,local=%d) checksum header mismatch", g, i)
				}
				out[idx] = got
			}
		}
		return out
	}
	decode := func(lost map[key]bool) ([]byte, error) {
		return codec.Decode(readSurvivors(lost), geom)
	}

	lost := map[key]bool{}

	// 1. Baseline through three real Nexuses.
	decoded, err := decode(lost)
	if err != nil {
		t.Fatalf("baseline decode: %v", err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatal("baseline decode does not match payload")
	}

	// 2. Simulate a whole Nexus loss: wipe geo group 1 from its store.
	for i := 0; i < groupSize; i++ {
		if _, err := nexuses[1].store.DestroyShard(ctx, setID, 1, i); err != nil {
			t.Fatalf("DestroyShard(nexus=1,local=%d): %v", i, err)
		}
		lost[key{1, i}] = true
	}
	if got := nexuses[1].store.Stats().ShardCount; got != 0 {
		t.Fatalf("lost nexus still holds %d shards", got)
	}
	decoded, err = decode(lost)
	if err != nil {
		t.Fatalf("decode after whole-nexus loss: %v", err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatal("decode after whole-nexus loss does not match payload")
	}

	// 3. Also lose local_k disks in surviving Nexus 0 (inner reconstruct).
	for i := 0; i < params.LocalK; i++ {
		if _, err := nexuses[0].store.DestroyShard(ctx, setID, 0, i); err != nil {
			t.Fatalf("DestroyShard(nexus=0,local=%d): %v", i, err)
		}
		lost[key{0, i}] = true
	}
	decoded, err = decode(lost)
	if err != nil {
		t.Fatalf("decode after nexus + disk loss: %v", err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatal("decode after nexus + disk loss does not match payload")
	}

	// 4. Losing Nexus 2 as well leaves only 1 of geo_n=2 groups: must fail.
	for i := 0; i < groupSize; i++ {
		if _, err := nexuses[2].store.DestroyShard(ctx, setID, 2, i); err != nil {
			t.Fatalf("DestroyShard(nexus=2,local=%d): %v", i, err)
		}
		lost[key{2, i}] = true
	}
	if _, err := decode(lost); err == nil {
		t.Fatal("decode with only one surviving geo group succeeded; want ErrTooFewShards")
	}
}
