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
