package client_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/fass-storage/fass/internal/agent/client"
	"github.com/fass-storage/fass/internal/agent/shard"
	"github.com/fass-storage/fass/internal/agent/store"
	"github.com/fass-storage/fass/internal/agent/transport"
	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/ec"
)

var params = ec.Params{GeoN: 2, GeoK: 1, LocalN: 16, LocalK: 4}

func newCluster(t *testing.T) (*client.Client, *store.Store, *httptest.Server) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(context.Background(), store.Options{
		Root:   t.TempDir(),
		Logger: logger,
	})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	srv, err := transport.New(transport.Options{Store: st, Logger: logger, Version: "test"})
	if err != nil {
		t.Fatalf("transport.New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return client.New(client.Options{}), st, ts
}

func TestClientPutGetDeleteHasHealth(t *testing.T) {
	c, st, ts := newCluster(t)
	ctx := context.Background()
	setID := contract.ShardSetID("11111111-1111-4111-8111-111111111111")
	payload := bytes.Repeat([]byte("client-roundtrip"), 32)

	err := c.PutShard(ctx, ts.URL, contract.PutShardRequest{
		ShardSetID: setID,
		GeoGroup:   1,
		LocalIndex: 7,
		Params:     params,
		ChunkIndex: 3,
		PayloadLen: len(payload),
		Checksum:   shard.Sum64(payload),
		Body:       bytes.NewReader(payload),
	})
	if err != nil {
		t.Fatalf("PutShard: %v", err)
	}
	if st.Stats().ShardCount != 1 {
		t.Fatalf("store shard count = %d", st.Stats().ShardCount)
	}

	rc, info, err := c.GetShard(ctx, ts.URL, setID, 1, 7)
	if err != nil {
		t.Fatalf("GetShard: %v", err)
	}
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read shard: %v", err)
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("close shard: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch over HTTP client")
	}
	if info.Checksum != shard.Sum64(payload) || info.ShardSetID != setID || info.GeoGroup != 1 || info.LocalIndex != 7 {
		t.Fatalf("info = %+v", info)
	}
	if info.Size != int64(len(payload)) {
		t.Fatalf("info.Size = %d, want %d", info.Size, len(payload))
	}

	has, err := c.HasShards(ctx, ts.URL, []contract.ShardSetID{setID, "nope"})
	if err != nil {
		t.Fatalf("HasShards: %v", err)
	}
	if len(has) != 2 || !has[0] || has[1] {
		t.Fatalf("has = %v", has)
	}

	if err := c.Health(ctx, ts.URL); err != nil {
		t.Fatalf("Health: %v", err)
	}

	if err := c.DeleteShards(ctx, ts.URL, []contract.ShardSetID{setID}); err != nil {
		t.Fatalf("DeleteShards: %v", err)
	}
	_, _, err = c.GetShard(ctx, ts.URL, setID, 1, 7)
	if !errors.Is(err, contract.ErrNotFound) {
		t.Fatalf("GetShard after delete err = %v, want ErrNotFound", err)
	}
	// Deleting an already-absent set is idempotent.
	if err := c.DeleteShards(ctx, ts.URL, []contract.ShardSetID{setID}); err != nil {
		t.Fatalf("idempotent DeleteShards: %v", err)
	}
}

func TestClientInventoryStatsScrub(t *testing.T) {
	c, _, ts := newCluster(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		payload := []byte{byte(i), 0xaa}
		err := c.PutShard(ctx, ts.URL, contract.PutShardRequest{
			ShardSetID: contract.ShardSetID("22222222-2222-4222-8222-00000000000" + strconv.Itoa(i)),
			Params:     params,
			PayloadLen: len(payload),
			Checksum:   shard.Sum64(payload),
			Body:       bytes.NewReader(payload),
		})
		if err != nil {
			t.Fatalf("PutShard: %v", err)
		}
	}

	entries, next, err := c.Inventory(ctx, ts.URL, "", 2)
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	if len(entries) != 2 || next == "" {
		t.Fatalf("first page = %d entries, next=%q", len(entries), next)
	}
	entries2, next2, err := c.Inventory(ctx, ts.URL, next, 2)
	if err != nil {
		t.Fatalf("Inventory page 2: %v", err)
	}
	if len(entries2) != 1 || next2 != "" {
		t.Fatalf("second page = %d entries, next=%q", len(entries2), next2)
	}

	stats, err := c.Stats(ctx, ts.URL)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.ShardCount != 3 || stats.DiskID == "" || stats.Version != "test" {
		t.Fatalf("stats = %+v", stats)
	}

	if err := c.Scrub(ctx, ts.URL); err != nil {
		t.Fatalf("Scrub: %v", err)
	}
}

func TestClientAcceptsHostPortEndpoint(t *testing.T) {
	c, _, ts := newCluster(t)
	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(u.Host, "/") {
		t.Fatalf("unexpected host %q", u.Host)
	}
	if err := c.Health(context.Background(), u.Host); err != nil {
		t.Fatalf("Health with host:port endpoint: %v", err)
	}
}

func TestClientChecksumVerification(t *testing.T) {
	// A malicious/broken agent returns a checksum that does not match the body.
	payload := []byte("body bytes")
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Fass-Checksum", strconv.FormatUint(shard.Sum64([]byte("other bytes")), 10))
		w.Header().Set("X-Fass-Created-At", "2026-01-01T00:00:00Z")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	defer bad.Close()

	c := client.New(client.Options{})
	rc, _, err := c.GetShard(context.Background(), bad.URL, "set", 0, 0)
	if err != nil {
		t.Fatalf("GetShard: %v", err)
	}
	_, err = io.ReadAll(rc)
	rc.Close()
	if !errors.Is(err, client.ErrChecksumMismatch) {
		t.Fatalf("read err = %v, want ErrChecksumMismatch", err)
	}
}

func TestClientStatusMapping(t *testing.T) {
	cases := []struct {
		status int
		want   error
	}{
		{http.StatusNotFound, contract.ErrNotFound},
		{http.StatusConflict, contract.ErrConflict},
		{http.StatusInsufficientStorage, contract.ErrInsufficientCap},
		{http.StatusForbidden, contract.ErrForbidden},
		{http.StatusServiceUnavailable, contract.ErrUnavailable},
	}
	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{"error":{"code":"X","message":"boom"}}`))
			}))
			defer srv.Close()

			c := client.New(client.Options{})
			payload := []byte("abc")
			err := c.PutShard(context.Background(), srv.URL, contract.PutShardRequest{
				ShardSetID: "set", Params: params, PayloadLen: 3,
				Checksum: shard.Sum64(payload), Body: bytes.NewReader(payload),
			})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if !strings.Contains(err.Error(), "boom") {
				t.Fatalf("error lost server message: %v", err)
			}
		})
	}
}

func TestClientRejectsUnknownPayloadLen(t *testing.T) {
	c := client.New(client.Options{})
	err := c.PutShard(context.Background(), "127.0.0.1:1", contract.PutShardRequest{
		ShardSetID: "set", Params: params, PayloadLen: -1,
		Checksum: 1, Body: bytes.NewReader(nil),
	})
	if err == nil || !strings.Contains(err.Error(), "payload length") {
		t.Fatalf("err = %v", err)
	}
}
