package store

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/fass-storage/fass/internal/agent/shard"
	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/ec"
)

func TestHeaderRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		set  contract.ShardSetID
	}{
		{"uuid set id", "0f1e2d3c-4b5a-4968-8776-655443322110"},
		{"arbitrary set id", "chunk-set/arbitrary-text"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			created := time.UnixMicro(1_726_000_000_123456).UTC()
			payload := []byte("shard bytes for header test")
			h := Header{
				Version:    shardVersion,
				Params:     ec.Params{GeoN: 2, GeoK: 1, LocalN: 16, LocalK: 4},
				ChunkIndex: 42,
				GeoGroup:   2,
				LocalIndex: 17,
				SetID:      tc.set,
				PayloadLen: int64(len(payload)),
				Checksum:   shard.Sum256(payload),
				CreatedAt:  created,
			}
			b, err := h.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary: %v", err)
			}
			if len(b) != headerFixedLen+len(tc.set) {
				t.Fatalf("encoded len = %d, want %d", len(b), headerFixedLen+len(tc.set))
			}
			got, hdrLen, err := ParseHeader(b)
			if err != nil {
				t.Fatalf("ParseHeader: %v", err)
			}
			if hdrLen != len(b) {
				t.Fatalf("hdrLen = %d, want %d", hdrLen, len(b))
			}
			if got.SetID != tc.set || got.GeoGroup != 2 || got.LocalIndex != 17 ||
				got.ChunkIndex != 42 || got.PayloadLen != int64(len(payload)) ||
				got.Checksum != shard.Sum256(payload) || !got.CreatedAt.Equal(created) {
				t.Fatalf("round trip mismatch: %+v", got)
			}
			if got.Params != h.Params {
				t.Fatalf("params = %+v, want %+v", got.Params, h.Params)
			}
		})
	}
}

func TestHeaderRejectsMalformed(t *testing.T) {
	h := Header{
		Version:    shardVersion,
		Params:     ec.Params{GeoN: 2, GeoK: 1, LocalN: 16, LocalK: 4},
		ChunkIndex: 1,
		GeoGroup:   0,
		LocalIndex: 0,
		SetID:      "01234567-89ab-4cde-8f01-23456789abcd",
		PayloadLen: 3,
		Checksum:   shard.Sum256([]byte("abc")),
		CreatedAt:  time.Now().UTC(),
	}
	good, err := h.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		buf  []byte
	}{
		{"short", good[:10]},
		{"bad magic", append([]byte(strings.Repeat("X", 8)), good[8:]...)},
		{"bad version", append([]byte{good[0], good[1], good[2], good[3], good[4], good[5], good[6], good[7], 99}, good[9:]...)},
		{"truncated extension", good[:headerFixedLen+3]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := ParseHeader(tc.buf); err == nil {
				t.Fatal("ParseHeader succeeded, want error")
			}
		})
	}

	// Semantic validation on encode.
	badGroup := h
	badGroup.GeoGroup = 3
	if _, err := badGroup.MarshalBinary(); err == nil {
		t.Fatal("MarshalBinary accepted out-of-range geo_group")
	}
	badID := h
	badID.SetID = ""
	if _, err := badID.MarshalBinary(); err == nil {
		t.Fatal("MarshalBinary accepted empty set id")
	}
	badParams := h
	badParams.Params = ec.Params{GeoN: 0, LocalN: 16}
	if _, err := badParams.MarshalBinary(); err == nil {
		t.Fatal("MarshalBinary accepted invalid params")
	}
}

func TestIndexRecordRoundTrip(t *testing.T) {
	e := entry{
		SetID:      "0f1e2d3c-4b5a-4968-8776-655443322110",
		GeoGroup:   1,
		LocalIndex: 9,
		ChunkIndex: 3,
		Params:     ec.Params{GeoN: 2, GeoK: 1, LocalN: 16, LocalK: 4},
		PayloadLen: 512,
		FileSize:   512 + 164,
		Checksum:   0xdeadbeefcafef00d,
		CreatedAt:  time.UnixMicro(1_726_000_000_000000).UTC(),
	}
	e.ID = shard.ID(e.SetID, e.GeoGroup, e.LocalIndex)

	b := encodeIndexRecord(opAdd, e)
	op, got, err := decodeIndexRecord(b)
	if err != nil {
		t.Fatalf("decodeIndexRecord: %v", err)
	}
	if op != opAdd {
		t.Fatalf("op = %c", op)
	}
	if got != e {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, e)
	}

	if _, _, err := decodeIndexRecord([]byte{opAdd}); err == nil {
		t.Fatal("decodeIndexRecord accepted short payload")
	}
	if !bytes.Equal(b, encodeIndexRecord(opAdd, e)) {
		t.Fatal("encoding is not deterministic")
	}
}
