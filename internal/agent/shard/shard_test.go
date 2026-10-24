package shard

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/ec"
)

func TestSum64KnownVector(t *testing.T) {
	// SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
	// The FASS checksum is the big-endian uint64 of the first 8 bytes.
	const want uint64 = 0xba7816bf8f01cfea
	if got := Sum64([]byte("abc")); got != want {
		t.Fatalf("Sum64(abc) = %016x, want %016x", got, want)
	}

	h := NewHasher()
	if _, err := h.Write([]byte("a")); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Write([]byte("bc")); err != nil {
		t.Fatal(err)
	}
	if got := h.Sum64(); got != want {
		t.Fatalf("incremental Sum64 = %016x, want %016x", got, want)
	}
	if got := h.Sum256(); hex.EncodeToString(got[:]) != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("Sum256 = %x", got)
	}
	if got := Sum64(nil); got != 0xe3b0c44298fc1c14 {
		t.Fatalf("Sum64(empty) = %016x, want e3b0c44298fc1c14", got)
	}
}

func TestIDDeterministicAndAddressSensitive(t *testing.T) {
	set := contract.ShardSetID("0f1e2d3c-4b5a-4968-8776-655443322110")
	a := ID(set, 0, 0)
	b := ID(set, 0, 0)
	if a != b {
		t.Fatalf("ID not deterministic: %q != %q", a, b)
	}
	if len(a) != 26 {
		t.Fatalf("ID length = %d, want 26", len(a))
	}
	if a != strings.ToLower(a) {
		t.Fatalf("ID is not lowercase: %q", a)
	}
	for _, other := range []string{ID(set, 0, 1), ID(set, 1, 0), ID("another-set", 0, 0)} {
		if other == a {
			t.Fatalf("ID collision between distinct addresses: %q", a)
		}
	}
}

func TestSetIDBytes(t *testing.T) {
	raw, canonical := SetIDBytes("0f1e2d3c-4b5a-4968-8776-655443322110")
	if !canonical {
		t.Fatal("canonical UUID not recognised")
	}
	want := [16]byte{0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x49, 0x68, 0x87, 0x76, 0x65, 0x54, 0x43, 0x32, 0x21, 0x10}
	if raw != want {
		t.Fatalf("raw = %x, want %x", raw, want)
	}

	raw, canonical = SetIDBytes("shard-set-not-a-uuid")
	if canonical {
		t.Fatal("non-UUID reported canonical")
	}
	if raw == ([16]byte{}) {
		t.Fatal("non-UUID hash is all zeroes")
	}
}

func TestParamsHeaderRoundTrip(t *testing.T) {
	cases := []ec.Params{
		{GeoN: 2, GeoK: 1, LocalN: 16, LocalK: 4},
		{GeoN: 1, GeoK: 0, LocalN: 16, LocalK: 4},
		{GeoN: 3, GeoK: 2, LocalN: 4, LocalK: 2},
	}
	for _, p := range cases {
		h := ParamsHeader(p)
		got, err := ParseParamsHeader(h)
		if err != nil {
			t.Fatalf("ParseParamsHeader(%q): %v", h, err)
		}
		if got != p {
			t.Fatalf("round trip %+v -> %q -> %+v", p, h, got)
		}
	}

	for _, bad := range []string{"", "2,1,16", "2,1,16,4,5", "a,1,16,4", "2,1,0,4", "2,10,16,4"} {
		if _, err := ParseParamsHeader(bad); err == nil {
			t.Fatalf("ParseParamsHeader(%q) succeeded, want error", bad)
		}
	}
}
