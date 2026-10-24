package ec

import (
	"bytes"
	"math/rand"
	"testing"
)

func testParams() []Params {
	return []Params{
		{GeoN: 1, GeoK: 0, LocalN: 16, LocalK: 4},  // single-site 1.25x
		{GeoN: 2, GeoK: 1, LocalN: 16, LocalK: 4},  // recommended 3-site 1.875x
		{GeoN: 2, GeoK: 1, LocalN: 4, LocalK: 2},   // small test config
		{GeoN: 3, GeoK: 2, LocalN: 4, LocalK: 2},   // 2-site-tolerance 2.25x
		{GeoN: 1, GeoK: 0, LocalN: 20, LocalK: 40}, // Cubbit DS3-Cloud flat 20+60
		{GeoN: 1, GeoK: 0, LocalN: 4, LocalK: 0},   // no redundancy (ratio 1.0)
	}
}

func mustCodec(t *testing.T, p Params) *Codec {
	t.Helper()
	c, err := New(p)
	if err != nil {
		t.Fatalf("New(%+v): %v", p, err)
	}
	return c
}

func payload(n int, seed int64) []byte {
	r := rand.New(rand.NewSource(seed))
	b := make([]byte, n)
	r.Read(b)
	return b
}

func TestValidate(t *testing.T) {
	good := []Params{
		{GeoN: 1, GeoK: 0, LocalN: 2, LocalK: 1},
		{GeoN: 2, GeoK: 1, LocalN: 16, LocalK: 4},
		{GeoN: MaxGeoN, GeoK: MaxGeoK, LocalN: MaxLocalN, LocalK: MaxLocalK},
	}
	for _, p := range good {
		if err := p.Validate(); err != nil {
			t.Errorf("expected valid %+v: %v", p, err)
		}
	}
	bad := []Params{
		{GeoN: 0, GeoK: 0, LocalN: 2, LocalK: 1},
		{GeoN: 2, GeoK: -1, LocalN: 16, LocalK: 4},
		{GeoN: 1, GeoK: 0, LocalN: 0, LocalK: 0},
		{GeoN: 1, GeoK: 0, LocalN: 1, LocalK: 9}, // ratio 10 -> too high
		{GeoN: MaxGeoN + 1, GeoK: 0, LocalN: 2, LocalK: 1},
		{GeoN: 1, GeoK: 0, LocalN: 2, LocalK: 200}, // 202 shards, ratio 101
	}
	for _, p := range bad {
		if err := p.Validate(); err == nil {
			t.Errorf("expected invalid %+v", p)
		}
	}
}

func TestRatioKnownValues(t *testing.T) {
	cases := []struct {
		p    Params
		want float64
	}{
		{Params{1, 0, 16, 4}, 1.25},
		{Params{1, 0, 8, 2}, 1.25},
		{Params{2, 1, 16, 4}, 1.875},
		{Params{3, 2, 4, 2}, 2.5},
		{Params{1, 0, 20, 40}, 3.0},
		{Params{1, 0, 4, 0}, 1.0},
		{Params{1, 0, 6, 3}, 1.5},
	}
	for _, tc := range cases {
		if got := tc.p.Ratio(); got != tc.want {
			t.Errorf("%+v: ratio = %v, want %v", tc.p, got, tc.want)
		}
	}
}

func TestGeometryInvariants(t *testing.T) {
	sizes := []int{1, 2, 7, 100, 4096, 4096 + 13, 1 << 20, 1<<20 + 5}
	for _, p := range testParams() {
		c := mustCodec(t, p)
		for _, n := range sizes {
			g := c.Geometry(n)
			if g.TotalShards != p.TotalShards() {
				t.Fatalf("%+v n=%d: total shards %d, want %d", p, n, g.TotalShards, p.TotalShards())
			}
			if g.ShardSize*p.GeoN*p.LocalN < n {
				t.Fatalf("%+v n=%d: capacity %d < payload", p, n, g.ShardSize*p.GeoN*p.LocalN)
			}
			// Padding must stay below one coding unit.
			unit := p.GeoN * p.LocalN
			if pad := g.ShardSize*unit - n; pad >= unit && n > 0 {
				t.Fatalf("%+v n=%d: padding %d exceeds unit %d", p, n, pad, unit)
			}
			// Overhead using padded sizes never exceeds the nominal ratio by much.
			if n >= 1<<20 && g.Overhead() > p.Ratio()*1.01 {
				t.Fatalf("%+v n=%d: overhead %.4f > ratio %.4f", p, n, g.Overhead(), p.Ratio())
			}
		}
	}
}

func TestRoundTrip(t *testing.T) {
	sizes := []int{1, 2, 15, 16, 17, 255, 1000, 4096, 4096 + 1, 1 << 20, 1<<20 + 37}
	for _, p := range testParams() {
		c := mustCodec(t, p)
		for _, n := range sizes {
			want := payload(n, int64(n)+int64(p.GeoN))
			shards, geom, err := c.Encode(want)
			if err != nil {
				t.Fatalf("%+v encode n=%d: %v", p, n, err)
			}
			if len(shards) != geom.TotalShards {
				t.Fatalf("%+v n=%d: %d shards, want %d", p, n, len(shards), geom.TotalShards)
			}
			got, err := c.Decode(shards, geom)
			if err != nil {
				t.Fatalf("%+v decode n=%d: %v", p, n, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("%+v n=%d: round trip mismatch (%d vs %d bytes)", p, n, len(got), len(want))
			}
		}
	}
}

func TestEncodeIsDeterministic(t *testing.T) {
	c := mustCodec(t, Params{2, 1, 4, 2})
	want := payload(12345, 7)
	a, _, err := c.Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := c.Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			t.Fatalf("shard %d differs between encodes", i)
		}
	}
}

// TestLossTolerance is the core safety property: any combination of losses up
// to (LocalK per group) and (GeoK groups) must still reconstruct.
func TestLossTolerance(t *testing.T) {
	for _, p := range testParams() {
		c := mustCodec(t, p)
		const n = 5000
		want := payload(n, 42)
		shards, geom, err := c.Encode(want)
		if err != nil {
			t.Fatal(err)
		}
		groupSize := p.ShardsPerGroup()
		totalGroups := p.GeoN + p.GeoK

		// Drop GeoK whole groups (the last ones, which are parity groups).
		lossy := make([][]byte, len(shards))
		copy(lossy, shards)
		keepGroups := p.GeoN
		if keepGroups > totalGroups {
			keepGroups = totalGroups
		}
		for g := keepGroups; g < totalGroups; g++ {
			for i := 0; i < groupSize; i++ {
				lossy[g*groupSize+i] = nil
			}
		}
		// Additionally drop LocalK shards from each surviving group, rotating
		// which indices we drop so parity-only losses are not assumed.
		for g := 0; g < keepGroups; g++ {
			for i := 0; i < p.LocalK; i++ {
				idx := (g + i) % groupSize
				lossy[g*groupSize+idx] = nil
			}
		}

		got, err := c.Decode(lossy, geom)
		if err != nil {
			t.Fatalf("%+v: decode after losses: %v", p, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%+v: payload mismatch after losses", p)
		}
	}
}

func TestInsufficientShardsFail(t *testing.T) {
	p := Params{2, 1, 4, 2}
	c := mustCodec(t, p)
	want := payload(3000, 1)
	shards, geom, err := c.Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	groupSize := p.ShardsPerGroup()

	// Destroy two whole groups: only one group remains, but GeoN is 2.
	broken := make([][]byte, len(shards))
	copy(broken, shards)
	for g := 1; g < 3; g++ {
		for i := 0; i < groupSize; i++ {
			broken[g*groupSize+i] = nil
		}
	}
	if _, err := c.Decode(broken, geom); err == nil {
		t.Fatal("expected failure with too few groups")
	}

	// Destroy one group and all but LocalN-1 shards of another.
	broken = make([][]byte, len(shards))
	copy(broken, shards)
	for i := 2; i < groupSize; i++ { // leave 2 of 6 in group 0
		broken[i] = nil
	}
	for i := 0; i < groupSize; i++ {
		broken[groupSize+i] = nil
	}
	if _, err := c.Decode(broken, geom); err == nil {
		t.Fatal("expected failure with too few shards in a group")
	}
}

func TestCanDecode(t *testing.T) {
	p := Params{2, 1, 4, 2}
	c := mustCodec(t, p)
	shards, geom, err := c.Encode(payload(1000, 3))
	if err != nil {
		t.Fatal(err)
	}
	if groups, ok := c.CanDecode(shards, geom); !ok || groups != 3 {
		t.Fatalf("healthy: groups=%d ok=%v", groups, ok)
	}
	// Lose one entire group: 2 of 3 remain, still decodable.
	groupSize := p.ShardsPerGroup()
	for i := 2 * groupSize; i < 3*groupSize; i++ {
		shards[i] = nil
	}
	if groups, ok := c.CanDecode(shards, geom); !ok || groups != 2 {
		t.Fatalf("degraded: groups=%d ok=%v", groups, ok)
	}
}

func TestEmptyPayload(t *testing.T) {
	c := mustCodec(t, Params{2, 1, 4, 2})
	shards, geom, err := c.Encode(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(shards) != 0 || geom.CiphertextLen != 0 {
		t.Fatalf("empty payload should produce no shards, got %d", len(shards))
	}
	got, err := c.Decode(nil, geom)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty decode: %v %v", got, err)
	}
}

func BenchmarkEncode16MiB(b *testing.B) {
	c, err := New(Params{2, 1, 16, 4})
	if err != nil {
		b.Fatal(err)
	}
	data := make([]byte, 16<<20)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := c.Encode(data); err != nil {
			b.Fatal(err)
		}
	}
}
