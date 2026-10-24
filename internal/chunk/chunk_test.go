package chunk

import (
	"bytes"
	"errors"
	"io"
	"math/rand"
	"testing"
)

func TestValidateSize(t *testing.T) {
	for _, ok := range []int{MinSize, 8 << 20, DefaultSize, MaxSize} {
		if err := ValidateSize(ok); err != nil {
			t.Errorf("%d should be valid: %v", ok, err)
		}
	}
	for _, bad := range []int{0, -1, MinSize - 1, MinSize + 512, MaxSize + 1} {
		if err := ValidateSize(bad); err == nil {
			t.Errorf("%d should be invalid", bad)
		}
	}
}

func TestCount(t *testing.T) {
	const cs = 1 << 20
	cases := []struct{ size, want int64 }{
		{0, 0}, {1, 1}, {cs - 1, 1}, {cs, 1}, {cs + 1, 2}, {10 * cs, 10},
	}
	for _, c := range cases {
		if got := Count(c.size, cs); got != c.want {
			t.Errorf("Count(%d)=%d want %d", c.size, got, c.want)
		}
	}
}

func TestIterator(t *testing.T) {
	// Use a small chunk size to keep the test fast; ValidateSize is bypassed by
	// constructing the iterator directly through the exported constructor with a
	// valid size, so use 4 MiB and modest payloads.
	const cs = MinSize
	sizes := []int{0, 1, 100, cs - 1, cs, cs + 1, 2*cs + 7}
	for _, n := range sizes {
		payload := make([]byte, n)
		rand.New(rand.NewSource(int64(n))).Read(payload)

		it, err := NewIterator(bytes.NewReader(payload), cs)
		if err != nil {
			t.Fatal(err)
		}
		var got []byte
		chunks := 0
		for {
			c, err := it.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("n=%d: %v", n, err)
			}
			got = append(got, c...)
			chunks++
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("n=%d: reassembled payload differs", n)
		}
		if want := int(Count(int64(n), cs)); chunks != want {
			t.Fatalf("n=%d: %d chunks, want %d", n, chunks, want)
		}
	}
}

func TestIteratorEmptyReader(t *testing.T) {
	it, err := NewIterator(bytes.NewReader(nil), MinSize)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := it.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF, got %v", err)
	}
	// EOF is sticky.
	if _, err := it.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF again, got %v", err)
	}
}

func TestIteratorReadError(t *testing.T) {
	boom := errors.New("boom")
	it, err := NewIterator(io.MultiReader(bytes.NewReader(make([]byte, 10)), errReader{boom}), MinSize)
	if err != nil {
		t.Fatal(err)
	}
	_, err = it.Next()
	if !errors.Is(err, boom) {
		t.Fatalf("want wrapped boom, got %v", err)
	}
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func TestMapRange(t *testing.T) {
	const cs = 100
	cases := []struct {
		name             string
		size, start, end int64
		want             []ChunkRange
	}{
		{"start of first chunk", 1000, 0, 9, []ChunkRange{{0, 0, 10}}},
		{"span two chunks", 1000, 95, 105, []ChunkRange{{0, 95, 5}, {1, 0, 6}}},
		{"whole object", 250, 0, 249, []ChunkRange{{0, 0, 100}, {1, 0, 100}, {2, 0, 50}}},
		{"end clamped", 150, 100, 999, []ChunkRange{{1, 0, 50}}},
		{"single byte", 1000, 42, 42, []ChunkRange{{0, 42, 1}}},
		{"empty object", 0, 0, 0, nil},
	}
	for _, c := range cases {
		got, err := MapRange(c.size, cs, c.start, c.end)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(got) != len(c.want) {
			t.Fatalf("%s: got %+v want %+v", c.name, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("%s: range %d = %+v want %+v", c.name, i, got[i], c.want[i])
			}
		}
	}
}

func TestMapRangeRejectsBadInput(t *testing.T) {
	if _, err := MapRange(100, 10, -1, 5); err == nil {
		t.Fatal("negative start must fail")
	}
	if _, err := MapRange(100, 10, 10, 5); err == nil {
		t.Fatal("end<start must fail")
	}
	if _, err := MapRange(100, 0, 0, 5); err == nil {
		t.Fatal("zero chunk size must fail")
	}
}
