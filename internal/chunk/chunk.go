// Package chunk splits object payloads into the fixed-size chunks that are the
// minimum unit of redundancy (docs/03-data-plane.md §1).
//
// Chunk sizes are per-Redundancy-Class. A chunk is the unit handed to the
// encryptor and then to the erasure code, so exactly one chunk is in memory per
// in-flight pipeline slot; the chunker therefore reuses a single buffer and
// never allocates per chunk.
package chunk

import (
	"errors"
	"fmt"
	"io"
)

const (
	// MinSize keeps a chunk large enough that per-shard framing overhead is
	// amortised; 4 MiB with a 16+4 local code yields 256 KiB shards.
	MinSize = 4 << 20
	// DefaultSize is the default chunk size (docs/02 §1.2).
	DefaultSize = 16 << 20
	// MaxSize bounds gateway memory per pipeline slot.
	MaxSize = 64 << 20
)

var (
	ErrBadChunkSize = errors.New("chunk: chunk size out of range")
	ErrShortRead    = errors.New("chunk: reader returned short write")
)

// ValidateSize checks a configured chunk size.
func ValidateSize(n int) error {
	if n < MinSize || n > MaxSize || n%(1<<20) != 0 {
		return fmt.Errorf("%w: %d (want 1 MiB-aligned, %d..%d)", ErrBadChunkSize, n, MinSize, MaxSize)
	}
	return nil
}

// Count returns the number of chunks an object of size bytes occupies.
func Count(size int64, chunkSize int) int64 {
	if size <= 0 {
		return 0
	}
	return (size + int64(chunkSize) - 1) / int64(chunkSize)
}

// Iterator streams fixed-size chunks from a reader with a single reusable
// buffer. The slice returned by Next is only valid until the following Next
// call; callers that need to retain it must copy.
type Iterator struct {
	r     io.Reader
	size  int
	buf   []byte
	index int
	done  bool
	err   error
}

// NewIterator returns an iterator over r.
func NewIterator(r io.Reader, chunkSize int) (*Iterator, error) {
	if err := ValidateSize(chunkSize); err != nil {
		return nil, err
	}
	return &Iterator{r: r, size: chunkSize, buf: make([]byte, chunkSize)}, nil
}

// Next returns the next chunk. It returns (nil, io.EOF) exactly once at the end.
//
// A short final chunk is returned as-is (not padded): the erasure code pads
// internally with at most GeoN*LocalN-1 bytes, so there is no reason to inflate
// the last chunk here.
func (it *Iterator) Next() ([]byte, error) {
	if it.done {
		return nil, io.EOF
	}
	if it.err != nil {
		return nil, it.err
	}

	n, err := io.ReadFull(it.r, it.buf)
	switch {
	case err == nil:
		it.index++
		return it.buf[:n], nil
	case errors.Is(err, io.ErrUnexpectedEOF):
		// Final, short chunk.
		it.done = true
		it.index++
		return it.buf[:n], nil
	case errors.Is(err, io.EOF):
		it.done = true
		return nil, io.EOF
	default:
		it.err = fmt.Errorf("chunk: read: %w", err)
		return nil, it.err
	}
}

// Index reports the index of the chunk most recently returned.
func (it *Iterator) Index() int { return it.index - 1 }

// ChunkRange describes the part of a chunk that a byte range touches.
type ChunkRange struct {
	Index  int   // chunk index
	Offset int64 // offset within the chunk
	Length int64 // bytes needed from this chunk
}

// MapRange translates an inclusive byte range [start, end] of an object into
// the chunks and intra-chunk offsets a reader must fetch. Returned ranges are
// in ascending chunk order.
func MapRange(objectSize, chunkSize, start, end int64) ([]ChunkRange, error) {
	if chunkSize <= 0 {
		return nil, ErrBadChunkSize
	}
	if start < 0 || end < start {
		return nil, fmt.Errorf("chunk: invalid range [%d,%d]", start, end)
	}
	if objectSize > 0 && end >= objectSize {
		end = objectSize - 1
	}
	if objectSize == 0 || end < start {
		return nil, nil
	}

	var out []ChunkRange
	for idx := int(start / chunkSize); int64(idx)*chunkSize <= end; idx++ {
		chunkStart := int64(idx) * chunkSize
		chunkEnd := chunkStart + chunkSize - 1
		lo := max64(start, chunkStart)
		hi := min64(end, chunkEnd)
		if lo > hi {
			continue
		}
		out = append(out, ChunkRange{
			Index:  idx,
			Offset: lo - chunkStart,
			Length: hi - lo + 1,
		})
	}
	return out, nil
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
