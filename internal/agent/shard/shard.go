// Package shard contains the agent-local identity and hashing helpers for
// immutable data-plane shards.
//
// Wire contract (Lead decision, supersedes the BLAKE2b wording in
// docs/03-data-plane.md §2.3): the 64-bit shard checksum that travels in the
// X-Fass-Checksum header and in contract.ChunkRef.Checksums is
//
//	checksum = BigEndian( SHA-256(shard payload bytes)[0:8] )
//
// The on-disk shard id is derived with the same stdlib hash:
//
//	shard_id = base32( SHA-256( shard_set_id ‖ BE32(geo_group) ‖ BE32(local_index) )[:16] )
//
// Shard ids are an agent-local on-disk naming detail — the wire always
// addresses shards by (shard_set_id, geo_group, local_index) — so using
// SHA-256 instead of BLAKE2b here has no cross-service compatibility impact.
// Stdlib only: no new module dependency is introduced.
package shard

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/ec"
)

// DigestSize is the size in bytes of the hash digest used across the agent.
const DigestSize = 32

// IDLen is the number of digest bytes that make up a shard id (128 bits).
const IDLen = 16

// ErrBadParamsHeader is returned when X-Fass-Params cannot be parsed.
var ErrBadParamsHeader = errors.New("shard: malformed params header")

// Sum256 returns the SHA-256 digest of data.
func Sum256(data []byte) [32]byte { return sha256.Sum256(data) }

// Sum64 returns the FASS shard checksum of data: the big-endian uint64 formed
// from the first eight bytes of SHA-256(data).
func Sum64(data []byte) uint64 {
	sum := sha256.Sum256(data)
	return binary.BigEndian.Uint64(sum[:8])
}

// Hasher is an incremental SHA-256 hasher that also exposes the FASS 64-bit
// shard checksum.
type Hasher struct{ h hash.Hash }

// NewHasher returns a fresh hasher.
func NewHasher() *Hasher { return &Hasher{h: sha256.New()} }

// Write implements io.Writer.
func (h *Hasher) Write(p []byte) (int, error) { return h.h.Write(p) }

// Reset discards all accumulated state.
func (h *Hasher) Reset() { h.h.Reset() }

// Size reports the digest size.
func (h *Hasher) Size() int { return DigestSize }

// BlockSize reports the underlying block size.
func (h *Hasher) BlockSize() int { return sha256.BlockSize }

// Sum256 returns the full SHA-256 digest of everything written so far.
func (h *Hasher) Sum256() [32]byte {
	var out [32]byte
	copy(out[:], h.h.Sum(nil))
	return out
}

// Sum64 returns the FASS shard checksum of everything written so far.
func (h *Hasher) Sum64() uint64 {
	sum := h.Sum256()
	return binary.BigEndian.Uint64(sum[:8])
}

var _ hash.Hash = (*Hasher)(nil)

// ChecksumReader wraps r so callers can accumulate the payload checksum while
// streaming. Reads pass through unchanged; the caller decides what to do with
// Sum64/Sum256 at EOF.
type ChecksumReader struct {
	R  interface{ Read([]byte) (int, error) }
	hs *Hasher
}

// NewChecksumReader wraps r with a fresh checksum accumulator.
func NewChecksumReader(r interface{ Read([]byte) (int, error) }) *ChecksumReader {
	return &ChecksumReader{R: r, hs: NewHasher()}
}

func (c *ChecksumReader) Read(p []byte) (int, error) {
	n, err := c.R.Read(p)
	if n > 0 {
		_, _ = c.hs.Write(p[:n])
	}
	return n, err
}

// Sum64 returns the checksum of the bytes read so far.
func (c *ChecksumReader) Sum64() uint64 { return c.hs.Sum64() }

// Sum256 returns the digest of the bytes read so far.
func (c *ChecksumReader) Sum256() [32]byte { return c.hs.Sum256() }

// ID is the content-derived on-disk identifier of one shard.
func ID(setID contract.ShardSetID, geoGroup, localIndex int) string {
	buf := make([]byte, 0, len(setID)+8)
	buf = append(buf, setID...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(geoGroup))
	buf = binary.BigEndian.AppendUint32(buf, uint32(localIndex))
	sum := sha256.Sum256(buf)
	return strings.ToLower(base32NoPad.EncodeToString(sum[:IDLen]))
}

// SetIDBytes returns the 16-byte fixed representation of a shard set id stored
// in the shard header: the raw UUID bytes when the id is a canonical UUID,
// otherwise the first 16 bytes of its SHA-256 digest. The exact textual id is
// carried separately in the header extension so recovery never has to invert
// this.
func SetIDBytes(s string) (raw [16]byte, canonical bool) {
	hexStr := strings.ReplaceAll(s, "-", "")
	if len(hexStr) != 32 {
		sum := sha256.Sum256([]byte(s))
		copy(raw[:], sum[:16])
		return raw, false
	}
	for i := 0; i < 16; i++ {
		b, err := strconv.ParseUint(hexStr[i*2:i*2+2], 16, 8)
		if err != nil {
			sum := sha256.Sum256([]byte(s))
			copy(raw[:], sum[:16])
			return raw, false
		}
		raw[i] = byte(b)
	}
	return raw, true
}

// ParamsHeader renders ec.Params in the X-Fass-Params wire form "n,k,n,k"
// (docs/07-wire-api.md §2).
func ParamsHeader(p ec.Params) string {
	return fmt.Sprintf("%d,%d,%d,%d", p.GeoN, p.GeoK, p.LocalN, p.LocalK)
}

// ParseParamsHeader parses the X-Fass-Params wire form.
func ParseParamsHeader(s string) (ec.Params, error) {
	parts := strings.Split(strings.TrimSpace(s), ",")
	if len(parts) != 4 {
		return ec.Params{}, fmt.Errorf("%w: want 4 comma-separated integers, got %q", ErrBadParamsHeader, s)
	}
	var vals [4]int
	for i, part := range parts {
		v, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			return ec.Params{}, fmt.Errorf("%w: %q", ErrBadParamsHeader, s)
		}
		vals[i] = v
	}
	p := ec.Params{GeoN: vals[0], GeoK: vals[1], LocalN: vals[2], LocalK: vals[3]}
	if err := p.Validate(); err != nil {
		return ec.Params{}, fmt.Errorf("%w: %v", ErrBadParamsHeader, err)
	}
	return p, nil
}

// base32NoPad is lowercase base32 without padding: 16 bytes encode to 26
// characters, which is a safe filename on every filesystem.
var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)
