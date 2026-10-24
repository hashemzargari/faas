// Package ec implements FASS's two-tier Reed–Solomon erasure code.
//
// A payload is first encoded with the *geo* code across Nexuses, then each
// geo piece is encoded with the *local* code across the disks of one Nexus:
//
//	payload
//	  └─ geo RS(GeoN, GeoK)      → GeoN+GeoK pieces, one per Nexus
//	       └─ local RS(LocalN, LocalK) → LocalN+LocalK shards per Nexus
//
// The degenerate case GeoK == 0 and GeoN == 1 is a flat single-tier code, which
// is how Cubbit DS3-Cloud's flat 20+40 scheme is expressed.
//
// The code is deliberately linear over GF(2^8) and applied to *ciphertext*: a
// decoder therefore never needs a key, which is what allows repair to run on
// untrusted, key-less nodes.
package ec

import (
	"errors"
	"fmt"
	"sync"

	"github.com/klauspost/reedsolomon"
)

// Hard limits keep a single chunk's fan-out within GF(2^8) and within sane
// operational bounds. See docs/03-data-plane.md §2.2.
const (
	MaxGeoN     = 16
	MaxGeoK     = 8
	MaxLocalN   = 128
	MaxLocalK   = 64
	MaxRatioNum = 4 // refuse configurations above 4x overhead
)

var (
	ErrBadParams    = errors.New("ec: invalid parameters")
	ErrBadGeometry  = errors.New("ec: geometry mismatch")
	ErrTooFewShards = errors.New("ec: not enough shards to reconstruct")
	ErrShardSize    = errors.New("ec: shard size mismatch")
)

// Params describes one Redundancy Class's coding parameters.
type Params struct {
	GeoN   int `json:"geo_n"`
	GeoK   int `json:"geo_k"`
	LocalN int `json:"local_n"`
	LocalK int `json:"local_k"`
}

// Validate reports whether the parameters are self-consistent and within limits.
func (p Params) Validate() error {
	switch {
	case p.GeoN < 1:
		return fmt.Errorf("%w: geo_n must be >= 1", ErrBadParams)
	case p.GeoK < 0:
		return fmt.Errorf("%w: geo_k must be >= 0", ErrBadParams)
	case p.LocalN < 1:
		return fmt.Errorf("%w: local_n must be >= 1", ErrBadParams)
	case p.LocalK < 0:
		return fmt.Errorf("%w: local_k must be >= 0", ErrBadParams)
	case p.GeoN > MaxGeoN || p.GeoK > MaxGeoK:
		return fmt.Errorf("%w: geo tier out of range (n<=%d, k<=%d)", ErrBadParams, MaxGeoN, MaxGeoK)
	case p.LocalN > MaxLocalN || p.LocalK > MaxLocalK:
		return fmt.Errorf("%w: local tier out of range (n<=%d, k<=%d)", ErrBadParams, MaxLocalN, MaxLocalK)
	case p.GeoN+p.GeoK > 254 || p.LocalN+p.LocalK > 254:
		return fmt.Errorf("%w: total shards per tier must be <= 254", ErrBadParams)
	case p.Ratio() > MaxRatioNum:
		return fmt.Errorf("%w: ratio %.4f exceeds %d", ErrBadParams, p.Ratio(), MaxRatioNum)
	}
	return nil
}

// Ratio is the storage overhead: raw bytes stored per payload byte.
//
//	((GeoN+GeoK)/GeoN) * ((LocalN+LocalK)/LocalN)
func (p Params) Ratio() float64 {
	return (float64(p.GeoN+p.GeoK) / float64(p.GeoN)) *
		(float64(p.LocalN+p.LocalK) / float64(p.LocalN))
}

// ShardsPerGroup is the number of shards stored in one Nexus for one chunk.
func (p Params) ShardsPerGroup() int { return p.LocalN + p.LocalK }

// TotalShards is the number of shards stored for one chunk across all Nexuses.
func (p Params) TotalShards() int { return (p.GeoN + p.GeoK) * p.ShardsPerGroup() }

// Geometry is the concrete layout of a coded chunk.
type Geometry struct {
	Params
	// CiphertextLen is the exact length of the encoded payload, excluding padding.
	CiphertextLen int
	// PieceLen is the padded length of one geo piece.
	PieceLen int
	// ShardSize is the length of every local shard.
	ShardSize int
	// TotalShards is the number of shards produced/required.
	TotalShards int
}

// Overhead returns raw bytes stored / payload bytes, using padded sizes.
func (g Geometry) Overhead() float64 {
	if g.CiphertextLen == 0 {
		return 0
	}
	return float64(g.ShardSize*g.TotalShards) / float64(g.CiphertextLen)
}

// Codec is a reusable encoder/decoder for one Params. It is safe for concurrent
// use: underlying Reed–Solomon encoders are stateless, and geometry memoisation
// is guarded.
type Codec struct {
	p      Params
	outer  reedsolomon.Encoder
	inner  reedsolomon.Encoder
	hasOut bool
	hasIn  bool

	mu    sync.RWMutex
	geoms map[int]Geometry
}

// New builds a Codec, validating parameters first.
func New(p Params) (*Codec, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	c := &Codec{p: p, geoms: make(map[int]Geometry)}

	if p.GeoK > 0 {
		enc, err := reedsolomon.New(p.GeoN, p.GeoK)
		if err != nil {
			return nil, fmt.Errorf("ec: outer codec: %w", err)
		}
		c.outer, c.hasOut = enc, true
	}
	if p.LocalK > 0 {
		enc, err := reedsolomon.New(p.LocalN, p.LocalK)
		if err != nil {
			return nil, fmt.Errorf("ec: inner codec: %w", err)
		}
		c.inner, c.hasIn = enc, true
	}
	return c, nil
}

// Params returns the codec's parameters.
func (c *Codec) Params() Params { return c.p }

// Geometry computes the layout for a payload of ciphertextLen bytes.
//
// The payload is padded twice: up to a multiple of GeoN*LocalN bytes so that
// every geo piece splits evenly into LocalN shards. Padding is bounded by
// GeoN*LocalN-1 bytes — negligible even for tiny objects.
func (c *Codec) Geometry(ciphertextLen int) Geometry {
	c.mu.RLock()
	g, ok := c.geoms[ciphertextLen]
	c.mu.RUnlock()
	if ok {
		return g
	}

	unit := c.p.GeoN * c.p.LocalN
	shardSize := 0
	if ciphertextLen > 0 {
		shardSize = (ciphertextLen + unit - 1) / unit
	}
	g = Geometry{
		Params:        c.p,
		CiphertextLen: ciphertextLen,
		PieceLen:      shardSize * c.p.LocalN,
		ShardSize:     shardSize,
		TotalShards:   c.p.TotalShards(),
	}
	c.mu.Lock()
	c.geoms[ciphertextLen] = g
	c.mu.Unlock()
	return g
}

// Encode splits ciphertext into shards laid out as
// index = group*ShardsPerGroup + localIndex.
//
// The caller owns the returned shards; they do not alias ciphertext.
func (c *Codec) Encode(ciphertext []byte) ([][]byte, Geometry, error) {
	geom := c.Geometry(len(ciphertext))
	if len(ciphertext) == 0 {
		return nil, geom, nil
	}

	// 1. Lay the payload into GeoN data pieces, zero-padded to PieceLen.
	pieces := make([][]byte, c.p.GeoN+c.p.GeoK)
	for i := range pieces {
		pieces[i] = make([]byte, geom.PieceLen)
	}
	for i := 0; i < c.p.GeoN; i++ {
		start := i * geom.PieceLen
		end := start + geom.PieceLen
		if start < len(ciphertext) {
			if end > len(ciphertext) {
				end = len(ciphertext)
			}
			copy(pieces[i], ciphertext[start:end])
		}
	}

	// 2. Outer (geo) encode.
	if c.hasOut {
		if err := c.outer.Encode(pieces); err != nil {
			return nil, geom, fmt.Errorf("ec: outer encode: %w", err)
		}
	}

	// 3. Inner (local) encode each piece.
	out := make([][]byte, 0, geom.TotalShards)
	for g := 0; g < c.p.GeoN+c.p.GeoK; g++ {
		shards := split(pieces[g], c.p.LocalN, c.p.LocalK, geom.ShardSize)
		if c.hasIn {
			if err := c.inner.Encode(shards); err != nil {
				return nil, geom, fmt.Errorf("ec: inner encode: %w", err)
			}
		}
		out = append(out, shards...)
	}
	return out, geom, nil
}

// Decode reconstructs the payload from a sparse shard slice of length
// geom.TotalShards. Missing shards are nil.
//
// Reconstruction needs at least GeoN groups that each hold at least LocalN
// shards. Extra survivors are ignored.
func (c *Codec) Decode(shards [][]byte, geom Geometry) ([]byte, error) {
	if geom.CiphertextLen == 0 {
		return []byte{}, nil
	}
	if geom.TotalShards != c.p.TotalShards() {
		return nil, fmt.Errorf("%w: expected %d shards, geometry says %d",
			ErrBadGeometry, c.p.TotalShards(), geom.TotalShards)
	}
	if len(shards) != geom.TotalShards {
		return nil, fmt.Errorf("%w: got %d shard slots, want %d",
			ErrBadGeometry, len(shards), geom.TotalShards)
	}
	for _, s := range shards {
		if s != nil && len(s) != geom.ShardSize {
			return nil, fmt.Errorf("%w: want %d, got %d", ErrShardSize, geom.ShardSize, len(s))
		}
	}

	// 1. Inner decode every group that has quorum, yielding a geo piece.
	pieces := make([][]byte, c.p.GeoN+c.p.GeoK)
	present := 0
	groupSize := c.p.ShardsPerGroup()
	for g := 0; g < c.p.GeoN+c.p.GeoK; g++ {
		group := make([][]byte, groupSize)
		copy(group, shards[g*groupSize:(g+1)*groupSize])

		have := 0
		for _, s := range group {
			if s != nil {
				have++
			}
		}
		if have < c.p.LocalN {
			continue
		}
		if c.hasIn && have < groupSize {
			if err := c.inner.Reconstruct(group); err != nil {
				continue // unusable group; try the others
			}
		} else if !c.hasIn && have < groupSize {
			continue
		}

		piece := make([]byte, 0, geom.PieceLen)
		for i := 0; i < c.p.LocalN; i++ {
			piece = append(piece, group[i]...)
		}
		pieces[g] = piece
		present++
	}

	// 2. Outer decode once enough Nexuses are reachable.
	if present < c.p.GeoN {
		return nil, fmt.Errorf("%w: %d/%d groups available, need %d",
			ErrTooFewShards, present, c.p.GeoN+c.p.GeoK, c.p.GeoN)
	}
	if c.hasOut && present < len(pieces) {
		if err := c.outer.Reconstruct(pieces); err != nil {
			return nil, fmt.Errorf("ec: outer reconstruct: %w", err)
		}
	}

	// 3. Concatenate data pieces and trim padding.
	out := make([]byte, 0, c.p.GeoN*geom.PieceLen)
	for i := 0; i < c.p.GeoN; i++ {
		if pieces[i] == nil {
			return nil, fmt.Errorf("%w: data piece %d missing", ErrTooFewShards, i)
		}
		out = append(out, pieces[i]...)
	}
	if len(out) < geom.CiphertextLen {
		return nil, fmt.Errorf("%w: reconstructed %d bytes, want %d",
			ErrTooFewShards, len(out), geom.CiphertextLen)
	}
	return out[:geom.CiphertextLen], nil
}

// CanDecode reports how many groups are currently reconstructible and whether
// that is enough. Useful for repair scheduling and for read-path hedging.
func (c *Codec) CanDecode(shards [][]byte, geom Geometry) (groups int, ok bool) {
	if geom.CiphertextLen == 0 {
		return 0, true
	}
	groupSize := c.p.ShardsPerGroup()
	for g := 0; g < c.p.GeoN+c.p.GeoK; g++ {
		have := 0
		for i := g * groupSize; i < (g+1)*groupSize && i < len(shards); i++ {
			if shards[i] != nil {
				have++
			}
		}
		if have >= c.p.LocalN {
			groups++
		}
	}
	return groups, groups >= c.p.GeoN
}

// split cuts piece into n data shards and reserves k parity slots, so the
// result can be passed straight to reedsolomon.Encoder.Encode.
func split(piece []byte, n, k, shardSize int) [][]byte {
	out := make([][]byte, n+k)
	for i := n; i < n+k; i++ {
		out[i] = make([]byte, shardSize)
	}
	for i := 0; i < n; i++ {
		out[i] = make([]byte, shardSize)
		start := i * shardSize
		if start < len(piece) {
			end := start + shardSize
			if end > len(piece) {
				end = len(piece)
			}
			copy(out[i], piece[start:end])
		}
	}
	return out
}
