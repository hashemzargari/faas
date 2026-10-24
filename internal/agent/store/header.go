package store

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/fass-storage/fass/internal/agent/shard"
	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/ec"
)

// On-disk shard header, docs/03-data-plane.md §2.3.
//
// Layout (all integers little-endian), fixed part 128 bytes:
//
//	 0..8   magic "FASSSHD1"
//	 8      version (1)
//	 9      flags (bit0: set_id16 holds a canonical UUID; bit1: text extension present)
//	10..12  geo_n     u16
//	12..14  geo_k     u16
//	14..16  local_n   u16
//	16..18  local_k   u16
//	18..22  chunk_index u32
//	22..26  geo_group u32
//	26..30  local_index u32
//	30..46  shard_set_id (16 bytes; raw UUID or SHA-256 prefix, see flags)
//	46..48  set_id text length u16
//	48..56  payload_len i64
//	56..88  checksum SHA-256(payload) [32]
//	88..96  created_at unix microseconds i64
//	96..128 reserved (zero)
//
// Then the exact textual set id (set_id text length bytes), then the payload.
//
// The fixed 16-byte field is what the specification names; the textual
// extension makes the header genuinely self-describing (docs/03 §2.3 design
// consequence) and lets crash recovery rebuild the index from the shard files
// alone, without guessing whether a set id was a UUID or arbitrary text.
const (
	shardMagic      = "FASSSHD1"
	shardVersion    = 1
	headerFixedLen  = 128
	maxSetIDTextLen = 1024

	flagSetID16UUID = 1 << 0
	flagSetIDText   = 1 << 1

	createdAtOffset = 88
)

var (
	// ErrBadHeader is returned for a malformed or unsupported shard header.
	ErrBadHeader = errors.New("store: bad shard header")
)

// Header is the parsed on-disk shard header.
type Header struct {
	Version    uint8
	Flags      uint8
	Params     ec.Params
	ChunkIndex int
	GeoGroup   int
	LocalIndex int
	SetID      contract.ShardSetID
	SetID16    [16]byte
	PayloadLen int64
	Checksum   [32]byte
	CreatedAt  time.Time
}

// HeaderLen is the encoded header length for this header (fixed part plus the
// set-id text extension).
func (h Header) HeaderLen() int { return headerFixedLen + len(h.SetID) }

// MarshalBinary encodes the header, including the set-id text extension.
func (h Header) MarshalBinary() ([]byte, error) {
	if h.SetID == "" {
		return nil, fmt.Errorf("%w: empty shard_set_id", ErrBadHeader)
	}
	if len(h.SetID) > maxSetIDTextLen {
		return nil, fmt.Errorf("%w: shard_set_id longer than %d bytes", ErrBadHeader, maxSetIDTextLen)
	}
	if h.PayloadLen < 0 {
		return nil, fmt.Errorf("%w: negative payload length", ErrBadHeader)
	}
	if err := h.validate(); err != nil {
		return nil, err
	}
	geoN, geoK, localN, localK, err := paramsToU16(h.Params)
	if err != nil {
		return nil, err
	}

	flags := uint8(flagSetIDText)
	setID16 := h.SetID16
	if raw, canonical := shard.SetIDBytes(string(h.SetID)); canonical {
		flags |= flagSetID16UUID
		setID16 = raw
	}

	buf := make([]byte, headerFixedLen+len(h.SetID))
	copy(buf[0:8], shardMagic)
	buf[8] = shardVersion
	buf[9] = flags
	binary.LittleEndian.PutUint16(buf[10:12], geoN)
	binary.LittleEndian.PutUint16(buf[12:14], geoK)
	binary.LittleEndian.PutUint16(buf[14:16], localN)
	binary.LittleEndian.PutUint16(buf[16:18], localK)
	binary.LittleEndian.PutUint32(buf[18:22], uint32(h.ChunkIndex))
	binary.LittleEndian.PutUint32(buf[22:26], uint32(h.GeoGroup))
	binary.LittleEndian.PutUint32(buf[26:30], uint32(h.LocalIndex))
	copy(buf[30:46], setID16[:])
	binary.LittleEndian.PutUint16(buf[46:48], uint16(len(h.SetID)))
	binary.LittleEndian.PutUint64(buf[48:56], uint64(h.PayloadLen))
	copy(buf[56:88], h.Checksum[:])
	binary.LittleEndian.PutUint64(buf[88:96], uint64(h.CreatedAt.UnixMicro()))
	copy(buf[headerFixedLen:], h.SetID)
	return buf, nil
}

// ParseHeader parses a header from buf. totalLen is the full header length
// (fixed part + extension) and therefore the payload offset within the file.
func ParseHeader(buf []byte) (h Header, totalLen int, err error) {
	if len(buf) < headerFixedLen {
		return Header{}, 0, fmt.Errorf("%w: short read (%d bytes)", ErrBadHeader, len(buf))
	}
	if string(buf[0:8]) != shardMagic {
		return Header{}, 0, fmt.Errorf("%w: bad magic %q", ErrBadHeader, string(buf[0:8]))
	}
	h.Version = buf[8]
	if h.Version != shardVersion {
		return Header{}, 0, fmt.Errorf("%w: unsupported version %d", ErrBadHeader, h.Version)
	}
	h.Flags = buf[9]
	geoN := binary.LittleEndian.Uint16(buf[10:12])
	geoK := binary.LittleEndian.Uint16(buf[12:14])
	localN := binary.LittleEndian.Uint16(buf[14:16])
	localK := binary.LittleEndian.Uint16(buf[16:18])
	h.ChunkIndex = int(int32(binary.LittleEndian.Uint32(buf[18:22])))
	h.GeoGroup = int(int32(binary.LittleEndian.Uint32(buf[22:26])))
	h.LocalIndex = int(int32(binary.LittleEndian.Uint32(buf[26:30])))
	copy(h.SetID16[:], buf[30:46])
	textLen := int(binary.LittleEndian.Uint16(buf[46:48]))
	payloadLen := binary.LittleEndian.Uint64(buf[48:56])
	copy(h.Checksum[:], buf[56:88])
	createdMicro := int64(binary.LittleEndian.Uint64(buf[88:96]))

	if textLen > maxSetIDTextLen {
		return Header{}, 0, fmt.Errorf("%w: set id text length %d", ErrBadHeader, textLen)
	}
	if h.Flags&flagSetIDText == 0 {
		return Header{}, 0, fmt.Errorf("%w: missing set id text extension", ErrBadHeader)
	}
	if payloadLen > uint64(1<<62) {
		return Header{}, 0, fmt.Errorf("%w: implausible payload length %d", ErrBadHeader, payloadLen)
	}
	total := headerFixedLen + textLen
	if len(buf) < total {
		return Header{}, 0, fmt.Errorf("%w: truncated set id extension", ErrBadHeader)
	}
	h.SetID = contract.ShardSetID(string(buf[headerFixedLen:total]))
	h.Params = ec.Params{GeoN: int(geoN), GeoK: int(geoK), LocalN: int(localN), LocalK: int(localK)}
	h.PayloadLen = int64(payloadLen)
	h.CreatedAt = time.UnixMicro(createdMicro).UTC()
	if err := h.validate(); err != nil {
		return Header{}, 0, err
	}
	return h, total, nil
}

func (h Header) validate() error {
	if h.SetID == "" {
		return fmt.Errorf("%w: empty shard_set_id", ErrBadHeader)
	}
	if err := h.Params.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrBadHeader, err)
	}
	if h.GeoGroup < 0 || h.GeoGroup >= h.Params.GeoN+h.Params.GeoK {
		return fmt.Errorf("%w: geo_group %d out of range", ErrBadHeader, h.GeoGroup)
	}
	if h.LocalIndex < 0 || h.LocalIndex >= h.Params.ShardsPerGroup() {
		return fmt.Errorf("%w: local_index %d out of range", ErrBadHeader, h.LocalIndex)
	}
	return nil
}

// paramsToU16 rejects parameter values that cannot be stored in the header.
// ec.Params.Validate keeps all documented values far below 65535, so this is a
// belt-and-braces guard rather than a documented constraint.
func paramsToU16(p ec.Params) (geoN, geoK, localN, localK uint16, err error) {
	for _, v := range []int{p.GeoN, p.GeoK, p.LocalN, p.LocalK} {
		if v < 0 || v > 0xffff {
			return 0, 0, 0, 0, fmt.Errorf("%w: parameter %d out of u16 range", ErrBadHeader, v)
		}
	}
	return uint16(p.GeoN), uint16(p.GeoK), uint16(p.LocalN), uint16(p.LocalK), nil
}

// readHeaderAt reads and parses a header from the start of r.
func readHeaderAt(r io.ReaderAt) (Header, int, error) {
	buf := make([]byte, headerFixedLen)
	if err := readFullAt(r, buf, 0); err != nil {
		return Header{}, 0, fmt.Errorf("%w: %v", ErrBadHeader, err)
	}
	textLen := int(binary.LittleEndian.Uint16(buf[46:48]))
	if textLen > maxSetIDTextLen {
		return Header{}, 0, fmt.Errorf("%w: set id text length %d", ErrBadHeader, textLen)
	}
	full := make([]byte, headerFixedLen+textLen)
	copy(full, buf)
	if textLen > 0 {
		if err := readFullAt(r, full[headerFixedLen:], int64(headerFixedLen)); err != nil {
			return Header{}, 0, fmt.Errorf("%w: %v", ErrBadHeader, err)
		}
	}
	return ParseHeader(full)
}

// readFullAt fills buf from off, tolerating the (n == len(buf), io.EOF) case
// that io.ReaderAt implementations are allowed to return.
func readFullAt(r io.ReaderAt, buf []byte, off int64) error {
	n, err := r.ReadAt(buf, off)
	if n == len(buf) {
		return nil
	}
	if err == nil || err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return err
}
