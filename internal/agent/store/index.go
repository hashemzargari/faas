package store

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/fass-storage/fass/internal/agent/shard"
	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/ec"
)

// The shard index is a small append-only log with periodic compaction. It maps
// the computed shard id to the shard's metadata so that lookups, Has,
// delete-by-set and paginated inventory need no directory walking. Pebble was
// deliberately not added as a dependency (Lead decision).
//
// File format:
//
//	file header: "FASSIDX1" (8) | version u16 | flags u16 | reserved [4]byte
//	record:      payload_len u32 | payload | crc32(payload) u32
//	payload:     op u8 ('A' add, 'D' delete) | set_id_len u16 | set_id |
//	             geo_group u32 | local_index u32 | chunk_index u32 |
//	             geo_n u16 | geo_k u16 | local_n u16 | local_k u16 |
//	             payload_len i64 | file_size i64 | checksum u64 |
//	             created_at_unix_micro i64
//
// A torn tail (crash mid-append) is detected by length/CRC and truncated at
// boot; complete records before it are kept. Shard files whose index record was
// lost are recovered by scanning shards/ at boot (see store.Open).
const (
	indexMagic    = "FASSIDX1"
	indexVersion  = 1
	indexHdrLen   = 16
	maxIndexRec   = shard.DigestSize*4 + 4096
	opAdd         = 'A'
	opDelete      = 'D'
	indexFilename = "shards.idx"
)

var errCorruptIndex = errors.New("store: corrupt index record")

// entry is the in-memory index entry for one stored shard.
type entry struct {
	ID         string
	SetID      contract.ShardSetID
	GeoGroup   int
	LocalIndex int
	ChunkIndex int
	Params     ec.Params
	PayloadLen int64
	FileSize   int64
	Checksum   uint64
	CreatedAt  time.Time
}

func (e entry) shardInfo() contract.ShardInfo {
	return contract.ShardInfo{
		ShardSetID: e.SetID,
		GeoGroup:   e.GeoGroup,
		LocalIndex: e.LocalIndex,
		Size:       e.FileSize,
		Checksum:   e.Checksum,
		CreatedAt:  e.CreatedAt,
	}
}

func (e entry) slot() int {
	return e.GeoGroup*e.Params.ShardsPerGroup() + e.LocalIndex
}

// indexFile owns the on-disk append-only index log.
type indexFile struct {
	path    string
	f       *os.File
	records int // records written since the log was opened or last compacted
}

// openIndex opens (creating if needed) the index log and replays it into a
// fresh in-memory map. If the tail is torn, the file is truncated to the last
// complete record.
func openIndex(path string) (*indexFile, map[string]entry, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, nil, fmt.Errorf("store: create index dir: %w", err)
	}

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, nil, fmt.Errorf("store: open index: %w", err)
	}

	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("store: stat index: %w", err)
	}

	if fi.Size() == 0 {
		if err := writeIndexHeader(f); err != nil {
			f.Close()
			return nil, nil, err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return nil, nil, fmt.Errorf("store: fsync index header: %w", err)
		}
	} else if fi.Size() < indexHdrLen {
		// A crash between create and header write: start over.
		if err := f.Truncate(0); err != nil {
			f.Close()
			return nil, nil, fmt.Errorf("store: truncate empty index: %w", err)
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			f.Close()
			return nil, nil, fmt.Errorf("store: seek index: %w", err)
		}
		if err := writeIndexHeader(f); err != nil {
			f.Close()
			return nil, nil, err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return nil, nil, fmt.Errorf("store: fsync index header: %w", err)
		}
	} else {
		hdr := make([]byte, indexHdrLen)
		if err := readFullAt(f, hdr, 0); err != nil {
			f.Close()
			return nil, nil, fmt.Errorf("store: read index header: %w", err)
		}
		if string(hdr[0:8]) != indexMagic {
			f.Close()
			return nil, nil, fmt.Errorf("store: bad index magic %q in %s", string(hdr[0:8]), path)
		}
		if v := binary.LittleEndian.Uint16(hdr[8:10]); v != indexVersion {
			f.Close()
			return nil, nil, fmt.Errorf("store: unsupported index version %d in %s", v, path)
		}
	}

	entries, good, recs, err := replayIndex(f)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if good < fi.Size() {
		// Drop the torn tail so the next append starts from a clean boundary.
		if err := f.Truncate(good); err != nil {
			f.Close()
			return nil, nil, fmt.Errorf("store: truncate torn index tail: %w", err)
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return nil, nil, fmt.Errorf("store: fsync trimmed index: %w", err)
		}
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("store: seek index end: %w", err)
	}

	ix := &indexFile{path: path, f: f, records: recs}
	return ix, entries, nil
}

func writeIndexHeader(f *os.File) error {
	hdr := make([]byte, indexHdrLen)
	copy(hdr[0:8], indexMagic)
	binary.LittleEndian.PutUint16(hdr[8:10], indexVersion)
	if _, err := f.Write(hdr); err != nil {
		return fmt.Errorf("store: write index header: %w", err)
	}
	return nil
}

// replayIndex applies every complete record and returns the last good offset
// and the number of records applied.
func replayIndex(f *os.File) (map[string]entry, int64, int, error) {
	entries := make(map[string]entry)
	off := int64(indexHdrLen)
	recs := 0
	var lenBuf [4]byte
	for {
		if _, err := f.ReadAt(lenBuf[:], off); err != nil {
			if errors.Is(err, io.EOF) {
				return entries, off, recs, nil
			}
			return nil, 0, 0, fmt.Errorf("store: read index record length: %w", err)
		}
		recLen := int(binary.LittleEndian.Uint32(lenBuf[:]))
		if recLen <= 0 || recLen > maxIndexRec {
			return entries, off, recs, nil // torn/corrupt tail
		}
		buf := make([]byte, recLen+4)
		if err := readFullAt(f, buf, off+4); err != nil {
			return entries, off, recs, nil // torn tail
		}
		payload := buf[:recLen]
		wantCRC := binary.LittleEndian.Uint32(buf[recLen:])
		if crc32.ChecksumIEEE(payload) != wantCRC {
			return entries, off, recs, nil // torn tail
		}
		op, e, err := decodeIndexRecord(payload)
		if err != nil {
			return entries, off, recs, nil // unusable tail
		}
		switch op {
		case opAdd:
			entries[e.ID] = e
		case opDelete:
			delete(entries, e.ID)
		default:
			return entries, off, recs, nil
		}
		off += int64(4 + recLen + 4)
		recs++
	}
}

func (ix *indexFile) appendAdd(e entry) error  { return ix.append(opAdd, e) }
func (ix *indexFile) appendDelete(e entry) error { return ix.append(opDelete, e) }

func (ix *indexFile) append(op byte, e entry) error {
	payload := encodeIndexRecord(op, e)
	if len(payload) > maxIndexRec {
		return fmt.Errorf("store: index record too large (%d bytes)", len(payload))
	}
	buf := make([]byte, 4+len(payload)+4)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(len(payload)))
	copy(buf[4:], payload)
	binary.LittleEndian.PutUint32(buf[4+len(payload):], crc32.ChecksumIEEE(payload))
	if _, err := ix.f.Write(buf); err != nil {
		return fmt.Errorf("store: append index record: %w", err)
	}
	ix.records++
	return nil
}

func (ix *indexFile) sync() error {
	if err := ix.f.Sync(); err != nil {
		return fmt.Errorf("store: fsync index: %w", err)
	}
	return nil
}

// rewrite compacts the log to one add record per live entry, atomically
// (temp file + fsync + rename + fsync(dir)).
func (ix *indexFile) rewrite(entries map[string]entry) error {
	dir := filepath.Dir(ix.path)
	tmpPath := ix.path + ".compact"
	tmp, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("store: create compacted index: %w", err)
	}
	cleanup := func() {
		tmp.Close()
		os.Remove(tmpPath)
	}
	if err := writeIndexHeader(tmp); err != nil {
		cleanup()
		return err
	}
	ids := make([]string, 0, len(entries))
	for id := range entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		payload := encodeIndexRecord(opAdd, entries[id])
		buf := make([]byte, 4+len(payload)+4)
		binary.LittleEndian.PutUint32(buf[0:4], uint32(len(payload)))
		copy(buf[4:], payload)
		binary.LittleEndian.PutUint32(buf[4+len(payload):], crc32.ChecksumIEEE(payload))
		if _, err := tmp.Write(buf); err != nil {
			cleanup()
			return fmt.Errorf("store: write compacted index: %w", err)
		}
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("store: fsync compacted index: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("store: close compacted index: %w", err)
	}
	if err := ix.f.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("store: close index before rename: %w", err)
	}
	if err := os.Rename(tmpPath, ix.path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("store: rename compacted index: %w", err)
	}
	if err := fsyncDir(dir); err != nil {
		return err
	}
	f, err := os.OpenFile(ix.path, os.O_RDWR|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("store: reopen compacted index: %w", err)
	}
	ix.f = f
	ix.records = len(ids)
	return nil
}

func (ix *indexFile) Close() error {
	if ix == nil || ix.f == nil {
		return nil
	}
	err := ix.f.Close()
	ix.f = nil
	return err
}

func encodeIndexRecord(op byte, e entry) []byte {
	buf := make([]byte, 0, 96+len(e.SetID))
	buf = append(buf, op)
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(e.SetID)))
	buf = append(buf, e.SetID...)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(e.GeoGroup))
	buf = binary.LittleEndian.AppendUint32(buf, uint32(e.LocalIndex))
	buf = binary.LittleEndian.AppendUint32(buf, uint32(e.ChunkIndex))
	buf = binary.LittleEndian.AppendUint16(buf, uint16(e.Params.GeoN))
	buf = binary.LittleEndian.AppendUint16(buf, uint16(e.Params.GeoK))
	buf = binary.LittleEndian.AppendUint16(buf, uint16(e.Params.LocalN))
	buf = binary.LittleEndian.AppendUint16(buf, uint16(e.Params.LocalK))
	buf = binary.LittleEndian.AppendUint64(buf, uint64(e.PayloadLen))
	buf = binary.LittleEndian.AppendUint64(buf, uint64(e.FileSize))
	buf = binary.LittleEndian.AppendUint64(buf, e.Checksum)
	buf = binary.LittleEndian.AppendUint64(buf, uint64(e.CreatedAt.UnixMicro()))
	return buf
}

func decodeIndexRecord(payload []byte) (byte, entry, error) {
	var e entry
	if len(payload) < 3 {
		return 0, e, errCorruptIndex
	}
	op := payload[0]
	setLen := int(binary.LittleEndian.Uint16(payload[1:3]))
	if setLen <= 0 || len(payload) < 3+setLen+52 {
		return 0, e, errCorruptIndex
	}
	e.SetID = contract.ShardSetID(payload[3 : 3+setLen])
	off := 3 + setLen
	e.GeoGroup = int(int32(binary.LittleEndian.Uint32(payload[off:])))
	e.LocalIndex = int(int32(binary.LittleEndian.Uint32(payload[off+4:])))
	e.ChunkIndex = int(int32(binary.LittleEndian.Uint32(payload[off+8:])))
	e.Params = ec.Params{
		GeoN:   int(binary.LittleEndian.Uint16(payload[off+12:])),
		GeoK:   int(binary.LittleEndian.Uint16(payload[off+14:])),
		LocalN: int(binary.LittleEndian.Uint16(payload[off+16:])),
		LocalK: int(binary.LittleEndian.Uint16(payload[off+18:])),
	}
	e.PayloadLen = int64(binary.LittleEndian.Uint64(payload[off+20:]))
	e.FileSize = int64(binary.LittleEndian.Uint64(payload[off+28:]))
	e.Checksum = binary.LittleEndian.Uint64(payload[off+36:])
	e.CreatedAt = time.UnixMicro(int64(binary.LittleEndian.Uint64(payload[off+44:]))).UTC()
	e.ID = shard.ID(e.SetID, e.GeoGroup, e.LocalIndex)
	if err := e.Params.Validate(); err != nil {
		return 0, e, errCorruptIndex
	}
	if op != opAdd && op != opDelete {
		return 0, e, errCorruptIndex
	}
	return op, e, nil
}
