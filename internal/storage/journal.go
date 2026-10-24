package storage

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
)

// On-disk formats. Both the snapshot and the journal are sequences of frames:
//
//	frame := uint32 length (LE) | uint32 crc32(1,0x1edc6f41)(payload) | payload
//
// payload := uint8 version | uint32 recordCount | record*
// record  := uint8 op (1=put, 2=delete)
//
//	uint16 spaceLen | uint32 keyLen | uint32 valLen | space | key | val
//
// A frame is atomic: either the whole commit lands or (on a torn tail after a
// crash) it is discarded during replay. All integers are little-endian; keys use
// raw byte order, which is what ordered scans rely on.
const (
	snapshotMagic = "FASSSNP1"
	journalMagic  = "FASSWAL1"

	recordVersion = 1
	opPut         = 1
	opDelete      = 2
	frameHeader   = 8
	payloadHeader = 5

	snapshotName = "snapshot.db"
	journalName  = "journal.wal"
	lockName     = "LOCK"

	compactMinBytes = 8 << 20 // 8 MiB
)

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// openJournal opens (creating if needed) the write-ahead log and replays it on
// top of the snapshot state.
func (db *DB) openJournal() error {
	path := filepath.Join(db.dir, journalName)
	_, statErr := os.Stat(path)
	if errors.Is(statErr, os.ErrNotExist) {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("storage: create journal: %w", err)
		}
		if _, err := f.WriteString(journalMagic); err != nil {
			f.Close()
			return fmt.Errorf("storage: write journal header: %w", err)
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return fmt.Errorf("storage: sync journal header: %w", err)
		}
		db.wal = f
		db.walSize = int64(len(journalMagic))
		return syncDir(db.dir)
	}
	if statErr != nil {
		return fmt.Errorf("storage: stat journal: %w", statErr)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("storage: read journal: %w", err)
	}
	if len(raw) < len(journalMagic) || string(raw[:len(journalMagic)]) != journalMagic {
		return fmt.Errorf("storage: %s: bad magic (data dir corrupt or not a fass store)", path)
	}
	consumed, err := replayFrames(raw[len(journalMagic):], db.applyRecord)
	if err != nil {
		return fmt.Errorf("storage: replay journal: %w", err)
	}
	// Truncate a torn tail so the next append starts from a valid offset.
	valid := int64(len(journalMagic) + consumed)
	if valid != int64(len(raw)) {
		if err := os.Truncate(path, valid); err != nil {
			return fmt.Errorf("storage: truncate torn journal tail: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("storage: reopen journal: %w", err)
	}
	if _, err := f.Seek(valid, io.SeekStart); err != nil {
		f.Close()
		return fmt.Errorf("storage: seek journal: %w", err)
	}
	db.wal = f
	db.walSize = valid
	return nil
}

// loadSnapshot loads the snapshot into memory. A missing snapshot is not an
// error (fresh data directory).
func (db *DB) loadSnapshot() error {
	path := filepath.Join(db.dir, snapshotName)
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("storage: read snapshot: %w", err)
	}
	if len(raw) < len(snapshotMagic) || string(raw[:len(snapshotMagic)]) != snapshotMagic {
		return fmt.Errorf("storage: %s: bad magic", path)
	}
	if _, err := replayFrames(raw[len(snapshotMagic):], db.applyRecord); err != nil {
		return fmt.Errorf("storage: replay snapshot: %w", err)
	}
	return nil
}

func (db *DB) applyRecord(op byte, space, key, val []byte) {
	switch op {
	case opPut:
		sm := db.data[string(space)]
		if sm == nil {
			sm = make(map[string][]byte)
			db.data[string(space)] = sm
		}
		sm[string(key)] = append([]byte(nil), val...)
	case opDelete:
		if sm := db.data[string(space)]; sm != nil {
			delete(sm, string(key))
		}
	}
}

// appendJournal writes all mutations of one transaction as a single fsync'd
// frame. It is the durability point of Update.
func (db *DB) appendJournal(muts []mutation) error {
	payload := encodePayload(muts)
	frame := make([]byte, frameHeader+len(payload))
	binary.LittleEndian.PutUint32(frame[0:4], uint32(len(payload)))
	binary.LittleEndian.PutUint32(frame[4:8], crc32.Checksum(payload, crcTable))
	copy(frame[frameHeader:], payload)

	if _, err := db.wal.Write(frame); err != nil {
		return fmt.Errorf("storage: append journal: %w", err)
	}
	if err := db.wal.Sync(); err != nil {
		return fmt.Errorf("storage: fsync journal: %w", err)
	}
	db.walSize += int64(len(frame))
	return nil
}

func encodePayload(muts []mutation) []byte {
	size := payloadHeader
	for _, m := range muts {
		size += 1 + 2 + 4 + 4 + len(m.space) + len(m.key)
		if !m.del {
			size += len(m.val)
		}
	}
	buf := make([]byte, 0, size)
	buf = append(buf, recordVersion)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(muts)))
	for _, m := range muts {
		if m.del {
			buf = append(buf, opDelete)
		} else {
			buf = append(buf, opPut)
		}
		buf = binary.LittleEndian.AppendUint16(buf, uint16(len(m.space)))
		buf = binary.LittleEndian.AppendUint32(buf, uint32(len(m.key)))
		if m.del {
			buf = binary.LittleEndian.AppendUint32(buf, 0)
		} else {
			buf = binary.LittleEndian.AppendUint32(buf, uint32(len(m.val)))
		}
		buf = append(buf, m.space...)
		buf = append(buf, m.key...)
		if !m.del {
			buf = append(buf, m.val...)
		}
	}
	return buf
}

// replayFrames verifies and decodes concatenated frames, calling fn for every
// record. It returns the number of bytes of valid frames consumed. A trailing
// partial or corrupt frame is treated as a torn tail and excluded from consumed;
// corruption in the middle of the stream is reported as an error.
func replayFrames(data []byte, fn func(op byte, space, key, val []byte)) (int, error) {
	off := 0
	for off < len(data) {
		if len(data)-off < frameHeader {
			return off, nil // torn tail
		}
		n := int(binary.LittleEndian.Uint32(data[off : off+4]))
		want := binary.LittleEndian.Uint32(data[off+4 : off+8])
		if n < payloadHeader || n > 1<<30 {
			return off, nil // torn/garbage tail
		}
		if len(data)-off-frameHeader < n {
			return off, nil // torn tail
		}
		payload := data[off+frameHeader : off+frameHeader+n]
		if crc32.Checksum(payload, crcTable) != want {
			if off+frameHeader+n >= len(data) {
				return off, nil // last frame torn
			}
			return off, fmt.Errorf("corrupt frame at offset %d", off)
		}
		if err := decodePayload(payload, fn); err != nil {
			return off, err
		}
		off += frameHeader + n
	}
	return off, nil
}

func decodePayload(payload []byte, fn func(op byte, space, key, val []byte)) error {
	if len(payload) < payloadHeader {
		return fmt.Errorf("short payload")
	}
	if payload[0] != recordVersion {
		return fmt.Errorf("unsupported record version %d", payload[0])
	}
	count := int(binary.LittleEndian.Uint32(payload[1:5]))
	p := payload[payloadHeader:]
	for i := 0; i < count; i++ {
		if len(p) < 1+2+4+4 {
			return fmt.Errorf("truncated record %d", i)
		}
		op := p[0]
		spaceLen := int(binary.LittleEndian.Uint16(p[1:3]))
		keyLen := int(binary.LittleEndian.Uint32(p[3:7]))
		valLen := int(binary.LittleEndian.Uint32(p[7:11]))
		p = p[11:]
		if len(p) < spaceLen+keyLen+valLen {
			return fmt.Errorf("truncated record %d body", i)
		}
		space := p[:spaceLen]
		key := p[spaceLen : spaceLen+keyLen]
		var val []byte
		if valLen > 0 {
			val = p[spaceLen+keyLen : spaceLen+keyLen+valLen]
		}
		p = p[spaceLen+keyLen+valLen:]
		if op != opPut && op != opDelete {
			return fmt.Errorf("unknown op %d", op)
		}
		fn(op, space, key, val)
	}
	return nil
}

// compactLocked rewrites the snapshot from the in-memory state and truncates
// the journal. Caller must hold wmu.
func (db *DB) compactLocked() error {
	dir := db.dir
	tmp := filepath.Join(dir, snapshotName+".tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("storage: create snapshot: %w", err)
	}
	if _, err := f.WriteString(snapshotMagic); err != nil {
		f.Close()
		return fmt.Errorf("storage: write snapshot header: %w", err)
	}

	// One frame per space keeps peak memory bounded by the space size.
	db.mu.RLock()
	spaces := make([]string, 0, len(db.data))
	for s := range db.data {
		spaces = append(spaces, s)
	}
	db.mu.RUnlock()
	for _, space := range spaces {
		db.mu.RLock()
		sm := db.data[space]
		muts := make([]mutation, 0, len(sm))
		for k, v := range sm {
			muts = append(muts, mutation{space: []byte(space), key: []byte(k), val: v})
		}
		db.mu.RUnlock()
		payload := encodePayload(muts)
		frame := make([]byte, frameHeader+len(payload))
		binary.LittleEndian.PutUint32(frame[0:4], uint32(len(payload)))
		binary.LittleEndian.PutUint32(frame[4:8], crc32.Checksum(payload, crcTable))
		copy(frame[frameHeader:], payload)
		if _, err := f.Write(frame); err != nil {
			f.Close()
			return fmt.Errorf("storage: write snapshot frame: %w", err)
		}
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("storage: fsync snapshot: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("storage: close snapshot: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, snapshotName)); err != nil {
		return fmt.Errorf("storage: install snapshot: %w", err)
	}
	if err := syncDir(dir); err != nil {
		return err
	}

	// Truncate the WAL: all of its content is now in the snapshot.
	if db.wal != nil {
		if err := db.wal.Truncate(int64(len(journalMagic))); err != nil {
			return fmt.Errorf("storage: truncate journal: %w", err)
		}
		if _, err := db.wal.Seek(int64(len(journalMagic)), io.SeekStart); err != nil {
			return fmt.Errorf("storage: seek journal: %w", err)
		}
		if err := db.wal.Sync(); err != nil {
			return fmt.Errorf("storage: sync truncated journal: %w", err)
		}
	}
	db.walSize = int64(len(journalMagic))
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("storage: open dir for sync: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("storage: fsync dir: %w", err)
	}
	return nil
}
