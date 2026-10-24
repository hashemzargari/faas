// Package storage is the coordinator's persistence boundary.
//
// Production uses PostgreSQL: the canonical relational schema lives in
// docs/schema.sql and the repository interfaces in this package are deliberately
// shaped like tables (ordered scans, prefix lookups, atomic multi-row commits)
// so a database/sql + pgx adapter can implement them without changing any
// caller.
//
// Dev mode (`fass-coordinator --embedded-db`, the default) uses the embedded
// engine implemented in this package: a single-writer, write-ahead-logged,
// ordered key-value store built on the standard library only. Its durability
// guarantee is explicit and narrow:
//
//   - every Update is one WAL frame with a CRC32 and is fsync'd before it is
//     applied, so a crash never leaves a partially applied commit;
//   - a torn tail frame after a crash is detected and truncated on Open;
//   - a periodic snapshot + journal truncation bounds recovery time;
//   - exactly one process may own a data directory (no inter-process locking
//     beyond an exclusive lock file);
//   - it is not a general-purpose database and must not be used for production
//     multi-coordinator deployments.
//
// The store is intentionally narrow: Get/Put/Delete/Scan inside a transaction.
// Domain modelling (buckets, object versions, manifests, ...) lives in
// internal/coord/meta, auth and membership on top of it.
package storage

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

var spaceCounters = []byte("counters")

var (
	// ErrNotFound is returned by Get/Scan lookups for a missing key.
	ErrNotFound = errors.New("storage: key not found")
	// ErrUnavailable reports that the persistence backend cannot currently be
	// reached (connection refused, failover in progress, pool closed). It is a
	// retryable condition: the control plane maps it to 503, never to a 500 that
	// looks permanent. Backends wrap it into the underlying error.
	ErrUnavailable = errors.New("storage: backend unavailable")
	// ErrClosed is returned once Close has been called.
	ErrClosed = errors.New("storage: closed")
)

// DB is the embedded key-value store. It is safe for concurrent readers; writers
// are serialised (single-writer engine).
type DB struct {
	dir     string
	memOnly bool
	mu      sync.RWMutex // guards data
	data    map[string]map[string][]byte
	wmu     sync.Mutex // serialises writes + journal + compaction
	wal     *os.File
	walSize int64
	lock    *fileLock
	closed  bool
}

// Open opens (and creates) the store in dir. An empty dir selects an
// in-memory store, which is useful for unit tests only.
//
// Open replays the snapshot and then the journal; it truncates a torn tail
// frame, which is the expected state after an abrupt process death.
func Open(dir string) (*DB, error) {
	db := &DB{dir: dir, memOnly: dir == "", data: make(map[string]map[string][]byte)}
	if db.memOnly {
		return db, nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("storage: create data dir: %w", err)
	}
	lock, err := acquireLock(filepath.Join(dir, "LOCK"))
	if err != nil {
		return nil, err
	}
	db.lock = lock

	if err := db.loadSnapshot(); err != nil {
		return nil, err
	}
	if err := db.openJournal(); err != nil {
		return nil, err
	}
	// Compaction bounds WAL recovery time on the next boot.
	if db.walSize > compactMinBytes {
		if err := db.compactLocked(); err != nil {
			return nil, err
		}
	}
	return db, nil
}

// Close flushes and closes the store. It is safe to call more than once.
func (db *DB) Close() error {
	db.wmu.Lock()
	defer db.wmu.Unlock()
	if db.closed {
		return nil
	}
	db.closed = true
	var errs []error
	if db.wal != nil {
		if err := db.wal.Sync(); err != nil {
			errs = append(errs, err)
		}
		if err := db.wal.Close(); err != nil {
			errs = append(errs, err)
		}
		db.wal = nil
	}
	if db.lock != nil {
		if err := db.lock.release(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// View runs fn against a consistent read-only snapshot of the store.
//
// The callback must use the provided transaction for all reads; calling back into
// View or Update from inside it can deadlock against a waiting writer and is not
// supported.
func (db *DB) View(ctx context.Context, fn func(Reader) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	db.mu.RLock()
	defer db.mu.RUnlock()
	if db.closed {
		return ErrClosed
	}
	return fn(&ReadTx{db: db})
}

// Update runs fn against a read/write transaction and commits all its mutations
// atomically: one WAL frame, one fsync, then applied in memory. If fn returns an
// error nothing is written.
//
// The callback must use the provided transaction for all reads and writes; it
// must not call View or Update (see View).
func (db *DB) Update(ctx context.Context, fn func(Writer) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	db.wmu.Lock()
	defer db.wmu.Unlock()
	if db.closed {
		return ErrClosed
	}

	// Readers may proceed while the transaction body runs; writers are excluded
	// by wmu, so the in-memory view cannot change underneath fn.
	db.mu.RLock()
	tx := &WriteTx{ReadTx: ReadTx{db: db}, batch: newBatch()}
	err := fn(tx)
	db.mu.RUnlock()
	if err != nil {
		return err
	}
	muts := tx.batch.muts
	if len(muts) == 0 {
		return nil
	}

	if !db.memOnly {
		if err := db.appendJournal(muts); err != nil {
			return err
		}
	}
	db.mu.Lock()
	db.apply(muts)
	db.mu.Unlock()

	if !db.memOnly && db.walSize > compactMinBytes {
		if err := db.compactLocked(); err != nil {
			return err
		}
	}
	return nil
}

// ReadTx is a read-only view of the store.
type ReadTx struct{ db *DB }

// Get returns a copy of the value stored at (space, key).
func (tx *ReadTx) Get(space, key []byte) ([]byte, error) {
	if err := validAddr(space, key); err != nil {
		return nil, err
	}
	spaceMap, ok := tx.db.data[string(space)]
	if !ok {
		return nil, ErrNotFound
	}
	v, ok := spaceMap[string(key)]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), v...), nil
}

// Has reports whether (space, key) exists.
func (tx *ReadTx) Has(space, key []byte) bool {
	_, err := tx.Get(space, key)
	return err == nil
}

// Scan iterates keys of space whose key has prefix, in ascending byte order.
// Returning a non-nil error from fn stops the scan and is returned to the caller
// (wrapping ErrStop as nil). The key/value passed to fn are copies and safe to
// retain.
func (tx *ReadTx) Scan(space, prefix []byte, fn func(key, value []byte) error) error {
	if err := validAddr(space, nil); err != nil {
		return err
	}
	spaceMap := tx.db.data[string(space)]
	keys := make([]string, 0, len(spaceMap))
	for k := range spaceMap {
		if strings.HasPrefix(k, string(prefix)) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := fn([]byte(k), append([]byte(nil), spaceMap[k]...)); err != nil {
			if errors.Is(err, errStop) {
				return nil
			}
			return err
		}
	}
	return nil
}

// Count returns the number of keys in space with prefix.
func (tx *ReadTx) Count(space, prefix []byte) (int, error) {
	n := 0
	err := tx.Scan(space, prefix, func(_, _ []byte) error {
		n++
		return nil
	})
	return n, err
}

// WriteTx is a read/write transaction. Reads observe the transaction's own
// uncommitted writes (read-your-writes).
type WriteTx struct {
	ReadTx
	batch *batch
}

// Get returns the value at (space, key), preferring the transaction's pending
// writes.
func (tx *WriteTx) Get(space, key []byte) ([]byte, error) {
	if m, ok := tx.batch.overlay[addr(string(space), string(key))]; ok {
		if m.del {
			return nil, ErrNotFound
		}
		return append([]byte(nil), m.val...), nil
	}
	return tx.ReadTx.Get(space, key)
}

// Scan iterates keys like ReadTx.Scan but observes the transaction's pending
// writes: staged puts are included and staged deletes are hidden.
func (tx *WriteTx) Scan(space, prefix []byte, fn func(key, value []byte) error) error {
	if err := validAddr(space, nil); err != nil {
		return err
	}
	merged := make(map[string][]byte)
	if sm := tx.db.data[string(space)]; sm != nil {
		for k, v := range sm {
			if strings.HasPrefix(k, string(prefix)) {
				merged[k] = v
			}
		}
	}
	for a, m := range tx.batch.overlay {
		if string(m.space) != string(space) {
			continue
		}
		k := string(m.key)
		if !strings.HasPrefix(k, string(prefix)) {
			continue
		}
		if m.del {
			delete(merged, k)
		} else {
			merged[k] = m.val
		}
		_ = a
	}
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := fn([]byte(k), append([]byte(nil), merged[k]...)); err != nil {
			if errors.Is(err, errStop) {
				return nil
			}
			return err
		}
	}
	return nil
}

// Has reports whether (space, key) exists, including pending writes.
func (tx *WriteTx) Has(space, key []byte) bool {
	_, err := tx.Get(space, key)
	return err == nil
}

// Put stages a write. The value is copied.
func (tx *WriteTx) Put(space, key, val []byte) error {
	if err := validAddr(space, key); err != nil {
		return err
	}
	m := mutation{
		space: append([]byte(nil), space...),
		key:   append([]byte(nil), key...),
		val:   append([]byte(nil), val...),
	}
	tx.batch.add(m)
	return nil
}

// Delete stages a delete. Deleting a missing key is a no-op.
func (tx *WriteTx) Delete(space, key []byte) error {
	if err := validAddr(space, key); err != nil {
		return err
	}
	tx.batch.add(mutation{
		space: append([]byte(nil), space...),
		key:   append([]byte(nil), key...),
		del:   true,
	})
	return nil
}

// NextSequence implements the counter-based sequence for the embedded engine.
// It reads and writes the counter row inside the same transaction (the embedded
// engine serialises writers, so this cannot deadlock).
func (tx *WriteTx) NextSequence(name string) (uint64, error) {
	raw, err := tx.Get(spaceCounters, []byte(name))
	switch {
	case errors.Is(err, ErrNotFound):
	case err != nil:
		return 0, err
	}
	var cur uint64
	if len(raw) == 8 {
		cur = binary.BigEndian.Uint64(raw)
	}
	next := cur + 1
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], next)
	if err := tx.Put(spaceCounters, []byte(name), buf[:]); err != nil {
		return 0, err
	}
	return next, nil
}

// ---------------------------------------------------------------------------
// Typed helpers — the coordinator stores JSON records, which keeps the dev and
// PostgreSQL representations isomorphic.
// ---------------------------------------------------------------------------

// GetJSON decodes the JSON record at (space, key) into T.
func GetJSON[T any](tx Reader, space, key []byte) (T, error) {
	var out T
	raw, err := tx.Get(space, key)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, fmt.Errorf("storage: decode %s/%q: %w", space, key, err)
	}
	return out, nil
}

// PutJSON encodes v as JSON at (space, key).
func PutJSON[T any](tx Writer, space, key []byte, v T) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("storage: encode %s/%q: %w", space, key, err)
	}
	return tx.Put(space, key, raw)
}

// ScanJSON decodes every record of space with prefix, calling fn in key order
// with the decoded value.
func ScanJSON[T any](tx Reader, space, prefix []byte, fn func(key []byte, v T) error) error {
	return tx.Scan(space, prefix, func(k, raw []byte) error {
		var v T
		if err := json.Unmarshal(raw, &v); err != nil {
			return fmt.Errorf("storage: decode %s/%q: %w", space, k, err)
		}
		return fn(k, v)
	})
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

var errStop = errors.New("storage: stop scan")

// ErrStopScan is the sentinel returned by StopScan. Backends recognise it via
// errors.Is so a callback can end a scan early without an error.
var ErrStopScan = errStop

// StopScan stops a Scan early without reporting an error. Usage:
//
//	return storage.StopScan()
func StopScan() error { return errStop }

type mutation struct {
	space []byte
	key   []byte
	val   []byte
	del   bool
}

func addr(space, key string) string { return space + "\x00" + key }

type batch struct {
	muts    []mutation
	overlay map[string]mutation
}

func newBatch() *batch { return &batch{overlay: make(map[string]mutation)} }

func (b *batch) add(m mutation) {
	a := addr(string(m.space), string(m.key))
	b.overlay[a] = m
	b.muts = append(b.muts, m)
}

func (db *DB) apply(muts []mutation) {
	for _, m := range muts {
		sm := db.data[string(m.space)]
		if m.del {
			if sm != nil {
				delete(sm, string(m.key))
			}
			continue
		}
		if sm == nil {
			sm = make(map[string][]byte)
			db.data[string(m.space)] = sm
		}
		sm[string(m.key)] = m.val
	}
}

func validAddr(space, key []byte) error {
	if len(space) == 0 {
		return fmt.Errorf("storage: empty space name")
	}
	if strings.IndexByte(string(space), 0) >= 0 {
		return fmt.Errorf("storage: space name contains NUL")
	}
	_ = key
	return nil
}

// JoinKey builds a composite key from parts, NUL-separated. NUL cannot appear in
// S3 bucket names, and object keys containing NUL are rejected by the gateway,
// so this is unambiguous for the coordinator's key spaces.
func JoinKey(parts ...string) []byte {
	return []byte(strings.Join(parts, "\x00"))
}

// JoinKeyN builds a composite key from n NUL-separated string parts followed by
// any trailing raw bytes (used for big-endian numeric suffixes).
func JoinKeyN(parts []string, suffix []byte) []byte {
	out := make([]byte, 0, 16)
	for _, p := range parts {
		out = append(out, p...)
		out = append(out, 0)
	}
	return append(out, suffix...)
}
