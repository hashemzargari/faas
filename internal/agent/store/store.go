// Package store implements the per-disk immutable shard store of a FASS agent
// (docs/03-data-plane.md §2.3, docs/04-services.md §6.3).
//
// Layout under the agent root (/data):
//
//	shards/<aa>/<bb>/<shard_id>.shard   immutable shard: header + payload
//	index/shards.idx                    append-only metadata index (compacted)
//	incoming/*.partial                  write temp files, swept on boot
//	quarantine/                         corrupt shards kept for forensics
//	state.json                          disk identity + format version
//
// Write protocol: temp file in incoming/ → write header placeholder → stream
// payload while hashing → patch header → fsync(file) → rename into shards/ →
// fsync(dir) → append index record → fsync(index). A crash leaves at worst a
// .partial file (swept) or an orphan .shard file (recovered from its
// self-describing header at boot).
//
// Shards are immutable: rewriting the same address with identical bytes is an
// idempotent 201-equivalent (PutResult.Idempotent), different bytes return
// contract.ErrConflict.
package store

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fass-storage/fass/internal/agent/shard"
	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/ec"
)

// Defaults from docs/04-services.md §6.4.
const (
	defaultReservePct    = 5.0
	defaultMaxShardBytes = 32 << 20

	// Compaction thresholds: rewrite the log when it holds more than twice the
	// live entries and is at least indexCompactionMin records long.
	indexCompactionFactor = 2
	indexCompactionMin    = 1024

	stripeCount = 256
)

var (
	// ErrClosed is returned after Close.
	ErrClosed = errors.New("store: closed")
	// ErrReadOnly is returned when a write is attempted on a read-only store.
	ErrReadOnly = errors.New("store: read-only")
	// ErrChecksumMismatch is returned when the body's checksum does not match
	// the expected one.
	ErrChecksumMismatch = errors.New("store: checksum mismatch")
	// ErrCorrupt is returned when a stored shard fails checksum verification.
	ErrCorrupt = errors.New("store: corrupt shard")
	// ErrTooLarge is returned when a shard exceeds Options.MaxShardBytes.
	ErrTooLarge = errors.New("store: shard exceeds max size")
	// ErrBadRequest is returned for invalid addresses or parameters.
	ErrBadRequest = errors.New("store: invalid request")
	// ErrLengthMismatch is returned when the body length differs from the
	// declared payload length.
	ErrLengthMismatch = errors.New("store: payload length mismatch")
	// ErrInsufficientCapacity is the agent-side 507 condition.
	ErrInsufficientCapacity = contract.ErrInsufficientCap
)

// CapacityFunc reports total and free bytes for the filesystem holding root.
type CapacityFunc func(root string) (total, free int64, err error)

// Options configures a Store.
type Options struct {
	// Root is the agent data directory ("/data").
	Root string
	// ReservePct is the share of the filesystem reserved so the disk never
	// fills (default 5%).
	ReservePct float64
	// MaxShardBytes caps a single shard payload (default 32 MiB).
	MaxShardBytes int64
	// DisableVerifyOnRead serves shards without pre-verifying their checksum.
	// Off by default: the Lead's rule is that a corrupt shard is never served.
	DisableVerifyOnRead bool
	// ReadOnly opens the store for reads only (drain/forensics).
	ReadOnly bool
	// Logger defaults to slog.Default().
	Logger *slog.Logger
	// CapacityFunc is a test hook; defaults to statfs on Linux.
	CapacityFunc CapacityFunc
	// OnCorrupt is called after a corrupt shard is quarantined so the caller
	// can report CORRUPT to the coordinator.
	OnCorrupt func(contract.ShardStatus)
}

// PutRequest describes one shard write.
type PutRequest struct {
	ShardSetID contract.ShardSetID
	GeoGroup   int
	LocalIndex int
	Params     ec.Params
	ChunkIndex int
	// PayloadLen is the declared payload length; -1 means "read until EOF".
	PayloadLen int64
	Checksum   uint64
}

// PutResult reports the outcome of a shard write.
type PutResult struct {
	Checksum   uint64
	Stored     int64
	Idempotent bool
}

// Stats is the /v1/stats surface plus a few internal counters.
type Stats struct {
	DiskID        string
	FormatVersion int
	ShardCount    int64
	SetCount      int64
	UsedBytes     int64
	PayloadBytes  int64
	TotalBytes    int64
	RawFreeBytes  int64
	ReservedBytes int64
	FreeBytes     int64 // free bytes net of the reservation, never negative
}

// Store is one agent's shard store.
type Store struct {
	root          string
	shardDir      string
	incomingDir   string
	indexDir      string
	quarantineDir string
	stateFile     string

	opts Options
	log  *slog.Logger
	cap  CapacityFunc

	mu          sync.RWMutex
	idx         map[string]entry
	setCounts   map[string]int
	sorted      []string
	sortedDirty bool
	ix          *indexFile

	usedBytes    atomic.Int64
	payloadBytes atomic.Int64

	stripes [stripeCount]sync.Mutex
	closed  atomic.Bool

	state State
}

// Open initialises (or recovers) a shard store.
func Open(ctx context.Context, opts Options) (*Store, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(opts.Root) == "" {
		return nil, fmt.Errorf("%w: empty root", ErrBadRequest)
	}
	if opts.ReservePct < 0 || opts.ReservePct >= 100 {
		return nil, fmt.Errorf("%w: reserve_pct must be in [0,100)", ErrBadRequest)
	}
	if opts.ReservePct == 0 {
		opts.ReservePct = defaultReservePct
	}
	if opts.MaxShardBytes <= 0 {
		opts.MaxShardBytes = defaultMaxShardBytes
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.CapacityFunc == nil {
		opts.CapacityFunc = diskCapacity
	}

	root, err := filepath.Abs(opts.Root)
	if err != nil {
		return nil, fmt.Errorf("store: resolve root: %w", err)
	}

	s := &Store{
		root:          root,
		shardDir:      filepath.Join(root, "shards"),
		incomingDir:   filepath.Join(root, "incoming"),
		indexDir:      filepath.Join(root, "index"),
		quarantineDir: filepath.Join(root, "quarantine"),
		stateFile:     filepath.Join(root, "state.json"),
		opts:          opts,
		log:           opts.Logger.With("component", "store", "root", root),
		cap:           opts.CapacityFunc,
		idx:           make(map[string]entry),
		setCounts:     make(map[string]int),
		sortedDirty:   true,
	}

	for _, dir := range []string{s.shardDir, s.incomingDir, s.indexDir, s.quarantineDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("store: create %s: %w", dir, err)
		}
	}

	if s.state, err = loadOrCreateState(s.stateFile); err != nil {
		return nil, err
	}

	ix, entries, err := openIndex(filepath.Join(s.indexDir, indexFilename))
	if err != nil {
		return nil, err
	}
	s.ix = ix
	s.idx = entries
	for _, e := range entries {
		s.setCounts[string(e.SetID)]++
		s.usedBytes.Add(e.FileSize)
		s.payloadBytes.Add(e.PayloadLen)
	}

	if err := s.sweepIncoming(); err != nil {
		s.log.Warn("sweeping incoming/ failed; partial writes may remain", "err", err)
	}
	if err := s.reconcile(); err != nil {
		// Reconciliation failures must not silently lose shards: fail open so an
		// operator sees the disk instead of the agent serving a half-recovered
		// index.
		s.ix.Close()
		return nil, fmt.Errorf("store: reconcile shards at boot: %w", err)
	}
	s.log.Info("shard store opened",
		"disk_id", s.state.DiskID, "shards", len(s.idx),
		"used_bytes", s.usedBytes.Load(), "reserve_pct", s.opts.ReservePct)
	return s, nil
}

// Root returns the absolute store root.
func (s *Store) Root() string { return s.root }

// DiskID returns the persisted disk identity.
func (s *Store) DiskID() string { return s.state.DiskID }

// FormatVersion returns the on-disk format version.
func (s *Store) FormatVersion() int { return s.state.FormatVersion }

// ReadOnly reports whether the store rejects writes.
func (s *Store) ReadOnly() bool { return s.opts.ReadOnly }

// MaxShardBytes is the configured per-shard payload cap.
func (s *Store) MaxShardBytes() int64 { return s.opts.MaxShardBytes }

// Close flushes and closes the index.
func (s *Store) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ix.sync(); err != nil {
		return err
	}
	return s.ix.Close()
}

// pathFor is the on-disk path of a shard id: shards/<aa>/<bb>/<id>.shard.
func (s *Store) pathFor(id string) string {
	aa, bb := "00", "00"
	if len(id) >= 4 {
		aa, bb = id[0:2], id[2:4]
	}
	return filepath.Join(s.shardDir, aa, bb, id+".shard")
}

func (s *Store) stripe(id string) *sync.Mutex {
	// FNV-1a over the id, then modulo the stripe count. A cheap, stable hash is
	// enough: stripes only reduce lock contention between unrelated shards.
	var h uint32 = 2166136261
	for i := 0; i < len(id); i++ {
		h ^= uint32(id[i])
		h *= 16777619
	}
	return &s.stripes[h%stripeCount]
}

// lookup returns the index entry for a shard id.
func (s *Store) lookup(id string) (entry, bool) {
	s.mu.RLock()
	e, ok := s.idx[id]
	s.mu.RUnlock()
	return e, ok
}

// addEntry records a new shard in the in-memory index and the on-disk log.
// Callers must serialize with stripe locks; s.mu protects the maps.
func (s *Store) addEntry(e entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.idx[e.ID]; ok {
		return nil
	}
	if err := s.ix.appendAdd(e); err != nil {
		return err
	}
	if err := s.ix.sync(); err != nil {
		return err
	}
	s.idx[e.ID] = e
	s.setCounts[string(e.SetID)]++
	s.usedBytes.Add(e.FileSize)
	s.payloadBytes.Add(e.PayloadLen)
	s.sortedDirty = true
	s.maybeCompactLocked()
	return nil
}

// removeEntry drops a shard from the in-memory index and appends a tombstone.
func (s *Store) removeEntry(e entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.idx[e.ID]
	if !ok {
		return nil
	}
	if err := s.ix.appendDelete(cur); err != nil {
		return err
	}
	if err := s.ix.sync(); err != nil {
		return err
	}
	delete(s.idx, cur.ID)
	if n := s.setCounts[string(cur.SetID)]; n <= 1 {
		delete(s.setCounts, string(cur.SetID))
	} else {
		s.setCounts[string(cur.SetID)] = n - 1
	}
	s.usedBytes.Add(-cur.FileSize)
	s.payloadBytes.Add(-cur.PayloadLen)
	s.sortedDirty = true
	s.maybeCompactLocked()
	return nil
}

// maybeCompactLocked rewrites the log when it is mostly tombstones. The caller
// holds s.mu.
func (s *Store) maybeCompactLocked() {
	if s.ix.records < indexCompactionMin || s.ix.records < indexCompactionFactor*len(s.idx) {
		return
	}
	if err := s.ix.rewrite(s.idx); err != nil {
		s.log.Warn("index compaction failed; continuing with append log", "err", err)
		return
	}
	s.log.Info("compacted shard index", "entries", len(s.idx))
}

// sweepIncoming deletes leftover .partial temp files from a previous crash and
// stale compaction temporaries.
func (s *Store) sweepIncoming() error {
	ents, err := os.ReadDir(s.incomingDir)
	if err != nil {
		return fmt.Errorf("read incoming dir: %w", err)
	}
	swept := 0
	for _, ent := range ents {
		if ent.IsDir() {
			continue
		}
		p := filepath.Join(s.incomingDir, ent.Name())
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", p, err)
		}
		swept++
	}
	if idxEnts, err := os.ReadDir(s.indexDir); err == nil {
		for _, ent := range idxEnts {
			if strings.HasSuffix(ent.Name(), ".compact") || strings.HasSuffix(ent.Name(), ".tmp") {
				p := filepath.Join(s.indexDir, ent.Name())
				if err := os.Remove(p); err == nil {
					swept++
				}
			}
		}
	}
	if swept > 0 {
		s.log.Info("swept crash leftovers", "files", swept)
	}
	return nil
}

// reconcile rebuilds index entries for orphan .shard files (shard written and
// renamed before the index record was appended, or a lost index) and repairs
// files that live at a path inconsistent with their header. It does not delete
// unknown files: an operator can inspect them.
func (s *Store) reconcile() error {
	recovered := 0
	walkErr := filepath.WalkDir(s.shardDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".shard") {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			s.log.Warn("cannot open shard file during reconcile", "path", path, "err", err)
			return nil
		}
		hdr, hdrLen, err := readHeaderAt(f)
		f.Close()
		if err != nil {
			s.log.Warn("skipping unreadable shard file during reconcile", "path", path, "err", err)
			return nil
		}
		fi, err := os.Stat(path)
		if err != nil {
			return nil
		}
		if fi.Size() != int64(hdrLen)+hdr.PayloadLen {
			s.log.Warn("shard file size mismatch during reconcile; leaving for operator",
				"path", path, "size", fi.Size(), "header_payload", hdr.PayloadLen, "header_len", hdrLen)
			return nil
		}
		id := shard.ID(hdr.SetID, hdr.GeoGroup, hdr.LocalIndex)
		want := s.pathFor(id)
		if want != path {
			if _, statErr := os.Stat(want); statErr == nil {
				s.log.Warn("shard file at unexpected path with an existing destination; leaving for operator",
					"path", path, "expected", want)
				return nil
			}
			if err := os.MkdirAll(filepath.Dir(want), 0o755); err != nil {
				return err
			}
			if err := os.Rename(path, want); err != nil {
				s.log.Warn("cannot move misplaced shard file", "path", path, "expected", want, "err", err)
				return nil
			}
			s.log.Warn("moved misplaced shard file", "from", path, "to", want)
		}
		if _, ok := s.lookup(id); ok {
			return nil
		}
		e := entry{
			ID:         id,
			SetID:      hdr.SetID,
			GeoGroup:   hdr.GeoGroup,
			LocalIndex: hdr.LocalIndex,
			ChunkIndex: hdr.ChunkIndex,
			Params:     hdr.Params,
			PayloadLen: hdr.PayloadLen,
			FileSize:   fi.Size(),
			Checksum:   binaryBigEndianUint64(hdr.Checksum[:8]),
			CreatedAt:  hdr.CreatedAt,
		}
		if err := s.addEntry(e); err != nil {
			return fmt.Errorf("record recovered shard %s: %w", id, err)
		}
		recovered++
		return nil
	})
	if walkErr != nil {
		return walkErr
	}
	if recovered > 0 {
		s.log.Info("recovered orphan shards into the index", "count", recovered)
	}
	return nil
}

// Put stores one shard. See the package comment for the crash-safe protocol.
func (s *Store) Put(ctx context.Context, req PutRequest, body io.Reader) (PutResult, error) {
	if err := ctx.Err(); err != nil {
		return PutResult{}, err
	}
	if s.closed.Load() {
		return PutResult{}, ErrClosed
	}
	if s.opts.ReadOnly {
		return PutResult{}, ErrReadOnly
	}
	if body == nil {
		return PutResult{}, fmt.Errorf("%w: nil body", ErrBadRequest)
	}
	if err := s.validatePut(req); err != nil {
		return PutResult{}, err
	}

	id := shard.ID(req.ShardSetID, req.GeoGroup, req.LocalIndex)
	lock := s.stripe(id)
	lock.Lock()
	defer lock.Unlock()

	if err := ctx.Err(); err != nil {
		return PutResult{}, err
	}

	// Idempotent / conflict fast path: compare the address' existing metadata
	// without consuming the request body when it can never match.
	if existing, ok := s.lookup(id); ok {
		res, handled, err := s.checkExisting(ctx, id, existing, req)
		if err != nil || handled {
			return res, err
		}
	} else if _, err := os.Stat(s.pathFor(id)); err == nil {
		// Orphan shard file not in the index (crash between rename and index
		// append): adopt it if it matches, refuse to overwrite otherwise.
		f, openErr := os.Open(s.pathFor(id))
		if openErr != nil {
			return PutResult{}, fmt.Errorf("store: open orphan shard %s: %w", id, openErr)
		}
		hdr, _, hdrErr := readHeaderAt(f)
		var size int64
		if fi, statErr := f.Stat(); statErr == nil {
			size = fi.Size()
		}
		f.Close()
		if hdrErr != nil {
			_ = os.Remove(s.pathFor(id))
		} else if hdr.SetID != req.ShardSetID || hdr.GeoGroup != req.GeoGroup || hdr.LocalIndex != req.LocalIndex {
			return PutResult{}, fmt.Errorf("store: put %s: orphan shard header address mismatch: %w", id, ErrCorrupt)
		} else if hdr.PayloadLen == req.PayloadLen || req.PayloadLen < 0 {
			if binaryBigEndianUint64(hdr.Checksum[:8]) != req.Checksum {
				return PutResult{}, fmt.Errorf("store: put %s: different bytes for immutable shard: %w", id, contract.ErrConflict)
			}
			e := entry{
				ID: id, SetID: req.ShardSetID, GeoGroup: req.GeoGroup,
				LocalIndex: req.LocalIndex, ChunkIndex: hdr.ChunkIndex, Params: hdr.Params,
				PayloadLen: hdr.PayloadLen, FileSize: size,
				Checksum: binaryBigEndianUint64(hdr.Checksum[:8]), CreatedAt: hdr.CreatedAt,
			}
			if err := s.addEntry(e); err != nil {
				return PutResult{}, err
			}
			return PutResult{Checksum: req.Checksum, Stored: 0, Idempotent: true}, nil
		} else {
			return PutResult{}, fmt.Errorf("store: put %s: different bytes for immutable shard: %w", id, contract.ErrConflict)
		}
	}

	// Capacity admission: reject before reading a large body when the declared
	// length already proves there is no room.
	if req.PayloadLen >= 0 {
		if err := s.checkCapacity(req.PayloadLen); err != nil {
			return PutResult{}, err
		}
	}

	tmp, err := os.CreateTemp(s.incomingDir, "put-*.partial")
	if err != nil {
		return PutResult{}, fmt.Errorf("store: create temp shard: %w", err)
	}
	tmpPath := tmp.Name()
	renamed := false
	defer func() {
		tmp.Close()
		if !renamed {
			os.Remove(tmpPath)
		}
	}()

	hdrLen := headerFixedLen + len(req.ShardSetID)
	placeholder := make([]byte, hdrLen)
	if _, err := tmp.Write(placeholder); err != nil {
		return PutResult{}, fmt.Errorf("store: write header placeholder: %w", err)
	}

	hasher := shard.NewHasher()
	limit := s.opts.MaxShardBytes + 1
	if req.PayloadLen >= 0 && req.PayloadLen < limit {
		limit = req.PayloadLen + 1
	}
	n, err := io.Copy(io.MultiWriter(tmp, hasher), io.LimitReader(&contextReader{ctx: ctx, r: body}, limit))
	if err != nil {
		return PutResult{}, fmt.Errorf("store: write shard payload: %w", err)
	}
	if n > s.opts.MaxShardBytes {
		return PutResult{}, fmt.Errorf("%w: payload exceeds %d bytes", ErrTooLarge, s.opts.MaxShardBytes)
	}
	if req.PayloadLen >= 0 && n != req.PayloadLen {
		return PutResult{}, fmt.Errorf("%w: declared %d, got %d", ErrLengthMismatch, req.PayloadLen, n)
	}

	sum := hasher.Sum256()
	if binaryBigEndianUint64(sum[:8]) != req.Checksum {
		return PutResult{}, fmt.Errorf("%w: expected %016x, computed %016x",
			ErrChecksumMismatch, req.Checksum, binaryBigEndianUint64(sum[:8]))
	}

	// The checksum is verified above; now re-read the (small) temp file to hash
	// the actual bytes written. io.Copy above hashed through the same reader,
	// so the payload digest is already known — but a short write would have
	// already errored. No second pass is needed.
	hdr := Header{
		Version:    shardVersion,
		Params:     req.Params,
		ChunkIndex: req.ChunkIndex,
		GeoGroup:   req.GeoGroup,
		LocalIndex: req.LocalIndex,
		SetID:      req.ShardSetID,
		PayloadLen: n,
		Checksum:   sum,
		CreatedAt:  time.Now().UTC(),
	}
	hdrBytes, err := hdr.MarshalBinary()
	if err != nil {
		return PutResult{}, err
	}
	if len(hdrBytes) != hdrLen {
		return PutResult{}, fmt.Errorf("store: internal header length mismatch (%d != %d)", len(hdrBytes), hdrLen)
	}
	if _, err := tmp.WriteAt(hdrBytes, 0); err != nil {
		return PutResult{}, fmt.Errorf("store: patch shard header: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return PutResult{}, fmt.Errorf("store: fsync shard: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return PutResult{}, fmt.Errorf("store: close temp shard: %w", err)
	}

	// Re-check capacity with the true size (PayloadLen may have been unknown).
	if err := s.checkCapacity(n); err != nil {
		return PutResult{}, err
	}

	if _, err := os.Stat(s.pathFor(id)); err == nil {
		// A file appeared after the fast path (only possible for an orphan in a
		// racing process); never overwrite immutable bytes.
		return PutResult{}, fmt.Errorf("store: put %s: destination appeared concurrently: %w", id, contract.ErrConflict)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return PutResult{}, fmt.Errorf("store: stat destination %s: %w", s.pathFor(id), err)
	}

	finalPath := s.pathFor(id)
	if err := os.MkdirAll(filepath.Dir(finalPath), 0o755); err != nil {
		return PutResult{}, fmt.Errorf("store: create shard dir: %w", err)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return PutResult{}, fmt.Errorf("store: rename shard into place: %w", err)
	}
	renamed = true
	if err := fsyncDir(filepath.Dir(finalPath)); err != nil {
		return PutResult{}, err
	}

	e := entry{
		ID:         id,
		SetID:      req.ShardSetID,
		GeoGroup:   req.GeoGroup,
		LocalIndex: req.LocalIndex,
		ChunkIndex: req.ChunkIndex,
		Params:     req.Params,
		PayloadLen: n,
		FileSize:   int64(hdrLen) + n,
		Checksum:   binaryBigEndianUint64(sum[:8]),
		CreatedAt:  hdr.CreatedAt,
	}
	if err := s.addEntry(e); err != nil {
		return PutResult{}, err
	}
	return PutResult{Checksum: e.Checksum, Stored: n}, nil
}

// checkExisting handles the idempotent-rewrite / immutability-conflict decision
// for an address already present in the index. It returns handled=true when the
// caller must return res immediately.
func (s *Store) checkExisting(ctx context.Context, id string, existing entry, req PutRequest) (res PutResult, handled bool, err error) {
	if err := ctx.Err(); err != nil {
		return PutResult{}, true, err
	}
	f, openErr := os.Open(s.pathFor(id))
	if openErr != nil {
		if errors.Is(openErr, fs.ErrNotExist) {
			// Stale index entry (file removed out of band): drop it and let the
			// caller proceed with a fresh write.
			if rmErr := s.removeEntry(existing); rmErr != nil {
				return PutResult{}, true, rmErr
			}
			return PutResult{}, false, nil
		}
		return PutResult{}, true, fmt.Errorf("store: open existing shard %s: %w", id, openErr)
	}
	hdr, hdrLen, hdrErr := readHeaderAt(f)
	f.Close()
	if hdrErr != nil {
		// The stored shard is unreadable: quarantine it and allow the write.
		s.log.Warn("quarantining unreadable shard header", "shard_id", id, "err", hdrErr)
		if qErr := s.quarantine(existing, hdrErr); qErr != nil {
			return PutResult{}, true, qErr
		}
		return PutResult{}, false, nil
	}
	_ = hdrLen
	if req.PayloadLen >= 0 && hdr.PayloadLen != req.PayloadLen {
		return PutResult{}, true, fmt.Errorf("store: put %s: different bytes for immutable shard: %w", id, contract.ErrConflict)
	}
	if binaryBigEndianUint64(hdr.Checksum[:8]) != req.Checksum {
		return PutResult{}, true, fmt.Errorf("store: put %s: different bytes for immutable shard: %w", id, contract.ErrConflict)
	}
	return PutResult{Checksum: binaryBigEndianUint64(hdr.Checksum[:8]), Stored: 0, Idempotent: true}, true, nil
}

func (s *Store) validatePut(req PutRequest) error {
	if req.ShardSetID == "" {
		return fmt.Errorf("%w: empty shard_set_id", ErrBadRequest)
	}
	if len(req.ShardSetID) > maxSetIDTextLen {
		return fmt.Errorf("%w: shard_set_id too long", ErrBadRequest)
	}
	if err := req.Params.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrBadRequest, err)
	}
	if req.GeoGroup < 0 || req.GeoGroup >= req.Params.GeoN+req.Params.GeoK {
		return fmt.Errorf("%w: geo_group %d out of range", ErrBadRequest, req.GeoGroup)
	}
	if req.LocalIndex < 0 || req.LocalIndex >= req.Params.ShardsPerGroup() {
		return fmt.Errorf("%w: local_index %d out of range", ErrBadRequest, req.LocalIndex)
	}
	if req.ChunkIndex < 0 {
		return fmt.Errorf("%w: negative chunk_index", ErrBadRequest)
	}
	if req.PayloadLen < -1 {
		return fmt.Errorf("%w: negative payload length", ErrBadRequest)
	}
	if req.PayloadLen > s.opts.MaxShardBytes {
		return fmt.Errorf("%w: payload %d exceeds %d", ErrTooLarge, req.PayloadLen, s.opts.MaxShardBytes)
	}
	return nil
}

// capacity returns total, raw free, reserved and net free bytes.
func (s *Store) capacity() (total, rawFree, reserved, free int64, err error) {
	total, rawFree, err = s.cap(s.root)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("store: statfs: %w", err)
	}
	reserved = int64(float64(total) * s.opts.ReservePct / 100.0)
	free = rawFree - reserved
	if free < 0 {
		free = 0
	}
	return total, rawFree, reserved, free, nil
}

// checkCapacity enforces the 5% disk reservation.
func (s *Store) checkCapacity(want int64) error {
	if s.opts.ReadOnly {
		return nil
	}
	_, _, _, free, err := s.capacity()
	if err != nil {
		// Without capacity information the safe behaviour is to keep serving;
		// a full disk still fails the write at the filesystem level.
		s.log.Warn("capacity check skipped", "err", err)
		return nil
	}
	if want > free {
		return fmt.Errorf("%w: need %d bytes, %d free after %.1f%% reservation",
			ErrInsufficientCapacity, want, free, s.opts.ReservePct)
	}
	return nil
}

// Get opens a shard for streaming. Unless DisableVerifyOnRead is set, the
// payload checksum is verified before any byte is returned ("do not serve
// corrupt shards"); a mismatch quarantines the shard and returns ErrCorrupt.
func (s *Store) Get(ctx context.Context, setID contract.ShardSetID, geoGroup, localIndex int) (*Reader, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.closed.Load() {
		return nil, ErrClosed
	}
	id := shard.ID(setID, geoGroup, localIndex)
	e, ok := s.lookup(id)
	if !ok {
		return nil, fmt.Errorf("store: get %s: %w", id, contract.ErrNotFound)
	}
	path := s.pathFor(id)
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			_ = s.removeEntry(e)
			return nil, fmt.Errorf("store: get %s: %w", id, contract.ErrNotFound)
		}
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	hdr, hdrLen, err := readHeaderAt(f)
	if err != nil {
		f.Close()
		s.log.Warn("corrupt shard header; quarantining", "shard_id", id, "err", err)
		if qErr := s.quarantine(e, err); qErr != nil {
			s.log.Warn("quarantine failed", "shard_id", id, "err", qErr)
		}
		return nil, fmt.Errorf("store: header %s: %w: %w", id, ErrCorrupt, err)
	}
	if hdr.SetID != setID || hdr.GeoGroup != geoGroup || hdr.LocalIndex != localIndex {
		f.Close()
		err := fmt.Errorf("%w: header address does not match file name", ErrCorrupt)
		if qErr := s.quarantine(e, err); qErr != nil {
			s.log.Warn("quarantine failed", "shard_id", id, "err", qErr)
		}
		return nil, fmt.Errorf("store: %s: %w", id, err)
	}

	info := contract.ShardInfo{
		ShardSetID: hdr.SetID,
		GeoGroup:   hdr.GeoGroup,
		LocalIndex: hdr.LocalIndex,
		Size:       int64(hdrLen) + hdr.PayloadLen,
		Checksum:   binaryBigEndianUint64(hdr.Checksum[:8]),
		CreatedAt:  hdr.CreatedAt,
	}

	section := io.NewSectionReader(f, int64(hdrLen), hdr.PayloadLen)
	rd := &Reader{
		Header:   hdr,
		Info:     info,
		f:        f,
		r:        section,
		hasher:   nil,
		verified: s.opts.DisableVerifyOnRead,
	}
	if !s.opts.DisableVerifyOnRead {
		hasher := shard.NewHasher()
		if _, err := io.Copy(hasher, section); err != nil {
			f.Close()
			return nil, fmt.Errorf("store: verify %s: %w", id, err)
		}
		if hasher.Sum256() != hdr.Checksum {
			f.Close()
			verr := fmt.Errorf("%w: payload digest != header checksum", ErrCorrupt)
			if qErr := s.quarantine(e, verr); qErr != nil {
				s.log.Warn("quarantine failed", "shard_id", id, "err", qErr)
			}
			return nil, fmt.Errorf("store: %s: %w", id, verr)
		}
		rd.hasher = hasher
		rd.r = io.NewSectionReader(f, int64(hdrLen), hdr.PayloadLen)
	}
	return rd, nil
}

// Reader streams one shard payload. Callers must Close it.
type Reader struct {
	Header Header
	Info   contract.ShardInfo

	f        *os.File
	r        io.Reader
	hasher   *shard.Hasher
	verified bool
	mu       sync.Mutex
	err      error
	closeOne sync.Once
}

// Read implements io.Reader. With lazy verification it validates the checksum
// at EOF and returns ErrCorrupt instead of a clean EOF on mismatch.
func (r *Reader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return 0, r.err
	}
	n, err := r.r.Read(p)
	if err == io.EOF && !r.verified {
		r.verified = true
		if r.hasher.Sum256() != r.Header.Checksum {
			r.err = ErrCorrupt
			return n, r.err
		}
	}
	return n, err
}

// Close releases the underlying file.
func (r *Reader) Close() error {
	var err error
	r.closeOne.Do(func() {
		if r.f != nil {
			err = r.f.Close()
		}
	})
	return err
}

// Stat returns the stored metadata for one shard without reading its payload.
func (s *Store) Stat(ctx context.Context, setID contract.ShardSetID, geoGroup, localIndex int) (contract.ShardInfo, error) {
	if err := ctx.Err(); err != nil {
		return contract.ShardInfo{}, err
	}
	e, ok := s.lookup(shard.ID(setID, geoGroup, localIndex))
	if !ok {
		return contract.ShardInfo{}, fmt.Errorf("store: stat: %w", contract.ErrNotFound)
	}
	return e.shardInfo(), nil
}

// Params returns the codec parameters recorded for a stored shard (used by the
// scrubber to translate (group, index) into a global slot number).
func (s *Store) Params(setID contract.ShardSetID, geoGroup, localIndex int) (ec.Params, bool) {
	e, ok := s.lookup(shard.ID(setID, geoGroup, localIndex))
	if !ok {
		return ec.Params{}, false
	}
	return e.Params, true
}

// Has reports per shard set whether this agent holds at least one shard of it.
// The wire signature (docs/07 §2) addresses sets, not individual slots.
func (s *Store) Has(ctx context.Context, ids []contract.ShardSetID) ([]bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := make([]bool, len(ids))
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i, id := range ids {
		out[i] = s.setCounts[string(id)] > 0
	}
	return out, nil
}

// DeleteSet removes every shard belonging to one shard set. Files are removed
// before index tombstones are written: a crash in between leaves orphan files
// that boot reconciliation re-adopts, never a dangling index entry.
func (s *Store) DeleteSet(ctx context.Context, setID contract.ShardSetID) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if s.closed.Load() {
		return 0, ErrClosed
	}
	if s.opts.ReadOnly {
		return 0, ErrReadOnly
	}

	s.mu.RLock()
	var victims []entry
	for _, e := range s.idx {
		if e.SetID == setID {
			victims = append(victims, e)
		}
	}
	s.mu.RUnlock()

	removed := 0
	for _, e := range victims {
		if err := ctx.Err(); err != nil {
			return removed, err
		}
		lock := s.stripe(e.ID)
		lock.Lock()
		if _, ok := s.lookup(e.ID); ok {
			if err := os.Remove(s.pathFor(e.ID)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				lock.Unlock()
				return removed, fmt.Errorf("store: delete %s: %w", e.ID, err)
			}
			if err := s.removeEntry(e); err != nil {
				lock.Unlock()
				return removed, err
			}
			removed++
		}
		lock.Unlock()
	}
	return removed, nil
}

// Inventory returns one page of shards ordered by shard id. after is the last
// shard id of the previous page ("" starts at the beginning); next is the
// cursor for the following page, "" when the page is the last.
func (s *Store) Inventory(ctx context.Context, after string, limit int) ([]contract.ShardInfo, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	if limit <= 0 {
		limit = 1000
	}
	if limit > 10000 {
		limit = 10000
	}

	keys := s.sortedKeys()
	start := sort.Search(len(keys), func(i int) bool { return keys[i] > after })

	s.mu.RLock()
	out := make([]contract.ShardInfo, 0, min(limit, len(keys)-start))
	i := start
	for ; i < len(keys) && len(out) < limit; i++ {
		e, ok := s.idx[keys[i]]
		if !ok {
			continue
		}
		out = append(out, e.shardInfo())
	}
	s.mu.RUnlock()

	next := ""
	if i < len(keys) && len(out) == limit {
		next = keys[i-1]
	}
	return out, next, nil
}

// sortedKeys returns a sorted snapshot of indexed shard ids, rebuilding the
// cache when the index changed.
func (s *Store) sortedKeys() []string {
	s.mu.RLock()
	if !s.sortedDirty && s.sorted != nil {
		keys := s.sorted
		s.mu.RUnlock()
		return keys
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sortedDirty || s.sorted == nil {
		keys := make([]string, 0, len(s.idx))
		for id := range s.idx {
			keys = append(keys, id)
		}
		sort.Strings(keys)
		s.sorted = keys
		s.sortedDirty = false
	}
	return s.sorted
}

// Verify re-reads one shard end to end and validates its checksum, quarantining
// it on mismatch. It returns the shard metadata on success.
func (s *Store) Verify(ctx context.Context, setID contract.ShardSetID, geoGroup, localIndex int) (contract.ShardInfo, error) {
	if err := ctx.Err(); err != nil {
		return contract.ShardInfo{}, err
	}
	id := shard.ID(setID, geoGroup, localIndex)
	e, ok := s.lookup(id)
	if !ok {
		return contract.ShardInfo{}, fmt.Errorf("store: verify: %w", contract.ErrNotFound)
	}
	f, err := os.Open(s.pathFor(id))
	if err != nil {
		return contract.ShardInfo{}, fmt.Errorf("store: open %s: %w", id, err)
	}
	defer f.Close()
	hdr, hdrLen, err := readHeaderAt(f)
	if err != nil {
		if qErr := s.quarantine(e, err); qErr != nil {
			s.log.Warn("quarantine failed", "shard_id", id, "err", qErr)
		}
		return contract.ShardInfo{}, fmt.Errorf("store: verify %s: %w: %w", id, ErrCorrupt, err)
	}
	hasher := shard.NewHasher()
	if _, err := io.Copy(hasher, io.NewSectionReader(f, int64(hdrLen), hdr.PayloadLen)); err != nil {
		return contract.ShardInfo{}, fmt.Errorf("store: read %s: %w", id, err)
	}
	if hasher.Sum256() != hdr.Checksum {
		verr := fmt.Errorf("%w: payload digest != header checksum", ErrCorrupt)
		if qErr := s.quarantine(e, verr); qErr != nil {
			s.log.Warn("quarantine failed", "shard_id", id, "err", qErr)
		}
		return contract.ShardInfo{}, fmt.Errorf("store: verify %s: %w", id, verr)
	}
	return e.shardInfo(), nil
}

// quarantine moves a corrupt shard out of the serving set and reports it.
func (s *Store) quarantine(e entry, cause error) error {
	lock := s.stripe(e.ID)
	lock.Lock()
	defer lock.Unlock()

	if _, ok := s.lookup(e.ID); !ok {
		return nil
	}
	src := s.pathFor(e.ID)
	dst := filepath.Join(s.quarantineDir, e.ID+".shard")
	if err := os.Rename(src, dst); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("store: quarantine %s: %w", e.ID, err)
	}
	if err := fsyncDir(s.quarantineDir); err != nil {
		return err
	}
	if err := s.removeEntry(e); err != nil {
		return err
	}
	s.log.Error("shard quarantined", "shard_id", e.ID, "set_id", e.SetID,
		"geo_group", e.GeoGroup, "local_index", e.LocalIndex, "reason", cause)
	if s.opts.OnCorrupt != nil {
		s.opts.OnCorrupt(contract.ShardStatus{
			ShardSetID: e.SetID,
			Slot:       e.slot(),
			State:      "CORRUPT",
		})
	}
	return nil
}

// DestroyShard removes one shard file and its index entry (maintenance path;
// normal deletion is set-scoped via DeleteSet).
func (s *Store) DestroyShard(ctx context.Context, setID contract.ShardSetID, geoGroup, localIndex int) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if s.opts.ReadOnly {
		return false, ErrReadOnly
	}
	id := shard.ID(setID, geoGroup, localIndex)
	lock := s.stripe(id)
	lock.Lock()
	defer lock.Unlock()
	e, ok := s.lookup(id)
	if !ok {
		return false, nil
	}
	if err := os.Remove(s.pathFor(id)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("store: destroy %s: %w", id, err)
	}
	if err := s.removeEntry(e); err != nil {
		return false, err
	}
	return true, nil
}

// Stats reports capacity and counters for /v1/stats and heartbeats.
func (s *Store) Stats() Stats {
	total, rawFree, reserved, free, err := s.capacity()
	if err != nil {
		s.log.Warn("stats capacity unavailable", "err", err)
	}
	s.mu.RLock()
	sets := len(s.setCounts)
	s.mu.RUnlock()
	return Stats{
		DiskID:        s.state.DiskID,
		FormatVersion: s.state.FormatVersion,
		ShardCount:    int64(len(s.sortedKeys())),
		SetCount:      int64(sets),
		UsedBytes:     s.usedBytes.Load(),
		PayloadBytes:  s.payloadBytes.Load(),
		TotalBytes:    total,
		RawFreeBytes:  rawFree,
		ReservedBytes: reserved,
		FreeBytes:     free,
	}
}

// Walk iterates the inventory in pages until fn returns an error or the cursor
// is exhausted. It is used by the scrubber and by boot-time audits.
func (s *Store) Walk(ctx context.Context, pageSize int, fn func(contract.ShardInfo) error) error {
	cursor := ""
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		page, next, err := s.Inventory(ctx, cursor, pageSize)
		if err != nil {
			return err
		}
		for _, info := range page {
			if err := fn(info); err != nil {
				return err
			}
		}
		if next == "" || len(page) == 0 {
			return nil
		}
		cursor = next
	}
}

// contextReader aborts a body read when the request context is cancelled.
type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *contextReader) Read(p []byte) (int, error) {
	select {
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	default:
	}
	return c.r.Read(p)
}

// binaryBigEndianUint64 decodes the FASS checksum convention
// (BigEndian(SHA-256(payload)[0:8])).
func binaryBigEndianUint64(b []byte) uint64 {
	if len(b) < 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b[:8])
}

// fsyncDir makes directory entries durable.
func fsyncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("store: open dir %s for fsync: %w", dir, err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("store: fsync dir %s: %w", dir, err)
	}
	return nil
}

// ParseChecksum parses the decimal uint64 X-Fass-Checksum header value.
func ParseChecksum(s string) (uint64, error) {
	v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("store: parse checksum %q: %w", s, err)
	}
	return v, nil
}
