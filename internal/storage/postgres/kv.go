package postgres

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/fass-storage/fass/internal/storage"
)

// blobSpace is the one storage space routed to the blobs table. Manifest blobs
// are compressed binary pages; putting them through jsonb would TOAST a 1 MiB
// object for no reason, and immutability means they never bloat the row table.
const blobSpace = "manifest_blobs"

// bytesKey is the JSON wrapper used for the few binary records the coordinator
// stores (counters and similar). JSONB is the value column for parseable
// records; this escape keeps raw bytes lossless without a second table.
const bytesKey = "__fass_bytes_base64__"

// KV implements storage.Store on top of PostgreSQL using the two-table layout
// documented in docs/schema.sql (kv + blobs).
type KV struct {
	db *DB
}

// OpenKV connects, verifies the schema is present (never migrates implicitly) and
// returns a store. A missing schema fails here with an actionable message, not on
// the first gateway request.
func OpenKV(ctx context.Context, cfg Config) (*KV, error) {
	db, err := Open(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := db.Verify(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &KV{db: db}, nil
}

// NewKV wraps an already-open pooled connection.
func NewKV(db *DB) *KV { return &KV{db: db} }

// DB exposes the pooled connection (migrations, health checks, tests).
func (k *KV) DB() *DB { return k.db }

// Close closes the pool.
func (k *KV) Close() error { return k.db.Close() }

// View runs fn in a read-only, repeatable-read transaction.
func (k *KV) View(ctx context.Context, fn func(storage.Reader) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tx, err := k.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return fmt.Errorf("postgres: begin read tx: %w", err)
	}
	defer tx.Rollback()
	if err := fn(&txRead{ctx: ctx, tx: tx}); err != nil {
		return err
	}
	return tx.Rollback()
}

// Update runs fn in one transaction and commits it atomically. Serialization
// failures and deadlocks are retried a bounded number of times (the callback is a
// pure transaction body, so re-running it from scratch is safe); every other
// error is surfaced to the caller.
func (k *KV) Update(ctx context.Context, fn func(storage.Writer) error) error {
	const attempts = 3
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := k.db.InTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
			w := &txWrite{ctx: ctx, tx: tx, overlay: make(map[string]mutation)}
			if err := fn(w); err != nil {
				return err
			}
			return w.flush()
		})
		if err == nil {
			return nil
		}
		lastErr = err
		if !retryable(err) {
			return err
		}
		time.Sleep(time.Duration(attempt+1) * 10 * time.Millisecond)
	}
	return fmt.Errorf("postgres: transaction retries exhausted: %w", lastErr)
}

// retryable reports PostgreSQL serialization failure / deadlock.
func retryable(err error) bool {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		switch pg.Code {
		case "40001", "40P01":
			return true
		}
	}
	return false
}

type mutation struct {
	space []byte
	key   []byte
	val   []byte
	del   bool
	blob  bool
}

func overlayKey(space, key []byte) string {
	return string(space) + "\x00" + string(key)
}

// txRead is the read-only transaction implementation.
type txRead struct {
	ctx context.Context
	tx  *sql.Tx
}

func (t *txRead) Get(space, key []byte) ([]byte, error) {
	return getValue(t.ctx, t.tx, space, key, false)
}

func (t *txRead) Has(space, key []byte) bool {
	_, err := t.Get(space, key)
	return err == nil
}

func (t *txRead) Scan(space, prefix []byte, fn func(key, value []byte) error) error {
	return scanValues(t.ctx, t.tx, space, prefix, nil, fn)
}

func (t *txRead) Count(space, prefix []byte) (int, error) {
	return countValues(t.ctx, t.tx, space, prefix, nil)
}

// txWrite is the read/write transaction implementation. Reads observe the
// transaction's own staged writes; row locks are taken with SELECT ... FOR UPDATE
// in the order the callback reads them (the commit path is documented as reading
// bucket → latest → version index in that order).
type txWrite struct {
	ctx     context.Context
	tx      *sql.Tx
	overlay map[string]mutation
	muts    []mutation
}

func (t *txWrite) Get(space, key []byte) ([]byte, error) {
	if m, ok := t.overlay[overlayKey(space, key)]; ok {
		if m.del {
			return nil, storage.ErrNotFound
		}
		return append([]byte(nil), m.val...), nil
	}
	return getValue(t.ctx, t.tx, space, key, true)
}

func (t *txWrite) Has(space, key []byte) bool {
	_, err := t.Get(space, key)
	return err == nil
}

func (t *txWrite) Scan(space, prefix []byte, fn func(key, value []byte) error) error {
	return scanValues(t.ctx, t.tx, space, prefix, t.overlay, fn)
}

func (t *txWrite) Count(space, prefix []byte) (int, error) {
	return countValues(t.ctx, t.tx, space, prefix, t.overlay)
}

func (t *txWrite) Put(space, key, val []byte) error {
	if len(space) == 0 {
		return fmt.Errorf("storage: empty space name")
	}
	if strings.IndexByte(string(space), 0) >= 0 {
		return fmt.Errorf("storage: space name contains NUL")
	}
	m := mutation{
		space: append([]byte(nil), space...),
		key:   append([]byte(nil), key...),
		val:   append([]byte(nil), val...),
	}
	if string(space) == blobSpace {
		m.blob = true
	}
	t.overlay[overlayKey(space, key)] = m
	t.muts = append(t.muts, m)
	return nil
}

func (t *txWrite) Delete(space, key []byte) error {
	if len(space) == 0 {
		return fmt.Errorf("storage: empty space name")
	}
	m := mutation{space: append([]byte(nil), space...), key: append([]byte(nil), key...), del: true, blob: string(space) == blobSpace}
	t.overlay[overlayKey(space, key)] = m
	t.muts = append(t.muts, m)
	return nil
}

// flush applies staged mutations in program order inside the transaction.
func (t *txWrite) flush() error {
	for _, m := range t.muts {
		if m.blob {
			if err := applyBlob(t.ctx, t.tx, m); err != nil {
				return err
			}
			continue
		}
		if m.del {
			if _, err := t.tx.ExecContext(t.ctx,
				"DELETE FROM kv WHERE space = $1 AND key = $2", string(m.space), m.key); err != nil {
				return fmt.Errorf("postgres: delete %s/%q: %w", m.space, m.key, err)
			}
			continue
		}
		encoded, err := encodeValue(m.val)
		if err != nil {
			return fmt.Errorf("postgres: encode %s/%q: %w", m.space, m.key, err)
		}
		if _, err := t.tx.ExecContext(t.ctx,
			`INSERT INTO kv (space, key, value) VALUES ($1,$2,$3::jsonb)
			 ON CONFLICT (space, key) DO UPDATE SET value = EXCLUDED.value`,
			string(m.space), m.key, encoded); err != nil {
			return fmt.Errorf("postgres: put %s/%q: %w", m.space, m.key, err)
		}
	}
	return nil
}

// encodeValue stores JSON records verbatim; binary values are base64-wrapped.
func encodeValue(raw []byte) ([]byte, error) {
	if json.Valid(raw) {
		return raw, nil
	}
	wrapped, err := json.Marshal(map[string]string{bytesKey: base64.StdEncoding.EncodeToString(raw)})
	if err != nil {
		return nil, err
	}
	return wrapped, nil
}

func decodeValue(raw []byte) ([]byte, error) {
	// The wrapper is only produced for non-JSON payloads; a JSON document that
	// happens to contain exactly this key is not a record shape we write.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err == nil {
		if b64, ok := probe[bytesKey]; ok && len(probe) == 1 {
			var s string
			if err := json.Unmarshal(b64, &s); err == nil {
				return base64.StdEncoding.DecodeString(s)
			}
		}
	}
	return raw, nil
}

func getValue(ctx context.Context, tx *sql.Tx, space, key []byte, forUpdate bool) ([]byte, error) {
	if string(space) == blobSpace {
		return getBlob(ctx, tx, key)
	}
	q := "SELECT value FROM kv WHERE space = $1 AND key = $2"
	if forUpdate {
		q += " FOR UPDATE"
	}
	var raw []byte
	err := tx.QueryRowContext(ctx, q, string(space), key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: get %s/%q: %w", space, key, err)
	}
	return decodeValue(raw)
}

// rangeBounds returns the half-open key range for a prefix.
func rangeBounds(prefix []byte) (end []byte, bounded bool) {
	if len(prefix) == 0 {
		return nil, false
	}
	end = append([]byte(nil), prefix...)
	for i := len(end) - 1; i >= 0; i-- {
		if end[i] != 0xFF {
			end[i]++
			return end[:i+1], true
		}
	}
	return nil, false
}

func scanValues(ctx context.Context, tx *sql.Tx, space, prefix []byte, overlay map[string]mutation, fn func(key, value []byte) error) error {
	if string(space) == blobSpace {
		return scanBlobs(ctx, tx, prefix, overlay, fn)
	}
	q := "SELECT key, value FROM kv WHERE space = $1"
	args := []any{string(space)}
	if len(prefix) > 0 {
		q += " AND key >= $2"
		args = append(args, prefix)
		if end, bounded := rangeBounds(prefix); bounded {
			q += " AND key < $3"
			args = append(args, end)
		}
	}
	q += " ORDER BY key"
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return fmt.Errorf("postgres: scan %s: %w", space, err)
	}
	defer rows.Close()

	merged := make(map[string][]byte)
	for rows.Next() {
		var k, raw []byte
		if err := rows.Scan(&k, &raw); err != nil {
			return err
		}
		merged[string(k)] = raw
	}
	if err := rows.Err(); err != nil {
		return err
	}
	// Apply the transaction's uncommitted writes.
	for a, m := range overlay {
		if string(m.space) != string(space) || m.blob {
			continue
		}
		key := []byte(m.key)
		if len(prefix) > 0 && !hasPrefix(key, prefix) {
			continue
		}
		if m.del {
			delete(merged, string(key))
		} else {
			val, err := encodeValue(m.val)
			if err != nil {
				return err
			}
			merged[string(key)] = val
		}
		_ = a
	}
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		val, err := decodeValue(merged[k])
		if err != nil {
			return err
		}
		if err := fn([]byte(k), val); err != nil {
			if errors.Is(err, storage.ErrStopScan) {
				return nil
			}
			return err
		}
	}
	return nil
}

func countValues(ctx context.Context, tx *sql.Tx, space, prefix []byte, overlay map[string]mutation) (int, error) {
	n := 0
	err := scanValues(ctx, tx, space, prefix, overlay, func(_, _ []byte) error {
		n++
		return nil
	})
	return n, err
}

func hasPrefix(b, prefix []byte) bool {
	return len(b) >= len(prefix) && string(b[:len(prefix)]) == string(prefix)
}

// ---------------------------------------------------------------------------
// Content-addressed manifest blobs
// ---------------------------------------------------------------------------

func blobKey(key []byte) ([]byte, error) {
	raw, err := hex.DecodeString(string(key))
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("postgres: blob key %q is not a SHA-256 hex digest", key)
	}
	return raw, nil
}

func applyBlob(ctx context.Context, tx *sql.Tx, m mutation) error {
	hash, err := blobKey(m.key)
	if err != nil {
		return err
	}
	if m.del {
		if _, err := tx.ExecContext(ctx, "DELETE FROM blobs WHERE hash = $1", hash); err != nil {
			return fmt.Errorf("postgres: delete blob: %w", err)
		}
		return nil
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO blobs (hash, data) VALUES ($1,$2)
		 ON CONFLICT (hash) DO NOTHING`, hash, m.val); err != nil {
		return fmt.Errorf("postgres: put blob: %w", err)
	}
	return nil
}

func getBlob(ctx context.Context, tx *sql.Tx, key []byte) ([]byte, error) {
	hash, err := blobKey(key)
	if err != nil {
		return nil, err
	}
	var data []byte
	err = tx.QueryRowContext(ctx, "SELECT data FROM blobs WHERE hash = $1", hash).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: get blob: %w", err)
	}
	return data, nil
}

func scanBlobs(ctx context.Context, tx *sql.Tx, prefix []byte, overlay map[string]mutation, fn func(key, value []byte) error) error {
	hexPrefix := string(prefix)
	// Blob keys are ASCII hex digests. A half-byte prefix cannot be expressed as
	// a bytea range; decode the even part and filter the nibble in Go so the
	// query stays a bounded index range rather than a full table scan.
	lowerHex := hexPrefix
	oddNibble := ""
	if len(lowerHex)%2 == 1 {
		oddNibble = lowerHex[len(lowerHex)-1:]
		lowerHex = lowerHex[:len(lowerHex)-1]
	}
	var lower []byte
	if lowerHex != "" {
		decoded, err := hex.DecodeString(lowerHex)
		if err != nil {
			return fmt.Errorf("postgres: blob prefix %q is not hex", prefix)
		}
		lower = decoded
	}
	q := "SELECT hash, data FROM blobs"
	var args []any
	useRange := len(lower) > 0
	if useRange {
		q += " WHERE hash >= $1"
		args = append(args, lower)
		if end, bounded := rangeBounds(lower); bounded {
			q += " AND hash < $2"
			args = append(args, end)
		}
	}
	q += " ORDER BY hash"
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return fmt.Errorf("postgres: scan blobs: %w", err)
	}
	defer rows.Close()
	merged := make(map[string][]byte)
	for rows.Next() {
		var hash, data []byte
		if err := rows.Scan(&hash, &data); err != nil {
			return err
		}
		k := hex.EncodeToString(hash)
		if oddNibble != "" && !strings.HasPrefix(k, lowerHex+oddNibble) {
			continue
		}
		merged[k] = data
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, m := range overlay {
		if !m.blob {
			continue
		}
		k := string(m.key)
		if !strings.HasPrefix(k, hexPrefix) {
			continue
		}
		if m.del {
			delete(merged, k)
		} else {
			merged[k] = m.val
		}
	}
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !strings.HasPrefix(k, hexPrefix) {
			continue
		}
		if err := fn([]byte(k), merged[k]); err != nil {
			if errors.Is(err, storage.ErrStopScan) {
				return nil
			}
			return err
		}
	}
	return nil
}
