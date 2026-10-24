package storage

import "context"

// Store is the persistence boundary the coordinator services are written
// against. The embedded engine (*DB) and the PostgreSQL adapter both implement
// it; callers never depend on the backend.
//
// One View is one consistent read snapshot; one Update is one atomic commit. That
// transaction contract is what makes the manifest commit the single act that
// publishes an object (docs/02 §5.1): either every record the callback wrote is
// durable, or none of it is.
type Store interface {
	View(ctx context.Context, fn func(Reader) error) error
	Update(ctx context.Context, fn func(Writer) error) error
	Close() error
}

// Reader is the ordered key-value read surface shared by View and Update
// transactions.
type Reader interface {
	Get(space, key []byte) ([]byte, error)
	Has(space, key []byte) bool
	Scan(space, prefix []byte, fn func(key, value []byte) error) error
	Count(space, prefix []byte) (int, error)
}

// LimitedScanner is an optional capability of read transactions: visit at most
// limit keys of the prefix range. Implementations must visit keys in the same
// ascending order as Scan. Callers that need pagination-correct results ask for
// one more key than the page bound and fall back to Scan when the bound is hit
// (a marker may need to skip an unbounded number of rows).
type LimitedScanner interface {
	ScanLimited(space, prefix []byte, limit int, fn func(key, value []byte) error) error
}

// Writer is a read/write transaction: reads observe the transaction's own staged
// writes (read-your-writes), and nothing is durable until Update returns nil.
type Writer interface {
	Reader
	Put(space, key, val []byte) error
	Delete(space, key []byte) error
	// GetShared reads inside a write transaction with a shared row lock: other
	// shared readers proceed concurrently, while an exclusive writer (bucket
	// deletion) is blocked until this transaction ends. That preserves
	// read-vs-delete safety without serialising all commits on a shared row.
	GetShared(space, key []byte) ([]byte, error)
	// GetUnlocked reads without taking any row lock. Use only where a unique
	// constraint (or an outer retry) arbitrates concurrent writers.
	GetUnlocked(space, key []byte) ([]byte, error)
	// NextSequence allocates the next value of a named monotonic sequence inside
	// the transaction. Backends may implement it with a lock-free native sequence;
	// callers must not assume contiguous values, only that allocations are
	// monotonic within a key's serialization scope.
	NextSequence(name string) (uint64, error)
}
