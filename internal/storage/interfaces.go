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

// Writer is a read/write transaction: reads observe the transaction's own staged
// writes (read-your-writes), and nothing is durable until Update returns nil.
type Writer interface {
	Reader
	Put(space, key, val []byte) error
	Delete(space, key []byte) error
}
