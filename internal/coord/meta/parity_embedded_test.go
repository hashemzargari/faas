package meta_test

import (
	"context"
	"testing"

	"github.com/fass-storage/fass/internal/coord/meta/parity"
	"github.com/fass-storage/fass/internal/storage"
)

// TestEmbeddedParity runs the backend-neutral suite against the embedded store.
// The same suite runs against PostgreSQL in internal/storage/postgres, which is
// how "the two backends behave identically" is enforced rather than assumed.
func TestEmbeddedParity(t *testing.T) {
	ctx := context.Background()
	db, err := storage.Open("")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	parity.Run(t, db)
}
