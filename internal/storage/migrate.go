package storage

import (
	"context"
	"fmt"
	"strconv"

)

// SchemaVersion is the logical schema version of the coordinator metadata store.
//
// The number is shared by both backends:
//   - PostgreSQL applies the DDL in docs/schema.sql (production);
//   - the embedded engine records it in the meta space and runs the migration
//     functions below, which backfill keys added by a release.
//
// A store written by a newer version is refused rather than silently
// misinterpreted.
const SchemaVersion = 1

var metaSpace = []byte("meta")

var (
	schemaVersionKey = []byte("schema_version")
)

// Migrate brings the store up to SchemaVersion. It is idempotent and safe to run
// on every boot, before any other component touches the store.
func Migrate(ctx context.Context, db *DB) error {
	if db == nil {
		return fmt.Errorf("storage: nil db")
	}
	var current int
	err := db.View(ctx, func(tx *ReadTx) error {
		raw, err := tx.Get(metaSpace, schemaVersionKey)
		if err == ErrNotFound {
			return nil
		}
		if err != nil {
			return err
		}
		current, err = strconv.Atoi(string(raw))
		return err
	})
	if err != nil {
		return fmt.Errorf("storage: read schema version: %w", err)
	}
	if current > SchemaVersion {
		return fmt.Errorf("storage: data dir schema version %d is newer than this binary (%d): upgrade the coordinator", current, SchemaVersion)
	}
	for v := current + 1; v <= SchemaVersion; v++ {
		migrate, ok := migrations[v]
		if !ok {
			return fmt.Errorf("storage: no migration for schema version %d", v)
		}
		if err := db.Update(ctx, func(tx *WriteTx) error {
			if err := migrate(ctx, tx); err != nil {
				return err
			}
			return tx.Put(metaSpace, schemaVersionKey, []byte(strconv.Itoa(v)))
		}); err != nil {
			return fmt.Errorf("storage: migrate to v%d: %w", v, err)
		}
	}
	return nil
}

// SchemaVersionOf returns the schema version recorded in the store (0 if the
// store has never been migrated).
func SchemaVersionOf(ctx context.Context, db *DB) (int, error) {
	var v int
	err := db.View(ctx, func(tx *ReadTx) error {
		raw, err := tx.Get(metaSpace, schemaVersionKey)
		if err == ErrNotFound {
			return nil
		}
		if err != nil {
			return err
		}
		v, err = strconv.Atoi(string(raw))
		return err
	})
	return v, err
}

// migrations is keyed by the version it produces.
//
// v1 is the initial layout: the relational tables live in docs/schema.sql; the
// embedded engine's key spaces are documented there too and are created
// lazily, so v1 has no work beyond recording the version.
var migrations = map[int]func(context.Context, *WriteTx) error{
	1: func(ctx context.Context, tx *WriteTx) error { return nil },
}
