package postgres

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/fass-storage/fass/internal/storage/postgres/migrations"
)

// SchemaVersion is the PostgreSQL schema version this binary expects. It matches
// storage.SchemaVersion: the embedded and PostgreSQL backends record the same
// logical metadata version.
const SchemaVersion = 1

// migrationFiles is the embedded ordered migration set.
var migrationFiles embed.FS = migrations.FS

// Migrate applies pending migrations. It is idempotent (each file is recorded in
// schema_migrations and never replayed) and takes a transaction-scoped advisory
// lock so two coordinators starting a migration concurrently cannot interleave.
func (d *DB) Migrate(ctx context.Context) error {
	if err := d.ensureMigrationTable(ctx); err != nil {
		return err
	}
	return d.InTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(730451)"); err != nil {
			return fmt.Errorf("postgres: migration lock: %w", err)
		}
		applied, err := appliedVersions(ctx, tx)
		if err != nil {
			return err
		}
		names, err := migrationNames()
		if err != nil {
			return err
		}
		for _, name := range names {
			version, err := parseMigrationVersion(name)
			if err != nil {
				return err
			}
			if applied[version] {
				continue
			}
			body, err := migrationFiles.ReadFile(name)
			if err != nil {
				return fmt.Errorf("postgres: read migration %s: %w", name, err)
			}
			if _, err := tx.ExecContext(ctx, string(body)); err != nil {
				return fmt.Errorf("postgres: apply migration %s: %w", name, err)
			}
			if _, err := tx.ExecContext(ctx,
				"INSERT INTO schema_migrations(version, name) VALUES ($1,$2)", version, name); err != nil {
				return fmt.Errorf("postgres: record migration %s: %w", name, err)
			}
		}
		return nil
	})
}

// SchemaVersionOf returns the highest applied migration version (0 when the
// schema has never been migrated).
func (d *DB) SchemaVersionOf(ctx context.Context) (int, error) {
	var v int
	err := d.QueryRowContext(ctx,
		"SELECT COALESCE(MAX(version),0) FROM schema_migrations").Scan(&v)
	if err != nil {
		return 0, fmt.Errorf("postgres: read schema version (has the migrate command been run?): %w", err)
	}
	return v, nil
}

// Verify reports whether the schema is usable by this binary, with an actionable
// error instead of a first-request failure.
func (d *DB) Verify(ctx context.Context) error {
	v, err := d.SchemaVersionOf(ctx)
	if err != nil {
		return fmt.Errorf("postgres: schema is not initialised: run `fass-coordinator migrate --db-dsn ...`: %w", err)
	}
	if v == 0 {
		return fmt.Errorf("postgres: schema is not initialised: run `fass-coordinator migrate --db-dsn ...`")
	}
	if v > SchemaVersion {
		return fmt.Errorf("postgres: schema version %d is newer than this binary (%d): upgrade the coordinator", v, SchemaVersion)
	}
	if v < SchemaVersion {
		return fmt.Errorf("postgres: schema version %d is older than this binary (%d): run `fass-coordinator migrate`", v, SchemaVersion)
	}
	return nil
}

func (d *DB) ensureMigrationTable(ctx context.Context) error {
	_, err := d.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version int PRIMARY KEY,
		name text NOT NULL,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`)
	if err != nil {
		return fmt.Errorf("postgres: create schema_migrations: %w", err)
	}
	return nil
}

func appliedVersions(ctx context.Context, tx *sql.Tx) (map[int]bool, error) {
	rows, err := tx.QueryContext(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return nil, fmt.Errorf("postgres: list migrations: %w", err)
	}
	defer rows.Close()
	out := make(map[int]bool)
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out[v] = true
	}
	return out, rows.Err()
}

func migrationNames() ([]string, error) {
	entries, err := fs.ReadDir(migrationFiles, ".")
	if err != nil {
		return nil, fmt.Errorf("postgres: list embedded migrations: %w", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

func parseMigrationVersion(name string) (int, error) {
	idx := strings.IndexByte(name, '_')
	if idx <= 0 {
		return 0, fmt.Errorf("postgres: migration %q does not start with a version", name)
	}
	v, err := strconv.Atoi(name[:idx])
	if err != nil {
		return 0, fmt.Errorf("postgres: migration %q has an invalid version: %w", name, err)
	}
	return v, nil
}
