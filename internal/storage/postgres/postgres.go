// Package postgres is the production implementation of the FASS metadata
// repository, backed by PostgreSQL.
//
// The normative schema is docs/schema.sql (the embedded dev store mirrors it;
// see the schema-drift test in internal/coord). This package exists so the
// driver dependency is real and pinned in go.mod/vendor, and so the adapter has
// an obvious home. The repository methods are implemented against the
// interfaces in internal/storage.
//
// Design constraints:
//   - The primary is the single writer; reads that must observe a write go to
//     it. Standby reads are an explicit opt-in, never the default, because
//     "list after put returned the old page" is not acceptable for an object
//     store.
//   - Every metadata mutation is one transaction. The commit protocol depends
//     on it: shards are written first and the manifest commit is the single
//     atomic act that makes an object visible (docs/02 §5.1).
//   - No application-level retry loops around serialization failures here; the
//     caller owns retry policy so it can distinguish a benign conflict
//     (retry) from a real constraint violation (surface).
package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Config describes one PostgreSQL primary.
type Config struct {
	DSN             string        // postgres://user:pass@host/db?sslmode=verify-full
	MaxOpenConns    int           // default 40
	MaxIdleConns    int           // default 10
	ConnMaxLifetime time.Duration // default 30m
	StatementTime   time.Duration // default 5s; protects against a slow query pinning a gateway
}

func (c *Config) withDefaults() {
	if c.MaxOpenConns <= 0 {
		c.MaxOpenConns = 40
	}
	if c.MaxIdleConns <= 0 {
		c.MaxIdleConns = 10
	}
	if c.ConnMaxLifetime <= 0 {
		c.ConnMaxLifetime = 30 * time.Minute
	}
	if c.StatementTime <= 0 {
		c.StatementTime = 5 * time.Second
	}
}

// DB wraps a *sql.DB configured for FASS.
type DB struct {
	*sql.DB
	statementTime time.Duration
}

// Open connects and verifies the connection. It does not migrate: schema
// application is a separate, explicit step so a production deployment never
// mutates its schema as a side effect of a process restart.
func Open(ctx context.Context, cfg Config) (*DB, error) {
	if cfg.DSN == "" {
		return nil, fmt.Errorf("postgres: empty DSN")
	}
	cfg.withDefaults()

	connCfg, err := pgx.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("postgres: parse DSN: %w", err)
	}
	// statement_timeout is a per-session setting: put it in the startup packet so
	// every pooled connection has it, instead of SET-ing one pooled connection.
	if _, ok := connCfg.RuntimeParams["statement_timeout"]; !ok {
		connCfg.RuntimeParams["statement_timeout"] = fmt.Sprintf("%d", cfg.StatementTime.Milliseconds())
	}
	db := stdlib.OpenDB(*connCfg)
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		db.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}
	return &DB{DB: db, statementTime: cfg.StatementTime}, nil
}

// InTx runs fn inside a transaction, rolling back on error or panic.
//
// The distinction that matters for correctness: a returned error rolls back, a
// panic rolls back and re-panics. Never swallow the panic — a half-applied
// metadata write is worse than a crashed request.
func (d *DB) InTx(ctx context.Context, fn func(ctx context.Context, tx *sql.Tx) error) (err error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("postgres: begin: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if err = fn(ctx, tx); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("postgres: commit: %w", err)
	}
	return nil
}
