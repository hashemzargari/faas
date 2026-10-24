// Command fass-coordinator runs the FASS control plane: metadata, membership and
// health, authorisation, placement, and the internal HTTP/JSON API in
// docs/07-wire-api.md §1.
//
// Dev mode uses the embedded WAL store (--data-dir); production points the same
// repository interfaces at PostgreSQL (docs/schema.sql).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fass-storage/fass/internal/agent/client"
	"github.com/fass-storage/fass/internal/coord"
	"github.com/fass-storage/fass/internal/coord/api"
	"github.com/fass-storage/fass/internal/coord/bootstrap"
	"github.com/fass-storage/fass/internal/coord/gc"
	"github.com/fass-storage/fass/internal/coord/lifecycle"
	"github.com/fass-storage/fass/internal/coord/membership"
	"github.com/fass-storage/fass/internal/coord/placement"
	"github.com/fass-storage/fass/internal/coord/recovery"
	"github.com/fass-storage/fass/internal/storage"
	"github.com/fass-storage/fass/internal/storage/postgres"
)

// openStore opens the configured persistence backend. Embedded remains the dev
// default; PostgreSQL requires an explicit DSN and never migrates implicitly
// unless --db-migrate-on-start=true is set (production should run the migrate
// subcommand instead: a process restart must not mutate a schema).
func openStore(ctx context.Context, cfg config) (storage.Store, error) {
	switch cfg.dbDriver {
	case "", "embedded":
		db, err := storage.Open(cfg.dataDir)
		if err != nil {
			return nil, err
		}
		if err := storage.Migrate(ctx, db); err != nil {
			_ = db.Close()
			return nil, err
		}
		return db, nil
	case "postgres":
		if cfg.dbDSN == "" {
			return nil, fmt.Errorf("--db-driver=postgres requires --db-dsn (or FASS_COORDINATOR_DB_DSN)")
		}
		pgCfg := postgres.Config{
			DSN:             cfg.dbDSN,
			MaxOpenConns:    cfg.dbMaxOpenConns,
			MaxIdleConns:    cfg.dbMaxIdleConns,
			ConnMaxLifetime: cfg.dbConnMaxLife,
			StatementTime:   cfg.dbStmtTimeout,
		}
		if cfg.dbMigrateOnBoot {
			db, err := postgres.Open(ctx, pgCfg)
			if err != nil {
				return nil, err
			}
			if err := db.Migrate(ctx); err != nil {
				_ = db.Close()
				return nil, fmt.Errorf("postgres: apply migrations: %w", err)
			}
			_ = db.Close()
		}
		kv, err := postgres.OpenKV(ctx, pgCfg)
		if err != nil {
			return nil, err
		}
		return kv, nil
	default:
		return nil, fmt.Errorf("unknown --db-driver %q (want embedded or postgres)", cfg.dbDriver)
	}
}

// runMigrate applies PostgreSQL migrations explicitly: `fass-coordinator migrate
// --db-dsn ...`. It is the production path; the server itself defaults to not
// migrating.
func runMigrate(args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	dsn := fs.String("db-dsn", envString("FASS_COORDINATOR_DB_DSN", ""), "PostgreSQL DSN")
	stmtTimeout := fs.Duration("db-statement-timeout", envDuration("FASS_COORDINATOR_DB_STATEMENT_TIMEOUT", 30*time.Second), "statement_timeout for the migration session")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dsn == "" {
		return fmt.Errorf("migrate: --db-dsn (or FASS_COORDINATOR_DB_DSN) is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	db, err := postgres.Open(ctx, postgres.Config{DSN: *dsn, StatementTime: *stmtTimeout})
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	v, err := db.SchemaVersionOf(ctx)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	fmt.Printf("fass-coordinator: schema migrated to version %d\n", v)
	return nil
}

func envString(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// version is stamped by the build ("-X main.version=...").
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "fass-coordinator: %v\n", err)
		os.Exit(1)
	}
}

type config struct {
	listen      string
	dataDir     string
	maintenance bool
	logLevel    string
	logFormat   string
	// deletion GC (docs/03 §6)
	gcEnabled   bool
	gcInterval  time.Duration
	gcBatch     int
	agentScheme string
	// dev bootstrap (docs/07 §1.8) and dev-tunable health timings
	devBootstrap      bool
	heartbeatInterval time.Duration
	suspectAfter      time.Duration
	offlineAfter      time.Duration
	// devClockOffset shifts the coordinator clock. Dev-only and gated behind
	// --dev-bootstrap; it exists so lifecycle expiry can be exercised without
	// waiting days, never as a production backdoor.
	devClockOffset time.Duration
	// lifecycle sweep (docs/05 §5.6)
	lifecycleEnabled  bool
	lifecycleInterval time.Duration
	// repair status (docs/07 §1.6): budget comes from docs/04 defaults, and the
	// shard-set inventory is refreshed in the background so the status endpoint
	// never scans on request.
	repairBudgetMBps      int
	repairRefreshInterval time.Duration
	// Persistence backend: embedded (default, dev) or postgres (production).
	dbDriver        string
	dbDSN           string
	dbMigrateOnBoot bool
	dbMaxOpenConns  int
	dbMaxIdleConns  int
	dbConnMaxLife   time.Duration
	dbStmtTimeout   time.Duration
}

func run(args []string) error {
	if len(args) > 0 && args[0] == "migrate" {
		return runMigrate(args[1:])
	}
	cfg, err := parseConfig(args)
	if err != nil {
		return err
	}
	logger, err := newLogger(cfg.logLevel, cfg.logFormat)
	if err != nil {
		return err
	}
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	now := time.Now
	if cfg.devBootstrap && cfg.devClockOffset != 0 {
		offset := cfg.devClockOffset
		now = func() time.Time { return time.Now().Add(offset) }
		logger.Warn("DEV CLOCK OFFSET ACTIVE: coordinator clock is shifted (dev-bootstrap only)", "offset", offset.String())
	}
	store, err := openStore(ctx, cfg)
	if err != nil {
		return fmt.Errorf("open coordinator store: %w", err)
	}
	svc := coord.NewWithStore(store, true, coord.Config{
		Now:         now,
		Maintenance: cfg.maintenance,
		Membership: membership.Config{
			HeartbeatInterval: cfg.heartbeatInterval,
			SuspectAfter:      cfg.suspectAfter,
			OfflineAfter:      cfg.offlineAfter,
		},
		Placement: placement.DefaultConfig(),
		Logger:    logger,
	})
	defer svc.Close()

	go svc.RunMaintenance(ctx)

	// Dev bootstrap: create/reconcile the deterministic cluster before serving,
	// then emit the one-line payload the agent/gateway tooling consumes.
	if cfg.devBootstrap {
		payload, err := bootstrap.Run(ctx, svc.Meta, svc.Auth, svc.Members, bootstrap.DevConfig(cfg.dataDir))
		if err != nil {
			return fmt.Errorf("dev bootstrap: %w", err)
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("dev bootstrap: encode payload: %w", err)
		}
		fmt.Printf("FASS_DEV_BOOTSTRAP %s\n", raw)
		logger.Info("dev bootstrap ready",
			"swarm", bootstrap.DevSwarmID,
			"rc_id", payload.RCID,
			"ring_id", payload.RingID,
			"bucket", payload.Bucket,
			"agents", len(payload.Agents),
			"access_key_id", payload.AccessKeyID)
	}

	// Deletion GC: drain tombstoned versions' shards once their grace period has
	// elapsed. Agent transport is HTTP in v1 (docs/07 §2).
	server := api.New(svc, logger)
	repairSvc := recovery.New(recovery.Config{
		PerSiteBudgetMBps: cfg.repairBudgetMBps,
		Now:               now,
		Logger:            logger,
	})
	server.SetRepair(repairSvc)
	go repairSvc.RunRefresher(ctx, recovery.NewMetaSource(svc.Meta), cfg.repairRefreshInterval)
	logger.Info("repair status enabled",
		"per_site_budget_mbps", cfg.repairBudgetMBps,
		"shard_set_refresh", cfg.repairRefreshInterval.String())
	if cfg.gcEnabled {
		agentClient := client.New(client.Options{Scheme: cfg.agentScheme, Timeout: 15 * time.Second})
		executor := gc.New(svc.Meta, agentClient, gc.Config{
			Interval: cfg.gcInterval,
			Batch:    cfg.gcBatch,
			Logger:   logger,
		})
		go executor.Run(ctx)
		server.SetGCStats(executor.Stats)
		logger.Info("deletion GC enabled", "interval", cfg.gcInterval.String(), "batch", cfg.gcBatch)
	} else {
		logger.Warn("deletion GC disabled: tombstoned shards will accumulate")
	}
	// Lifecycle expiry sweep (docs/05 §5.6): metadata-first, retention-aware.
	if cfg.lifecycleEnabled {
		lifecycleExec := lifecycle.New(svc.Meta, lifecycle.Config{
			Interval: cfg.lifecycleInterval,
			Now:      now,
			Logger:   logger,
		})
		go lifecycleExec.Run(ctx)
		logger.Info("lifecycle sweep enabled", "interval", cfg.lifecycleInterval.String())
	}
	handler := server.Handler()
	httpSrv := &http.Server{
		Addr:              cfg.listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	ln, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.listen, err)
	}
	logger.Info("coordinator listening",
		"addr", ln.Addr().String(),
		"data_dir", displayDataDir(cfg.dataDir),
		"maintenance", cfg.maintenance,
		"version", version,
	)

	serveErr := make(chan error, 1)
	go func() {
		if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	select {
	case err := <-serveErr:
		if err != nil {
			return fmt.Errorf("serve: %w", err)
		}
		return nil
	case <-ctx.Done():
		logger.Info("shutting down coordinator")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	return nil
}

func parseConfig(args []string) (config, error) {
	fs := flag.NewFlagSet("fass-coordinator", flag.ContinueOnError)
	cfg := config{}
	fs.StringVar(&cfg.listen, "listen", envOr("FASS_COORDINATOR_LISTEN", ":7000"), "HTTP listen address (docs/07 §1)")
	fs.StringVar(&cfg.dataDir, "data-dir", envOr("FASS_COORDINATOR_DATA_DIR", "data/coordinator"), "embedded store directory (empty = in-memory)")
	fs.BoolVar(&cfg.maintenance, "maintenance", envBool("FASS_COORDINATOR_MAINTENANCE"), "reject agent announce with 503 under maintenance")
	fs.StringVar(&cfg.logLevel, "log-level", envOr("FASS_COORDINATOR_LOG_LEVEL", "info"), "debug|info|warn|error")
	fs.StringVar(&cfg.logFormat, "log-format", envOr("FASS_COORDINATOR_LOG_FORMAT", "json"), "json|text")
	fs.BoolVar(&cfg.gcEnabled, "gc", envBoolDefault("FASS_COORDINATOR_GC", true), "run the deletion-queue shard GC")
	fs.DurationVar(&cfg.gcInterval, "gc-interval", envDuration("FASS_COORDINATOR_GC_INTERVAL", gc.DefaultInterval), "deletion GC pass interval")
	fs.IntVar(&cfg.gcBatch, "gc-batch", envInt("FASS_COORDINATOR_GC_BATCH", gc.DefaultBatch), "max deletion entries per GC pass")
	fs.StringVar(&cfg.agentScheme, "agent-scheme", envOr("FASS_COORDINATOR_AGENT_SCHEME", "http"), "scheme for agent shard endpoints (http in dev, https in prod)")
	fs.BoolVar(&cfg.devBootstrap, "dev-bootstrap", envBoolDefault("FASS_COORDINATOR_DEV_BOOTSTRAP", false), "create/reconcile the deterministic dev cluster and print FASS_DEV_BOOTSTRAP <json>")
	fs.DurationVar(&cfg.heartbeatInterval, "heartbeat-interval", envDuration("FASS_COORDINATOR_HEARTBEAT_INTERVAL", membership.DefaultHeartbeatInterval), "expected agent heartbeat interval")
	fs.DurationVar(&cfg.suspectAfter, "suspect-after", envDuration("FASS_COORDINATOR_SUSPECT_AFTER", membership.DefaultSuspectAfter), "mark an agent SUSPECT after this much silence")
	fs.DurationVar(&cfg.offlineAfter, "offline-after", envDuration("FASS_COORDINATOR_OFFLINE_AFTER", membership.DefaultOfflineAfter), "mark an agent OFFLINE after this much silence")
	fs.BoolVar(&cfg.lifecycleEnabled, "lifecycle", envBoolDefault("FASS_COORDINATOR_LIFECYCLE", true), "run the S3 lifecycle expiry sweep")
	fs.DurationVar(&cfg.lifecycleInterval, "lifecycle-interval", envDuration("FASS_COORDINATOR_LIFECYCLE_INTERVAL", lifecycle.DefaultInterval), "lifecycle sweep interval")
	fs.DurationVar(&cfg.devClockOffset, "dev-clock-offset", envDuration("FASS_COORDINATOR_DEV_CLOCK_OFFSET", 0), "DEV ONLY (requires --dev-bootstrap): shift the coordinator clock by this duration; used by the compat suite to test lifecycle without waiting days")
	fs.StringVar(&cfg.dbDriver, "db-driver", envString("FASS_COORDINATOR_DB_DRIVER", "embedded"), "persistence backend: embedded (dev WAL store) or postgres")
	fs.StringVar(&cfg.dbDSN, "db-dsn", envString("FASS_COORDINATOR_DB_DSN", ""), "PostgreSQL DSN (required for --db-driver=postgres); a bad DSN fails at startup, never at the first request")
	fs.BoolVar(&cfg.dbMigrateOnBoot, "db-migrate-on-start", envBoolDefault("FASS_COORDINATOR_DB_MIGRATE_ON_START", false), "apply PostgreSQL migrations at startup (default false: production must run the migrate subcommand explicitly)")
	fs.IntVar(&cfg.dbMaxOpenConns, "db-max-open-conns", envInt("FASS_COORDINATOR_DB_MAX_OPEN_CONNS", 40), "PostgreSQL connection pool: maximum open connections")
	fs.IntVar(&cfg.dbMaxIdleConns, "db-max-idle-conns", envInt("FASS_COORDINATOR_DB_MAX_IDLE_CONNS", 10), "PostgreSQL connection pool: maximum idle connections")
	fs.DurationVar(&cfg.dbConnMaxLife, "db-conn-max-lifetime", envDuration("FASS_COORDINATOR_DB_CONN_MAX_LIFETIME", 30*time.Minute), "PostgreSQL connection maximum lifetime")
	fs.DurationVar(&cfg.dbStmtTimeout, "db-statement-timeout", envDuration("FASS_COORDINATOR_DB_STATEMENT_TIMEOUT", 5*time.Second), "PostgreSQL statement_timeout for every pooled connection")
	fs.IntVar(&cfg.repairBudgetMBps, "repair-per-site-budget-mbps", envInt("FASS_COORDINATOR_REPAIR_BUDGET_MBPS", 200), "inter-site repair bandwidth budget reported by /v1/repair/status (0 = not configured, reported as null)")
	fs.DurationVar(&cfg.repairRefreshInterval, "repair-refresh-interval", envDuration("FASS_COORDINATOR_REPAIR_REFRESH_INTERVAL", time.Minute), "how often the background refresher rebuilds the shard-set redundancy inventory")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if cfg.listen == "" {
		return cfg, fmt.Errorf("--listen must not be empty")
	}
	return cfg, nil
}

func newLogger(level, format string) (*slog.Logger, error) {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "info", "":
		lv = slog.LevelInfo
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		return nil, fmt.Errorf("invalid log level %q", level)
	}
	opts := &slog.HandlerOptions{Level: lv}
	var h slog.Handler
	switch strings.ToLower(format) {
	case "text", "":
		h = slog.NewTextHandler(os.Stderr, opts)
	case "json":
		h = slog.NewJSONHandler(os.Stderr, opts)
	default:
		return nil, fmt.Errorf("invalid log format %q", format)
	}
	return slog.New(h).With("service", "fass-coordinator", "version", version), nil
}

func displayDataDir(dir string) string {
	if dir == "" {
		return "(memory)"
	}
	return dir
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func envBool(key string) bool {
	switch strings.ToLower(os.Getenv(key)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func envBoolDefault(key string, def bool) bool {
	if _, ok := os.LookupEnv(key); !ok {
		return def
	}
	return envBool(key)
}

func envDuration(key string, def time.Duration) time.Duration {
	if raw, ok := os.LookupEnv(key); ok {
		if d, err := time.ParseDuration(raw); err == nil && d > 0 {
			return d
		}
	}
	return def
}

func envInt(key string, def int) int {
	if raw, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			return n
		}
	}
	return def
}
