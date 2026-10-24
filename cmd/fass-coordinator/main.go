// Command fass-coordinator runs the FASS control plane: metadata, membership and
// health, authorisation, placement, and the internal HTTP/JSON API in
// docs/07-wire-api.md §1.
//
// Dev mode uses the embedded WAL store (--data-dir); production points the same
// repository interfaces at PostgreSQL (docs/schema.sql).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fass-storage/fass/internal/coord"
	"github.com/fass-storage/fass/internal/coord/api"
	"github.com/fass-storage/fass/internal/coord/membership"
	"github.com/fass-storage/fass/internal/coord/placement"
)

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
}

func run(args []string) error {
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

	svc, err := coord.Open(ctx, cfg.dataDir, coord.Config{
		Maintenance: cfg.maintenance,
		Membership: membership.Config{
			HeartbeatInterval: membership.DefaultHeartbeatInterval,
			SuspectAfter:      membership.DefaultSuspectAfter,
			OfflineAfter:      membership.DefaultOfflineAfter,
		},
		Placement: placement.DefaultConfig(),
		Logger:    logger,
	})
	if err != nil {
		return fmt.Errorf("open coordinator: %w", err)
	}
	defer svc.Close()

	go svc.RunMaintenance(ctx)

	handler := api.New(svc, logger).Handler()
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
