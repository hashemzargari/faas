// Command fass-console is the FASS operator web console.
//
// It is a separate process from the coordinator and gateway: it consumes only
// the coordinator's documented HTTP+JSON API, so it works against a remote
// control plane and cannot couple the UI to internal packages.
//
// Server-rendered Go templates + HTMX, assets in embed.FS, no Node toolchain.
// Read-only by default; the two safe writes (activate/decommission an agent)
// require --read-only=false in addition to Basic auth and a CSRF token.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fass-storage/fass/internal/console"
)

var version = "0.1.0-dev"

type config struct {
	listen      string
	coordinator string
	user        string
	password    string
	readOnly    bool
	httpTimeout time.Duration
	logLevel    string
	logFormat   string
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "fass-console: %v\n", err)
		os.Exit(1)
	}
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

	srv, err := console.New(console.Config{
		CoordinatorURL: cfg.coordinator,
		User:           cfg.user,
		Password:       cfg.password,
		ReadOnly:       cfg.readOnly,
		Version:        version,
		Logger:         logger,
		HTTPClient:     &http.Client{Timeout: cfg.httpTimeout},
	})
	if err != nil {
		return err
	}

	httpSrv := &http.Server{
		Addr:              cfg.listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("console listening",
			"addr", cfg.listen,
			"coordinator", cfg.coordinator,
			"read_only", cfg.readOnly,
			"user", cfg.user,
		)
		if !cfg.readOnly {
			logger.Warn("write actions are ENABLED: activate/decommission are available to anyone with the console password")
		}
		errCh <- httpSrv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func parseConfig(args []string) (config, error) {
	fs := flag.NewFlagSet("fass-console", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	cfg := config{
		listen:      envOr("FASS_CONSOLE_LISTEN", "127.0.0.1:8081"),
		coordinator: envOr("FASS_COORDINATOR_URL", "http://127.0.0.1:7000"),
		user:        envOr("FASS_CONSOLE_USER", "admin"),
		password:    envOr("FASS_CONSOLE_PASSWORD", ""),
		readOnly:    envBoolDefault("FASS_CONSOLE_READ_ONLY", true),
		httpTimeout: 5 * time.Second,
		logLevel:    envOr("FASS_LOG_LEVEL", "info"),
		logFormat:   envOr("FASS_LOG_FORMAT", "text"),
	}
	fs.StringVar(&cfg.listen, "listen", cfg.listen, "HTTP listen address (env FASS_CONSOLE_LISTEN)")
	fs.StringVar(&cfg.coordinator, "coordinator", cfg.coordinator, "coordinator base URL (env FASS_COORDINATOR_URL)")
	fs.StringVar(&cfg.user, "console-user", cfg.user, "HTTP Basic user (env FASS_CONSOLE_USER)")
	fs.StringVar(&cfg.password, "console-password", cfg.password, "HTTP Basic password (env FASS_CONSOLE_PASSWORD, required)")
	fs.BoolVar(&cfg.readOnly, "read-only", cfg.readOnly, "disable the activate/decommission write actions (env FASS_CONSOLE_READ_ONLY)")
	fs.DurationVar(&cfg.httpTimeout, "coordinator-timeout", cfg.httpTimeout, "per-request coordinator timeout")
	fs.StringVar(&cfg.logLevel, "log-level", cfg.logLevel, "debug|info|warn|error")
	fs.StringVar(&cfg.logFormat, "log-format", cfg.logFormat, "json|text")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	if *showVersion {
		fmt.Printf("fass-console %s\n", version)
		os.Exit(0)
	}
	if fs.NArg() > 0 {
		return config{}, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if cfg.listen == "" {
		return config{}, errors.New("--listen must not be empty")
	}
	if cfg.password == "" {
		return config{}, errors.New("--console-password is required (or set FASS_CONSOLE_PASSWORD); refusing to run an unauthenticated operator console")
	}
	if !strings.HasPrefix(cfg.coordinator, "http://") && !strings.HasPrefix(cfg.coordinator, "https://") {
		return config{}, fmt.Errorf("--coordinator %q must start with http:// or https://", cfg.coordinator)
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
	return slog.New(h).With("service", "fass-console", "version", version), nil
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return v
	}
	return def
}

func envBool(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func envBoolDefault(key string, def bool) bool {
	if _, ok := os.LookupEnv(key); !ok {
		return def
	}
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return def
	}
	return v
}
