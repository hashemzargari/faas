// Command fass-bridge implements DS3 Bridge: a resumable, write-through S3→FASS
// migrator with a small JSON control plane (docs/04 §10, docs/08 §5).
//
// It is not an S3 endpoint and does not proxy reads: migration is complete when
// every source object has been copied, verified by read-back, and then deleted
// from the source. Point clients at the target gateway once the bridge reports
// completed (or earlier — write-through means target writes always win).
package main

import (
	"context"
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

	"github.com/fass-storage/fass/internal/bridge"
)

var version = "0.1.0-dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "fass-bridge: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("fass-bridge", flag.ContinueOnError)
	listen := fs.String("listen", envOr("FASS_BRIDGE_LISTEN", ":8082"), "control API listen address (JSON, not S3)")
	dataDir := fs.String("data-dir", envOr("FASS_BRIDGE_DATA_DIR", ".dev/bridge"), "journal directory (mode 0700; holds credentials, one file per bridge)")
	concurrency := fs.Int("concurrency", envInt("FASS_BRIDGE_CONCURRENCY", 4), "simultaneous object transfers")
	maxBPS := fs.Int64("max-bytes-per-second", envInt64("FASS_BRIDGE_MAX_BYTES_PER_SECOND", 0), "source read throttle in bytes/s (0 = unlimited)")
	maxRPS := fs.Int("max-requests-per-second", envInt("FASS_BRIDGE_MAX_REQUESTS_PER_SECOND", 0), "S3 API call throttle (0 = unlimited)")
	multipart := fs.Int64("multipart-threshold", envInt64("FASS_BRIDGE_MULTIPART_THRESHOLD", 8<<20), "objects at/above this size use multipart upload")
	partSize := fs.Int64("part-size", envInt64("FASS_BRIDGE_PART_SIZE", 8<<20), "multipart part size (>= 5 MiB)")
	logLevel := fs.String("log-level", envOr("FASS_BRIDGE_LOG_LEVEL", "info"), "debug|info|warn|error")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println(version)
		return nil
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(strings.ToUpper(*logLevel))); err != nil {
		return fmt.Errorf("invalid --log-level %q", *logLevel)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	mgr, err := bridge.NewManager(bridge.Options{
		DataDir:              *dataDir,
		Concurrency:          *concurrency,
		MaxBytesPerSecond:    *maxBPS,
		MaxRequestsPerSecond: *maxRPS,
		MultipartThreshold:   *multipart,
		PartSize:             *partSize,
		Log:                  logger,
	})
	if err != nil {
		return err
	}
	defer mgr.Close()

	srv := &http.Server{
		Addr:              *listen,
		Handler:           bridge.NewHTTPHandler(mgr),
		ReadHeaderTimeout: 10 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() {
		logger.Info("fass-bridge control API listening", "addr", *listen, "data_dir", *dataDir, "version", version,
			"concurrency", *concurrency, "max_bytes_per_second", *maxBPS, "max_requests_per_second", *maxRPS)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envInt64(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}
