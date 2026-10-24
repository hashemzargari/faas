// Command fass-agent is the per-disk storage daemon.
//
// It owns exactly one disk, serves immutable ciphertext shards over the agent
// HTTP API (docs/07-wire-api.md §2), announces itself to the coordinator,
// heartbeats, scrubs its shards in the background and can execute local and geo
// repair jobs. It never needs an encryption key: everything it stores and
// repairs is ciphertext (encrypt-then-code, docs/03 §5.3).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fass-storage/fass/internal/agent/client"
	"github.com/fass-storage/fass/internal/agent/coordclient"
	"github.com/fass-storage/fass/internal/agent/identity"
	"github.com/fass-storage/fass/internal/agent/repair"
	"github.com/fass-storage/fass/internal/agent/scrub"
	"github.com/fass-storage/fass/internal/agent/shard"
	"github.com/fass-storage/fass/internal/agent/store"
	"github.com/fass-storage/fass/internal/agent/transport"
	"github.com/fass-storage/fass/internal/contract"
)

// version is reported in announcements, /v1/stats and metrics.
const version = "0.1.0-dev"

type config struct {
	disk        string
	diskID      string
	port        int
	nexusID     string
	nodeID      string
	coordURL    string
	secret      string
	hostname    string
	reservePct  float64
	maxShard    int64
	scrub       bool
	scrubPeriod time.Duration
	scrubRate   int64
	repair      bool
	repairWork  int
	repairFetch int
	heartbeat   time.Duration
	shutdown    time.Duration
	logLevel    string
	showVersion bool
}

func main() {
	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "fass-agent:", err)
		os.Exit(2)
	}
	if cfg.showVersion {
		fmt.Println("fass-agent", version)
		return
	}
	logger := newLogger(cfg.logLevel)
	if err := run(context.Background(), cfg, logger); err != nil {
		logger.Error("agent exited with error", "err", err)
		os.Exit(1)
	}
}

func parseFlags(args []string) (config, error) {
	cfg := config{}
	fs := flag.NewFlagSet("fass-agent", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&cfg.disk, "disk", "./data", "path to the disk this agent owns")
	fs.StringVar(&cfg.diskID, "disk-id", "", "authoritative disk UUID for this disk (default: generate/persist in <disk>/state.json; a mismatch with the persisted id refuses to start)")
	fs.IntVar(&cfg.port, "port", 7100, "shard HTTP listen port (0 picks a free port)")
	fs.StringVar(&cfg.nexusID, "nexus-id", "", "nexus (site/AZ) this agent belongs to")
	fs.StringVar(&cfg.nodeID, "node-id", "", "node id reported to the coordinator")
	fs.StringVar(&cfg.coordURL, "coordinator-url", "http://127.0.0.1:7000", "coordinator control-plane URL")
	fs.StringVar(&cfg.secret, "secret", "", "one-time announce secret issued by the coordinator")
	fs.StringVar(&cfg.hostname, "hostname", hostname(), "hostname reported in the announce request")
	fs.Float64Var(&cfg.reservePct, "reserve-pct", 5, "percentage of the filesystem kept free (never filled)")
	fs.Int64Var(&cfg.maxShard, "max-shard-bytes", 32<<20, "maximum single shard payload size")
	fs.BoolVar(&cfg.scrub, "scrub", true, "enable the rolling background scrubber")
	fs.DurationVar(&cfg.scrubPeriod, "scrub-period", 168*time.Hour, "time between scrub passes")
	fs.Int64Var(&cfg.scrubRate, "scrub-rate", 50<<20, "scrub read rate limit in bytes/second")
	fs.BoolVar(&cfg.repair, "repair", true, "claim and execute repair jobs from the coordinator")
	fs.IntVar(&cfg.repairWork, "repair-workers", 1, "concurrent repair claim loops")
	fs.IntVar(&cfg.repairFetch, "repair-fetch-concurrency", 8, "parallel shard fetches per repair job")
	fs.DurationVar(&cfg.heartbeat, "heartbeat-interval", 5*time.Second, "heartbeat interval")
	fs.DurationVar(&cfg.shutdown, "shutdown-timeout", 15*time.Second, "graceful shutdown timeout")
	fs.StringVar(&cfg.logLevel, "log-level", "info", "log level: debug, info, warn, error")
	fs.BoolVar(&cfg.showVersion, "version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	if fs.NArg() > 0 {
		return config{}, fmt.Errorf("unexpected arguments: %v", strings.Join(fs.Args(), " "))
	}
	if cfg.port < 0 || cfg.port > 65535 {
		return config{}, fmt.Errorf("invalid --port %d", cfg.port)
	}
	if cfg.reservePct < 0 || cfg.reservePct >= 100 {
		return config{}, fmt.Errorf("invalid --reserve-pct %v", cfg.reservePct)
	}
	if cfg.maxShard <= 0 {
		return config{}, fmt.Errorf("invalid --max-shard-bytes %d", cfg.maxShard)
	}
	if cfg.heartbeat <= 0 {
		return config{}, fmt.Errorf("invalid --heartbeat-interval %v", cfg.heartbeat)
	}
	return cfg, nil
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}

func run(parent context.Context, cfg config, logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, store.Options{
		Root:          cfg.disk,
		DiskID:        cfg.diskID,
		ReservePct:    cfg.reservePct,
		MaxShardBytes: cfg.maxShard,
		Logger:        logger,
	})
	if err != nil {
		return fmt.Errorf("open shard store: %w", err)
	}
	defer func() {
		if err := st.Close(); err != nil {
			logger.Warn("closing store", "err", err)
		}
	}()

	ident, err := identity.LoadOrCreate(filepath.Join(st.Root(), "identity"))
	if err != nil {
		return fmt.Errorf("agent identity: %w", err)
	}

	coord, err := coordclient.New(cfg.coordURL, coordclient.Options{
		Timeout: 10 * time.Second,
		Logger:  logger,
	})
	if err != nil {
		return fmt.Errorf("coordinator client: %w", err)
	}

	var scrubber *scrub.Scrubber
	if cfg.scrub {
		scrubber, err = scrub.New(scrub.Options{
			Store:       st,
			Period:      cfg.scrubPeriod,
			BytesPerSec: cfg.scrubRate,
			Reporter:    coord,
			Logger:      logger,
		})
		if err != nil {
			return fmt.Errorf("scrubber: %w", err)
		}
	}

	srv, err := transport.New(transport.Options{
		Store:           st,
		Scrubber:        scrubber,
		NodeID:          cfg.nodeID,
		Version:         version,
		Logger:          logger,
		ShutdownTimeout: cfg.shutdown,
	})
	if err != nil {
		return fmt.Errorf("transport: %w", err)
	}

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.port))
	if err != nil {
		return fmt.Errorf("listen on port %d: %w", cfg.port, err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	logger.Info("fass-agent starting",
		"version", version,
		"disk", st.Root(),
		"disk_id", st.DiskID(),
		"disk_id_explicit", cfg.diskID != "",
		"shards", st.Stats().ShardCount,
		"port", port,
		"node_id", cfg.nodeID,
		"nexus_id", cfg.nexusID,
		"public_key", ident.PublicKeyBase64(),
		"coordinator", cfg.coordURL,
	)

	gctx, gcancel := context.WithCancel(ctx)
	var wg sync.WaitGroup

	serveErr := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		serveErr <- srv.ServeListener(gctx, ln)
	}()

	if scrubber != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := scrubber.Run(gctx); err != nil && gctx.Err() == nil {
				logger.Warn("scrub loop stopped", "err", err)
			}
		}()
	}

	agentIDCh := make(chan contract.AgentID, 1)
	membershipErr := make(chan error, 1)
	if cfg.secret == "" {
		logger.Warn("no --secret provided: announcing and heartbeating are disabled (dev mode)")
	} else {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cursorFn := func() string { return "" }
			if scrubber != nil {
				cursorFn = scrubber.Cursor
			}
			if err := runMembership(gctx, logger, coord, cfg, ident, st, srv, port, cursorFn, agentIDCh); err != nil && gctx.Err() == nil {
				membershipErr <- err
			}
		}()
	}

	var repairErr chan error
	if cfg.repair {
		repairErr = make(chan error, 1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-gctx.Done():
				return
			case agentID := <-agentIDCh:
				exec, err := repair.New(repair.Options{
					Client:           client.New(client.Options{}),
					Coordinator:      coord,
					Worker:           string(agentID),
					Workers:          cfg.repairWork,
					FetchConcurrency: cfg.repairFetch,
					Logger:           logger,
				})
				if err != nil {
					repairErr <- fmt.Errorf("repair executor: %w", err)
					return
				}
				if err := exec.Run(gctx); err != nil && gctx.Err() == nil {
					repairErr <- err
				}
			}
		}()
	}

	var runErr error
	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received; draining")
	case err := <-serveErr:
		if err != nil {
			runErr = fmt.Errorf("http server: %w", err)
		}
	case err := <-membershipErr:
		runErr = fmt.Errorf("membership: %w", err)
	case err := <-repairErr:
		runErr = fmt.Errorf("repair: %w", err)
	}

	gcancel()
	wg.Wait()
	if err := st.Close(); err != nil && runErr == nil {
		runErr = fmt.Errorf("close store: %w", err)
	}
	logger.Info("fass-agent stopped")
	return runErr
}

// runMembership announces this agent (with retries), then heartbeats until the
// context is cancelled.
func runMembership(
	ctx context.Context,
	logger *slog.Logger,
	coord *coordclient.Client,
	cfg config,
	ident *identity.Identity,
	st *store.Store,
	srv *transport.Server,
	port int,
	cursorFn func() string,
	agentIDCh chan<- contract.AgentID,
) error {
	stats := st.Stats()
	req := contract.AnnounceRequest{
		PublicKey:     ident.PublicKey,
		Secret:        cfg.secret,
		NodeID:        contract.NodeID(cfg.nodeID),
		DiskID:        st.DiskID(),
		Port:          port,
		CapacityBytes: stats.TotalBytes,
		Version:       version,
		Hostname:      cfg.hostname,
	}

	backoff := time.Second
	var res contract.AnnounceResult
	for {
		var err error
		res, err = coord.Announce(ctx, req)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return nil
		}
		logger.Warn("agent announce failed; retrying", "err", err, "retry_in", backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}

	logger.Info("agent announced",
		"agent_id", res.AgentID,
		"nexus_id", res.NexusID,
		"state", res.State,
		"ring_ids", res.RingIDs,
	)
	persistAgentState(st.Root(), logger, agentState{
		AgentID:     res.AgentID,
		NexusID:     res.NexusID,
		DiskID:      st.DiskID(),
		AnnouncedAt: time.Now().UTC(),
	})
	select {
	case agentIDCh <- res.AgentID:
	default:
	}

	ticker := time.NewTicker(cfg.heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		hb, err := buildHeartbeat(res.AgentID, st.DiskID(), cfg.diskID, st.Stats(),
			srv.LoadEWMA(), cursorFn(), time.Now().UTC())
		if err != nil {
			// Identity divergence would make the agent lie about which disk it
			// serves. Fail the membership loop loudly instead.
			return fmt.Errorf("heartbeat: %w", err)
		}
		if err := coord.Heartbeat(ctx, hb); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			logger.Warn("heartbeat failed", "err", err)
		}
	}
}

// buildHeartbeat assembles the heartbeat payload. The reported disk id is
// always the identity bound to the disk in <disk>/state.json (Store.DiskID()),
// never the raw --disk-id flag: in a healthy agent they are identical, and if
// they ever diverge the agent must fail loudly rather than report an identity it
// is not actually serving.
func buildHeartbeat(
	agentID contract.AgentID,
	boundDiskID string,
	flagDiskID string,
	stats store.Stats,
	loadEWMA float64,
	scrubCursor string,
	now time.Time,
) (contract.Heartbeat, error) {
	if boundDiskID == "" {
		return contract.Heartbeat{}, errors.New("agent has no bound disk identity")
	}
	if flagDiskID != "" && flagDiskID != boundDiskID {
		return contract.Heartbeat{}, fmt.Errorf(
			"disk identity diverged: --disk-id=%q but the store is bound to %q; refusing to heartbeat",
			flagDiskID, boundDiskID)
	}
	return contract.Heartbeat{
		AgentID:         agentID,
		DiskID:          boundDiskID,
		FreeBytes:       stats.FreeBytes,
		UsedBytes:       stats.UsedBytes,
		ShardCount:      stats.ShardCount,
		LoadEWMA:        loadEWMA,
		ScrubCursor:     scrubCursor,
		InventoryDigest: inventoryDigest(stats),
		Time:            now,
	}, nil
}

// inventoryDigest is a cheap summary the coordinator compares between reports;
// a mismatch triggers a targeted scrub (docs/03 §5.1).
func inventoryDigest(stats store.Stats) string {
	summary := fmt.Sprintf("v1|%d|%d|%d|%d", stats.ShardCount, stats.SetCount, stats.UsedBytes, stats.PayloadBytes)
	return fmt.Sprintf("%016x", shard.Sum64([]byte(summary)))
}

type agentState struct {
	AgentID     contract.AgentID `json:"agent_id"`
	NexusID     contract.NexusID `json:"nexus_id"`
	DiskID      string           `json:"disk_id"`
	AnnouncedAt time.Time        `json:"announced_at"`
}

func persistAgentState(root string, logger *slog.Logger, state agentState) {
	dir := filepath.Join(root, "state")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		logger.Warn("cannot create state dir", "err", err)
		return
	}
	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		logger.Warn("cannot encode agent state", "err", err)
		return
	}
	path := filepath.Join(dir, "agent.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		logger.Warn("cannot write agent state", "err", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		logger.Warn("cannot install agent state", "err", err)
	}
}
