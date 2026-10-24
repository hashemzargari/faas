// Command fass-gateway runs the FASS S3 edge: the S3 frontend (routing, XML,
// auth), the offloader (chunk → encrypt → EC → shards → commit) and Smart Data
// Placement.
//
// It is stateless: metadata and authorisation come from the coordinator, shard
// I/O goes directly to the agents, and nothing is persisted locally.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fass-storage/fass/internal/agent/client"
	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/ec"
	"github.com/fass-storage/fass/internal/gateway/agenttls"
	"github.com/fass-storage/fass/internal/gateway/authz"
	"github.com/fass-storage/fass/internal/gateway/coordclient"
	"github.com/fass-storage/fass/internal/gateway/metrics"
	"github.com/fass-storage/fass/internal/gateway/offloader"
	"github.com/fass-storage/fass/internal/gateway/s3"
	"github.com/fass-storage/fass/internal/gateway/sdp"
)

// version is stamped by the build ("-X main.version=...").
var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "pki" {
		if err := runPKI(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "fass-gateway pki: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println(version)
		return
	}
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "fass-gateway: %v\n", err)
		os.Exit(1)
	}
}

type config struct {
	listenHTTP  string
	listenAdmin string
	coordinator string
	tlsCert     string
	tlsKey      string

	// Data/control plane security. insecure is the explicit, loud plaintext
	// escape hatch; agentTLS is off|auto|require; requireMTLS rejects plaintext
	// peers. Non-dev without TLS material refuses to start.
	insecure      bool
	agentTLS      string
	requireMTLS   bool
	caCert        string
	clientCert    string
	clientKey     string
	coordinatorCA string
	// coordinatorInsecure explicitly allows plaintext control-plane traffic
	// (dev/transitional), independent of data-plane TLS.
	coordinatorInsecure bool

	region            string
	virtualHostDomain string
	addressing        string
	allowAnonymous    bool
	defaultRCID       string

	chunkSize     int
	workers       int
	frameSize     int
	shardParallel int
	shardTimeout  time.Duration
	shardRetries  int
	readParallel  int
	readTimeout   time.Duration
	hedgeAfter    time.Duration

	geoN, geoK, localN, localK int
	maxObjectSize              int64
	maxSinglePut               int64

	keySeed     string
	tenantSeeds multiFlag
	sdpPolicy   string
	// dev allows an ephemeral key seed; non-dev gateways refuse to start
	// without a stable seed so a restart cannot silently orphan every object.
	dev bool

	logLevel  string
	logFormat string
}

// multiFlag collects repeated "tenant=hexseed" flags.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
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

	// Security posture: fail closed, never silently downgrade.
	agentMode, err := agenttls.ParseMode(cfg.agentTLS)
	if err != nil {
		return err
	}
	insecure := cfg.insecure
	if cfg.dev && cfg.caCert == "" && !cfg.insecure {
		// Dev default may stay plaintext, but it is loud and visible.
		insecure = true
		agentMode = agenttls.ModeOff
		logger.Warn("DEV MODE: data/control planes are PLAINTEXT. Configure --ca-cert/--tls-cert/--tls-key for TLS; /healthz reports security.insecure=true.")
	}
	if insecure {
		agentMode = agenttls.ModeOff
		logger.Warn("INSECURE MODE (enabled by --insecure or --dev): shard and coordinator traffic is plaintext; /healthz reports security.insecure=true. Never use in production.")
	}
	if err := validateSecurityConfig(cfg, insecure, agentMode); err != nil {
		return err
	}
	agentHTTP, agentSecurity, err := agenttls.NewClient(agenttls.Options{
		Mode:        agentMode,
		CAFile:      cfg.caCert,
		CertFile:    cfg.clientCert,
		KeyFile:     cfg.clientKey,
		RequireMTLS: cfg.requireMTLS,
		Logger:      logger,
	})
	if err != nil {
		return fmt.Errorf("data-plane TLS: %w", err)
	}

	// Data plane.
	keyrings, err := buildKeyrings(cfg, logger)
	if err != nil {
		return err
	}
	shardClient := client.New(client.Options{UserAgent: "fass-gateway/" + version, HTTPClient: agentHTTP, Scheme: agentSecurity.Scheme()})

	// Coordination. The control-plane TLS client uses the same CA and identity;
	// its ServerName is the coordinator's URL host.
	coordHTTP := &http.Client{Timeout: 10 * time.Second}
	coordinatorTLS := !insecure && !cfg.coordinatorInsecure
	if coordinatorTLS {
		caFile := cfg.coordinatorCA
		if caFile == "" {
			caFile = cfg.caCert
		}
		coordHTTP, _, err = agenttls.NewClient(agenttls.Options{
			Mode:        agenttls.ModeRequire,
			CAFile:      caFile,
			CertFile:    cfg.clientCert,
			KeyFile:     cfg.clientKey,
			RequireMTLS: cfg.requireMTLS,
			Logger:      logger,
		})
		if err != nil {
			return fmt.Errorf("coordinator TLS: %w", err)
		}
	} else if cfg.coordinatorInsecure && !insecure {
		logger.Warn("CONTROL PLANE IS PLAINTEXT (--coordinator-insecure) while the data plane uses TLS; /healthz reports security.coordinator_insecure=true")
	}
	coord, err := coordclient.New(coordclient.Options{
		BaseURL:    cfg.coordinator,
		UserAgent:  "fass-gateway/" + version,
		HTTPClient: coordHTTP,
	})
	if err != nil {
		return err
	}

	off, err := offloader.New(offloader.Deps{
		Coord:    coord,
		Shards:   shardClient,
		Keyrings: keyrings,
		Logger:   logger,
		Config: offloader.Config{
			ChunkSize:           cfg.chunkSize,
			MaxConcurrentChunks: cfg.workers,
			FrameSize:           cfg.frameSize,
			ShardPutParallel:    cfg.shardParallel,
			ShardPutTimeout:     cfg.shardTimeout,
			ShardPutRetries:     cfg.shardRetries,
			ShardReadParallel:   cfg.readParallel,
			ShardReadTimeout:    cfg.readTimeout,
			HedgeAfter:          cfg.hedgeAfter,
		},
	})
	if err != nil {
		return err
	}

	// Smart Data Placement.
	var placement *sdp.Engine
	if cfg.sdpPolicy != "" {
		body, rerr := os.ReadFile(cfg.sdpPolicy)
		if rerr != nil {
			return fmt.Errorf("read SDP policy: %w", rerr)
		}
		placement, err = sdp.Compile(body)
		if err != nil {
			return fmt.Errorf("compile SDP policy: %w", err)
		}
		logger.Info("smart data placement loaded", "rules", placement.Rules(), "file", cfg.sdpPolicy)
	}

	registry := metrics.New()
	verifier := authz.New(coord, authz.Options{ClockSkew: 15 * time.Minute})

	s3cfg := s3.Config{
		Region:            cfg.region,
		VirtualHostDomain: cfg.virtualHostDomain,
		Addressing:        s3.Addressing(cfg.addressing),
		AllowAnonymous:    cfg.allowAnonymous,
		ServerVersion:     version,
		Limits:            s3.DefaultLimits(),
		Compat:            s3.DefaultCompat(),
		ChunkSize:         cfg.chunkSize,
		DefaultParams:     ec.Params{GeoN: cfg.geoN, GeoK: cfg.geoK, LocalN: cfg.localN, LocalK: cfg.localK},
		DefaultRCID:       cfg.defaultRCID,
	}
	s3cfg.Limits.MaxObjectSize = cfg.maxObjectSize
	s3cfg.Limits.MaxSinglePut = cfg.maxSinglePut

	frontend := s3.New(s3.Deps{
		Coord:   coord,
		Authn:   verifier,
		Authz:   verifier,
		Off:     off,
		SDP:     placement,
		Logger:  logger,
		Metrics: registry,
		Config:  s3cfg,
	})

	readiness := &readinessChecker{url: strings.TrimRight(cfg.coordinator, "/") + "/v1/healthz", client: coordHTTP}
	readiness.start(ctx, logger)

	secStatus := securityStatus{
		Insecure:        insecure,
		AgentMode:       string(agentMode),
		RequireMTLS:     cfg.requireMTLS,
		S3TLS:           cfg.tlsCert != "" && cfg.tlsKey != "",
		CoordinatorTLS:  coordinatorTLS,
		CertNotAfter:    formatNotAfter(agentSecurity.NotAfter),
		CertFingerprint: agentSecurity.Fingerprint,
	}
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("GET /healthz", healthHandler("ok", secStatus))
	adminMux.HandleFunc("GET /readyz", readiness.handler)
	adminMux.Handle("GET /metrics", registry.Handler())

	// The M0 contract is curl :8080/healthz, so the frontend listener also
	// serves the liveness/readiness/metrics endpoints.
	mainHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			healthHandler("ok", secStatus)(w, r)
		case "/readyz":
			readiness.handler(w, r)
		case "/metrics":
			registry.Handler().ServeHTTP(w, r)
		default:
			frontend.ServeHTTP(w, r)
		}
	})

	httpServer := &http.Server{
		Addr:              cfg.listenHTTP,
		Handler:           mainHandler,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}
	adminServer := &http.Server{
		Addr:              cfg.listenAdmin,
		Handler:           adminMux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	errCh := make(chan error, 2)
	go func() {
		logger.Info("gateway listening", "addr", cfg.listenHTTP, "coordinator", cfg.coordinator)
		if cfg.tlsCert != "" || cfg.tlsKey != "" {
			if cfg.tlsCert == "" || cfg.tlsKey == "" {
				errCh <- errors.New("both --tls-cert and --tls-key are required for TLS")
				return
			}
			errCh <- httpServer.ListenAndServeTLS(cfg.tlsCert, cfg.tlsKey)
			return
		}
		errCh <- httpServer.ListenAndServe()
	}()
	go func() {
		logger.Info("gateway admin listening", "addr", cfg.listenAdmin)
		errCh <- adminServer.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutting down")
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for _, srv := range []*http.Server{httpServer, adminServer} {
		wg.Add(1)
		go func(srv *http.Server) {
			defer wg.Done()
			if err := srv.Shutdown(shutdownCtx); err != nil {
				logger.Error("shutdown", "addr", srv.Addr, "error", err)
			}
		}(srv)
	}
	wg.Wait()
	return nil
}

// buildKeyrings builds the tenant keyring provider from flags/env.
func buildKeyrings(cfg config, logger *slog.Logger) (offloader.KeyringProvider, error) {
	seeds := make(map[contract.TenantID][]byte, len(cfg.tenantSeeds))
	for _, entry := range cfg.tenantSeeds {
		tenant, hexSeed, ok := strings.Cut(entry, "=")
		if !ok || tenant == "" {
			return nil, fmt.Errorf("invalid --tenant-key %q (want tenant=hexseed)", entry)
		}
		seed, err := decodeSeed(hexSeed)
		if err != nil {
			return nil, fmt.Errorf("tenant %q: %w", tenant, err)
		}
		seeds[contract.TenantID(tenant)] = seed
	}
	var defaultSeed []byte
	if cfg.keySeed != "" {
		var err error
		if defaultSeed, err = decodeSeed(cfg.keySeed); err != nil {
			return nil, err
		}
	}
	if len(defaultSeed) == 0 && len(seeds) == 0 {
		if !cfg.dev {
			return nil, fmt.Errorf("no tenant key seed configured: refusing to start outside --dev mode. " +
				"Set --key-seed <hex> (single-key mode) or --tenant-key tenant=<hex> (repeatable). " +
				"An ephemeral seed would make every object unreadable after a restart.")
		}
		// Dev convenience: an ephemeral seed keeps the gateway runnable without a
		// KMS. Print it so a developer can pin it and keep their data.
		generated, err := offloader.GenerateSeed()
		if err != nil {
			return nil, err
		}
		logger.Warn("no key seed configured (--dev): using an EPHEMERAL seed. Objects become unreadable after restart. " +
			"Pin it with --key-seed " + hex.EncodeToString(generated))
		defaultSeed = generated
	}
	return offloader.NewStaticKeyrings(defaultSeed, seeds)
}

func decodeSeed(s string) ([]byte, error) {
	seed, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("seed must be hex: %w", err)
	}
	if len(seed) < 16 {
		return nil, fmt.Errorf("seed must be at least 16 bytes")
	}
	return seed, nil
}

// ---------------------------------------------------------------------------
// readiness
// ---------------------------------------------------------------------------

type readinessChecker struct {
	url       string
	client    *http.Client
	ready     atomic.Bool
	lastError atomic.Value
}

func (r *readinessChecker) start(ctx context.Context, logger *slog.Logger) {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			r.check(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (r *readinessChecker) check(ctx context.Context) {
	callCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(callCtx, http.MethodGet, r.url, nil)
	if err != nil {
		return
	}
	resp, err := r.client.Do(req)
	if err != nil {
		r.ready.Store(false)
		r.lastError.Store(err.Error())
		return
	}
	defer resp.Body.Close()
	r.ready.Store(resp.StatusCode == http.StatusOK)
}

func (r *readinessChecker) handler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !r.ready.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"not ready","reason":"coordinator unavailable"}`))
		return
	}
	_, _ = w.Write([]byte(`{"status":"ready"}`))
}

// securityStatus is the machine-readable security posture served by /healthz.
// It is intentionally impossible to hide plaintext: insecure=true and
// agent_mode="off" are always present.
type securityStatus struct {
	Insecure        bool   `json:"insecure"`
	AgentMode       string `json:"agent_mode"`
	RequireMTLS     bool   `json:"require_mtls"`
	S3TLS           bool   `json:"s3_tls"`
	CoordinatorTLS  bool   `json:"coordinator_tls"`
	CertNotAfter    string `json:"cert_not_after,omitempty"`
	CertFingerprint string `json:"cert_fingerprint,omitempty"`
}

func healthHandler(status string, sec securityStatus) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body, err := json.Marshal(struct {
			Status   string         `json:"status"`
			Security securityStatus `json:"security"`
		}{Status: status, Security: sec})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(body)
	}
}

// formatNotAfter renders a certificate expiry for /healthz, empty when absent so
// the field is omitted rather than showing Go's zero time.
func formatNotAfter(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// validateSecurityConfig enforces fail-closed defaults: outside dev/--insecure
// the data plane must have TLS material and the coordinator must be https.
func validateSecurityConfig(cfg config, insecure bool, agentMode agenttls.Mode) error {
	if insecure {
		return nil
	}
	if cfg.caCert == "" {
		return fmt.Errorf("refusing to start: data-plane TLS requires --ca-cert (or run --insecure/--dev for plaintext)")
	}
	if agentMode == agenttls.ModeOff {
		return fmt.Errorf("refusing to start: --agent-tls=off requires --insecure in a non-dev deployment")
	}
	if cfg.requireMTLS && (cfg.clientCert == "" || cfg.clientKey == "") {
		return fmt.Errorf("refusing to start: --require-mtls needs --tls-cert and --tls-key")
	}
	u, err := url.Parse(cfg.coordinator)
	if err != nil {
		return fmt.Errorf("invalid --coordinator URL: %w", err)
	}
	if u.Scheme != "https" && !cfg.coordinatorInsecure {
		return fmt.Errorf("refusing to start: coordinator control plane must use https when TLS is enforced (got %q); pass --coordinator-insecure only for explicit dev/transitional mode", cfg.coordinator)
	}
	if u.Scheme == "https" && cfg.coordinatorInsecure {
		return fmt.Errorf("--coordinator-insecure conflicts with an https --coordinator URL")
	}
	return nil
}

// ---------------------------------------------------------------------------
// config
// ---------------------------------------------------------------------------

func parseConfig(args []string) (config, error) {
	fs := flag.NewFlagSet("fass-gateway", flag.ContinueOnError)
	cfg := config{
		listenHTTP:        envOr("FASS_GATEWAY_LISTEN", ":8080"),
		listenAdmin:       envOr("FASS_GATEWAY_ADMIN_LISTEN", ":9000"),
		coordinator:       envOr("FASS_COORDINATOR_URL", "http://127.0.0.1:7001"),
		region:            envOr("FASS_GATEWAY_REGION", contract.DefaultRegion),
		virtualHostDomain: envOr("FASS_GATEWAY_VHOST_DOMAIN", ""),
		addressing:        envOr("FASS_GATEWAY_ADDRESSING", "both"),
		defaultRCID:       envOr("FASS_GATEWAY_DEFAULT_RC", ""),
		keySeed:           envOr("FASS_GATEWAY_KEY_SEED", ""),
		sdpPolicy:         envOr("FASS_GATEWAY_SDP_POLICY", ""),
		logLevel:          envOr("FASS_LOG_LEVEL", "info"),
		logFormat:         envOr("FASS_LOG_FORMAT", "text"),
	}
	cfg.clientCert = envOr("FASS_GATEWAY_CLIENT_CERT", "")
	cfg.clientKey = envOr("FASS_GATEWAY_CLIENT_KEY", "")
	allowAnon, _ := strconv.ParseBool(envOr("FASS_GATEWAY_ALLOW_ANONYMOUS", "true"))
	cfg.allowAnonymous = allowAnon
	cfg.chunkSize = envInt("FASS_GATEWAY_CHUNK_SIZE", 16<<20)
	cfg.workers = envInt("FASS_GATEWAY_WORKERS", 4)
	cfg.frameSize = envInt("FASS_GATEWAY_FRAME_SIZE", 1<<20)
	cfg.shardParallel = envInt("FASS_GATEWAY_SHARD_PARALLEL", 16)
	cfg.shardRetries = envInt("FASS_GATEWAY_SHARD_RETRIES", 2)
	cfg.readParallel = envInt("FASS_GATEWAY_READ_PARALLEL", 32)
	cfg.geoN = envInt("FASS_GATEWAY_GEO_N", 2)
	cfg.geoK = envInt("FASS_GATEWAY_GEO_K", 1)
	cfg.localN = envInt("FASS_GATEWAY_LOCAL_N", 16)
	cfg.localK = envInt("FASS_GATEWAY_LOCAL_K", 4)

	fs.StringVar(&cfg.listenHTTP, "listen", cfg.listenHTTP, "S3 HTTP listen address")
	fs.StringVar(&cfg.listenAdmin, "admin-listen", cfg.listenAdmin, "admin listen address (healthz, readyz, metrics)")
	fs.StringVar(&cfg.coordinator, "coordinator", cfg.coordinator, "coordinator HTTP base URL")
	fs.StringVar(&cfg.region, "region", cfg.region, "region reported by the gateway")
	fs.StringVar(&cfg.virtualHostDomain, "virtual-host-domain", cfg.virtualHostDomain, "domain for virtual-hosted-style addressing (empty disables it)")
	fs.StringVar(&cfg.addressing, "addressing", cfg.addressing, "addressing style: path|virtual|both")
	fs.BoolVar(&cfg.allowAnonymous, "allow-anonymous", cfg.allowAnonymous, "allow unsigned requests (authorisation is still enforced)")
	fs.StringVar(&cfg.defaultRCID, "default-redundancy-class", cfg.defaultRCID, "default Redundancy Class id")
	fs.IntVar(&cfg.chunkSize, "chunk-size", cfg.chunkSize, "chunk size in bytes (4-64 MiB, 1 MiB aligned)")
	fs.IntVar(&cfg.workers, "offloader-workers", cfg.workers, "max concurrent chunks (bounds memory)")
	fs.IntVar(&cfg.frameSize, "crypto-frame-size", cfg.frameSize, "AES-GCM frame size")
	fs.IntVar(&cfg.shardParallel, "shard-parallel", cfg.shardParallel, "max parallel shard PUTs per chunk")
	fs.DurationVar(&cfg.shardTimeout, "shard-put-timeout", 5*time.Second, "per-shard PUT timeout")
	fs.IntVar(&cfg.shardRetries, "shard-put-retries", cfg.shardRetries, "per-shard PUT retries before displacement")
	fs.IntVar(&cfg.readParallel, "shard-read-parallel", cfg.readParallel, "max parallel shard GETs per chunk")
	fs.DurationVar(&cfg.readTimeout, "shard-read-timeout", 10*time.Second, "per-shard GET timeout")
	fs.DurationVar(&cfg.hedgeAfter, "read-hedge-after", 50*time.Millisecond, "start parity-shard hedges after this delay")
	fs.IntVar(&cfg.geoN, "geo-n", cfg.geoN, "default RC geo data shards")
	fs.IntVar(&cfg.geoK, "geo-k", cfg.geoK, "default RC geo parity shards")
	fs.IntVar(&cfg.localN, "local-n", cfg.localN, "default RC local data shards")
	fs.IntVar(&cfg.localK, "local-k", cfg.localK, "default RC local parity shards")
	fs.Int64Var(&cfg.maxObjectSize, "max-object-size", 5<<40, "maximum object size in bytes")
	fs.Int64Var(&cfg.maxSinglePut, "max-single-put", 5<<30, "maximum single PUT size in bytes")
	fs.StringVar(&cfg.keySeed, "key-seed", cfg.keySeed, "hex tenant key seed (dev single-key mode)")
	fs.Var(&cfg.tenantSeeds, "tenant-key", "per-tenant key seed as tenant=hexseed (repeatable)")
	fs.StringVar(&cfg.sdpPolicy, "sdp-policy", cfg.sdpPolicy, "path to a Smart Data Placement policy JSON file")
	fs.StringVar(&cfg.tlsCert, "tls-cert", envOr("FASS_GATEWAY_TLS_CERT", ""), "TLS certificate file")
	fs.StringVar(&cfg.tlsKey, "tls-key", envOr("FASS_GATEWAY_TLS_KEY", ""), "TLS key file for the S3 listener")
	fs.StringVar(&cfg.clientKey, "client-key", envOr("FASS_GATEWAY_CLIENT_KEY", ""), "gateway client key for mTLS")
	fs.StringVar(&cfg.coordinatorCA, "coordinator-ca", envOr("FASS_GATEWAY_COORDINATOR_CA", ""), "CA bundle for the coordinator (defaults to --ca-cert)")
	fs.BoolVar(&cfg.coordinatorInsecure, "coordinator-insecure", envBool("FASS_GATEWAY_COORDINATOR_INSECURE", false), "explicitly allow plaintext control-plane traffic (dev/transitional; logged and visible in /healthz)")
	fs.BoolVar(&cfg.dev, "dev", envBool("FASS_GATEWAY_DEV", false), "dev mode: allow an ephemeral key seed when none is configured")
	fs.StringVar(&cfg.agentTLS, "agent-tls", envOr("FASS_GATEWAY_AGENT_TLS", "require"), "data-plane TLS mode: off|auto|require (auto = mixed-mode rollout)")
	fs.BoolVar(&cfg.requireMTLS, "require-mtls", envBool("FASS_GATEWAY_REQUIRE_MTLS", false), "reject plaintext peers and require client certificates (strict mode)")
	fs.BoolVar(&cfg.insecure, "insecure", envBool("FASS_GATEWAY_INSECURE", false), "explicitly allow plaintext data/control traffic (logged on every start, visible in /healthz)")
	fs.StringVar(&cfg.caCert, "ca-cert", envOr("FASS_GATEWAY_CA_CERT", ""), "cluster CA certificate used to verify agents and the coordinator")
	fs.StringVar(&cfg.clientCert, "client-cert", envOr("FASS_GATEWAY_CLIENT_CERT", ""), "gateway client certificate for mTLS (agent and coordinator)")
	fs.StringVar(&cfg.logLevel, "log-level", cfg.logLevel, "log level: debug|info|warn|error")
	fs.StringVar(&cfg.logFormat, "log-format", cfg.logFormat, "log format: text|json")
	fs.StringVar(&cfg.coordinator, "coord", cfg.coordinator, "alias for --coordinator")

	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	switch cfg.addressing {
	case "path", "virtual", "both":
	default:
		return config{}, fmt.Errorf("invalid --addressing %q (path|virtual|both)", cfg.addressing)
	}
	if err := validateParams(ec.Params{GeoN: cfg.geoN, GeoK: cfg.geoK, LocalN: cfg.localN, LocalK: cfg.localK}); err != nil {
		return config{}, err
	}
	return cfg, nil
}

func validateParams(p ec.Params) error {
	if err := p.Validate(); err != nil {
		return fmt.Errorf("invalid default redundancy class: %w", err)
	}
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
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

func newLogger(level, format string) (*slog.Logger, error) {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "info", "":
		lvl = slog.LevelInfo
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		return nil, fmt.Errorf("invalid log level %q", level)
	}
	opts := &slog.HandlerOptions{Level: lvl}
	if strings.EqualFold(format, "json") {
		return slog.New(slog.NewJSONHandler(os.Stdout, opts)), nil
	}
	return slog.New(slog.NewTextHandler(os.Stdout, opts)), nil
}
