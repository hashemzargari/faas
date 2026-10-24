// Package transport implements the agent's HTTP shard API, docs/07-wire-api.md
// §2 (paths and payloads are frozen; the same endpoints are spoken by gateways,
// repairers, scrubbers and the console).
//
// The server is deliberately thin: it validates wire parameters, converts
// store errors into the documented status codes, and streams at most one shard
// per request. All checksum semantics live in the store.
package transport

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fass-storage/fass/internal/agent/shard"
	"github.com/fass-storage/fass/internal/agent/store"
	"github.com/fass-storage/fass/internal/agent/uid"
	"github.com/fass-storage/fass/internal/contract"
)

// Scrubber is the subset of the scrub loop the HTTP surface needs.
type Scrubber interface {
	// Trigger requests an out-of-band scrub pass. It must not block.
	Trigger()
	// Cursor reports the rolling scrub position (for stats/heartbeat).
	Cursor() string
}

// Options configures the agent HTTP server.
type Options struct {
	Store    *store.Store
	Scrubber Scrubber
	NodeID   string
	Version  string
	Logger   *slog.Logger
	// TLS enables the shard listener's TLS/mTLS configuration. Nil means the
	// listener is plaintext, which transport reports honestly as
	// {"tls":false,"insecure":true} in /v1/healthz. cmd/fass-agent refuses to
	// run plaintext unless the operator passed --insecure.
	TLS *ServerTLS
	// ReadHeaderTimeout defaults to 10s.
	ReadHeaderTimeout time.Duration
	// ShutdownTimeout defaults to 15s.
	ShutdownTimeout time.Duration
}

// Server is the agent HTTP shard server.
type Server struct {
	store    *store.Store
	scrubber Scrubber
	tls      *ServerTLS
	nodeID   string
	version  string
	log      *slog.Logger
	handler  http.Handler
	metrics  *metrics

	loadMu   sync.Mutex
	loadEWMA float64

	readHeaderTimeout time.Duration
	shutdownTimeout   time.Duration
}

// New builds the agent HTTP server. It does not listen; call Serve.
func New(opts Options) (*Server, error) {
	if opts.Store == nil {
		return nil, errors.New("transport: nil store")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.NodeID == "" {
		opts.NodeID = string(opts.Store.DiskID())
	}
	if opts.Version == "" {
		opts.Version = "dev"
	}
	if opts.ReadHeaderTimeout <= 0 {
		opts.ReadHeaderTimeout = 10 * time.Second
	}
	if opts.ShutdownTimeout <= 0 {
		opts.ShutdownTimeout = 15 * time.Second
	}

	s := &Server{
		store:             opts.Store,
		scrubber:          opts.Scrubber,
		tls:               opts.TLS,
		nodeID:            opts.NodeID,
		version:           opts.Version,
		log:               opts.Logger.With("component", "transport"),
		metrics:           newMetrics(),
		readHeaderTimeout: opts.ReadHeaderTimeout,
		shutdownTimeout:   opts.ShutdownTimeout,
	}
	s.handler = s.recoverMiddleware(s.requestIDMiddleware(s.observeMiddleware(s.routes())))
	return s, nil
}

// Handler returns the http.Handler (usable directly with httptest).
func (s *Server) Handler() http.Handler { return s.handler }

// Serve listens on addr until ctx is cancelled, then shuts down gracefully.
func (s *Server) Serve(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("transport: listen %s: %w", addr, err)
	}
	return s.ServeListener(ctx, ln)
}

// ServeListener serves on an existing listener; used by tests and by cmd when
// the port must be resolved before announcing.
func (s *Server) ServeListener(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: s.readHeaderTimeout,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}

	if s.tls != nil {
		srv.ErrorLog = log.New(tlsErrorLogWriter{logger: s.log}, "", 0)
		ln = tls.NewListener(ln, s.tls.Config())
	}

	errCh := make(chan error, 1)
	go func() {
		err := srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()
	s.log.Info("agent http server listening", "addr", ln.Addr().String())

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			s.log.Warn("graceful shutdown timed out; closing", "err", err)
			_ = srv.Close()
		}
		return nil
	case err := <-errCh:
		return err
	}
}

// Security reports the listener's security posture. A transport built without
// TLS is plaintext and reports Insecure=true; cmd/fass-agent prevents that from
// happening accidentally by refusing to start without --insecure.
func (s *Server) Security() SecurityInfo {
	if s.tls == nil {
		return SecurityInfo{Enabled: false, Insecure: true}
	}
	return s.tls.Info()
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// Shard data plane.
	mux.HandleFunc("PUT /v1/shards/{set}/{group}/{index}", s.handlePutShard)
	mux.HandleFunc("GET /v1/shards/{set}/{group}/{index}", s.handleGetShard)
	mux.HandleFunc("DELETE /v1/shards/{set}", s.handleDeleteSet)
	mux.HandleFunc("POST /v1/shards:has", s.handleHas)

	// Method fallbacks keep errors JSON instead of net/http's plain 405.
	mux.HandleFunc("/v1/shards/{set}/{group}/{index}", s.handleMethodNotAllowed)
	mux.HandleFunc("/v1/shards/{set}", s.handleMethodNotAllowed)
	mux.HandleFunc("/v1/shards:has", s.handleMethodNotAllowed)

	// Observability and control.
	mux.HandleFunc("GET /v1/inventory", s.handleInventory)
	mux.HandleFunc("/v1/inventory", s.handleMethodNotAllowed)
	mux.HandleFunc("GET /v1/stats", s.handleStats)
	mux.HandleFunc("/v1/stats", s.handleMethodNotAllowed)
	mux.HandleFunc("GET /v1/healthz", s.handleHealthz)
	mux.HandleFunc("/v1/healthz", s.handleMethodNotAllowed)
	mux.HandleFunc("POST /v1/scrub", s.handleScrub)
	mux.HandleFunc("/v1/scrub", s.handleMethodNotAllowed)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.HandleFunc("/", s.handleNotFound)
	return mux
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func (s *Server) handlePutShard(w http.ResponseWriter, r *http.Request) {
	setID := contract.ShardSetID(r.PathValue("set"))
	group, err := strconv.Atoi(r.PathValue("group"))
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "InvalidArgument", "geo_group must be an integer")
		return
	}
	index, err := strconv.Atoi(r.PathValue("index"))
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "InvalidArgument", "local_index must be an integer")
		return
	}
	params, err := shard.ParseParamsHeader(r.Header.Get("X-Fass-Params"))
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "InvalidParams", err.Error())
		return
	}
	chunkIndex := 0
	if raw := r.Header.Get("X-Fass-Chunk-Index"); raw != "" {
		chunkIndex, err = strconv.Atoi(raw)
		if err != nil || chunkIndex < 0 {
			s.writeError(w, r, http.StatusBadRequest, "InvalidArgument", "X-Fass-Chunk-Index must be a non-negative integer")
			return
		}
	}
	checksum, err := store.ParseChecksum(r.Header.Get("X-Fass-Checksum"))
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "InvalidChecksum", "X-Fass-Checksum must be a uint64")
		return
	}
	if r.ContentLength < 0 {
		s.writeError(w, r, http.StatusLengthRequired, "LengthRequired", "Content-Length is required for shard PUT")
		return
	}

	body := http.MaxBytesReader(w, r.Body, s.store.MaxShardBytes()+1)
	res, err := s.store.Put(r.Context(), store.PutRequest{
		ShardSetID: setID,
		GeoGroup:   group,
		LocalIndex: index,
		Params:     params,
		ChunkIndex: chunkIndex,
		PayloadLen: r.ContentLength,
		Checksum:   checksum,
	}, body)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	if res.Idempotent {
		s.metrics.inc("shard_put_idempotent_total")
	} else {
		s.metrics.inc("shard_put_total")
		s.metrics.add("bytes_written_total", res.Stored)
	}
	s.writeJSON(w, r, http.StatusCreated, putShardResponse{Checksum: res.Checksum, Stored: res.Stored})
}

func (s *Server) handleGetShard(w http.ResponseWriter, r *http.Request) {
	setID := contract.ShardSetID(r.PathValue("set"))
	group, err := strconv.Atoi(r.PathValue("group"))
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "InvalidArgument", "geo_group must be an integer")
		return
	}
	index, err := strconv.Atoi(r.PathValue("index"))
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "InvalidArgument", "local_index must be an integer")
		return
	}

	rd, err := s.store.Get(r.Context(), setID, group, index)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	defer rd.Close()

	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Length", strconv.FormatInt(rd.Header.PayloadLen, 10))
	h.Set("X-Fass-Checksum", strconv.FormatUint(binaryChecksum(rd.Header.Checksum), 10))
	h.Set("X-Fass-Created-At", rd.Header.CreatedAt.UTC().Format(time.RFC3339))
	h.Set("X-Fass-Params", shard.ParamsHeader(rd.Header.Params))
	h.Set("X-Fass-Chunk-Index", strconv.Itoa(rd.Header.ChunkIndex))
	w.WriteHeader(http.StatusOK)
	n, copyErr := io.Copy(w, rd)
	if copyErr != nil {
		s.log.Warn("shard GET aborted while streaming", "shard_set_id", setID,
			"geo_group", group, "local_index", index, "err", copyErr)
		return
	}
	s.metrics.inc("shard_get_total")
	s.metrics.add("bytes_read_total", n)
}

func (s *Server) handleDeleteSet(w http.ResponseWriter, r *http.Request) {
	setID := contract.ShardSetID(r.PathValue("set"))
	n, err := s.store.DeleteSet(r.Context(), setID)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	s.metrics.add("shard_delete_total", int64(n))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleHas(w http.ResponseWriter, r *http.Request) {
	var req hasRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		s.writeError(w, r, http.StatusBadRequest, "InvalidArgument", err.Error())
		return
	}
	if len(req.IDs) > maxBatchIDs {
		s.writeError(w, r, http.StatusBadRequest, "InvalidArgument",
			fmt.Sprintf("too many ids: %d > %d", len(req.IDs), maxBatchIDs))
		return
	}
	ids := make([]contract.ShardSetID, len(req.IDs))
	for i, id := range req.IDs {
		ids[i] = contract.ShardSetID(id)
	}
	present, err := s.store.Has(r.Context(), ids)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	s.writeJSON(w, r, http.StatusOK, hasResponse{Present: present})
}

func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	after := q.Get("after")
	limit := 1000
	if raw := q.Get("limit"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v <= 0 {
			s.writeError(w, r, http.StatusBadRequest, "InvalidArgument", "limit must be a positive integer")
			return
		}
		limit = v
	}
	entries, next, err := s.store.Inventory(r.Context(), after, limit)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	if entries == nil {
		entries = []contract.ShardInfo{}
	}
	s.metrics.inc("inventory_total")
	s.writeJSON(w, r, http.StatusOK, inventoryResponse{Entries: entries, Next: next})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	st := s.store.Stats()
	sec := s.Security()
	resp := statsResponse{
		TLS:           tlsStatsFrom(sec),
		FreeBytes:     st.FreeBytes,
		UsedBytes:     st.UsedBytes,
		TotalBytes:    st.TotalBytes,
		ReservedBytes: st.ReservedBytes,
		ShardCount:    st.ShardCount,
		SetCount:      st.SetCount,
		LoadEWMA:      s.load(),
		DiskID:        st.DiskID,
		NodeID:        s.nodeID,
		Version:       s.version,
		ScrubCursor:   s.scrubCursor(),
	}
	s.writeJSON(w, r, http.StatusOK, resp)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	sec := s.Security()
	resp := healthResponse{
		State:    stateReady,
		DiskID:   s.store.DiskID(),
		NodeID:   s.nodeID,
		TLS:      sec.Enabled,
		Insecure: sec.Insecure,
	}
	if sec.Enabled && !sec.NotAfter.IsZero() {
		notAfter := sec.NotAfter.UTC()
		resp.TLSNotAfter = &notAfter
	}
	s.writeJSON(w, r, http.StatusOK, resp)
}

func (s *Server) handleScrub(w http.ResponseWriter, r *http.Request) {
	if s.scrubber == nil {
		s.writeJSON(w, r, http.StatusAccepted, scrubResponse{State: "disabled"})
		return
	}
	s.scrubber.Trigger()
	s.metrics.inc("scrub_triggered_total")
	s.writeJSON(w, r, http.StatusAccepted, scrubResponse{State: "scheduled"})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	s.metrics.render(w, s.store.Stats(), s.load(), s.Security())
}

func (s *Server) handleMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Allow", allowedMethods(r.URL.Path))
	s.writeError(w, r, http.StatusMethodNotAllowed, "MethodNotAllowed", "method not allowed for this resource")
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	s.writeError(w, r, http.StatusNotFound, "NotFound", "unknown agent endpoint")
}

// ---------------------------------------------------------------------------
// Error mapping and helpers
// ---------------------------------------------------------------------------

// writeStoreError maps store sentinels onto the documented HTTP status codes.
// It never panics on a request path.
func (s *Server) writeStoreError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, context.Canceled):
		// Client went away; status no longer matters.
		s.writeError(w, r, 499, "Canceled", "request canceled")
	case errors.Is(err, context.DeadlineExceeded):
		s.writeError(w, r, http.StatusGatewayTimeout, "Timeout", "request deadline exceeded")
	case errors.Is(err, contract.ErrNotFound):
		s.metrics.inc("shard_get_notfound_total")
		s.writeError(w, r, http.StatusNotFound, "NoSuchShard", "shard not found")
	case errors.Is(err, contract.ErrConflict):
		s.metrics.inc("shard_put_conflict_total")
		s.writeError(w, r, http.StatusConflict, "Conflict", "shard is immutable and different bytes are already stored at this address")
	case errors.Is(err, store.ErrInsufficientCapacity):
		s.metrics.inc("shard_put_insufficient_total")
		s.writeError(w, r, http.StatusInsufficientStorage, "InsufficientStorage", "disk free space below reservation")
	case errors.Is(err, store.ErrChecksumMismatch):
		s.metrics.inc("shard_put_checksum_total")
		s.writeError(w, r, http.StatusBadRequest, "InvalidChecksum", "checksum does not match payload")
	case errors.Is(err, store.ErrLengthMismatch):
		s.writeError(w, r, http.StatusBadRequest, "InvalidLength", "payload length differs from Content-Length")
	case errors.Is(err, store.ErrTooLarge):
		s.writeError(w, r, http.StatusRequestEntityTooLarge, "PayloadTooLarge", "shard exceeds the configured maximum")
	case errors.Is(err, store.ErrCorrupt):
		s.metrics.inc("shard_corrupt_total")
		s.writeError(w, r, http.StatusInternalServerError, "CorruptShard", "stored shard failed checksum verification and was quarantined")
	case errors.Is(err, store.ErrBadRequest), errors.Is(err, store.ErrBadHeader):
		s.writeError(w, r, http.StatusBadRequest, "InvalidArgument", err.Error())
	case errors.Is(err, store.ErrReadOnly), errors.Is(err, store.ErrClosed):
		s.writeError(w, r, http.StatusServiceUnavailable, "Unavailable", "agent is not accepting writes")
	default:
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			s.writeError(w, r, http.StatusRequestEntityTooLarge, "PayloadTooLarge", "shard exceeds the configured maximum")
			return
		}
		s.log.Error("agent request failed", "method", r.Method, "path", r.URL.Path, "err", err)
		s.writeError(w, r, http.StatusInternalServerError, "InternalError", "internal storage error")
	}
}

func (s *Server) writeJSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.log.Warn("encode response failed", "path", r.URL.Path, "err", err)
	}
}

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorEnvelope{Error: errorDetail{Code: code, Message: message}})
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

type ctxKey int

const requestIDKey ctxKey = iota

func (s *Server) requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Fass-Request-Id")
		if id == "" {
			id = uid.New()
		}
		w.Header().Set("X-Fass-Request-Id", id)
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) observeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		s.metrics.inflight.Add(1)
		defer s.metrics.inflight.Add(-1)
		next.ServeHTTP(sw, r)
		dur := time.Since(start)
		status := sw.status
		if status == 0 {
			status = http.StatusOK
		}
		s.metrics.inc("http_requests_total")
		switch {
		case status >= 500:
			s.metrics.inc("http_requests_5xx_total")
		case status >= 400:
			s.metrics.inc("http_requests_4xx_total")
		default:
			s.metrics.inc("http_requests_2xx_total")
		}
		s.observeLoad(dur.Seconds())
		attrs := []any{
			"request_id", requestID(r.Context()),
			"method", r.Method,
			"path", r.URL.Path,
			"status", status,
			"bytes", sw.bytes,
			"duration_ms", float64(dur.Microseconds()) / 1000.0,
		}
		if status >= 500 {
			s.log.Error("agent request", attrs...)
		} else if status >= 400 {
			s.log.Warn("agent request", attrs...)
		} else {
			s.log.Debug("agent request", attrs...)
		}
	})
}

func (s *Server) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				s.log.Error("panic serving agent request", "method", r.Method,
					"path", r.URL.Path, "panic", rec)
				s.writeError(w, r, http.StatusInternalServerError, "InternalError", "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}

func requestID(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

func (s *Server) observeLoad(seconds float64) {
	s.loadMu.Lock()
	s.loadEWMA = 0.9*s.loadEWMA + 0.1*seconds
	s.loadMu.Unlock()
}

// LoadEWMA reports the request-latency EWMA (seconds) for heartbeats.
func (s *Server) LoadEWMA() float64 { return s.load() }

func (s *Server) load() float64 {
	s.loadMu.Lock()
	defer s.loadMu.Unlock()
	return s.loadEWMA
}

func (s *Server) scrubCursor() string {
	if s.scrubber == nil {
		return ""
	}
	return s.scrubber.Cursor()
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, maxJSONBody+1))
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}

// binaryChecksum exposes the stored 32-byte digest as the wire uint64.
func binaryChecksum(sum [32]byte) uint64 {
	return shard.Sum64FromDigest(sum)
}

func allowedMethods(path string) string {
	switch {
	case strings.HasPrefix(path, "/v1/shards/"):
		return "GET, PUT, DELETE"
	case path == "/v1/shards:has", path == "/v1/scrub":
		return "POST"
	default:
		return "GET"
	}
}
