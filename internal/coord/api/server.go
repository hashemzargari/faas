// Package api is the coordinator's HTTP/JSON transport (docs/07-wire-api.md §1).
//
// It is deliberately thin: decode, call the contract.Coordinator implementation,
// encode. All business rules live in coord/meta/auth/membership/placement. The
// wire shapes in this package are the documented ones — the contract's types are
// the JSON format wherever docs/07 does not name the fields explicitly.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/coord"
	"github.com/fass-storage/fass/internal/coord/coerr"
	"github.com/fass-storage/fass/internal/coord/id"
	"github.com/fass-storage/fass/internal/coord/recovery"
	"github.com/fass-storage/fass/internal/storage"
)

// MaxJSONBody bounds non-streaming control-plane request bodies. A full-object
// commit carries a chunk table (≤ 60 slots per 16 MiB chunk), so it is allowed to
// be larger than a typical control request.
const MaxJSONBody = 64 << 20

// requestIDHeader is the correlation id every request carries (docs/07 §1).
const requestIDHeader = "X-Fass-Request-Id"

// Server is the coordinator HTTP handler.
type Server struct {
	svc     *coord.Service
	logger  *slog.Logger
	mux     *http.ServeMux
	metrics *metrics
	now     func() time.Time
	// gcStats, when set, exposes the deletion-GC executor counters on /metrics.
	gcStats func() map[string]int64
	// dbTimings exposes PostgreSQL statement timings for load-test attribution
	// (only set when the coordinator runs with --db-debug-timings).
	dbTimings func() any
	// repair is the repair-state authority backing GET /v1/repair/status and the
	// repair metrics. It is always non-nil so the endpoint works in every build.
	repair *recovery.Service
	// transport describes the listener's security state, reported by /healthz and
	// /readyz so operators never have to guess whether the control plane is
	// encrypted (same honesty rule as the repair endpoint's nulls).
	transport transportState
}

// transportState is the TLS/mTLS posture of the listener.
type transportState struct {
	tls      bool
	mtls     bool
	insecure bool
}

// New builds the HTTP server. The returned Handler is safe for concurrent Use.
func New(svc *coord.Service, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{
		svc:     svc,
		logger:  logger,
		mux:     http.NewServeMux(),
		metrics: newMetrics(),
		now:     time.Now,
		repair:  recovery.New(recovery.Config{Now: time.Now, Logger: logger}),
		// Direct api.New users (unit tests, in-process harnesses) are plaintext
		// until the process sets the real listener state.
		transport: transportState{insecure: true},
	}
	s.routes()
	return s
}

// SetGCStats registers the deletion-GC counter source exposed on /metrics.
func (s *Server) SetGCStats(fn func() map[string]int64) { s.gcStats = fn }

// SetDBTimings registers the optional PostgreSQL timing snapshot endpoint.
func (s *Server) SetDBTimings(fn func() any) { s.dbTimings = fn }

// SetRepair replaces the repair-state service (the coordinator configures the
// per-site budget and starts the background shard-set refresher on it).
func (s *Server) SetRepair(r *recovery.Service) {
	if r != nil {
		s.repair = r
	}
}

// Repair exposes the repair-state service.
func (s *Server) Repair() *recovery.Service { return s.repair }

// SetTransportSecurity records the listener's TLS posture for /healthz, /readyz
// and /v1/healthz. insecure is true only for a deliberate plaintext dev listener.
func (s *Server) SetTransportSecurity(tls, mtls, insecure bool) {
	s.transport = transportState{tls: tls, mtls: mtls, insecure: insecure}
}

// Handler returns the middleware-wrapped HTTP handler.
func (s *Server) Handler() http.Handler {
	return s.recoverer(s.requestID(s.instrument(s.mux)))
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.logger.Error("panic on request path", "panic", rec, "path", r.URL.Path, "stack", string(debug.Stack()))
				writeError(w, r, coerr.ErrInternal)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := r.Header.Get(requestIDHeader)
		if rid == "" || len(rid) > 128 {
			rid = id.New()
		}
		w.Header().Set(requestIDHeader, rid)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, rid)))
	})
}

type requestIDKey struct{}

func requestID(r *http.Request) string {
	if v, ok := r.Context().Value(requestIDKey{}).(string); ok {
		return v
	}
	return ""
}

func (s *Server) instrument(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		route := r.Pattern
		if route == "" {
			route = "unmatched"
		}
		s.metrics.observe(route, r.Method, sw.status, time.Since(start))
		s.logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"route", route,
			"status", sw.status,
			"bytes", sw.bytes,
			"duration_ms", float64(time.Since(start).Microseconds())/1000.0,
			"request_id", requestID(r),
		)
	})
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

type errorEnvelope struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

func writeJSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		writeError(w, r, fmt.Errorf("api: encode response: %w", err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

func writeError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, storage.ErrUnavailable) {
		// The metadata backend is unreachable (failover, pool exhausted). This is
		// retryable: answer 503 ServiceUnavailable, never a permanent-looking 500.
		err = coerr.E(503, coerr.CodeServiceUnavailable, "The metadata store is temporarily unavailable; retry the request")
	}
	e := coerr.From(err)
	// Log 5xx with the underlying cause; never leak it to the client.
	if e.Status >= 500 {
		slog.Default().Error("request failed", "code", e.Code, "err", err, "path", r.URL.Path, "request_id", requestID(r))
	}
	body := errorEnvelope{Error: errorBody{Code: e.Code, Message: coerr.MessageOf(err), RequestID: requestID(r)}}
	raw, merr := json.Marshal(body)
	if merr != nil {
		raw = []byte(`{"error":{"code":"InternalError","message":"internal error"}}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.Status)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(raw)
}

// readJSON decodes a bounded JSON body. Unknown fields are rejected so a gateway
// typo in a field name fails loudly instead of silently storing a zero value.
func readJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	defer r.Body.Close()
	body := http.MaxBytesReader(w, r.Body, MaxJSONBody)
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return coerr.Invalidf("request body is empty")
		}
		return coerr.Invalidf("invalid JSON body: %v", err)
	}
	return nil
}

type uploadPartsRequest struct {
	ETag       string                  `json:"etag"`
	Size       int64                   `json:"size"`
	Chunks     []contract.ChunkRef     `json:"chunks"`
	Encryption contract.EncryptionMeta `json:"encryption"`
}

// cleanBucket validates a bucket name from a path or query parameter.
func cleanBucket(name string) (string, error) {
	if name == "" {
		return "", coerr.Invalidf("bucket name is required")
	}
	if len(name) > 63 {
		return "", coerr.Invalidf("bucket name is too long")
	}
	return name, nil
}

// objectKey returns the object key from a path wildcard, honouring the documented
// rule that both %2F and raw slashes are accepted as part of the key.
func objectKey(r *http.Request) string {
	key := r.PathValue("key")
	if key == "" {
		return ""
	}
	if decoded, err := url.PathUnescape(key); err == nil {
		return decoded
	}
	return key
}

// objectSubresource splits a key wildcard into the object key and one of the
// docs/07 §1.4b subresources. Escaped slashes (%2F) always mean "part of the
// key", which is how a gateway disambiguates a key that literally ends in
// "/tags" from the tagging subresource.
func objectSubresource(r *http.Request) (key, sub string) {
	raw := r.PathValue("key")
	key = objectKey(r)
	escapedKeyPart := r.URL.EscapedPath()
	if i := strings.Index(escapedKeyPart, "/v1/objects/"); i >= 0 {
		rest := escapedKeyPart[i+len("/v1/objects/"):]
		if j := strings.Index(rest, "/"); j >= 0 {
			escapedKeyPart = rest[j+1:]
		} else {
			escapedKeyPart = ""
		}
	}
	if strings.Contains(strings.ToLower(escapedKeyPart), "%2f") {
		return key, ""
	}
	for _, suffix := range []string{"/tags", "/retention", "/legal-hold", "/acl"} {
		if strings.HasSuffix(key, suffix) && len(key) > len(suffix) {
			return strings.TrimSuffix(key, suffix), suffix[1:]
		}
	}
	_ = raw
	return key, ""
}

// objectVersion reads ?version= from the query.
func objectVersion(r *http.Request) contract.VersionID {
	return contract.VersionID(r.URL.Query().Get("version"))
}

// intQuery parses a bounded integer query parameter.
func intQuery(r *http.Request, name string, def int) (int, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def, nil
	}
	var n int
	if _, err := fmt.Sscanf(raw, "%d", &n); err != nil || n < 0 {
		return 0, coerr.Invalidf("query parameter %q must be a non-negative integer", name)
	}
	return n, nil
}

// boolQuery parses a presence-or-value boolean query parameter.
func boolQuery(r *http.Request, name string) bool {
	switch strings.ToLower(r.URL.Query().Get(name)) {
	case "", "0", "false", "no":
		return false
	}
	return true
}

// healthz answers both /healthz (docs/04) and /v1/healthz (docs/07),
// including the transport security state so "is this control-plane hop
// encrypted?" is answered by the endpoint instead of by documentation.
func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	body, err := s.svc.Health(r.Context())
	if err != nil {
		// Honesty over optimism: health must never claim ok while the system of
		// record is unreachable. 503 is what load balancers and operators expect.
		writeJSON(w, r, http.StatusServiceUnavailable, map[string]any{
			"status":   "unhealthy",
			"database": "unreachable",
			"tls":      s.transport.tls,
			"mtls":     s.transport.mtls,
			"insecure": s.transport.insecure,
			"error":    "metadata store unreachable; see coordinator logs",
		})
		return
	}
	if body == nil {
		body = map[string]any{}
	}
	body["tls"] = s.transport.tls
	body["mtls"] = s.transport.mtls
	body["insecure"] = s.transport.insecure
	writeJSON(w, r, http.StatusOK, body)
}
