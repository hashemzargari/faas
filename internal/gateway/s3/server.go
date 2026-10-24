// Package s3 implements the S3-compatible HTTP frontend: addressing, routing,
// the XML contract, request validation, and the operation handlers.
//
// The package is stateless. It talks to the coordinator for metadata and
// authorisation (contract.Coordinator), delegates payload movement to the
// offloader, and never touches a disk. See docs/05-s3-api.md for the operation
// matrix this package implements.
package s3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/ec"
	"github.com/fass-storage/fass/internal/gateway/authz"
	"github.com/fass-storage/fass/internal/gateway/metrics"
	"github.com/fass-storage/fass/internal/gateway/offloader"
	"github.com/fass-storage/fass/internal/gateway/sdp"
	"github.com/fass-storage/fass/internal/gateway/sigv4"
)

// Addressing selects path-style, virtual-hosted, or both.
type Addressing string

const (
	// AddressingPath accepts only /{bucket}/{key}.
	AddressingPath Addressing = "path"
	// AddressingVirtual accepts only {bucket}.{domain}/{key}.
	AddressingVirtual Addressing = "virtual"
	// AddressingBoth accepts both (virtual-hosted wins when the host matches).
	AddressingBoth Addressing = "both"
)

// Limits are the S3 limits from docs/05 §6.
type Limits struct {
	MaxObjectSize int64
	MaxSinglePut  int64
	PartSizeMin   int64
	PartSizeMax   int64
	MaxParts      int
	ListPageMax   int
	MaxKeyLength  int
	MaxUserMeta   int
	MaxTags       int
}

// DefaultLimits returns the documented defaults.
func DefaultLimits() Limits {
	return Limits{
		MaxObjectSize: 5 << 40, // 5 TiB
		MaxSinglePut:  5 << 30, // 5 GiB
		PartSizeMin:   5 << 20, // 5 MiB
		PartSizeMax:   5 << 30, // 5 GiB
		MaxParts:      10000,
		ListPageMax:   1000,
		MaxKeyLength:  1024,
		MaxUserMeta:   2 << 10,
		MaxTags:       10,
	}
}

// CompatConfig controls the deliberate divergences in docs/05 §9.
type CompatConfig struct {
	// VerifyChecksums enforces Content-MD5 and x-amz-checksum-* (D1).
	VerifyChecksums bool
	// ConditionalWrites honours If-Match / If-None-Match (D2).
	ConditionalWrites bool
	// RejectSSEC rejects SSE-C headers instead of ignoring them (D4).
	RejectSSEC bool
}

// DefaultCompat is the FASS behaviour: strict and safe.
func DefaultCompat() CompatConfig {
	return CompatConfig{VerifyChecksums: true, ConditionalWrites: true, RejectSSEC: true}
}

// Config is the static configuration of the frontend.
type Config struct {
	Region            string
	VirtualHostDomain string
	Addressing        Addressing
	// AllowAnonymous permits unsigned requests; authorisation is still enforced
	// by the coordinator (public-read ACLs work, everything else is denied).
	AllowAnonymous bool
	ServerVersion  string
	Limits         Limits
	Compat         CompatConfig
	// ChunkSize and DefaultParams describe the default redundancy class used
	// when no Smart Data Placement rule selects one.
	ChunkSize     int
	DefaultParams ec.Params
	DefaultRCID   string
	// ListPageMax bounds max-keys/max-parts values.
	ListPageMax int
}

// Deps are the server's collaborators.
type Deps struct {
	Coord   contract.Coordinator
	Authn   Authenticator
	Authz   Authorizer
	Off     offloader.Offloader
	SDP     *sdp.Engine
	Logger  *slog.Logger
	Metrics *metrics.Registry
	Config  Config
	Now     func() time.Time
}

// Authenticator identifies and verifies the caller. authz.Verifier implements it.
type Authenticator interface {
	Authenticate(ctx context.Context, r *http.Request) (authz.Identity, error)
}

// Authorizer evaluates authorisation decisions. authz.Verifier implements it.
type Authorizer interface {
	Authorize(ctx context.Context, id authz.Identity, action contract.Action, res contract.Resource, cond map[string]string) error
}

// Server is the S3 HTTP handler.
type Server struct {
	coord   contract.Coordinator
	authn   Authenticator
	authz   Authorizer
	off     offloader.Offloader
	sdp     *sdp.Engine
	log     *slog.Logger
	metrics *metrics.Registry
	cfg     Config
	now     func() time.Time
	limits  Limits
}

// New builds a Server. It panics only on programmer error (nil coordinator),
// never on a request path.
func New(d Deps) *Server {
	if d.Coord == nil {
		panic("s3: nil coordinator")
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	cfg := d.Config
	if cfg.Region == "" {
		cfg.Region = contract.DefaultRegion
	}
	if cfg.Addressing == "" {
		cfg.Addressing = AddressingBoth
	}
	if cfg.ServerVersion == "" {
		cfg.ServerVersion = "dev"
	}
	if cfg.Limits.MaxObjectSize == 0 {
		cfg.Limits = DefaultLimits()
	}
	if cfg.ChunkSize == 0 {
		cfg.ChunkSize = 16 << 20
	}
	if cfg.Compat == (CompatConfig{}) {
		cfg.Compat = DefaultCompat()
	}
	if cfg.ListPageMax == 0 {
		cfg.ListPageMax = cfg.Limits.ListPageMax
	}
	if cfg.DefaultParams == (ec.Params{}) {
		cfg.DefaultParams = ec.Params{GeoN: 2, GeoK: 1, LocalN: 16, LocalK: 4}
	}
	now := d.Now
	if now == nil {
		now = time.Now
	}
	return &Server{
		coord:   d.Coord,
		authn:   d.Authn,
		authz:   d.Authz,
		off:     d.Off,
		sdp:     d.SDP,
		log:     d.Logger,
		metrics: d.Metrics,
		cfg:     cfg,
		now:     now,
		limits:  cfg.Limits,
	}
}

// ---------------------------------------------------------------------------
// Request state
// ---------------------------------------------------------------------------

type ctxKey struct{}

type requestState struct {
	requestID string
	identity  authz.Identity
	op        operation
	started   time.Time
	// chunked is the aws-chunked body decoder, kept so trailers (e.g. flexible
	// checksums) can be verified before the object is committed.
	chunked *sigv4.ChunkedReader
}

func state(r *http.Request) *requestState {
	if st, ok := r.Context().Value(ctxKey{}).(*requestState); ok {
		return st
	}
	return &requestState{}
}

func requestIDFromRequest(r *http.Request) string {
	if st, ok := r.Context().Value(ctxKey{}).(*requestState); ok {
		return st.requestID
	}
	return ""
}

// ---------------------------------------------------------------------------
// HTTP entry point
// ---------------------------------------------------------------------------

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := s.now()
	st := &requestState{requestID: authz.RequestID(), started: start}
	w.Header().Set("x-amz-request-id", st.requestID)
	w.Header().Set("x-amz-id-2", st.requestID)
	w.Header().Set("Server", "fass/"+s.cfg.ServerVersion)
	r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, st))

	rec := &statusRecorder{ResponseWriter: w}
	defer s.recoverPanic(rec, r)

	target, err := s.parseTarget(r)
	if err != nil {
		s.fail(rec, r, err)
		return
	}
	op := resolveOperation(r, target)
	st.op = op

	if op == opUnsupported {
		s.fail(rec, r, ErrNotImplemented.withMessage("The requested operation is not supported by this S3 implementation."))
		s.observe(st, rec, target)
		return
	}

	identity, authErr := s.authenticate(r)
	if authErr != nil {
		s.fail(rec, r, authErr)
		s.observe(st, rec, target)
		return
	}
	st.identity = identity
	r, err = s.decodeStreamingBody(r, identity)
	if err != nil {
		s.fail(rec, r, err)
		s.observe(st, rec, target)
		return
	}

	s.dispatch(rec, r, target, op)
	s.observe(st, rec, target)
}

// authenticate resolves the caller, allowing anonymous access only when
// configured and only through the normal ACL evaluation (the handler enforces
// that).
func (s *Server) authenticate(r *http.Request) (authz.Identity, error) {
	if s.authn == nil {
		return authz.Identity{Principal: authz.Anonymous(), Anonymous: true}, nil
	}
	id, err := s.authn.Authenticate(r.Context(), r)
	if err == nil {
		return id, nil
	}
	if errors.Is(err, authz.ErrUnsigned) && s.cfg.AllowAnonymous {
		return authz.Identity{Principal: authz.Anonymous(), Anonymous: true}, nil
	}
	return authz.Identity{}, err
}

// decodeStreamingBody wraps an aws-chunked body in a verifying reader.
func (s *Server) decodeStreamingBody(r *http.Request, id authz.Identity) (*http.Request, error) {
	if id.Streaming == nil {
		return r, nil
	}
	cr, err := sigv4.NewChunkedReader(r.Body, sigv4.ChunkedOptions{
		Kind:          id.Streaming.Kind,
		SeedSignature: id.Streaming.SeedSignature,
		SigningKey:    id.Streaming.SigningKey,
		AmzDate:       id.Streaming.AmzDate,
		Scope:         id.Streaming.Scope,
		MaxChunkBytes: int(s.limits.MaxSinglePut),
	})
	if err != nil {
		return r, ErrInvalidRequest.withMessage("%s", err.Error())
	}
	r.Body = io.NopCloser(cr)
	state(r).chunked = cr
	if n := r.Header.Get("x-amz-decoded-content-length"); n != "" {
		size, perr := strconv.ParseInt(n, 10, 64)
		if perr != nil || size < 0 {
			return r, ErrInvalidArgument.withMessage("Invalid x-amz-decoded-content-length.")
		}
		r.ContentLength = size
	}
	return r, nil
}

// recoverPanic guarantees a 500 rather than a broken connection if a handler
// has a bug. Request paths must not panic; this is a backstop.
func (s *Server) recoverPanic(w *statusRecorder, r *http.Request) {
	rec := recover()
	if rec == nil {
		return
	}
	s.log.Error("panic serving s3 request",
		"request_id", requestIDFromRequest(r),
		"method", r.Method, "path", r.URL.Path,
		"panic", fmt.Sprint(rec),
		"stack", string(debug.Stack()))
	if !w.wroteHeader {
		writeErrorResponse(w, r, ErrInternalError)
	}
}

// observe records metrics and a structured access log line.
func (s *Server) observe(st *requestState, rec *statusRecorder, target target) {
	elapsed := s.now().Sub(st.started)
	code := rec.status
	if code == 0 {
		code = http.StatusOK
	}
	if s.metrics != nil {
		s.metrics.Inc("fass_gateway_requests_total", map[string]string{
			"op":     string(st.op),
			"status": strconv.Itoa(code),
		})
		s.metrics.Add("fass_gateway_response_bytes_total", map[string]string{"op": string(st.op)}, uint64(rec.written))
		s.metrics.SetGauge("fass_gateway_request_duration_seconds_last", map[string]string{"op": string(st.op)}, elapsed.Seconds())
	}
	s.log.Debug("s3 request",
		"request_id", st.requestID,
		"op", string(st.op),
		"bucket", target.Bucket,
		"key", target.Key,
		"status", code,
		"duration_ms", elapsed.Milliseconds(),
	)
}

// fail renders an error response.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	writeErrorResponse(w, r, err)
	if r != nil {
		if api := mapError(err); api.Status >= 500 {
			s.log.Error("s3 request failed", "request_id", requestIDFromRequest(r),
				"method", r.Method, "path", r.URL.Path, "error", err.Error())
		}
	}
}

// ---------------------------------------------------------------------------
// Addressing
// ---------------------------------------------------------------------------

type target struct {
	Bucket        string
	Key           string
	VirtualHosted bool
}

func (t target) hasBucket() bool { return t.Bucket != "" }

// parseTarget resolves path-style vs virtual-hosted addressing.
func (s *Server) parseTarget(r *http.Request) (target, error) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))

	if s.cfg.Addressing != AddressingPath {
		domain := strings.ToLower(strings.TrimSuffix(s.cfg.VirtualHostDomain, "."))
		if domain != "" && host != domain && strings.HasSuffix(host, "."+domain) {
			bucket := strings.TrimSuffix(host, "."+domain)
			if bucket == "" {
				return target{}, ErrInvalidBucketName
			}
			return target{
				Bucket:        bucket,
				Key:           strings.TrimPrefix(r.URL.Path, "/"),
				VirtualHosted: true,
			}, nil
		}
	}
	if s.cfg.Addressing == AddressingVirtual {
		return target{}, ErrMethodNotAllowed.withMessage("Path-style addressing is disabled on this endpoint.")
	}

	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		return target{}, nil
	}
	bucket, key, _ := strings.Cut(path, "/")
	return target{Bucket: bucket, Key: key}, nil
}

// ---------------------------------------------------------------------------
// Helpers shared by handlers
// ---------------------------------------------------------------------------

func (s *Server) region() string {
	if s.cfg.Region != "" {
		return s.cfg.Region
	}
	return contract.DefaultRegion
}

// ownerID is the canonical owner id used in ACLs and x-amz-expected-bucket-owner.
// FASS models one project per bucket, so the project id is the owner.
func ownerID(b contract.BucketConfig) string {
	if b.ProjectID != "" {
		return string(b.ProjectID)
	}
	return string(b.TenantID)
}

// loadBucket fetches a bucket, enforcing existence and the expected-owner
// header. Errors are already S3 API errors.
func (s *Server) loadBucket(r *http.Request, name string) (contract.BucketConfig, error) {
	if err := validateBucketName(name); err != nil {
		return contract.BucketConfig{}, err
	}
	b, err := s.coord.GetBucket(r.Context(), name)
	if err != nil {
		if errors.Is(err, contract.ErrNotFound) {
			return contract.BucketConfig{}, ErrNoSuchBucket
		}
		return contract.BucketConfig{}, mapError(err)
	}
	if expected := r.Header.Get("x-amz-expected-bucket-owner"); expected != "" && expected != ownerID(b) {
		return contract.BucketConfig{}, ErrAccessDenied
	}
	return b, nil
}

// authorize evaluates one action against the CRN of the target resource.
func (s *Server) authorize(r *http.Request, id authz.Identity, action contract.Action, b *contract.BucketConfig, bucket, key string, cond map[string]string) error {
	res := contract.Resource{Region: s.region(), Bucket: bucket, Key: key}
	if key == "" {
		res.Kind = "bucket"
	} else {
		res.Kind = "object"
	}
	if b != nil {
		res.TenantID = b.TenantID
		res.ProjectID = b.ProjectID
	} else {
		res.TenantID = id.Principal.TenantID
		res.ProjectID = id.Principal.ProjectID
	}
	if s.authz == nil {
		return nil
	}
	return s.authz.Authorize(r.Context(), id, action, res, cond)
}

func (s *Server) authorizeBucket(r *http.Request, action contract.Action, b contract.BucketConfig, key string, cond map[string]string) error {
	return s.authorize(r, state(r).identity, action, &b, b.Name, key, cond)
}

// principal returns the request identity.
func (s *Server) principal(r *http.Request) authz.Identity { return state(r).identity }

// validateBucketName enforces the S3 bucket naming rules.
func validateBucketName(name string) error {
	if len(name) < 3 || len(name) > 63 {
		return ErrInvalidBucketName
	}
	prevDot := false
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			prevDot = false
		case c == '-':
			if i == 0 || i == len(name)-1 {
				return ErrInvalidBucketName
			}
			prevDot = false
		case c == '.':
			if i == 0 || i == len(name)-1 || prevDot || name[i-1] == '-' {
				return ErrInvalidBucketName
			}
			prevDot = true
		default:
			return ErrInvalidBucketName
		}
	}
	// Reject IP-address-shaped names.
	if ip := net.ParseIP(name); ip != nil {
		return ErrInvalidBucketName
	}
	return nil
}

// validateKey enforces the documented key length limit.
func (s *Server) validateKey(key string) error {
	if key == "" {
		return ErrInvalidArgument.withMessage("The object key must not be empty.")
	}
	if len(key) > s.limits.MaxKeyLength {
		return ErrKeyTooLong
	}
	return nil
}

// intParam parses an integer query parameter within bounds.
func intParam(r *http.Request, name string, def, min, max int) (int, *APIError) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < min {
		return 0, ErrInvalidArgument.withMessage("Invalid value for %s.", name)
	}
	if max > 0 && n > max {
		n = max
	}
	return n, nil
}

// pagingParams parses max-keys/max-parts with the documented defaults.
func (s *Server) pagingParams(r *http.Request, name string, def int) (int, *APIError) {
	return intParam(r, name, def, 0, s.cfg.ListPageMax)
}

// urlQueryUnescape decodes a single query component.
func urlQueryUnescape(s string) (string, error) { return url.QueryUnescape(s) }

// statusRecorder captures the status code and byte count for logs and metrics.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	written     int64
	wroteHeader bool
}

func (w *statusRecorder) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.status = code
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusRecorder) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(b)
	w.written += int64(n)
	return n, err
}

// Flush forwards to the wrapped writer when it supports flushing (streamed GETs).
func (w *statusRecorder) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *statusRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// sortedKeys returns map keys in deterministic order.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
