// Package coordclient is the gateway's HTTP client for the coordinator's
// control plane (docs/07-wire-api.md §1).
//
// It implements contract.Coordinator directly over the wire format: the contract
// types are the JSON payloads (they carry snake_case tags), so there are no
// parallel request/response structs here except the tiny envelopes the wire API
// specifies.
package coordclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fass-storage/fass/internal/contract"
)

// Options configures the client.
type Options struct {
	// BaseURL is the coordinator HTTP endpoint, e.g. http://127.0.0.1:7001.
	BaseURL string
	// HTTPClient may be nil (a sensible default is created).
	HTTPClient *http.Client
	// Timeout bounds a single control-plane call. Defaults to 10 s.
	Timeout time.Duration
	// UserAgent is sent as User-Agent.
	UserAgent string
	// AdaptiveRetries retries idempotent GETs on transport errors.
	AdaptiveRetries int
}

// Client implements contract.Coordinator over HTTP.
type Client struct {
	base    string
	hc      *http.Client
	timeout time.Duration
	ua      string
	retries int
	reqSeq  atomic.Uint64
}

var _ contract.Coordinator = (*Client)(nil)

// APIError is a non-2xx coordinator response. It maps onto contract sentinels so
// callers can use errors.Is across the boundary.
type APIError struct {
	Status  int    `json:"-"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Error implements error.
func (e *APIError) Error() string {
	return fmt.Sprintf("coordinator: %s (HTTP %d): %s", e.Code, e.Status, e.Message)
}

// HTTPStatus exposes the status so the S3 edge can preserve 405/409 semantics.
func (e *APIError) HTTPStatus() int { return e.Status }

// ErrorCode exposes the coordinator's own error code so the S3 edge can surface
// typed validation errors (e.g. InvalidRequest) instead of a generic 500.
func (e *APIError) ErrorCode() string { return e.Code }

// ErrorMessage exposes the coordinator's message for the same reason.
func (e *APIError) ErrorMessage() string { return e.Message }

// Is maps coordinator error codes onto the shared sentinels.
func (e *APIError) Is(target error) bool {
	switch target {
	case contract.ErrNotFound:
		return e.Status == http.StatusNotFound
	case contract.ErrAlreadyExists:
		return e.Status == http.StatusConflict && strings.Contains(strings.ToLower(e.Code), "already")
	case contract.ErrConflict:
		return e.Status == http.StatusConflict
	case contract.ErrForbidden:
		return e.Status == http.StatusForbidden
	case contract.ErrPrecondition:
		return e.Status == http.StatusPreconditionFailed
	case contract.ErrNotImplemented:
		return e.Status == http.StatusNotImplemented
	case contract.ErrUnavailable:
		return e.Status == http.StatusServiceUnavailable || e.Status == http.StatusBadGateway || e.Status == http.StatusGatewayTimeout
	case contract.ErrInsufficientCap:
		return e.Status == http.StatusInsufficientStorage
	}
	return false
}

// New builds a client.
func New(opts Options) (*Client, error) {
	if opts.BaseURL == "" {
		return nil, errors.New("coordclient: base URL is required")
	}
	base := strings.TrimRight(opts.BaseURL, "/")
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("coordclient: invalid base URL %q", opts.BaseURL)
	}
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Transport: &http.Transport{
			MaxIdleConns:        64,
			MaxIdleConnsPerHost: 32,
			IdleConnTimeout:     90 * time.Second,
		}}
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ua := opts.UserAgent
	if ua == "" {
		ua = "fass-gateway"
	}
	return &Client{base: base, hc: hc, timeout: timeout, ua: ua, retries: opts.AdaptiveRetries}, nil
}

// ---------------------------------------------------------------------------
// transport
// ---------------------------------------------------------------------------

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf("coordclient: encode request: %w", err)
		}
	}
	target := c.base + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}

	var lastErr error
	attempts := 1
	if c.retries > 0 && (method == http.MethodGet || method == http.MethodHead) {
		attempts += c.retries
	}
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * 100 * time.Millisecond):
			}
		}
		lastErr = c.doOnce(ctx, method, target, payload, out)
		if lastErr == nil {
			return nil
		}
		var api *APIError
		if errors.As(lastErr, &api) {
			return lastErr // server rejected the request; retrying will not help
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return lastErr
}

func (c *Client) doOnce(ctx context.Context, method, target string, payload []byte, out any) error {
	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	var reader io.Reader
	if payload != nil {
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(callCtx, method, target, reader)
	if err != nil {
		return fmt.Errorf("coordclient: build request: %w", err)
	}
	req.Header.Set("X-Fass-Request-Id", requestID(c.reqSeq.Add(1)))
	req.Header.Set("User-Agent", c.ua)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("coordclient: %s %s: %w", method, target, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		api := &APIError{Status: resp.StatusCode}
		var env struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(raw, &env) == nil && env.Error.Code != "" {
			api.Code, api.Message = env.Error.Code, env.Error.Message
		} else {
			api.Code = http.StatusText(resp.StatusCode)
			api.Message = strings.TrimSpace(string(raw))
		}
		return api
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("coordclient: decode %s %s response: %w", method, target, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Authorizer
// ---------------------------------------------------------------------------

// VerifySignature resolves an access key id to a principal and HMAC secret.
func (c *Client) VerifySignature(ctx context.Context, accessKeyID string) (contract.Principal, []byte, error) {
	var out struct {
		Principal contract.Principal `json:"principal"`
		HMACKey   string             `json:"hmac_key"`
	}
	path := "/v1/auth/keys/" + url.PathEscape(accessKeyID)
	if err := c.do(ctx, http.MethodPost, path, nil, nil, &out); err != nil {
		return contract.Principal{}, nil, err
	}
	secret, err := base64.StdEncoding.DecodeString(out.HMACKey)
	if err != nil {
		// Accept hex for robustness across coordinator builds.
		secret, err = hex.DecodeString(out.HMACKey)
		if err != nil {
			return contract.Principal{}, nil, fmt.Errorf("coordclient: invalid hmac_key encoding: %w", err)
		}
	}
	return out.Principal, secret, nil
}

// Authorize evaluates the policy chain.
func (c *Client) Authorize(ctx context.Context, rc contract.RequestContext) (contract.Decision, error) {
	req := struct {
		Principal  contract.Principal `json:"principal"`
		Action     contract.Action    `json:"action"`
		Resource   contract.Resource  `json:"resource"`
		SourceIP   string             `json:"source_ip,omitempty"`
		Conditions map[string]string  `json:"conditions,omitempty"`
	}{rc.Principal, rc.Action, rc.Resource, rc.SourceIP, rc.Condition}
	var out struct {
		Allowed bool   `json:"allowed"`
		Reason  string `json:"reason"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/auth/authorize", nil, req, &out); err != nil {
		return contract.Decision{}, err
	}
	return contract.Decision{Allowed: out.Allowed, Reason: out.Reason}, nil
}

// ---------------------------------------------------------------------------
// Buckets
// ---------------------------------------------------------------------------

func (c *Client) GetBucket(ctx context.Context, bucket string) (contract.BucketConfig, error) {
	var out contract.BucketConfig
	err := c.do(ctx, http.MethodGet, "/v1/buckets/"+url.PathEscape(bucket), nil, nil, &out)
	return out, err
}

func (c *Client) CreateBucket(ctx context.Context, b contract.BucketConfig) error {
	return c.do(ctx, http.MethodPost, "/v1/buckets", nil, b, nil)
}

func (c *Client) UpdateBucketConfig(ctx context.Context, b contract.BucketConfig) error {
	// The coordinator's PATCH endpoint accepts only mutable fields and rejects
	// unknown ones, so send the documented patch shape rather than a full
	// BucketConfig.
	patch := struct {
		Versioning  *string `json:"versioning,omitempty"`
		Ownership   *string `json:"ownership,omitempty"`
		ObjectLock  *bool   `json:"object_lock,omitempty"`
		DefaultRCID *string `json:"default_rc_id,omitempty"`
		QuotaBytes  *int64  `json:"quota_bytes,omitempty"`
	}{}
	if b.Versioning != "" {
		patch.Versioning = &b.Versioning
	}
	if b.Ownership != "" {
		patch.Ownership = &b.Ownership
	}
	if b.ObjectLock {
		patch.ObjectLock = &b.ObjectLock
	}
	if b.DefaultRCID != "" {
		patch.DefaultRCID = &b.DefaultRCID
	}
	if b.QuotaBytes != 0 {
		patch.QuotaBytes = &b.QuotaBytes
	}
	return c.do(ctx, http.MethodPatch, "/v1/buckets/"+url.PathEscape(b.Name), nil, patch, nil)
}

func (c *Client) DeleteBucket(ctx context.Context, bucket string) error {
	return c.do(ctx, http.MethodDelete, "/v1/buckets/"+url.PathEscape(bucket), nil, nil, nil)
}

func (c *Client) ListBuckets(ctx context.Context, p contract.Principal) ([]contract.BucketConfig, error) {
	q := url.Values{}
	if p.TenantID != "" {
		q.Set("tenant_id", string(p.TenantID))
		q.Set("project_id", string(p.ProjectID))
	}
	var out struct {
		Buckets []contract.BucketConfig `json:"buckets"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/buckets", q, nil, &out)
	return out.Buckets, err
}

func (c *Client) GetBucketACL(ctx context.Context, bucket string) (contract.ACL, error) {
	var out contract.ACL
	err := c.do(ctx, http.MethodGet, "/v1/buckets/"+url.PathEscape(bucket)+"/acl", nil, nil, &out)
	return out, err
}

func (c *Client) PutBucketACL(ctx context.Context, bucket string, acl contract.ACL) error {
	return c.do(ctx, http.MethodPut, "/v1/buckets/"+url.PathEscape(bucket)+"/acl", nil, acl, nil)
}

func (c *Client) GetBucketLifecycle(ctx context.Context, bucket string) ([]byte, error) {
	target := c.base + "/v1/buckets/" + url.PathEscape(bucket) + "/lifecycle"
	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(callCtx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Fass-Request-Id", requestID(c.reqSeq.Add(1)))
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("coordclient: get lifecycle: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, &APIError{Status: resp.StatusCode, Code: "NoSuchLifecycleConfiguration", Message: "lifecycle not configured"}
	}
	if resp.StatusCode >= 400 {
		return nil, &APIError{Status: resp.StatusCode, Code: http.StatusText(resp.StatusCode)}
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func (c *Client) PutBucketLifecycle(ctx context.Context, bucket string, xml []byte) error {
	target := c.base + "/v1/buckets/" + url.PathEscape(bucket) + "/lifecycle"
	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(callCtx, http.MethodPut, target, bytes.NewReader(xml))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("X-Fass-Request-Id", requestID(c.reqSeq.Add(1)))
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("coordclient: put lifecycle: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return &APIError{Status: resp.StatusCode, Code: http.StatusText(resp.StatusCode)}
	}
	return nil
}

func (c *Client) DeleteBucketLifecycle(ctx context.Context, bucket string) error {
	return c.do(ctx, http.MethodDelete, "/v1/buckets/"+url.PathEscape(bucket)+"/lifecycle", nil, nil, nil)
}

// ---------------------------------------------------------------------------
// Objects
// ---------------------------------------------------------------------------

func (c *Client) ResolvePlacement(ctx context.Context, req contract.PlacementRequest) (contract.Placement, error) {
	var out contract.Placement
	err := c.do(ctx, http.MethodPost, "/v1/placement", nil, req, &out)
	return out, err
}

func (c *Client) CommitObject(ctx context.Context, req contract.CommitRequest) (contract.CommitResult, error) {
	var out struct {
		VersionID contract.VersionID `json:"version_id"`
		ETag      string             `json:"etag"`
	}
	err := c.do(ctx, http.MethodPost, "/v1/objects:commit", nil, req, &out)
	return contract.CommitResult{VersionID: out.VersionID, ETag: out.ETag}, err
}

func (c *Client) GetManifest(ctx context.Context, bucket, key string, version contract.VersionID) (contract.Manifest, error) {
	var out contract.Manifest
	q := url.Values{}
	if version != "" {
		q.Set("version", string(version))
	}
	err := c.do(ctx, http.MethodGet, objectPath(bucket, key), q, nil, &out)
	return out, err
}

func (c *Client) DeleteObject(ctx context.Context, bucket, key string, version contract.VersionID, bypassGovernance bool) (contract.VersionID, bool, error) {
	q := url.Values{}
	if version != "" {
		q.Set("version", string(version))
	}
	if bypassGovernance {
		q.Set("bypass", "true")
	}
	var out struct {
		VersionID    contract.VersionID `json:"version_id"`
		DeleteMarker bool               `json:"delete_marker"`
	}
	err := c.do(ctx, http.MethodDelete, objectPath(bucket, key), q, nil, &out)
	return out.VersionID, out.DeleteMarker, err
}

func (c *Client) ListObjects(ctx context.Context, req contract.ListRequest) (contract.ListResult, error) {
	q := url.Values{}
	q.Set("bucket_id", string(req.BucketID))
	if req.Prefix != "" {
		q.Set("prefix", req.Prefix)
	}
	if req.Delimiter != "" {
		q.Set("delimiter", req.Delimiter)
	}
	// Always send the value verbatim: the S3 handler applies the default when the
	// client omits max-keys, so 0 here means an explicit empty page. The
	// coordinator treats negative as unset.
	q.Set("max_keys", strconv.Itoa(req.MaxKeys))
	if req.StartAfter != "" {
		q.Set("start_after", req.StartAfter)
	}
	if req.ContinuationToken != "" {
		q.Set("token", req.ContinuationToken)
	}
	if req.Versions {
		q.Set("versions", "true")
	}
	if req.KeyMarker != "" {
		q.Set("key_marker", req.KeyMarker)
	}
	if req.VersionIDMarker != "" {
		q.Set("version_id_marker", req.VersionIDMarker)
	}
	var out contract.ListResult
	err := c.do(ctx, http.MethodGet, "/v1/objects", q, nil, &out)
	return out, err
}

// ---------------------------------------------------------------------------
// Object sub-resources
// ---------------------------------------------------------------------------

// objectSubresources are the docs/07 §1.4b sub-resources. The coordinator
// disambiguates a key that literally ends in one of these words by
// percent-encoding its slashes.
var objectSubresources = []string{"tags", "retention", "legal-hold", "acl"}

// objectPath keeps slashes raw (the coordinator accepts raw slashes as part of
// the key) but escapes the whole key when it could be mistaken for a
// sub-resource path.
func objectPath(bucket, key string) string {
	escaped := strings.ReplaceAll(url.PathEscape(key), "%2F", "/")
	for _, sub := range objectSubresources {
		if strings.HasSuffix(key, "/"+sub) {
			escaped = url.PathEscape(key)
			break
		}
	}
	return "/v1/objects/" + url.PathEscape(bucket) + "/" + escaped
}

// objectSubPath addresses a sub-resource. Slashes in the key stay literal so the
// coordinator's suffix split recovers the full key; the trailing /<sub> is what
// marks the sub-resource.
func objectSubPath(bucket, key, sub string) string {
	return "/v1/objects/" + url.PathEscape(bucket) + "/" +
		strings.ReplaceAll(url.PathEscape(key), "%2F", "/") + "/" + sub
}

func (c *Client) GetObjectTags(ctx context.Context, bucket, key string, v contract.VersionID) (map[string]string, error) {
	q := versionQuery(v)
	var out struct {
		Tags map[string]string `json:"tags"`
	}
	err := c.do(ctx, http.MethodGet, objectSubPath(bucket, key, "tags"), q, nil, &out)
	return out.Tags, err
}

func (c *Client) PutObjectTags(ctx context.Context, bucket, key string, v contract.VersionID, tags map[string]string) error {
	body := struct {
		Tags map[string]string `json:"tags"`
	}{Tags: tags}
	return c.do(ctx, http.MethodPut, objectSubPath(bucket, key, "tags"), versionQuery(v), body, nil)
}

func (c *Client) GetObjectRetention(ctx context.Context, bucket, key string, v contract.VersionID) (*contract.Retention, error) {
	var out contract.Retention
	err := c.do(ctx, http.MethodGet, objectSubPath(bucket, key, "retention"), versionQuery(v), nil, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) PutObjectRetention(ctx context.Context, bucket, key string, v contract.VersionID, r *contract.Retention) error {
	return c.do(ctx, http.MethodPut, objectSubPath(bucket, key, "retention"), versionQuery(v), r, nil)
}

func (c *Client) GetObjectACL(ctx context.Context, bucket, key string, v contract.VersionID) (contract.ACL, error) {
	var out contract.ACL
	err := c.do(ctx, http.MethodGet, objectSubPath(bucket, key, "acl"), versionQuery(v), nil, &out)
	return out, err
}

func (c *Client) PutObjectACL(ctx context.Context, bucket, key string, v contract.VersionID, acl contract.ACL) error {
	return c.do(ctx, http.MethodPut, objectSubPath(bucket, key, "acl"), versionQuery(v), acl, nil)
}

func versionQuery(v contract.VersionID) url.Values {
	q := url.Values{}
	if v != "" {
		q.Set("version", string(v))
	}
	return q
}

// ---------------------------------------------------------------------------
// Multipart
// ---------------------------------------------------------------------------

func (c *Client) CreateUpload(ctx context.Context, bucket, key string, meta contract.CommitRequest) (contract.UploadID, error) {
	req := struct {
		Bucket string                 `json:"bucket"`
		Key    string                 `json:"key"`
		Meta   contract.CommitRequest `json:"meta"`
	}{bucket, key, meta}
	var out struct {
		UploadID contract.UploadID `json:"upload_id"`
	}
	err := c.do(ctx, http.MethodPost, "/v1/uploads", nil, req, &out)
	return out.UploadID, err
}

func (c *Client) CommitPart(ctx context.Context, up contract.UploadID, partNumber int, etag string, size int64, chunks []contract.ChunkRef, enc contract.EncryptionMeta) error {
	req := struct {
		ETag       string                  `json:"etag"`
		Size       int64                   `json:"size"`
		Chunks     []contract.ChunkRef     `json:"chunks"`
		Encryption contract.EncryptionMeta `json:"encryption"`
	}{etag, size, chunks, enc}
	path := "/v1/uploads/" + url.PathEscape(string(up)) + "/parts/" + strconv.Itoa(partNumber)
	return c.do(ctx, http.MethodPut, path, nil, req, nil)
}

func (c *Client) ListParts(ctx context.Context, up contract.UploadID) ([]contract.PartInfo, error) {
	var out struct {
		Parts []contract.PartInfo `json:"parts"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/uploads/"+url.PathEscape(string(up))+"/parts", nil, nil, &out)
	return out.Parts, err
}

func (c *Client) ListUploads(ctx context.Context, bucketID contract.BucketID) ([]contract.UploadInfo, error) {
	q := url.Values{"bucket_id": []string{string(bucketID)}}
	var out struct {
		Uploads []contract.UploadInfo `json:"uploads"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/uploads", q, nil, &out)
	return out.Uploads, err
}

func (c *Client) CompleteUpload(ctx context.Context, up contract.UploadID) (contract.CommitResult, error) {
	var out struct {
		VersionID contract.VersionID `json:"version_id"`
		ETag      string             `json:"etag"`
	}
	err := c.do(ctx, http.MethodPost, "/v1/uploads/"+url.PathEscape(string(up))+":complete", nil, nil, &out)
	return contract.CommitResult{VersionID: out.VersionID, ETag: out.ETag}, err
}

func (c *Client) AbortUpload(ctx context.Context, up contract.UploadID) error {
	return c.do(ctx, http.MethodDelete, "/v1/uploads/"+url.PathEscape(string(up)), nil, nil, nil)
}

// ---------------------------------------------------------------------------
// Agent/repair methods: the gateway does not call these. They are implemented as
// explicit errors so a future caller fails loudly rather than silently.
// ---------------------------------------------------------------------------

func (c *Client) Announce(ctx context.Context, a contract.AnnounceRequest) (contract.AnnounceResult, error) {
	return contract.AnnounceResult{}, fmt.Errorf("coordclient: announce is agent-only: %w", contract.ErrNotImplemented)
}

func (c *Client) Heartbeat(ctx context.Context, hb contract.Heartbeat) error {
	return fmt.Errorf("coordclient: heartbeat is agent-only: %w", contract.ErrNotImplemented)
}

func (c *Client) ReportShardStatus(ctx context.Context, r []contract.ShardStatus) error {
	return fmt.Errorf("coordclient: shard status is agent-only: %w", contract.ErrNotImplemented)
}

func (c *Client) ClaimRepairJob(ctx context.Context, worker string) (*contract.RepairJob, error) {
	return nil, fmt.Errorf("coordclient: repair jobs are agent-only: %w", contract.ErrNotImplemented)
}

func (c *Client) CommitRepair(ctx context.Context, r contract.RepairResult) error {
	return fmt.Errorf("coordclient: repair commits are agent-only: %w", contract.ErrNotImplemented)
}

// requestID builds a lightweight unique request id.
func requestID(seq uint64) string {
	var b [12]byte
	b[0] = byte(seq >> 32)
	b[1] = byte(seq >> 24)
	b[2] = byte(seq >> 16)
	b[3] = byte(seq >> 8)
	b[4] = byte(seq)
	if _, err := rand.Read(b[5:]); err != nil {
		return "req-" + strconv.FormatUint(seq, 10)
	}
	return hex.EncodeToString(b[:])
}
