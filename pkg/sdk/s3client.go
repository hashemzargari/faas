// Package sdk is the Go client for FASS.
//
// v1 is a minimal, dependency-free S3 client (SigV4/SigV2, presigned URLs)
// used by the CLI and the end-to-end suite. Zero-knowledge client-side
// encryption lands here in v1.1 — in that mode the client, not the gateway,
// owns key material.
package sdk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fass-storage/fass/internal/gateway/sigv4"
)

// Client talks to one FASS gateway endpoint.
type Client struct {
	Endpoint *url.URL
	Region   string
	AK       string
	SK       string
	HTTP     *http.Client

	// UnsignedPayload sends "UNSIGNED-PAYLOAD" instead of a content hash, which
	// avoids buffering large uploads. Disabled by default so the gateway can
	// verify payload integrity end to end.
	UnsignedPayload bool

	// PathStyle always addresses /{bucket}/{key}. FASS supports virtual-hosted
	// style too, but path style works for any endpoint (including localhost).
	PathStyle bool
}

// Option customises a Client.
type Option func(*Client)

// WithHTTPClient injects a caller-controlled HTTP client.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.HTTP = h } }

// WithUnsignedPayload avoids buffering request bodies for the signature.
func WithUnsignedPayload() Option { return func(c *Client) { c.UnsignedPayload = true } }

// New builds a client. endpoint may omit the scheme (https is assumed).
func New(endpoint, region, accessKey, secretKey string, opts ...Option) (*Client, error) {
	if !strings.Contains(endpoint, "://") {
		endpoint = "https://" + endpoint
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("sdk: bad endpoint: %w", err)
	}
	if region == "" {
		region = "eu-west-1"
	}
	c := &Client{
		Endpoint:  u,
		Region:    region,
		AK:        accessKey,
		SK:        secretKey,
		HTTP:      &http.Client{Timeout: 5 * time.Minute},
		PathStyle: true,
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// Object is a listing entry.
type Object struct {
	Key          string
	Size         int64
	ETag         string
	LastModified time.Time
}

// Bucket is a bucket entry.
type Bucket struct {
	Name         string
	CreationDate time.Time
}

// Error is an S3 error response.
type Error struct {
	StatusCode int
	Code       string
	Message    string
	RequestID  string
	Resource   string
}

func (e *Error) Error() string {
	return fmt.Sprintf("s3: %s (%d): %s", e.Code, e.StatusCode, e.Message)
}

// IsNoSuchKey reports whether err is a missing-object error.
func IsNoSuchKey(err error) bool {
	var se *Error
	if ok := asError(err, &se); ok {
		return se.Code == "NoSuchKey" || se.Code == "NoSuchBucket"
	}
	return false
}

// asError is a tiny errors.As without importing errors twice in call sites.
func asError(err error, target **Error) bool {
	for err != nil {
		if e, ok := err.(*Error); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// ListBuckets issues GET /.
func (c *Client) ListBuckets(ctx context.Context) ([]Bucket, error) {
	resp, err := c.do(ctx, http.MethodGet, "/", nil, nil, 0, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := check(resp); err != nil {
		return nil, err
	}
	var out struct {
		Buckets []struct {
			Name         string `xml:"Name"`
			CreationDate string `xml:"CreationDate"`
		} `xml:"Buckets>Bucket"`
	}
	if err := xml.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("sdk: decode ListBuckets: %w", err)
	}
	bs := make([]Bucket, 0, len(out.Buckets))
	for _, b := range out.Buckets {
		t, _ := time.Parse(time.RFC3339, b.CreationDate)
		bs = append(bs, Bucket{Name: b.Name, CreationDate: t})
	}
	return bs, nil
}

// CreateBucket issues PUT /{bucket}.
func (c *Client) CreateBucket(ctx context.Context, bucket string) error {
	resp, err := c.do(ctx, http.MethodPut, "/"+bucket, nil, nil, 0, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return check(resp)
}

// DeleteBucket issues DELETE /{bucket}.
func (c *Client) DeleteBucket(ctx context.Context, bucket string) error {
	resp, err := c.do(ctx, http.MethodDelete, "/"+bucket, nil, nil, 0, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return check(resp)
}

// PutObject uploads an object. size must match the number of bytes in body
// unless WithUnsignedPayload is set.
func (c *Client) PutObject(ctx context.Context, bucket, key string, body io.Reader, size int64, contentType string) (string, error) {
	h := http.Header{}
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	var payloadHash string
	if c.UnsignedPayload {
		payloadHash = "UNSIGNED-PAYLOAD"
	} else {
		var rdr io.Reader = body
		if size <= 0 {
			// Unknown size: buffer so the payload hash can be computed.
			data, err := io.ReadAll(body)
			if err != nil {
				return "", fmt.Errorf("sdk: read body: %w", err)
			}
			rdr = bytes.NewReader(data)
			size = int64(len(data))
		}
		payloadHash, body = c.hashAndReplay(rdr, size)
	}
	resp, err := c.do(ctx, http.MethodPut, objectPath(bucket, key), nil, body, size, h, payloadHash)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if err := check(resp); err != nil {
		return "", err
	}
	return strings.Trim(resp.Header.Get("ETag"), `"`), nil
}

// hashAndReplay buffers the body to compute SHA-256. Callers that cannot
// buffer should use WithUnsignedPayload.
func (c *Client) hashAndReplay(r io.Reader, size int64) (string, io.Reader) {
	data, err := io.ReadAll(r)
	if err != nil {
		return "UNSIGNED-PAYLOAD", r
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), bytes.NewReader(data)
}

// GetObject returns the object body; the caller closes it.
func (c *Client) GetObject(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	resp, err := c.do(ctx, http.MethodGet, objectPath(bucket, key), nil, nil, 0, nil)
	if err != nil {
		return nil, err
	}
	if err := check(resp); err != nil {
		resp.Body.Close()
		return nil, err
	}
	return resp.Body, nil
}

// HeadObject returns size and ETag without transferring the body.
func (c *Client) HeadObject(ctx context.Context, bucket, key string) (int64, string, error) {
	resp, err := c.do(ctx, http.MethodHead, objectPath(bucket, key), nil, nil, 0, nil)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	if err := check(resp); err != nil {
		return 0, "", err
	}
	return resp.ContentLength, strings.Trim(resp.Header.Get("ETag"), `"`), nil
}

// DeleteObject issues DELETE /{bucket}/{key}.
func (c *Client) DeleteObject(ctx context.Context, bucket, key string) error {
	resp, err := c.do(ctx, http.MethodDelete, objectPath(bucket, key), nil, nil, 0, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return check(resp)
}

// ListObjectsV2 returns up to maxKeys entries under prefix (one page).
func (c *Client) ListObjectsV2(ctx context.Context, bucket, prefix string, maxKeys int) ([]Object, bool, error) {
	q := url.Values{}
	q.Set("list-type", "2")
	if prefix != "" {
		q.Set("prefix", prefix)
	}
	if maxKeys > 0 {
		q.Set("max-keys", fmt.Sprint(maxKeys))
	}
	resp, err := c.do(ctx, http.MethodGet, "/"+bucket, q, nil, 0, nil)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if err := check(resp); err != nil {
		return nil, false, err
	}
	var out struct {
		IsTruncated bool `xml:"IsTruncated"`
		Contents    []struct {
			Key          string `xml:"Key"`
			Size         int64  `xml:"Size"`
			ETag         string `xml:"ETag"`
			LastModified string `xml:"LastModified"`
		} `xml:"Contents"`
	}
	if err := xml.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, false, fmt.Errorf("sdk: decode ListObjectsV2: %w", err)
	}
	objs := make([]Object, 0, len(out.Contents))
	for _, o := range out.Contents {
		t, _ := time.Parse(time.RFC3339, o.LastModified)
		objs = append(objs, Object{
			Key: o.Key, Size: o.Size,
			ETag: strings.Trim(o.ETag, `"`), LastModified: t,
		})
	}
	return objs, out.IsTruncated, nil
}

// DefaultPresignTTL is used when a caller passes a non-positive TTL.
const DefaultPresignTTL = 15 * time.Minute

// PresignGet returns a presigned GET URL valid for ttl (default 15 minutes).
func (c *Client) PresignGet(ctx context.Context, bucket, key string, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = DefaultPresignTTL
	}
	u := c.resolve(objectPath(bucket, key), nil)
	if err := sigv4.SignURL(u, c.AK, c.SK, http.MethodGet, time.Now(), ttl); err != nil {
		return "", fmt.Errorf("sdk: presign: %w", err)
	}
	return u.String(), nil
}

// --- transport helpers -----------------------------------------------------

func (c *Client) resolve(path string, query url.Values) *url.URL {
	u := *c.Endpoint
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	u.RawQuery = query.Encode()
	return &u
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body io.Reader, size int64, h http.Header, payloadHash ...string) (*http.Response, error) {
	u := c.resolve(path, query)
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("sdk: build request: %w", err)
	}
	if size > 0 || method == http.MethodPut {
		req.ContentLength = size
	}
	for k, vs := range h {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	hash := ""
	if len(payloadHash) > 0 {
		hash = payloadHash[0]
	}
	if hash == "" {
		if method == http.MethodPut || method == http.MethodPost {
			if c.UnsignedPayload {
				hash = "UNSIGNED-PAYLOAD"
			} else {
				// No body was supplied to sign against; safest legal value.
				hash = "UNSIGNED-PAYLOAD"
			}
		} else {
			hash = emptyPayloadHash
		}
	}
	if err := sigv4.SignRequest(req, c.AK, c.SK, time.Now(), hash); err != nil {
		return nil, fmt.Errorf("sdk: sign: %w", err)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sdk: %s %s: %w", method, u.Path, err)
	}
	return resp, nil
}

const emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func check(resp *http.Response) error {
	if resp.StatusCode < 300 {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	e := &Error{StatusCode: resp.StatusCode, RequestID: resp.Header.Get("x-amz-request-id")}
	var parsed struct {
		Code     string `xml:"Code"`
		Message  string `xml:"Message"`
		Resource string `xml:"Resource"`
	}
	if xml.Unmarshal(body, &parsed) == nil && parsed.Code != "" {
		e.Code, e.Message, e.Resource = parsed.Code, parsed.Message, parsed.Resource
	} else {
		e.Code = http.StatusText(resp.StatusCode)
		e.Message = strings.TrimSpace(string(body))
	}
	return e
}

func objectPath(bucket, key string) string {
	return "/" + bucket + "/" + key
}

// GetObjectRange fetches an inclusive byte range [start, end] of an object.
// A nil range (start<0) is treated as the whole object.
func (c *Client) GetObjectRange(ctx context.Context, bucket, key string, start, end int64) (io.ReadCloser, error) {
	h := http.Header{}
	if start >= 0 && end >= start {
		h.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
	}
	resp, err := c.do(ctx, http.MethodGet, objectPath(bucket, key), nil, nil, 0, h)
	if err != nil {
		return nil, err
	}
	if err := check(resp); err != nil {
		resp.Body.Close()
		return nil, err
	}
	return resp.Body, nil
}
