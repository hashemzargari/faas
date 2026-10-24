package bridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/fass-storage/fass/internal/gateway/sigv4"
)

// s3Client is a deliberately small S3 client for the bridge. It signs with the
// shared SigV4 implementation (region-aware, unlike the gateway's convenience
// helper which pins eu-west-1) and implements exactly the operations migration
// needs: list, head, get, put, multipart create/upload/complete, delete.
type s3Client struct {
	base      *url.URL
	region    string
	ak, sk    string
	pathStyle bool
	hc        *http.Client
	lim       *limiter
	now       func() time.Time
	log       *slog.Logger
}

func newS3Client(e Endpoint, hc *http.Client, lim *limiter, now func() time.Time, log *slog.Logger) (*s3Client, error) {
	base, err := url.Parse(e.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("bridge: parse endpoint %q: %w", e.Endpoint, err)
	}
	region := strings.TrimSpace(e.Region)
	if region == "" {
		region = "us-east-1"
	}
	if hc == nil {
		hc = &http.Client{Timeout: 0}
	}
	if now == nil {
		now = time.Now
	}
	return &s3Client{
		base:      base,
		region:    region,
		ak:        e.AccessKey,
		sk:        e.SecretKey,
		pathStyle: e.UsePathStyle,
		hc:        hc,
		lim:       lim,
		now:       now,
		log:       log,
	}, nil
}

// objectURL builds the request URL. Path-style is forced for IP/localhost
// endpoints and for hosts that are already bucket-subdomain-unfriendly.
func (c *s3Client) objectURL(bucket, key string, query url.Values) *url.URL {
	u := *c.base
	host := u.Hostname()
	ip := strings.Count(host, ".") == 3
	pathStyle := c.pathStyle || ip || host == "localhost"
	basePath := strings.TrimSuffix(u.Path, "/")
	if pathStyle {
		u.Path = basePath + "/" + bucket
		if key != "" {
			u.Path += "/" + key
		}
	} else {
		u.Host = bucket + "." + u.Host
		u.Path = basePath + "/" + key
	}
	u.RawQuery = query.Encode()
	return &u
}

func (c *s3Client) do(ctx context.Context, method, bucket, key string, query url.Values, body io.Reader, size int64, payloadHash string, hdr http.Header) (*http.Response, error) {
	u := c.objectURL(bucket, key, query)
	if c.lim != nil {
		if err := c.lim.request(ctx); err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("bridge: build %s request: %w", method, err)
	}
	if size > 0 || method == http.MethodPut || method == http.MethodPost {
		req.ContentLength = size
	}
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if payloadHash == "" {
		if method == http.MethodGet || method == http.MethodHead || method == http.MethodDelete {
			payloadHash = sigv4.EmptyStringSHA256
		} else {
			payloadHash = "UNSIGNED-PAYLOAD"
		}
	}
	if err := c.sign(req, payloadHash); err != nil {
		return nil, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bridge: %s %s: %w", method, u.Path, err)
	}
	return resp, nil
}

// sign implements SigV4 header auth with a configurable region (the gateway
// verifier owns the canonical algorithm; only the scope differs).
func (c *s3Client) sign(req *http.Request, payloadHash string) error {
	t := c.now().UTC()
	req.Header.Set("x-amz-date", t.Format("20060102T150405Z"))
	req.Header.Set("x-amz-content-sha256", payloadHash)
	signed := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	cHeaders, err := sigv4.CanonicalHeaders(req, signed)
	if err != nil {
		return fmt.Errorf("bridge: canonical headers: %w", err)
	}
	scope := sigv4.NewScope(t, c.region, sigv4.ServiceS3)
	cr := sigv4.CanonicalRequest(req.Method, sigv4.CanonicalURI(req.URL.EscapedPath()),
		sigv4.CanonicalQuery(req.URL.Query(), false), cHeaders, signed, payloadHash)
	sts := sigv4.StringToSign(t.Format("20060102T150405Z"), scope, cr)
	sig := sigv4.Sign(sigv4.SigningKey(c.sk, scope), sts)
	req.Header.Set("Authorization", sigv4.Algorithm+" Credential="+c.ak+"/"+scope.String()+
		", SignedHeaders="+strings.Join(signed, ";")+", Signature="+sig)
	return nil
}

type s3Object struct {
	Key          string
	Size         int64
	ETag         string
	LastModified time.Time
}

func (c *s3Client) listObjects(ctx context.Context, bucket, continuationToken string, maxKeys int) ([]s3Object, string, error) {
	q := url.Values{}
	q.Set("list-type", "2")
	if continuationToken != "" {
		q.Set("continuation-token", continuationToken)
	}
	if maxKeys > 0 {
		q.Set("max-keys", strconv.Itoa(maxKeys))
	}
	resp, err := c.do(ctx, http.MethodGet, bucket, "", q, nil, 0, "", nil)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if err := parseS3Error(resp); err != nil {
		return nil, "", err
	}
	var out struct {
		IsTruncated           bool   `xml:"IsTruncated"`
		NextContinuationToken string `xml:"NextContinuationToken"`
		Contents              []struct {
			Key          string `xml:"Key"`
			Size         int64  `xml:"Size"`
			ETag         string `xml:"ETag"`
			LastModified string `xml:"LastModified"`
		} `xml:"Contents"`
	}
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&out); err != nil {
		return nil, "", fmt.Errorf("bridge: decode ListObjectsV2: %w", err)
	}
	objects := make([]s3Object, 0, len(out.Contents))
	for _, o := range out.Contents {
		t, _ := time.Parse(time.RFC3339, o.LastModified)
		objects = append(objects, s3Object{Key: o.Key, Size: o.Size, ETag: strings.Trim(o.ETag, `"`), LastModified: t})
	}
	return objects, out.NextContinuationToken, nil
}

func (c *s3Client) listBuckets(ctx context.Context) ([]string, error) {
	resp, err := c.do(ctx, http.MethodGet, "", "", nil, nil, 0, "", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := parseS3Error(resp); err != nil {
		return nil, err
	}
	var out struct {
		Buckets []struct {
			Name string `xml:"Name"`
		} `xml:"Buckets>Bucket"`
	}
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("bridge: decode ListBuckets: %w", err)
	}
	names := make([]string, 0, len(out.Buckets))
	for _, b := range out.Buckets {
		names = append(names, b.Name)
	}
	return names, nil
}

func (c *s3Client) headObject(ctx context.Context, bucket, key string) (s3Object, error) {
	resp, err := c.do(ctx, http.MethodHead, bucket, key, nil, nil, 0, "", nil)
	if err != nil {
		return s3Object{}, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode == http.StatusNotFound {
		return s3Object{}, ErrNotFound
	}
	if resp.StatusCode >= 300 {
		return s3Object{}, &s3Error{Status: resp.StatusCode, Code: "HTTP" + strconv.Itoa(resp.StatusCode), RequestID: resp.Header.Get("x-amz-request-id")}
	}
	size := int64(-1)
	if v := resp.Header.Get("Content-Length"); v != "" {
		size, _ = strconv.ParseInt(v, 10, 64)
	}
	lastModified, _ := http.ParseTime(resp.Header.Get("Last-Modified"))
	return s3Object{
		Key:          key,
		Size:         size,
		ETag:         strings.Trim(resp.Header.Get("Etag"), `"`),
		LastModified: lastModified,
	}, nil
}

func (c *s3Client) getObject(ctx context.Context, bucket, key string) (io.ReadCloser, s3Object, error) {
	resp, err := c.do(ctx, http.MethodGet, bucket, key, nil, nil, 0, "", nil)
	if err != nil {
		return nil, s3Object{}, err
	}
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil, s3Object{}, ErrNotFound
	}
	if err := parseS3Error(resp); err != nil {
		resp.Body.Close()
		return nil, s3Object{}, err
	}
	size := resp.ContentLength
	lastModified, _ := http.ParseTime(resp.Header.Get("Last-Modified"))
	return resp.Body, s3Object{Key: key, Size: size, ETag: strings.Trim(resp.Header.Get("Etag"), `"`), LastModified: lastModified}, nil
}

func (c *s3Client) deleteObject(ctx context.Context, bucket, key string) error {
	resp, err := c.do(ctx, http.MethodDelete, bucket, key, nil, nil, 0, "", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return parseS3Error(resp)
}

func (c *s3Client) createBucket(ctx context.Context, bucket string) error {
	resp, err := c.do(ctx, http.MethodPut, bucket, "", nil, nil, 0, "", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if resp.StatusCode == http.StatusConflict || resp.StatusCode == 409 {
		return nil // BucketAlreadyOwnedByYou / AlreadyExists
	}
	if resp.StatusCode >= 300 {
		return parseS3ErrorMessage(resp.StatusCode, resp.Header.Get("x-amz-request-id"), body)
	}
	return nil
}

// putFile uploads a local file as one PUT. source opens the object body and
// returns its SHA-256 so the signed payload hash matches the bytes sent.
func (c *s3Client) putFile(ctx context.Context, bucket, key string, source func() (io.ReadCloser, string, int64, error)) error {
	body, hash, size, err := source()
	if err != nil {
		return err
	}
	defer body.Close()
	resp, err := c.do(ctx, http.MethodPut, bucket, key, nil, body, size, hash, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return parseS3Error(resp)
}

func (c *s3Client) createMultipart(ctx context.Context, bucket, key, contentType string) (string, error) {
	q := url.Values{"uploads": {""}}
	hdr := http.Header{}
	if contentType != "" {
		hdr.Set("Content-Type", contentType)
	}
	resp, err := c.do(ctx, http.MethodPost, bucket, key, q, nil, 0, sigv4.EmptyStringSHA256, hdr)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if err := parseS3Error(resp); err != nil {
		return "", err
	}
	var out struct {
		UploadID string `xml:"UploadId"`
	}
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", fmt.Errorf("bridge: decode CreateMultipartUpload: %w", err)
	}
	if out.UploadID == "" {
		return "", fmt.Errorf("bridge: CreateMultipartUpload returned no UploadId")
	}
	return out.UploadID, nil
}

func (c *s3Client) uploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int, r io.Reader, size int64, hash string) (string, error) {
	q := url.Values{"partNumber": {strconv.Itoa(partNumber)}, "uploadId": {uploadID}}
	resp, err := c.do(ctx, http.MethodPut, bucket, key, q, r, size, hash, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if err := parseS3Error(resp); err != nil {
		return "", err
	}
	etag := strings.Trim(resp.Header.Get("Etag"), `"`)
	if etag == "" {
		return "", fmt.Errorf("bridge: UploadPart %d returned no ETag", partNumber)
	}
	return etag, nil
}

func (c *s3Client) completeMultipart(ctx context.Context, bucket, key, uploadID string, parts []completedPart) error {
	var buf bytes.Buffer
	buf.WriteString(`<CompleteMultipartUpload>`)
	for _, p := range parts {
		fmt.Fprintf(&buf, `<Part><PartNumber>%d</PartNumber><ETag>"%s"</ETag></Part>`, p.Number, p.ETag)
	}
	buf.WriteString(`</CompleteMultipartUpload>`)
	sum := sha256.Sum256(buf.Bytes())
	q := url.Values{"uploadId": {uploadID}}
	resp, err := c.do(ctx, http.MethodPost, bucket, key, q, bytes.NewReader(buf.Bytes()), int64(buf.Len()), hex.EncodeToString(sum[:]), http.Header{"Content-Type": {"application/xml"}})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return parseS3Error(resp)
}

func (c *s3Client) abortMultipart(ctx context.Context, bucket, key, uploadID string) {
	q := url.Values{"uploadId": {uploadID}}
	resp, err := c.do(ctx, http.MethodDelete, bucket, key, q, nil, 0, "", nil)
	if err == nil {
		resp.Body.Close()
	}
}

type completedPart struct {
	Number int
	ETag   string
}

// objectLockEnabled probes GET /bucket?object-lock. A 200 means retention is
// configured; the documented not-found error means it is not. Anything else is
// an error (never assume unlocked on a failed probe).
func (c *s3Client) objectLockEnabled(ctx context.Context, bucket string) (bool, error) {
	q := url.Values{"object-lock": {""}}
	resp, err := c.do(ctx, http.MethodGet, bucket, "", q, nil, 0, "", nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	// Some implementations answer 400 with ObjectLockConfigurationNotFoundError.
	var e struct {
		Code string `xml:"Code"`
	}
	_ = xml.Unmarshal(body, &e)
	switch e.Code {
	case "ObjectLockConfigurationNotFoundError", "NoSuchObjectLockConfiguration", "ObjectLockConfigurationNotFound":
		return false, nil
	}
	if resp.StatusCode >= 500 {
		return false, parseS3ErrorMessage(resp.StatusCode, resp.Header.Get("x-amz-request-id"), body)
	}
	return false, nil
}

// s3Error is a non-2xx S3 response.
type s3Error struct {
	Status    int
	Code      string
	Message   string
	RequestID string
}

func (e *s3Error) Error() string {
	return fmt.Sprintf("bridge: S3 %d %s: %s (request id %s)", e.Status, e.Code, e.Message, e.RequestID)
}

func parseS3Error(resp *http.Response) error {
	if resp.StatusCode < 300 {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return parseS3ErrorMessage(resp.StatusCode, resp.Header.Get("x-amz-request-id"), body)
}

func parseS3ErrorMessage(status int, requestID string, body []byte) error {
	var e struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	_ = xml.Unmarshal(body, &e)
	if status == http.StatusNotFound {
		return fmt.Errorf("%w: %s", ErrNotFound, strings.TrimSpace(e.Code))
	}
	return &s3Error{Status: status, Code: e.Code, Message: e.Message, RequestID: requestID}
}

// limiter implements coarse request and byte-rate throttling shared by all
// workers. It is intentionally simple: token buckets would be more precise, but
// the goal is "never saturate the source", not exact shaping.
type limiter struct {
	mu        chan struct{}
	reqIval   time.Duration
	byteIval  time.Duration
	nextReq   time.Time
	nextBytes time.Time
	now       func() time.Time
}

func newLimiter(maxRPS int, maxBPS int64, now func() time.Time) *limiter {
	l := &limiter{mu: make(chan struct{}, 1), now: now}
	if l.now == nil {
		l.now = time.Now
	}
	if maxRPS > 0 {
		l.reqIval = time.Second / time.Duration(maxRPS)
	}
	if maxBPS > 0 {
		l.byteIval = time.Second
		l.byteIval = time.Duration(float64(time.Second) / float64(maxBPS))
	}
	return l
}

func (l *limiter) request(ctx context.Context) error {
	if l == nil || l.reqIval <= 0 {
		return nil
	}
	l.mu <- struct{}{}
	defer func() { <-l.mu }()
	wait := time.Until(l.nextReq)
	now := l.now()
	if l.nextReq.IsZero() || wait < 0 {
		wait = 0
	}
	l.nextReq = now.Add(l.reqIval)
	if wait > 0 {
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (l *limiter) bytes(ctx context.Context, n int64) error {
	if l == nil || l.byteIval <= 0 || n <= 0 {
		return nil
	}
	wait := time.Duration(float64(n) * float64(l.byteIval))
	select {
	case <-time.After(wait):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
