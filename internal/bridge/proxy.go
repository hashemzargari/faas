package bridge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/fass-storage/fass/internal/gateway/sigv4"
)

// ProxySecurity is the S3 listener's posture, reported on its /healthz.
type ProxySecurity struct {
	TLS         bool `json:"tls"`
	Insecure    bool `json:"insecure"`
	RequireMTLS bool `json:"require_mtls"`
}

// NewS3ProxyHandler exposes the buckets under migration as an S3-compatible
// endpoint (Phase 2 of DS3 Bridge):
//
//   - GET/HEAD: serve the target when it holds a version at least as new as the
//     source, otherwise stream the source (Range supported). If the source
//     disappears between the HEAD decision and the GET (the mover just copied
//     and deleted it), retry the target instead of hallucinating a 404.
//   - PUT/DELETE/multipart: always the target. A successful proxy DELETE also
//     removes the source copy so a later migration pass cannot resurrect it.
//   - ListObjectsV2/ListObjectVersions: from the source while the bucket is
//     in-progress (visible as `listing_source:"source"` in the status API and
//     as `x-fass-bridge-listing` on the response), from the target once the
//     bucket is completed. Merged pagination is deliberately deferred: a
//     half-merged listing is more dangerous than an explicit caveat.
//
// SigV4 is verified against the bridge's target credentials; TLS/mTLS is the
// caller's responsibility (cmd wires pki.ServerConfig).
func NewS3ProxyHandler(m *Manager, sec ProxySecurity) http.Handler {
	return &proxyHandler{mgr: m, sec: sec}
}

type proxyHandler struct {
	mgr *Manager
	sec ProxySecurity
}

func (p *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":   "ok",
			"security": p.sec,
			"bridges":  p.mgr.Count(),
		})
		return
	}
	p.mgr.opts.Log.Debug("bridge proxy request", "method", r.Method, "host", r.Host, "path", r.URL.Path)
	bucket, key := splitProxyPath(r.URL.Path)
	b := p.mgr.bridgeForBucket(bucket)
	if b == nil {
		// Virtual-hosted addressing puts the bucket in the Host header.
		if hostBucket := virtualHostBucket(r.Host); hostBucket != "" {
			if hb := p.mgr.bridgeForBucket(hostBucket); hb != nil {
				bucket, key, b = hostBucket, strings.TrimPrefix(r.URL.Path, "/"), hb
			}
		}
	}
	if bucket == "" || b == nil {
		p.mgr.opts.Log.Debug("bridge proxy: bucket is not tracked", "bucket", bucket, "host", r.Host, "path", r.URL.Path)
		writeProxyError(w, http.StatusNotFound, "NoSuchBucket", "the bucket is not tracked by any bridge")
		return
	}
	if err := verifyProxyRequest(r, b); err != nil {
		code := "SignatureDoesNotMatch"
		if errors.Is(err, sigv4.ErrMissingAuth) {
			code = "AccessDenied"
		} else if errors.Is(err, sigv4.ErrInvalidAccessKeyID) {
			code = "InvalidAccessKeyId"
		}
		writeProxyError(w, http.StatusForbidden, code, err.Error())
		return
	}
	p.dispatch(w, r, b, bucket, key)
}

func (p *proxyHandler) dispatch(w http.ResponseWriter, r *http.Request, b *bridge, bucket, key string) {
	q := r.URL.Query()
	switch {
	case r.Method == http.MethodGet && q.Get("list-type") == "2":
		p.forwardListing(w, r, b, bucket, key)
		return
	case r.Method == http.MethodGet && q.Has("versions"):
		p.forwardListing(w, r, b, bucket, key)
		return
	case r.Method == http.MethodPost && q.Has("uploads"):
		p.forwardWrite(w, r, b, bucket, key)
		return
	case (r.Method == http.MethodPut && q.Has("partNumber")) || (r.Method == http.MethodPost && q.Has("uploadId")) || (r.Method == http.MethodDelete && q.Has("uploadId")):
		p.forwardWrite(w, r, b, bucket, key)
		return
	case key != "" && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		p.proxyRead(w, r, b, bucket, key)
		return
	case key != "" && (r.Method == http.MethodPut || r.Method == http.MethodDelete):
		p.forwardWrite(w, r, b, bucket, key)
		return
	default:
		writeProxyError(w, http.StatusNotImplemented, "NotImplemented", "operation is not supported by the bridge proxy")
	}
}

// proxyRead implements the GET/HEAD decision. Both methods use the same helper
// pair, so a HEAD and a GET in a stable state report/stream the same copy.
func (p *proxyHandler) proxyRead(w http.ResponseWriter, r *http.Request, b *bridge, bucket, key string) {
	ctx := r.Context()
	src, tgt, err := b.clients(ctx)
	if err != nil {
		writeProxyError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	targetObj, targetErr := headOrAbsent(ctx, tgt, bucket, key)
	if targetErr != nil {
		writeProxyError(w, http.StatusInternalServerError, "InternalError", targetErr.Error())
		return
	}
	sourceObj, sourceErr := headOrAbsent(ctx, src, bucket, key)
	if sourceErr != nil {
		writeProxyError(w, http.StatusInternalServerError, "InternalError", sourceErr.Error())
		return
	}

	b.opts.Log.Debug("bridge proxy read decision", "bucket", bucket, "key", key,
		"target_found", targetObj.Key != "", "target_mtime", targetObj.LastModified,
		"target_err", targetErr, "source_found", sourceObj.Key != "", "source_mtime", sourceObj.LastModified,
		"source_err", sourceErr)
	serveTarget := targetIsCurrent(targetObj, sourceObj)
	if !serveTarget && sourceObj.Key == "" {
		if targetObj.Key == "" {
			writeProxyError(w, http.StatusNotFound, "NoSuchKey", "the key does not exist on the source or the target")
			return
		}
		serveTarget = true
	}

	if serveTarget {
		p.streamObject(w, r, tgt, bucket, key, false)
		return
	}
	// Serve the source; if the mover finished between our HEAD and this GET, the
	// object is now only on the target — retry there rather than 404.
	served, status, err := p.streamObjectFrom(ctx, w, r, src, bucket, key)
	if err != nil {
		writeProxyError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if !served && status == http.StatusNotFound {
		p.streamObject(w, r, tgt, bucket, key, false)
		return
	}
	if served {
		b.enqueueCopy(bucket, key)
	}
}

// streamObject proxies from one side, copying status/headers/body.
func (p *proxyHandler) streamObject(w http.ResponseWriter, r *http.Request, c *s3Client, bucket, key string, track bool) {
	_, _, err := p.streamObjectFrom(r.Context(), w, r, c, bucket, key)
	if err != nil {
		writeProxyError(w, http.StatusInternalServerError, "InternalError", err.Error())
	}
}

// streamObjectFrom reports whether the object was served, and the upstream status
// (404 lets the caller retry the other copy).
func (p *proxyHandler) streamObjectFrom(ctx context.Context, w http.ResponseWriter, r *http.Request, c *s3Client, bucket, key string) (bool, int, error) {
	hdr := http.Header{}
	if rng := r.Header.Get("Range"); rng != "" {
		hdr.Set("Range", rng)
	}
	resp, err := c.do(ctx, r.Method, bucket, key, r.URL.Query(), nil, 0, "", hdr)
	if err != nil {
		return false, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, http.StatusNotFound, nil
	}
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		writeProxyError(w, resp.StatusCode, s3CodeFromBody(body), string(body))
		return true, resp.StatusCode, nil
	}
	copyResponseHeaders(w.Header(), resp.Header)
	if r.Method == http.MethodHead {
		w.WriteHeader(resp.StatusCode)
		return true, resp.StatusCode, nil
	}
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	return true, resp.StatusCode, err
}

// forwardListing proxies ListObjectsV2/ListObjectVersions. Source while the
// bucket is in-progress (with an explicit marker header), target afterwards.
func (p *proxyHandler) forwardListing(w http.ResponseWriter, r *http.Request, b *bridge, bucket, key string) {
	side := b.listingSource(bucket)
	var c *s3Client
	var err error
	ctx := r.Context()
	src, tgt, cerr := b.clients(ctx)
	if cerr != nil {
		writeProxyError(w, http.StatusInternalServerError, "InternalError", cerr.Error())
		return
	}
	if side == "source" {
		c = src
	} else {
		c = tgt
	}
	resp, err := c.do(ctx, r.Method, bucket, key, r.URL.Query(), nil, 0, "", nil)
	if err != nil {
		writeProxyError(w, http.StatusBadGateway, "ServiceUnavailable", err.Error())
		return
	}
	defer resp.Body.Close()
	copyResponseHeaders(w.Header(), resp.Header)
	w.Header().Set("x-fass-bridge-listing", side)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		writeProxyError(w, resp.StatusCode, s3CodeFromBody(body), string(body))
		return
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// forwardWrite proxies PUT/DELETE/multipart operations to the target. For DELETE
// it also removes a source copy so the mover cannot resurrect a deleted object;
// for PUT the mover's target-is-newer rule protects the write from a stale copy.
func (p *proxyHandler) forwardWrite(w http.ResponseWriter, r *http.Request, b *bridge, bucket, key string) {
	ctx := r.Context()
	src, tgt, err := b.clients(ctx)
	if err != nil {
		writeProxyError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	body, size, hash, cleanup, err := requestPayload(r)
	if err != nil {
		writeProxyError(w, http.StatusBadRequest, "InvalidRequest", err.Error())
		return
	}
	if cleanup != nil {
		defer cleanup()
	}
	hdr := http.Header{}
	for _, name := range []string{"Content-Type", "Cache-Control", "Content-Disposition", "Content-Encoding"} {
		if v := r.Header.Get(name); v != "" {
			hdr.Set(name, v)
		}
	}
	resp, err := tgt.do(ctx, r.Method, bucket, key, r.URL.Query(), body, size, hash, hdr)
	if err != nil {
		writeProxyError(w, http.StatusBadGateway, "ServiceUnavailable", err.Error())
		return
	}
	defer resp.Body.Close()
	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)

	if r.Method == http.MethodDelete && key != "" && resp.StatusCode < 300 {
		// Writes always target, but a source copy left behind would be re-copied
		// by the mover later; delete it now that the authoritative delete landed.
		if _, err := src.headObject(ctx, bucket, key); err == nil {
			if derr := src.deleteObject(ctx, bucket, key); derr != nil {
				b.opts.Log.Warn("bridge proxy: deleted target but source cleanup failed; the mover may resurrect it",
					"bridge_id", b.st.ID, "bucket", bucket, "key", key, "error", derr.Error())
			}
		}
	}
}

// requestPayload normalises a request body for re-signing against the target:
// aws-chunked streaming bodies are decoded (their chunk signatures are bound to
// the client's key), otherwise the declared payload hash is reused so large
// uploads stream through without buffering.
func requestPayload(r *http.Request) (io.Reader, int64, string, func(), error) {
	if r.Body == nil || r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodDelete {
		return nil, 0, sigv4.EmptyStringSHA256, nil, nil
	}
	// Streaming signature: decode to a temp file (the chunk MACs cannot be
	// reused with the target's signing key) and sign a plain payload.
	if strings.HasPrefix(r.Header.Get("x-amz-content-sha256"), "STREAMING-") {
		f, err := os.CreateTemp("", "fass-bridge-proxy-*")
		if err != nil {
			return nil, 0, "", nil, err
		}
		h := sha256.New()
		n, err := io.Copy(io.MultiWriter(f, h), r.Body)
		if err != nil {
			f.Close()
			os.Remove(f.Name())
			return nil, 0, "", nil, err
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			f.Close()
			os.Remove(f.Name())
			return nil, 0, "", nil, err
		}
		return f, n, hex.EncodeToString(h.Sum(nil)), func() { f.Close(); os.Remove(f.Name()) }, nil
	}
	if h := r.Header.Get("x-amz-content-sha256"); h != "" && h != "UNSIGNED-PAYLOAD" && r.ContentLength >= 0 {
		return r.Body, r.ContentLength, h, nil, nil
	}
	f, err := os.CreateTemp("", "fass-bridge-proxy-*")
	if err != nil {
		return nil, 0, "", nil, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), r.Body)
	if err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, 0, "", nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, 0, "", nil, err
	}
	return f, n, hex.EncodeToString(h.Sum(nil)), func() { f.Close(); os.Remove(f.Name()) }, nil
}

func verifyProxyRequest(r *http.Request, b *bridge) error {
	keys := func(_ context.Context, accessKeyID string) (string, error) {
		if accessKeyID == b.st.Target.AccessKey {
			return b.st.Target.SecretKey, nil
		}
		return "", sigv4.ErrInvalidAccessKeyID
	}
	if r.URL.Query().Get("X-Amz-Signature") != "" {
		_, err := sigv4.VerifyPresigned(r.Context(), r, keys, sigv4.Options{})
		return err
	}
	_, err := sigv4.VerifyHeader(r.Context(), r, keys, sigv4.Options{})
	return err
}

func headOrAbsent(ctx context.Context, c *s3Client, bucket, key string) (s3Object, error) {
	obj, err := c.headObject(ctx, bucket, key)
	if err == nil {
		return obj, nil
	}
	if err == ErrNotFound {
		return s3Object{}, nil
	}
	return s3Object{}, err
}

// virtualHostBucket extracts the bucket from a "bucket.host:port" Host header.
// IP-literal hosts have no bucket prefix.
func virtualHostBucket(host string) string {
	host = strings.Split(host, ":")[0]
	if net.ParseIP(host) != nil {
		return ""
	}
	if i := strings.IndexByte(host, '.'); i > 0 {
		return host[:i]
	}
	return ""
}

func splitProxyPath(path string) (string, string) {
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		return "", ""
	}
	if i := strings.IndexByte(path, '/'); i >= 0 {
		return path[:i], path[i+1:]
	}
	return path, ""
}

func copyResponseHeaders(dst, src http.Header) {
	for k, vs := range src {
		switch strings.ToLower(k) {
		case "connection", "keep-alive", "transfer-encoding", "date", "server":
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func writeProxyError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message><Resource>%s</Resource></Error>`,
		xmlEscape(code), xmlEscape(msg), "")
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}

func s3CodeFromBody(body []byte) string {
	var e struct {
		Code string `xml:"Code"`
	}
	_ = xml.Unmarshal(body, &e)
	if e.Code == "" {
		return "InternalError"
	}
	return e.Code
}
