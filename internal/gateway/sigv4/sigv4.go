// Package sigv4 implements AWS Signature Version 4 (header and presigned query
// auth), AWS Signature Version 2, and the AWS chunked streaming payload signing
// schemes used by S3 clients.
//
// The package contains only the cryptographic/canonicalisation primitives. It
// never talks to the coordinator and knows nothing about FASS principals: the
// caller supplies a KeyProvider that maps an access key id to its secret, which
// lets the gateway verify signatures locally with key material fetched (and
// cached) from the coordinator. See internal/gateway/authz.
//
// Canonicalisation follows the AWS specification literally, including the S3
// deviations:
//   - the canonical URI is the raw (single-encoded) request path and is not
//     normalised (S3 does not normalise path segments);
//   - a signed request must include the host header;
//   - the payload hash is taken from x-amz-content-sha256, defaulting to the
//     SHA-256 of the empty string for bodiless requests.
package sigv4

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	// Algorithm is the SigV4 algorithm identifier.
	Algorithm = "AWS4-HMAC-SHA256"
	// AlgorithmV2 is the SigV2 algorithm identifier ("AWS <key>:<sig>").
	AlgorithmV2 = "AWS"
	// Terminator is the last component of a credential scope.
	Terminator = "aws4_request"
	// ServiceS3 is the signing service name for S3.
	ServiceS3 = "s3"

	// PayloadUnsigned declares that the payload is not signed. Presigned URLs
	// always use this value; header-auth clients may also use it.
	PayloadUnsigned = "UNSIGNED-PAYLOAD"
	// PayloadStreaming signs the body chunk by chunk.
	PayloadStreaming = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	// PayloadStreamingTrailer is the chunked signing scheme with trailers.
	PayloadStreamingTrailer = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
	// PayloadUnsignedTrailer is the aws-chunked framing used by modern SDKs for
	// flexible checksums: the payload bytes are unsigned, trailers are signed.
	PayloadUnsignedTrailer = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
	// PayloadUnsignedChunked is the aws-chunked framing with no signing at all
	// (some SDKs emit it with Content-Encoding: aws-chunked).
	PayloadUnsignedChunked = "STREAMING-UNSIGNED-PAYLOAD"

	// EmptyStringSHA256 is SHA-256("").
	EmptyStringSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// Scope is a SigV4 credential scope: <date>/<region>/<service>/aws4_request.
type Scope struct {
	Date       string // YYYYMMDD, UTC
	Region     string
	Service    string
	Terminator string
}

// NewScope builds a credential scope for the given signing time.
func NewScope(t time.Time, region, service string) Scope {
	if service == "" {
		service = ServiceS3
	}
	return Scope{
		Date:       t.UTC().Format("20060102"),
		Region:     region,
		Service:    service,
		Terminator: Terminator,
	}
}

// String renders the scope the way it appears in a credential.
func (s Scope) String() string {
	return s.Date + "/" + s.Region + "/" + s.Service + "/" + s.Terminator
}

// KeyProvider resolves an access key id to its secret key. The returned error
// should be wrapped with ErrInvalidAccessKeyID when the key is unknown.
type KeyProvider func(ctx context.Context, accessKeyID string) (secret string, err error)

// Options configures verification behaviour.
type Options struct {
	// Service is the expected signing service. Defaults to "s3".
	Service string
	// ClockSkew bounds how far a request's signing time may be from now.
	// Defaults to 15 minutes (docs/04 §1.5 auth.clock_skew).
	ClockSkew time.Duration
	// Now supplies the current time; defaults to time.Now.
	Now func() time.Time
	// MaxPresignExpiry caps X-Amz-Expires. Defaults to 7 days (docs/05 §2).
	MaxPresignExpiry time.Duration
	// AllowUnsignedPayloadHash treats a missing x-amz-content-sha256 as
	// UNSIGNED-PAYLOAD instead of SHA-256(""). Off by default: S3 clients are
	// expected to send the header, which is what binds the body to the
	// signature.
	AllowUnsignedPayloadHash bool
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now().UTC()
	}
	return time.Now().UTC()
}

func (o Options) skew() time.Duration {
	if o.ClockSkew > 0 {
		return o.ClockSkew
	}
	return 15 * time.Minute
}

func (o Options) service() string {
	if o.Service != "" {
		return o.Service
	}
	return ServiceS3
}

func (o Options) maxPresign() time.Duration {
	if o.MaxPresignExpiry > 0 {
		return o.MaxPresignExpiry
	}
	return 7 * 24 * time.Hour
}

// Verified describes an authenticated S3 request.
type Verified struct {
	AccessKeyID   string
	Scope         Scope
	SignedHeaders []string
	Signature     string // hex signature presented by the client
	SignedTime    time.Time
	Presigned     bool
	PayloadHash   string // signed payload declaration: hex hash, UNSIGNED-PAYLOAD, ...
	// Streaming is set when the body uses aws-chunked framing.
	Streaming *StreamingMeta
}

// StreamingMeta carries what the chunked decoder needs. It is populated by the
// verifier and consumed by NewChunkedReader.
type StreamingMeta struct {
	// Kind is one of the STREAMING-* payload declarations.
	Kind string
	// SeedSignature is the request signature the chunk chain starts from.
	SeedSignature string
	// SigningKey is the derived aws4_request key.
	SigningKey []byte
	// AmzDate is the ISO-8601 signing timestamp used by the request.
	AmzDate string
	// Scope is the credential scope used by the request.
	Scope Scope
}

// uriEncode percent-encodes s per RFC 3986, encoding every byte except the
// unreserved set. When encodeSlash is false, '/' is preserved (path segments).
func uriEncode(s string, encodeSlash bool) string {
	const upperhex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		if c == '/' && !encodeSlash {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(upperhex[c>>4])
		b.WriteByte(upperhex[c&0xf])
	}
	return b.String()
}

// URLEncode percent-encodes a query key or value exactly as SigV4 requires.
func URLEncode(s string) string { return uriEncode(s, true) }

// CanonicalURI returns the canonical URI for an S3 request: the raw request
// path with an empty path normalised to "/" and no other normalisation applied.
// rawPath is expected to be the escaped (wire) path, as returned by
// (*url.URL).EscapedPath.
func CanonicalURI(rawPath string) string {
	if rawPath == "" {
		return "/"
	}
	if !strings.HasPrefix(rawPath, "/") {
		return "/" + rawPath
	}
	return rawPath
}

// CanonicalQuery renders the canonical query string: parameters sorted by
// (encoded) name then value, both RFC 3986 encoded, with repeated parameters
// preserved. When excludeSignature is true the X-Amz-Signature parameter is
// omitted, as presigned-URL verification requires.
func CanonicalQuery(values url.Values, excludeSignature bool) string {
	type pair struct{ k, v string }
	pairs := make([]pair, 0, len(values))
	for k, vs := range values {
		if excludeSignature && k == "X-Amz-Signature" {
			continue
		}
		ek := URLEncode(k)
		for _, v := range vs {
			pairs = append(pairs, pair{ek, URLEncode(v)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	var b strings.Builder
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(p.k)
		b.WriteByte('=')
		b.WriteString(p.v)
	}
	return b.String()
}

// CanonicalHeaders renders the canonical headers block and validates that every
// signed header is present and that host is signed. The returned block ends with
// a newline after each header, as required by SigV4.
func CanonicalHeaders(r *http.Request, signed []string) (string, error) {
	if len(signed) == 0 {
		return "", fmt.Errorf("%w: empty signed headers", ErrMalformedAuth)
	}
	hasHost := false
	for _, h := range signed {
		if h == "host" {
			hasHost = true
		}
	}
	if !hasHost {
		return "", ErrMissingSignedHost
	}

	var b strings.Builder
	for _, name := range signed {
		name = strings.ToLower(strings.TrimSpace(name))
		var vals []string
		if name == "host" {
			if host := r.Host; host != "" {
				vals = append(vals, host)
			}
		}
		if vs, ok := r.Header[http.CanonicalHeaderKey(name)]; ok {
			vals = append(vals, vs...)
		}
		if len(vals) == 0 {
			return "", fmt.Errorf("%w: signed header %q is missing", ErrMalformedAuth, name)
		}
		cleaned := make([]string, 0, len(vals))
		for _, v := range vals {
			cleaned = append(cleaned, collapseSpaces(strings.TrimSpace(v)))
		}
		b.WriteString(name)
		b.WriteByte(':')
		b.WriteString(strings.Join(cleaned, ","))
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// collapseSpaces replaces runs of space/tab with a single space, as SigV4
// requires for header values outside quoted strings.
func collapseSpaces(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' {
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteByte(c)
	}
	return b.String()
}

// CanonicalRequest builds the canonical request string.
func CanonicalRequest(method, canonicalURI, canonicalQuery, canonicalHeaders string, signedHeaders []string, payloadHash string) string {
	return method + "\n" +
		canonicalURI + "\n" +
		canonicalQuery + "\n" +
		canonicalHeaders + "\n" +
		strings.Join(signedHeaders, ";") + "\n" +
		payloadHash
}

// StringToSign builds the SigV4 string to sign.
func StringToSign(amzDate string, scope Scope, canonicalRequest string) string {
	sum := sha256.Sum256([]byte(canonicalRequest))
	return Algorithm + "\n" +
		amzDate + "\n" +
		scope.String() + "\n" +
		hex.EncodeToString(sum[:])
}

// SigningKey derives the SigV4 signing key for a secret and scope.
func SigningKey(secret string, scope Scope) []byte {
	k := hmacSHA256([]byte("AWS4"+secret), scope.Date)
	k = hmacSHA256(k, scope.Region)
	k = hmacSHA256(k, scope.Service)
	return hmacSHA256(k, Terminator)
}

// Sign returns the lowercase hex signature of stringToSign under key.
func Sign(key []byte, stringToSign string) string {
	return hex.EncodeToString(hmacSHA256(key, stringToSign))
}

// SignRequest signs r in place the way an S3 client would, using header auth.
// It exists for tests and for the gateway's own integration clients; it sets
// x-amz-date, x-amz-content-sha256 and Authorization.
func SignRequest(r *http.Request, accessKeyID, secret string, t time.Time, payloadHash string) error {
	if payloadHash == "" {
		payloadHash = EmptyStringSHA256
	}
	r.Header.Set("x-amz-date", t.UTC().Format("20060102T150405Z"))
	r.Header.Set("x-amz-content-sha256", payloadHash)

	scope := NewScope(t, "eu-west-1", ServiceS3)
	signed := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	cHeaders, err := CanonicalHeaders(r, signed)
	if err != nil {
		return err
	}
	amzDate := t.UTC().Format("20060102T150405Z")
	cr := CanonicalRequest(r.Method, CanonicalURI(r.URL.EscapedPath()),
		CanonicalQuery(r.URL.Query(), false), cHeaders, signed, payloadHash)
	sts := StringToSign(amzDate, scope, cr)
	sig := Sign(SigningKey(secret, scope), sts)
	r.Header.Set("Authorization", Algorithm+" Credential="+accessKeyID+"/"+scope.String()+
		", SignedHeaders="+strings.Join(signed, ";")+", Signature="+sig)
	return nil
}

// SignURL presigns u (query auth) the way an S3 client would. It returns the
// URL with X-Amz-Signature set.
func SignURL(u *url.URL, accessKeyID, secret, method string, t time.Time, expires time.Duration) error {
	scope := NewScope(t, "eu-west-1", ServiceS3)
	amzDate := t.UTC().Format("20060102T150405Z")
	q := u.Query()
	q.Set("X-Amz-Algorithm", Algorithm)
	q.Set("X-Amz-Credential", accessKeyID+"/"+scope.String())
	q.Set("X-Amz-Date", amzDate)
	q.Set("X-Amz-Expires", fmt.Sprintf("%d", int(expires.Seconds())))
	q.Set("X-Amz-SignedHeaders", "host")
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(method, u.String(), nil)
	if err != nil {
		return err
	}
	cHeaders, err := CanonicalHeaders(req, []string{"host"})
	if err != nil {
		return err
	}
	cr := CanonicalRequest(method, CanonicalURI(req.URL.EscapedPath()),
		CanonicalQuery(req.URL.Query(), true), cHeaders, []string{"host"}, PayloadUnsigned)
	sig := Sign(SigningKey(secret, scope), StringToSign(amzDate, scope, cr))
	q.Set("X-Amz-Signature", sig)
	u.RawQuery = q.Encode()
	return nil
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// HashPayload returns the lowercase hex SHA-256 of b.
func HashPayload(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
