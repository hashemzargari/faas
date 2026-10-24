package sigv4

import (
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Sentinel errors. Callers map these to S3 error codes (docs/05 §7).
var (
	ErrMissingAuth         = errors.New("sigv4: request is not signed")
	ErrMalformedAuth       = errors.New("sigv4: malformed authorization")
	ErrUnsupportedAlgorithm = errors.New("sigv4: unsupported signing algorithm")
	ErrInvalidAccessKeyID  = errors.New("sigv4: invalid access key id")
	ErrSignatureMismatch   = errors.New("sigv4: signature mismatch")
	ErrRequestTimeSkewed   = errors.New("sigv4: request time too skewed")
	ErrExpiredPresign      = errors.New("sigv4: presigned URL expired")
	ErrMissingSignedHost   = errors.New("sigv4: host header not signed")
	ErrInvalidPayloadHash  = errors.New("sigv4: invalid x-amz-content-sha256")
	ErrCorruptChunkedBody  = errors.New("sigv4: corrupt aws-chunked body")
)

const amzDateFormat = "20060102T150405Z"

// credential is the parsed Credential= component.
type credential struct {
	AccessKeyID string
	Scope       Scope
}

func parseCredential(s string) (credential, error) {
	parts := strings.Split(s, "/")
	if len(parts) != 5 {
		return credential{}, fmt.Errorf("%w: credential %q must have 5 components", ErrMalformedAuth, s)
	}
	if parts[0] == "" {
		return credential{}, fmt.Errorf("%w: empty access key id", ErrMalformedAuth)
	}
	if parts[4] != Terminator {
		return credential{}, fmt.Errorf("%w: credential terminator %q", ErrMalformedAuth, parts[4])
	}
	return credential{
		AccessKeyID: parts[0],
		Scope:       Scope{Date: parts[1], Region: parts[2], Service: parts[3], Terminator: parts[4]},
	}, nil
}

// ParseAuthorization parses an AWS4-HMAC-SHA256 Authorization header.
func ParseAuthorization(r *http.Request) (Verified, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return Verified{}, ErrMissingAuth
	}
	scheme, rest, ok := strings.Cut(auth, " ")
	if !ok {
		return Verified{}, fmt.Errorf("%w: %q", ErrMalformedAuth, auth)
	}
	if scheme != Algorithm {
		return Verified{}, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, scheme)
	}

	var cred credential
	var signedHeaders []string
	var signature string
	for _, part := range strings.Split(rest, ",") {
		part = strings.TrimSpace(part)
		name, value, ok := strings.Cut(part, "=")
		if !ok {
			return Verified{}, fmt.Errorf("%w: component %q", ErrMalformedAuth, part)
		}
		switch strings.TrimSpace(name) {
		case "Credential":
			c, err := parseCredential(value)
			if err != nil {
				return Verified{}, err
			}
			cred = c
		case "SignedHeaders":
			for _, h := range strings.Split(value, ";") {
				h = strings.ToLower(strings.TrimSpace(h))
				if h != "" {
					signedHeaders = append(signedHeaders, h)
				}
			}
		case "Signature":
			signature = strings.ToLower(strings.TrimSpace(value))
		default:
			// Unknown components are ignored for forward compatibility, as AWS
			// itself does.
		}
	}
	if cred.AccessKeyID == "" || len(signedHeaders) == 0 || signature == "" {
		return Verified{}, fmt.Errorf("%w: incomplete Authorization header", ErrMalformedAuth)
	}

	amzDate, err := parseAmzDate(r.Header.Get("x-amz-date"))
	if err != nil {
		return Verified{}, err
	}
	if cred.Scope.Date != amzDate.Format("20060102") {
		return Verified{}, fmt.Errorf("%w: credential date %q does not match x-amz-date",
			ErrMalformedAuth, cred.Scope.Date)
	}

	payloadHash, err := payloadHashFromHeader(r, false, Options{})
	if err != nil {
		return Verified{}, err
	}

	return Verified{
		AccessKeyID:   cred.AccessKeyID,
		Scope:         cred.Scope,
		SignedHeaders: sortSignedHeaders(signedHeaders),
		Signature:     signature,
		SignedTime:    amzDate,
		PayloadHash:   payloadHash,
	}, nil
}

// ParsePresigned parses a presigned-URL query (X-Amz-* parameters).
func ParsePresigned(r *http.Request, opts Options) (Verified, error) {
	q := r.URL.Query()
	if q.Get("X-Amz-Algorithm") == "" && q.Get("X-Amz-Credential") == "" {
		return Verified{}, ErrMissingAuth
	}
	if alg := q.Get("X-Amz-Algorithm"); alg != Algorithm {
		return Verified{}, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, alg)
	}
	cred, err := parseCredential(q.Get("X-Amz-Credential"))
	if err != nil {
		return Verified{}, err
	}
	amzDate, err := parseAmzDate(q.Get("X-Amz-Date"))
	if err != nil {
		return Verified{}, err
	}
	if cred.Scope.Date != amzDate.Format("20060102") {
		return Verified{}, fmt.Errorf("%w: credential date does not match X-Amz-Date", ErrMalformedAuth)
	}

	expiresStr := q.Get("X-Amz-Expires")
	if expiresStr == "" {
		return Verified{}, fmt.Errorf("%w: missing X-Amz-Expires", ErrMalformedAuth)
	}
	secs, err := strconv.ParseInt(expiresStr, 10, 64)
	if err != nil || secs <= 0 {
		return Verified{}, fmt.Errorf("%w: invalid X-Amz-Expires %q", ErrMalformedAuth, expiresStr)
	}
	expires := time.Duration(secs) * time.Second
	if expires > opts.maxPresign() {
		return Verified{}, fmt.Errorf("%w: X-Amz-Expires %s exceeds maximum %s",
			ErrMalformedAuth, expires, opts.maxPresign())
	}

	var signedHeaders []string
	for _, h := range strings.Split(q.Get("X-Amz-SignedHeaders"), ";") {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			signedHeaders = append(signedHeaders, h)
		}
	}
	if len(signedHeaders) == 0 {
		return Verified{}, fmt.Errorf("%w: missing X-Amz-SignedHeaders", ErrMalformedAuth)
	}

	payloadHash, err := payloadHashFromHeader(r, true, opts)
	if err != nil {
		return Verified{}, err
	}

	return Verified{
		AccessKeyID:   cred.AccessKeyID,
		Scope:         cred.Scope,
		SignedHeaders: sortSignedHeaders(signedHeaders),
		Signature:     strings.ToLower(q.Get("X-Amz-Signature")),
		SignedTime:    amzDate,
		Presigned:     true,
		PayloadHash:   payloadHash,
	}, nil
}

// VerifyHeader authenticates a header-signed request and returns the verified
// facts. It does not read or consume the body.
func VerifyHeader(ctx context.Context, r *http.Request, keys KeyProvider, opts Options) (Verified, error) {
	v, err := ParseAuthorization(r)
	if err != nil {
		return Verified{}, err
	}
	secret, err := lookupKey(ctx, keys, v.AccessKeyID)
	if err != nil {
		return Verified{}, err
	}
	now := opts.now()
	if skew := now.Sub(v.SignedTime); skew > opts.skew() || skew < -opts.skew() {
		return Verified{}, fmt.Errorf("%w: signed at %s, now %s",
			ErrRequestTimeSkewed, v.SignedTime.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	if v.Scope.Service != opts.service() {
		return Verified{}, fmt.Errorf("%w: service %q (want %q)",
			ErrUnsupportedAlgorithm, v.Scope.Service, opts.service())
	}

	if err := checkSignature(r, v, secret, false); err != nil {
		return Verified{}, err
	}

	if isStreamingPayload(v.PayloadHash) {
		key := SigningKey(secret, v.Scope)
		v.Streaming = &StreamingMeta{
			Kind:          v.PayloadHash,
			SeedSignature: v.Signature,
			SigningKey:    key,
			AmzDate:       v.SignedTime.Format(amzDateFormat),
			Scope:         v.Scope,
		}
	}
	return v, nil
}

// VerifyPresigned authenticates a presigned-URL request.
func VerifyPresigned(ctx context.Context, r *http.Request, keys KeyProvider, opts Options) (Verified, error) {
	v, err := ParsePresigned(r, opts)
	if err != nil {
		return Verified{}, err
	}
	secret, err := lookupKey(ctx, keys, v.AccessKeyID)
	if err != nil {
		return Verified{}, err
	}
	now := opts.now()
	expires := time.Duration(mustParseExpires(r)) * time.Second
	if now.After(v.SignedTime.Add(expires)) {
		return Verified{}, fmt.Errorf("%w: expired at %s", ErrExpiredPresign,
			v.SignedTime.Add(expires).Format(time.RFC3339))
	}
	if now.Before(v.SignedTime.Add(-opts.skew())) {
		return Verified{}, fmt.Errorf("%w: signed in the future at %s",
			ErrRequestTimeSkewed, v.SignedTime.Format(time.RFC3339))
	}
	if v.Signature == "" {
		return Verified{}, fmt.Errorf("%w: missing X-Amz-Signature", ErrMalformedAuth)
	}
	if err := checkSignature(r, v, secret, true); err != nil {
		return Verified{}, err
	}
	return v, nil
}

// checkSignature recomputes the canonical request and compares signatures in
// constant time.
func checkSignature(r *http.Request, v Verified, secret string, presigned bool) error {
	cHeaders, err := CanonicalHeaders(r, v.SignedHeaders)
	if err != nil {
		return err
	}
	cr := CanonicalRequest(
		r.Method,
		CanonicalURI(r.URL.EscapedPath()),
		CanonicalQuery(r.URL.Query(), presigned),
		cHeaders,
		v.SignedHeaders,
		v.PayloadHash,
	)
	amzDate := v.SignedTime.Format(amzDateFormat)
	expected := Sign(SigningKey(secret, v.Scope), StringToSign(amzDate, v.Scope, cr))
	if !hmac.Equal([]byte(expected), []byte(v.Signature)) {
		return fmt.Errorf("%w: computed %s", ErrSignatureMismatch, expected)
	}
	return nil
}

func lookupKey(ctx context.Context, keys KeyProvider, accessKeyID string) (string, error) {
	if keys == nil {
		return "", fmt.Errorf("%w: no key provider", ErrInvalidAccessKeyID)
	}
	secret, err := keys(ctx, accessKeyID)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrInvalidAccessKeyID, accessKeyID)
	}
	if secret == "" {
		return "", fmt.Errorf("%w: empty secret for %s", ErrInvalidAccessKeyID, accessKeyID)
	}
	return secret, nil
}

func parseAmzDate(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, fmt.Errorf("%w: missing x-amz-date", ErrMalformedAuth)
	}
	t, err := time.Parse(amzDateFormat, strings.TrimSpace(s))
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: bad x-amz-date %q: %v", ErrMalformedAuth, s, err)
	}
	return t.UTC(), nil
}

func mustParseExpires(r *http.Request) int64 {
	n, _ := strconv.ParseInt(r.URL.Query().Get("X-Amz-Expires"), 10, 64)
	return n
}

// payloadHashFromHeader resolves the payload declaration for the canonical
// request. presigned selects the presigned default.
func payloadHashFromHeader(r *http.Request, presigned bool, opts Options) (string, error) {
	if h := strings.TrimSpace(r.Header.Get("x-amz-content-sha256")); h != "" {
		if !validPayloadHash(h) {
			return "", fmt.Errorf("%w: %q", ErrInvalidPayloadHash, h)
		}
		return h, nil
	}
	if presigned {
		return PayloadUnsigned, nil
	}
	if opts.AllowUnsignedPayloadHash {
		return PayloadUnsigned, nil
	}
	// Bodiless requests (GET/HEAD/DELETE) sign SHA-256(""). A request with a
	// body that omits x-amz-content-sha256 is either non-S3 SigV4 (where the
	// hash is computed) or malformed; either way recomputing is impossible
	// before verifying the signature, so the empty hash is the only sound
	// default and the signature will simply not match.
	return EmptyStringSHA256, nil
}

func validPayloadHash(h string) bool {
	switch h {
	case PayloadUnsigned, PayloadStreaming, PayloadStreamingTrailer,
		PayloadUnsignedTrailer, PayloadUnsignedChunked:
		return true
	}
	if len(h) != 64 {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func isStreamingPayload(h string) bool {
	switch h {
	case PayloadStreaming, PayloadStreamingTrailer, PayloadUnsignedTrailer, PayloadUnsignedChunked:
		return true
	}
	return false
}

func sortSignedHeaders(in []string) []string {
	out := append([]string(nil), in...)
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// IsStreaming reports whether a payload declaration uses aws-chunked framing.
func IsStreaming(payloadHash string) bool { return isStreamingPayload(payloadHash) }
