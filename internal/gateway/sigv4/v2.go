package sigv4

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SigV2 sentinel errors.
var (
	ErrV2MissingAuth = errors.New("sigv2: request is not signed")
	ErrV2Malformed   = errors.New("sigv2: malformed authorization")
	ErrV2Expired     = errors.New("sigv2: presigned URL expired")
)

// v2SubResources is the exact set of query parameters that participate in the
// SigV2 canonicalised resource (AWS "SubResources" plus response overrides).
var v2SubResources = map[string]bool{
	"acl": true, "lifecycle": true, "location": true, "logging": true,
	"notification": true, "partNumber": true, "policy": true,
	"requestPayment": true, "torrent": true, "uploadId": true, "uploads": true,
	"versionId": true, "versioning": true, "versions": true, "website": true,
	"delete": true, "tagging": true, "retention": true, "legal-hold": true,
	"object-lock": true, "ownershipControls": true, "cors": true,
	"encryption": true, "replication": true, "accelerate": true,
	"response-cache-control":       true,
	"response-content-disposition": true,
	"response-content-encoding":    true,
	"response-content-language":    true,
	"response-content-type":        true,
	"response-expires":             true,
}

// V2Auth is the parsed SigV2 authentication.
type V2Auth struct {
	AccessKeyID string
	Signature   string
	// Presigned is true when credentials arrived via query parameters.
	Presigned bool
	// Expires is the presign expiry (only for Presigned).
	Expires time.Time
}

// ParseV2 extracts SigV2 credentials from headers or the query string.
func ParseV2(r *http.Request) (V2Auth, error) {
	auth := r.Header.Get("Authorization")
	if auth != "" {
		if !strings.HasPrefix(auth, AlgorithmV2+" ") {
			return V2Auth{}, fmt.Errorf("%w: scheme %q", ErrV2Malformed, auth)
		}
		rest := strings.TrimSpace(strings.TrimPrefix(auth, AlgorithmV2+" "))
		key, sig, ok := strings.Cut(rest, ":")
		if !ok || key == "" || sig == "" {
			return V2Auth{}, fmt.Errorf("%w: expected 'AWS key:signature'", ErrV2Malformed)
		}
		return V2Auth{AccessKeyID: key, Signature: sig}, nil
	}

	q := r.URL.Query()
	key := q.Get("AWSAccessKeyId")
	if key == "" {
		return V2Auth{}, ErrV2MissingAuth
	}
	// '+' is decoded to ' ' by url.ParseQuery; base64 signatures contain '+',
	// so restore it. This is the classic SigV2 presign interoperability bug.
	sig := strings.ReplaceAll(q.Get("Signature"), " ", "+")
	if sig == "" {
		return V2Auth{}, fmt.Errorf("%w: missing Signature query parameter", ErrV2Malformed)
	}
	expStr := q.Get("Expires")
	if expStr == "" {
		return V2Auth{}, fmt.Errorf("%w: missing Expires query parameter", ErrV2Malformed)
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return V2Auth{}, fmt.Errorf("%w: bad Expires %q", ErrV2Malformed, expStr)
	}
	return V2Auth{
		AccessKeyID: key,
		Signature:   sig,
		Presigned:   true,
		Expires:     time.Unix(exp, 0).UTC(),
	}, nil
}

// V2StringToSign builds the SigV2 string to sign for a request.
func V2StringToSign(r *http.Request) string {
	var b strings.Builder
	b.WriteString(r.Method)
	b.WriteByte('\n')
	b.WriteString(r.Header.Get("Content-MD5"))
	b.WriteByte('\n')
	b.WriteString(r.Header.Get("Content-Type"))
	b.WriteByte('\n')
	// Presigned requests sign the Expires value in place of the Date header.
	if exp := r.URL.Query().Get("Expires"); exp != "" && r.Header.Get("Date") == "" {
		b.WriteString(exp)
	} else {
		b.WriteString(r.Header.Get("Date"))
	}
	b.WriteByte('\n')

	// Canonicalized x-amz-* headers, lowercased and sorted.
	amz := amzHeaderNames(r)
	for _, name := range amz {
		vals := r.Header[http.CanonicalHeaderKey(name)]
		cleaned := make([]string, 0, len(vals))
		for _, v := range vals {
			cleaned = append(cleaned, strings.TrimSpace(v))
		}
		b.WriteString(name)
		b.WriteByte(':')
		b.WriteString(strings.Join(cleaned, ","))
		b.WriteByte('\n')
	}

	// Canonicalized resource.
	b.WriteString(V2CanonicalResource(r))
	return b.String()
}

// V2CanonicalResource renders the canonicalised resource: the request path plus
// the sorted sub-resource query parameters. Values are used *as sent* (raw
// query encoding) because SigV2 signs the literal resource, and base64 version
// ids can contain '+' that url.Query would turn into a space.
func V2CanonicalResource(r *http.Request) string {
	path := r.URL.EscapedPath()
	if path == "" {
		path = "/"
	}

	type sub struct{ key, value string }
	var subs []sub
	for _, pair := range strings.Split(r.URL.RawQuery, "&") {
		if pair == "" {
			continue
		}
		rawKey, rawVal, _ := strings.Cut(pair, "=")
		key, err := url.QueryUnescape(rawKey)
		if err != nil {
			key = rawKey
		}
		if !v2SubResources[key] {
			continue
		}
		subs = append(subs, sub{key: key, value: rawVal})
	}
	if len(subs) == 0 {
		return path
	}
	sort.Slice(subs, func(i, j int) bool { return subs[i].key < subs[j].key })

	var b strings.Builder
	b.WriteString(path)
	b.WriteByte('?')
	for i, s := range subs {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(s.key)
		if s.value != "" {
			b.WriteByte('=')
			b.WriteString(s.value)
		}
	}
	return b.String()
}

// VerifyV2 validates a SigV2 request against secret. It does not consume the
// body and does not check Content-MD5 (the gateway's payload verification does).
func VerifyV2(r *http.Request, secret string, now time.Time, skew time.Duration) (V2Auth, error) {
	a, err := ParseV2(r)
	if err != nil {
		return V2Auth{}, err
	}
	if a.Presigned {
		if now.After(a.Expires) {
			return V2Auth{}, fmt.Errorf("%w: expired at %s", ErrV2Expired, a.Expires.Format(time.RFC3339))
		}
	} else {
		// Header auth: bound the Date header to prevent replay. Legacy clients
		// send RFC 1123 with a numeric zone ("+0000"), which http.ParseTime
		// does not accept, so try the RFC 1123 variants explicitly.
		dateStr := r.Header.Get("Date")
		if dateStr == "" {
			dateStr = r.Header.Get("x-amz-date")
		}
		if dateStr == "" {
			return V2Auth{}, fmt.Errorf("%w: missing Date header", ErrV2Malformed)
		}
		signed, perr := parseHTTPDate(dateStr)
		if perr != nil {
			return V2Auth{}, fmt.Errorf("%w: bad Date %q", ErrV2Malformed, dateStr)
		}
		if d := now.Sub(signed); d > skew || d < -skew {
			return V2Auth{}, fmt.Errorf("%w: signed at %s", ErrRequestTimeSkewed, signed.Format(time.RFC3339))
		}
	}

	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(V2StringToSign(r)))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(a.Signature)) {
		return V2Auth{}, fmt.Errorf("%w: computed %s", ErrSignatureMismatch, want)
	}
	return a, nil
}

// SignV2Header signs r the way legacy S3 clients do, for tests.
func SignV2Header(r *http.Request, accessKeyID, secret string, t time.Time) {
	r.Header.Set("Date", t.UTC().Format(http.TimeFormat))
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(V2StringToSign(r)))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	r.Header.Set("Authorization", AlgorithmV2+" "+accessKeyID+":"+sig)
}

// SignV2URL presigns a URL with SigV2 query auth, for tests.
func SignV2URL(u *url.URL, accessKeyID, secret, method string, expires time.Time) {
	q := u.Query()
	q.Set("AWSAccessKeyId", accessKeyID)
	q.Set("Expires", strconv.FormatInt(expires.Unix(), 10))
	u.RawQuery = q.Encode()
	r := &http.Request{Method: method, URL: u, Header: http.Header{}}
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(V2StringToSign(r)))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	q.Set("Signature", sig)
	u.RawQuery = q.Encode()
}

func amzHeaderNames(r *http.Request) []string {
	var names []string
	for k := range r.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-amz-") {
			names = append(names, lk)
		}
	}
	sort.Strings(names)
	return names
}

// parseHTTPDate parses the date formats legacy S3 clients use for SigV2.
func parseHTTPDate(s string) (time.Time, error) {
	formats := []string{
		http.TimeFormat, // Mon, 02 Jan 2006 15:04:05 GMT
		time.RFC1123Z,   // Mon, 02 Jan 2006 15:04:05 -0700
		time.RFC1123,    // Mon, 02 Jan 2006 15:04:05 MST
		time.RFC850,     // Monday, 02-Jan-06 15:04:05 MST
		time.ANSIC,      // Mon Jan _2 15:04:05 2006
		amzDateFormat,   // 20060102T150405Z
	}
	var err error
	for _, f := range formats {
		var t time.Time
		t, err = time.Parse(f, s)
		if err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, err
}
