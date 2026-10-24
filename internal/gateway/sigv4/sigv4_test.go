package sigv4

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The reference values in this file were produced by an independent Python
// implementation of the AWS SigV4/SigV2 specifications (and cross-checked
// against the published AWS SigV4 test suite "get-vanilla" and the SigV2
// examples in the AWS documentation). They must not be regenerated from this
// package: that would make the tests vacuous.
const (
	testSecret    = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	testAccessKey = "AKIDEXAMPLE"
	testAWSDate   = "20150830T123600Z"
	testRawDate   = "20150830"
	testScope     = "20150830/us-east-1/service/aws4_request"
	testEmptySHA  = EmptyStringSHA256
)

func testKeys(secret string) KeyProvider {
	return func(ctx context.Context, accessKeyID string) (string, error) {
		if accessKeyID != testAccessKey && accessKeyID != "AKIAIOSFODNN7EXAMPLE" {
			return "", errors.New("unknown key")
		}
		return secret, nil
	}
}

func TestCanonicalRequestVectors(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		uri        string
		query      string
		headers    map[string]string
		signed     []string
		payload    string
		wantCR     string
		wantString string // string to sign, when the vector covers it
		wantSig    string
		region     string
		service    string
	}{
		{
			name:    "get-vanilla (AWS SigV4 suite)",
			method:  "GET",
			uri:     "/",
			query:   "",
			headers: map[string]string{"host": "example.amazonaws.com", "x-amz-date": testAWSDate},
			signed:  []string{"host", "x-amz-date"},
			payload: testEmptySHA,
			wantCR: "GET\n/\n\n" +
				"host:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\n" +
				"host;x-amz-date\n" + testEmptySHA,
			wantString: "AWS4-HMAC-SHA256\n20150830T123600Z\n" + testScope + "\n" +
				"bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63",
			wantSig: "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
			region:  "us-east-1",
			service: "service",
		},
		{
			name:    "query parameters sorted by key then value",
			method:  "GET",
			uri:     "/",
			query:   "Param2=value2&Param1=value1",
			headers: map[string]string{"host": "example.amazonaws.com", "x-amz-date": testAWSDate},
			signed:  []string{"host", "x-amz-date"},
			payload: testEmptySHA,
			wantCR: "GET\n/\nParam1=value1&Param2=value2\n" +
				"host:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\n" +
				"host;x-amz-date\n" + testEmptySHA,
			wantSig: "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500",
			region:  "us-east-1",
			service: "service",
		},
		{
			name:    "form-urlencoded body hash",
			method:  "POST",
			uri:     "/",
			headers: map[string]string{"host": "example.amazonaws.com", "x-amz-date": testAWSDate, "content-type": "application/x-www-form-urlencoded"},
			signed:  []string{"content-type", "host", "x-amz-date"},
			payload: HashPayload([]byte("Param1=value1")),
			wantCR: "POST\n/\n\ncontent-type:application/x-www-form-urlencoded\n" +
				"host:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\n" +
				"content-type;host;x-amz-date\n" + HashPayload([]byte("Param1=value1")),
			wantSig: "ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a",
			region:  "us-east-1",
			service: "service",
		},
		{
			name:   "aws s3api list-buckets",
			method: "GET",
			uri:    "/",
			headers: map[string]string{
				"host":                 "s3.eu-west-1.amazonaws.com",
				"x-amz-content-sha256": testEmptySHA,
				"x-amz-date":           "20261024T113000Z",
			},
			signed:  []string{"host", "x-amz-content-sha256", "x-amz-date"},
			payload: testEmptySHA,
			wantCR: "GET\n/\n\nhost:s3.eu-west-1.amazonaws.com\n" +
				"x-amz-content-sha256:" + testEmptySHA + "\n" +
				"x-amz-date:20261024T113000Z\n\n" +
				"host;x-amz-content-sha256;x-amz-date\n" + testEmptySHA,
			wantString: "AWS4-HMAC-SHA256\n20261024T113000Z\n20261024/eu-west-1/s3/aws4_request\n" +
				"a14015a0aa09ccc005b4860883e009645e57d88917451bc7d2c25a8b4054651d",
			wantSig: "f4488e70a3238934769caba471f9af5eae4a982db0b29b0ba16a55b89c3dc736",
			region:  "eu-west-1",
			service: "s3",
		},
		{
			name:   "get-object with escaped key, query and range",
			method: "GET",
			uri:    "/mybucket/mykey%20with%20space",
			query:  "x-id=GetObject",
			headers: map[string]string{
				"host":                 "s3.eu-west-1.amazonaws.com",
				"x-amz-content-sha256": testEmptySHA,
				"x-amz-date":           "20261024T113000Z",
				"range":                "bytes=0-99",
			},
			signed:  []string{"host", "range", "x-amz-content-sha256", "x-amz-date"},
			payload: testEmptySHA,
			wantCR: "GET\n/mybucket/mykey%20with%20space\nx-id=GetObject\n" +
				"host:s3.eu-west-1.amazonaws.com\nrange:bytes=0-99\n" +
				"x-amz-content-sha256:" + testEmptySHA + "\n" +
				"x-amz-date:20261024T113000Z\n\n" +
				"host;range;x-amz-content-sha256;x-amz-date\n" + testEmptySHA,
			wantSig: "5b34d9cf408a4e7f965a049bae0d52c6884eb54f747650a68b38f1f410a23c44",
			region:  "eu-west-1",
			service: "s3",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := http.NewRequest(tc.method, "https://"+tc.headers["host"]+tc.uri+"?"+tc.query, nil)
			if err != nil {
				t.Fatal(err)
			}
			for k, v := range tc.headers {
				if k == "host" {
					continue
				}
				r.Header.Set(k, v)
			}
			cHeaders, err := CanonicalHeaders(r, tc.signed)
			if err != nil {
				t.Fatalf("CanonicalHeaders: %v", err)
			}
			gotCR := CanonicalRequest(tc.method, CanonicalURI(r.URL.EscapedPath()), CanonicalQuery(r.URL.Query(), false), cHeaders, tc.signed, tc.payload)
			if gotCR != tc.wantCR {
				t.Fatalf("canonical request mismatch\n got: %q\nwant: %q", gotCR, tc.wantCR)
			}
			scope := Scope{Date: testRawDate, Region: tc.region, Service: tc.service, Terminator: Terminator}
			if tc.service == "s3" && tc.region == "eu-west-1" {
				scope.Date = "20261024"
			}
			amzDate := tc.headers["x-amz-date"]
			gotSTS := StringToSign(amzDate, scope, gotCR)
			if tc.wantString != "" && gotSTS != tc.wantString {
				t.Fatalf("string to sign mismatch\n got: %q\nwant: %q", gotSTS, tc.wantString)
			}
			gotSig := Sign(SigningKey(testSecret, scope), gotSTS)
			if gotSig != tc.wantSig {
				t.Fatalf("signature mismatch: got %s want %s", gotSig, tc.wantSig)
			}
		})
	}
}

func TestVerifyHeaderAWSListBuckets(t *testing.T) {
	const sig = "f4488e70a3238934769caba471f9af5eae4a982db0b29b0ba16a55b89c3dc736"
	r, err := http.NewRequest(http.MethodGet, "https://s3.eu-west-1.amazonaws.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("x-amz-date", "20261024T113000Z")
	r.Header.Set("x-amz-content-sha256", testEmptySHA)
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261024/eu-west-1/s3/aws4_request, "+
		"SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature="+sig)

	opts := Options{Now: func() time.Time { return time.Date(2026, 10, 24, 11, 30, 0, 0, time.UTC) }}
	v, err := VerifyHeader(context.Background(), r, testKeys(testSecret), opts)
	if err != nil {
		t.Fatalf("VerifyHeader: %v", err)
	}
	if v.AccessKeyID != testAccessKey {
		t.Errorf("access key = %q", v.AccessKeyID)
	}
	if v.Presigned {
		t.Error("header auth marked presigned")
	}
	if v.PayloadHash != testEmptySHA {
		t.Errorf("payload hash = %q", v.PayloadHash)
	}
	if v.Streaming != nil {
		t.Error("unexpected streaming metadata")
	}
}

func TestVerifyHeaderRejectsTampering(t *testing.T) {
	const sig = "5b34d9cf408a4e7f965a049bae0d52c6884eb54f747650a68b38f1f410a23c44"
	build := func() *http.Request {
		r, err := http.NewRequest(http.MethodGet, "https://s3.eu-west-1.amazonaws.com/mybucket/mykey%20with%20space?x-id=GetObject", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("x-amz-date", "20261024T113000Z")
		r.Header.Set("x-amz-content-sha256", testEmptySHA)
		r.Header.Set("range", "bytes=0-99")
		r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261024/eu-west-1/s3/aws4_request, "+
			"SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature="+sig)
		return r
	}
	opts := Options{Now: func() time.Time { return time.Date(2026, 10, 24, 11, 30, 0, 0, time.UTC) }}

	r := build()
	if _, err := VerifyHeader(context.Background(), r, testKeys(testSecret), opts); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*http.Request)
		want   error
	}{
		{"changed range header", func(r *http.Request) { r.Header.Set("range", "bytes=0-10") }, ErrSignatureMismatch},
		{"changed path", func(r *http.Request) { r.URL.Path = "/mybucket/other" }, ErrSignatureMismatch},
		{"added query param", func(r *http.Request) { r.URL.RawQuery += "&foo=bar" }, ErrSignatureMismatch},
		{"unknown access key", func(r *http.Request) {
			r.Header.Set("Authorization", strings.ReplaceAll(r.Header.Get("Authorization"), "AKIDEXAMPLE", "AKIAUNKNOWN"))
		}, ErrInvalidAccessKeyID},
		{"host not signed", func(r *http.Request) {
			r.Header.Set("Authorization", strings.ReplaceAll(r.Header.Get("Authorization"), "host;", ""))
		}, ErrMissingSignedHost},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := build()
			tc.mutate(r)
			_, err := VerifyHeader(context.Background(), r, testKeys(testSecret), opts)
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestVerifyHeaderClockSkew(t *testing.T) {
	r, err := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("x-amz-date", testAWSDate)
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, "+
		"SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31")
	opts := Options{
		Service: "service",
		Now:     func() time.Time { return time.Date(2015, 8, 30, 13, 0, 0, 0, time.UTC) },
	}
	if _, err := VerifyHeader(context.Background(), r, testKeys(testSecret), opts); !errors.Is(err, ErrRequestTimeSkewed) {
		t.Fatalf("error = %v, want ErrRequestTimeSkewed", err)
	}
}

func TestVerifyPresigned(t *testing.T) {
	const sig = "b7c0e001110a9e012896f832467d8c91445cbd4cc73fe01af06964743ceff2fe"
	rawURL := "https://s3.eu-west-1.amazonaws.com/bucket/key.obj?" +
		"X-Amz-Algorithm=AWS4-HMAC-SHA256&" +
		"X-Amz-Credential=AKIDEXAMPLE%2F20261024%2Feu-west-1%2Fs3%2Faws4_request&" +
		"X-Amz-Date=20261024T113000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&" +
		"X-Amz-Signature=" + sig
	r, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{Now: func() time.Time { return time.Date(2026, 10, 24, 11, 35, 0, 0, time.UTC) }}
	v, err := VerifyPresigned(context.Background(), r, testKeys(testSecret), opts)
	if err != nil {
		t.Fatalf("VerifyPresigned: %v", err)
	}
	if !v.Presigned || v.PayloadHash != PayloadUnsigned {
		t.Fatalf("verified = %+v", v)
	}

	// Expired.
	opts.Now = func() time.Time { return time.Date(2026, 10, 24, 13, 0, 0, 0, time.UTC) }
	if _, err := VerifyPresigned(context.Background(), r, testKeys(testSecret), opts); !errors.Is(err, ErrExpiredPresign) {
		t.Fatalf("error = %v, want ErrExpiredPresign", err)
	}

	// Tampered query.
	r2, _ := http.NewRequest(http.MethodGet, strings.Replace(rawURL, "bucket/key.obj", "bucket/other.obj", 1), nil)
	opts.Now = func() time.Time { return time.Date(2026, 10, 24, 11, 35, 0, 0, time.UTC) }
	if _, err := VerifyPresigned(context.Background(), r2, testKeys(testSecret), opts); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("error = %v, want ErrSignatureMismatch", err)
	}
}

func TestSignURLRoundTrip(t *testing.T) {
	u, _ := url.Parse("https://s3.eu-west-1.amazonaws.com/bucket/a%20key?x-id=GetObject")
	now := time.Date(2026, 10, 24, 11, 30, 0, 0, time.UTC)
	if err := SignURL(u, testAccessKey, testSecret, http.MethodGet, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	r, _ := http.NewRequest(http.MethodGet, u.String(), nil)
	opts := Options{Now: func() time.Time { return now.Add(time.Minute) }}
	if _, err := VerifyPresigned(context.Background(), r, testKeys(testSecret), opts); err != nil {
		t.Fatalf("round trip: %v", err)
	}
}

func TestSignRequestRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	r, _ := http.NewRequest(http.MethodPut, "https://s3.eu-west-1.amazonaws.com/bucket/key", strings.NewReader("hello"))
	r.ContentLength = 5
	if err := SignRequest(r, testAccessKey, testSecret, now, HashPayload([]byte("hello"))); err != nil {
		t.Fatal(err)
	}
	opts := Options{Now: func() time.Time { return now }}
	if _, err := VerifyHeader(context.Background(), r, testKeys(testSecret), opts); err != nil {
		t.Fatalf("round trip: %v", err)
	}
}

func TestVerifyV2AWSExamples(t *testing.T) {
	const v2Secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	now := time.Date(2007, 3, 27, 19, 40, 0, 0, time.UTC)

	t.Run("puppy.jpg header auth (AWS docs)", func(t *testing.T) {
		r, _ := http.NewRequest(http.MethodGet, "https://s3.amazonaws.com/johnsmith/photos/puppy.jpg", nil)
		r.Header.Set("Date", "Tue, 27 Mar 2007 19:36:42 +0000")
		r.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:bWq2s1WEIj+Ydj0vQ697zp+IXMU=")
		if _, err := VerifyV2(r, v2Secret, now, 15*time.Minute); err != nil {
			t.Fatalf("VerifyV2: %v", err)
		}
	})

	t.Run("subresource and amz header (AWS docs)", func(t *testing.T) {
		r, _ := http.NewRequest(http.MethodGet, "https://s3.amazonaws.com/johnsmith/photos/puppy.jpg?acl&versionId=3/L4kqtJlcpXroDTDmJ+rmSpXd3dIbrHY+MTRCxf3vjVBH40Nr8X8gdRQBpUMLUo", nil)
		r.Header.Set("Date", "Tue, 27 Mar 2007 19:42:41 +0000")
		r.Header.Set("x-amz-acl", "public-read")
		r.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:JHIpnGyrvYFWjKrWLlpnixjYtV0=")
		if _, err := VerifyV2(r, v2Secret, now, 15*time.Minute); err != nil {
			t.Fatalf("VerifyV2: %v", err)
		}
	})
}

func TestSignV2RoundTrip(t *testing.T) {
	now := time.Now().UTC()
	r, _ := http.NewRequest(http.MethodPut, "https://s3.amazonaws.com/bucket/key?acl", strings.NewReader("x"))
	r.Header.Set("Content-Type", "text/plain")
	SignV2Header(r, testAccessKey, testSecret, now)
	if _, err := VerifyV2(r, testSecret, now, 15*time.Minute); err != nil {
		t.Fatalf("header round trip: %v", err)
	}

	u, _ := url.Parse("https://s3.amazonaws.com/bucket/key?versionId=abc")
	SignV2URL(u, testAccessKey, testSecret, http.MethodGet, now.Add(time.Hour))
	pr, _ := http.NewRequest(http.MethodGet, u.String(), nil)
	if _, err := VerifyV2(pr, testSecret, now, 15*time.Minute); err != nil {
		t.Fatalf("presign round trip: %v", err)
	}
}

func TestChunkedReaderVerifiesAndDecodes(t *testing.T) {
	const amzDate = "20261024T113000Z"
	scope := Scope{Date: "20261024", Region: "eu-west-1", Service: "s3", Terminator: Terminator}
	// Reference body generated by the independent Python signer for this scope.
	const body = "19;chunk-signature=b9834c136bdab395cbfa4f56012b466b14c6c39831f3f1edeb98962e1a47f7ef\r\n" +
		"hello aws chunked payload\r\n" +
		"c;chunk-signature=d0a8459adc91bdbb27d7c227da3b67b402ce4a8abb79a8a185770fda1f5b3455\r\n" +
		"second chunk\r\n" +
		"0;chunk-signature=0e1943267812ec99bc0331f68ea2ac479578b40479888775788bd50210fb1f0a\r\n\r\n"
	opts := ChunkedOptions{
		Kind:          PayloadStreaming,
		SeedSignature: "e35cd6645f291f680578c45e5b664cf09a159002b036a344b3e244abf482495d",
		SigningKey:    SigningKey(testSecret, scope),
		AmzDate:       amzDate,
		Scope:         scope,
	}
	r, err := NewChunkedReader(strings.NewReader(body), opts)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "hello aws chunked payloadsecond chunk" {
		t.Fatalf("payload = %q", got)
	}
	if r.DecodedLen() != int64(len(got)) {
		t.Fatalf("DecodedLen = %d", r.DecodedLen())
	}

	// Flipping one payload byte must fail verification.
	tampered := strings.Replace(body, "hello aws chunked payload", "hello AWS chunked payload", 1)
	r2, _ := NewChunkedReader(strings.NewReader(tampered), opts)
	if _, err := io.ReadAll(r2); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("error = %v, want ErrSignatureMismatch", err)
	}
}

func TestChunkedReaderRejectsBadSignatureChain(t *testing.T) {
	scope := Scope{Date: "20261024", Region: "eu-west-1", Service: "s3", Terminator: Terminator}
	opts := ChunkedOptions{
		Kind:          PayloadStreaming,
		SeedSignature: strings.Repeat("0", 64),
		SigningKey:    SigningKey(testSecret, scope),
		AmzDate:       "20261024T113000Z",
		Scope:         scope,
	}
	body := "2;chunk-signature=" + strings.Repeat("0", 64) + "\r\nhi\r\n0;chunk-signature=" + strings.Repeat("0", 64) + "\r\n\r\n"
	r, err := NewChunkedReader(strings.NewReader(body), opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("error = %v, want ErrSignatureMismatch", err)
	}
}

func TestCanonicalURI(t *testing.T) {
	tests := map[string]string{
		"":                      "/",
		"/":                     "/",
		"/bucket":               "/bucket",
		"/bucket/a%20b":         "/bucket/a%20b",
		"/b/c%2Fd":              "/b/c%2Fd",
		"bucket/noleadingslash": "/bucket/noleadingslash",
	}
	for in, want := range tests {
		if got := CanonicalURI(in); got != want {
			t.Errorf("CanonicalURI(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestChunkedReaderUnsignedTrailer(t *testing.T) {
	payload := []byte("payload with a flexible checksum trailer")
	scope := Scope{Date: "20261024", Region: "eu-west-1", Service: "s3", Terminator: Terminator}
	key := SigningKey(testSecret, scope)
	const amzDate = "20261024T113000Z"
	seed := strings.Repeat("ab", 32)
	trailerValue := "AAAAAA=="
	canonical := "x-amz-checksum-crc32:" + trailerValue + "\n"
	trailerSTS := "AWS4-HMAC-SHA256-TRAILER\n" + amzDate + "\n" + scope.String() + "\n" +
		seed + "\n" + HashPayload([]byte(canonical))
	trailerSig := Sign(key, trailerSTS)

	var body bytes.Buffer
	fmt.Fprintf(&body, "%x\r\n", len(payload))
	body.Write(payload)
	body.WriteString("\r\n0\r\n")
	fmt.Fprintf(&body, "x-amz-checksum-crc32:%s\r\n", trailerValue)
	fmt.Fprintf(&body, "x-amz-trailer-signature:%s\r\n\r\n", trailerSig)

	r, err := NewChunkedReader(bytes.NewReader(body.Bytes()), ChunkedOptions{
		Kind:          PayloadUnsignedTrailer,
		SeedSignature: seed,
		SigningKey:    key,
		AmzDate:       amzDate,
		Scope:         scope,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v (body=%q)", err, body.String())
	}
	if string(got) != string(payload) {
		t.Fatalf("payload = %q", got)
	}
	if r.Trailers()["x-amz-checksum-crc32"] != trailerValue {
		t.Fatalf("trailers = %v", r.Trailers())
	}
}
