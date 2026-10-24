//go:build compat

package compat

// A small, dependency-free SigV4 S3 client used by the compatibility suite.
//
// The suite deliberately speaks the S3 wire protocol instead of reusing pkg/sdk:
// the point is to assert what an arbitrary SDK sees (XML element names, status
// codes, headers, encoding), not to test our own convenience wrapper. Requests
// are signed exactly as an SDK would sign them.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type s3client struct {
	endpoint string // http://127.0.0.1:port
	region   string
	access   string
	secret   string
	hc       *http.Client
}

type s3response struct {
	Status    int
	Header    http.Header
	Body      []byte
	RequestID string
	Method    string
	URL       string
}

func newS3Client(endpoint, region, access, secret string) *s3client {
	return &s3client{
		endpoint: strings.TrimRight(endpoint, "/"),
		region:   region,
		access:   access,
		secret:   secret,
		hc:       &http.Client{Timeout: 30 * time.Second},
	}
}

// pathFor builds a path-style request path with per-segment escaping.
func pathFor(bucket, key string) string {
	p := "/"
	if bucket == "" {
		return p
	}
	p += url.PathEscape(bucket)
	if key == "" {
		return p
	}
	segs := strings.Split(key, "/")
	for i, seg := range segs {
		segs[i] = url.PathEscape(seg)
	}
	return p + "/" + strings.Join(segs, "/")
}

// do sends one signed S3 request. headers are sent verbatim but only
// host/x-amz-content-sha256/x-amz-date are signed (a valid subset SDKs use).
func (c *s3client) do(ctx context.Context, method, bucket, key string, query url.Values, headers http.Header, body []byte) (*s3response, error) {
	p := pathFor(bucket, key)
	u := c.endpoint + p
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, reader)
	if err != nil {
		return nil, err
	}
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	c.sign(req, query, body)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	out := &s3response{
		Status:    resp.StatusCode,
		Header:    resp.Header.Clone(),
		Body:      raw,
		RequestID: resp.Header.Get("X-Amz-Request-Id"),
		Method:    method,
		URL:       u,
	}
	return out, nil
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (c *s3client) sign(req *http.Request, query url.Values, body []byte) {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	payloadHash := sha256Hex(body)

	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadHash)
	req.Host = req.URL.Host

	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalQuery := canonicalQueryString(query)
	canonicalHeaders := "host:" + req.URL.Host + "\n" +
		"x-amz-content-sha256:" + payloadHash + "\n" +
		"x-amz-date:" + amzDate + "\n"
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canonicalRequest := strings.Join([]string{
		req.Method, canonicalURI, canonicalQuery, canonicalHeaders, signedHeaders, payloadHash,
	}, "\n")

	scope := dateStamp + "/" + c.region + "/s3/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canonicalRequest))
	kDate := hmacSHA256([]byte("AWS4"+c.secret), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(c.region))
	kService := hmacSHA256(kRegion, []byte("s3"))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))
	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.access, scope, signedHeaders, signature))
}

// canonicalQueryString encodes query parameters the AWS way (%20, sorted, no
// '+' for spaces).
func canonicalQueryString(query url.Values) string {
	if len(query) == 0 {
		return ""
	}
	keys := make([]string, 0, len(query))
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vs := append([]string(nil), query[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, awsEscape(k)+"="+awsEscape(v))
		}
	}
	return strings.Join(parts, "&")
}

func awsEscape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// xmlDecode unmarshals a response body, surfacing the raw body on failure.
func xmlDecode(body []byte, out any) error {
	if err := xml.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode XML: %w (body: %s)", err, truncate(body, 512))
	}
	return nil
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}

// ---------------------------------------------------------------------------
// Wire types (subset of the S3 XML documents the suite inspects)
// ---------------------------------------------------------------------------

type xmlError struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	Resource  string   `xml:"Resource"`
	RequestID string   `xml:"RequestId"`
}

type s3objectXML struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
}

type commonPrefixXML struct {
	Prefix string `xml:"Prefix"`
}

type listV2XML struct {
	Name                  string            `xml:"Name"`
	Prefix                string            `xml:"Prefix"`
	Delimiter             string            `xml:"Delimiter"`
	MaxKeys               int               `xml:"MaxKeys"`
	KeyCount              int               `xml:"KeyCount"`
	IsTruncated           bool              `xml:"IsTruncated"`
	ContinuationToken     string            `xml:"ContinuationToken"`
	NextContinuationToken string            `xml:"NextContinuationToken"`
	StartAfter            string            `xml:"StartAfter"`
	EncodingType          string            `xml:"EncodingType"`
	Contents              []s3objectXML     `xml:"Contents"`
	CommonPrefixes        []commonPrefixXML `xml:"CommonPrefixes"`
}

type listV1XML struct {
	Name           string            `xml:"Name"`
	Prefix         string            `xml:"Prefix"`
	Marker         string            `xml:"Marker"`
	NextMarker     string            `xml:"NextMarker"`
	MaxKeys        int               `xml:"MaxKeys"`
	IsTruncated    bool              `xml:"IsTruncated"`
	Delimiter      string            `xml:"Delimiter"`
	EncodingType   string            `xml:"EncodingType"`
	Contents       []s3objectXML     `xml:"Contents"`
	CommonPrefixes []commonPrefixXML `xml:"CommonPrefixes"`
}

type versionXML struct {
	Key            string `xml:"Key"`
	VersionID      string `xml:"VersionId"`
	IsLatest       bool   `xml:"IsLatest"`
	LastModified   string `xml:"LastModified"`
	ETag           string `xml:"ETag"`
	Size           int64  `xml:"Size"`
	IsDeleteMarker bool   `xml:"IsDeleteMarker"`
	StorageClass   string `xml:"StorageClass"`
}

type listVersionsXML struct {
	Name                string            `xml:"Name"`
	Prefix              string            `xml:"Prefix"`
	KeyMarker           string            `xml:"KeyMarker"`
	VersionIDMarker     string            `xml:"VersionIdMarker"`
	NextKeyMarker       string            `xml:"NextKeyMarker"`
	NextVersionIDMarker string            `xml:"NextVersionIdMarker"`
	MaxKeys             int               `xml:"MaxKeys"`
	IsTruncated         bool              `xml:"IsTruncated"`
	Delimiter           string            `xml:"Delimiter"`
	EncodingType        string            `xml:"EncodingType"`
	Versions            []versionXML      `xml:"Version"`
	DeleteMarkers       []versionXML      `xml:"DeleteMarker"`
	CommonPrefixes      []commonPrefixXML `xml:"CommonPrefixes"`
}

type taggingXMLDoc struct {
	XMLName xml.Name `xml:"Tagging"`
	TagSet  struct {
		Tags []struct {
			Key   string `xml:"Key"`
			Value string `xml:"Value"`
		} `xml:"Tag"`
	} `xml:"TagSet"`
}

type retentionXMLDoc struct {
	XMLName         xml.Name `xml:"Retention"`
	Mode            string   `xml:"Mode"`
	RetainUntilDate string   `xml:"RetainUntilDate"`
}

type legalHoldXMLDoc struct {
	XMLName xml.Name `xml:"LegalHold"`
	Status  string   `xml:"Status"`
}

type aclXMLDoc struct {
	XMLName xml.Name `xml:"AccessControlPolicy"`
	Owner   struct {
		ID string `xml:"ID"`
	} `xml:"Owner"`
	Grants []struct {
		Grantee struct {
			ID  string `xml:"ID"`
			URI string `xml:"URI"`
		} `xml:"Grantee"`
		Permission string `xml:"Permission"`
	} `xml:"AccessControlList>Grant"`
}

// ---------------------------------------------------------------------------
// Operation helpers used by the conformance tests
// ---------------------------------------------------------------------------

func (c *cluster) call(method, bucket, key string, query url.Values, headers map[string]string, body []byte) (*s3response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return c.client.do(ctx, method, bucket, key, query, h, body)
}

func (c *cluster) createBucket(bucket string, headers map[string]string) *s3response {
	c.t.Helper()
	resp, err := c.call("PUT", bucket, "", nil, headers, nil)
	if err != nil {
		c.failS3(nil, "CreateBucket(%s): %v", bucket, err)
	}
	c.mustStatus(resp, http.StatusOK, "CreateBucket")
	return resp
}

func (c *cluster) deleteBucket(bucket string) *s3response {
	c.t.Helper()
	resp, err := c.call("DELETE", bucket, "", nil, nil, nil)
	if err != nil {
		c.failS3(nil, "DeleteBucket(%s): %v", bucket, err)
	}
	return resp
}

func (c *cluster) putObject(bucket, key string, data []byte, headers map[string]string) *s3response {
	c.t.Helper()
	resp, err := c.call("PUT", bucket, key, nil, headers, data)
	if err != nil {
		c.failS3(nil, "PutObject(%s/%s): %v", bucket, key, err)
	}
	return resp
}

func (c *cluster) getObject(bucket, key, version string) *s3response {
	c.t.Helper()
	q := url.Values{}
	if version != "" {
		q.Set("versionId", version)
	}
	resp, err := c.call("GET", bucket, key, q, nil, nil)
	if err != nil {
		c.failS3(nil, "GetObject(%s/%s): %v", bucket, key, err)
	}
	return resp
}

func (c *cluster) headObject(bucket, key, version string) *s3response {
	c.t.Helper()
	q := url.Values{}
	if version != "" {
		q.Set("versionId", version)
	}
	resp, err := c.call("HEAD", bucket, key, q, nil, nil)
	if err != nil {
		c.failS3(nil, "HeadObject: %v", err)
	}
	return resp
}

func (c *cluster) deleteObject(bucket, key, version string, bypass bool) *s3response {
	c.t.Helper()
	q := url.Values{}
	if version != "" {
		q.Set("versionId", version)
	}
	headers := map[string]string{}
	if bypass {
		headers["x-amz-bypass-governance-retention"] = "true"
	}
	resp, err := c.call("DELETE", bucket, key, q, headers, nil)
	if err != nil {
		c.failS3(nil, "DeleteObject: %v", err)
	}
	return resp
}

func (c *cluster) listV2(bucket string, params map[string]string) (*listV2XML, *s3response) {
	c.t.Helper()
	q := url.Values{"list-type": {"2"}}
	for k, v := range params {
		q.Set(k, v)
	}
	resp, err := c.call("GET", bucket, "", q, nil, nil)
	if err != nil {
		c.failS3(nil, "ListObjectsV2: %v", err)
	}
	c.mustStatus(resp, http.StatusOK, "ListObjectsV2")
	var out listV2XML
	if err := xmlDecode(resp.Body, &out); err != nil {
		c.failS3(resp, "ListObjectsV2: %v", err)
	}
	return &out, resp
}

func (c *cluster) listV1(bucket string, params map[string]string) (*listV1XML, *s3response) {
	c.t.Helper()
	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	resp, err := c.call("GET", bucket, "", q, nil, nil)
	if err != nil {
		c.failS3(nil, "ListObjects: %v", err)
	}
	c.mustStatus(resp, http.StatusOK, "ListObjects")
	var out listV1XML
	if err := xmlDecode(resp.Body, &out); err != nil {
		c.failS3(resp, "ListObjects: %v", err)
	}
	return &out, resp
}

func (c *cluster) listVersions(bucket string, params map[string]string) (*listVersionsXML, *s3response) {
	c.t.Helper()
	q := url.Values{"versions": {""}}
	for k, v := range params {
		q.Set(k, v)
	}
	resp, err := c.call("GET", bucket, "", q, nil, nil)
	if err != nil {
		c.failS3(nil, "ListObjectVersions: %v", err)
	}
	c.mustStatus(resp, http.StatusOK, "ListObjectVersions")
	var out listVersionsXML
	if err := xmlDecode(resp.Body, &out); err != nil {
		c.failS3(resp, "ListObjectVersions: %v", err)
	}
	return &out, resp
}

func (c *cluster) putBucketVersioning(bucket, status string) *s3response {
	c.t.Helper()
	body := []byte(`<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>` + status + `</Status></VersioningConfiguration>`)
	resp, err := c.call("PUT", bucket, "", url.Values{"versioning": {""}}, map[string]string{"Content-Type": "application/xml"}, body)
	if err != nil {
		c.failS3(nil, "PutBucketVersioning: %v", err)
	}
	return resp
}

func (c *cluster) getBucketVersioning(bucket string) (string, *s3response) {
	c.t.Helper()
	resp, err := c.call("GET", bucket, "", url.Values{"versioning": {""}}, nil, nil)
	if err != nil {
		c.failS3(nil, "GetBucketVersioning: %v", err)
	}
	var doc struct {
		Status string `xml:"Status"`
	}
	_ = xmlDecode(resp.Body, &doc)
	return doc.Status, resp
}

func (c *cluster) putObjectRetention(bucket, key, version, mode string, until time.Time) *s3response {
	c.t.Helper()
	q := url.Values{"retention": {""}}
	if version != "" {
		q.Set("versionId", version)
	}
	body := []byte(fmt.Sprintf(`<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Mode>%s</Mode><RetainUntilDate>%s</RetainUntilDate></Retention>`,
		mode, until.UTC().Format(time.RFC3339)))
	resp, err := c.call("PUT", bucket, key, q, map[string]string{"Content-Type": "application/xml"}, body)
	if err != nil {
		c.failS3(nil, "PutObjectRetention: %v", err)
	}
	return resp
}

func (c *cluster) getObjectRetention(bucket, key, version string) (*retentionXMLDoc, *s3response) {
	c.t.Helper()
	q := url.Values{"retention": {""}}
	if version != "" {
		q.Set("versionId", version)
	}
	resp, err := c.call("GET", bucket, key, q, nil, nil)
	if err != nil {
		c.failS3(nil, "GetObjectRetention: %v", err)
	}
	c.mustStatus(resp, http.StatusOK, "GetObjectRetention")
	var doc retentionXMLDoc
	if err := xmlDecode(resp.Body, &doc); err != nil {
		c.failS3(resp, "GetObjectRetention: %v", err)
	}
	return &doc, resp
}

func (c *cluster) putLegalHold(bucket, key, version, status string) *s3response {
	c.t.Helper()
	q := url.Values{"legal-hold": {""}}
	if version != "" {
		q.Set("versionId", version)
	}
	body := []byte(`<LegalHold xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>` + status + `</Status></LegalHold>`)
	resp, err := c.call("PUT", bucket, key, q, map[string]string{"Content-Type": "application/xml"}, body)
	if err != nil {
		c.failS3(nil, "PutObjectLegalHold: %v", err)
	}
	return resp
}

func (c *cluster) getLegalHold(bucket, key, version string) (string, *s3response) {
	c.t.Helper()
	q := url.Values{"legal-hold": {""}}
	if version != "" {
		q.Set("versionId", version)
	}
	resp, err := c.call("GET", bucket, key, q, nil, nil)
	if err != nil {
		c.failS3(nil, "GetObjectLegalHold: %v", err)
	}
	var doc legalHoldXMLDoc
	_ = xmlDecode(resp.Body, &doc)
	return doc.Status, resp
}

func (c *cluster) putObjectTagging(bucket, key, version string, tags map[string]string) *s3response {
	c.t.Helper()
	q := url.Values{"tagging": {""}}
	if version != "" {
		q.Set("versionId", version)
	}
	var b strings.Builder
	b.WriteString(`<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><TagSet>`)
	for k, v := range tags {
		fmt.Fprintf(&b, `<Tag><Key>%s</Key><Value>%s</Value></Tag>`, xmlEscape(k), xmlEscape(v))
	}
	b.WriteString(`</TagSet></Tagging>`)
	resp, err := c.call("PUT", bucket, key, q, map[string]string{"Content-Type": "application/xml"}, []byte(b.String()))
	if err != nil {
		c.failS3(nil, "PutObjectTagging: %v", err)
	}
	return resp
}

func (c *cluster) getObjectTagging(bucket, key, version string) (map[string]string, *s3response) {
	c.t.Helper()
	q := url.Values{"tagging": {""}}
	if version != "" {
		q.Set("versionId", version)
	}
	resp, err := c.call("GET", bucket, key, q, nil, nil)
	if err != nil {
		c.failS3(nil, "GetObjectTagging: %v", err)
	}
	c.mustStatus(resp, http.StatusOK, "GetObjectTagging")
	var doc taggingXMLDoc
	if err := xmlDecode(resp.Body, &doc); err != nil {
		c.failS3(resp, "GetObjectTagging: %v", err)
	}
	out := map[string]string{}
	for _, tag := range doc.TagSet.Tags {
		out[tag.Key] = tag.Value
	}
	return out, resp
}

func (c *cluster) deleteObjectTagging(bucket, key, version string) *s3response {
	c.t.Helper()
	q := url.Values{"tagging": {""}}
	if version != "" {
		q.Set("versionId", version)
	}
	resp, err := c.call("DELETE", bucket, key, q, nil, nil)
	if err != nil {
		c.failS3(nil, "DeleteObjectTagging: %v", err)
	}
	return resp
}

func (c *cluster) putLifecycle(bucket, xmlBody string) *s3response {
	c.t.Helper()
	resp, err := c.call("PUT", bucket, "", url.Values{"lifecycle": {""}}, map[string]string{"Content-Type": "application/xml"}, []byte(xmlBody))
	if err != nil {
		c.failS3(nil, "PutBucketLifecycleConfiguration: %v", err)
	}
	return resp
}

func (c *cluster) getLifecycle(bucket string) *s3response {
	c.t.Helper()
	resp, err := c.call("GET", bucket, "", url.Values{"lifecycle": {""}}, nil, nil)
	if err != nil {
		c.failS3(nil, "GetBucketLifecycleConfiguration: %v", err)
	}
	return resp
}

func (c *cluster) putBucketACL(bucket, canned string) *s3response {
	c.t.Helper()
	resp, err := c.call("PUT", bucket, "", url.Values{"acl": {""}}, map[string]string{"x-amz-acl": canned}, nil)
	if err != nil {
		c.failS3(nil, "PutBucketAcl: %v", err)
	}
	return resp
}

func (c *cluster) getBucketACL(bucket string) (*aclXMLDoc, *s3response) {
	c.t.Helper()
	resp, err := c.call("GET", bucket, "", url.Values{"acl": {""}}, nil, nil)
	if err != nil {
		c.failS3(nil, "GetBucketAcl: %v", err)
	}
	c.mustStatus(resp, http.StatusOK, "GetBucketAcl")
	var doc aclXMLDoc
	if err := xmlDecode(resp.Body, &doc); err != nil {
		c.failS3(resp, "GetBucketAcl: %v", err)
	}
	return &doc, resp
}

func (c *cluster) putOwnershipControls(bucket, ownership string) *s3response {
	c.t.Helper()
	body := []byte(`<OwnershipControls xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ObjectOwnership>` + ownership + `</ObjectOwnership></Rule></OwnershipControls>`)
	resp, err := c.call("PUT", bucket, "", url.Values{"ownershipControls": {""}}, map[string]string{"Content-Type": "application/xml"}, body)
	if err != nil {
		c.failS3(nil, "PutBucketOwnershipControls: %v", err)
	}
	return resp
}

func (c *cluster) copyObject(srcBucket, srcKey, dstBucket, dstKey string, headers map[string]string) *s3response {
	c.t.Helper()
	h := map[string]string{"x-amz-copy-source": "/" + srcBucket + "/" + url.PathEscape(srcKey)}
	for k, v := range headers {
		h[k] = v
	}
	resp, err := c.call("PUT", dstBucket, dstKey, nil, h, nil)
	if err != nil {
		c.failS3(nil, "CopyObject: %v", err)
	}
	return resp
}

func xmlEscape(s string) string {
	var b strings.Builder
	if err := xml.EscapeText(&b, []byte(s)); err != nil {
		return s
	}
	return b.String()
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }
