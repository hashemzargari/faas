package s3

import (
	"crypto/md5"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/gateway/authz"
	"github.com/fass-storage/fass/internal/gateway/offloader"
)

// readBody reads at most max bytes and maps failures onto S3 errors.
func readBody(r *http.Request, max int64) ([]byte, *APIError) {
	if r.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, max+1))
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrIncompleteBody
		}
		return nil, ErrInternalError
	}
	if int64(len(body)) > max {
		return nil, ErrEntityTooLarge
	}
	return body, nil
}

// decodeXMLBody reads and XML-decodes a request body.
func decodeXMLBody(r *http.Request, max int64, v any) *APIError {
	body, apiErr := readBody(r, max)
	if apiErr != nil {
		return apiErr
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return ErrMalformedXML
	}
	if err := xml.Unmarshal(body, v); err != nil {
		return ErrMalformedXML
	}
	return nil
}

// validStorageClass enforces the three documented routing labels (docs/05 §5.7).
func validStorageClass(sc string) bool {
	switch strings.ToUpper(strings.TrimSpace(sc)) {
	case "", "STANDARD", "HOT", "COLD":
		return true
	}
	return false
}

// normalizeStorageClass upper-cases and defaults the storage class.
func normalizeStorageClass(sc string) string {
	sc = strings.ToUpper(strings.TrimSpace(sc))
	if sc == "" {
		return "STANDARD"
	}
	return sc
}

// versionFromQuery returns the versionId query parameter.
func versionFromQuery(r *http.Request) contract.VersionID {
	return contract.VersionID(r.URL.Query().Get("versionId"))
}

// newUUID generates a version/shard-set id. Cubbit uses UUIDv4 for version ids
// and clients must treat them as opaque (docs/05 §5.1); reusing the UUIDv4
// generator keeps the format consistent.
func (s *Server) newUUID() string { return contract.NewUUID() }

// regionFor returns the region to report for a bucket.
func (s *Server) regionFor(b contract.BucketConfig) string {
	if b.Region != "" {
		return b.Region
	}
	return s.region()
}

// ownerDisplayName is the human-readable owner label in XML responses.
func ownerDisplayName(id authz.Identity) string {
	if id.AccessKey != "" {
		return id.AccessKey
	}
	if id.Principal.ProjectID != "" {
		return string(id.Principal.ProjectID)
	}
	return "anonymous"
}

// collectUserMeta extracts the metadata and response headers S3 stores with an
// object. Keys are stored exactly as the response header names they represent.
func (s *Server) collectUserMeta(r *http.Request) (map[string]string, *APIError) {
	meta := make(map[string]string)
	for k, vs := range r.Header {
		lk := strings.ToLower(k)
		switch lk {
		case "content-encoding", "content-disposition", "content-language", "cache-control",
			"expires", "x-amz-website-redirect-location":
			meta[lk] = strings.TrimSpace(strings.Join(vs, ","))
		default:
			if strings.HasPrefix(lk, "x-amz-meta-") {
				meta[lk] = strings.TrimSpace(strings.Join(vs, ","))
			}
		}
	}
	total := 0
	for k, v := range meta {
		if strings.HasPrefix(k, "x-amz-meta-") {
			total += len(k) + len(v)
		}
	}
	if total > s.limits.MaxUserMeta {
		return nil, ErrInvalidRequest.withMessage("Your metadata headers exceed the maximum allowed metadata size.")
	}
	return meta, nil
}

// applyMetadataHeaders restores stored metadata as response headers.
func applyMetadataHeaders(h http.Header, meta map[string]string) {
	for k, v := range meta {
		h.Set(canonicalMetadataHeader(k), v)
	}
}

// validTagKey and validTagValue enforce the documented tagging limits.
func validTagKey(k string) bool   { return k != "" && len(k) <= 128 }
func validTagValue(v string) bool { return len(v) <= 256 }

// validateTags enforces at most 10 tags with bounded key/value lengths.
func (s *Server) validateTags(tags map[string]string) *APIError {
	if len(tags) > s.limits.MaxTags {
		return ErrInvalidTag.withMessage("Object tags cannot be greater than %d.", s.limits.MaxTags)
	}
	for k, v := range tags {
		if !validTagKey(k) || !validTagValue(v) {
			return ErrInvalidTag
		}
	}
	return nil
}

// parseTaggingXML parses a Tagging request body into a tag map.
func parseTaggingXML(body []byte) (map[string]string, *APIError) {
	var doc taggingRequest
	if err := xml.Unmarshal(body, &doc); err != nil {
		return nil, ErrMalformedXML
	}
	tags := make(map[string]string, len(doc.TagSet.Tags))
	for _, t := range doc.TagSet.Tags {
		tags[t.Key] = t.Value
	}
	return tags, nil
}

// taggingXMLFromMap renders a tag map as a Tagging document.
func taggingXMLFromMap(tags map[string]string) taggingXML {
	doc := taggingXML{}
	for _, k := range sortedKeys(tags) {
		doc.TagSet.Tags = append(doc.TagSet.Tags, tagXML{Key: k, Value: tags[k]})
	}
	return doc
}

// retentionFromHeaders builds an object retention from x-amz-object-lock-*.
func retentionFromHeaders(r *http.Request) (*contract.Retention, *APIError) {
	mode := strings.ToUpper(strings.TrimSpace(r.Header.Get("x-amz-object-lock-mode")))
	untilStr := strings.TrimSpace(r.Header.Get("x-amz-object-lock-retain-until-date"))
	legalHold := strings.EqualFold(strings.TrimSpace(r.Header.Get("x-amz-object-lock-legal-hold")), "ON")

	if mode == "" && untilStr == "" {
		if legalHold {
			return &contract.Retention{LegalHold: true}, nil
		}
		return nil, nil
	}
	if mode != "GOVERNANCE" && mode != "COMPLIANCE" {
		return nil, ErrInvalidRetention.withMessage("Invalid x-amz-object-lock-mode %q.", mode)
	}
	if untilStr == "" {
		return nil, ErrInvalidRetention.withMessage("x-amz-object-lock-retain-until-date is required with a retention mode.")
	}
	until, err := parseRetainUntil(untilStr)
	if err != nil {
		return nil, ErrInvalidRetention.withMessage("Invalid x-amz-object-lock-retain-until-date %q.", untilStr)
	}
	if !until.After(time.Now()) {
		return nil, ErrInvalidRetention.withMessage("The retain-until date must be in the future.")
	}
	return &contract.Retention{Mode: mode, RetainUntil: until, LegalHold: legalHold}, nil
}

// parseRetainUntil accepts the ISO-8601 forms S3 clients use.
func parseRetainUntil(s string) (time.Time, error) {
	formats := []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05Z0700", time.RFC1123, http.TimeFormat}
	var err error
	for _, f := range formats {
		var t time.Time
		if t, err = time.Parse(f, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, err
}

// checksumsFromRequest collects the checksums the client declared in headers.
func (s *Server) checksumsFromRequest(r *http.Request) ([]offloader.ExpectedChecksum, *APIError) {
	if !s.cfg.Compat.VerifyChecksums {
		return nil, nil
	}
	var out []offloader.ExpectedChecksum
	add := func(alg offloader.ChecksumAlgorithm, header string) *APIError {
		raw := strings.TrimSpace(r.Header.Get(header))
		if raw == "" {
			return nil
		}
		value, err := decodeChecksum(raw, alg)
		if err != nil {
			return ErrInvalidArgument.withMessage("Invalid %s checksum.", header)
		}
		out = append(out, offloader.ExpectedChecksum{Algorithm: alg, Value: value})
		return nil
	}
	if apiErr := add(offloader.ChecksumMD5, "Content-MD5"); apiErr != nil {
		return nil, apiErr
	}
	if apiErr := add(offloader.ChecksumSHA1, "x-amz-checksum-sha1"); apiErr != nil {
		return nil, apiErr
	}
	if apiErr := add(offloader.ChecksumSHA256, "x-amz-checksum-sha256"); apiErr != nil {
		return nil, apiErr
	}
	if apiErr := add(offloader.ChecksumCRC32, "x-amz-checksum-crc32"); apiErr != nil {
		return nil, apiErr
	}
	if apiErr := add(offloader.ChecksumCRC32C, "x-amz-checksum-crc32c"); apiErr != nil {
		return nil, apiErr
	}
	return out, nil
}

// contentLength returns the declared body length, or -1 when unknown.
func contentLength(r *http.Request) int64 {
	if r.ContentLength >= 0 {
		return r.ContentLength
	}
	return -1
}

// parseContentRangeHeader parses "bytes=start-end" for UploadPartCopy.
func parseContentRangeHeader(v string) (*offloader.ByteRange, *APIError) {
	v = strings.TrimSpace(v)
	if !strings.HasPrefix(v, "bytes=") {
		return nil, ErrInvalidRange
	}
	startStr, endStr, ok := strings.Cut(strings.TrimPrefix(v, "bytes="), "-")
	if !ok {
		return nil, ErrInvalidRange
	}
	start, err1 := strconv.ParseInt(strings.TrimSpace(startStr), 10, 64)
	end, err2 := strconv.ParseInt(strings.TrimSpace(endStr), 10, 64)
	if err1 != nil || err2 != nil || start < 0 || end < start {
		return nil, ErrInvalidRange
	}
	return &offloader.ByteRange{Start: start, Length: end - start + 1}, nil
}

// etagMatches compares ETags ignoring quoting and the weak prefix.
func etagMatches(a, b string) bool {
	normalize := func(s string) string {
		s = strings.TrimSpace(s)
		s = strings.TrimPrefix(s, "W/")
		return strings.Trim(s, `"`)
	}
	return normalize(a) == normalize(b)
}

// md5Hex is the S3 ETag algorithm for single-part objects.
func md5Hex(b []byte) string {
	sum := md5.Sum(b)
	return fmt.Sprintf("%x", sum[:])
}
