package s3

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/fass-storage/fass/internal/gateway/offloader"
)

// parseRange validates a Range header against the object size. Multi-range
// requests are documented to yield a single 206 range (docs/05 §4), so only the
// first range is honoured.
func parseRange(header string, size int64) (*offloader.ByteRange, *APIError) {
	header = strings.TrimSpace(header)
	if header == "" {
		return nil, nil
	}
	if size <= 0 {
		return nil, rangeFault(size)
	}
	if !strings.HasPrefix(header, "bytes=") {
		return nil, ErrInvalidRange
	}
	spec := strings.TrimPrefix(header, "bytes=")
	if i := strings.IndexByte(spec, ','); i >= 0 {
		spec = spec[:i]
	}
	startStr, endStr, ok := strings.Cut(strings.TrimSpace(spec), "-")
	if !ok {
		return nil, rangeFault(size)
	}
	startStr, endStr = strings.TrimSpace(startStr), strings.TrimSpace(endStr)

	var start, end int64
	if startStr == "" {
		// Suffix range: "-N" = last N bytes.
		n, err := strconv.ParseInt(endStr, 10, 64)
		if err != nil || n <= 0 {
			return nil, rangeFault(size)
		}
		if n > size {
			n = size
		}
		start, end = size-n, size-1
	} else {
		var err error
		start, err = strconv.ParseInt(startStr, 10, 64)
		if err != nil || start < 0 || start >= size {
			return nil, rangeFault(size)
		}
		if endStr == "" {
			end = size - 1
		} else {
			end, err = strconv.ParseInt(endStr, 10, 64)
			if err != nil || end < start {
				return nil, rangeFault(size)
			}
			if end >= size {
				end = size - 1
			}
		}
	}
	return &offloader.ByteRange{Start: start, Length: end - start + 1}, nil
}

// rangeFault returns a 416 carrying the required Content-Range header.
func rangeFault(size int64) *APIError {
	e := *ErrInvalidRange
	e.Header = http.Header{"Content-Range": []string{fmt.Sprintf("bytes */%d", size)}}
	return &e
}

// etagInList reports whether etag appears in a comma-separated If-* list.
func etagInList(list, etag string) bool {
	for _, part := range strings.Split(list, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if etagMatches(part, etag) {
			return true
		}
	}
	return false
}

// checkPreconditions applies RFC 9110 conditional request semantics.
//
// For reads it returns ErrNotModified (304); for writes ErrPreconditionFailed
// (412). This is divergence D2 in docs/05 §9: Cubbit ignores these headers, we
// honour them.
func checkPreconditions(r *http.Request, etag string, lastModified time.Time, write bool) *APIError {
	ifMatch := r.Header.Get("If-Match")
	ifUnmod := r.Header.Get("If-Unmodified-Since")
	ifNoneMatch := r.Header.Get("If-None-Match")
	ifMod := r.Header.Get("If-Modified-Since")

	if ifMatch != "" {
		if !etagInList(ifMatch, etag) {
			return ErrPreconditionFailed
		}
	} else if ifUnmod != "" {
		if t, err := http.ParseTime(ifUnmod); err == nil && lastModified.After(t.Add(time.Second)) {
			return ErrPreconditionFailed
		}
	}

	if ifNoneMatch != "" {
		if ifNoneMatch == "*" || etagInList(ifNoneMatch, etag) {
			if write {
				return ErrPreconditionFailed
			}
			return ErrNotModified
		}
	} else if ifMod != "" {
		if t, err := http.ParseTime(ifMod); err == nil && !lastModified.After(t.Add(time.Second)) {
			return ErrNotModified
		}
	}
	return nil
}

// checkCopySourcePreconditions applies the x-amz-copy-source-if-* family.
func checkCopySourcePreconditions(r *http.Request, etag string, lastModified time.Time) *APIError {
	if v := r.Header.Get("x-amz-copy-source-if-match"); v != "" && !etagInList(v, etag) {
		return ErrPreconditionFailed
	}
	if v := r.Header.Get("x-amz-copy-source-if-none-match"); v != "" && etagInList(v, etag) {
		return ErrPreconditionFailed
	}
	if v := r.Header.Get("x-amz-copy-source-if-unmodified-since"); v != "" {
		if t, err := http.ParseTime(v); err == nil && lastModified.After(t.Add(time.Second)) {
			return ErrPreconditionFailed
		}
	}
	if v := r.Header.Get("x-amz-copy-source-if-modified-since"); v != "" {
		if t, err := http.ParseTime(v); err == nil && !lastModified.After(t.Add(time.Second)) {
			return ErrPreconditionFailed
		}
	}
	return nil
}

// writeNotModified sends a 304 with no body.
func writeNotModified(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNotModified)
}

// copySource identifies a CopyObject/UploadPartCopy source.
type copySource struct {
	Bucket    string
	Key       string
	VersionID string
}

// parseCopySource parses the x-amz-copy-source header. The value is
// URL-encoded and may carry ?versionId=.
func parseCopySource(raw string) (copySource, *APIError) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return copySource{}, ErrInvalidArgument.withMessage("Missing x-amz-copy-source header.")
	}
	version := ""
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		query := raw[i+1:]
		raw = raw[:i]
		if v, err := url.ParseQuery(query); err == nil {
			version = v.Get("versionId")
		}
	}
	raw = strings.TrimPrefix(raw, "/")
	bucket, key, ok := strings.Cut(raw, "/")
	if !ok || bucket == "" || key == "" {
		return copySource{}, ErrInvalidArgument.withMessage("Invalid x-amz-copy-source header.")
	}
	decodedBucket, err := url.PathUnescape(bucket)
	if err != nil {
		return copySource{}, ErrInvalidArgument.withMessage("Invalid x-amz-copy-source header.")
	}
	decodedKey, err := url.PathUnescape(key)
	if err != nil {
		return copySource{}, ErrInvalidArgument.withMessage("Invalid x-amz-copy-source header.")
	}
	return copySource{Bucket: decodedBucket, Key: decodedKey, VersionID: version}, nil
}

// setContentRange writes the Content-Range header for a 206 response.
func setContentRange(w http.ResponseWriter, start, length, total int64) {
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, start+length-1, total))
}
