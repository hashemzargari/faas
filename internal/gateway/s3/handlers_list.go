package s3

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/fass-storage/fass/internal/contract"
)

// encodeKey applies encoding-type=url when requested.
func encodeKey(key, encodingType string) string {
	if strings.EqualFold(encodingType, "url") {
		return url.QueryEscape(key)
	}
	return key
}

// listParams extracts the shared listing parameters.
func (s *Server) listParams(r *http.Request, maxParam string) (prefix, delimiter, encodingType string, maxKeys int, apiErr *APIError) {
	q := r.URL.Query()
	prefix = q.Get("prefix")
	delimiter = q.Get("delimiter")
	encodingType = q.Get("encoding-type")
	if encodingType != "" && !strings.EqualFold(encodingType, "url") {
		return "", "", "", 0, ErrInvalidArgument.withMessage("Invalid encoding-type %q.", encodingType)
	}
	maxKeys, apiErr = s.pagingParams(r, maxParam, s.limits.ListPageMax)
	return prefix, delimiter, encodingType, maxKeys, apiErr
}

// handleListObjects implements the V1 ListObjects API.
func (s *Server) handleListObjects(w http.ResponseWriter, r *http.Request, t target) {
	b, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.authorizeBucket(r, contract.ActionListBucket, b, "", map[string]string{
		"s3:prefix":    r.URL.Query().Get("prefix"),
		"s3:delimiter": r.URL.Query().Get("delimiter"),
		"s3:max-keys":  r.URL.Query().Get("max-keys"),
	}); err != nil {
		s.fail(w, r, err)
		return
	}
	prefix, delimiter, encodingType, maxKeys, apiErr := s.listParams(r, "max-keys")
	if apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	marker := r.URL.Query().Get("marker")
	result, err := s.coord.ListObjects(r.Context(), contract.ListRequest{
		BucketID:   b.BucketID,
		Prefix:     prefix,
		Delimiter:  delimiter,
		MaxKeys:    maxKeys,
		StartAfter: marker,
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	owner := &xmlOwner{ID: ownerID(b)}
	res := listObjectsV1Result{
		Name:         b.Name,
		Prefix:       encodeKey(prefix, encodingType),
		Marker:       encodeKey(marker, encodingType),
		MaxKeys:      maxKeys,
		Delimiter:    encodeKey(delimiter, encodingType),
		IsTruncated:  result.IsTruncated,
		EncodingType: encodingType,
	}
	for _, e := range result.Entries {
		if e.CommonPrefix != "" {
			res.CommonPrefixes = append(res.CommonPrefixes, commonPrefixXML{Prefix: encodeKey(e.CommonPrefix, encodingType)})
			continue
		}
		res.Contents = append(res.Contents, objectXML{
			Key:          encodeKey(e.Key, encodingType),
			LastModified: xmlTime(e.LastModified),
			ETag:         quoteETag(e.ETag),
			Size:         e.Size,
			Owner:        owner,
			StorageClass: storageClassOrDefault(e.StorageClass),
		})
	}
	if result.IsTruncated {
		// NextMarker is only defined for delimiter listings; derive it from the
		// last emitted key or common prefix otherwise.
		if result.NextKeyMarker != "" {
			res.NextMarker = encodeKey(result.NextKeyMarker, encodingType)
		} else if n := len(res.Contents); n > 0 {
			res.NextMarker = res.Contents[n-1].Key
		} else if n := len(res.CommonPrefixes); n > 0 {
			res.NextMarker = res.CommonPrefixes[n-1].Prefix
		}
	}
	writeXML(w, http.StatusOK, res)
}

// handleListObjectsV2 implements ListObjectsV2.
func (s *Server) handleListObjectsV2(w http.ResponseWriter, r *http.Request, t target) {
	q := r.URL.Query()
	if q.Get("list-type") != "2" {
		s.fail(w, r, ErrInvalidArgument.withMessage("Invalid list-type %q; only list-type=2 is supported.", q.Get("list-type")))
		return
	}
	b, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.authorizeBucket(r, contract.ActionListBucket, b, "", map[string]string{
		"s3:prefix":    q.Get("prefix"),
		"s3:delimiter": q.Get("delimiter"),
		"s3:max-keys":  q.Get("max-keys"),
	}); err != nil {
		s.fail(w, r, err)
		return
	}
	prefix, delimiter, encodingType, maxKeys, apiErr := s.listParams(r, "max-keys")
	if apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	continuation := q.Get("continuation-token")
	startAfter := q.Get("start-after")
	fetchOwner := strings.EqualFold(q.Get("fetch-owner"), "true")

	result, err := s.coord.ListObjects(r.Context(), contract.ListRequest{
		BucketID:          b.BucketID,
		Prefix:            prefix,
		Delimiter:         delimiter,
		MaxKeys:           maxKeys,
		StartAfter:        startAfter,
		ContinuationToken: continuation,
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}

	res := listObjectsV2Result{
		Name:              b.Name,
		Prefix:            encodeKey(prefix, encodingType),
		KeyCount:          len(result.Entries),
		MaxKeys:           maxKeys,
		Delimiter:         encodeKey(delimiter, encodingType),
		IsTruncated:       result.IsTruncated,
		ContinuationToken: continuation,
		StartAfter:        encodeKey(startAfter, encodingType),
		EncodingType:      encodingType,
	}
	if result.IsTruncated && result.NextContinuationToken != "" {
		res.NextContinuationToken = result.NextContinuationToken
	}
	var owner *xmlOwner
	if fetchOwner {
		owner = &xmlOwner{ID: ownerID(b)}
	}
	for _, e := range result.Entries {
		if e.CommonPrefix != "" {
			res.CommonPrefixes = append(res.CommonPrefixes, commonPrefixXML{Prefix: encodeKey(e.CommonPrefix, encodingType)})
			continue
		}
		res.Contents = append(res.Contents, objectXML{
			Key:          encodeKey(e.Key, encodingType),
			LastModified: xmlTime(e.LastModified),
			ETag:         quoteETag(e.ETag),
			Size:         e.Size,
			Owner:        owner,
			StorageClass: storageClassOrDefault(e.StorageClass),
		})
	}
	writeXML(w, http.StatusOK, res)
}

// handleListObjectVersions implements ListObjectVersions.
func (s *Server) handleListObjectVersions(w http.ResponseWriter, r *http.Request, t target) {
	q := r.URL.Query()
	b, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.authorizeBucket(r, contract.ActionListBucket, b, "", map[string]string{
		"s3:prefix": r.URL.Query().Get("prefix"),
	}); err != nil {
		s.fail(w, r, err)
		return
	}
	prefix, delimiter, encodingType, maxKeys, apiErr := s.listParams(r, "max-keys")
	if apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	keyMarker := q.Get("key-marker")
	versionIDMarker := q.Get("version-id-marker")

	// The contract's continuation token is opaque; encode both version markers
	// into it so pagination is exactly lossless.
	token := ""
	if keyMarker != "" || versionIDMarker != "" {
		token = keyMarker + "\x00" + versionIDMarker
	}

	result, err := s.coord.ListObjects(r.Context(), contract.ListRequest{
		BucketID:          b.BucketID,
		Prefix:            prefix,
		Delimiter:         delimiter,
		MaxKeys:           maxKeys,
		Versions:          true,
		ContinuationToken: token,
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}

	res := listVersionsResult{
		Name:            b.Name,
		Prefix:          encodeKey(prefix, encodingType),
		KeyMarker:       encodeKey(keyMarker, encodingType),
		VersionIDMarker: versionIDMarker,
		MaxKeys:         maxKeys,
		Delimiter:       encodeKey(delimiter, encodingType),
		IsTruncated:     result.IsTruncated,
		EncodingType:    encodingType,
	}
	owner := &xmlOwner{ID: ownerID(b)}
	lastKey, lastVersion := "", ""
	for _, e := range result.Entries {
		if e.CommonPrefix != "" {
			res.CommonPrefixes = append(res.CommonPrefixes, commonPrefixXML{Prefix: encodeKey(e.CommonPrefix, encodingType)})
			continue
		}
		lastKey, lastVersion = e.Key, string(e.VersionID)
		if e.IsDeleteMarker {
			res.DeleteMarkers = append(res.DeleteMarkers, deleteMarkerXML{
				Key:          encodeKey(e.Key, encodingType),
				VersionID:    string(e.VersionID),
				IsLatest:     e.IsLatest,
				LastModified: xmlTime(e.LastModified),
				Owner:        owner,
			})
			continue
		}
		res.Versions = append(res.Versions, versionXML{
			Key:          encodeKey(e.Key, encodingType),
			VersionID:    string(e.VersionID),
			IsLatest:     e.IsLatest,
			LastModified: xmlTime(e.LastModified),
			ETag:         quoteETag(e.ETag),
			Size:         e.Size,
			Owner:        owner,
			StorageClass: storageClassOrDefault(e.StorageClass),
		})
	}
	if result.IsTruncated {
		res.NextKeyMarker = encodeKey(result.NextKeyMarker, encodingType)
		res.NextVersionIDMarker = result.NextVersionIDMarker
		if res.NextKeyMarker == "" {
			res.NextKeyMarker = encodeKey(lastKey, encodingType)
			res.NextVersionIDMarker = lastVersion
		}
	}
	writeXML(w, http.StatusOK, res)
}

// handleDeleteObjects implements the POST ?delete multi-object delete.
func (s *Server) handleDeleteObjects(w http.ResponseWriter, r *http.Request, t target) {
	b, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.authorizeBucket(r, contract.ActionDeleteObject, b, "", nil); err != nil {
		s.fail(w, r, err)
		return
	}
	bypass := strings.EqualFold(r.Header.Get("x-amz-bypass-governance-retention"), "true")
	if bypass {
		if err := s.authorizeBucket(r, contract.ActionBypassGovern, b, "", nil); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	var req deleteObjectsRequest
	if apiErr := decodeXMLBody(r, 2<<20, &req); apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	if len(req.Objects) == 0 {
		s.fail(w, r, ErrMalformedXML)
		return
	}
	if len(req.Objects) > 1000 {
		s.fail(w, r, ErrMalformedXML.withMessage("A single DeleteObjects request may contain at most 1000 keys."))
		return
	}

	res := deleteObjectsResult{}
	for _, obj := range req.Objects {
		versionID, isMarker, delErr := s.coord.DeleteObject(r.Context(), t.Bucket, obj.Key, contract.VersionID(obj.VersionID), bypass)
		if delErr != nil {
			if errors.Is(delErr, contract.ErrNotFound) {
				// AWS is idempotent: deleting a missing key succeeds.
				if !req.Quiet {
					res.Deleted = append(res.Deleted, deletedXML{Key: obj.Key, VersionID: obj.VersionID})
				}
				continue
			}
			api := mapError(delErr)
			res.Errors = append(res.Errors, deleteErrorXML{
				Key: obj.Key, VersionID: obj.VersionID, Code: api.Code, Message: api.Message,
			})
			continue
		}
		if req.Quiet {
			continue
		}
		d := deletedXML{Key: obj.Key, DeleteMarker: isMarker}
		switch {
		case obj.VersionID != "":
			d.VersionID = obj.VersionID
		case isMarker:
			d.DeleteMarkerVersionID = string(versionID)
		default:
			// Unversioned delete: AWS returns neither a version id nor a marker.
			_ = versionID
		}
		res.Deleted = append(res.Deleted, d)
	}
	writeXML(w, http.StatusOK, res)
}

// storageClassOrDefault reports STANDARD when the stored value is empty.
func storageClassOrDefault(sc string) string {
	if strings.TrimSpace(sc) == "" {
		return "STANDARD"
	}
	return sc
}

// parseMaxParts parses the max-parts parameter.
func (s *Server) parseMaxParts(r *http.Request) (int, *APIError) {
	raw := r.URL.Query().Get("max-parts")
	if raw == "" {
		return 1000, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0, ErrInvalidArgument.withMessage("Invalid max-parts.")
	}
	if n > 1000 {
		n = 1000
	}
	return n, nil
}
