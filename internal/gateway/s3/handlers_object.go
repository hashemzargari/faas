package s3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/gateway/offloader"
	"github.com/fass-storage/fass/internal/gateway/sdp"
)

// ---------------------------------------------------------------------------
// PutObject
// ---------------------------------------------------------------------------

func (s *Server) handlePutObject(w http.ResponseWriter, r *http.Request, t target) {
	if err := s.validateKey(t.Key); err != nil {
		s.fail(w, r, err)
		return
	}
	b, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if apiErr := s.authorizePut(r, b, t.Key); apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	if apiErr := s.rejectUnsupportedEncryption(r); apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	storageClass := strings.ToUpper(strings.TrimSpace(r.Header.Get("x-amz-storage-class")))
	if !validStorageClass(storageClass) {
		s.fail(w, r, ErrInvalidStorageClass)
		return
	}
	storageClass = normalizeStorageClass(storageClass)

	if contentLength(r) > s.limits.MaxSinglePut {
		s.fail(w, r, ErrEntityTooLarge)
		return
	}
	meta, apiErr := s.collectUserMeta(r)
	if apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	tags, apiErr := s.tagsFromPutRequest(r)
	if apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	retention, apiErr := retentionFromHeaders(r)
	if apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	if retention != nil && !b.ObjectLock {
		s.fail(w, r, ErrInvalidRequest.withMessage("Bucket is missing an Object Lock configuration."))
		return
	}
	checksums, apiErr := s.checksumsFromRequest(r)
	if apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}

	rcID, drop, apiErr := s.routePlacement(r, b, t.Key, contentLength(r), r.Header.Get("Content-Type"), storageClass)
	if apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	if drop {
		s.fail(w, r, ErrAccessDenied.withMessage("Upload rejected by Smart Data Placement policy."))
		return
	}

	versionID, _ := s.mintVersionID(b)
	spec := s.objectSpec(b, t.Key, versionID, contentLength(r),
		r.Header.Get("Content-Type"), meta, tags, storageClass, rcID)
	spec.Checksums = checksums
	spec.Retention = retention
	if s.cfg.Compat.ConditionalWrites {
		spec.IfMatch = r.Header.Get("If-Match")
		spec.IfNoneMatch = r.Header.Get("If-None-Match")
	}
	spec.DeferredChecksums = s.deferredChecksums(r)

	res, err := s.off.Write(r.Context(), spec, r.Body)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteETag(res.ETag))
	versionHeader(w.Header(), b, res.VersionID)
	writeEmpty(w, http.StatusOK)
}

// authorizePut authorizes PutObject plus the object-lock bypass if requested.
func (s *Server) authorizePut(r *http.Request, b contract.BucketConfig, key string) *APIError {
	cond := map[string]string{}
	if acl := r.Header.Get("x-amz-acl"); acl != "" {
		cond["s3:x-amz-acl"] = acl
	}
	if err := s.authorizeBucket(r, contract.ActionPutObject, b, key, cond); err != nil {
		return mapError(err)
	}
	if isTrueHeader(r, "x-amz-bypass-governance-retention") {
		if err := s.authorizeBucket(r, contract.ActionBypassGovern, b, key, nil); err != nil {
			return mapError(err)
		}
	}
	return nil
}

// rejectUnsupportedEncryption refuses confidentiality headers we cannot honour
// (docs/05 §9 D4: never accept-and-ignore an encryption header).
func (s *Server) rejectUnsupportedEncryption(r *http.Request) *APIError {
	if !s.cfg.Compat.RejectSSEC {
		return nil
	}
	for k := range r.Header {
		switch strings.ToLower(k) {
		case "x-amz-server-side-encryption-customer-algorithm",
			"x-amz-server-side-encryption-customer-key",
			"x-amz-server-side-encryption-customer-key-md5":
			return ErrNotImplemented.withMessage("SSE-C is not implemented; refusing to accept a client key that would not be used.")
		}
	}
	if v := r.Header.Get("x-amz-server-side-encryption"); v != "" {
		return ErrNotImplemented.withMessage("Server-side encryption mode %q is not implemented by this gateway.", v)
	}
	return nil
}

// tagsFromPutRequest parses the x-amz-tagging header (an improvement over
// Cubbit, which ignores it: docs/05 §4).
func (s *Server) tagsFromPutRequest(r *http.Request) (map[string]string, *APIError) {
	tags, err := splitTags(r.Header.Get("x-amz-tagging"))
	if err != nil {
		return nil, ErrInvalidTag.withMessage("%s", err.Error())
	}
	if apiErr := s.validateTags(tags); apiErr != nil {
		return nil, apiErr
	}
	return tags, nil
}

// routePlacement evaluates Smart Data Placement for an upload.
func (s *Server) routePlacement(r *http.Request, b contract.BucketConfig, key string, size int64, contentType, storageClass string) (rcID string, drop bool, apiErr *APIError) {
	rcID = b.DefaultRCID
	if rcID == "" {
		rcID = s.cfg.DefaultRCID
	}
	if s.sdp == nil || s.sdp.Rules() == 0 {
		return rcID, false, nil
	}
	tenantName := string(b.TenantID)
	decision := s.sdp.Evaluate(sdp.ObjectMeta{
		Key:          key,
		Size:         size,
		ContentType:  contentType,
		TenantName:   tenantName,
		StorageClass: storageClass,
	})
	switch decision.Action {
	case sdp.ActionDrop:
		return "", true, nil
	case sdp.ActionRoute:
		return decision.RCID, false, nil
	default:
		return rcID, false, nil
	}
}

// objectSpec assembles the offloader description of a write.
func (s *Server) objectSpec(b contract.BucketConfig, key string, versionID contract.VersionID, size int64, contentType string, meta, tags map[string]string, storageClass, rcID string) offloader.ObjectSpec {
	return offloader.ObjectSpec{
		BucketID:     b.BucketID,
		Bucket:       b.Name,
		Key:          key,
		TenantID:     b.TenantID,
		ProjectID:    b.ProjectID,
		VersionID:    versionID,
		Size:         size,
		MaxBytes:     s.limits.MaxSinglePut,
		ContentType:  contentType,
		UserMeta:     meta,
		Tags:         tags,
		StorageClass: storageClass,
		RCID:         rcID,
		Params:       s.cfg.DefaultParams,
		ChunkSize:    s.cfg.ChunkSize,
	}
}

// deferredChecksums returns a callback resolving checksums that only become
// available after the body has been consumed (aws-chunked trailers).
func (s *Server) deferredChecksums(r *http.Request) func() []offloader.ExpectedChecksum {
	if !s.cfg.Compat.VerifyChecksums || r.Header.Get("x-amz-trailer") == "" {
		return nil
	}
	return func() []offloader.ExpectedChecksum {
		st := state(r)
		if st.chunked == nil {
			return nil
		}
		var out []offloader.ExpectedChecksum
		for name, value := range st.chunked.Trailers() {
			alg, ok := trailerChecksumAlgorithm(name)
			if !ok {
				continue
			}
			decoded, err := decodeChecksum(value, alg)
			if err != nil {
				continue
			}
			out = append(out, offloader.ExpectedChecksum{Algorithm: alg, Value: decoded})
		}
		return out
	}
}

// trailerChecksumAlgorithm maps a trailer header name to a checksum algorithm.
func trailerChecksumAlgorithm(name string) (offloader.ChecksumAlgorithm, bool) {
	switch strings.ToLower(name) {
	case "x-amz-checksum-sha1":
		return offloader.ChecksumSHA1, true
	case "x-amz-checksum-sha256":
		return offloader.ChecksumSHA256, true
	case "x-amz-checksum-crc32":
		return offloader.ChecksumCRC32, true
	case "x-amz-checksum-crc32c":
		return offloader.ChecksumCRC32C, true
	case "x-amz-checksum-crc64nvme":
		return offloader.ChecksumCRC64NVME, true
	}
	return "", false
}

// ---------------------------------------------------------------------------
// GetObject / HeadObject
// ---------------------------------------------------------------------------

func (s *Server) handleGetObject(w http.ResponseWriter, r *http.Request, t target, head bool) {
	if err := s.validateKey(t.Key); err != nil {
		s.failHead(w, r, err, head)
		return
	}
	b, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.failHead(w, r, err, head)
		return
	}
	cond := map[string]string{"s3:versionid": r.URL.Query().Get("versionId")}
	if err := s.authorizeBucket(r, contract.ActionGetObject, b, t.Key, cond); err != nil {
		s.failHead(w, r, err, head)
		return
	}
	versionID := versionFromQuery(r)
	manifest, err := s.coord.GetManifest(r.Context(), t.Bucket, t.Key, versionID)
	if err != nil {
		if errors.Is(err, contract.ErrNotFound) {
			s.failHead(w, r, ErrNoSuchKey, head)
			return
		}
		s.failHead(w, r, err, head)
		return
	}

	h := w.Header()
	setManifestHeaders(h, manifestView{
		createdAt:    manifest.CreatedAt,
		contentType:  manifest.ContentType,
		versionID:    string(manifest.VersionID),
		storageClass: "STANDARD",
		userMeta:     manifest.UserMeta,
	}, manifest.ETag)
	applyMetadataHeaders(h, manifest.UserMeta)

	if s.cfg.Compat.ConditionalWrites {
		if apiErr := checkPreconditions(r, manifest.ETag, manifest.CreatedAt, false); apiErr != nil {
			if apiErr == ErrNotModified || apiErr.Status == http.StatusNotModified {
				writeNotModified(w)
				return
			}
			s.failHead(w, r, apiErr, head)
			return
		}
	}

	rng, apiErr := parseRange(r.Header.Get("Range"), manifest.Size)
	if apiErr != nil {
		s.failHead(w, r, apiErr, head)
		return
	}

	status := http.StatusOK
	length := manifest.Size
	if rng != nil {
		status = http.StatusPartialContent
		length = rng.Length
		setContentRange(w, rng.Start, rng.Length, manifest.Size)
	}
	h.Set("Content-Length", fmt.Sprintf("%d", length))
	w.WriteHeader(status)
	if head {
		return
	}
	if err := s.off.Read(r.Context(), offloader.ReadRequest{
		Bucket:    t.Bucket,
		Key:       t.Key,
		TenantID:  manifest.TenantID,
		ProjectID: manifest.ProjectID,
		Manifest:  manifest,
		Range:     rng,
	}, w); err != nil && !errors.Is(err, r.Context().Err()) {
		s.log.Error("object read failed after headers were sent",
			"request_id", requestIDFromRequest(r), "bucket", t.Bucket, "key", t.Key, "error", err.Error())
	}
}

// failHead writes either a full XML error (GET) or only the status (HEAD), as
// HTTP forbids a response body for HEAD.
func (s *Server) failHead(w http.ResponseWriter, r *http.Request, err error, head bool) {
	if !head {
		s.fail(w, r, err)
		return
	}
	api := mapError(err)
	if api.Status >= 500 {
		s.log.Error("head object failed", "request_id", requestIDFromRequest(r), "error", err.Error())
	}
	w.WriteHeader(api.Status)
}

// ---------------------------------------------------------------------------
// DeleteObject
// ---------------------------------------------------------------------------

func (s *Server) handleDeleteObject(w http.ResponseWriter, r *http.Request, t target) {
	if err := s.validateKey(t.Key); err != nil {
		s.fail(w, r, err)
		return
	}
	b, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	bypass := isTrueHeader(r, "x-amz-bypass-governance-retention")
	if err := s.authorizeBucket(r, contract.ActionDeleteObject, b, t.Key, map[string]string{
		"s3:versionid": r.URL.Query().Get("versionId"),
	}); err != nil {
		s.fail(w, r, err)
		return
	}
	if bypass {
		if err := s.authorizeBucket(r, contract.ActionBypassGovern, b, t.Key, nil); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	versionID, isMarker, err := s.coord.DeleteObject(r.Context(), t.Bucket, t.Key, versionFromQuery(r), bypass)
	if err != nil && !errors.Is(err, contract.ErrNotFound) {
		s.fail(w, r, err)
		return
	}
	versionHeader(w.Header(), b, versionID)
	if isMarker {
		w.Header().Set("x-amz-delete-marker", "true")
	}
	writeEmpty(w, http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// CopyObject
// ---------------------------------------------------------------------------

func (s *Server) handleCopyObject(w http.ResponseWriter, r *http.Request, t target) {
	if err := s.validateKey(t.Key); err != nil {
		s.fail(w, r, err)
		return
	}
	src, apiErr := parseCopySource(r.Header.Get("x-amz-copy-source"))
	if apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	if src.Bucket == t.Bucket && src.Key == t.Key && src.VersionID == "" {
		s.fail(w, r, ErrInvalidRequest.withMessage("This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata, storage class, website redirect location or encryption attributes."))
		return
	}

	srcBucket, err := s.loadBucket(r, src.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if expected := r.Header.Get("x-amz-source-expected-bucket-owner"); expected != "" && expected != ownerID(srcBucket) {
		s.fail(w, r, ErrAccessDenied)
		return
	}
	if err := s.authorizeBucket(r, contract.ActionGetObject, srcBucket, src.Key, nil); err != nil {
		s.fail(w, r, err)
		return
	}

	dstBucket, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if apiErr := s.authorizePut(r, dstBucket, t.Key); apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	if apiErr := s.rejectUnsupportedEncryption(r); apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}

	manifest, err := s.coord.GetManifest(r.Context(), src.Bucket, src.Key, contract.VersionID(src.VersionID))
	if err != nil {
		if errors.Is(err, contract.ErrNotFound) {
			s.fail(w, r, ErrNoSuchKey)
			return
		}
		s.fail(w, r, err)
		return
	}
	if apiErr := checkCopySourcePreconditions(r, manifest.ETag, manifest.CreatedAt); apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}

	// Metadata and tagging directives.
	metadataDirective := strings.ToUpper(strings.TrimSpace(r.Header.Get("x-amz-metadata-directive")))
	if metadataDirective == "" {
		metadataDirective = "COPY"
	}
	if metadataDirective != "COPY" && metadataDirective != "REPLACE" {
		s.fail(w, r, ErrInvalidArgument.withMessage("Invalid x-amz-metadata-directive %q.", metadataDirective))
		return
	}
	taggingDirective := strings.ToUpper(strings.TrimSpace(r.Header.Get("x-amz-tagging-directive")))
	if taggingDirective == "" {
		taggingDirective = "COPY"
	}
	if taggingDirective != "COPY" && taggingDirective != "REPLACE" {
		s.fail(w, r, ErrInvalidArgument.withMessage("Invalid x-amz-tagging-directive %q.", taggingDirective))
		return
	}

	var meta map[string]string
	var contentType string
	tags := map[string]string{}
	if metadataDirective == "REPLACE" {
		var apiErr *APIError
		if meta, apiErr = s.collectUserMeta(r); apiErr != nil {
			s.fail(w, r, apiErr)
			return
		}
		contentType = r.Header.Get("Content-Type")
	} else {
		meta = cloneMap(manifest.UserMeta)
		contentType = manifest.ContentType
	}
	if taggingDirective == "REPLACE" {
		var apiErr *APIError
		if tags, apiErr = s.tagsFromPutRequest(r); apiErr != nil {
			s.fail(w, r, apiErr)
			return
		}
	} else {
		for k, v := range manifest.Tags {
			tags[k] = v
		}
	}

	storageClass := strings.ToUpper(strings.TrimSpace(r.Header.Get("x-amz-storage-class")))
	if !validStorageClass(storageClass) {
		s.fail(w, r, ErrInvalidStorageClass)
		return
	}
	storageClass = normalizeStorageClass(storageClass)

	var srcRange *offloader.ByteRange
	if rangeHeader := r.Header.Get("x-amz-copy-source-range"); rangeHeader != "" {
		var apiErr *APIError
		if srcRange, apiErr = parseContentRangeHeader(rangeHeader); apiErr != nil {
			s.fail(w, r, apiErr)
			return
		}
		if srcRange.Start+srcRange.Length > manifest.Size {
			s.fail(w, r, ErrInvalidRange)
			return
		}
	}

	size := manifest.Size
	if srcRange != nil {
		size = srcRange.Length
	}
	if size > s.limits.MaxSinglePut {
		s.fail(w, r, ErrEntityTooLarge)
		return
	}
	rcID, drop, apiErr2 := s.routePlacement(r, dstBucket, t.Key, size, contentType, storageClass)
	if apiErr2 != nil {
		s.fail(w, r, apiErr2)
		return
	}
	if drop {
		s.fail(w, r, ErrAccessDenied.withMessage("Upload rejected by Smart Data Placement policy."))
		return
	}

	versionID, _ := s.mintVersionID(dstBucket)
	spec := s.objectSpec(dstBucket, t.Key, versionID, size, contentType, meta, tags, storageClass, rcID)
	if s.cfg.Compat.ConditionalWrites {
		spec.IfMatch = r.Header.Get("If-Match")
		spec.IfNoneMatch = r.Header.Get("If-None-Match")
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	pr, pw := io.Pipe()
	go func() {
		err := s.off.Read(ctx, offloader.ReadRequest{
			Bucket:    src.Bucket,
			Key:       src.Key,
			TenantID:  manifest.TenantID,
			ProjectID: manifest.ProjectID,
			Manifest:  manifest,
			Range:     srcRange,
		}, pw)
		_ = pw.CloseWithError(err)
	}()
	res, err := s.off.Write(ctx, spec, pr)
	cancel()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteETag(res.ETag))
	versionHeader(w.Header(), dstBucket, res.VersionID)
	writeXML(w, http.StatusOK, copyObjectResultXML{
		LastModified: xmlTime(s.now()),
		ETag:         quoteETag(res.ETag),
	})
}

// ---------------------------------------------------------------------------
// Object ACL
// ---------------------------------------------------------------------------

func (s *Server) handleGetObjectACL(w http.ResponseWriter, r *http.Request, t target) {
	b, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.authorizeBucket(r, contract.ActionGetObjectAcl, b, t.Key, nil); err != nil {
		s.fail(w, r, err)
		return
	}
	owner := ownerID(b)
	acl, err := s.coord.GetObjectACL(r.Context(), t.Bucket, t.Key, versionFromQuery(r))
	if err != nil {
		if errors.Is(err, contract.ErrNotFound) {
			acl = defaultACL(owner)
		} else {
			s.fail(w, r, err)
			return
		}
	}
	if len(acl.Grants) == 0 {
		acl = defaultACL(owner)
	}
	writeXML(w, http.StatusOK, aclToXML(acl, ownerDisplayName(s.principal(r))))
}

func (s *Server) handlePutObjectACL(w http.ResponseWriter, r *http.Request, t target) {
	b, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.authorizeBucket(r, contract.ActionPutObjectAcl, b, t.Key, nil); err != nil {
		s.fail(w, r, err)
		return
	}
	if b.Ownership == "BucketOwnerEnforced" {
		s.fail(w, r, ErrACLNotSupported)
		return
	}
	owner := ownerID(b)
	acl, apiErr := aclFromRequest(r, owner, owner)
	if apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	if err := s.coord.PutObjectACL(r.Context(), t.Bucket, t.Key, versionFromQuery(r), acl); err != nil {
		s.fail(w, r, err)
		return
	}
	writeEmpty(w, http.StatusOK)
}

func isTrueHeader(r *http.Request, name string) bool {
	return strings.EqualFold(strings.TrimSpace(r.Header.Get(name)), "true")
}

func cloneMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
