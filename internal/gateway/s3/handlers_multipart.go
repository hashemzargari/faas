package s3

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/gateway/offloader"
)

// cachedUpload is the immutable identity of an in-progress upload.
type cachedUpload struct {
	key       string
	versionID contract.VersionID
	expires   time.Time
}

// uploadCacheTTL bounds how long upload metadata is cached. Uploads never change
// their key or version id, so this only bounds memory for abandoned uploads.
const uploadCacheTTL = 5 * time.Minute

// resolveUpload looks up an upload's version id (minted at CreateMultipartUpload)
// so every part binds it in its chunk AAD. The coordinator's contract exposes the
// version id through UploadInfo.VersionID.
func (s *Server) resolveUpload(ctx context.Context, uploadID contract.UploadID, bucketID contract.BucketID) (cachedUpload, *APIError) {
	now := s.now()
	s.uploadsMu.Lock()
	if up, ok := s.uploadsCache[uploadID]; ok && now.Before(up.expires) {
		s.uploadsMu.Unlock()
		return up, nil
	}
	s.uploadsMu.Unlock()

	uploads, err := s.coord.ListUploads(ctx, bucketID)
	if err != nil {
		return cachedUpload{}, mapError(err)
	}
	for _, up := range uploads {
		if up.UploadID != uploadID {
			continue
		}
		entry := cachedUpload{key: up.Key, versionID: up.VersionID, expires: now.Add(uploadCacheTTL)}
		s.uploadsMu.Lock()
		if len(s.uploadsCache) > 4096 {
			s.uploadsCache = make(map[contract.UploadID]cachedUpload)
		}
		s.uploadsCache[uploadID] = entry
		s.uploadsMu.Unlock()
		return entry, nil
	}
	return cachedUpload{}, ErrNoSuchUpload
}

// handleCreateMultipartUpload implements POST /{bucket}/{key}?uploads.
func (s *Server) handleCreateMultipartUpload(w http.ResponseWriter, r *http.Request, t target) {
	if err := s.validateKey(t.Key); err != nil {
		s.fail(w, r, err)
		return
	}
	b, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.authorizeBucket(r, contract.ActionCreateMultipart, b, t.Key, nil); err != nil {
		s.fail(w, r, err)
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
	rcID, drop, apiErr := s.routePlacement(r, b, t.Key, -1, r.Header.Get("Content-Type"), storageClass)
	if apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	if drop {
		s.fail(w, r, ErrAccessDenied.withMessage("Upload rejected by Smart Data Placement policy."))
		return
	}
	uploadMeta := contract.CommitRequest{
		// The version id is minted here so every part can bind it in its chunk
		// AAD and CompleteUpload can promote it into the manifest.
		VersionID:    contract.VersionID(s.newUUID()),
		BucketID:     b.BucketID,
		Key:          t.Key,
		ContentType:  r.Header.Get("Content-Type"),
		UserMeta:     meta,
		Tags:         tags,
		RCID:         rcID,
		StorageClass: storageClass,
		Retention:    retention,
	}
	uploadID, err := s.coord.CreateUpload(r.Context(), t.Bucket, t.Key, uploadMeta)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeXML(w, http.StatusOK, initiateMultipartUploadResult{
		Bucket:   b.Name,
		Key:      t.Key,
		UploadID: string(uploadID),
	})
}

// parsePartNumber validates the partNumber query parameter.
func parsePartNumber(r *http.Request, max int) (int, *APIError) {
	raw := r.URL.Query().Get("partNumber")
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > max {
		return 0, ErrInvalidPartNumber.withMessage("Part number must be an integer between 1 and %d, inclusive.", max)
	}
	return n, nil
}

// uploadIDParam returns the uploadId query parameter.
func uploadIDParam(r *http.Request) (contract.UploadID, *APIError) {
	id := r.URL.Query().Get("uploadId")
	if id == "" {
		return "", ErrInvalidArgument.withMessage("Missing uploadId.")
	}
	return contract.UploadID(id), nil
}

// handleUploadPart implements PUT /{bucket}/{key}?partNumber&uploadId.
func (s *Server) handleUploadPart(w http.ResponseWriter, r *http.Request, t target) {
	if err := s.validateKey(t.Key); err != nil {
		s.fail(w, r, err)
		return
	}
	partNumber, apiErr := parsePartNumber(r, s.limits.MaxParts)
	if apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	uploadID, apiErr := uploadIDParam(r)
	if apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	b, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.authorizeBucket(r, contract.ActionPutObject, b, t.Key, nil); err != nil {
		s.fail(w, r, err)
		return
	}
	if contentLength(r) > s.limits.PartSizeMax {
		s.fail(w, r, ErrEntityTooLarge.withMessage("Part size exceeds the maximum allowed part size."))
		return
	}
	checksums, apiErr := s.checksumsFromRequest(r)
	if apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	meta, apiErr := s.collectUserMeta(r)
	if apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}

	upload, apiErr := s.resolveUpload(r.Context(), uploadID, b.BucketID)
	if apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	if upload.key != t.Key {
		s.fail(w, r, ErrNoSuchUpload)
		return
	}
	spec := s.objectSpec(b, t.Key, upload.versionID, contentLength(r), r.Header.Get("Content-Type"), meta, nil, "STANDARD", b.DefaultRCID)
	spec.ChunkSize = s.cfg.ChunkSize
	spec.MaxBytes = s.limits.PartSizeMax
	spec.Checksums = checksums
	spec.DeferredChecksums = s.deferredChecksums(r)

	part, err := s.off.WritePart(r.Context(), spec, uploadID, partNumber, r.Body)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.coord.CommitPart(r.Context(), uploadID, partNumber, part.ETag, part.Size, part.Chunks, part.Encryption); err != nil {
		if errors.Is(err, contract.ErrNotFound) {
			s.fail(w, r, ErrNoSuchUpload)
			return
		}
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteETag(part.ETag))
	writeEmpty(w, http.StatusOK)
}

// handleUploadPartCopy implements PUT with x-amz-copy-source on a part.
func (s *Server) handleUploadPartCopy(w http.ResponseWriter, r *http.Request, t target) {
	if err := s.validateKey(t.Key); err != nil {
		s.fail(w, r, err)
		return
	}
	partNumber, apiErr := parsePartNumber(r, s.limits.MaxParts)
	if apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	uploadID, apiErr := uploadIDParam(r)
	if apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	src, apiErr := parseCopySource(r.Header.Get("x-amz-copy-source"))
	if apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	srcBucket, err := s.loadBucket(r, src.Bucket)
	if err != nil {
		s.fail(w, r, err)
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
	if err := s.authorizeBucket(r, contract.ActionPutObject, dstBucket, t.Key, nil); err != nil {
		s.fail(w, r, err)
		return
	}
	upload, apiErr := s.resolveUpload(r.Context(), uploadID, dstBucket.BucketID)
	if apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	if upload.key != t.Key {
		s.fail(w, r, ErrNoSuchUpload)
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
	var srcRange *offloader.ByteRange
	if rangeHeader := r.Header.Get("x-amz-copy-source-range"); rangeHeader != "" {
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
	spec := s.objectSpec(dstBucket, t.Key, upload.versionID, size, manifest.ContentType, manifest.UserMeta, nil, "STANDARD", dstBucket.DefaultRCID)
	spec.MaxBytes = s.limits.PartSizeMax
	part, err := s.off.WritePart(ctx, spec, uploadID, partNumber, pr)
	cancel()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.coord.CommitPart(r.Context(), uploadID, partNumber, part.ETag, part.Size, part.Chunks, part.Encryption); err != nil {
		if errors.Is(err, contract.ErrNotFound) {
			s.fail(w, r, ErrNoSuchUpload)
			return
		}
		s.fail(w, r, err)
		return
	}
	writeXML(w, http.StatusOK, copyPartResultXML{
		LastModified: xmlTime(s.now()),
		ETag:         quoteETag(part.ETag),
	})
}

// handleCompleteMultipartUpload implements POST ?uploadId.
func (s *Server) handleCompleteMultipartUpload(w http.ResponseWriter, r *http.Request, t target) {
	if err := s.validateKey(t.Key); err != nil {
		s.fail(w, r, err)
		return
	}
	uploadID, apiErr := uploadIDParam(r)
	if apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	b, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.authorizeBucket(r, contract.ActionPutObject, b, t.Key, nil); err != nil {
		s.fail(w, r, err)
		return
	}
	var req completeMultipartUploadRequest
	if apiErr := decodeXMLBody(r, 2<<20, &req); apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	if len(req.Parts) == 0 || len(req.Parts) > s.limits.MaxParts {
		s.fail(w, r, ErrMalformedXML.withMessage("The list of parts must contain between 1 and %d entries.", s.limits.MaxParts))
		return
	}
	parts, err := s.coord.ListParts(r.Context(), uploadID)
	if err != nil {
		if errors.Is(err, contract.ErrNotFound) {
			s.fail(w, r, ErrNoSuchUpload)
			return
		}
		s.fail(w, r, err)
		return
	}
	byNumber := make(map[int]contract.PartInfo, len(parts))
	for _, p := range parts {
		byNumber[p.PartNumber] = p
	}
	last := len(req.Parts) - 1
	for i, requested := range req.Parts {
		if i > 0 && requested.PartNumber <= req.Parts[i-1].PartNumber {
			s.fail(w, r, ErrInvalidPartOrder)
			return
		}
		p, ok := byNumber[requested.PartNumber]
		if !ok || !etagMatches(p.ETag, requested.ETag) {
			s.fail(w, r, ErrInvalidPart.withMessage("Part %d is missing or its ETag does not match.", requested.PartNumber))
			return
		}
		if i != last && p.Size < s.limits.PartSizeMin {
			s.fail(w, r, ErrEntityTooSmall.withMessage("Part %d is smaller than the minimum allowed part size.", requested.PartNumber))
			return
		}
	}
	res, err := s.coord.CompleteUpload(r.Context(), uploadID)
	if err != nil {
		if errors.Is(err, contract.ErrNotFound) {
			s.fail(w, r, ErrNoSuchUpload)
			return
		}
		s.fail(w, r, err)
		return
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	location := fmt.Sprintf("%s://%s/%s/%s", scheme, r.Host, t.Bucket, t.Key)
	if b.Versioning == "Enabled" {
		w.Header().Set("x-amz-version-id", string(res.VersionID))
	}
	writeXML(w, http.StatusOK, completeMultipartUploadResult{
		Location: location,
		Bucket:   b.Name,
		Key:      t.Key,
		ETag:     quoteETag(res.ETag),
	})
}

// handleAbortMultipartUpload implements DELETE ?uploadId.
func (s *Server) handleAbortMultipartUpload(w http.ResponseWriter, r *http.Request, t target) {
	uploadID, apiErr := uploadIDParam(r)
	if apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	b, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.authorizeBucket(r, contract.ActionAbortMultipart, b, t.Key, nil); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.coord.AbortUpload(r.Context(), uploadID); err != nil {
		if errors.Is(err, contract.ErrNotFound) {
			s.fail(w, r, ErrNoSuchUpload)
			return
		}
		s.fail(w, r, err)
		return
	}
	writeEmpty(w, http.StatusNoContent)
}

// handleListParts implements GET ?uploadId.
func (s *Server) handleListParts(w http.ResponseWriter, r *http.Request, t target) {
	uploadID, apiErr := uploadIDParam(r)
	if apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	b, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.authorizeBucket(r, contract.ActionListBucket, b, t.Key, nil); err != nil {
		s.fail(w, r, err)
		return
	}
	parts, err := s.coord.ListParts(r.Context(), uploadID)
	if err != nil {
		if errors.Is(err, contract.ErrNotFound) {
			s.fail(w, r, ErrNoSuchUpload)
			return
		}
		s.fail(w, r, err)
		return
	}
	maxParts, apiErr := s.parseMaxParts(r)
	if apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}
	marker, _ := strconv.Atoi(r.URL.Query().Get("part-number-marker"))
	sort.Slice(parts, func(i, j int) bool { return parts[i].PartNumber < parts[j].PartNumber })

	res := listPartsResult{
		Bucket:           b.Name,
		Key:              t.Key,
		UploadID:         string(uploadID),
		PartNumberMarker: marker,
		MaxParts:         maxParts,
	}
	for _, p := range parts {
		if p.PartNumber <= marker {
			continue
		}
		if len(res.Parts) >= maxParts {
			res.IsTruncated = true
			res.NextPartNumberMarker = res.Parts[len(res.Parts)-1].PartNumber
			break
		}
		res.Parts = append(res.Parts, partXML{
			PartNumber:   p.PartNumber,
			LastModified: xmlTime(s.now()),
			ETag:         quoteETag(p.ETag),
			Size:         p.Size,
		})
	}
	writeXML(w, http.StatusOK, res)
}

// handleListMultipartUploads implements GET /{bucket}?uploads.
func (s *Server) handleListMultipartUploads(w http.ResponseWriter, r *http.Request, t target) {
	b, err := s.loadBucket(r, t.Bucket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.authorizeBucket(r, contract.ActionListBucket, b, "", nil); err != nil {
		s.fail(w, r, err)
		return
	}
	q := r.URL.Query()
	prefix := q.Get("prefix")
	delimiter := q.Get("delimiter")
	encodingType := q.Get("encoding-type")
	keyMarker := q.Get("key-marker")
	uploadIDMarker := q.Get("upload-id-marker")
	maxUploads, apiErr := intParam(r, "max-uploads", 1000, 0, s.cfg.ListPageMax)
	if apiErr != nil {
		s.fail(w, r, apiErr)
		return
	}

	uploads, err := s.coord.ListUploads(r.Context(), b.BucketID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sort.Slice(uploads, func(i, j int) bool {
		if uploads[i].Key != uploads[j].Key {
			return uploads[i].Key < uploads[j].Key
		}
		return uploads[i].UploadID < uploads[j].UploadID
	})

	res := listMultipartUploadsResult{
		Bucket:         b.Name,
		KeyMarker:      encodeKey(keyMarker, encodingType),
		UploadIDMarker: uploadIDMarker,
		Prefix:         encodeKey(prefix, encodingType),
		Delimiter:      encodeKey(delimiter, encodingType),
		MaxUploads:     maxUploads,
	}
	owner := &xmlOwner{ID: ownerID(b)}
	seenPrefixes := make(map[string]bool)
	var page []uploadXML
	var commonPrefixes []commonPrefixXML
	pastMarker := keyMarker == ""
	truncated := false
	for _, up := range uploads {
		if !strings.HasPrefix(up.Key, prefix) {
			continue
		}
		if !pastMarker {
			if up.Key < keyMarker {
				continue
			}
			if up.Key == keyMarker {
				if uploadIDMarker != "" && up.UploadID <= contract.UploadID(uploadIDMarker) {
					continue
				}
			} else {
				pastMarker = true
			}
		}
		if delimiter != "" {
			if rest := strings.TrimPrefix(up.Key, prefix); strings.Contains(rest, delimiter) {
				cp := prefix + rest[:strings.Index(rest, delimiter)+len(delimiter)]
				if seenPrefixes[cp] {
					continue
				}
				if len(page)+len(commonPrefixes) >= maxUploads {
					truncated = true
					break
				}
				seenPrefixes[cp] = true
				commonPrefixes = append(commonPrefixes, commonPrefixXML{Prefix: encodeKey(cp, encodingType)})
				continue
			}
		}
		if len(page)+len(commonPrefixes) >= maxUploads {
			truncated = true
			break
		}
		page = append(page, uploadXML{
			Key:          encodeKey(up.Key, encodingType),
			UploadID:     string(up.UploadID),
			Initiator:    owner,
			Owner:        owner,
			StorageClass: storageClassOrDefault(up.StorageClass),
			Initiated:    xmlTime(up.Initiated),
		})
	}
	res.Uploads = page
	res.CommonPrefixes = commonPrefixes
	res.IsTruncated = truncated
	if truncated && len(page) > 0 {
		last := page[len(page)-1]
		res.NextKeyMarker = last.Key
		res.NextUploadIDMarker = last.UploadID
	}
	writeXML(w, http.StatusOK, res)
}

// decodeMultipartXML is a helper for tests to build a completion body.
func decodeMultipartXML(body []byte) ([]completePart, error) {
	var req completeMultipartUploadRequest
	if err := xml.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	return req.Parts, nil
}
