package api

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/coord/coerr"
	"github.com/fass-storage/fass/internal/coord/id"
)

// ---------------------------------------------------------------------------
// §1.2 Buckets
// ---------------------------------------------------------------------------

func (s *Server) handleCreateBucket(w http.ResponseWriter, r *http.Request) {
	var cfg contract.BucketConfig
	if err := readJSON(w, r, &cfg); err != nil {
		writeError(w, r, err)
		return
	}
	if cfg.Name == "" {
		writeError(w, r, coerr.Invalidf("bucket name is required"))
		return
	}
	if cfg.BucketID == "" {
		cfg.BucketID = contract.BucketID(id.New())
	}
	if err := s.svc.CreateBucket(r.Context(), cfg); err != nil {
		writeError(w, r, err)
		return
	}
	// Return the stored configuration, not the request: the coordinator applies
	// defaults (region, ownership, creation time) that the caller should observe.
	stored, err := s.svc.GetBucket(r.Context(), cfg.Name)
	if err != nil {
		writeError(w, r, err)
		return
	}
	w.Header().Set("Location", "/v1/buckets/"+cfg.Name)
	writeJSON(w, r, http.StatusCreated, stored)
}

// handleListBuckets lists buckets. The control plane is an internal mTLS service;
// the gateway supplies the principal it authenticated. Without a tenant filter the
// call behaves as root (console/admin behaviour).
func (s *Server) handleListBuckets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	principal := contract.Principal{
		TenantID:  contract.TenantID(q.Get("tenant_id")),
		ProjectID: contract.ProjectID(q.Get("project_id")),
		IsRoot:    q.Get("tenant_id") == "",
	}
	if r.Header.Get("X-Fass-Tenant") != "" {
		principal.TenantID = contract.TenantID(r.Header.Get("X-Fass-Tenant"))
		principal.ProjectID = contract.ProjectID(r.Header.Get("X-Fass-Project"))
		principal.IsRoot = false
	}
	buckets, err := s.svc.ListBuckets(r.Context(), principal)
	if err != nil {
		writeError(w, r, err)
		return
	}
	if buckets == nil {
		buckets = []contract.BucketConfig{}
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"buckets": buckets})
}

func (s *Server) handleGetBucket(w http.ResponseWriter, r *http.Request) {
	bucket, err := cleanBucket(r.PathValue("bucket"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	cfg, err := s.svc.GetBucket(r.Context(), bucket)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, cfg)
}

type patchBucketRequest struct {
	Versioning  *string `json:"versioning,omitempty"`
	Ownership   *string `json:"ownership,omitempty"`
	ObjectLock  *bool   `json:"object_lock,omitempty"`
	DefaultRCID *string `json:"default_rc_id,omitempty"`
	QuotaBytes  *int64  `json:"quota_bytes,omitempty"`
}

func (s *Server) handleUpdateBucket(w http.ResponseWriter, r *http.Request) {
	bucket, err := cleanBucket(r.PathValue("bucket"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	var patch patchBucketRequest
	if err := readJSON(w, r, &patch); err != nil {
		writeError(w, r, err)
		return
	}
	cfg, err := s.svc.GetBucket(r.Context(), bucket)
	if err != nil {
		writeError(w, r, err)
		return
	}
	if patch.Versioning != nil {
		cfg.Versioning = *patch.Versioning
	}
	if patch.Ownership != nil {
		cfg.Ownership = *patch.Ownership
	}
	if patch.ObjectLock != nil {
		cfg.ObjectLock = *patch.ObjectLock
	}
	if patch.DefaultRCID != nil {
		cfg.DefaultRCID = *patch.DefaultRCID
	}
	if patch.QuotaBytes != nil {
		cfg.QuotaBytes = *patch.QuotaBytes
	}
	if err := s.svc.UpdateBucketConfig(r.Context(), cfg); err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, cfg)
}

func (s *Server) handleDeleteBucket(w http.ResponseWriter, r *http.Request) {
	bucket, err := cleanBucket(r.PathValue("bucket"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	if err := s.svc.DeleteBucket(r.Context(), bucket); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetBucketLocation(w http.ResponseWriter, r *http.Request) {
	bucket, err := cleanBucket(r.PathValue("bucket"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	cfg, err := s.svc.GetBucket(r.Context(), bucket)
	if err != nil {
		writeError(w, r, err)
		return
	}
	region := cfg.Region
	if region == "" {
		region = contract.DefaultRegion
	}
	writeJSON(w, r, http.StatusOK, map[string]string{"region": region})
}

// ---------------------------------------------------------------------------
// §1.4b Bucket sub-resources
// ---------------------------------------------------------------------------

func (s *Server) handleGetBucketACL(w http.ResponseWriter, r *http.Request) {
	bucket, err := cleanBucket(r.PathValue("bucket"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	acl, err := s.svc.GetBucketACL(r.Context(), bucket)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, acl)
}

func (s *Server) handlePutBucketACL(w http.ResponseWriter, r *http.Request) {
	bucket, err := cleanBucket(r.PathValue("bucket"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	var acl contract.ACL
	if err := readJSON(w, r, &acl); err != nil {
		writeError(w, r, err)
		return
	}
	if err := s.svc.PutBucketACL(r.Context(), bucket, acl); err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, acl)
}

func (s *Server) handleGetBucketLifecycle(w http.ResponseWriter, r *http.Request) {
	bucket, err := cleanBucket(r.PathValue("bucket"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	xml, err := s.svc.GetBucketLifecycle(r.Context(), bucket)
	if err != nil {
		writeError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(xml)
}

func (s *Server) handlePutBucketLifecycle(w http.ResponseWriter, r *http.Request) {
	bucket, err := cleanBucket(r.PathValue("bucket"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	defer r.Body.Close()
	body := http.MaxBytesReader(w, r.Body, 1<<20)
	xml, err := readAllLimited(body, 1<<20)
	if err != nil {
		writeError(w, r, coerr.Invalidf("invalid lifecycle body: %v", err))
		return
	}
	if err := s.svc.PutBucketLifecycle(r.Context(), bucket, xml); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDeleteBucketLifecycle(w http.ResponseWriter, r *http.Request) {
	bucket, err := cleanBucket(r.PathValue("bucket"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	if err := s.svc.DeleteBucketLifecycle(r.Context(), bucket); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// §1.4 Objects
// ---------------------------------------------------------------------------

func (s *Server) handleCommitObject(w http.ResponseWriter, r *http.Request) {
	var req contract.CommitRequest
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	result, err := s.svc.CommitObject(r.Context(), req)
	if err != nil {
		writeError(w, r, err)
		return
	}
	s.metrics.commits.Add(1)
	writeJSON(w, r, http.StatusOK, map[string]any{
		"version_id": result.VersionID,
		"etag":       result.ETag,
	})
}

func (s *Server) handleGetObject(w http.ResponseWriter, r *http.Request) {
	bucket, err := cleanBucket(r.PathValue("bucket"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	key, sub := objectSubresource(r)
	if sub != "" {
		s.handleObjectSubresourceGet(w, r, bucket, key, sub)
		return
	}
	if key == "" {
		writeError(w, r, coerr.Invalidf("object key is required"))
		return
	}
	manifest, err := s.svc.GetManifest(r.Context(), bucket, key, objectVersion(r))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, manifest)
}

func (s *Server) handleHeadObject(w http.ResponseWriter, r *http.Request) {
	bucket, err := cleanBucket(r.PathValue("bucket"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	key := objectKey(r)
	manifest, err := s.svc.GetManifest(r.Context(), bucket, key, objectVersion(r))
	if err != nil {
		writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", "\""+manifest.ETag+"\"")
	w.Header().Set("X-Fass-Version-Id", string(manifest.VersionID))
	w.Header().Set("X-Fass-Size", strconv.FormatInt(manifest.Size, 10))
	w.Header().Set("Last-Modified", manifest.CreatedAt.UTC().Format(http.TimeFormat))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDeleteObject(w http.ResponseWriter, r *http.Request) {
	bucket, err := cleanBucket(r.PathValue("bucket"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	key, sub := objectSubresource(r)
	if sub == "tags" {
		if err := s.svc.PutObjectTags(r.Context(), bucket, key, objectVersion(r), map[string]string{}); err != nil {
			writeError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if key == "" {
		writeError(w, r, coerr.Invalidf("object key is required"))
		return
	}
	version, marker, err := s.svc.DeleteObject(r.Context(), bucket, key, objectVersion(r), boolQuery(r, "bypass"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]any{
		"version_id":    version,
		"delete_marker": marker,
	})
}

func (s *Server) handleListObjects(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	bucketName := q.Get("bucket")
	bucketID := contract.BucketID(q.Get("bucket_id"))
	if bucketName != "" {
		cfg, err := s.svc.GetBucket(r.Context(), bucketName)
		if err != nil {
			writeError(w, r, err)
			return
		}
		bucketID = cfg.BucketID
	}
	if bucketID == "" {
		writeError(w, r, coerr.Invalidf("bucket or bucket_id is required"))
		return
	}
	maxKeys, err := intQuery(r, "max_keys", 0)
	if err != nil {
		writeError(w, r, err)
		return
	}
	result, err := s.svc.ListObjects(r.Context(), contract.ListRequest{
		BucketID:          bucketID,
		Prefix:            q.Get("prefix"),
		Delimiter:         q.Get("delimiter"),
		MaxKeys:           maxKeys,
		StartAfter:        q.Get("start_after"),
		ContinuationToken: q.Get("token"),
		Versions:          boolQuery(r, "versions"),
	})
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, result)
}

// handlePutObjectSubresource handles the docs/07 §1.4b object PUT sub-resources.
func (s *Server) handlePutObjectSubresource(w http.ResponseWriter, r *http.Request) {
	bucket, err := cleanBucket(r.PathValue("bucket"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	key, sub := objectSubresource(r)
	version := objectVersion(r)
	if sub == "" || key == "" {
		writeError(w, r, coerr.ErrMethodNotAllowed)
		return
	}
	switch sub {
	case "tags":
		var body struct {
			Tags map[string]string `json:"tags"`
		}
		if err := readJSON(w, r, &body); err != nil {
			writeError(w, r, err)
			return
		}
		if body.Tags == nil {
			body.Tags = map[string]string{}
		}
		err = s.svc.PutObjectTags(r.Context(), bucket, key, version, body.Tags)
	case "retention":
		var ret contract.Retention
		if derr := readJSON(w, r, &ret); derr != nil {
			writeError(w, r, derr)
			return
		}
		err = s.svc.PutObjectRetention(r.Context(), bucket, key, version, &ret)
	case "legal-hold":
		var body struct {
			LegalHold bool `json:"legal_hold"`
		}
		if derr := readJSON(w, r, &body); derr != nil {
			writeError(w, r, derr)
			return
		}
		err = s.svc.Meta.PutObjectLegalHold(r.Context(), bucket, key, version, body.LegalHold)
	case "acl":
		var acl contract.ACL
		if derr := readJSON(w, r, &acl); derr != nil {
			writeError(w, r, derr)
			return
		}
		err = s.svc.PutObjectACL(r.Context(), bucket, key, version, acl)
	default:
		err = coerr.ErrMethodNotAllowed
	}
	if err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleObjectSubresourceGet(w http.ResponseWriter, r *http.Request, bucket, key, sub string) {
	version := objectVersion(r)
	switch sub {
	case "tags":
		tags, err := s.svc.GetObjectTags(r.Context(), bucket, key, version)
		if err != nil {
			writeError(w, r, err)
			return
		}
		writeJSON(w, r, http.StatusOK, map[string]any{"tags": tags})
	case "retention":
		ret, err := s.svc.GetObjectRetention(r.Context(), bucket, key, version)
		if err != nil {
			writeError(w, r, err)
			return
		}
		if ret == nil {
			writeError(w, r, coerr.E(404, "NoSuchObjectLockConfiguration", "The specified object does not have a retention configuration"))
			return
		}
		writeJSON(w, r, http.StatusOK, ret)
	case "legal-hold":
		ret, err := s.svc.GetObjectRetention(r.Context(), bucket, key, version)
		if err != nil {
			writeError(w, r, err)
			return
		}
		hold := ret != nil && ret.LegalHold
		writeJSON(w, r, http.StatusOK, map[string]any{"legal_hold": hold})
	case "acl":
		acl, err := s.svc.GetObjectACL(r.Context(), bucket, key, version)
		if err != nil {
			writeError(w, r, err)
			return
		}
		writeJSON(w, r, http.StatusOK, acl)
	default:
		writeError(w, r, coerr.ErrMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// §1.5 Multipart
// ---------------------------------------------------------------------------

type createUploadRequest struct {
	Bucket string                 `json:"bucket"`
	Key    string                 `json:"key"`
	Meta   contract.CommitRequest `json:"meta"`
}

func (s *Server) handleCreateUpload(w http.ResponseWriter, r *http.Request) {
	var req createUploadRequest
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	if req.Bucket == "" || req.Key == "" {
		writeError(w, r, coerr.Invalidf("bucket and key are required"))
		return
	}
	req.Meta.BucketID = ""
	uploadID, err := s.svc.CreateUpload(r.Context(), req.Bucket, req.Key, req.Meta)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"upload_id": uploadID})
}

func (s *Server) handleCommitPart(w http.ResponseWriter, r *http.Request) {
	uploadID := contract.UploadID(r.PathValue("uploadID"))
	partNumber, err := strconv.Atoi(r.PathValue("partNumber"))
	if err != nil || partNumber < 1 {
		writeError(w, r, coerr.Invalidf("part number must be a positive integer"))
		return
	}
	var req uploadPartsRequest
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	if err := s.svc.CommitPart(r.Context(), uploadID, partNumber, req.ETag, req.Size, req.Chunks, req.Encryption); err != nil {
		writeError(w, r, err)
		return
	}
	s.metrics.parts.Add(1)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListParts(w http.ResponseWriter, r *http.Request) {
	parts, err := s.svc.ListParts(r.Context(), contract.UploadID(r.PathValue("uploadID")))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"parts": parts})
}

func (s *Server) handleListUploads(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	bucketID := contract.BucketID(q.Get("bucket_id"))
	if name := q.Get("bucket"); name != "" {
		cfg, err := s.svc.GetBucket(r.Context(), name)
		if err != nil {
			writeError(w, r, err)
			return
		}
		bucketID = cfg.BucketID
	}
	if bucketID == "" {
		writeError(w, r, coerr.Invalidf("bucket or bucket_id is required"))
		return
	}
	uploads, err := s.svc.ListUploads(r.Context(), bucketID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"uploads": uploads})
}

// handleCompleteUpload serves POST /v1/uploads/{id}:complete. ServeMux cannot
// match a literal suffix inside a path segment, so the ":complete" verb is parsed
// from the wildcard value.
func (s *Server) handleCompleteUpload(w http.ResponseWriter, r *http.Request) {
	raw := r.PathValue("uploadID")
	idPart, verb := raw, ""
	if i := strings.LastIndex(raw, ":"); i >= 0 {
		idPart, verb = raw[:i], raw[i+1:]
	}
	if verb != "complete" {
		writeError(w, r, coerr.ErrMethodNotAllowed)
		return
	}
	result, err := s.svc.CompleteUpload(r.Context(), contract.UploadID(idPart))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]any{
		"version_id": result.VersionID,
		"etag":       result.ETag,
	})
}

func (s *Server) handleAbortUpload(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.AbortUpload(r.Context(), contract.UploadID(r.PathValue("uploadID"))); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// readAllLimited reads at most max bytes from rd.
func readAllLimited(rd interface{ Read([]byte) (int, error) }, max int64) ([]byte, error) {
	buf := make([]byte, 0, 4096)
	var total int64
	tmp := make([]byte, 4096)
	for {
		n, err := rd.Read(tmp)
		total += int64(n)
		if total > max {
			return nil, coerr.Invalidf("body exceeds %d bytes", max)
		}
		buf = append(buf, tmp[:n]...)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return buf, nil
			}
			return buf, err
		}
	}
}
