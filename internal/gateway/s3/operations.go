package s3

import (
	"net/http"
)

// operation identifies the S3 action a request maps to. The names match the S3
// API operation names so logs, metrics and tests read naturally.
type operation string

const (
	opInvalid operation = "Invalid"

	opListBuckets             operation = "ListBuckets"
	opCreateBucket            operation = "CreateBucket"
	opDeleteBucket            operation = "DeleteBucket"
	opHeadBucket              operation = "HeadBucket"
	opGetBucketLocation       operation = "GetBucketLocation"
	opGetBucketVersioning     operation = "GetBucketVersioning"
	opPutBucketVersioning     operation = "PutBucketVersioning"
	opGetBucketACL            operation = "GetBucketAcl"
	opPutBucketACL            operation = "PutBucketAcl"
	opGetBucketLifecycle      operation = "GetBucketLifecycleConfiguration"
	opPutBucketLifecycle      operation = "PutBucketLifecycleConfiguration"
	opDeleteBucketLifecycle   operation = "DeleteBucketLifecycle"
	opGetOwnershipControls    operation = "GetBucketOwnershipControls"
	opPutOwnershipControls    operation = "PutBucketOwnershipControls"
	opDeleteOwnershipControls operation = "DeleteBucketOwnershipControls"
	opGetObjectLockConfig     operation = "GetObjectLockConfiguration"
	opPutObjectLockConfig     operation = "PutObjectLockConfiguration"

	opListObjects        operation = "ListObjects"
	opListObjectsV2      operation = "ListObjectsV2"
	opListObjectVersions operation = "ListObjectVersions"
	opDeleteObjects      operation = "DeleteObjects"

	opPutObject           operation = "PutObject"
	opGetObject           operation = "GetObject"
	opHeadObject          operation = "HeadObject"
	opDeleteObject        operation = "DeleteObject"
	opCopyObject          operation = "CopyObject"
	opGetObjectACL        operation = "GetObjectAcl"
	opPutObjectACL        operation = "PutObjectAcl"
	opGetObjectTagging    operation = "GetObjectTagging"
	opPutObjectTagging    operation = "PutObjectTagging"
	opDeleteObjectTagging operation = "DeleteObjectTagging"
	opGetObjectRetention  operation = "GetObjectRetention"
	opPutObjectRetention  operation = "PutObjectRetention"
	opGetObjectLegalHold  operation = "GetObjectLegalHold"
	opPutObjectLegalHold  operation = "PutObjectLegalHold"

	opCreateMultipartUpload   operation = "CreateMultipartUpload"
	opUploadPart              operation = "UploadPart"
	opUploadPartCopy          operation = "UploadPartCopy"
	opCompleteMultipartUpload operation = "CompleteMultipartUpload"
	opAbortMultipartUpload    operation = "AbortMultipartUpload"
	opListParts               operation = "ListParts"
	opListMultipartUploads    operation = "ListMultipartUploads"

	// opUnsupported maps to the 54 operations in docs/05 §3 that we answer with
	// NotImplemented, exactly like Cubbit.
	opUnsupported operation = "NotImplemented"
)

func (o operation) String() string { return string(o) }

var unsupportedBucketQueries = map[string]bool{
	"policy": true, "publicAccessBlock": true, "cors": true, "website": true,
	"logging": true, "replication": true, "notification": true,
	"encryption": true, "analytics": true, "inventory": true, "metrics": true,
	"intelligent-tiering": true, "requestPayment": true, "accelerate": true,
	// Bucket tagging is explicitly unsupported (object tagging is supported).
	"tagging": true,
}

var unsupportedObjectQueries = map[string]bool{
	"torrent": true, "restore": true, "attributes": true, "select": true,
}

// resolveOperation maps method + address + query/headers onto an operation.
func resolveOperation(r *http.Request, t target) operation {
	q := r.URL.Query()
	has := func(k string) bool { return q.Has(k) }

	if !t.hasBucket() {
		if r.Method == http.MethodGet {
			return opListBuckets
		}
		return opUnsupported
	}
	if t.Key == "" {
		return resolveBucketOperation(r, has)
	}
	return resolveObjectOperation(r, has)
}

func resolveBucketOperation(r *http.Request, has func(string) bool) operation {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		switch {
		case has("location"):
			return opGetBucketLocation
		case has("versioning"):
			return opGetBucketVersioning
		case has("acl"):
			return opGetBucketACL
		case has("lifecycle"):
			return opGetBucketLifecycle
		case has("object-lock"):
			return opGetObjectLockConfig
		case has("ownershipControls"):
			return opGetOwnershipControls
		case has("versions"):
			return opListObjectVersions
		case has("uploads"):
			return opListMultipartUploads
		case has("list-type"):
			return opListObjectsV2
		}
		for k := range unsupportedBucketQueries {
			if has(k) {
				return opUnsupported
			}
		}
		if r.Method == http.MethodHead {
			return opHeadBucket
		}
		return opListObjects

	case http.MethodPut:
		switch {
		case has("versioning"):
			return opPutBucketVersioning
		case has("acl"):
			return opPutBucketACL
		case has("lifecycle"):
			return opPutBucketLifecycle
		case has("object-lock"):
			return opPutObjectLockConfig
		case has("ownershipControls"):
			return opPutOwnershipControls
		}
		for k := range unsupportedBucketQueries {
			if has(k) {
				return opUnsupported
			}
		}
		return opCreateBucket

	case http.MethodDelete:
		switch {
		case has("lifecycle"):
			return opDeleteBucketLifecycle
		case has("ownershipControls"):
			return opDeleteOwnershipControls
		}
		for k := range unsupportedBucketQueries {
			if has(k) {
				return opUnsupported
			}
		}
		return opDeleteBucket

	case http.MethodPost:
		if has("delete") {
			return opDeleteObjects
		}
		return opUnsupported
	}
	return opInvalid
}

func resolveObjectOperation(r *http.Request, has func(string) bool) operation {
	copySource := r.Header.Get("x-amz-copy-source") != ""

	switch r.Method {
	case http.MethodGet:
		switch {
		case has("uploadId"):
			return opListParts
		case has("acl"):
			return opGetObjectACL
		case has("tagging"):
			return opGetObjectTagging
		case has("retention"):
			return opGetObjectRetention
		case has("legal-hold"):
			return opGetObjectLegalHold
		case has("partNumber"):
			return opUnsupported
		}
		for k := range unsupportedObjectQueries {
			if has(k) {
				return opUnsupported
			}
		}
		return opGetObject

	case http.MethodHead:
		return opHeadObject

	case http.MethodPut:
		switch {
		case has("partNumber") || has("uploadId"):
			if copySource {
				return opUploadPartCopy
			}
			return opUploadPart
		case has("acl"):
			return opPutObjectACL
		case has("tagging"):
			return opPutObjectTagging
		case has("retention"):
			return opPutObjectRetention
		case has("legal-hold"):
			return opPutObjectLegalHold
		}
		for k := range unsupportedObjectQueries {
			if has(k) {
				return opUnsupported
			}
		}
		if copySource {
			return opCopyObject
		}
		return opPutObject

	case http.MethodPost:
		switch {
		case has("uploads"):
			return opCreateMultipartUpload
		case has("uploadId"):
			return opCompleteMultipartUpload
		}
		for k := range unsupportedObjectQueries {
			if has(k) {
				return opUnsupported
			}
		}
		return opUnsupported

	case http.MethodDelete:
		switch {
		case has("uploadId"):
			return opAbortMultipartUpload
		case has("tagging"):
			return opDeleteObjectTagging
		}
		return opDeleteObject
	}
	return opInvalid
}

// dispatch routes a resolved operation to its handler.
func (s *Server) dispatch(w http.ResponseWriter, r *http.Request, t target, op operation) {
	switch op {
	case opListBuckets:
		s.handleListBuckets(w, r, t)
	case opCreateBucket:
		s.handleCreateBucket(w, r, t)
	case opDeleteBucket:
		s.handleDeleteBucket(w, r, t)
	case opHeadBucket:
		s.handleHeadBucket(w, r, t)
	case opGetBucketLocation:
		s.handleGetBucketLocation(w, r, t)
	case opGetBucketVersioning:
		s.handleGetBucketVersioning(w, r, t)
	case opPutBucketVersioning:
		s.handlePutBucketVersioning(w, r, t)
	case opGetBucketACL:
		s.handleGetBucketACL(w, r, t)
	case opPutBucketACL:
		s.handlePutBucketACL(w, r, t)
	case opGetBucketLifecycle:
		s.handleGetBucketLifecycle(w, r, t)
	case opPutBucketLifecycle:
		s.handlePutBucketLifecycle(w, r, t)
	case opDeleteBucketLifecycle:
		s.handleDeleteBucketLifecycle(w, r, t)
	case opGetOwnershipControls:
		s.handleGetOwnershipControls(w, r, t)
	case opPutOwnershipControls:
		s.handlePutOwnershipControls(w, r, t)
	case opDeleteOwnershipControls:
		s.handleDeleteOwnershipControls(w, r, t)
	case opGetObjectLockConfig:
		s.handleGetObjectLockConfig(w, r, t)
	case opPutObjectLockConfig:
		s.handlePutObjectLockConfig(w, r, t)
	case opListObjects:
		s.handleListObjects(w, r, t)
	case opListObjectsV2:
		s.handleListObjectsV2(w, r, t)
	case opListObjectVersions:
		s.handleListObjectVersions(w, r, t)
	case opDeleteObjects:
		s.handleDeleteObjects(w, r, t)
	case opPutObject:
		s.handlePutObject(w, r, t)
	case opGetObject:
		s.handleGetObject(w, r, t, false)
	case opHeadObject:
		s.handleGetObject(w, r, t, true)
	case opDeleteObject:
		s.handleDeleteObject(w, r, t)
	case opCopyObject:
		s.handleCopyObject(w, r, t)
	case opGetObjectACL:
		s.handleGetObjectACL(w, r, t)
	case opPutObjectACL:
		s.handlePutObjectACL(w, r, t)
	case opGetObjectTagging:
		s.handleGetObjectTagging(w, r, t)
	case opPutObjectTagging:
		s.handlePutObjectTagging(w, r, t)
	case opDeleteObjectTagging:
		s.handleDeleteObjectTagging(w, r, t)
	case opGetObjectRetention:
		s.handleGetObjectRetention(w, r, t)
	case opPutObjectRetention:
		s.handlePutObjectRetention(w, r, t)
	case opGetObjectLegalHold:
		s.handleGetObjectLegalHold(w, r, t)
	case opPutObjectLegalHold:
		s.handlePutObjectLegalHold(w, r, t)
	case opCreateMultipartUpload:
		s.handleCreateMultipartUpload(w, r, t)
	case opUploadPart:
		s.handleUploadPart(w, r, t)
	case opUploadPartCopy:
		s.handleUploadPartCopy(w, r, t)
	case opCompleteMultipartUpload:
		s.handleCompleteMultipartUpload(w, r, t)
	case opAbortMultipartUpload:
		s.handleAbortMultipartUpload(w, r, t)
	case opListParts:
		s.handleListParts(w, r, t)
	case opListMultipartUploads:
		s.handleListMultipartUploads(w, r, t)
	default:
		s.fail(w, r, ErrMethodNotAllowed)
	}
}
