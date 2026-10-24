package s3

import (
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/gateway/authz"
	"github.com/fass-storage/fass/internal/gateway/offloader"
	"github.com/fass-storage/fass/internal/gateway/sigv4"
)

// APIError is an S3 error with its wire representation (docs/05 §7).
type APIError struct {
	Code     string
	Message  string
	Status   int
	Resource string
	// Header carries extra response headers, e.g. Retry-After.
	Header http.Header
}

// Error implements error.
func (e *APIError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Is matches API errors by code so callers can use errors.Is.
func (e *APIError) Is(target error) bool {
	var t *APIError
	if errors.As(target, &t) {
		return e.Code == t.Code
	}
	return false
}

// withResource returns a copy carrying the request resource.
func (e *APIError) withResource(res string) *APIError {
	cp := *e
	cp.Resource = res
	return &cp
}

// withMessage returns a copy with a different message.
func (e *APIError) withMessage(format string, args ...any) *APIError {
	cp := *e
	cp.Message = fmt.Sprintf(format, args...)
	return &cp
}

func apiErr(code, message string, status int) *APIError {
	return &APIError{Code: code, Message: message, Status: status}
}

// The error taxonomy from docs/05 §7. Keep this list in sync with the docs.
var (
	ErrAccessDenied          = apiErr("AccessDenied", "Access Denied.", http.StatusForbidden)
	ErrInvalidAccessKeyID    = apiErr("InvalidAccessKeyId", "The AWS Access Key Id you provided does not exist in our records.", http.StatusForbidden)
	ErrSignatureMismatch     = apiErr("SignatureDoesNotMatch", "The request signature we calculated does not match the signature you provided. Check your key and signing method.", http.StatusForbidden)
	ErrRequestTimeSkewed     = apiErr("RequestTimeTooSkewed", "The difference between the request time and the current time is too large.", http.StatusForbidden)
	ErrNoSuchBucket          = apiErr("NoSuchBucket", "The specified bucket does not exist.", http.StatusNotFound)
	ErrNoSuchKey             = apiErr("NoSuchKey", "The specified key does not exist.", http.StatusNotFound)
	ErrBucketAlreadyExists   = apiErr("BucketAlreadyExists", "The requested bucket name is not available. The bucket namespace is shared by all users of the system. Please select a different name and try again.", http.StatusConflict)
	ErrBucketAlreadyOwned    = apiErr("BucketAlreadyOwnedByYou", "Your previous request to create the named bucket succeeded and you already own it.", http.StatusConflict)
	ErrBucketNotEmpty        = apiErr("BucketNotEmpty", "The bucket you tried to delete is not empty.", http.StatusConflict)
	ErrInvalidBucketName     = apiErr("InvalidBucketName", "The specified bucket is not valid.", http.StatusBadRequest)
	ErrInvalidArgument       = apiErr("InvalidArgument", "Invalid Argument.", http.StatusBadRequest)
	ErrInvalidRequest        = apiErr("InvalidRequest", "Invalid Request.", http.StatusBadRequest)
	ErrInvalidStorageClass   = apiErr("InvalidStorageClass", "The storage class you specified is not valid.", http.StatusBadRequest)
	ErrPreconditionFailed    = apiErr("PreconditionFailed", "At least one of the pre-conditions you specified did not hold.", http.StatusPreconditionFailed)
	ErrNotModified           = apiErr("NotModified", "Not Modified.", http.StatusNotModified)
	ErrInvalidRange          = apiErr("InvalidRange", "The requested range is not satisfiable.", http.StatusRequestedRangeNotSatisfiable)
	ErrEntityTooLarge        = apiErr("EntityTooLarge", "Your proposed upload exceeds the maximum allowed object size.", http.StatusBadRequest)
	ErrEntityTooSmall        = apiErr("EntityTooSmall", "Your proposed upload is smaller than the minimum allowed object size.", http.StatusBadRequest)
	ErrBadDigest             = apiErr("BadDigest", "The Content-MD5 you specified did not match what we received.", http.StatusBadRequest)
	ErrInvalidPart           = apiErr("InvalidPart", "One or more of the specified parts could not be found. The part may not have been uploaded, or the specified entity tag may not match the part's entity tag.", http.StatusBadRequest)
	ErrInvalidPartOrder      = apiErr("InvalidPartOrder", "The list of parts was not in ascending order. Parts must be ordered by part number.", http.StatusBadRequest)
	ErrNoSuchUpload          = apiErr("NoSuchUpload", "The specified multipart upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.", http.StatusNotFound)
	ErrACLNotSupported       = apiErr("AccessControlListNotSupported", "The bucket does not allow ACLs.", http.StatusBadRequest)
	ErrInvalidBucketACL      = apiErr("InvalidBucketAclWithObjectOwnership", "Bucket cannot have ACLs set with ObjectOwnership's BucketOwnerEnforced setting.", http.StatusBadRequest)
	ErrObjectLockConfigFault = apiErr("ObjectLockConfigurationNotFoundError", "Object Lock configuration does not exist for this bucket.", http.StatusNotFound)
	ErrInvalidRetention      = apiErr("InvalidRetentionPeriod", "The retention period specified is not valid.", http.StatusBadRequest)
	ErrNotImplemented        = apiErr("NotImplemented", "A header or query you provided implies functionality that is not implemented.", http.StatusNotImplemented)
	ErrMethodNotAllowed      = apiErr("MethodNotAllowed", "The specified method is not allowed against this resource.", http.StatusMethodNotAllowed)
	ErrSlowDown              = apiErr("SlowDown", "Please reduce your request rate.", http.StatusServiceUnavailable)
	ErrInternalError         = apiErr("InternalError", "We encountered an internal error. Please try again.", http.StatusInternalServerError)
	ErrServiceUnavailable    = apiErr("ServiceUnavailable", "Please reduce your request rate.", http.StatusServiceUnavailable)
	ErrMalformedXML          = apiErr("MalformedXML", "The XML you provided was not well-formed or did not validate against our published schema.", http.StatusBadRequest)
	ErrInvalidTag            = apiErr("InvalidTag", "The tag provided was not a valid tag.", http.StatusBadRequest)
	ErrNoSuchTagSet          = apiErr("NoSuchTagSet", "The TagSet does not exist.", http.StatusNotFound)
	ErrNoSuchLifecycle       = apiErr("NoSuchLifecycleConfiguration", "The lifecycle configuration does not exist.", http.StatusNotFound)
	ErrInvalidBucketState    = apiErr("InvalidBucketState", "The request is not valid with the current state of the bucket.", http.StatusConflict)
	ErrKeyTooLong            = apiErr("KeyTooLongError", "Your key is too long.", http.StatusBadRequest)
	ErrIncompleteBody        = apiErr("IncompleteBody", "You did not provide the number of bytes specified by the Content-Length HTTP header.", http.StatusBadRequest)
	ErrInvalidPartNumber     = apiErr("InvalidArgument", "Part number must be an integer between 1 and 10000, inclusive.", http.StatusBadRequest)
	ErrAuthorizationQuery    = apiErr("AuthorizationQueryParametersError", "Query-string authentication version 4 requires the X-Amz-Algorithm, X-Amz-Credential, X-Amz-Signature, X-Amz-Date, X-Amz-SignedHeaders, and X-Amz-Expires parameters.", http.StatusBadRequest)
)

// mapError normalises any error from the layers below into an *APIError.
func mapError(err error) *APIError {
	if err == nil {
		return nil
	}
	var api *APIError
	if errors.As(err, &api) {
		return api
	}

	// Preserve HTTP status semantics from lower layers (e.g. the coordinator
	// returns 405 for a GET of an explicit delete-marker version).
	// Control-plane errors carry an HTTP status and often a typed code/message.
	// They must be mapped here, first: falling through used to turn every
	// coordinator 400 (invalid continuation token, retention period, markers, …)
	// into a 500 and hide the whole validation surface.
	if api := mapStatusError(err); api != nil {
		return api
	}

	// Contract layer.
	switch {
	case errors.Is(err, contract.ErrNotFound):
		return ErrNoSuchKey
	case errors.Is(err, contract.ErrAlreadyExists):
		return ErrBucketAlreadyExists
	case errors.Is(err, contract.ErrConflict):
		return ErrInvalidBucketState
	case errors.Is(err, contract.ErrForbidden):
		return ErrAccessDenied
	case errors.Is(err, contract.ErrPrecondition):
		return ErrPreconditionFailed
	case errors.Is(err, contract.ErrNotImplemented):
		return ErrNotImplemented
	case errors.Is(err, contract.ErrUnavailable):
		return ErrServiceUnavailable
	case errors.Is(err, contract.ErrInsufficientCap):
		return ErrServiceUnavailable
	}

	// Offloader layer.
	switch {
	case errors.Is(err, offloader.ErrBadDigest):
		return ErrBadDigest
	case errors.Is(err, offloader.ErrTooLarge):
		return ErrEntityTooLarge
	case errors.Is(err, offloader.ErrIncompleteBody):
		return ErrIncompleteBody
	case errors.Is(err, offloader.ErrNoSuchUpload):
		return ErrNoSuchUpload
	case errors.Is(err, offloader.ErrNotImplemented):
		return ErrNotImplemented
	}

	// Authentication layer.
	switch {
	case errors.Is(err, authz.ErrUnsigned):
		return ErrAccessDenied.withMessage("Anonymous access is not allowed for this operation.")
	case errors.Is(err, authz.ErrAccessDenied):
		return ErrAccessDenied
	case errors.Is(err, authz.ErrPrincipalUnknown):
		return ErrInvalidAccessKeyID
	case errors.Is(err, sigv4.ErrInvalidAccessKeyID):
		return ErrInvalidAccessKeyID
	case errors.Is(err, sigv4.ErrSignatureMismatch):
		return ErrSignatureMismatch
	case errors.Is(err, sigv4.ErrRequestTimeSkewed), errors.Is(err, sigv4.ErrExpiredPresign):
		return ErrRequestTimeSkewed
	case errors.Is(err, sigv4.ErrMissingAuth):
		return ErrAccessDenied.withMessage("Anonymous access is not allowed for this operation.")
	case errors.Is(err, sigv4.ErrUnsupportedAlgorithm), errors.Is(err, sigv4.ErrMalformedAuth),
		errors.Is(err, sigv4.ErrMissingSignedHost), errors.Is(err, sigv4.ErrInvalidPayloadHash):
		return ErrAuthorizationQuery.withMessage("%s", err.Error())
	case errors.Is(err, sigv4.ErrV2Malformed), errors.Is(err, sigv4.ErrV2MissingAuth), errors.Is(err, sigv4.ErrV2Expired):
		return ErrAuthorizationQuery.withMessage("%s", err.Error())
	}

	// Context cancellation / timeouts.
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return ErrIncompleteBody
	}

	// Never leak internal details to the client, but keep the message for logs.
	return ErrInternalError
}

// statusError is the shape of an error crossing the coordinator boundary. The
// coordinator's client implements it; tests can implement it too.
type statusError interface {
	HTTPStatus() int
	ErrorCode() string
	ErrorMessage() string
}

// mapStatusError converts a transport-level status error into the matching S3
// error, preserving the coordinator's typed code and message for client errors.
// It returns nil when err carries no status.
func mapStatusError(err error) *APIError {
	var se statusError
	if !errors.As(err, &se) {
		return nil
	}
	status := se.HTTPStatus()
	code, message := se.ErrorCode(), se.ErrorMessage()

	var base *APIError
	switch status {
	case http.StatusBadRequest:
		base = ErrInvalidArgument
	case http.StatusForbidden:
		base = ErrAccessDenied
	case http.StatusNotFound:
		base = ErrNoSuchKey
	case http.StatusMethodNotAllowed:
		base = ErrMethodNotAllowed
	case http.StatusConflict:
		base = ErrInvalidBucketState
	case http.StatusPreconditionFailed:
		base = ErrPreconditionFailed
	case http.StatusNotImplemented:
		base = ErrNotImplemented
	case http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusGatewayTimeout:
		base = ErrServiceUnavailable
	case http.StatusInsufficientStorage:
		// Storage exhaustion is transient from the client's point of view; S3
		// has no 507 class, so expose the retryable 503.
		base = ErrServiceUnavailable
	case http.StatusInternalServerError:
		// Never leak an internal error message; the gateway log has the detail.
		return ErrInternalError
	default:
		return nil
	}

	// The coordinator uses "InvalidRequest" as a generic bad-request code; S3
	// clients expect the documented "InvalidArgument" class for malformed
	// parameters (AWS itself answers a bad continuation token that way), so
	// normalise it while keeping the coordinator's precise message. Specific S3
	// 400 codes (InvalidPart, EntityTooLarge, …) are preserved.
	if status == http.StatusBadRequest && code == "InvalidRequest" {
		code = ErrInvalidArgument.Code
	}

	// "SlowDown" is the documented 503 code and carries Retry-After semantics.
	if code == "SlowDown" {
		out := *ErrSlowDown
		if message != "" {
			out.Message = message
		}
		return &out
	}
	if code != "" {
		out := *base
		out.Code = code
		if message != "" {
			out.Message = message
		}
		return &out
	}
	if message != "" {
		out := *base
		out.Message = message
		return &out
	}
	return base
}
