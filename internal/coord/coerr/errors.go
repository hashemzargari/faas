// Package coerr defines the coordinator's typed error taxonomy and its mapping
// to HTTP status codes and wire error codes.
//
// The mapping mirrors docs/04-services.md §12 (S3 error classes) and
// docs/07-wire-api.md §1.7 (the Cubbit-compatible announce taxonomy, where the
// exact message strings are part of the contract).
package coerr

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/fass-storage/fass/internal/contract"
)

// Error is a coordinator error carrying a wire code and HTTP status.
type Error struct {
	Status  int    // HTTP status
	Code    string // machine-readable wire code
	Message string // human-readable message (stable for the announce taxonomy)
	Err     error  // optional wrapped cause
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
	}
	return e.Code + ": " + e.Message
}

func (e *Error) Unwrap() error { return e.Err }

// E builds a coordinator error. Message is used verbatim on the wire.
func E(status int, code, format string, args ...any) *Error {
	return &Error{Status: status, Code: code, Message: fmt.Sprintf(format, args...)}
}

// Wrap builds a coordinator error with a cause.
func Wrap(err error, status int, code, message string) *Error {
	return &Error{Status: status, Code: code, Message: message, Err: err}
}

// Wire error codes. The announce codes are the Cubbit-compatible taxonomy.
const (
	CodeNoSuchBucket      = "NoSuchBucket"
	CodeNoSuchKey         = "NoSuchKey"
	CodeBucketNotEmpty    = "BucketNotEmpty"
	CodeBucketAlreadyOwned = "BucketAlreadyOwnedByYou"
	CodeAccessDenied      = "AccessDenied"
	CodeInvalidRequest    = "InvalidRequest"
	CodeInvalidPart       = "InvalidPart"
	CodeEntityTooLarge    = "EntityTooLarge"
	CodePreconditionFailed = "PreconditionFailed"
	CodeObjectLocked      = "AccessDenied"
	CodeMethodNotAllowed  = "MethodNotAllowed"
	CodeNotImplemented    = "NotImplemented"
	CodeSlowDown          = "SlowDown"
	CodeServiceUnavailable = "ServiceUnavailable"
	CodeInternal          = "InternalError"
	CodeConflict          = "Conflict"
	CodeInsufficientStorage = "InsufficientStorage"
	CodeNotFound          = "NotFound"
	CodeInvalidArgument   = "InvalidArgument"

	// Announce taxonomy — docs/07 §1.7.
	CodePortMismatch    = "PortMismatch"
	CodeSecretNotFound  = "SecretNotFound"
	CodeDuplicatePublicKey = "DuplicatePublicKey"
	CodeNotPending      = "NotPending"
	CodeSecretMismatch  = "SecretMismatch"
	CodeMaintenance     = "Maintenance"
)

var (
	ErrNoSuchBucket  = &Error{Status: http.StatusNotFound, Code: CodeNoSuchBucket, Message: "The specified bucket does not exist"}
	ErrNoSuchKey     = &Error{Status: http.StatusNotFound, Code: CodeNoSuchKey, Message: "The specified key does not exist"}
	ErrBucketNotEmpty = &Error{Status: http.StatusConflict, Code: CodeBucketNotEmpty, Message: "The bucket you tried to delete is not empty"}
	ErrAccessDenied  = &Error{Status: http.StatusForbidden, Code: CodeAccessDenied, Message: "Access Denied"}
	ErrInvalidRequest = &Error{Status: http.StatusBadRequest, Code: CodeInvalidRequest, Message: "Invalid request"}
	ErrInvalidPart   = &Error{Status: http.StatusBadRequest, Code: CodeInvalidPart, Message: "One or more of the specified parts could not be found"}
	ErrEntityTooLarge = &Error{Status: http.StatusBadRequest, Code: CodeEntityTooLarge, Message: "Your proposed upload exceeds the maximum allowed object size"}
	ErrPreconditionFailed = &Error{Status: http.StatusPreconditionFailed, Code: CodePreconditionFailed, Message: "At least one of the preconditions you specified did not hold"}
	ErrObjectLocked  = &Error{Status: http.StatusForbidden, Code: CodeObjectLocked, Message: "Object is protected by retention or legal hold"}
	ErrMethodNotAllowed = &Error{Status: http.StatusMethodNotAllowed, Code: CodeMethodNotAllowed, Message: "The specified method is not allowed against this resource"}
	ErrNotImplemented = &Error{Status: http.StatusNotImplemented, Code: CodeNotImplemented, Message: "A header or operation you provided implies functionality that is not implemented"}
	ErrSlowDown      = &Error{Status: http.StatusServiceUnavailable, Code: CodeSlowDown, Message: "Please reduce your request rate"}
	ErrServiceUnavailable = &Error{Status: http.StatusServiceUnavailable, Code: CodeServiceUnavailable, Message: "Service is unavailable, please retry"}
	ErrInternal      = &Error{Status: http.StatusInternalServerError, Code: CodeInternal, Message: "We encountered an internal error. Please try again"}
	ErrConflict      = &Error{Status: http.StatusConflict, Code: CodeConflict, Message: "Conflicting state"}
	ErrInsufficientStorage = &Error{Status: http.StatusInsufficientStorage, Code: CodeInsufficientStorage, Message: "Insufficient storage capacity"}
	ErrNotFound      = &Error{Status: http.StatusNotFound, Code: CodeNotFound, Message: "Not found"}

	// Announce errors. Messages are frozen by docs/07 §1.7.
	ErrPortMismatch       = &Error{Status: http.StatusBadRequest, Code: CodePortMismatch, Message: "Port mismatch"}
	ErrSecretNotFound     = &Error{Status: http.StatusForbidden, Code: CodeSecretNotFound, Message: "Secret not found"}
	ErrDuplicatePublicKey = &Error{Status: http.StatusConflict, Code: CodeDuplicatePublicKey, Message: "Agent with the same public key already exists"}
	ErrNotPending         = &Error{Status: http.StatusConflict, Code: CodeNotPending, Message: "agent is not in pending status"}
	ErrSecretMismatch     = &Error{Status: http.StatusConflict, Code: CodeSecretMismatch, Message: "Secret mismatch"}
	ErrMaintenance        = &Error{Status: http.StatusServiceUnavailable, Code: CodeMaintenance, Message: "under maintenance"}
)

// Invalidf builds a 400 InvalidRequest error with a specific message.
func Invalidf(format string, args ...any) *Error {
	return E(http.StatusBadRequest, CodeInvalidRequest, format, args...)
}

// From normalises any error to a *Error, mapping contract sentinels and unknown
// errors to the right wire class. Unknown errors become a generic 500 so
// internal details never leak to a client.
func From(err error) *Error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	switch {
	case errors.Is(err, contract.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, contract.ErrAlreadyExists):
		return &Error{Status: http.StatusConflict, Code: CodeConflict, Message: "Already exists"}
	case errors.Is(err, contract.ErrConflict):
		return ErrConflict
	case errors.Is(err, contract.ErrForbidden):
		return ErrAccessDenied
	case errors.Is(err, contract.ErrPrecondition):
		return ErrPreconditionFailed
	case errors.Is(err, contract.ErrNotImplemented):
		return ErrNotImplemented
	case errors.Is(err, contract.ErrUnavailable):
		return ErrServiceUnavailable
	case errors.Is(err, contract.ErrInsufficientCap):
		return ErrInsufficientStorage
	}
	// Wrapped sentinels keep their class even when they are not the outermost
	// error (e.g. fmt.Errorf("...: %w", ErrNoSuchKey)).
	for _, se := range sentinels {
		if errors.Is(err, se) {
			return se
		}
	}
	return &Error{Status: http.StatusInternalServerError, Code: CodeInternal, Message: ErrInternal.Message, Err: err}
}

var sentinels = []*Error{
	ErrNoSuchBucket, ErrNoSuchKey, ErrBucketNotEmpty, ErrAccessDenied,
	ErrInvalidRequest, ErrInvalidPart, ErrEntityTooLarge, ErrPreconditionFailed,
	ErrObjectLocked, ErrMethodNotAllowed, ErrNotImplemented, ErrSlowDown,
	ErrServiceUnavailable, ErrInternal, ErrConflict, ErrInsufficientStorage,
	ErrPortMismatch, ErrSecretNotFound, ErrDuplicatePublicKey, ErrNotPending,
	ErrSecretMismatch, ErrMaintenance,
}

// StatusOf returns the HTTP status for err (500 for unknown errors).
func StatusOf(err error) int {
	if err == nil {
		return http.StatusOK
	}
	return From(err).Status
}

// CodeOf returns the wire error code for err.
func CodeOf(err error) string {
	if err == nil {
		return ""
	}
	return From(err).Code
}

// MessageOf returns the stable wire message for err. Unknown errors are
// sanitised.
func MessageOf(err error) string {
	if err == nil {
		return ""
	}
	e := From(err)
	if e.Status >= 500 && e.Code == CodeInternal {
		return ErrInternal.Message
	}
	return e.Message
}

// IsClientError reports whether err maps to a 4xx status.
func IsClientError(err error) bool {
	s := StatusOf(err)
	return s >= 400 && s < 500
}

// sanitize removes newlines so a message is safe to place in a JSON/HTTP header
// field.
func sanitize(s string) string { return strings.ReplaceAll(strings.TrimSpace(s), "\n", " ") }
