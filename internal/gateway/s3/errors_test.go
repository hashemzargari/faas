package s3

import (
	"fmt"
	"net/http"
	"testing"
)

// statusErr mimics a control-plane error: an HTTP status plus the coordinator's
// typed code/message.
type statusErr struct {
	status  int
	code    string
	message string
}

func (e statusErr) Error() string {
	return fmt.Sprintf("%s (HTTP %d): %s", e.code, e.status, e.message)
}
func (e statusErr) HTTPStatus() int   { return e.status }
func (e statusErr) ErrorCode() string { return e.code }
func (e statusErr) ErrorMessage() string {
	return e.message
}

// TestMapCoordinatorStatuses pins the whole S3 mapping surface for errors that
// cross the coordinator boundary. Before G-1 every 400 fell through to 500, which
// hid every validation error (continuation tokens, retention periods, markers…).
func TestMapCoordinatorStatuses(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		code        string
		message     string
		wantStatus  int
		wantCode    string
		wantMessage string // "" means "don't care beyond non-empty"
	}{
		{
			name:   "400 generic InvalidRequest normalises to InvalidArgument, message kept",
			status: http.StatusBadRequest, code: "InvalidRequest",
			message:     "malformed continuation token",
			wantStatus:  http.StatusBadRequest,
			wantCode:    "InvalidArgument",
			wantMessage: "malformed continuation token",
		},
		{
			name:   "400 specific S3 code is preserved",
			status: http.StatusBadRequest, code: "InvalidPart",
			message:     "part etag mismatch",
			wantStatus:  http.StatusBadRequest,
			wantCode:    "InvalidPart",
			wantMessage: "part etag mismatch",
		},
		{
			name:       "400 without a typed code becomes InvalidArgument",
			status:     http.StatusBadRequest,
			wantStatus: http.StatusBadRequest,
			wantCode:   "InvalidArgument",
		},
		{
			name:   "403 AccessDenied",
			status: http.StatusForbidden, code: "AccessDenied", message: "Access Denied.",
			wantStatus: http.StatusForbidden, wantCode: "AccessDenied",
		},
		{
			name:   "404 NoSuchBucket is preserved",
			status: http.StatusNotFound, code: "NoSuchBucket", message: "The specified bucket does not exist.",
			wantStatus: http.StatusNotFound, wantCode: "NoSuchBucket",
		},
		{
			name:   "404 NoSuchKey is preserved",
			status: http.StatusNotFound, code: "NoSuchKey", message: "The specified key does not exist.",
			wantStatus: http.StatusNotFound, wantCode: "NoSuchKey",
		},
		{
			name:   "405 MethodNotAllowed",
			status: http.StatusMethodNotAllowed, code: "MethodNotAllowed", message: "not allowed on a delete marker",
			wantStatus: http.StatusMethodNotAllowed, wantCode: "MethodNotAllowed",
		},
		{
			name:   "409 BucketNotEmpty is preserved",
			status: http.StatusConflict, code: "BucketNotEmpty",
			wantStatus: http.StatusConflict, wantCode: "BucketNotEmpty",
		},
		{
			name:       "409 without a typed code becomes InvalidBucketState",
			status:     http.StatusConflict,
			wantStatus: http.StatusConflict,
			wantCode:   "InvalidBucketState",
		},
		{
			name:       "412 PreconditionFailed",
			status:     http.StatusPreconditionFailed,
			wantStatus: http.StatusPreconditionFailed, wantCode: "PreconditionFailed",
		},
		{
			name:   "500 is internal and does not leak the coordinator message",
			status: http.StatusInternalServerError, code: "InternalError", message: "panic trace: secret detail",
			wantStatus: http.StatusInternalServerError, wantCode: "InternalError",
			wantMessage: "We encountered an internal error. Please try again.",
		},
		{
			name:       "501 NotImplemented",
			status:     http.StatusNotImplemented,
			wantStatus: http.StatusNotImplemented, wantCode: "NotImplemented",
		},
		{
			name:   "503 SlowDown keeps its retryable code",
			status: http.StatusServiceUnavailable, code: "SlowDown", message: "Please reduce your request rate.",
			wantStatus: http.StatusServiceUnavailable, wantCode: "SlowDown",
			wantMessage: "Please reduce your request rate.",
		},
		{
			name:       "503 without a code becomes ServiceUnavailable",
			status:     http.StatusServiceUnavailable,
			wantStatus: http.StatusServiceUnavailable, wantCode: "ServiceUnavailable",
		},
		{
			name:       "507 storage exhaustion becomes a retryable 503",
			status:     http.StatusInsufficientStorage,
			wantStatus: http.StatusServiceUnavailable, wantCode: "ServiceUnavailable",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := statusErr{status: tc.status, code: tc.code, message: tc.message}
			api := mapError(err)
			if api.Status != tc.wantStatus {
				t.Fatalf("status = %d, want %d (%s)", api.Status, tc.wantStatus, api.Code)
			}
			if api.Code != tc.wantCode {
				t.Fatalf("code = %q, want %q", api.Code, tc.wantCode)
			}
			if tc.wantMessage != "" && api.Message != tc.wantMessage {
				t.Fatalf("message = %q, want %q", api.Message, tc.wantMessage)
			}
			if tc.wantMessage == "" && api.Message == "" {
				t.Fatal("empty error message")
			}
			if tc.status == http.StatusInternalServerError && api.Message == tc.message {
				t.Fatal("internal error message leaked to the client")
			}
		})
	}

	// An error with no status still maps through the old paths (unchanged).
	if api := mapError(fmt.Errorf("boom")); api.Code != "InternalError" {
		t.Fatalf("generic error mapped to %q", api.Code)
	}
}
