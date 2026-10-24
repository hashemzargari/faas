// Package bridge implements DS3 Bridge: a write-through, resumable migrator
// that copies objects from an existing S3 endpoint into FASS and deletes each
// source copy only after a verified read-back.
//
// It is deliberately not a data-path proxy: a gateway is not involved. "Reads
// proxy to the source until copied" is the operator-visible contract (point the
// application at the target once the bridge reports completed); the bridge
// itself moves bytes and verifies them.
package bridge

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Status values exposed by the control API.
const (
	StatusReady      = "ready"
	StatusInProgress = "in-progress"
	StatusCompleted  = "completed"
)

// Endpoint describes one S3 side of a migration.
type Endpoint struct {
	Endpoint     string `json:"endpoint"`
	Region       string `json:"region,omitempty"`
	AccessKey    string `json:"access_key"`
	SecretKey    string `json:"secret_key"`
	UsePathStyle bool   `json:"use_path_style,omitempty"`
	// SessionToken is intentionally rejected: the bridge needs permanent
	// credentials that survive the whole (resumable) migration.
	SessionToken string `json:"session_token,omitempty"`
}

func (e Endpoint) validate(role string) error {
	if strings.TrimSpace(e.Endpoint) == "" {
		return fmt.Errorf("bridge: %s endpoint is required", role)
	}
	u, err := url.Parse(e.Endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("bridge: %s endpoint %q must be an http(s) URL", role, e.Endpoint)
	}
	if e.AccessKey == "" || e.SecretKey == "" {
		return fmt.Errorf("bridge: %s access_key and secret_key are required", role)
	}
	if strings.TrimSpace(e.SessionToken) != "" {
		return fmt.Errorf("bridge: %s uses a session token; the bridge requires permanent credentials (no STS)", role)
	}
	return nil
}

// CreateRequest is the POST /v1/bridges body.
type CreateRequest struct {
	Source  Endpoint `json:"source"`
	Target  Endpoint `json:"target"`
	Buckets []string `json:"buckets,omitempty"`
	All     bool     `json:"all,omitempty"`
}

// BucketStatus is per-bucket progress.
type BucketStatus struct {
	Name         string `json:"name"`
	ObjectsTotal int64  `json:"objects_total"`
	Migrated     int64  `json:"migrated"`
	Failed       int64  `json:"failed"`
	Skipped      int64  `json:"skipped"`
	Bytes        int64  `json:"bytes"`
	Completed    bool   `json:"completed"`
}

// Status is the GET /v1/bridges/{id} body.
type Status struct {
	BridgeID  string         `json:"bridge_id"`
	Status    string         `json:"status"`
	CreatedAt time.Time      `json:"created_at"`
	Buckets   []BucketStatus `json:"buckets"`
	Error     string         `json:"error,omitempty"`
}

// Per-object outcomes persisted in the journal (resume + reporting).
const (
	objectMigrated = "migrated"
	objectFailed   = "failed"
	objectSkipped  = "skipped"
)

// Options configures the manager and migration workers.
type Options struct {
	// DataDir holds one JSON journal per bridge (mode 0600).
	DataDir string
	// Concurrency bounds simultaneous object transfers. Default 4.
	Concurrency int
	// MaxBytesPerSecond throttles source reads (0 = unlimited).
	MaxBytesPerSecond int64
	// MaxRequestsPerSecond throttles S3 API calls (0 = unlimited).
	MaxRequestsPerSecond int
	// MultipartThreshold is the object size at/above which multipart upload is
	// used (default 8 MiB, safely above FASS's 5 MiB minimum part size).
	MultipartThreshold int64
	// PartSize is the multipart part size (default 8 MiB).
	PartSize int64
	// HTTPClient overrides the S3 HTTP client (tests use httptest servers).
	HTTPClient *http.Client
	// Log receives per-object failures and lifecycle events (default slog.Default).
	Log *slog.Logger
	// Now overrides time.Now in tests.
	Now func() time.Time
}

// ErrNotFound maps an S3 404 (object or bucket missing).
var ErrNotFound = errors.New("bridge: not found")

// ObjectLockError is returned when a source bucket has Object Lock enabled; the
// bridge refuses to migrate it because deleting source copies after a verified
// read-back is not allowed under retention.
type ObjectLockError struct {
	Bucket string
}

func (e *ObjectLockError) Error() string {
	return fmt.Sprintf("bridge: source bucket %q has Object Lock enabled; unlock it or exclude the bucket (documented limitation)", e.Bucket)
}
