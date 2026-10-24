// Package lifecycle executes the partial S3 lifecycle surface documented in
// docs/05-s3-api.md §5.6: Expiration and NoncurrentVersionExpiration (plus
// ExpiredObjectDeleteMarker). The gateway validates and stores the configuration
// opaquely; the coordinator owns the clock-driven sweep because it owns the
// metadata.
//
// Invariants:
//   - a version protected by retention or legal hold is never expired, whatever
//     the mode (COMPLIANCE, GOVERNANCE) and whoever asks;
//   - expiry is metadata-first: the version is tombstoned and its shards are
//     queued for the deletion GC, never deleted inline;
//   - the sweep is idempotent; a crashed pass simply runs again.
package lifecycle

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/coord/coerr"
	"github.com/fass-storage/fass/internal/coord/meta"
)

// DefaultInterval is how often the sweep runs in production. Expiry precision is
// days, so this only bounds how late an eligible version is collected.
const DefaultInterval = 15 * time.Minute

// Config configures the executor.
type Config struct {
	Interval time.Duration
	// Now overrides the clock (tests via the dev-gated coordinator offset).
	Now    func() time.Time
	Logger *slog.Logger
}

func (c Config) withDefaults() Config {
	if c.Interval <= 0 {
		c.Interval = DefaultInterval
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return c
}

// Result reports one sweep.
type Result struct {
	Buckets           int
	NoncurrentExpired int
	CurrentExpired    int
	MarkersExpired    int
	Locked            int
}

// Executor sweeps lifecycle configurations and expires eligible versions.
type Executor struct {
	meta *meta.Service
	cfg  Config

	noncurrent atomic.Int64
	current    atomic.Int64
	markers    atomic.Int64
	locked     atomic.Int64
	lastRun    atomic.Int64
}

// New creates the executor.
func New(m *meta.Service, cfg Config) *Executor {
	return &Executor{meta: m, cfg: cfg.withDefaults()}
}

// Run sweeps immediately and then on a timer until ctx is cancelled.
func (e *Executor) Run(ctx context.Context) {
	ticker := time.NewTicker(e.cfg.Interval)
	defer ticker.Stop()
	for {
		if _, err := e.RunOnce(ctx, e.cfg.Now()); err != nil && !errors.Is(err, context.Canceled) {
			e.cfg.Logger.Warn("lifecycle sweep failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// lifecycleConfiguration mirrors the subset of the S3 document the gateway
// accepts (docs/05 §5.6). Rule elements the gateway rejects never reach here.
type lifecycleConfiguration struct {
	Rules []struct {
		ID         string `xml:"ID"`
		Status     string `xml:"Status"`
		Expiration *struct {
			Date                      string `xml:"Date"`
			Days                      int    `xml:"Days"`
			ExpiredObjectDeleteMarker *bool  `xml:"ExpiredObjectDeleteMarker"`
		} `xml:"Expiration"`
		NoncurrentVersionExpiration *struct {
			NoncurrentDays int `xml:"NoncurrentDays"`
		} `xml:"NoncurrentVersionExpiration"`
	} `xml:"Rule"`
}

// RunOnce performs one sweep.
func (e *Executor) RunOnce(ctx context.Context, now time.Time) (Result, error) {
	var res Result
	if err := ctx.Err(); err != nil {
		return res, err
	}
	buckets, err := e.meta.ListBuckets(ctx, contract.Principal{IsRoot: true})
	if err != nil {
		return res, fmt.Errorf("lifecycle: list buckets: %w", err)
	}
	var errs []error
	for _, b := range buckets {
		raw, err := e.meta.GetBucketLifecycle(ctx, b.Name)
		if err != nil {
			if errors.Is(err, coerr.ErrNotFound) || coerr.CodeOf(err) == "NoSuchLifecycleConfiguration" {
				continue
			}
			errs = append(errs, fmt.Errorf("bucket %s: read lifecycle: %w", b.Name, err))
			continue
		}
		var doc lifecycleConfiguration
		if err := xml.Unmarshal(raw, &doc); err != nil {
			errs = append(errs, fmt.Errorf("bucket %s: parse lifecycle: %w", b.Name, err))
			continue
		}
		res.Buckets++
		for _, rule := range doc.Rules {
			if !strings.EqualFold(rule.Status, "Enabled") {
				continue
			}
			if err := e.applyRule(ctx, b, rule, now, &res); err != nil {
				errs = append(errs, fmt.Errorf("bucket %s: %w", b.Name, err))
			}
		}
	}
	e.lastRun.Store(now.Unix())
	if len(errs) > 0 {
		return res, errors.Join(errs...)
	}
	return res, nil
}

func (e *Executor) applyRule(ctx context.Context, bucket contract.BucketConfig, rule struct {
	ID         string `xml:"ID"`
	Status     string `xml:"Status"`
	Expiration *struct {
		Date                      string `xml:"Date"`
		Days                      int    `xml:"Days"`
		ExpiredObjectDeleteMarker *bool  `xml:"ExpiredObjectDeleteMarker"`
	} `xml:"Expiration"`
	NoncurrentVersionExpiration *struct {
		NoncurrentDays int `xml:"NoncurrentDays"`
	} `xml:"NoncurrentVersionExpiration"`
}, now time.Time, res *Result) error {
	versions, err := e.meta.ListVersions(ctx, bucket.BucketID)
	if err != nil {
		return fmt.Errorf("list versions: %w", err)
	}

	if nc := rule.NoncurrentVersionExpiration; nc != nil && nc.NoncurrentDays > 0 {
		cutoff := now.Add(-time.Duration(nc.NoncurrentDays) * 24 * time.Hour)
		for _, v := range versions {
			if v.IsLatest {
				continue
			}
			if v.CreatedAt.IsZero() || v.CreatedAt.After(cutoff) {
				continue
			}
			expired, err := e.meta.ExpireVersion(ctx, bucket.BucketID, v.Key, v.VersionID)
			if err != nil {
				return fmt.Errorf("expire noncurrent %s@%s: %w", v.Key, v.VersionID, err)
			}
			if expired {
				res.NoncurrentExpired++
				e.noncurrent.Add(1)
			} else {
				res.Locked++
				e.locked.Add(1)
			}
		}
	}

	if exp := rule.Expiration; exp != nil {
		// ExpiredObjectDeleteMarker: remove a delete marker that is the latest
		// version when it is the only remaining version of its key.
		if exp.ExpiredObjectDeleteMarker != nil && *exp.ExpiredObjectDeleteMarker {
			live := make(map[string]int)
			marker := make(map[string]contract.VersionID)
			for _, v := range versions {
				live[v.Key]++
				if v.IsLatest && v.IsDeleteMarker {
					marker[v.Key] = v.VersionID
				}
			}
			for key, versionID := range marker {
				if live[key] != 1 {
					continue
				}
				expired, err := e.meta.ExpireVersion(ctx, bucket.BucketID, key, versionID)
				if err != nil {
					return fmt.Errorf("expire delete marker %s@%s: %w", key, versionID, err)
				}
				if expired {
					res.MarkersExpired++
					e.markers.Add(1)
				} else {
					res.Locked++
					e.locked.Add(1)
				}
			}
		}

		// Expiration (Days or Date) applies to the current version. Deleting the
		// current version keeps S3 semantics: a versioned bucket gets a delete
		// marker, an unversioned bucket is tombstoned; a locked version is never
		// touched.
		var cutoff time.Time
		hasCutoff := false
		if exp.Days > 0 {
			cutoff = now.Add(-time.Duration(exp.Days) * 24 * time.Hour)
			hasCutoff = true
		} else if strings.TrimSpace(exp.Date) != "" {
			if d, err := time.Parse(time.RFC3339, strings.TrimSpace(exp.Date)); err == nil {
				cutoff = d
				hasCutoff = true
			}
		}
		if hasCutoff {
			for _, v := range versions {
				if !v.IsLatest || v.IsDeleteMarker {
					continue
				}
				if v.CreatedAt.IsZero() || v.CreatedAt.After(cutoff) {
					continue
				}
				// Lifecycle never touches a version protected by retention or a
				// legal hold, even for the current version (S3 skips it entirely
				// rather than hiding it behind a marker).
				if lockedVersion(v, now) {
					res.Locked++
					e.locked.Add(1)
					continue
				}
				_, _, err := e.meta.DeleteObject(ctx, bucket.Name, v.Key, "", false)
				switch {
				case err == nil:
					res.CurrentExpired++
					e.current.Add(1)
				case errors.Is(err, coerr.ErrObjectLocked):
					res.Locked++
					e.locked.Add(1)
				default:
					return fmt.Errorf("expire current %s: %w", v.Key, err)
				}
			}
		}
	}
	return nil
}

// lockedVersion reports whether retention or a legal hold protects a version at
// time now. Governance bypass is irrelevant to lifecycle: S3 never expires
// locked versions.
func lockedVersion(v meta.VersionInfo, now time.Time) bool {
	r := v.Retention
	if r == nil {
		return false
	}
	if r.LegalHold {
		return true
	}
	if r.Mode == "" || r.RetainUntil.IsZero() {
		return false
	}
	return now.Before(r.RetainUntil)
}

// Stats exposes counters for the metrics handler.
func (e *Executor) Stats() map[string]int64 {
	return map[string]int64{
		"noncurrent_expired_total":   e.noncurrent.Load(),
		"current_expired_total":      e.current.Load(),
		"markers_expired_total":      e.markers.Load(),
		"locked_skipped_total":       e.locked.Load(),
		"last_run_timestamp_seconds": e.lastRun.Load(),
	}
}
