package meta

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/coord/coerr"
	"github.com/fass-storage/fass/internal/storage"
)

// Listing (docs/04 §5.2).
//
// ListObjectsV2 is an ordered range scan over the latest-version index with
// delimiter grouping done during the scan, never per-object round trips. Version
// listings scan the version table (key ascending, sequence descending) so the
// newest version of each key comes first, as S3 requires.
//
// v1 collects the matching key set in memory before paginating: correct and easy
// to reason about, with the PostgreSQL backend expected to push prefix/delimiter
// down to SQL. MaxKeys is enforced on the collected page, so memory is bounded by
// the number of matching keys rather than by MaxKeys.

const (
	// DefaultMaxKeys mirrors the S3 default page size.
	DefaultMaxKeys = 1000
	// MaxMaxKeys is the S3 upper bound.
	MaxMaxKeys = 1000
)

type candidate struct {
	sortKey  string // object key, or the common prefix for a grouped entry
	seq      uint64 // version sequence (0 for latest-mode entries)
	entry    contract.ObjectEntry
	isPrefix bool
}

type listToken struct {
	Key    string `json:"k"`
	Seq    uint64 `json:"s,omitempty"`
	Prefix bool   `json:"p,omitempty"`
}

func encodeToken(t listToken) string {
	raw, _ := json.Marshal(t) // struct of scalars: cannot fail
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeToken(s string) (listToken, error) {
	var t listToken
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return t, coerr.Invalidf("malformed continuation token")
	}
	if err := json.Unmarshal(raw, &t); err != nil {
		return t, coerr.Invalidf("malformed continuation token")
	}
	return t, nil
}

// ListObjects implements both ListObjects(V2) and ListObjectVersions.
//
// Version listings also carry S3's (KeyMarker, VersionIDMarker) pair; the public
// method passes them once the contract exposes them, while listObjects keeps the
// cursor logic testable independently of the wire struct.
func (s *Service) ListObjects(ctx context.Context, req contract.ListRequest) (contract.ListResult, error) {
	return s.listObjects(ctx, req, req.KeyMarker, contract.VersionID(req.VersionIDMarker))
}

// markerCursor is a resolved version-listing marker: resume strictly after this
// position in the key-ascending / sequence-descending order. SkipKey means the
// whole key was already emitted (or its marker version no longer exists).
type markerCursor struct {
	Key     string
	Seq     uint64
	SkipKey bool
}

// resolveMarker turns S3's (KeyMarker, VersionIDMarker) into a cursor position.
// If the marker version is gone (deleted between pages), S3 resumes after the
// whole key, so that page never repeats a version the client already saw.
func (s *Service) resolveMarker(ctx context.Context, bucketID contract.BucketID, versions bool, keyMarker string, versionIDMarker contract.VersionID) (*markerCursor, error) {
	if keyMarker == "" {
		return nil, nil
	}
	cur := &markerCursor{Key: keyMarker, SkipKey: true}
	if !versions || versionIDMarker == "" {
		return cur, nil
	}
	var seq uint64
	err := s.db.View(ctx, func(tx *storage.ReadTx) error {
		rec, err := storage.GetJSON[versionRecord](tx, spaceVersionIDs, versionIDKey(bucketID, keyMarker, versionIDMarker))
		if errors.Is(err, storage.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if rec.Deleted {
			// The marker version vanished between pages: resume after the whole
			// key, as S3 documents for a missing version-id-marker.
			return nil
		}
		seq = rec.Seq
		cur.SkipKey = false
		return nil
	})
	if err != nil {
		return nil, err
	}
	cur.Seq = seq
	return cur, nil
}

// atOrBeforeMarker reports whether c is at or before the marker position and must
// be skipped.
func atOrBeforeMarker(c candidate, cur markerCursor) bool {
	switch {
	case c.sortKey < cur.Key:
		return true
	case c.sortKey > cur.Key:
		return false
	case cur.SkipKey:
		return true
	case c.isPrefix:
		return true
	default:
		// Same key, newest-first order: everything with seq >= the marker was
		// already returned.
		return c.seq >= cur.Seq
	}
}

func (s *Service) listObjects(ctx context.Context, req contract.ListRequest, keyMarker string, versionIDMarker contract.VersionID) (contract.ListResult, error) {
	var result contract.ListResult
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if req.BucketID == "" {
		return result, coerr.Invalidf("bucket_id is required")
	}
	maxKeys := req.MaxKeys
	if maxKeys <= 0 {
		maxKeys = DefaultMaxKeys
	}
	if maxKeys > MaxMaxKeys {
		maxKeys = MaxMaxKeys
	}
	var token *listToken
	if req.ContinuationToken != "" {
		t, err := decodeToken(req.ContinuationToken)
		if err != nil {
			return result, err
		}
		token = &t
	}

	// Continuation tokens are internal and take precedence; S3 markers are the
	// external resumption contract (ListObjectVersions).
	var marker *markerCursor
	if token == nil && keyMarker != "" {
		m, merr := s.resolveMarker(ctx, req.BucketID, req.Versions, keyMarker, versionIDMarker)
		if merr != nil {
			return result, merr
		}
		marker = m
	}

	cands, err := s.collectCandidates(ctx, req)
	if err != nil {
		return result, err
	}
	// Deterministic order: key ascending; newest version first for version
	// listings.
	sort.SliceStable(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		if a.sortKey != b.sortKey {
			return a.sortKey < b.sortKey
		}
		return a.seq > b.seq
	})

	// StartAfter skips whole keys (all versions of a key for version listings).
	start := 0
	if req.StartAfter != "" {
		for start < len(cands) && cands[start].sortKey <= req.StartAfter {
			start++
		}
	}
	if token != nil {
		for start < len(cands) && !candidateAfter(cands[start], *token) {
			start++
		}
	} else if marker != nil {
		for start < len(cands) && atOrBeforeMarker(cands[start], *marker) {
			start++
		}
	}

	page := cands[start:]
	if len(page) > maxKeys {
		page = page[:maxKeys]
		result.IsTruncated = true
	}
	result.Entries = make([]contract.ObjectEntry, 0, len(page))
	for _, c := range page {
		result.Entries = append(result.Entries, c.entry)
	}
	result.KeyCount = len(result.Entries)
	if result.IsTruncated && len(result.Entries) > 0 {
		last := page[len(page)-1]
		tok := listToken{Key: last.sortKey, Seq: last.seq, Prefix: last.isPrefix}
		result.NextContinuationToken = encodeToken(tok)
		if req.Versions {
			result.NextKeyMarker = last.sortKey
			result.NextVersionIDMarker = string(last.entry.VersionID)
		}
	}
	return result, nil
}

// candidateAfter reports whether c comes strictly after the token position in the
// documented ordering.
func candidateAfter(c candidate, t listToken) bool {
	if c.sortKey != t.Key {
		return c.sortKey > t.Key
	}
	if c.isPrefix || t.Prefix {
		return false // the prefix entry is a single, already-emitted position
	}
	// Same key: versions are ordered newest-first, so a strictly later candidate
	// has a smaller sequence number.
	return c.seq < t.Seq
}

func (s *Service) collectCandidates(ctx context.Context, req contract.ListRequest) ([]candidate, error) {
	if req.Versions {
		return s.collectVersions(ctx, req)
	}
	return s.collectLatest(ctx, req)
}

func (s *Service) collectLatest(ctx context.Context, req contract.ListRequest) ([]candidate, error) {
	var out []candidate
	seenPrefix := make(map[string]bool)
	scanPrefix := append(bucketPrefix(req.BucketID), req.Prefix...)
	err := s.db.View(ctx, func(tx *storage.ReadTx) error {
		return storage.ScanJSON[latestRecord](tx, spaceLatest, scanPrefix, func(k []byte, rec latestRecord) error {
			key := strings.TrimSuffix(string(k[len(bucketPrefix(req.BucketID)):]), "\x00")
			if !strings.HasPrefix(key, req.Prefix) {
				return nil
			}
			if rec.DeleteMarker {
				return nil
			}
			if cp, grouped := groupPrefix(key, req.Prefix, req.Delimiter); grouped {
				if seenPrefix[cp] {
					return nil
				}
				seenPrefix[cp] = true
				out = append(out, candidate{
					sortKey:  cp,
					isPrefix: true,
					entry:    contract.ObjectEntry{CommonPrefix: cp},
				})
				return nil
			}
			out = append(out, candidate{
				sortKey: key,
				entry: contract.ObjectEntry{
					Key:          key,
					Size:         rec.Size,
					ETag:         rec.ETag,
					LastModified: rec.LastModified,
					VersionID:    rec.VersionID,
					IsLatest:     true,
					StorageClass: rec.StorageClass,
				},
			})
			return nil
		})
	})
	return out, err
}

func (s *Service) collectVersions(ctx context.Context, req contract.ListRequest) ([]candidate, error) {
	var out []candidate
	seenPrefix := make(map[string]bool)
	latestByKey := make(map[string]uint64)
	base := bucketPrefix(req.BucketID)
	scanPrefix := append(append([]byte(nil), base...), req.Prefix...)
	err := s.db.View(ctx, func(tx *storage.ReadTx) error {
		if err := storage.ScanJSON[latestRecord](tx, spaceLatest, base, func(_ []byte, rec latestRecord) error {
			latestByKey[rec.Key] = rec.Seq
			return nil
		}); err != nil {
			return err
		}
		return storage.ScanJSON[versionRecord](tx, spaceVersions, scanPrefix, func(k []byte, rec versionRecord) error {
			key := versionKeyToObjectKey(k, base)
			if key == "" || !strings.HasPrefix(key, req.Prefix) {
				return nil
			}
			if rec.Deleted {
				return nil
			}
			if cp, grouped := groupPrefix(key, req.Prefix, req.Delimiter); grouped {
				if seenPrefix[cp] {
					return nil
				}
				seenPrefix[cp] = true
				out = append(out, candidate{
					sortKey:  cp,
					isPrefix: true,
					entry:    contract.ObjectEntry{CommonPrefix: cp},
				})
				return nil
			}
			out = append(out, candidate{
				sortKey: key,
				seq:     rec.Seq,
				entry: contract.ObjectEntry{
					Key:            key,
					Size:           rec.Size,
					ETag:           rec.ETag,
					LastModified:   rec.CreatedAt,
					VersionID:      rec.VersionID,
					IsLatest:       latestByKey[key] == rec.Seq,
					IsDeleteMarker: rec.IsDeleteMarker,
					StorageClass:   rec.StorageClass,
				},
			})
			return nil
		})
	})
	return out, err
}

// groupPrefix applies the delimiter rule: returns the common prefix and whether
// the key should be grouped.
func groupPrefix(key, prefix, delimiter string) (string, bool) {
	if delimiter == "" {
		return "", false
	}
	rest := key[len(prefix):]
	i := strings.Index(rest, delimiter)
	if i < 0 {
		return "", false
	}
	return prefix + rest[:i+len(delimiter)], true
}

// versionKeyToObjectKey parses bucket_id\0key\0seq into the object key.
func versionKeyToObjectKey(k, base []byte) string {
	if !bytes.HasPrefix(k, base) || len(k) <= len(base)+9 {
		return ""
	}
	rest := k[len(base):]
	// The last 9 bytes are the NUL separator plus the 8-byte sequence number.
	key := rest[:len(rest)-9]
	return string(key)
}
