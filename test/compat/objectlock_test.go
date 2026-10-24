//go:build compat

package compat

import (
	"net/http"
	"testing"
	"time"
)

func (c *cluster) lockedBucket(t *testing.T) string {
	t.Helper()
	return c.newBucket(t, map[string]string{"x-amz-bucket-object-lock-enabled": "true"})
}

// TestComplianceRetentionCannotBeShortenedOrDeleted (S3 WORM rule): COMPLIANCE
// can only be extended, and no principal — including root — can shorten or delete
// it before RetainUntil.
func TestComplianceRetentionCannotBeShortenedOrDeleted(t *testing.T) {
	c := live
	bucket := c.lockedBucket(t)
	put := c.putObject(bucket, "worm", []byte("data"), nil)
	c.mustStatus(put, http.StatusOK, "PutObject into locked bucket")
	version := put.Header.Get("x-amz-version-id")
	if version == "" {
		c.failS3(put, "Object Lock bucket must auto-enable versioning and return a version id")
	}

	long := time.Now().UTC().Add(2 * time.Hour)
	c.mustStatus(c.putObjectRetention(bucket, "worm", version, "COMPLIANCE", long), http.StatusOK, "set COMPLIANCE retention")

	// Shortening is rejected.
	short := c.putObjectRetention(bucket, "worm", version, "COMPLIANCE", time.Now().UTC().Add(time.Hour))
	c.mustStatus(short, http.StatusBadRequest, "shorten COMPLIANCE retention")
	if code := errorCode(short); code != "InvalidRetentionPeriod" {
		c.failS3(short, "shorten COMPLIANCE error code = %q, want InvalidRetentionPeriod", code)
	}

	// Extending is allowed.
	extended := long.Add(time.Hour)
	c.mustStatus(c.putObjectRetention(bucket, "worm", version, "COMPLIANCE", extended), http.StatusOK, "extend COMPLIANCE retention")
	ret, _ := c.getObjectRetention(bucket, "worm", version)
	if ret.Mode != "COMPLIANCE" || ret.RetainUntilDate == "" {
		c.failS3(nil, "retention after extend = %+v", ret)
	}

	// Deleting the version is denied even for root, bypass or not.
	c.mustStatus(c.deleteObject(bucket, "worm", version, false), http.StatusForbidden, "delete COMPLIANCE version")
	c.mustStatus(c.deleteObject(bucket, "worm", version, true), http.StatusForbidden, "delete COMPLIANCE version with bypass")
	// The object remains readable.
	c.mustStatus(c.getObject(bucket, "worm", version), http.StatusOK, "GET COMPLIANCE version")
}

// TestGovernanceRetentionRules: GOVERNANCE can be extended without bypass,
// shortened only with bypass + the s3:BypassGovernanceRetention permission, and
// delete needs the bypass header.
func TestGovernanceRetentionRules(t *testing.T) {
	c := live
	bucket := c.lockedBucket(t)
	put := c.putObject(bucket, "gov", []byte("data"), nil)
	c.mustStatus(put, http.StatusOK, "PutObject")
	version := put.Header.Get("x-amz-version-id")

	until := time.Now().UTC().Add(2 * time.Hour)
	c.mustStatus(c.putObjectRetention(bucket, "gov", version, "GOVERNANCE", until), http.StatusOK, "set GOVERNANCE retention")
	// Extend without bypass: allowed.
	c.mustStatus(c.putObjectRetention(bucket, "gov", version, "GOVERNANCE", until.Add(time.Hour)), http.StatusOK, "extend GOVERNANCE retention")
	// Shorten without bypass: denied.
	c.mustStatus(c.putObjectRetention(bucket, "gov", version, "GOVERNANCE", time.Now().UTC().Add(30*time.Minute)), http.StatusForbidden, "shorten GOVERNANCE without bypass")

	// Delete without bypass: denied; with bypass: allowed (root holds the permission).
	c.mustStatus(c.deleteObject(bucket, "gov", version, false), http.StatusForbidden, "delete GOVERNANCE version without bypass")
	c.mustStatus(c.deleteObject(bucket, "gov", version, true), http.StatusNoContent, "delete GOVERNANCE version with bypass")
	c.mustStatus(c.getObject(bucket, "gov", version), http.StatusNotFound, "GET deleted GOVERNANCE version")
}

// TestLegalHoldBlocksDeleteRegardlessOfBypass: legal hold is independent of the
// mode and is never bypassed; clearing it restores deletability.
func TestLegalHoldBlocksDeleteRegardlessOfBypass(t *testing.T) {
	c := live
	bucket := c.lockedBucket(t)
	put := c.putObject(bucket, "hold", []byte("data"), nil)
	c.mustStatus(put, http.StatusOK, "PutObject")
	version := put.Header.Get("x-amz-version-id")

	c.mustStatus(c.putLegalHold(bucket, "hold", version, "ON"), http.StatusOK, "set legal hold ON")
	if status, _ := c.getLegalHold(bucket, "hold", version); status != "ON" {
		t.Fatalf("legal hold status = %q, want ON", status)
	}
	c.mustStatus(c.deleteObject(bucket, "hold", version, false), http.StatusForbidden, "delete under legal hold")
	c.mustStatus(c.deleteObject(bucket, "hold", version, true), http.StatusForbidden, "delete under legal hold with bypass")

	c.mustStatus(c.putLegalHold(bucket, "hold", version, "OFF"), http.StatusOK, "clear legal hold")
	c.mustStatus(c.deleteObject(bucket, "hold", version, false), http.StatusNoContent, "delete after legal hold cleared")
}

// TestRetentionOnDeleteMarkerIsSane: applying retention to a delete-marker
// version must either be rejected explicitly or be honoured (and then block
// non-bypass deletion); it must never 500 or corrupt the marker.
func TestRetentionOnDeleteMarkerIsSane(t *testing.T) {
	c := live
	bucket := c.lockedBucket(t)
	c.putKeys(t, bucket, "m")
	c.mustStatus(c.deleteObject(bucket, "m", "", false), http.StatusNoContent, "create delete marker")
	v, _ := c.listVersions(bucket, nil)
	if len(v.DeleteMarkers) != 1 {
		t.Fatalf("delete markers = %+v", v.DeleteMarkers)
	}
	marker := v.DeleteMarkers[0].VersionID
	future := time.Now().UTC().Add(time.Hour)
	resp := c.putObjectRetention(bucket, "m", marker, "GOVERNANCE", future)
	switch resp.Status {
	case http.StatusOK:
		// Honoured: non-bypass delete of the marker is blocked, bypass works.
		c.mustStatus(c.deleteObject(bucket, "m", marker, false), http.StatusForbidden, "delete retained marker without bypass")
		c.mustStatus(c.deleteObject(bucket, "m", marker, true), http.StatusNoContent, "delete retained marker with bypass")
	case http.StatusBadRequest, http.StatusNotFound:
		// Rejected explicitly (retention is not applicable to markers).
		c.mustStatus(c.deleteObject(bucket, "m", marker, false), http.StatusNoContent, "delete marker without retention")
	default:
		c.failS3(resp, "retention on delete marker returned an unexpected status")
	}
}

func errorCode(resp *s3response) string {
	var e xmlError
	_ = xmlDecode(resp.Body, &e)
	return e.Code
}
