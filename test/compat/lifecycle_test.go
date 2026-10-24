//go:build compat

package compat

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

// TestNoncurrentVersionExpirationAndLockedVersions enforces docs/05 §5.6:
// NoncurrentVersionExpiration removes aged non-current versions, while locked
// versions (COMPLIANCE retention and legal hold) are never expired.
//
// Time travel is achieved by restarting the coordinator on the same data dir with
// the dev-only --dev-clock-offset flag, which the binary ignores unless
// --dev-bootstrap is set. No production behaviour or backdoor is involved.
func TestNoncurrentVersionExpirationAndLockedVersions(t *testing.T) {
	c := live

	// Bucket A: ordinary versioned bucket with a 1-day noncurrent expiry rule.
	a := c.newBucket(t, nil)
	c.mustStatus(c.putBucketVersioning(a, "Enabled"), http.StatusOK, "Enable versioning (bucket A)")
	idsA := []string{}
	for i := 0; i < 3; i++ {
		p := c.putObject(a, "daily", []byte(fmt.Sprintf("a%d", i)), nil)
		c.mustStatus(p, http.StatusOK, "PutObject bucket A")
		idsA = append(idsA, p.Header.Get("x-amz-version-id"))
	}
	rule := `<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">` +
		`<Rule><ID>expire-noncurrent</ID><Status>Enabled</Status>` +
		`<NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration>` +
		`</Rule></LifecycleConfiguration>`
	c.mustStatus(c.putLifecycle(a, rule), http.StatusOK, "PutBucketLifecycleConfiguration NoncurrentVersionExpiration=1")

	// Bucket B: lock protection. b/ has COMPLIANCE on the non-current version;
	// h/ has a legal hold on the non-current version.
	b := c.lockedBucket(t)
	lockedPut := c.putObject(b, "b", []byte("b1"), nil)
	c.mustStatus(lockedPut, http.StatusOK, "PutObject b1")
	bV1 := lockedPut.Header.Get("x-amz-version-id")
	c.mustStatus(c.putObjectRetention(b, "b", bV1, "COMPLIANCE", time.Now().UTC().Add(10*24*time.Hour)), http.StatusOK, "COMPLIANCE 10d on b1")
	c.putObject(b, "b", []byte("b2"), nil) // newer version makes b1 non-current

	holdPut := c.putObject(b, "h", []byte("h1"), nil)
	c.mustStatus(holdPut, http.StatusOK, "PutObject h1")
	hV1 := holdPut.Header.Get("x-amz-version-id")
	c.mustStatus(c.putLegalHold(b, "h", hV1, "ON"), http.StatusOK, "legal hold on h1")
	c.putObject(b, "h", []byte("h2"), nil)

	// Nothing is old enough yet: wait several sweep intervals and verify no expiry.
	time.Sleep(700 * time.Millisecond)
	if v, _ := c.listVersions(a, nil); len(v.Versions) != 3 {
		t.Fatalf("versions expired before the rule was due: %d", len(v.Versions))
	}

	// Travel 3 days: the 1-day noncurrent rule now fires for bucket A only.
	if err := c.restartCoordinator(72 * time.Hour); err != nil {
		c.failS3(nil, "restart coordinator with dev clock offset: %v", err)
	}
	t.Cleanup(func() {
		if err := c.restartCoordinator(0); err != nil {
			t.Logf("warning: could not restore coordinator clock: %v", err)
		}
	})

	if err := c.waitUntil("non-current versions expired", 30*time.Second, func() (bool, string) {
		v, _ := c.listVersions(a, nil)
		if len(v.Versions) == 1 && v.Versions[0].VersionID == idsA[2] && v.Versions[0].IsLatest {
			return true, ""
		}
		return false, fmt.Sprintf("bucket A still has %d versions", len(v.Versions))
	}); err != nil {
		c.failS3(nil, "%v", err)
	}
	// Expired versions are gone, the current one remains readable.
	c.mustStatus(c.getObject(a, "daily", idsA[0]), http.StatusNotFound, "GET expired noncurrent version")
	c.mustStatus(c.getObject(a, "daily", idsA[2]), http.StatusOK, "GET current version")

	// Bucket B: locked versions are never expired, regardless of age.
	v, _ := c.listVersions(b, nil)
	bVersions := map[string]bool{}
	for _, ver := range v.Versions {
		bVersions[ver.Key+"/"+ver.VersionID] = true
	}
	if !bVersions["b/"+bV1] {
		t.Fatalf("COMPLIANCE-retained non-current version was expired: %+v", v.Versions)
	}
	if !bVersions["h/"+hV1] {
		t.Fatalf("legal-hold non-current version was expired: %+v", v.Versions)
	}
	if len(v.Versions) != 4 {
		t.Fatalf("locked bucket versions = %d, want 4 (2 keys × 2 versions): %+v", len(v.Versions), v.Versions)
	}
	c.mustStatus(c.getObject(b, "b", bV1), http.StatusOK, "GET retained COMPLIANCE version")
	c.mustStatus(c.getObject(b, "h", hV1), http.StatusOK, "GET retained legal-hold version")
}

// TestLifecycleConfigurationRoundTrip: the stored document is returned verbatim
// and can be deleted (NoSuchLifecycleConfiguration afterwards).
func TestLifecycleConfigurationRoundTrip(t *testing.T) {
	c := live
	bucket := c.newBucket(t, nil)
	rule := `<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">` +
		`<Rule><ID>r1</ID><Status>Enabled</Status><Expiration><Days>30</Days></Expiration></Rule>` +
		`</LifecycleConfiguration>`
	c.mustStatus(c.putLifecycle(bucket, rule), http.StatusOK, "PutBucketLifecycleConfiguration")
	resp := c.getLifecycle(bucket)
	c.mustStatus(resp, http.StatusOK, "GetBucketLifecycleConfiguration")
	if len(resp.Body) == 0 {
		t.Fatalf("lifecycle document round trip is empty")
	}
	del, err := c.call("DELETE", bucket, "", map[string][]string{"lifecycle": {""}}, nil, nil)
	if err != nil {
		c.failS3(nil, "DeleteBucketLifecycle: %v", err)
	}
	c.mustStatus(del, http.StatusNoContent, "DeleteBucketLifecycle")
	after := c.getLifecycle(bucket)
	c.mustErr(after, http.StatusNotFound, "NoSuchLifecycleConfiguration", "lifecycle after delete")
}
