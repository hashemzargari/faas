//go:build compat

package compat

import (
	"net/http"
	"testing"
)

// TestObjectTaggingRoundTripRules: PUT/GET/DELETE object tagging round trip, per
// version, with the documented limit of 10 tags.
func TestObjectTaggingRoundTripRules(t *testing.T) {
	c := live
	bucket := c.newBucket(t, nil)
	c.putKeys(t, bucket, "tagged")

	tags := map[string]string{"team": "storage", "env": "compat", "empty": ""}
	c.mustStatus(c.putObjectTagging(bucket, "tagged", "", tags), http.StatusOK, "PutObjectTagging")
	got, _ := c.getObjectTagging(bucket, "tagged", "")
	if len(got) != len(tags) {
		t.Fatalf("tags = %v, want %v", got, tags)
	}
	for k, v := range tags {
		if got[k] != v {
			t.Fatalf("tag %q = %q, want %q", k, got[k], v)
		}
	}

	// Replacing the tag set replaces it entirely (not a merge).
	c.mustStatus(c.putObjectTagging(bucket, "tagged", "", map[string]string{"only": "one"}), http.StatusOK, "PutObjectTagging replace")
	got, _ = c.getObjectTagging(bucket, "tagged", "")
	if len(got) != 1 || got["only"] != "one" {
		t.Fatalf("replaced tags = %v", got)
	}

	c.mustStatus(c.deleteObjectTagging(bucket, "tagged", ""), http.StatusNoContent, "DeleteObjectTagging")
	got, _ = c.getObjectTagging(bucket, "tagged", "")
	if len(got) != 0 {
		t.Fatalf("tags after delete = %v", got)
	}

	// More than 10 tags is rejected (documented limit).
	tooMany := map[string]string{}
	for i := 0; i < 11; i++ {
		tooMany[string(rune('a'+i))] = "x"
	}
	resp := c.putObjectTagging(bucket, "tagged", "", tooMany)
	if resp.Status == http.StatusOK {
		t.Fatalf("11 tags accepted; documented limit is 10")
	}
}

// TestCopyObjectPreservesTags: CopyObject copies tags by default (docs/05 §5.5).
func TestCopyObjectPreservesTags(t *testing.T) {
	c := live
	bucket := c.newBucket(t, nil)
	c.putKeys(t, bucket, "src")
	c.mustStatus(c.putObjectTagging(bucket, "src", "", map[string]string{"copied": "yes"}), http.StatusOK, "tag source")

	c.mustStatus(c.copyObject(bucket, "src", bucket, "dst", nil), http.StatusOK, "CopyObject")
	got, _ := c.getObjectTagging(bucket, "dst", "")
	if got["copied"] != "yes" {
		t.Fatalf("copied object tags = %v, want copied=yes", got)
	}
	// Source tags are untouched.
	srcTags, _ := c.getObjectTagging(bucket, "src", "")
	if srcTags["copied"] != "yes" {
		t.Fatalf("source tags changed: %v", srcTags)
	}
}

// TestInlineTaggingAtUpload: docs/05 §4 lists x-amz-tagging as honoured at upload
// (the deliberate improvement over Cubbit). §5.5 still says "no inline tagging" —
// contradiction reported to the Lead; the suite pins the implemented §4 behaviour
// so a regression is visible either way.
func TestInlineTaggingAtUpload(t *testing.T) {
	c := live
	bucket := c.newBucket(t, nil)
	resp := c.putObject(bucket, "inline", []byte("x"), map[string]string{
		"x-amz-tagging": "inline=yes&other=2",
	})
	c.mustStatus(resp, http.StatusOK, "PutObject with x-amz-tagging")
	got, _ := c.getObjectTagging(bucket, "inline", "")
	if got["inline"] != "yes" || got["other"] != "2" {
		t.Fatalf("inline tags = %v, want inline=yes, other=2 (docs/05 §4 improvement)", got)
	}
}

// TestBucketOwnerEnforcedRejectsACLWrites: docs/05 §5.3 — under
// BucketOwnerEnforced ACL writes fail with AccessControlListNotSupported.
func TestBucketOwnerEnforcedRejectsACLWrites(t *testing.T) {
	c := live
	bucket := c.newBucket(t, map[string]string{"x-amz-object-ownership": "BucketOwnerEnforced"})
	resp := c.putBucketACL(bucket, "public-read")
	c.mustErr(resp, http.StatusBadRequest, "AccessControlListNotSupported", "PUT bucket ACL under BucketOwnerEnforced")
	// GET ACL still works and reports the owner.
	acl, gresp := c.getBucketACL(bucket)
	if acl.Owner.ID == "" {
		c.failS3(gresp, "bucket ACL owner missing")
	}
}

// TestEnablingBucketOwnerEnforcedWithForeignGrantsIsRejected: docs/05 §5.3 —
// InvalidBucketAclWithObjectOwnership when the bucket ACL still grants others.
func TestEnablingBucketOwnerEnforcedWithForeignGrantsIsRejected(t *testing.T) {
	c := live
	bucket := c.newBucket(t, nil)
	// Default ObjectWriter ownership permits ACL writes.
	c.mustStatus(c.putBucketACL(bucket, "public-read"), http.StatusOK, "public-read ACL under ObjectWriter")
	resp := c.putOwnershipControls(bucket, "BucketOwnerEnforced")
	c.mustErr(resp, http.StatusBadRequest, "InvalidBucketAclWithObjectOwnership", "enable BucketOwnerEnforced with public grants")

	// After restoring a private ACL, the ownership change is allowed and ACL
	// writes are then rejected.
	c.mustStatus(c.putBucketACL(bucket, "private"), http.StatusOK, "restore private ACL")
	c.mustStatus(c.putOwnershipControls(bucket, "BucketOwnerEnforced"), http.StatusOK, "enable BucketOwnerEnforced")
	c.mustErr(c.putBucketACL(bucket, "public-read"), http.StatusBadRequest, "AccessControlListNotSupported", "ACL write after ownership change")
}

// TestCannedACLVisibility: public-read actually grants AllUsers READ (docs/05 D6).
func TestCannedACLVisibility(t *testing.T) {
	c := live
	bucket := c.newBucket(t, nil)
	c.mustStatus(c.putBucketACL(bucket, "private"), http.StatusOK, "private ACL")
	if _, resp := c.getBucketACL(bucket); resp.Status != http.StatusOK {
		t.Fatalf("GET ACL status = %d", resp.Status)
	}
	c.mustStatus(c.putBucketACL(bucket, "public-read"), http.StatusOK, "public-read ACL")
	acl, _ := c.getBucketACL(bucket)
	const allUsers = "http://acs.amazonaws.com/groups/global/AllUsers"
	found := false
	for _, g := range acl.Grants {
		if g.Grantee.URI == allUsers && g.Permission == "READ" {
			found = true
		}
	}
	if !found {
		t.Fatalf("public-read ACL grants = %+v, want AllUsers READ", acl.Grants)
	}
}
