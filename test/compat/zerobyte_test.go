//go:build compat

package compat

import (
	"net/http"
	"strings"
	"testing"
)

// TestZeroByteObjectSemantics is the S3 rule set for empty objects.
//
// It exists because a real DS3 Bridge migration of mixed-size objects found
// that GET of a zero-byte object returned 500 for every client: the coordinator
// stores no manifest blob when there are no chunks, so the read path tried to
// unwrap a zero-length file key. Every suite we had wrote and listed empty
// objects; none of them read one back. Empty files are ubiquitous in backups
// and static sites, so this is a field-grade rule, not an edge case.
func TestZeroByteObjectSemantics(t *testing.T) {
	c := live
	bucket := c.newBucket(t, nil)

	// 1. PUT of an empty body succeeds and yields the S3 ETag for empty input.
	const emptyKey = "empty/object.bin"
	put := c.putObject(bucket, emptyKey, []byte{}, nil)
	c.mustStatus(put, http.StatusOK, "PutObject(empty)")
	if got := strings.Trim(put.Header.Get("ETag"), `"`); got != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Fatalf("PutObject(empty) ETag = %q, want the MD5 of the empty string", got)
	}

	// 2. HEAD reports a zero length (not an absent/empty header).
	head := c.headObject(bucket, emptyKey, "")
	if head.Status != http.StatusOK {
		t.Fatalf("HeadObject(empty) status = %d, want 200", head.Status)
	}
	if cl := head.Header.Get("Content-Length"); cl != "0" {
		t.Fatalf("HeadObject(empty) Content-Length = %q, want \"0\"", cl)
	}

	// 3. The rule that was broken: GET must return 200 with an empty body.
	get := c.getObject(bucket, emptyKey, "")
	if get.Status != http.StatusOK {
		t.Fatalf("GetObject(empty) status = %d, want 200 (body=%q)", get.Status, string(get.Body))
	}
	if len(get.Body) != 0 {
		t.Fatalf("GetObject(empty) returned %d bytes, want 0", len(get.Body))
	}
	if cl := get.Header.Get("Content-Length"); cl != "0" {
		t.Fatalf("GetObject(empty) Content-Length = %q, want \"0\"", cl)
	}

	// 4. A byte range over an empty object is unsatisfiable: 416, not 500.
	rangeResp, err := c.call("GET", bucket, emptyKey, nil, map[string]string{"Range": "bytes=0-0"}, nil)
	if err != nil {
		t.Fatalf("GetObject(empty, Range): %v", err)
	}
	if rangeResp.Status != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("GetObject(empty, Range=bytes=0-0) status = %d, want 416", rangeResp.Status)
	}

	// 5. Copying an empty object produces another empty object.
	copyResp, err := c.call("PUT", bucket, "empty/copy.bin",
		nil, map[string]string{"x-amz-copy-source": "/" + bucket + "/" + emptyKey}, nil)
	if err != nil {
		t.Fatalf("CopyObject(empty): %v", err)
	}
	c.mustStatus(copyResp, http.StatusOK, "CopyObject(empty)")
	if got := c.getObject(bucket, "empty/copy.bin", ""); got.Status != http.StatusOK || len(got.Body) != 0 {
		t.Fatalf("GetObject(copy of empty) status=%d len=%d, want 200/0", got.Status, len(got.Body))
	}

	// 6. Listing reports Size 0 for empty objects, not a missing size.
	list, listResp := c.listV2(bucket, map[string]string{"prefix": "empty/"})
	c.mustStatus(listResp, http.StatusOK, "ListObjectsV2(empty)")
	sizes := map[string]int64{}
	for _, o := range list.Contents {
		sizes[o.Key] = o.Size
	}
	for _, key := range []string{emptyKey, "empty/copy.bin"} {
		if size, ok := sizes[key]; !ok || size != 0 {
			t.Fatalf("ListObjectsV2 %s: size=%d present=%v, want a listed object of size 0", key, size, ok)
		}
	}

	// 7. Deleting an empty object removes it.
	if del := c.deleteObject(bucket, emptyKey, "", false); del.Status != http.StatusNoContent {
		t.Fatalf("DeleteObject(empty) status = %d, want 204", del.Status)
	}
	if gone := c.getObject(bucket, emptyKey, ""); gone.Status != http.StatusNotFound {
		t.Fatalf("GetObject(deleted empty) status = %d, want 404", gone.Status)
	}
}
