//go:build compat

package compat

import (
	"encoding/xml"
	"net/http"
	"sort"
	"testing"
)

func filterKind(seq []versionEntry, kind string) []versionEntry {
	out := []versionEntry{}
	for _, e := range seq {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

func keysOfEntries(entries []versionEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Key)
	}
	return out
}

// versionEntry is one element of a ListObjectVersions document, in document
// order (Versions and DeleteMarkers are interleaved by the server).
type versionEntry struct {
	Kind      string // Version | DeleteMarker
	Key       string
	VersionID string
	IsLatest  bool
}

// parseVersionSequence walks the raw XML to preserve interleaving, which is the
// property that matters for S3 clients paging through versions.
func parseVersionSequence(t *testing.T, c *cluster, body []byte) []versionEntry {
	t.Helper()
	dec := xml.NewDecoder(bytesReader(body))
	var out []versionEntry
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if start.Name.Local != "Version" && start.Name.Local != "DeleteMarker" {
			continue
		}
		var v versionXML
		if err := dec.DecodeElement(&v, &start); err != nil {
			c.failS3(nil, "parse version element: %v", err)
		}
		out = append(out, versionEntry{Kind: start.Name.Local, Key: v.Key, VersionID: v.VersionID, IsLatest: v.IsLatest})
	}
	return out
}

// TestListObjectVersionsOrderingRules: keys ascending, versions newest-first,
// delete markers interleaved in sequence order, exactly one IsLatest per key.
func TestListObjectVersionsOrderingRules(t *testing.T) {
	c := live
	bucket := c.newBucket(t, nil)
	c.mustStatus(c.putBucketVersioning(bucket, "Enabled"), http.StatusOK, "Enable versioning")

	c.putKeys(t, bucket, "a") // va1
	c.putKeys(t, bucket, "a") // va2
	c.mustStatus(c.deleteObject(bucket, "a", "", false), http.StatusNoContent, "delete a (marker)")
	c.putKeys(t, bucket, "a") // va3, latest
	c.putKeys(t, bucket, "b") // vb1
	c.mustStatus(c.deleteObject(bucket, "b", "", false), http.StatusNoContent, "delete b (marker)")

	_, resp := c.listVersions(bucket, nil)
	seq := parseVersionSequence(t, c, resp.Body)

	// S3 documents Version and DeleteMarker elements interleaved in one
	// key/version order: keys ascending, and within a key newest first, with delete
	// markers in their sequence position (not grouped at the end).
	want := []versionEntry{
		{Kind: "Version", Key: "a", IsLatest: true},
		{Kind: "DeleteMarker", Key: "a", IsLatest: false},
		{Kind: "Version", Key: "a", IsLatest: false},
		{Kind: "Version", Key: "a", IsLatest: false},
		{Kind: "DeleteMarker", Key: "b", IsLatest: true},
		{Kind: "Version", Key: "b", IsLatest: false},
	}
	if len(seq) != len(want) {
		c.failS3(resp, "version sequence length = %d (%v), want %d", len(seq), seq, len(want))
	}
	for i := range want {
		got, exp := seq[i], want[i]
		if got.Kind != exp.Kind || got.Key != exp.Key || got.IsLatest != exp.IsLatest {
			c.failS3(resp, "entry %d = {kind %s key %s latest %v}, want {kind %s key %s latest %v} (full sequence %v)",
				i, got.Kind, got.Key, got.IsLatest, exp.Kind, exp.Key, exp.IsLatest, seq)
		}
		if got.VersionID == "" {
			c.failS3(resp, "entry %d (%s %s) has an empty version id", i, got.Kind, got.Key)
		}
	}
	versions := filterKind(seq, "Version")
	markers := filterKind(seq, "DeleteMarker")
	if len(versions) != 4 || len(markers) != 2 {
		c.failS3(resp, "version/marker counts = %d/%d, want 4/2: %v", len(versions), len(markers), seq)
	}

	// Exactly one IsLatest per key.
	latest := map[string]int{}
	for _, e := range seq {
		if e.IsLatest {
			latest[e.Key]++
		}
	}
	for key, n := range latest {
		if n != 1 {
			c.failS3(resp, "key %q has %d latest versions", key, n)
		}
	}
	for _, key := range []string{"a", "b"} {
		if latest[key] != 1 {
			c.failS3(resp, "key %q has no latest version", key)
		}
	}
}

// TestDeleteMarkerReplacementAndVersionDeletionRules.
func TestDeleteMarkerReplacementAndVersionDeletionRules(t *testing.T) {
	c := live
	bucket := c.newBucket(t, nil)
	c.mustStatus(c.putBucketVersioning(bucket, "Enabled"), http.StatusOK, "Enable versioning")

	put := c.putObject(bucket, "k", []byte("one"), nil)
	c.mustStatus(put, http.StatusOK, "PutObject")
	v1 := put.Header.Get("x-amz-version-id")
	if v1 == "" {
		c.failS3(put, "versioned put returned no x-amz-version-id")
	}

	del1 := c.deleteObject(bucket, "k", "", false)
	c.mustStatus(del1, http.StatusNoContent, "first delete creates marker")
	if del1.Header.Get("x-amz-delete-marker") != "true" || del1.Header.Get("x-amz-version-id") == "" {
		c.failS3(del1, "delete-marker headers missing: marker=%q version=%q",
			del1.Header.Get("x-amz-delete-marker"), del1.Header.Get("x-amz-version-id"))
	}

	// Repeating DELETE removes the existing marker instead of stacking another.
	del2 := c.deleteObject(bucket, "k", "", false)
	c.mustStatus(del2, http.StatusNoContent, "second delete removes marker")
	if del2.Header.Get("x-amz-delete-marker") != "true" {
		c.failS3(del2, "second delete must report delete-marker=true")
	}
	v, _ := c.listVersions(bucket, nil)
	if len(v.DeleteMarkers) != 0 {
		c.failS3(nil, "delete markers stacked: %v", v.DeleteMarkers)
	}
	// The object is visible again.
	get := c.getObject(bucket, "k", "")
	c.mustStatus(get, http.StatusOK, "GET after marker removal")
	if string(get.Body) != "one" {
		c.failS3(get, "body = %q, want %q", get.Body, "one")
	}

	// Deleting a specific version permanently removes only that version.
	put2 := c.putObject(bucket, "k", []byte("two"), nil)
	c.mustStatus(put2, http.StatusOK, "PutObject v2")
	v2 := put2.Header.Get("x-amz-version-id")
	c.mustStatus(c.deleteObject(bucket, "k", v2, false), http.StatusNoContent, "delete specific version")
	v, _ = c.listVersions(bucket, nil)
	if len(v.Versions) != 1 || v.Versions[0].VersionID != v1 || !v.Versions[0].IsLatest {
		c.failS3(nil, "after version delete, versions = %+v, want only %s", v.Versions, v1)
	}
	c.mustStatus(c.getObject(bucket, "k", v2), http.StatusNotFound, "GET deleted version")

	// Explicitly deleting a delete marker restores the previous version.
	c.mustStatus(c.deleteObject(bucket, "k", "", false), http.StatusNoContent, "create marker again")
	v, _ = c.listVersions(bucket, nil)
	if len(v.DeleteMarkers) != 1 {
		c.failS3(nil, "expected one delete marker, got %+v", v.DeleteMarkers)
	}
	marker := v.DeleteMarkers[0].VersionID
	c.mustStatus(c.deleteObject(bucket, "k", marker, false), http.StatusNoContent, "delete marker explicitly")
	get = c.getObject(bucket, "k", "")
	c.mustStatus(get, http.StatusOK, "GET after deleting marker")
	if string(get.Body) != "one" {
		c.failS3(get, "body after marker delete = %q", get.Body)
	}
}

// TestSuspendedVersioningNullVersionSemantics: S3 gives the new version the
// literal version id "null" and retains all existing versions.
func TestSuspendedVersioningNullVersionSemantics(t *testing.T) {
	c := live
	bucket := c.newBucket(t, nil)
	c.mustStatus(c.putBucketVersioning(bucket, "Enabled"), http.StatusOK, "Enable versioning")
	put1 := c.putObject(bucket, "s", []byte("v1"), nil)
	c.mustStatus(put1, http.StatusOK, "PutObject v1")
	v1 := put1.Header.Get("x-amz-version-id")
	put2 := c.putObject(bucket, "s", []byte("v2"), nil)
	c.mustStatus(put2, http.StatusOK, "PutObject v2")
	v2 := put2.Header.Get("x-amz-version-id")
	if v1 == "" || v2 == "" || v1 == v2 {
		c.failS3(put2, "expected two distinct version ids, got %q and %q", v1, v2)
	}

	c.mustStatus(c.putBucketVersioning(bucket, "Suspended"), http.StatusOK, "Suspend versioning")
	status, vresp := c.getBucketVersioning(bucket)
	if status != "Suspended" {
		c.failS3(vresp, "versioning status = %q, want Suspended", status)
	}

	suspendedPut := c.putObject(bucket, "s", []byte("v3-null"), nil)
	c.mustStatus(suspendedPut, http.StatusOK, "PutObject while suspended")
	if got := suspendedPut.Header.Get("x-amz-version-id"); got != "null" {
		c.failS3(suspendedPut, "suspended PUT version id = %q, want %q (S3 null version)", got, "null")
	}

	// A second suspended PUT replaces the null version, not the older versions.
	suspendedPut2 := c.putObject(bucket, "s", []byte("v4-null"), nil)
	c.mustStatus(suspendedPut2, http.StatusOK, "second PutObject while suspended")
	if got := suspendedPut2.Header.Get("x-amz-version-id"); got != "null" {
		c.failS3(suspendedPut2, "second suspended PUT version id = %q", got)
	}

	v, vlist := c.listVersions(bucket, nil)
	if len(v.Versions) != 3 {
		c.failS3(vlist, "suspended bucket has %d versions, want 3 (v1, v2, null): %+v", len(v.Versions), v.Versions)
	}
	got := map[string]bool{}
	for _, ver := range v.Versions {
		got[ver.VersionID] = true
	}
	if !got[v1] || !got[v2] || !got["null"] {
		c.failS3(vlist, "retained versions = %v, want %s, %s and null", got, v1, v2)
	}
	get := c.getObject(bucket, "s", "")
	c.mustStatus(get, http.StatusOK, "GET latest after suspended puts")
	if string(get.Body) != "v4-null" {
		c.failS3(get, "latest body = %q, want v4-null", get.Body)
	}
	// Old versions are still individually readable.
	for vid, want := range map[string]string{v1: "v1", v2: "v2"} {
		resp := c.getObject(bucket, "s", vid)
		c.mustStatus(resp, http.StatusOK, "GET retained version "+vid)
		if string(resp.Body) != want {
			c.failS3(resp, "version %s body = %q, want %q", vid, resp.Body, want)
		}
	}
}

// TestVersionListingMarkerPaginationOverS3: page through versions of one key
// using key-marker/version-id-marker; no duplicates, no gaps.
func TestVersionListingMarkerPaginationOverS3(t *testing.T) {
	c := live
	bucket := c.newBucket(t, nil)
	c.mustStatus(c.putBucketVersioning(bucket, "Enabled"), http.StatusOK, "Enable versioning")
	ids := []string{}
	for i := 0; i < 3; i++ {
		p := c.putObject(bucket, "paged", []byte{byte('a' + i)}, nil)
		c.mustStatus(p, http.StatusOK, "PutObject page fixture")
		ids = append(ids, p.Header.Get("x-amz-version-id"))
	}
	c.putKeys(t, bucket, "zeta")

	var seen []string
	keyMarker, versionMarker := "", ""
	for page := 0; page < 10; page++ {
		params := map[string]string{"max-keys": "1"}
		if keyMarker != "" {
			params["key-marker"] = keyMarker
		}
		if versionMarker != "" {
			params["version-id-marker"] = versionMarker
		}
		v, resp := c.listVersions(bucket, params)
		entries := append([]versionXML{}, v.Versions...)
		entries = append(entries, v.DeleteMarkers...)
		if len(entries) != 1 {
			c.failS3(resp, "page %d returned %d entries", page, len(entries))
		}
		seen = append(seen, entries[0].VersionID)
		if !v.IsTruncated {
			break
		}
		keyMarker, versionMarker = v.NextKeyMarker, v.NextVersionIDMarker
		if keyMarker == "" || versionMarker == "" {
			c.failS3(resp, "truncated page %d missing next markers: %+v", page, v)
		}
	}
	if len(seen) != 4 {
		t.Fatalf("walked %d versions, want 4: %v", len(seen), seen)
	}
	for i, want := range []string{ids[2], ids[1], ids[0]} {
		if seen[i] != want {
			t.Fatalf("paged versions = %v, want newest-first %v", seen, []string{ids[2], ids[1], ids[0]})
		}
	}
	// Last page is the second key's single version.
	if len(seen) == 4 && seen[3] == "" {
		t.Fatalf("zeta version id empty")
	}
	sortedSeen := append([]string{}, seen...)
	sort.Strings(sortedSeen)
	if len(sortedSeen) != 4 {
		t.Fatalf("duplicate version ids while paging: %v", seen)
	}
}
