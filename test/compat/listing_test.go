//go:build compat

package compat

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
)

// newBucket creates a bucket for a test and registers no cleanup (a fresh
// cluster is used per run).
func (c *cluster) newBucket(t *testing.T, headers map[string]string) string {
	t.Helper()
	c.t = t
	name := uniqueBucketName(t)
	c.createBucket(name, headers)
	return name
}

func (c *cluster) putKeys(t *testing.T, bucket string, keys ...string) {
	t.Helper()
	for _, k := range keys {
		resp := c.putObject(bucket, k, []byte("v:"+k), nil)
		c.mustStatus(resp, http.StatusOK, "PutObject("+k+")")
	}
}

func contentsKeys(l *listV2XML) []string {
	out := make([]string, 0, len(l.Contents))
	for _, o := range l.Contents {
		out = append(out, o.Key)
	}
	return out
}

func commonPrefixes(l *listV2XML) []string {
	out := make([]string, 0, len(l.CommonPrefixes))
	for _, p := range l.CommonPrefixes {
		out = append(out, p.Prefix)
	}
	return out
}

func assertKeys(t *testing.T, got, want []string, rule string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got %d entries %v, want %v", rule, len(got), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s: got %v, want %v", rule, got, want)
		}
	}
}

// TestListObjectsV2PrefixDelimiterRules is the S3 rule set for prefix/delimiter
// grouping: CommonPrefixes are sorted, de-duplicated, count toward MaxKeys, and
// the delimiter is treated as a literal substring delimiter at any position.
func TestListObjectsV2PrefixDelimiterRules(t *testing.T) {
	c := live
	bucket := c.newBucket(t, nil)
	c.putKeys(t, bucket,
		"a", "a/b", "a/b/c", "a/c", "ab", "b",
		"dir/", "dir/sub/z", "dir/x", "dir/y",
	)

	t.Run("delimiter-in-middle-groups-and-dedupes", func(t *testing.T) {
		l, _ := c.listV2(bucket, map[string]string{"prefix": "a/", "delimiter": "/"})
		assertKeys(t, contentsKeys(l), []string{"a/b", "a/c"}, "prefix a/ delimiter / contents")
		assertKeys(t, commonPrefixes(l), []string{"a/b/"}, "prefix a/ delimiter / common prefixes")
		if l.KeyCount != 3 {
			t.Fatalf("KeyCount = %d, want 3 (2 objects + 1 common prefix)", l.KeyCount)
		}
	})

	t.Run("delimiter-at-start-of-key", func(t *testing.T) {
		l, _ := c.listV2(bucket, map[string]string{"delimiter": "/"})
		assertKeys(t, contentsKeys(l), []string{"a", "ab", "b"}, "root delimiter contents")
		assertKeys(t, commonPrefixes(l), []string{"a/", "dir/"}, "root delimiter common prefixes")
	})

	t.Run("delimiter-at-end-of-key", func(t *testing.T) {
		l, _ := c.listV2(bucket, map[string]string{"prefix": "dir/", "delimiter": "/"})
		// "dir/" is itself an object whose remainder is empty, so it is a content
		// entry; "dir/sub/z" groups under "dir/sub/".
		assertKeys(t, contentsKeys(l), []string{"dir/", "dir/x", "dir/y"}, "prefix dir/ delimiter / contents")
		assertKeys(t, commonPrefixes(l), []string{"dir/sub/"}, "prefix dir/ delimiter / common prefixes")
	})

	t.Run("prefix-equals-a-key-exactly", func(t *testing.T) {
		l, _ := c.listV2(bucket, map[string]string{"prefix": "a/b"})
		assertKeys(t, contentsKeys(l), []string{"a/b", "a/b/c"}, "prefix a/b contents")
		if len(l.CommonPrefixes) != 0 {
			t.Fatalf("unexpected common prefixes: %v", commonPrefixes(l))
		}
	})

	t.Run("prefix-longer-than-anykey", func(t *testing.T) {
		l, _ := c.listV2(bucket, map[string]string{"prefix": "zzz/none"})
		if len(l.Contents) != 0 || len(l.CommonPrefixes) != 0 || l.IsTruncated || l.KeyCount != 0 {
			t.Fatalf("empty prefix listing = %+v", l)
		}
	})

	t.Run("delimiter-grouping-counts-against-maxkeys", func(t *testing.T) {
		// 3 contents + 2 prefixes, page size 2: all entries count.
		l, _ := c.listV2(bucket, map[string]string{"delimiter": "/", "max-keys": "2"})
		total := len(l.Contents) + len(l.CommonPrefixes)
		if total != 2 || !l.IsTruncated {
			t.Fatalf("max-keys=2: got %d entries (contents=%v prefixes=%v) truncated=%v",
				total, contentsKeys(l), commonPrefixes(l), l.IsTruncated)
		}
	})
}

// TestListObjectsV2MaxKeysRules pins the page-size boundaries.
func TestListObjectsV2MaxKeysRules(t *testing.T) {
	c := live
	bucket := c.newBucket(t, nil)
	c.putKeys(t, bucket, "k1", "k2", "k3")

	t.Run("max-keys-zero-returns-empty-not-truncated", func(t *testing.T) {
		l, _ := c.listV2(bucket, map[string]string{"max-keys": "0"})
		if len(l.Contents) != 0 || l.KeyCount != 0 || l.IsTruncated {
			t.Fatalf("max-keys=0 = %+v (S3: empty page, IsTruncated=false)", l)
		}
	})

	t.Run("max-keys-one-sets-token", func(t *testing.T) {
		l, _ := c.listV2(bucket, map[string]string{"max-keys": "1"})
		if len(l.Contents) != 1 || l.Contents[0].Key != "k1" || !l.IsTruncated || l.NextContinuationToken == "" {
			t.Fatalf("max-keys=1 = %+v", l)
		}
		next, _ := c.listV2(bucket, map[string]string{"max-keys": "1", "continuation-token": l.NextContinuationToken})
		if len(next.Contents) != 1 || next.Contents[0].Key != "k2" {
			t.Fatalf("second page = %+v", next)
		}
	})

	t.Run("max-keys-exactly-page-size-not-truncated", func(t *testing.T) {
		l, _ := c.listV2(bucket, map[string]string{"max-keys": "3"})
		if len(l.Contents) != 3 || l.IsTruncated || l.NextContinuationToken != "" {
			t.Fatalf("max-keys=3 = %+v", l)
		}
	})

	t.Run("malformed-continuation-token-is-invalid-argument", func(t *testing.T) {
		resp, err := c.call("GET", bucket, "", url.Values{
			"list-type":          {"2"},
			"continuation-token": {"not-a-valid-token"},
		}, nil, nil)
		if err != nil {
			c.failS3(nil, "malformed token request: %v", err)
		}
		c.mustErr(resp, http.StatusBadRequest, "InvalidArgument", "malformed continuation token must be InvalidArgument, never 500")
	})

	t.Run("startafter-and-continuation-token-interplay", func(t *testing.T) {
		// StartAfter is only honoured on the first page; a continuation token takes
		// over from the second.
		first, _ := c.listV2(bucket, map[string]string{"start-after": "k1"})
		assertKeys(t, contentsKeys(first), []string{"k2", "k3"}, "StartAfter k1")
		if first.StartAfter != "k1" {
			t.Fatalf("StartAfter echo = %q", first.StartAfter)
		}
		paged, _ := c.listV2(bucket, map[string]string{"max-keys": "1", "start-after": "k1"})
		if len(paged.Contents) != 1 || paged.Contents[0].Key != "k2" || paged.NextContinuationToken == "" {
			t.Fatalf("paged StartAfter = %+v", paged)
		}
		second, _ := c.listV2(bucket, map[string]string{"max-keys": "1", "continuation-token": paged.NextContinuationToken})
		if len(second.Contents) != 1 || second.Contents[0].Key != "k3" {
			t.Fatalf("continuation after StartAfter = %+v", second)
		}
		// Reusing the token replays the same page deterministically.
		again, _ := c.listV2(bucket, map[string]string{"max-keys": "1", "continuation-token": paged.NextContinuationToken})
		if len(again.Contents) != 1 || again.Contents[0].Key != "k3" {
			t.Fatalf("token reuse = %+v", again)
		}
	})
}

// TestListObjectsEncodingTypeURL: encoding-type=url must percent-encode keys and
// echo EncodingType, and decoding must recover the original key exactly.
func TestListObjectsEncodingTypeURL(t *testing.T) {
	c := live
	bucket := c.newBucket(t, nil)
	keys := []string{
		"space key.txt",
		"utf8/ключ-文件-🍰",
		"plus+sign",
		"percent%25literal",
		"amp&equals=question?",
	}
	c.putKeys(t, bucket, keys...)

	l, resp := c.listV2(bucket, map[string]string{"encoding-type": "url"})
	if l.EncodingType != "url" {
		c.failS3(resp, "EncodingType = %q, want url", l.EncodingType)
	}
	got := contentsKeys(l)
	if len(got) != len(keys) {
		c.failS3(resp, "encoded listing returned %d keys, want %d: %v", len(got), len(keys), got)
	}
	decodedKeys := make([]string, 0, len(got))
	for _, encoded := range got {
		decoded, err := url.QueryUnescape(encoded)
		if err != nil {
			c.failS3(resp, "key %q is not url-decodable: %v", encoded, err)
		}
		decodedKeys = append(decodedKeys, decoded)
	}
	want := append([]string(nil), keys...)
	sort.Strings(want)
	sort.Strings(decodedKeys)
	assertKeys(t, decodedKeys, want, "encoding-type=url round trip")
}

// TestListEmptyAndAllDeletedBuckets: empty bucket, only-delete-marker bucket, and
// every-version-deleted bucket all list as empty (with no stray prefixes).
func TestListEmptyAndAllDeletedBuckets(t *testing.T) {
	c := live
	bucket := c.newBucket(t, nil)
	l, _ := c.listV2(bucket, nil)
	if len(l.Contents) != 0 || l.KeyCount != 0 || l.IsTruncated {
		t.Fatalf("empty bucket listing = %+v", l)
	}

	// Only a delete marker.
	resp := c.putBucketVersioning(bucket, "Enabled")
	c.mustStatus(resp, http.StatusOK, "PutBucketVersioning Enabled")
	c.putKeys(t, bucket, "gone")
	c.mustStatus(c.deleteObject(bucket, "gone", "", false), http.StatusNoContent, "DELETE creates delete marker")
	l, _ = c.listV2(bucket, nil)
	if len(l.Contents) != 0 || l.KeyCount != 0 {
		t.Fatalf("bucket with only a delete marker = %+v", l)
	}
	v, _ := c.listVersions(bucket, nil)
	if len(v.Versions) != 1 || len(v.DeleteMarkers) != 1 {
		t.Fatalf("version listing = versions %v markers %v (the original version must be retained)", v.Versions, v.DeleteMarkers)
	}

	// Delete the delete marker and the retained version: the bucket is empty.
	for _, m := range v.DeleteMarkers {
		c.mustStatus(c.deleteObject(bucket, m.Key, m.VersionID, false), http.StatusNoContent, "DELETE delete marker")
	}
	for _, ver := range v.Versions {
		c.mustStatus(c.deleteObject(bucket, ver.Key, ver.VersionID, false), http.StatusNoContent, "DELETE retained version")
	}
	l, _ = c.listV2(bucket, nil)
	if len(l.Contents) != 0 || l.KeyCount != 0 {
		t.Fatalf("all-deleted bucket = %+v", l)
	}
	v, _ = c.listVersions(bucket, nil)
	if len(v.Versions)+len(v.DeleteMarkers) != 0 {
		t.Fatalf("all-deleted version listing = %+v", v)
	}
}

// TestListObjectsV1DelimiterAndMarker: the V1 surface (used by older rclone and
// s3cmd paths) must group and page identically, with NextMarker on truncation.
func TestListObjectsV1DelimiterAndMarker(t *testing.T) {
	c := live
	bucket := c.newBucket(t, nil)
	c.putKeys(t, bucket, "a/1", "a/2", "b/1", "c")

	l, _ := c.listV1(bucket, map[string]string{"delimiter": "/"})
	assertKeys(t, func() []string { // V1 contents
		out := []string{}
		for _, o := range l.Contents {
			out = append(out, o.Key)
		}
		return out
	}(), []string{"c"}, "V1 delimiter contents")
	prefixes := []string{}
	for _, p := range l.CommonPrefixes {
		prefixes = append(prefixes, p.Prefix)
	}
	sort.Strings(prefixes)
	if strings.Join(prefixes, ",") != "a/,b/" {
		t.Fatalf("V1 common prefixes = %v", prefixes)
	}

	page, _ := c.listV1(bucket, map[string]string{"max-keys": "1"})
	if !page.IsTruncated {
		t.Fatalf("V1 max-keys=1 not truncated")
	}
	// NextMarker is defined for delimiter listings; it must be non-empty when
	// truncated so clients can continue.
	if page.NextMarker == "" {
		t.Fatalf("V1 truncated page has no NextMarker")
	}
	if page.MaxKeys != 1 {
		t.Fatalf("MaxKeys echo = %d", page.MaxKeys)
	}
}
