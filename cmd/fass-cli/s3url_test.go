package main

import "testing"

func TestParseS3URL(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantBucket string
		wantKey    string
		wantErr    bool
	}{
		{"bucket only", "s3://dev-bucket", "dev-bucket", "", false},
		{"bucket slash", "s3://dev-bucket/", "dev-bucket", "", false},
		{"object", "s3://dev-bucket/e2e/object.bin", "dev-bucket", "e2e/object.bin", false},
		{"prefix", "s3://dev-bucket/e2e/", "dev-bucket", "e2e/", false},
		{"spaces in key", "s3://b/a b/c.txt", "b", "a b/c.txt", false},
		{"unicode key", "s3://b/üñï/çø", "b", "üñï/çø", false},
		{"double slash key", "s3://b//abs", "b", "/abs", false},
		{"empty", "s3://", "", "", true},
		{"missing bucket", "s3:///key", "", "", true},
		{"not s3", "/tmp/file", "", "", true},
		{"bucket whitespace", "s3://a b/key", "", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseS3URL(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseS3URL(%q) = %+v, want error", tc.raw, got)
				}
				if code := classifyError(err); code != 1 {
					t.Fatalf("parse error should be a user error (exit 1), got %d", code)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseS3URL(%q): %v", tc.raw, err)
			}
			if got.Bucket != tc.wantBucket || got.Key != tc.wantKey {
				t.Fatalf("parseS3URL(%q) = {%q,%q}, want {%q,%q}", tc.raw, got.Bucket, got.Key, tc.wantBucket, tc.wantKey)
			}
		})
	}
}

func TestS3URLString(t *testing.T) {
	if got := (s3URL{"b", ""}).String(); got != "s3://b" {
		t.Errorf("String() = %q", got)
	}
	if got := (s3URL{"b", "k/x"}).String(); got != "s3://b/k/x" {
		t.Errorf("String() = %q", got)
	}
}

func TestObjectKeyForDest(t *testing.T) {
	tests := []struct {
		dst  s3URL
		file string
		want string
	}{
		{s3URL{"b", ""}, "/tmp/a.txt", "a.txt"},
		{s3URL{"b", "dir/"}, "/tmp/a.txt", "dir/a.txt"},
		{s3URL{"b", "dir"}, "/tmp/a.txt", "dir"},
	}
	for _, tc := range tests {
		if got := objectKeyForDest(tc.dst, tc.file); got != tc.want {
			t.Errorf("objectKeyForDest(%v,%q) = %q, want %q", tc.dst, tc.file, got, tc.want)
		}
	}
}

func TestSafeJoin(t *testing.T) {
	if got, err := safeJoin("/tmp/out", "a/b.txt"); err != nil || got != "/tmp/out/a/b.txt" {
		t.Fatalf("safeJoin = %q, %v", got, err)
	}
	for _, rel := range []string{"../evil", "a/../../evil", "/etc/passwd", ""} {
		if _, err := safeJoin("/tmp/out", rel); err == nil {
			t.Errorf("safeJoin(%q) should be refused", rel)
		}
	}
}

func TestPrefixJoin(t *testing.T) {
	cases := []struct{ prefix, rel, want string }{
		{"", "a", "a"},
		{"p", "a", "p/a"},
		{"p/", "a", "p/a"},
	}
	for _, c := range cases {
		if got := prefixJoin(c.prefix, c.rel); got != c.want {
			t.Errorf("prefixJoin(%q,%q) = %q, want %q", c.prefix, c.rel, got, c.want)
		}
	}
}
