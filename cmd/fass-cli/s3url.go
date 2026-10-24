package main

import (
	"path/filepath"
	"strings"
)

// s3URL is a parsed s3://bucket/key reference.
//
// FASS keys may contain spaces, UTF-8 and slashes. We deliberately do not
// URL-decode: an operator typing s3://b/a%20b means the literal key "a%20b" as
// far as this CLI is concerned, which matches how the SDK escapes paths. The
// bucket name is validated by the gateway (and by S3 rules), not here.
type s3URL struct {
	Bucket string
	Key    string
}

func (u s3URL) String() string {
	if u.Key == "" {
		return "s3://" + u.Bucket
	}
	return "s3://" + u.Bucket + "/" + u.Key
}

// isS3Path reports whether p addresses S3 rather than the local filesystem.
func isS3Path(p string) bool { return strings.HasPrefix(strings.ToLower(p), "s3://") }

// parseS3URL parses s3://bucket[/key]. The key is everything after the first
// slash following the bucket, verbatim (so a trailing slash is preserved and
// means "prefix/directory").
func parseS3URL(raw string) (s3URL, error) {
	if !isS3Path(raw) {
		return s3URL{}, usagef("%q is not an s3:// URL", raw)
	}
	rest := raw[len("s3://"):]
	if rest == "" {
		return s3URL{}, usagef("s3:// URL is missing a bucket name")
	}
	bucket, key, found := strings.Cut(rest, "/")
	if bucket == "" {
		return s3URL{}, usagef("s3:// URL is missing a bucket name")
	}
	if strings.ContainsAny(bucket, " \t\n") {
		return s3URL{}, usagef("bucket %q contains whitespace", bucket)
	}
	if !found {
		return s3URL{bucket, ""}, nil
	}
	return s3URL{bucket, key}, nil
}

// objectKeyForDest resolves the destination key for a local file copy:
//   - s3://b                 -> key = basename(file)
//   - s3://b/dir/            -> key = dir/basename(file)
//   - s3://b/explicit-name   -> key = explicit-name (exact destination)
func objectKeyForDest(dst s3URL, localPath string) string {
	base := filepath.Base(localPath)
	if dst.Key == "" {
		return base
	}
	if strings.HasSuffix(dst.Key, "/") {
		return dst.Key + base
	}
	return dst.Key
}

// localPathForDest resolves where an S3 object lands locally. A destination that
// exists as a directory, or ends in a path separator, receives the object's
// basename; otherwise the destination is used verbatim.
func localPathForDest(dst, key string) string {
	base := pathBase(key)
	if dst == "" || strings.HasSuffix(dst, "/") || dst == "." {
		return filepath.Join(dst, base)
	}
	if fi, err := statPath(dst); err == nil && fi.IsDir() {
		return filepath.Join(dst, base)
	}
	return dst
}

// pathBase is filepath.Base for slash-separated S3 keys (filepath on Windows
// would treat "\\" specially; FASS keys are always "/"-separated).
func pathBase(key string) string {
	key = strings.TrimRight(key, "/")
	if i := strings.LastIndexByte(key, '/'); i >= 0 {
		return key[i+1:]
	}
	return key
}

// relativeKey computes the destination key suffix for a recursive directory
// upload. filepath.Rel returns OS separators; S3 keys always use "/".
func relativeKey(root, file string) (string, error) {
	rel, err := filepath.Rel(root, file)
	if err != nil {
		return "", err
	}
	return filepath.ToSlash(rel), nil
}

// prefixJoin joins an S3 prefix and a relative key without doubling slashes.
func prefixJoin(prefix, rel string) string {
	switch {
	case prefix == "":
		return rel
	case strings.HasSuffix(prefix, "/"):
		return prefix + rel
	default:
		return prefix + "/" + rel
	}
}
