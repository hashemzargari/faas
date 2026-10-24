package main

import (
	"context"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fass-storage/fass/pkg/sdk"
)

// maxListPage is the S3 listing page size. Listings always page to completion
// (S3 caps a page at 1000 keys); recursive operations must never silently stop
// at a page boundary, because a partial migration is worse than a failure.
const maxListPage = 1000

// forEachObject streams every object under prefix, page by page. It is the only
// listing primitive used by recursive cp/rm/ls so no call site can accidentally
// operate on just the first page.
func forEachObject(ctx context.Context, client *sdk.Client, bucket, prefix string, fn func(sdk.Object) error) error {
	token := ""
	for {
		objs, next, truncated, err := client.ListObjectsV2Page(ctx, bucket, prefix, token, maxListPage)
		if err != nil {
			return sdkError("list s3://"+bucket+"/"+prefix, err)
		}
		for _, o := range objs {
			if err := fn(o); err != nil {
				return err
			}
		}
		if !truncated || next == "" {
			return nil
		}
		if next == token {
			// Defensive: a gateway returning the same token would loop forever.
			return servicef(nil, "list s3://%s/%s: continuation token did not advance", bucket, prefix)
		}
		token = next
	}
}

// statPath is os.Stat behind a function variable so tests can simulate paths.
var statPath = os.Stat

// ---------------------------------------------------------------------------
// ls
// ---------------------------------------------------------------------------

type bucketJSON struct {
	Name    string    `json:"name"`
	Created time.Time `json:"created"`
}

type objectJSON struct {
	Key          string    `json:"key"`
	Size         int64     `json:"size"`
	ETag         string    `json:"etag"`
	LastModified time.Time `json:"last_modified"`
}

func runLS(ctx context.Context, g *globalOpts, args []string, stdout io.Writer) error {
	if len(args) > 1 {
		return usagef("ls takes at most one s3://bucket[/prefix] argument")
	}
	client, err := g.s3Client()
	if err != nil {
		return err
	}

	if len(args) == 0 {
		buckets, err := client.ListBuckets(ctx)
		if err != nil {
			return sdkError("list buckets", err)
		}
		if g.jsonOut {
			out := make([]bucketJSON, 0, len(buckets))
			for _, b := range buckets {
				out = append(out, bucketJSON{Name: b.Name, Created: b.CreationDate})
			}
			return writeJSON(stdout, out)
		}
		t := newTable("BUCKET", "CREATED")
		for _, b := range buckets {
			t.add(b.Name, humanTime(b.CreationDate))
		}
		t.render(stdout)
		return nil
	}

	ref, err := parseS3URL(args[0])
	if err != nil {
		return err
	}
	var objs []sdk.Object
	if err := forEachObject(ctx, client, ref.Bucket, ref.Key, func(o sdk.Object) error {
		objs = append(objs, o)
		return nil
	}); err != nil {
		return err
	}
	if g.jsonOut {
		out := make([]objectJSON, 0, len(objs))
		for _, o := range objs {
			out = append(out, objectJSON{Key: o.Key, Size: o.Size, ETag: o.ETag, LastModified: o.LastModified})
		}
		return writeJSON(stdout, out)
	}
	t := newTable("KEY", "SIZE", "ETAG", "MODIFIED")
	for _, o := range objs {
		t.add(o.Key, humanBytes(o.Size), o.ETag, humanTime(o.LastModified))
	}
	t.render(stdout)
	return nil
}

// ---------------------------------------------------------------------------
// cp
// ---------------------------------------------------------------------------

type transferJSON struct {
	Source string `json:"source"`
	Dest   string `json:"dest"`
	Size   int64  `json:"size"`
	ETag   string `json:"etag,omitempty"`
}

type transfer struct {
	source string
	dest   string
	size   int64
	etag   string
}

func runCP(ctx context.Context, g *globalOpts, args []string, recursive bool, contentType string, stdout, stderr io.Writer) error {
	if len(args) != 2 {
		return usagef("cp requires exactly two arguments: <source> <destination>")
	}
	src, dst := args[0], args[1]
	srcS3, dstS3 := isS3Path(src), isS3Path(dst)
	if srcS3 == dstS3 {
		if srcS3 {
			return usagef("cp between two s3:// URLs is supported (s3://a/k s3://b/k), but both sides cannot be local")
		}
		return usagef("cp needs at least one s3:// side; use `cp` from the shell for local→local copies")
	}
	client, err := g.s3Client()
	if err != nil {
		return err
	}

	var transfers []transfer
	switch {
	case !srcS3 && dstS3:
		ref, err := parseS3URL(dst)
		if err != nil {
			return err
		}
		transfers, err = uploadPath(ctx, g, client, src, ref, recursive, contentType, stdout, stderr)
		if err != nil {
			return err
		}
	case srcS3 && !dstS3:
		ref, err := parseS3URL(src)
		if err != nil {
			return err
		}
		transfers, err = downloadPath(ctx, g, client, ref, dst, recursive, stdout, stderr)
		if err != nil {
			return err
		}
	default: // s3 -> s3
		srcRef, err := parseS3URL(src)
		if err != nil {
			return err
		}
		dstRef, err := parseS3URL(dst)
		if err != nil {
			return err
		}
		transfers, err = serverSideCopy(ctx, g, client, srcRef, dstRef, recursive, stdout, stderr)
		if err != nil {
			return err
		}
	}

	if g.jsonOut {
		out := make([]transferJSON, 0, len(transfers))
		for _, t := range transfers {
			out = append(out, transferJSON{Source: t.source, Dest: t.dest, Size: t.size, ETag: t.etag})
		}
		return writeJSON(stdout, out)
	}
	if !g.quiet {
		var total int64
		for _, t := range transfers {
			total += t.size
		}
		fmt.Fprintf(stdout, "copied %d object(s), %s\n", len(transfers), humanBytes(total))
	}
	return nil
}

// uploadPath copies a local file or directory to S3.
func uploadPath(ctx context.Context, g *globalOpts, client *sdk.Client, src string, dst s3URL, recursive bool, contentType string, stdout, stderr io.Writer) ([]transfer, error) {
	fi, err := statPath(src)
	if err != nil {
		return nil, usagef("cannot stat %s: %v", src, err)
	}
	var out []transfer
	if fi.IsDir() {
		if !recursive {
			return nil, usagef("%s is a directory; pass --recursive (-r)", src)
		}
		prefix := dst.Key
		if prefix != "" && !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
		err := filepath.WalkDir(src, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				return nil
			}
			rel, err := relativeKey(src, path)
			if err != nil {
				return err
			}
			key := prefixJoin(prefix, rel)
			t, err := uploadFile(ctx, g, client, path, dst.Bucket, key, contentType)
			if err != nil {
				fmt.Fprintf(stderr, "fass: upload %s: %v\n", path, err)
				return err
			}
			out = append(out, t)
			printTransfer(stdout, g, "upload", t)
			return nil
		})
		if err != nil {
			return out, sdkError("copy directory "+src, err)
		}
		return out, nil
	}

	key := objectKeyForDest(dst, src)
	t, err := uploadFile(ctx, g, client, src, dst.Bucket, key, contentType)
	if err != nil {
		return nil, err
	}
	printTransfer(stdout, g, "upload", t)
	return []transfer{t}, nil
}

func uploadFile(ctx context.Context, g *globalOpts, client *sdk.Client, path, bucket, key, contentType string) (transfer, error) {
	f, err := os.Open(path)
	if err != nil {
		return transfer{}, usagef("open %s: %v", path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return transfer{}, usagef("stat %s: %v", path, err)
	}
	ctype := contentType
	if ctype == "" {
		ctype = mime.TypeByExtension(filepath.Ext(path))
	}
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	etag, err := client.PutObject(ctx, bucket, key, f, fi.Size(), ctype)
	if err != nil {
		return transfer{}, sdkError("upload "+path, err)
	}
	return transfer{source: path, dest: s3URL{bucket, key}.String(), size: fi.Size(), etag: etag}, nil
}

// downloadPath copies an S3 object or prefix to the local filesystem.
func downloadPath(ctx context.Context, g *globalOpts, client *sdk.Client, src s3URL, dst string, recursive bool, stdout, stderr io.Writer) ([]transfer, error) {
	if recursive {
		var out []transfer
		err := forEachObject(ctx, client, src.Bucket, src.Key, func(o sdk.Object) error {
			rel := strings.TrimPrefix(o.Key, src.Key)
			rel = strings.TrimPrefix(rel, "/")
			if rel == "" {
				rel = pathBase(o.Key)
			}
			target, err := safeJoin(dst, rel)
			if err != nil {
				return err
			}
			t, err := downloadFile(ctx, client, src.Bucket, o.Key, target, o.Size)
			if err != nil {
				fmt.Fprintf(stderr, "fass: download s3://%s/%s: %v\n", src.Bucket, o.Key, err)
				return err
			}
			out = append(out, t)
			printTransfer(stdout, g, "download", t)
			return nil
		})
		if err != nil {
			return out, err
		}
		return out, nil
	}

	// Single object: HEAD first so we know the expected size and can verify the
	// download before declaring success.
	size, etag, err := client.HeadObject(ctx, src.Bucket, src.Key)
	if err != nil {
		return nil, sdkError("head "+src.String(), err)
	}
	target := localPathForDest(dst, src.Key)
	t, err := downloadFile(ctx, client, src.Bucket, src.Key, target, size)
	if err != nil {
		return nil, err
	}
	t.etag = etag
	printTransfer(stdout, g, "download", t)
	return []transfer{t}, nil
}

func downloadFile(ctx context.Context, client *sdk.Client, bucket, key, target string, expected int64) (transfer, error) {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return transfer{}, servicef(err, "create directory for %s", target)
	}
	body, err := client.GetObject(ctx, bucket, key)
	if err != nil {
		return transfer{}, sdkError("download s3://"+bucket+"/"+key, err)
	}
	defer body.Close()

	f, err := os.Create(target)
	if err != nil {
		return transfer{}, servicef(err, "create %s", target)
	}
	n, copyErr := io.Copy(f, body)
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(target)
		return transfer{}, servicef(copyErr, "write %s", target)
	}
	if closeErr != nil {
		_ = os.Remove(target)
		return transfer{}, servicef(closeErr, "close %s", target)
	}
	if expected >= 0 && n != expected {
		_ = os.Remove(target)
		return transfer{}, servicef(nil, "downloaded %d bytes but S3 reported %d for s3://%s/%s", n, expected, bucket, key)
	}
	return transfer{source: s3URL{bucket, key}.String(), dest: target, size: n}, nil
}

// serverSideCopy copies S3 objects by streaming them through the client (there
// is no gateway copy endpoint in pkg/sdk yet; CopyObject exists in the S3 API
// but the SDK does not wrap it, so a GET+PUT is the honest implementation).
func serverSideCopy(ctx context.Context, g *globalOpts, client *sdk.Client, src, dst s3URL, recursive bool, stdout, stderr io.Writer) ([]transfer, error) {
	if !recursive {
		if src.Key == "" || dst.Key == "" {
			return nil, usagef("s3→s3 copy needs an object key on both sides (or use --recursive)")
		}
		size, _, err := client.HeadObject(ctx, src.Bucket, src.Key)
		if err != nil {
			return nil, sdkError("head "+src.String(), err)
		}
		body, err := client.GetObject(ctx, src.Bucket, src.Key)
		if err != nil {
			return nil, sdkError("download "+src.String(), err)
		}
		defer body.Close()
		newETag, err := client.PutObject(ctx, dst.Bucket, dst.Key, body, size, "application/octet-stream")
		if err != nil {
			return nil, sdkError("upload "+dst.String(), err)
		}
		t := transfer{source: src.String(), dest: dst.String(), size: size, etag: newETag}
		printTransfer(stdout, g, "copy", t)
		return []transfer{t}, nil
	}

	prefix := dst.Key
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	var out []transfer
	err := forEachObject(ctx, client, src.Bucket, src.Key, func(o sdk.Object) error {
		rel := strings.TrimPrefix(o.Key, src.Key)
		rel = strings.TrimPrefix(rel, "/")
		key := prefixJoin(prefix, rel)
		body, err := client.GetObject(ctx, src.Bucket, o.Key)
		if err != nil {
			fmt.Fprintf(stderr, "fass: copy s3://%s/%s: %v\n", src.Bucket, o.Key, err)
			return sdkError("copy s3://"+src.Bucket+"/"+o.Key, err)
		}
		etag, perr := client.PutObject(ctx, dst.Bucket, key, body, o.Size, "application/octet-stream")
		body.Close()
		if perr != nil {
			fmt.Fprintf(stderr, "fass: copy s3://%s/%s: %v\n", src.Bucket, o.Key, perr)
			return sdkError("copy to s3://"+dst.Bucket+"/"+key, perr)
		}
		t := transfer{source: s3URL{src.Bucket, o.Key}.String(), dest: s3URL{dst.Bucket, key}.String(), size: o.Size, etag: etag}
		out = append(out, t)
		printTransfer(stdout, g, "copy", t)
		return nil
	})
	return out, err
}

func printTransfer(w io.Writer, g *globalOpts, verb string, t transfer) {
	if g.quiet || g.jsonOut {
		return
	}
	fmt.Fprintf(w, "%-8s %s -> %s (%s)\n", verb, t.source, t.dest, humanBytes(t.size))
}

// safeJoin joins base and rel, refusing paths that escape base (a malicious or
// accidental ".." key must never write outside the destination directory).
func safeJoin(base, rel string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(rel))
	if clean == "." || clean == "" {
		return "", usagef("refusing to write object with an empty relative path")
	}
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", usagef("refusing path traversal in object key %q", rel)
	}
	return filepath.Join(base, clean), nil
}

// ---------------------------------------------------------------------------
// rm
// ---------------------------------------------------------------------------

func runRM(ctx context.Context, g *globalOpts, args []string, recursive bool, stdout io.Writer) error {
	if len(args) != 1 {
		return usagef("rm requires exactly one s3://bucket/key argument")
	}
	ref, err := parseS3URL(args[0])
	if err != nil {
		return err
	}
	if ref.Key == "" && !recursive {
		return usagef("rm needs an object key; pass --recursive to delete every object in the bucket")
	}
	client, err := g.s3Client()
	if err != nil {
		return err
	}

	deleted := []string{}
	if !recursive {
		if err := client.DeleteObject(ctx, ref.Bucket, ref.Key); err != nil {
			return sdkError("delete "+ref.String(), err)
		}
		deleted = append(deleted, ref.Key)
		if !g.quiet && !g.jsonOut {
			fmt.Fprintf(stdout, "deleted %s\n", ref.String())
		}
	} else {
		err := forEachObject(ctx, client, ref.Bucket, ref.Key, func(o sdk.Object) error {
			if err := client.DeleteObject(ctx, ref.Bucket, o.Key); err != nil {
				fmt.Fprintf(os.Stderr, "fass: delete s3://%s/%s: %v\n", ref.Bucket, o.Key, err)
				return sdkError("delete s3://"+ref.Bucket+"/"+o.Key, err)
			}
			deleted = append(deleted, o.Key)
			if !g.quiet && !g.jsonOut {
				fmt.Fprintf(stdout, "deleted s3://%s/%s\n", ref.Bucket, o.Key)
			}
			return nil
		})
		if err != nil {
			return err
		}
		if len(deleted) == 0 && !g.quiet && !g.jsonOut {
			fmt.Fprintln(stdout, "no objects matched")
		}
	}
	if g.jsonOut {
		return writeJSON(stdout, deleted)
	}
	return nil
}

// ---------------------------------------------------------------------------
// mb / rb
// ---------------------------------------------------------------------------

func runBucket(ctx context.Context, g *globalOpts, cmd string, args []string, stdout io.Writer) error {
	if len(args) != 1 {
		return usagef("%s requires exactly one bucket name", cmd)
	}
	name := args[0]
	if isS3Path(name) {
		ref, err := parseS3URL(name)
		if err != nil {
			return err
		}
		if ref.Key != "" {
			return usagef("%s takes a bucket name, not an object key", cmd)
		}
		name = ref.Bucket
	}
	if name == "" {
		return usagef("bucket name is empty")
	}
	client, err := g.s3Client()
	if err != nil {
		return err
	}
	action := "created"
	if cmd == "mb" {
		if err := client.CreateBucket(ctx, name); err != nil {
			return sdkError("create bucket "+name, err)
		}
	} else {
		action = "deleted"
		if err := client.DeleteBucket(ctx, name); err != nil {
			return sdkError("delete bucket "+name, err)
		}
	}
	if g.jsonOut {
		return writeJSON(stdout, map[string]string{"bucket": name, "action": action})
	}
	if !g.quiet {
		fmt.Fprintf(stdout, "bucket %s: %s\n", name, action)
	}
	return nil
}

// ---------------------------------------------------------------------------
// presign
// ---------------------------------------------------------------------------

func runPresign(ctx context.Context, g *globalOpts, args []string, ttl time.Duration, stdout io.Writer) error {
	if len(args) != 1 {
		return usagef("presign requires exactly one s3://bucket/key argument")
	}
	if ttl <= 0 {
		return usagef("--ttl must be positive")
	}
	if ttl > 7*24*time.Hour {
		return usagef("--ttl cannot exceed 7 days (S3 presign limit)")
	}
	ref, err := parseS3URL(args[0])
	if err != nil {
		return err
	}
	if ref.Key == "" {
		return usagef("presign needs an object key")
	}
	client, err := g.s3Client()
	if err != nil {
		return err
	}
	u, err := client.PresignGet(ctx, ref.Bucket, ref.Key, ttl)
	if err != nil {
		return servicef(err, "presign %s", ref.String())
	}
	if g.jsonOut {
		return writeJSON(stdout, map[string]string{"url": u, "expires_in": ttl.String()})
	}
	fmt.Fprintln(stdout, u)
	return nil
}

// sdkError adds the failed operation to the error while preserving the
// underlying *sdk.Error so classifyError can map 4xx to exit 1 and 5xx/network
// errors to exit 2. It deliberately does NOT wrap in serviceError: that would
// mask the S3 status code.
func sdkError(op string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", op, err)
}
