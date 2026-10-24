package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeS3 is a deliberately dumb in-memory S3 server: enough XML to exercise the
// CLI through pkg/sdk (which signs real SigV4 requests; the fake ignores auth).
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][]byte // "/bucket/key" -> data
	buckets map[string]bool
	etags   map[string]string
}

func newFakeS3() *fakeS3 {
	return &fakeS3{objects: map[string][]byte{}, buckets: map[string]bool{"dev-bucket": true}, etags: map[string]string{}}
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := r.URL.Path
	switch r.Method {
	case http.MethodGet:
		if path == "/" {
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><ListAllMyBucketsResult><Buckets>`)
			for name := range f.buckets {
				fmt.Fprintf(w, `<Bucket><Name>%s</Name><CreationDate>2026-01-02T03:04:05Z</CreationDate></Bucket>`, name)
			}
			fmt.Fprint(w, `</Buckets></ListAllMyBucketsResult>`)
			return
		}
		if r.URL.Query().Get("list-type") == "2" || r.URL.Query().Has("prefix") {
			bucket := strings.TrimPrefix(path, "/")
			prefix := r.URL.Query().Get("prefix")
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><IsTruncated>false</IsTruncated>`)
			var keys []string
			for k := range f.objects {
				if strings.HasPrefix(k, "/"+bucket+"/") {
					keys = append(keys, strings.TrimPrefix(k, "/"+bucket+"/"))
				}
			}
			// deterministic order
			for i := 0; i < len(keys); i++ {
				for j := i + 1; j < len(keys); j++ {
					if keys[j] < keys[i] {
						keys[i], keys[j] = keys[j], keys[i]
					}
				}
			}
			for _, k := range keys {
				if !strings.HasPrefix(k, prefix) {
					continue
				}
				data := f.objects["/"+bucket+"/"+k]
				fmt.Fprintf(w, `<Contents><Key>%s</Key><Size>%d</Size><ETag>"%s"</ETag><LastModified>2026-01-02T03:04:05Z</LastModified></Contents>`,
					xmlEscape(k), len(data), f.etagFor(k, data))
			}
			fmt.Fprint(w, `</ListBucketResult>`)
			return
		}
		data, ok := f.objects[path]
		if !ok {
			writeS3Error(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")
			return
		}
		w.Header().Set("ETag", `"`+f.etags[path]+`"`)
		w.Header().Set("Content-Length", fmt.Sprint(len(data)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	case http.MethodHead:
		data, ok := f.objects[path]
		if !ok {
			writeS3Error(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")
			return
		}
		w.Header().Set("ETag", `"`+f.etags[path]+`"`)
		w.Header().Set("Content-Length", fmt.Sprint(len(data)))
		w.WriteHeader(http.StatusOK)
	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(strings.TrimPrefix(path, "/"), "/") { // bucket create
			f.buckets[strings.TrimPrefix(path, "/")] = true
			w.WriteHeader(http.StatusOK)
			return
		}
		f.objects[path] = body
		f.etags[path] = fmt.Sprintf("%x", sha256.Sum256(body))[:16]
		w.Header().Set("ETag", `"`+f.etags[path]+`"`)
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		name := strings.TrimPrefix(path, "/")
		if _, ok := f.objects[path]; ok {
			delete(f.objects, path)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if f.buckets[name] {
			delete(f.buckets, name)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeS3Error(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist.")
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (f *fakeS3) etagFor(key string, data []byte) string {
	if e, ok := f.etags["/"+key]; ok {
		return e
	}
	return fmt.Sprintf("%x", sha256.Sum256(data))[:16]
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func writeS3Error(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message></Error>`, code, msg)
}

func cliEnv(t *testing.T, endpoint string) {
	t.Helper()
	isolateEnv(t)
	t.Setenv("FASS_ENDPOINT", endpoint)
	t.Setenv("FASS_ACCESS_KEY_ID", "test-ak")
	t.Setenv("FASS_SECRET_ACCESS_KEY", "test-sk")
}

func runCLI(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), args, &stdout, &stderr)
	return stdout.String(), stderr.String(), code
}

func TestRunLSBucketsAndObjects(t *testing.T) {
	srv := httptest.NewServer(newFakeS3())
	defer srv.Close()
	cliEnv(t, srv.URL)

	out, stderr, code := runCLI(t, "ls")
	if code != 0 {
		t.Fatalf("ls exit %d: %s", code, stderr)
	}
	if !strings.Contains(out, "BUCKET") || !strings.Contains(out, "dev-bucket") {
		t.Fatalf("bucket table missing: %q", out)
	}

	out, stderr, code = runCLI(t, "ls", "--json", "s3://dev-bucket/")
	if code != 0 {
		t.Fatalf("ls --json exit %d: %s", code, stderr)
	}
	if strings.TrimSpace(out) != "[]" {
		t.Fatalf("empty object listing JSON = %q", out)
	}
}

func TestRunCPUpAndDown(t *testing.T) {
	srv := httptest.NewServer(newFakeS3())
	defer srv.Close()
	cliEnv(t, srv.URL)

	dir := t.TempDir()
	src := filepath.Join(dir, "payload.bin")
	data := make([]byte, 128<<10)
	for i := range data {
		data[i] = byte(i * 31)
	}
	if err := os.WriteFile(src, data, 0o600); err != nil {
		t.Fatal(err)
	}

	out, stderr, code := runCLI(t, "cp", src, "s3://dev-bucket/e2e/payload.bin")
	if code != 0 {
		t.Fatalf("cp up exit %d: %s\n%s", code, stderr, out)
	}
	if !strings.Contains(out, "e2e/payload.bin") {
		t.Fatalf("upload progress missing: %q", out)
	}

	dst := filepath.Join(dir, "roundtrip.bin")
	if _, stderr, code = runCLI(t, "cp", "s3://dev-bucket/e2e/payload.bin", dst); code != 0 {
		t.Fatalf("cp down exit %d: %s", code, stderr)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(got) != sha256.Sum256(data) {
		t.Fatal("round-tripped bytes differ")
	}

	// --json must be valid JSON with source/dest/size.
	out, stderr, code = runCLI(t, "cp", "s3://dev-bucket/e2e/payload.bin", filepath.Join(dir, "j.bin"), "--json")
	if code != 0 {
		t.Fatalf("cp --json exit %d: %s", code, stderr)
	}
	if !strings.Contains(out, `"dest"`) || !strings.Contains(out, `"size": 131072`) {
		t.Fatalf("cp JSON = %q", out)
	}
}

func TestRunCPRecursiveDirectory(t *testing.T) {
	srv := httptest.NewServer(newFakeS3())
	defer srv.Close()
	cliEnv(t, srv.URL)

	dir := t.TempDir()
	src := filepath.Join(dir, "tree")
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("alpha"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "sub", "b.txt"), []byte("bravo"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, stderr, code := runCLI(t, "cp", "-r", src, "s3://dev-bucket/backup"); code != 0 {
		t.Fatalf("recursive upload exit %d: %s", code, stderr)
	}
	out, stderr, code := runCLI(t, "ls", "--json", "s3://dev-bucket/backup/")
	if code != 0 {
		t.Fatalf("list exit %d: %s", code, stderr)
	}
	if !strings.Contains(out, "backup/a.txt") || !strings.Contains(out, "backup/sub/b.txt") {
		t.Fatalf("uploaded keys missing: %s", out)
	}

	dst := filepath.Join(dir, "restore")
	if _, stderr, code := runCLI(t, "cp", "-r", "s3://dev-bucket/backup/", dst); code != 0 {
		t.Fatalf("recursive download exit %d: %s", code, stderr)
	}
	if got, err := os.ReadFile(filepath.Join(dst, "a.txt")); err != nil || string(got) != "alpha" {
		t.Fatalf("restored a.txt = %q, %v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(dst, "sub", "b.txt")); err != nil || string(got) != "bravo" {
		t.Fatalf("restored sub/b.txt = %q, %v", got, err)
	}
}

func TestRunCPRequiresRecursiveForDirectory(t *testing.T) {
	srv := httptest.NewServer(newFakeS3())
	defer srv.Close()
	cliEnv(t, srv.URL)
	dir := t.TempDir()
	_, stderr, code := runCLI(t, "cp", dir, "s3://dev-bucket/x")
	if code != 1 {
		t.Fatalf("directory without -r: exit %d (want 1), stderr %q", code, stderr)
	}
	if !strings.Contains(stderr, "recursive") {
		t.Fatalf("error should mention --recursive: %q", stderr)
	}
}

func TestRunBucketCommands(t *testing.T) {
	srv := httptest.NewServer(newFakeS3())
	defer srv.Close()
	cliEnv(t, srv.URL)

	if _, stderr, code := runCLI(t, "mb", "--json", "new-bucket"); code != 0 {
		t.Fatalf("mb exit %d: %s", code, stderr)
	}
	out, _, code := runCLI(t, "mb", "--json", "new-bucket")
	if code != 0 || !strings.Contains(out, `"action": "created"`) {
		t.Fatalf("mb JSON = %q (exit %d)", out, code)
	}
	if _, stderr, code := runCLI(t, "rb", "new-bucket"); code != 0 {
		t.Fatalf("rb exit %d: %s", code, stderr)
	}
	if _, _, code := runCLI(t, "mb"); code != 1 {
		t.Fatalf("mb without args exit %d, want 1", code)
	}
}

func TestRunRM(t *testing.T) {
	fake := newFakeS3()
	fake.objects["/dev-bucket/a.txt"] = []byte("a")
	fake.objects["/dev-bucket/dir/b.txt"] = []byte("b")
	fake.objects["/dev-bucket/dir/c.txt"] = []byte("c")
	srv := httptest.NewServer(fake)
	defer srv.Close()
	cliEnv(t, srv.URL)

	if _, stderr, code := runCLI(t, "rm", "s3://dev-bucket/a.txt"); code != 0 {
		t.Fatalf("rm exit %d: %s", code, stderr)
	}
	out, stderr, code := runCLI(t, "rm", "-r", "--json", "s3://dev-bucket/dir/")
	if code != 0 {
		t.Fatalf("rm -r exit %d: %s", code, stderr)
	}
	if !strings.Contains(out, "dir/b.txt") || !strings.Contains(out, "dir/c.txt") {
		t.Fatalf("deleted keys JSON = %q", out)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.objects) != 0 {
		t.Fatalf("objects remain: %v", fake.objects)
	}
}

func TestRunPresign(t *testing.T) {
	srv := httptest.NewServer(newFakeS3())
	defer srv.Close()
	cliEnv(t, srv.URL)

	out, stderr, code := runCLI(t, "presign", "s3://dev-bucket/key.txt", "--ttl", "10m")
	if code != 0 {
		t.Fatalf("presign exit %d: %s", code, stderr)
	}
	u := strings.TrimSpace(out)
	if !strings.Contains(u, "X-Amz-Signature=") || !strings.Contains(u, "X-Amz-Expires=600") {
		t.Fatalf("presigned URL = %q", u)
	}
	if _, _, code := runCLI(t, "presign", "s3://dev-bucket/key.txt", "--ttl", "8d"); code != 1 {
		t.Fatalf("ttl > 7d should be a user error, got %d", code)
	}
}

func TestMissingCredentialsExitCode(t *testing.T) {
	isolateEnv(t)
	t.Setenv("FASS_ENDPOINT", "http://127.0.0.1:1")
	_, stderr, code := runCLI(t, "ls")
	if code != 1 {
		t.Fatalf("missing credentials exit %d, want 1 (stderr %q)", code, stderr)
	}
}

func TestServiceDownExitCode(t *testing.T) {
	isolateEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // now unreachable
	t.Setenv("FASS_ENDPOINT", url)
	t.Setenv("FASS_ACCESS_KEY_ID", "ak")
	t.Setenv("FASS_SECRET_ACCESS_KEY", "sk")

	_, _, code := runCLI(t, "ls", "--timeout", "500ms")
	if code != 2 {
		t.Fatalf("unreachable S3 exit %d, want 2", code)
	}
}

func TestFlagsAfterPositionals(t *testing.T) {
	// `-r` must be accepted after positional arguments (Go's flag package alone
	// would stop parsing at the first positional).
	fs := flag.NewFlagSet("cp", flag.ContinueOnError)
	var recursive bool
	fs.BoolVar(&recursive, "recursive", false, "")
	fs.BoolVar(&recursive, "r", false, "")
	pos, err := parseInterspersed(fs, []string{"src", "s3://b/k", "-r"})
	if err != nil {
		t.Fatalf("parseInterspersed: %v", err)
	}
	if !recursive {
		t.Fatal("-r after positionals was not applied")
	}
	if len(pos) != 2 || pos[0] != "src" || pos[1] != "s3://b/k" {
		t.Fatalf("positionals = %v", pos)
	}
}
