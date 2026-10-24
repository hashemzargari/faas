package bridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

const listPageSize = 1000

// migrate runs every incomplete bucket, resuming from the persisted journal.
func (b *bridge) migrate(ctx context.Context, opts Options) error {
	lim := newLimiter(opts.MaxRequestsPerSecond, opts.MaxBytesPerSecond, opts.Now)
	src, err := newS3Client(b.st.Source, opts.HTTPClient, lim, opts.Now, opts.Log)
	if err != nil {
		return err
	}
	tgt, err := newS3Client(b.st.Target, opts.HTTPClient, lim, opts.Now, opts.Log)
	if err != nil {
		return err
	}
	for _, bucket := range b.st.Buckets {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		b.mu.Lock()
		completed := bucket.Completed
		b.mu.Unlock()
		if completed {
			continue
		}
		if err := b.migrateBucket(ctx, src, tgt, lim, bucket); err != nil {
			return err
		}
	}
	return nil
}

func (b *bridge) migrateBucket(ctx context.Context, src, tgt *s3Client, lim *limiter, bucket *journalBucket) error {
	// Documented limitation: Object Lock retention makes the "delete source after
	// verified copy" contract impossible, so refuse before touching anything.
	locked, err := src.objectLockEnabled(ctx, bucket.Name)
	if err != nil {
		return fmt.Errorf("bridge: probe Object Lock on %q: %w", bucket.Name, err)
	}
	if locked {
		return &ObjectLockError{Bucket: bucket.Name}
	}

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		b.mu.Lock()
		token := bucket.ContinuationToken
		b.mu.Unlock()

		objects, next, err := src.listObjects(ctx, bucket.Name, token, listPageSize)
		if err != nil {
			return fmt.Errorf("bridge: list %q: %w", bucket.Name, err)
		}
		if len(objects) > 0 {
			if err := b.processPage(ctx, src, tgt, lim, bucket, objects); err != nil {
				return err
			}
		}
		b.mu.Lock()
		bucket.ContinuationToken = next
		saveErr := saveJournal(b.path, b.st)
		b.mu.Unlock()
		if saveErr != nil {
			return saveErr
		}
		if next == "" {
			break
		}
	}

	b.mu.Lock()
	bucket.Completed = true
	saveErr := saveJournal(b.path, b.st)
	b.mu.Unlock()
	return saveErr
}

// processPage copies one listing page with bounded concurrency, waits for all
// objects, then lets the caller persist the continuation token.
func (b *bridge) processPage(ctx context.Context, src, tgt *s3Client, lim *limiter, bucket *journalBucket, objects []s3Object) error {
	concurrency := b.opts.Concurrency
	if concurrency < 1 {
		concurrency = 1
	}
	jobs := make(chan s3Object)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for obj := range jobs {
				if ctx.Err() != nil {
					return
				}
				if err := b.copyObject(ctx, src, tgt, lim, bucket, obj); err != nil {
					if ctx.Err() != nil {
						// Interrupted: leave the object unclassified so the resumed
						// run retries it rather than counting a shutdown as failure.
						return
					}
					// Failures are counted, never retried within the run, and the
					// source copy is left untouched.
					b.recordOutcome(bucket, obj.Key, objectFailed, 0, err)
				}
			}
		}()
	}
	for _, obj := range objects {
		select {
		case jobs <- obj:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return ctx.Err()
		}
	}
	close(jobs)
	wg.Wait()
	return ctx.Err()
}

// copyObject implements the per-object contract:
//  1. skip if a target version is at least as new as the source (a stale source
//     copy must never overwrite a write that landed on the target);
//  2. copy source → target (single PUT or multipart);
//  3. verify by re-reading the target (size + SHA-256);
//  4. delete the source only after verification succeeded.
func (b *bridge) copyObject(ctx context.Context, src, tgt *s3Client, lim *limiter, bucket *journalBucket, obj s3Object) error {
	b.mu.Lock()
	_, done := bucket.Done[obj.Key]
	b.mu.Unlock()
	if done {
		return nil // resumed run: already classified
	}

	if target, err := tgt.headObject(ctx, bucket.Name, obj.Key); err == nil {
		if newestTarget(target, obj) {
			// Leave the source in place: the target has the authoritative (newer)
			// version, and deleting the source would discard the only other copy.
			b.recordOutcome(bucket, obj.Key, objectSkipped, 0, nil)
			return nil
		}
	} else if !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("head target: %w", err)
	}

	path, size, sum, err := b.download(ctx, src, bucket.Name, obj.Key)
	if err != nil {
		return err
	}
	defer os.Remove(path)

	if size >= b.opts.MultipartThreshold {
		err = tgt.putMultipart(ctx, bucket.Name, obj.Key, path, size, b.opts.PartSize)
	} else {
		err = tgt.putFile(ctx, bucket.Name, obj.Key, fileSource(path))
	}
	if err != nil {
		return fmt.Errorf("upload: %w", err)
	}

	if err := verifyTarget(ctx, tgt, bucket.Name, obj.Key, size, sum); err != nil {
		// Verification failure: keep the source (the caller counts it failed).
		// The target copy is left alone because a concurrent writer may own it.
		return fmt.Errorf("verify: %w", err)
	}

	// The source may have been overwritten while we were copying it; deleting it
	// then would destroy the newer source object. Re-check before deleting.
	current, err := src.headObject(ctx, bucket.Name, obj.Key)
	if err != nil {
		return fmt.Errorf("re-head source before delete: %w", err)
	}
	if current.Size != obj.Size || (obj.ETag != "" && current.ETag != "" && current.ETag != obj.ETag) {
		return fmt.Errorf("source changed during copy (size %d→%d); source retained", obj.Size, current.Size)
	}
	if err := src.deleteObject(ctx, bucket.Name, obj.Key); err != nil {
		return fmt.Errorf("delete source: %w", err)
	}
	if lim != nil {
		if err := lim.bytes(ctx, size); err != nil {
			return err
		}
	}
	b.recordOutcome(bucket, obj.Key, objectMigrated, size, nil)
	return nil
}

// newestTarget reports whether the target already holds a version at least as
// new as the source listing entry.
func newestTarget(target, source s3Object) bool {
	if target.LastModified.IsZero() || source.LastModified.IsZero() {
		return false
	}
	return !target.LastModified.Before(source.LastModified)
}

// download streams the source object to a temp file, returning its path, size
// and hex SHA-256. The size is the number of bytes actually read; the caller
// verifies the target against it, so a source that changes mid-read is caught
// by the pre-delete re-head.
func (b *bridge) download(ctx context.Context, src *s3Client, bucket, key string) (string, int64, string, error) {
	body, meta, err := src.getObject(ctx, bucket, key)
	if err != nil {
		return "", 0, "", fmt.Errorf("get source: %w", err)
	}
	defer body.Close()
	f, err := os.CreateTemp("", "fass-bridge-*")
	if err != nil {
		return "", 0, "", fmt.Errorf("bridge: temp file: %w", err)
	}
	path := f.Name()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), body)
	closeErr := f.Close()
	if err != nil {
		os.Remove(path)
		return "", 0, "", fmt.Errorf("read source: %w", err)
	}
	if closeErr != nil {
		os.Remove(path)
		return "", 0, "", closeErr
	}
	if meta.Size >= 0 && meta.Size != n {
		os.Remove(path)
		return "", 0, "", fmt.Errorf("source size changed during read (listing %d, read %d)", meta.Size, n)
	}
	return path, n, hex.EncodeToString(h.Sum(nil)), nil
}

// fileSource opens the temp file and returns its SHA-256 and size so the upload
// is signed against a verifiable payload.
func fileSource(path string) func() (io.ReadCloser, string, int64, error) {
	return func() (io.ReadCloser, string, int64, error) {
		f, err := os.Open(path)
		if err != nil {
			return nil, "", 0, err
		}
		h := sha256.New()
		n, err := io.Copy(h, f)
		if err != nil {
			f.Close()
			return nil, "", 0, err
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			f.Close()
			return nil, "", 0, err
		}
		return f, hex.EncodeToString(h.Sum(nil)), n, nil
	}
}

// putMultipart uploads a local file in PartSize chunks.
func (c *s3Client) putMultipart(ctx context.Context, bucket, key, path string, size, partSize int64) error {
	uploadID, err := c.createMultipart(ctx, bucket, key, "")
	if err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		c.abortMultipart(ctx, bucket, key, uploadID)
		return err
	}
	defer f.Close()
	var parts []completedPart
	buf := make([]byte, partSize)
	for number := 1; ; number++ {
		n, rerr := io.ReadFull(f, buf)
		if rerr == io.EOF {
			break
		}
		if rerr != nil && rerr != io.ErrUnexpectedEOF {
			c.abortMultipart(ctx, bucket, key, uploadID)
			return fmt.Errorf("bridge: read part %d: %w", number, rerr)
		}
		sum := sha256.Sum256(buf[:n])
		etag, err := c.uploadPart(ctx, bucket, key, uploadID, number, bytes.NewReader(buf[:n]), int64(n), hex.EncodeToString(sum[:]))
		if err != nil {
			c.abortMultipart(ctx, bucket, key, uploadID)
			return fmt.Errorf("bridge: upload part %d: %w", number, err)
		}
		parts = append(parts, completedPart{Number: number, ETag: etag})
		if rerr == io.ErrUnexpectedEOF {
			break
		}
	}
	if len(parts) == 0 {
		c.abortMultipart(ctx, bucket, key, uploadID)
		return fmt.Errorf("bridge: multipart upload with no parts (size %d)", size)
	}
	if err := c.completeMultipart(ctx, bucket, key, uploadID, parts); err != nil {
		c.abortMultipart(ctx, bucket, key, uploadID)
		return err
	}
	return nil
}

// verifyTarget re-reads the copied object and compares size and SHA-256.
func verifyTarget(ctx context.Context, tgt *s3Client, bucket, key string, wantSize int64, wantHash string) error {
	head, err := tgt.headObject(ctx, bucket, key)
	if err != nil {
		return fmt.Errorf("head target: %w", err)
	}
	if head.Size >= 0 && head.Size != wantSize {
		return fmt.Errorf("size mismatch: target %d, source %d", head.Size, wantSize)
	}
	body, meta, err := tgt.getObject(ctx, bucket, key)
	if err != nil {
		return fmt.Errorf("get target: %w", err)
	}
	defer body.Close()
	h := sha256.New()
	n, err := io.Copy(h, body)
	if err != nil {
		return fmt.Errorf("read target: %w", err)
	}
	if meta.Size >= 0 && meta.Size != n {
		return fmt.Errorf("target truncated: header %d, read %d", meta.Size, n)
	}
	if n != wantSize {
		return fmt.Errorf("size mismatch after read: target %d, source %d", n, wantSize)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != wantHash {
		return fmt.Errorf("SHA-256 mismatch: target %s, source %s", got, wantHash)
	}
	return nil
}

// recordOutcome classifies an object exactly once and persists the journal so a
// restart resumes without re-copying or double-counting.
func (b *bridge) recordOutcome(bucket *journalBucket, key, outcome string, bytes int64, failure error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, exists := bucket.Done[key]; exists {
		return
	}
	bucket.Done[key] = outcome
	switch outcome {
	case objectMigrated:
		bucket.Migrated++
		bucket.Bytes += bytes
	case objectFailed:
		bucket.Failed++
	case objectSkipped:
		bucket.Skipped++
	}
	if failure != nil {
		b.opts.Log.Warn("bridge object failed (source retained)",
			"bridge_id", b.st.ID, "bucket", bucket.Name, "key", key, "error", failure.Error())
	}
	if err := saveJournal(b.path, b.st); err != nil {
		b.opts.Log.Error("bridge: persist journal", "bridge_id", b.st.ID, "error", err)
	}
}
