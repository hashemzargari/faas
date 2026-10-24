package offloader

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/fass-storage/fass/internal/chunk"
	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/crypto"
	"github.com/fass-storage/fass/internal/ec"
	"github.com/fass-storage/fass/internal/gateway/metrics"
)

// Additional offloader errors exposed to callers.
var (
	// ErrKeyMismatch means the manifest's key fingerprint does not match the
	// configured tenant keyring: fail precisely instead of with a GCM failure.
	ErrKeyMismatch = errors.New("offloader: key fingerprint mismatch")
	// ErrMissingShards means the read path could not assemble enough shards.
	ErrMissingShards = errors.New("offloader: not enough shards available")
)

// Config tunes the data-plane pipeline.
type Config struct {
	// ChunkSize is the default chunk size (per-RC; 16 MiB default).
	ChunkSize int
	// MaxConcurrentChunks bounds the write pipeline depth, and therefore
	// gateway memory: depth × (chunk + geo pieces + all shards), see docs/03 §1.3.
	MaxConcurrentChunks int
	// FrameSize is the AES-GCM frame size.
	FrameSize int

	// ShardPutParallel is the max concurrent shard PUTs per chunk.
	ShardPutParallel int
	// ShardPutTimeout and ShardPutRetries define the displacement trigger.
	ShardPutTimeout time.Duration
	ShardPutRetries int
	// MaxDisplacements bounds how many times a chunk's placement is retried.
	MaxDisplacements int

	// ShardReadParallel bounds concurrent shard GETs per chunk.
	ShardReadParallel int
	ShardReadTimeout  time.Duration
	ShardReadRetries  int
	// HedgeAfter starts fetching parity shards when the data shards are slow.
	HedgeAfter time.Duration
}

// DefaultConfig returns the documented defaults (docs/04 §1.5).
func DefaultConfig() Config {
	return Config{
		ChunkSize:           chunk.DefaultSize,
		MaxConcurrentChunks: 4,
		FrameSize:           crypto.DefaultFrameSize,
		ShardPutParallel:    16,
		ShardPutTimeout:     5 * time.Second,
		ShardPutRetries:     2,
		MaxDisplacements:    3,
		ShardReadParallel:   32,
		ShardReadTimeout:    10 * time.Second,
		ShardReadRetries:    1,
		HedgeAfter:          50 * time.Millisecond,
	}
}

func (c Config) withDefaults() Config {
	d := DefaultConfig()
	if c.ChunkSize == 0 {
		c.ChunkSize = d.ChunkSize
	}
	if c.MaxConcurrentChunks <= 0 {
		c.MaxConcurrentChunks = d.MaxConcurrentChunks
	}
	if c.FrameSize == 0 {
		c.FrameSize = d.FrameSize
	}
	if c.ShardPutParallel <= 0 {
		c.ShardPutParallel = d.ShardPutParallel
	}
	if c.ShardPutTimeout <= 0 {
		c.ShardPutTimeout = d.ShardPutTimeout
	}
	if c.ShardPutRetries < 0 {
		c.ShardPutRetries = 0
	}
	if c.MaxDisplacements <= 0 {
		c.MaxDisplacements = d.MaxDisplacements
	}
	if c.ShardReadParallel <= 0 {
		c.ShardReadParallel = d.ShardReadParallel
	}
	if c.ShardReadTimeout <= 0 {
		c.ShardReadTimeout = d.ShardReadTimeout
	}
	if c.ShardReadRetries < 0 {
		c.ShardReadRetries = 0
	}
	if c.HedgeAfter < 0 {
		c.HedgeAfter = 0
	}
	return c
}

// Deps are the offloader's collaborators.
type Deps struct {
	Coord    contract.Coordinator
	Shards   contract.AgentClient
	Keyrings KeyringProvider
	Logger   *slog.Logger
	Metrics  *metrics.Registry
	Config   Config
	Now      func() time.Time
}

// Offloader is the gateway data-plane engine. It is safe for concurrent use.
type Offloader struct {
	coord    contract.Coordinator
	shards   contract.AgentClient
	keyrings KeyringProvider
	log      *slog.Logger
	metrics  *metrics.Registry
	cfg      Config
	readSem  chan struct{}
}

// New builds an Offloader.
func New(d Deps) (*Offloader, error) {
	if d.Coord == nil {
		return nil, errors.New("offloader: nil coordinator")
	}
	if d.Shards == nil {
		return nil, errors.New("offloader: nil agent client")
	}
	if d.Keyrings == nil {
		return nil, errors.New("offloader: nil keyring provider")
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	cfg := d.Config.withDefaults()
	if err := chunk.ValidateSize(cfg.ChunkSize); err != nil {
		return nil, fmt.Errorf("offloader: %w", err)
	}
	return &Offloader{
		coord:    d.Coord,
		shards:   d.Shards,
		keyrings: d.Keyrings,
		log:      d.Logger,
		metrics:  d.Metrics,
		cfg:      cfg,
		readSem:  make(chan struct{}, cfg.ShardReadParallel),
	}, nil
}

// Config returns the effective configuration.
func (o *Offloader) Config() Config { return o.cfg }

// NewEncryptionMeta mints the object-level encryption metadata (a fresh random
// FileKey wrapped by the tenant KEK) for a multipart upload. Every part must be
// encrypted under this FileKey: a per-part key would leave all but one part
// undecryptable from the committed manifest.
func (o *Offloader) NewEncryptionMeta(ctx context.Context, tenant contract.TenantID) (contract.EncryptionMeta, error) {
	kr, err := o.keyrings.KeyringFor(ctx, tenant)
	if err != nil {
		return contract.EncryptionMeta{}, err
	}
	fileKey, err := crypto.NewFileKey()
	if err != nil {
		return contract.EncryptionMeta{}, err
	}
	defer fileKey.Zero()
	wrapped, err := kr.WrapKey(fileKey)
	if err != nil {
		return contract.EncryptionMeta{}, fmt.Errorf("offloader: wrap file key: %w", err)
	}
	fingerprint := kr.Fingerprint()
	return contract.EncryptionMeta{
		Mode:           "single-key",
		WrapKeyVersion: 1,
		WrappedFileKey: wrapped,
		KeyFingerprint: fingerprint[:],
		FrameSize:      o.cfg.FrameSize,
	}, nil
}

// writeResult is the outcome of the chunk pipeline before the commit.
type writeResult struct {
	chunks     []contract.ChunkRef
	size       int64
	etag       string
	encryption contract.EncryptionMeta
	ringID     contract.RingID
}

// Write encrypts, erasure-codes, places and writes one object, then commits it.
// It returns only after every shard is acknowledged and the manifest is
// committed (docs/04 §2.3 invariant 1).
func (o *Offloader) Write(ctx context.Context, spec ObjectSpec, body io.Reader) (contract.CommitResult, error) {
	res, err := o.writeChunks(ctx, spec, body)
	if err != nil {
		return contract.CommitResult{}, err
	}
	commit := contract.CommitRequest{
		VersionID:    spec.VersionID,
		BucketID:     spec.BucketID,
		Key:          spec.Key,
		Size:         res.size,
		ETag:         res.etag,
		ChunkSize:    o.chunkSize(spec),
		Chunks:       res.chunks,
		Encryption:   res.encryption,
		ContentType:  spec.ContentType,
		UserMeta:     spec.UserMeta,
		Tags:         spec.Tags,
		RCID:         spec.RCID,
		RingID:       res.ringID,
		StorageClass: spec.StorageClass,
		IfMatch:      spec.IfMatch,
		IfNoneMatch:  spec.IfNoneMatch,
		Retention:    spec.Retention,
	}
	out, err := o.coord.CommitObject(ctx, commit)
	if err != nil {
		return contract.CommitResult{}, fmt.Errorf("offloader: commit object %s/%s: %w", spec.Bucket, spec.Key, err)
	}
	if out.ETag == "" {
		out.ETag = res.etag
	}
	if out.VersionID == "" {
		out.VersionID = spec.VersionID
	}
	if o.metrics != nil {
		o.metrics.Add("fass_gateway_bytes_written_total", map[string]string{"tenant": string(spec.TenantID)}, uint64(res.size))
	}
	return out, nil
}

// WritePart writes one multipart part and returns its reference. The part is not
// committed as an object; CompleteMultipartUpload assembles the manifest of
// part manifests (docs/05 §8).
func (o *Offloader) WritePart(ctx context.Context, spec ObjectSpec, uploadID contract.UploadID, partNumber int, body io.Reader) (PartRef, error) {
	if partNumber < 1 {
		return PartRef{}, fmt.Errorf("offloader: invalid part number %d", partNumber)
	}
	// Every part restarts chunk indices at 0, so the scope is what keeps part 2's
	// shard-set ids disjoint from part 1's (see contract.ShardSetIDForScoped).
	spec.PartScope = fmt.Sprintf("part/%d", partNumber)
	res, err := o.writeChunks(ctx, spec, body)
	if err != nil {
		return PartRef{}, err
	}
	return PartRef{
		ETag:       res.etag,
		Size:       res.size,
		Chunks:     res.chunks,
		Encryption: res.encryption,
	}, nil
}

// encryptorFor returns the chunk encryptor for a write. Multipart parts must
// reuse the object's file key (established at CreateMultipartUpload); a single
// PUT mints a fresh one. Either way the encryption metadata recorded in the
// manifest is the one that unlocks every chunk.
func (o *Offloader) encryptorFor(ctx context.Context, spec ObjectSpec) (*crypto.ChunkEncryptor, contract.EncryptionMeta, error) {
	kr, err := o.keyrings.KeyringFor(ctx, spec.TenantID)
	if err != nil {
		return nil, contract.EncryptionMeta{}, err
	}
	if spec.Encryption != nil && len(spec.Encryption.WrappedFileKey) > 0 {
		if fp := kr.Fingerprint(); len(spec.Encryption.KeyFingerprint) > 0 &&
			!bytes.Equal(fp[:], spec.Encryption.KeyFingerprint) {
			return nil, contract.EncryptionMeta{}, fmt.Errorf("%w: upload fingerprint %x, keyring %x",
				ErrKeyMismatch, spec.Encryption.KeyFingerprint, fp)
		}
		fileKey, err := kr.UnwrapKey(spec.Encryption.WrappedFileKey)
		if err != nil {
			return nil, contract.EncryptionMeta{}, fmt.Errorf("offloader: unwrap upload file key: %w", err)
		}
		defer fileKey.Zero()
		frameSize := spec.Encryption.FrameSize
		if frameSize == 0 {
			frameSize = o.cfg.FrameSize
		}
		enc, err := crypto.NewChunkEncryptor(fileKey, frameSize)
		if err != nil {
			return nil, contract.EncryptionMeta{}, err
		}
		return enc, *spec.Encryption, nil
	}

	fileKey, err := crypto.NewFileKey()
	if err != nil {
		return nil, contract.EncryptionMeta{}, err
	}
	defer fileKey.Zero()
	wrapped, err := kr.WrapKey(fileKey)
	if err != nil {
		return nil, contract.EncryptionMeta{}, fmt.Errorf("offloader: wrap file key: %w", err)
	}
	fingerprint := kr.Fingerprint()
	enc, err := crypto.NewChunkEncryptor(fileKey, o.cfg.FrameSize)
	if err != nil {
		return nil, contract.EncryptionMeta{}, err
	}
	return enc, contract.EncryptionMeta{
		Mode:           "single-key",
		WrapKeyVersion: 1,
		WrappedFileKey: wrapped,
		KeyFingerprint: fingerprint[:],
		FrameSize:      o.cfg.FrameSize,
	}, nil
}

func (o *Offloader) chunkSize(spec ObjectSpec) int {
	if spec.ChunkSize > 0 {
		return spec.ChunkSize
	}
	return o.cfg.ChunkSize
}

// chunkJob is one in-flight chunk on the write pipeline.
type chunkJob struct {
	index     int
	plaintext []byte
}

// writeChunks runs the bounded write pipeline. Memory is bounded by
// MaxConcurrentChunks × chunk size (plus the encoder's transient buffers).
func (o *Offloader) writeChunks(ctx context.Context, spec ObjectSpec, body io.Reader) (*writeResult, error) {
	chunkSize := o.chunkSize(spec)
	if err := chunk.ValidateSize(chunkSize); err != nil {
		return nil, fmt.Errorf("offloader: %w", err)
	}
	codec, err := ec.New(spec.Params)
	if err != nil {
		return nil, fmt.Errorf("offloader: invalid redundancy class: %w", err)
	}

	enc, encMeta, err := o.encryptorFor(ctx, spec)
	if err != nil {
		return nil, err
	}

	maxBytes := spec.MaxBytes
	if maxBytes <= 0 {
		maxBytes = spec.Size
	}
	if maxBytes <= 0 {
		maxBytes = 5 << 40
	}

	digests := newDigestSet(spec.Checksums)
	workers := o.cfg.MaxConcurrentChunks
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan chunkJob)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var refs []contract.ChunkRef
	var ringID contract.RingID
	var firstErr error
	fail := func(err error) {
		mu.Lock()
		if firstErr == nil {
			firstErr = err
			cancel()
		}
		mu.Unlock()
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if ctx.Err() != nil {
					continue
				}
				ref, ring, err := o.processChunk(ctx, spec, codec, enc, job)
				clear(job.plaintext)
				if err != nil {
					fail(err)
					continue
				}
				mu.Lock()
				refs = append(refs, ref)
				if ringID == "" {
					ringID = ring
				}
				mu.Unlock()
			}
		}()
	}

	var total int64
	index := 0
	var readErr error
loop:
	for {
		buf := make([]byte, chunkSize)
		n, rerr := io.ReadFull(body, buf)
		if n > 0 {
			total += int64(n)
			if total > maxBytes {
				readErr = ErrTooLarge
				break
			}
			digests.Update(buf[:n])
			select {
			case jobs <- chunkJob{index: index, plaintext: buf[:n]}:
				index++
			case <-ctx.Done():
				readErr = ctx.Err()
				break loop
			}
		}
		switch {
		case errors.Is(rerr, io.EOF), errors.Is(rerr, io.ErrUnexpectedEOF):
			break loop
		case rerr != nil:
			readErr = fmt.Errorf("offloader: read request body: %w", rerr)
			break loop
		}
	}
	close(jobs)
	wg.Wait()

	if readErr != nil && !errors.Is(readErr, context.Canceled) {
		return nil, readErr
	}
	if firstErr != nil {
		return nil, firstErr
	}
	if spec.Size >= 0 && total != spec.Size {
		return nil, fmt.Errorf("%w: read %d bytes, expected %d", ErrIncompleteBody, total, spec.Size)
	}

	expected := spec.Checksums
	if spec.DeferredChecksums != nil {
		expected = append(expected, spec.DeferredChecksums()...)
	}
	if err := digests.Verify(expected); err != nil {
		return nil, err
	}

	sort.Slice(refs, func(i, j int) bool { return refs[i].Index < refs[j].Index })
	return &writeResult{
		chunks:     refs,
		size:       total,
		etag:       digests.ETag(),
		encryption: encMeta,
		ringID:     ringID,
	}, nil
}

// processChunk runs encrypt → encode → place → shard PUTs for one chunk.
func (o *Offloader) processChunk(ctx context.Context, spec ObjectSpec, codec *ec.Codec, enc *crypto.ChunkEncryptor, job chunkJob) (contract.ChunkRef, contract.RingID, error) {
	aad := crypto.ChunkAAD{
		TenantID:   string(spec.TenantID),
		Bucket:     spec.Bucket,
		Key:        spec.Key,
		VersionID:  string(spec.VersionID),
		ChunkIndex: job.index,
	}
	ciphertext, err := enc.EncryptChunk(job.plaintext, aad)
	if err != nil {
		return contract.ChunkRef{}, "", fmt.Errorf("offloader: encrypt chunk %d: %w", job.index, err)
	}
	shards, geom, err := codec.Encode(ciphertext)
	if err != nil {
		return contract.ChunkRef{}, "", fmt.Errorf("offloader: encode chunk %d: %w", job.index, err)
	}
	if len(shards) == 0 {
		return contract.ChunkRef{}, "", fmt.Errorf("%w: chunk %d produced no shards", ErrManifest, job.index)
	}

	shardSetID := contract.ShardSetIDForScoped(spec.BucketID, spec.Key, spec.VersionID, spec.PartScope, job.index)
	slots, checksums, ringID, generation, err := o.placeAndWriteShards(ctx, spec, shardSetID, job.index, len(ciphertext), shards)
	if err != nil {
		return contract.ChunkRef{}, "", err
	}
	return contract.ChunkRef{
		Index:         job.index,
		Params:        spec.Params,
		CiphertextLen: len(ciphertext),
		ShardSize:     geom.ShardSize,
		Slots:         slots,
		Checksums:     checksums,
		Generation:    generation,
		// Authoritative shard-set address for this chunk. Stamping it lets the
		// coordinator assemble multipart chunk tables (which renumber Index)
		// without the read path ever re-deriving the wrong address.
		ShardSetID: shardSetID,
		// The AAD index is the index used at encryption time: part-local for
		// multipart, object-wide for a single PUT. It must travel with the ref
		// because CompleteUpload renumbers Index across parts.
		AADChunkIndex: job.index,
	}, ringID, nil
}

// placeAndWriteShards resolves placement and writes every shard, displacing
// failed slots onto replacement agents (docs/03 §4.4).
func (o *Offloader) placeAndWriteShards(ctx context.Context, spec ObjectSpec, shardSetID contract.ShardSetID, chunkIndex, chunkBytes int, shards [][]byte) ([]contract.Slot, []uint64, contract.RingID, int, error) {
	req := contract.PlacementRequest{
		ShardSetID: shardSetID,
		Params:     spec.Params,
		ChunkBytes: chunkBytes,
		TenantID:   spec.TenantID,
		ProjectID:  spec.ProjectID,
		RCID:       spec.RCID,
		RingID:     spec.RingID,
	}
	placement, err := o.coord.ResolvePlacement(ctx, req)
	if err != nil {
		return nil, nil, "", 0, fmt.Errorf("%w: %v", ErrPlacement, err)
	}
	if err := validatePlacement(placement, len(shards)); err != nil {
		return nil, nil, "", 0, err
	}
	slots := append([]contract.Slot(nil), placement.Slots...)
	ringID := placement.RingID
	generation := placement.Generation
	checksums := make([]uint64, len(shards))
	for i, shard := range shards {
		checksums[i] = Checksum64(shard)
	}

	excluded := make(map[contract.AgentID]struct{})
	for attempt := 0; ; attempt++ {
		failed := o.putWave(ctx, slots, shardSetID, chunkIndex, spec.Params, shards)
		if len(failed) == 0 {
			return slots, checksums, ringID, generation, nil
		}
		if attempt >= o.cfg.MaxDisplacements {
			return nil, nil, "", 0, fmt.Errorf("%w: %d shard slots still failing after %d displacements",
				ErrShardWrite, len(failed), attempt)
		}
		for idx := range failed {
			excluded[slots[idx].AgentID] = struct{}{}
		}
		req.ExcludeAgents = make([]contract.AgentID, 0, len(excluded))
		for id := range excluded {
			req.ExcludeAgents = append(req.ExcludeAgents, id)
		}
		sort.Slice(req.ExcludeAgents, func(i, j int) bool { return req.ExcludeAgents[i] < req.ExcludeAgents[j] })
		replacement, perr := o.coord.ResolvePlacement(ctx, req)
		if perr != nil {
			return nil, nil, "", 0, fmt.Errorf("%w: resolve displacement: %v", ErrPlacement, perr)
		}
		if err := validatePlacement(replacement, len(shards)); err != nil {
			return nil, nil, "", 0, err
		}
		for idx := range failed {
			o.log.Warn("displacing shard slot",
				"shard_set_id", string(shardSetID),
				"chunk_index", chunkIndex,
				"slot", idx,
				"failed_agent", string(slots[idx].AgentID),
				"replacement_agent", string(replacement.Slots[idx].AgentID))
			if o.metrics != nil {
				o.metrics.Inc("fass_gateway_shard_displacements_total", nil)
			}
			slots[idx] = replacement.Slots[idx]
		}
		generation = replacement.Generation
		if replacement.RingID != "" {
			ringID = replacement.RingID
		}
	}
}

func validatePlacement(p contract.Placement, want int) error {
	if len(p.Slots) != want {
		return fmt.Errorf("%w: placement returned %d slots, need %d", ErrPlacement, len(p.Slots), want)
	}
	for i, s := range p.Slots {
		if s.Endpoint == "" {
			return fmt.Errorf("%w: slot %d has no endpoint", ErrPlacement, i)
		}
	}
	return nil
}

// putWave writes all shards for one chunk and reports the failed indices.
func (o *Offloader) putWave(ctx context.Context, slots []contract.Slot, shardSetID contract.ShardSetID, chunkIndex int, params ec.Params, shards [][]byte) map[int]error {
	failed := make(map[int]error)
	var mu sync.Mutex
	sem := make(chan struct{}, o.cfg.ShardPutParallel)
	var wg sync.WaitGroup
	for idx := range shards {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if err := o.putShardWithRetry(ctx, slots[idx], shardSetID, chunkIndex, params, shards[idx]); err != nil {
				mu.Lock()
				failed[idx] = err
				mu.Unlock()
			}
		}(idx)
	}
	wg.Wait()
	return failed
}

// putShardWithRetry PUTs one shard with a bounded timeout and retries.
func (o *Offloader) putShardWithRetry(ctx context.Context, slot contract.Slot, shardSetID contract.ShardSetID, chunkIndex int, params ec.Params, shard []byte) error {
	checksum := Checksum64(shard)
	var lastErr error
	for attempt := 0; attempt <= o.cfg.ShardPutRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		attemptCtx, cancel := context.WithTimeout(ctx, o.cfg.ShardPutTimeout)
		err := o.shards.PutShard(attemptCtx, slot.Endpoint, contract.PutShardRequest{
			ShardSetID: shardSetID,
			GeoGroup:   slot.GeoGroup,
			LocalIndex: slot.LocalIndex,
			Params:     params,
			ChunkIndex: chunkIndex,
			PayloadLen: len(shard),
			Checksum:   checksum,
			Body:       bytes.NewReader(shard),
		})
		cancel()
		if err == nil {
			if o.metrics != nil {
				o.metrics.Inc("fass_gateway_shard_puts_total", map[string]string{"result": "ok"})
			}
			return nil
		}
		lastErr = err
		if o.metrics != nil {
			o.metrics.Inc("fass_gateway_shard_puts_total", map[string]string{"result": "error"})
		}
		// A capacity error will not improve on retry: displace immediately.
		if errors.Is(err, contract.ErrInsufficientCap) {
			break
		}
	}
	return fmt.Errorf("%w: agent %s (%s): %v", ErrShardWrite, slot.AgentID, slot.Endpoint, lastErr)
}
