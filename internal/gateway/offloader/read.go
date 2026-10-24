package offloader

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/fass-storage/fass/internal/chunk"
	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/crypto"
	"github.com/fass-storage/fass/internal/ec"
)

// Read reconstructs an object (or a byte range of it) and streams the plaintext
// to w. It is the exact inverse of Write:
//
//	shards → inner decode per geo group → outer decode once geo_n groups are
//	reachable → decrypt → write
//
// Chunks are processed in order with a bounded number of shard GETs in flight,
// so memory stays bounded by a small multiple of the chunk size.
func (o *Offloader) Read(ctx context.Context, req ReadRequest, w io.Writer) error {
	m := req.Manifest
	if m.Size < 0 {
		return fmt.Errorf("%w: negative object size", ErrManifest)
	}
	if m.Size == 0 {
		// A zero-byte object has no chunks and therefore no manifest blob
		// (the coordinator only stores a blob when the chunk table is non-empty),
		// so its manifest carries a zero encryption envelope. There is no
		// ciphertext to unlock and no shard to fetch: the correct body is empty.
		return nil
	}

	aadVersion := string(m.VersionID)

	tenant := req.TenantID
	if tenant == "" {
		tenant = m.TenantID
	}
	kr, err := o.keyrings.KeyringFor(ctx, tenant)
	if err != nil {
		return err
	}
	fingerprint := kr.Fingerprint()
	if len(m.Encryption.KeyFingerprint) > 0 && !bytes.Equal(fingerprint[:], m.Encryption.KeyFingerprint) {
		return fmt.Errorf("%w: manifest fingerprint %x, keyring %x",
			ErrKeyMismatch, m.Encryption.KeyFingerprint, fingerprint)
	}
	fileKey, err := kr.UnwrapKey(m.Encryption.WrappedFileKey)
	if err != nil {
		return fmt.Errorf("offloader: unwrap file key: %w", err)
	}
	defer fileKey.Zero()
	frameSize := m.Encryption.FrameSize
	if frameSize == 0 {
		frameSize = o.cfg.FrameSize
	}
	enc, err := crypto.NewChunkEncryptor(fileKey, frameSize)
	if err != nil {
		return err
	}

	// Per-chunk plaintext lengths. Multipart parts of arbitrary size make chunk
	// lengths non-uniform mid-object, so byte ranges must be mapped through a
	// prefix sum, never through arithmetic on a fixed chunk size.
	lengths, err := chunkPlaintextLengths(m, frameSize)
	if err != nil {
		return err
	}
	needed, err := planChunkRanges(lengths, req.Range)
	if err != nil {
		return err
	}

	for _, cr := range needed {
		if cr.Index < 0 || cr.Index >= len(m.Chunks) {
			return fmt.Errorf("%w: chunk %d not in manifest (%d chunks)", ErrManifest, cr.Index, len(m.Chunks))
		}
		ref := m.Chunks[cr.Index]
		codec, err := ec.New(ref.Params)
		if err != nil {
			return fmt.Errorf("%w: chunk %d params: %v", ErrManifest, cr.Index, err)
		}
		plaintext, err := o.readChunk(ctx, tenant, m.BucketID, req.Bucket, req.Key, aadVersion, ref.AADChunkIndex, codec, ref, enc)
		if err != nil && errors.Is(err, ErrMissingShards) {
			// Bounded retry: the data exists on healthy agents, so one retry that
			// re-resolves the manifest (the coordinator is authoritative for
			// slots/shard-set ids) should either succeed or prove a real loss.
			// This is deliberately per-chunk: earlier chunks have already been
			// streamed, so retrying the whole object would duplicate bytes.
			if retryErr := sleepCtx(ctx, o.cfg.HedgeAfter); retryErr == nil {
				if fresh, ferr := o.coord.GetManifest(ctx, req.Bucket, req.Key, m.VersionID); ferr == nil &&
					cr.Index < len(fresh.Chunks) && sameObjectVersion(m, fresh, cr.Index) {
					// Only adopt the refreshed chunk when the manifest provably
					// describes the same version. Suspended buckets reuse the
					// version id "null", so an overwrite can make GetManifest return
					// a *different* object under the same id; mixing its chunk refs
					// into a partially streamed read of the old object would serve
					// frankenbytes. On identity mismatch we retry with the original
					// refs (a consistent old-version read) and fail honestly if the
					// data is genuinely gone.
					ref = fresh.Chunks[cr.Index]
					if c2, cerr := ec.New(ref.Params); cerr == nil {
						codec = c2
					}
				}
				plaintext, err = o.readChunk(ctx, tenant, m.BucketID, req.Bucket, req.Key, aadVersion, ref.AADChunkIndex, codec, ref, enc)
			}
		}
		if err != nil {
			return err
		}
		if cr.Offset < 0 || cr.Length < 0 || cr.Offset+cr.Length > int64(len(plaintext)) {
			return fmt.Errorf("%w: chunk %d range [%d,%d) outside %d plaintext bytes",
				ErrManifest, cr.Index, cr.Offset, cr.Offset+cr.Length, len(plaintext))
		}
		if _, err := w.Write(plaintext[cr.Offset : cr.Offset+cr.Length]); err != nil {
			return fmt.Errorf("offloader: write response body: %w", err)
		}
	}
	return nil
}

// chunkPlaintextLengths derives each chunk's plaintext length from its
// ciphertext length.
//
// crypto frames a chunk as 28-byte header + plaintext + 28 bytes of GCM
// nonce/tag per frame, with 1 MiB frames by default, so
//
//	ctLen = header + P + overhead*ceil(P/frameSize)
//
// has exactly one solution for P. Deriving it (instead of assuming every chunk
// is full) is what makes multipart objects readable: a part boundary can leave a
// short chunk anywhere in the object.
func chunkPlaintextLengths(m contract.Manifest, frameSize int) ([]int64, error) {
	if frameSize <= 0 {
		return nil, fmt.Errorf("%w: invalid frame size %d", ErrManifest, frameSize)
	}
	lengths := make([]int64, len(m.Chunks))
	var total int64
	for i, ref := range m.Chunks {
		if ref.CiphertextLen < 0 {
			return nil, fmt.Errorf("%w: chunk %d negative ciphertext length", ErrManifest, i)
		}
		p, err := plaintextLenFor(ref.CiphertextLen, frameSize)
		if err != nil {
			return nil, fmt.Errorf("%w: chunk %d: %v", ErrManifest, i, err)
		}
		lengths[i] = int64(p)
		total += int64(p)
	}
	if m.Size > 0 && total != m.Size {
		return nil, fmt.Errorf("%w: chunk plaintext lengths sum to %d, manifest says %d", ErrManifest, total, m.Size)
	}
	return lengths, nil
}

// plaintextLenFor inverts the crypto chunk framing equation.
func plaintextLenFor(ciphertextLen, frameSize int) (int, error) {
	const header = 28
	const overhead = 28 // 12-byte nonce + 16-byte GCM tag
	if ciphertextLen == 0 {
		return 0, nil
	}
	if ciphertextLen < header {
		return 0, fmt.Errorf("ciphertext shorter than the chunk header")
	}
	body := ciphertextLen - header
	// frameCount is ceil(P/frameSize); start from the lower bound and probe a
	// couple of candidates to absorb rounding.
	q := body / (frameSize + overhead)
	for _, frames := range []int{q, q + 1, q + 2} {
		if frames < 0 {
			continue
		}
		p := body - overhead*frames
		if p < 0 {
			continue
		}
		if (frames == 0 && p == 0) || (frames > 0 && (frames-1)*frameSize < p && p <= frames*frameSize) {
			if frames == (p+frameSize-1)/frameSize {
				return p, nil
			}
		}
	}
	return 0, fmt.Errorf("ciphertext length %d does not match the frame layout", ciphertextLen)
}

// planChunkRanges maps an object byte range onto chunk slices using per-chunk
// plaintext lengths. A nil range reads everything.
func planChunkRanges(lengths []int64, rng *ByteRange) ([]chunk.ChunkRange, error) {
	if rng == nil {
		out := make([]chunk.ChunkRange, 0, len(lengths))
		for i, l := range lengths {
			out = append(out, chunk.ChunkRange{Index: i, Offset: 0, Length: l})
		}
		return out, nil
	}
	if rng.Start < 0 || rng.Length < 0 {
		return nil, fmt.Errorf("%w: invalid range", ErrManifest)
	}
	if rng.Length == 0 {
		return nil, nil
	}
	end := rng.Start + rng.Length // exclusive
	var out []chunk.ChunkRange
	var offset int64
	for i, l := range lengths {
		chunkStart, chunkEnd := offset, offset+l
		offset = chunkEnd
		if chunkEnd <= rng.Start || chunkStart >= end {
			continue
		}
		lo := max64(rng.Start, chunkStart)
		hi := min64(end, chunkEnd)
		if lo >= hi {
			continue
		}
		out = append(out, chunk.ChunkRange{Index: i, Offset: lo - chunkStart, Length: hi - lo})
		if offset >= end {
			break
		}
	}
	return out, nil
}

// sameObjectVersion reports whether two manifests describe the same immutable
// version, so chunk refs are interchangeable. Checks the object identity (size,
// ETag) and the encryption envelope (a re-encrypted object can share bytes but
// not the file key), plus the chunk geometry at the index being retried.
func sameObjectVersion(a, b contract.Manifest, index int) bool {
	if a.Size != b.Size || a.ETag != b.ETag || a.VersionID != b.VersionID {
		return false
	}
	if len(a.Chunks) != len(b.Chunks) {
		return false
	}
	if len(a.Encryption.WrappedFileKey) != 0 || len(b.Encryption.WrappedFileKey) != 0 {
		if !bytes.Equal(a.Encryption.WrappedFileKey, b.Encryption.WrappedFileKey) {
			return false
		}
	}
	if index < len(a.Chunks) && index < len(b.Chunks) {
		if a.Chunks[index].CiphertextLen != b.Chunks[index].CiphertextLen {
			return false
		}
	}
	return true
}

// sleepCtx waits d or until ctx is done.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// readChunk fetches enough shards for one chunk and reverses coding + encryption.
// aadIndex is the chunk index that was bound in the AAD when the chunk was
// written: the global index for a single PUT, the part-local index for a
// multipart part.
func (o *Offloader) readChunk(ctx context.Context, tenant contract.TenantID, bucketID contract.BucketID, bucket, key, aadVersion string, aadIndex int, codec *ec.Codec, ref contract.ChunkRef, enc *crypto.ChunkEncryptor) ([]byte, error) {
	geom := codec.Geometry(ref.CiphertextLen)
	if geom.CiphertextLen == 0 {
		return []byte{}, nil
	}
	if len(ref.Slots) != geom.TotalShards {
		return nil, fmt.Errorf("%w: chunk %d has %d slots, want %d", ErrManifest, ref.Index, len(ref.Slots), geom.TotalShards)
	}

	// Prefer the authoritative shard-set id stamped at write time. Only objects
	// written before the field existed fall back to the (single-PUT) derivation.
	shardSetID := ref.ShardSetID
	if shardSetID == "" {
		shardSetID = contract.ShardSetIDFor(bucketID, key, contract.VersionID(aadVersion), ref.Index)
	}
	shards := make([][]byte, geom.TotalShards)
	diag := &shardDiag{reasons: map[string]int{}}
	params := ref.Params
	groupSize := params.ShardsPerGroup()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	for g := 0; g < params.GeoN+params.GeoK; g++ {
		group := g
		wg.Add(1)
		go func() {
			defer wg.Done()
			slots := ref.Slots[group*groupSize : (group+1)*groupSize]
			checksums := make([]uint64, groupSize)
			for i := 0; i < groupSize; i++ {
				idx := group*groupSize + i
				if idx < len(ref.Checksums) {
					checksums[i] = ref.Checksums[idx]
				}
			}
			got, ok := o.fetchGroup(ctx, slots, checksums, shardSetID, group, geom.ShardSize, params.LocalN, diag)
			if !ok {
				return
			}
			copy(shards[group*groupSize:], got)
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	groups, ok := codec.CanDecode(shards, geom)
	if !ok {
		diag.logFailure(o, shardSetID, ref, geom, groups, params)
		return nil, fmt.Errorf("%w: chunk %d: %d/%d geo groups reconstructible, need %d",
			ErrMissingShards, ref.Index, groups, params.GeoN+params.GeoK, params.GeoN)
	}
	ciphertext, err := codec.Decode(shards, geom)
	if err != nil {
		return nil, fmt.Errorf("%w: chunk %d: %v", ErrDecode, ref.Index, err)
	}
	aad := crypto.ChunkAAD{
		TenantID:   string(tenant),
		Bucket:     bucket,
		Key:        key,
		VersionID:  aadVersion,
		ChunkIndex: aadIndex,
	}
	plaintext, err := enc.DecryptChunk(ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("offloader: decrypt chunk %d: %w", ref.Index, err)
	}
	if o.metrics != nil {
		o.metrics.Add("fass_gateway_bytes_read_total", nil, uint64(len(plaintext)))
	}
	return plaintext, nil
}

// fetchGroup fetches at least localN shards of one geo group: data shards are
// requested first, then parity shards are hedged in after HedgeAfter (or as soon
// as the data shards finish without quorum). It returns nil,false when the group
// cannot be reconstructed.
func (o *Offloader) fetchGroup(ctx context.Context, slots []contract.Slot, checksums []uint64, shardSetID contract.ShardSetID, group, shardSize, localN int, diag *shardDiag) ([][]byte, bool) {
	out := make([][]byte, len(slots))
	if len(slots) < localN {
		return nil, false
	}
	gctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var mu sync.Mutex
	have := 0
	quorum := make(chan struct{})
	var quorumOnce sync.Once

	var dataWG, parityWG sync.WaitGroup
	launch := func(wg *sync.WaitGroup, idx int) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case o.readSem <- struct{}{}:
				defer func() { <-o.readSem }()
			case <-gctx.Done():
				if diag != nil {
					diag.record(fetchFailure{Reason: "semaphore_drop", Group: group, Index: idx, Endpoint: slots[idx].Endpoint})
				}
				return
			}
			var want uint64
			if idx < len(checksums) {
				want = checksums[idx]
			}
			data, ok := o.getShardBytes(gctx, slots[idx].Endpoint, shardSetID, group, idx, want, shardSize, diag)
			if !ok {
				return
			}
			mu.Lock()
			out[idx] = data
			have++
			reached := have >= localN
			mu.Unlock()
			if reached {
				quorumOnce.Do(func() { close(quorum) })
			}
		}()
	}

	for i := 0; i < localN; i++ {
		launch(&dataWG, i)
	}
	dataFinished := make(chan struct{})
	go func() {
		dataWG.Wait()
		close(dataFinished)
	}()

	select {
	case <-quorum:
		cancel()
		// Every launched goroutine writes into `out`, which readChunk copies as
		// soon as this function returns. Returning before the parity goroutines
		// (launched by a hedge) have stopped let the copy race with their writes:
		// a torn slice element made CanDecode see a phantom missing group while
		// the agents had served every shard. Always join both wait groups.
		dataWG.Wait()
		parityWG.Wait()
		return out, true
	case <-dataFinished:
		// Fall through to parity.
	case <-time.After(o.cfg.HedgeAfter):
		// Data shards are slow: hedge with parity now.
	case <-gctx.Done():
		dataWG.Wait()
		return nil, false
	}

	for i := localN; i < len(slots); i++ {
		launch(&parityWG, i)
	}
	parityFinished := make(chan struct{})
	go func() {
		parityWG.Wait()
		close(parityFinished)
	}()
	select {
	case <-quorum:
		// Quorum reached: cancel the rest, their results are not needed.
		cancel()
	case <-parityFinished:
		// All parity shards have been attempted. Wait for in-flight *data*
		// shards too before deciding: cancelling here used to silently drop data
		// goroutines that were merely queued on the semaphore, turning available
		// shards into a phantom "not enough shards" failure.
	case <-gctx.Done():
	}
	dataWG.Wait()
	parityWG.Wait()
	if ctx.Err() == nil {
		cancel()
	}

	mu.Lock()
	haveNow := have
	mu.Unlock()
	if haveNow < localN {
		return nil, false
	}
	return out, true
}

// getShardBytes fetches and validates one shard. ok=false means missing, short,
// or checksum-mismatched, so the caller can fall back to parity.
func (o *Offloader) getShardBytes(ctx context.Context, endpoint string, shardSetID contract.ShardSetID, group, index int, wantChecksum uint64, shardSize int, diag *shardDiag) ([]byte, bool) {
	reason := ""
	failure := fetchFailure{Group: group, Index: index, Endpoint: endpoint, WantSize: shardSize, WantChecksum: wantChecksum}
	for attempt := 0; attempt <= o.cfg.ShardReadRetries; attempt++ {
		if ctx.Err() != nil {
			reason = "ctx"
			break
		}
		attemptCtx, cancel := context.WithTimeout(ctx, o.cfg.ShardReadTimeout)
		rc, info, err := o.shards.GetShard(attemptCtx, endpoint, shardSetID, group, index)
		if err != nil {
			cancel()
			if ctx.Err() != nil {
				reason = "ctx"
			} else {
				reason = "transport"
				failure.Detail = err.Error()
			}
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(rc, int64(shardSize)+1))
		closeErr := rc.Close()
		cancel()
		if readErr != nil || closeErr != nil {
			reason = "read"
			if readErr != nil {
				failure.Detail = readErr.Error()
			}
			continue
		}
		if len(data) != shardSize {
			reason = "size"
			failure.GotSize = len(data)
			continue
		}
		computed := Checksum64(data)
		failure.GotChecksum = computed
		if wantChecksum != 0 && computed != wantChecksum {
			reason = "checksum"
			if o.metrics != nil {
				o.metrics.Inc("fass_gateway_shard_checksum_mismatch_total", nil)
			}
			continue
		}
		if info.Checksum != 0 && info.Checksum != computed {
			reason = "info_checksum"
			continue
		}
		if o.metrics != nil {
			o.metrics.Inc("fass_gateway_shard_gets_total", map[string]string{"result": "ok"})
		}
		return data, true
	}
	if reason == "" {
		reason = "unknown"
	}
	failure.Reason = reason
	if diag != nil {
		diag.record(failure)
	}
	if o.metrics != nil {
		o.metrics.Inc("fass_gateway_shard_gets_total", map[string]string{"result": "error"})
		o.metrics.Inc("fass_gateway_shard_get_errors_total", map[string]string{"reason": reason})
	}
	return nil, false
}
