package offloader

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
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

	aadVersion := string(m.VersionID)
	// Multipart parts are written before the final version id exists; the mode
	// prefix marks that they bound an empty AAD version instead.
	if strings.HasPrefix(m.Encryption.Mode, MultipartModePrefix) {
		aadVersion = ""
	}

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

	chunkSize := m.ChunkSize
	if chunkSize <= 0 {
		chunkSize = o.cfg.ChunkSize
	}
	needed, err := chunkRanges(m, chunkSize, req.Range)
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
		plaintext, err := o.readChunk(ctx, tenant, m.BucketID, req.Bucket, req.Key, aadVersion, codec, ref, enc)
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

// chunkRanges maps the requested range onto chunk slices. A nil range means the
// whole object.
func chunkRanges(m contract.Manifest, chunkSize int, rng *ByteRange) ([]chunk.ChunkRange, error) {
	if rng == nil {
		out := make([]chunk.ChunkRange, 0, len(m.Chunks))
		for i := range m.Chunks {
			start := int64(i) * int64(chunkSize)
			length := int64(chunkSize)
			if remaining := m.Size - start; remaining < length {
				length = remaining
			}
			if length <= 0 {
				break
			}
			out = append(out, chunk.ChunkRange{Index: i, Offset: 0, Length: length})
		}
		return out, nil
	}
	if rng.Length <= 0 || rng.Start < 0 {
		return nil, nil
	}
	end := rng.Start + rng.Length - 1
	return chunk.MapRange(m.Size, int64(chunkSize), rng.Start, end)
}

// readChunk fetches enough shards for one chunk and reverses coding + encryption.
func (o *Offloader) readChunk(ctx context.Context, tenant contract.TenantID, bucketID contract.BucketID, bucket, key, aadVersion string, codec *ec.Codec, ref contract.ChunkRef, enc *crypto.ChunkEncryptor) ([]byte, error) {
	geom := codec.Geometry(ref.CiphertextLen)
	if geom.CiphertextLen == 0 {
		return []byte{}, nil
	}
	if len(ref.Slots) != geom.TotalShards {
		return nil, fmt.Errorf("%w: chunk %d has %d slots, want %d", ErrManifest, ref.Index, len(ref.Slots), geom.TotalShards)
	}

	// Shard set ids are derived from the object version; multipart parts used an
	// empty version at write time, which aadVersion reflects.
	shardSetID := contract.ShardSetIDFor(bucketID, key, contract.VersionID(aadVersion), ref.Index)
	shards := make([][]byte, geom.TotalShards)
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
			got, ok := o.fetchGroup(ctx, slots, checksums, shardSetID, group, geom.ShardSize, params.LocalN)
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
		ChunkIndex: ref.Index,
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
func (o *Offloader) fetchGroup(ctx context.Context, slots []contract.Slot, checksums []uint64, shardSetID contract.ShardSetID, group, shardSize, localN int) ([][]byte, bool) {
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
				return
			}
			var want uint64
			if idx < len(checksums) {
				want = checksums[idx]
			}
			data, ok := o.getShardBytes(gctx, slots[idx].Endpoint, shardSetID, group, idx, want, shardSize)
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
		dataWG.Wait()
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
	case <-parityFinished:
	case <-gctx.Done():
	}
	cancel()
	dataWG.Wait()
	parityWG.Wait()

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
func (o *Offloader) getShardBytes(ctx context.Context, endpoint string, shardSetID contract.ShardSetID, group, index int, wantChecksum uint64, shardSize int) ([]byte, bool) {
	for attempt := 0; attempt <= o.cfg.ShardReadRetries; attempt++ {
		if ctx.Err() != nil {
			return nil, false
		}
		attemptCtx, cancel := context.WithTimeout(ctx, o.cfg.ShardReadTimeout)
		rc, info, err := o.shards.GetShard(attemptCtx, endpoint, shardSetID, group, index)
		if err != nil {
			cancel()
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(rc, int64(shardSize)+1))
		closeErr := rc.Close()
		cancel()
		if readErr != nil || closeErr != nil || len(data) != shardSize {
			continue
		}
		computed := Checksum64(data)
		if wantChecksum != 0 && computed != wantChecksum {
			if o.metrics != nil {
				o.metrics.Inc("fass_gateway_shard_checksum_mismatch_total", nil)
			}
			continue
		}
		if info.Checksum != 0 && info.Checksum != computed {
			continue
		}
		if o.metrics != nil {
			o.metrics.Inc("fass_gateway_shard_gets_total", map[string]string{"result": "ok"})
		}
		return data, true
	}
	if o.metrics != nil {
		o.metrics.Inc("fass_gateway_shard_gets_total", map[string]string{"result": "error"})
	}
	return nil, false
}
