package offloader

import (
	"fmt"
	"sync"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/ec"
)

// fetchFailure is one rejected shard, with enough detail to tell "the shard was
// missing" apart from "the shard arrived but we refused it".
type fetchFailure struct {
	Reason       string // transport|status|read|size|checksum|info_checksum|ctx|semaphore_drop
	Group        int
	Index        int
	Endpoint     string
	WantSize     int
	GotSize      int
	WantChecksum uint64
	GotChecksum  uint64
	Detail       string
}

// shardDiag aggregates per-shard failures for one chunk read. It exists so a
// chunk that ends up unreconstructible produces one attributable ERROR line
// instead of an opaque "not enough shards" (the counters previously could not
// distinguish missing shards from rejected bytes).
type shardDiag struct {
	mu      sync.Mutex
	reasons map[string]int
	samples []fetchFailure
}

func (d *shardDiag) record(f fetchFailure) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.reasons[f.Reason]++
	if len(d.samples) < 12 {
		d.samples = append(d.samples, f)
	}
}

func (d *shardDiag) logFailure(o *Offloader, shardSetID contract.ShardSetID, ref contract.ChunkRef, geom ec.Geometry, groups int, params ec.Params) {
	if d == nil {
		return
	}
	d.mu.Lock()
	reasons := make(map[string]int, len(d.reasons))
	for k, v := range d.reasons {
		reasons[k] = v
	}
	samples := append([]fetchFailure(nil), d.samples...)
	d.mu.Unlock()

	if o.metrics != nil {
		o.metrics.Inc("fass_gateway_chunk_unreconstructible_total", nil)
	}
	o.log.Error("shard chunk unreconstructible",
		"shard_set_id", string(shardSetID), "chunk", ref.Index,
		"groups_reconstructible", groups, "geo_n", params.GeoN, "geo_k", params.GeoK,
		"ciphertext_len", ref.CiphertextLen, "expected_shard_size", geom.ShardSize,
		"slots", len(ref.Slots), "checksums", len(ref.Checksums), "reasons", fmt.Sprint(reasons))
	for _, f := range samples {
		o.log.Error("shard fetch failure detail",
			"shard_set_id", string(shardSetID), "chunk", ref.Index,
			"group", f.Group, "index", f.Index, "endpoint", f.Endpoint, "reason", f.Reason,
			"expected_size", f.WantSize, "actual_size", f.GotSize,
			"expected_checksum", fmt.Sprintf("%016x", f.WantChecksum), "actual_checksum", fmt.Sprintf("%016x", f.GotChecksum),
			"detail", f.Detail)
	}
}
