package recovery

import (
	"context"
	"fmt"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/coord/meta"
)

// MetaSource builds the shard-set inventory from committed manifests. It runs in
// the background refresher, never on the HTTP path; scanning manifests is the
// only way to know which agents hold which shards, and it is acceptable at the
// refresher's cadence (60 s by default) for the same reason the recovery
// orchestrator itself must do it.
type MetaSource struct {
	Meta *meta.Service
}

// NewMetaSource returns a source over the coordinator metadata service.
func NewMetaSource(m *meta.Service) *MetaSource { return &MetaSource{Meta: m} }

// ShardSets walks every live object version and returns one state per shard set.
func (src *MetaSource) ShardSets(ctx context.Context) ([]ShardSetState, error) {
	if src == nil || src.Meta == nil {
		return nil, fmt.Errorf("recovery: meta source is not configured")
	}
	buckets, err := src.Meta.ListBuckets(ctx, contract.Principal{IsRoot: true})
	if err != nil {
		return nil, fmt.Errorf("recovery: list buckets: %w", err)
	}
	seen := make(map[contract.ShardSetID]*ShardSetState)
	for _, b := range buckets {
		versions, err := src.Meta.ListVersions(ctx, b.BucketID)
		if err != nil {
			return nil, fmt.Errorf("recovery: list versions in %s: %w", b.Name, err)
		}
		for _, v := range versions {
			if v.IsDeleteMarker {
				continue
			}
			manifest, err := src.Meta.GetManifest(ctx, b.Name, v.Key, v.VersionID)
			if err != nil {
				// A racing delete between ListVersions and GetManifest is normal.
				continue
			}
			for _, ref := range manifest.Chunks {
				id := ref.ShardSetID
				if id == "" {
					id = contract.ShardSetIDFor(manifest.BucketID, manifest.Key, manifest.VersionID, ref.Index)
				}
				st, ok := seen[id]
				if !ok {
					st = &ShardSetState{ID: id, Params: ref.Params, Groups: make(map[int][]contract.AgentID)}
					seen[id] = st
				}
				for _, slot := range ref.Slots {
					st.Groups[slot.GeoGroup] = append(st.Groups[slot.GeoGroup], slot.AgentID)
				}
			}
		}
	}
	out := make([]ShardSetState, 0, len(seen))
	for _, st := range seen {
		out = append(out, *st)
	}
	return out, nil
}
