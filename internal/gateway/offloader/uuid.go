package offloader

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"

	"github.com/fass-storage/fass/internal/contract"
)

// newUUID returns a random UUIDv4 string.
func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is fatal for the process; a request path must not
		// panic, so fall back to a deterministic-but-unique-per-call value is
		// impossible. Return an all-zero UUID: the coordinator will reject the
		// duplicate rather than silently corrupt metadata.
		return "00000000-0000-4000-8000-000000000000"
	}
	return formatUUID(b)
}

func formatUUID(b [16]byte) string {
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	var out [36]byte
	hex.Encode(out[0:8], b[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], b[10:16])
	return string(out[:])
}

// ShardSetIDFor derives the shard-set id for one chunk deterministically from
// its object identity:
//
//	uuid(SHA-256("fass/shardset/v1" ‖ bucket_id ‖ \\0 ‖ key ‖ \\0 ‖ version_id ‖ \\0 ‖ chunk_index))
//
// The contract's ChunkRef does not carry a shard-set id, but agents address
// shards by (shard_set_id, geo_group, local_index) and repair must recompute the
// same set. Deriving it removes that field from the commit path while keeping
// every party (gateway, coordinator repair, agents) in agreement. The
// derivation is versioned so it can change compatibly later.
func ShardSetIDFor(bucketID contract.BucketID, key string, versionID contract.VersionID, chunkIndex int) contract.ShardSetID {
	h := sha256.New()
	h.Write([]byte("fass/shardset/v1\x00"))
	h.Write([]byte(bucketID))
	h.Write([]byte{0})
	h.Write([]byte(key))
	h.Write([]byte{0})
	h.Write([]byte(versionID))
	h.Write([]byte{0})
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], uint64(chunkIndex))
	h.Write(idx[:])
	var b [16]byte
	copy(b[:], h.Sum(nil)[:16])
	return contract.ShardSetID(formatUUID(b))
}
