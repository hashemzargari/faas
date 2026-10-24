package contract

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// ShardSetIDFor derives the shard-set id for one chunk deterministically from
// its object identity:
//
//	uuid(SHA-256("fass/shardset/v1" ‖ bucket_id ‖ 0 ‖ key ‖ 0 ‖ version_id ‖ 0 ‖ BE64(chunk_index)))
//
// Why derive rather than store: agents address shards by
// (shard_set_id, geo_group, local_index), and three separate parties must agree
// on that id — the gateway when it writes, the coordinator's GC when it
// deletes, and the repair orchestrator when it reconstructs. Deriving it from
// the object identity means it never has to appear in ChunkRef at all, and it
// cannot disagree. The domain-separated, versioned prefix lets the algorithm
// change later without colliding with ids derived by older code.
//
// This lives in the contract package (not the gateway) because the dependency
// direction must be coordinator → contract, never coordinator → gateway.
func ShardSetIDFor(bucketID BucketID, key string, versionID VersionID, chunkIndex int) ShardSetID {
	return ShardSetIDForScoped(bucketID, key, versionID, "", chunkIndex)
}

// ShardSetIDForScoped is ShardSetIDFor with a scope discriminator.
//
// scope MUST be empty for a normal single-PUT object, and MUST be unique per
// multipart part (use "part/<n>"). Without it, every part restarts chunk
// indices at zero and part 2 derives the same shard-set id as part 1, so its
// shards collide with part 1's immutable shards and the write fails with 409 —
// which is exactly the bug that broke every aws-cli upload over the multipart
// threshold. The empty scope keeps the historical derivation byte-identical,
// so objects written before this field existed still resolve.
func ShardSetIDForScoped(bucketID BucketID, key string, versionID VersionID, scope string, chunkIndex int) ShardSetID {
	h := sha256.New()
	h.Write([]byte("fass/shardset/v1\x00"))
	if scope != "" {
		h.Write([]byte(scope))
		h.Write([]byte{0})
	}
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
	return ShardSetID(formatUUIDv4(b))
}

// NewUUID returns a random UUIDv4 string, used for version ids and upload ids.
func NewUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A failing CSPRNG is unrecoverable; return a value the coordinator will
		// reject as a duplicate rather than silently reusing an identity.
		return "00000000-0000-4000-8000-000000000000"
	}
	return formatUUIDv4(b)
}

// formatUUIDv4 renders 16 bytes as a canonical UUID string with the version and
// variant bits set.
func formatUUIDv4(b [16]byte) string {
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
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
