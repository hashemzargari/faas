package offloader

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
)

// Checksum64 is the shard checksum used throughout FASS: the first 8 bytes of
// SHA-256, big-endian, as a uint64.
//
// This is the ruling in docs/03 §2.3 (decided 2026-10-24): the Go standard
// library has no BLAKE2b, so the truncated SHA-256 is used by the gateway, the
// coordinator and the agents alike, keeping the wire header, the JSON payload
// and ChunkRef.Checksums consistent without an extra dependency.
func Checksum64(b []byte) uint64 {
	sum := sha256.Sum256(b)
	return binary.BigEndian.Uint64(sum[:8])
}

// digestSet accumulates the checksums a client declared for a payload and the
// object ETag's MD5.
type digestSet struct {
	hashers map[ChecksumAlgorithm]hash.Hash
	md5     hash.Hash
}

// newDigestSet creates a set that computes every supported checksum.
//
// All algorithms are computed unconditionally because aws-chunked trailer
// checksums are only materialised after the body has been consumed: registering
// hashers lazily from the header checksums would make a trailer-only checksum
// unverifiable.
func newDigestSet(_ []ExpectedChecksum) *digestSet {
	md5Hasher := md5.New()
	return &digestSet{
		md5: md5Hasher,
		hashers: map[ChecksumAlgorithm]hash.Hash{
			// MD5 doubles as the ETag hasher.
			ChecksumMD5:    md5Hasher,
			ChecksumSHA1:   sha1.New(),
			ChecksumSHA256: sha256.New(),
			ChecksumCRC32:  crc32.NewIEEE(),
			ChecksumCRC32C: crc32.New(crc32.MakeTable(crc32.Castagnoli)),
		},
	}
}

func (d *digestSet) Update(p []byte) {
	d.md5.Write(p)
	for alg, h := range d.hashers {
		if alg == ChecksumMD5 {
			continue
		}
		h.Write(p)
	}
}

// Verify compares accumulated digests against every expected checksum.
func (d *digestSet) Verify(expected []ExpectedChecksum) error {
	for _, e := range expected {
		var got []byte
		switch e.Algorithm {
		case ChecksumMD5:
			got = d.md5.Sum(nil)
		default:
			h, ok := d.hashers[e.Algorithm]
			if !ok {
				if e.Algorithm == ChecksumCRC64NVME {
					return fmt.Errorf("%w: CRC64NVME checksums are not supported", ErrNotImplemented)
				}
				return fmt.Errorf("%w: unsupported checksum algorithm %q", ErrBadDigest, e.Algorithm)
			}
			got = h.Sum(nil)
		}
		if !equalBytes(got, e.Value) {
			return fmt.Errorf("%w: %s mismatch", ErrBadDigest, e.Algorithm)
		}
	}
	return nil
}

// ETag returns the MD5 hex digest of the payload (the S3 single-part ETag).
func (d *digestSet) ETag() string { return fmt.Sprintf("%x", d.md5.Sum(nil)) }

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// errChecksumMismatch is returned by the read path when a fetched shard does not
// match its manifest checksum; it is retried against another shard.
var errChecksumMismatch = errors.New("offloader: shard checksum mismatch")
