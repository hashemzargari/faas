package s3

import (
	"encoding/base64"
	"fmt"

	"github.com/fass-storage/fass/internal/gateway/offloader"
)

// decodeChecksum decodes a base64 checksum header and validates its length for
// the announced algorithm.
func decodeChecksum(raw string, alg offloader.ChecksumAlgorithm) ([]byte, error) {
	value, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("base64: %w", err)
	}
	want := 0
	switch alg {
	case offloader.ChecksumMD5:
		want = 16
	case offloader.ChecksumSHA1:
		want = 20
	case offloader.ChecksumSHA256:
		want = 32
	case offloader.ChecksumCRC32, offloader.ChecksumCRC32C:
		want = 4
	case offloader.ChecksumCRC64NVME:
		want = 8
	default:
		return nil, fmt.Errorf("unknown checksum algorithm %q", alg)
	}
	if len(value) != want {
		return nil, fmt.Errorf("checksum is %d bytes, want %d", len(value), want)
	}
	return value, nil
}
