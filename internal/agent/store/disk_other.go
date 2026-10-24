//go:build !linux

package store

// diskCapacity is a conservative fallback for non-Linux development hosts: it
// cannot inspect the filesystem, so it disables the capacity admission check
// instead of guessing wrong. Production targets are Linux (docs/02 §7).
func diskCapacity(path string) (total, free int64, err error) {
	return 0, 1 << 62, nil
}
