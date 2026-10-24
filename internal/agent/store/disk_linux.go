//go:build linux

package store

import "syscall"

// diskCapacity reports total and available bytes of the filesystem holding
// path using statfs(2). Bavail (available to unprivileged users) is used rather
// than Bfree so the 5% root reserve of the filesystem itself is respected.
func diskCapacity(path string) (total, free int64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	bsize := int64(st.Bsize)
	if bsize <= 0 {
		bsize = 4096
	}
	total = int64(st.Blocks) * bsize
	free = int64(st.Bavail) * bsize
	return total, free, nil
}
