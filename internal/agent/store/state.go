package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fass-storage/fass/internal/agent/uid"
)

// stateFormatVersion is bumped when the on-disk layout changes incompatibly.
const stateFormatVersion = 1

// maxDiskIDLen bounds the operator-supplied disk identity. Disk ids are
// UUIDv4 strings in the documented deployment, but an operator may use a
// hardware serial; anything longer is a configuration mistake.
const maxDiskIDLen = 128

// ErrDiskIDMismatch is returned when the caller supplies an authoritative
// --disk-id that differs from the id persisted in state.json. Refusing to start
// is the "same disk mounted to another agent" protection: serving with a
// mismatched identity would claim shards the agent does not own.
var ErrDiskIDMismatch = errors.New("store: disk identity mismatch")

// State is the per-disk identity, docs/04-services.md §6.3 state.json.
//
// The disk id is generated once and never changes: an agent that is restarted
// against a different disk must refuse to serve, otherwise it would silently
// claim to hold shards it does not have.
type State struct {
	FormatVersion int       `json:"format_version"`
	DiskID        string    `json:"disk_id"`
	CreatedAt     time.Time `json:"created_at"`
}

// loadOrCreateState reads state.json or creates it on first boot.
//
// requested is the operator-supplied identity (--disk-id). On a fresh disk it
// becomes authoritative and is persisted; on an existing disk it must match the
// persisted id or the store refuses to open (see ErrDiskIDMismatch).
func loadOrCreateState(path, requested string) (State, error) {
	if err := validateDiskID(requested); err != nil {
		return State{}, err
	}
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		var st State
		if err := json.Unmarshal(b, &st); err != nil {
			return State{}, fmt.Errorf("store: parse %s: %w", path, err)
		}
		if st.FormatVersion != stateFormatVersion {
			return State{}, fmt.Errorf("store: %s has format version %d, this build supports %d",
				path, st.FormatVersion, stateFormatVersion)
		}
		if st.DiskID == "" {
			return State{}, fmt.Errorf("store: %s has no disk_id", path)
		}
		if requested != "" && requested != st.DiskID {
			return State{}, fmt.Errorf("%w: %s already records disk id %q but --disk-id is %q; "+
				"refusing to start (this disk may belong to another agent — remove %s only if you intend to re-identify it)",
				ErrDiskIDMismatch, path, st.DiskID, requested, path)
		}
		return st, nil
	case errors.Is(err, os.ErrNotExist):
		diskID := requested
		if diskID == "" {
			diskID = uid.New()
		}
		st := State{
			FormatVersion: stateFormatVersion,
			DiskID:        diskID,
			CreatedAt:     time.Now().UTC(),
		}
		if err := writeState(path, st); err != nil {
			return State{}, err
		}
		return st, nil
	default:
		return State{}, fmt.Errorf("store: read %s: %w", path, err)
	}
}

// validateDiskID checks an operator-supplied disk identity: empty means "no
// explicit identity" (generate one), otherwise it must be a short, opaque,
// whitespace-free string. The documented production form is a UUIDv4, but the
// store does not enforce that so hardware serials remain usable.
func validateDiskID(id string) error {
	if id == "" {
		return nil
	}
	if id != strings.TrimSpace(id) {
		return fmt.Errorf("%w: disk id %q has leading or trailing whitespace", ErrBadRequest, id)
	}
	if len(id) > maxDiskIDLen {
		return fmt.Errorf("%w: disk id is %d bytes, maximum is %d", ErrBadRequest, len(id), maxDiskIDLen)
	}
	for _, r := range id {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: disk id contains a control character", ErrBadRequest)
		}
	}
	return nil
}

// writeState atomically writes state.json.
func writeState(path string, st State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("store: create state dir: %w", err)
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("store: marshal state: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return fmt.Errorf("store: write state: %w", err)
	}
	f, err := os.OpenFile(tmp, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("store: open state for fsync: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("store: fsync state: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("store: close state: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("store: rename state: %w", err)
	}
	return fsyncDir(filepath.Dir(path))
}
