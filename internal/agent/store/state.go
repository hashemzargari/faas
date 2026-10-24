package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fass-storage/fass/internal/agent/uid"
)

// stateFormatVersion is bumped when the on-disk layout changes incompatibly.
const stateFormatVersion = 1

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
func loadOrCreateState(path string) (State, error) {
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
		return st, nil
	case errors.Is(err, os.ErrNotExist):
		st := State{
			FormatVersion: stateFormatVersion,
			DiskID:        uid.New(),
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
