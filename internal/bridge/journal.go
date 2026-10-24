package bridge

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// journalState is the durable shape of one bridge. It contains credentials
// (mode 0600) because a restart must resume without asking the operator for them
// again; DELETE removes the file, never the data.
type journalState struct {
	ID        string           `json:"bridge_id"`
	CreatedAt time.Time        `json:"created_at"`
	Source    Endpoint         `json:"source"`
	Target    Endpoint         `json:"target"`
	Status    string           `json:"status"`
	Error     string           `json:"error,omitempty"`
	Buckets   []*journalBucket `json:"buckets"`
}

type journalBucket struct {
	Name              string            `json:"name"`
	Migrated          int64             `json:"migrated"`
	Failed            int64             `json:"failed"`
	Skipped           int64             `json:"skipped"`
	Bytes             int64             `json:"bytes"`
	Done              map[string]string `json:"done"`
	ContinuationToken string            `json:"continuation_token,omitempty"`
	Completed         bool              `json:"completed"`
}

func (b *journalBucket) objectsTotal() int64 { return b.Migrated + b.Failed + b.Skipped }

func journalPath(dir, id string) string { return filepath.Join(dir, id+".json") }

// saveJournal writes atomically (temp file + rename) with mode 0600 so a crash
// mid-write cannot leave a half-parsed journal.
func saveJournal(path string, st *journalState) error {
	body, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("bridge: marshal journal: %w", err)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".bridge-*.tmp")
	if err != nil {
		return fmt.Errorf("bridge: create journal temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return fmt.Errorf("bridge: write journal: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("bridge: commit journal: %w", err)
	}
	return nil
}

func loadJournal(path string) (*journalState, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var st journalState
	if err := json.Unmarshal(body, &st); err != nil {
		return nil, fmt.Errorf("bridge: parse journal %s: %w", path, err)
	}
	if st.ID == "" {
		return nil, errors.New("bridge: journal has no bridge id")
	}
	for _, b := range st.Buckets {
		if b.Done == nil {
			b.Done = map[string]string{}
		}
	}
	return &st, nil
}

func loadJournals(dir string) ([]*journalState, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("bridge: read data dir: %w", err)
	}
	var out []*journalState
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		st, err := loadJournal(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		if st.Status == StatusInProgress {
			// The previous process died mid-run. Mark it ready so an explicit
			// /start resumes from the persisted journal rather than looking stuck.
			st.Status = StatusReady
		}
		out = append(out, st)
	}
	return out, nil
}
