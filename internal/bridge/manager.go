package bridge

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"
)

// Manager owns all bridges in one process, backed by one JSON journal per
// bridge in Options.DataDir.
type Manager struct {
	opts    Options
	mu      sync.Mutex
	bridges map[string]*bridge
	closed  bool
}

type bridge struct {
	mu      sync.Mutex
	st      *journalState
	path    string
	opts    Options
	cancel  context.CancelFunc
	running bool
	done    chan struct{} // closed when the current run goroutine exits
}

// NewManager loads persisted bridges and applies defaults.
func NewManager(opts Options) (*Manager, error) {
	if opts.DataDir == "" {
		return nil, errors.New("bridge: data dir is required")
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 4
	}
	if opts.MultipartThreshold <= 0 {
		opts.MultipartThreshold = 8 << 20
	}
	if opts.PartSize <= 0 {
		opts.PartSize = 8 << 20
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if err := os.MkdirAll(opts.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("bridge: create data dir: %w", err)
	}
	m := &Manager{opts: opts, bridges: map[string]*bridge{}}
	states, err := loadJournals(opts.DataDir)
	if err != nil {
		return nil, err
	}
	for _, st := range states {
		m.bridges[st.ID] = &bridge{st: st, path: journalPath(opts.DataDir, st.ID), opts: opts}
	}
	return m, nil
}

// Close cancels running migrations and waits for their goroutines.
func (m *Manager) Close() {
	m.mu.Lock()
	m.closed = true
	bridges := make([]*bridge, 0, len(m.bridges))
	for _, b := range m.bridges {
		bridges = append(bridges, b)
	}
	m.mu.Unlock()
	for _, b := range bridges {
		b.mu.Lock()
		cancel, done := b.cancel, b.done
		b.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		if done != nil {
			<-done
		}
	}
}

// Create validates the request, creates the destination buckets ("no copy yet"
// per docs/04 §10), persists a ready journal and returns its status.
func (m *Manager) Create(ctx context.Context, req CreateRequest) (Status, error) {
	if err := req.Source.validate("source"); err != nil {
		return Status{}, err
	}
	if err := req.Target.validate("target"); err != nil {
		return Status{}, err
	}
	now := m.opts.Now
	src, err := newS3Client(req.Source, m.opts.HTTPClient, nil, now, m.opts.Log)
	if err != nil {
		return Status{}, err
	}
	tgt, err := newS3Client(req.Target, m.opts.HTTPClient, nil, now, m.opts.Log)
	if err != nil {
		return Status{}, err
	}
	buckets := append([]string(nil), req.Buckets...)
	if req.All {
		sourceBuckets, err := src.listBuckets(ctx)
		if err != nil {
			return Status{}, fmt.Errorf("bridge: list source buckets: %w", err)
		}
		buckets = append(buckets, sourceBuckets...)
	}
	buckets = dedupeBuckets(buckets)
	if len(buckets) == 0 {
		return Status{}, errors.New("bridge: provide buckets or all=true")
	}
	for _, name := range buckets {
		if err := tgt.createBucket(ctx, name); err != nil {
			return Status{}, fmt.Errorf("bridge: create target bucket %q: %w", name, err)
		}
	}

	st := &journalState{
		ID:        newBridgeID(),
		CreatedAt: m.opts.Now().UTC(),
		Source:    req.Source,
		Target:    req.Target,
		Status:    StatusReady,
		Buckets:   make([]*journalBucket, 0, len(buckets)),
	}
	for _, name := range buckets {
		st.Buckets = append(st.Buckets, &journalBucket{Name: name, Done: map[string]string{}})
	}
	path := journalPath(m.opts.DataDir, st.ID)
	if err := saveJournal(path, st); err != nil {
		return Status{}, err
	}
	b := &bridge{st: st, path: path, opts: m.opts}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return Status{}, errors.New("bridge: manager is shutting down")
	}
	m.bridges[st.ID] = b
	return statusOf(st), nil
}

// Start begins (or resumes) a migration. It is idempotent: a running or
// completed bridge is a no-op.
func (m *Manager) Start(id string) error {
	m.mu.Lock()
	b := m.bridges[id]
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return errors.New("bridge: manager is shutting down")
	}
	if b == nil {
		return fmt.Errorf("bridge: unknown bridge %q", id)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.running || b.st.Status == StatusCompleted {
		return nil
	}
	b.st.Status = StatusInProgress
	b.st.Error = ""
	if err := saveJournal(b.path, b.st); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	b.cancel = cancel
	b.running = true
	b.done = make(chan struct{})
	done := b.done
	opts := b.opts
	go func() {
		defer close(done)
		err := b.migrate(ctx, opts)
		b.mu.Lock()
		defer b.mu.Unlock()
		b.running = false
		b.cancel = nil
		switch {
		case err != nil && errors.Is(err, context.Canceled):
			// Interrupted (shutdown/delete): keep it resumable rather than
			// pretending the migration finished.
			b.st.Status = StatusReady
		case err != nil:
			b.st.Status = StatusCompleted
			b.st.Error = err.Error()
			opts.Log.Error("bridge migration stopped with an error", "bridge_id", b.st.ID, "error", err)
		default:
			b.st.Status = StatusCompleted
		}
		if saveErr := saveJournal(b.path, b.st); saveErr != nil {
			opts.Log.Error("bridge: persist final state", "bridge_id", b.st.ID, "error", saveErr)
		}
	}()
	return nil
}

// Status returns a snapshot of a bridge.
func (m *Manager) Status(id string) (Status, error) {
	m.mu.Lock()
	b := m.bridges[id]
	m.mu.Unlock()
	if b == nil {
		return Status{}, fmt.Errorf("bridge: unknown bridge %q", id)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return statusOf(b.st), nil
}

// Delete stops tracking a bridge and removes its journal. It never deletes data
// on either side (docs/04 §10).
func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	b := m.bridges[id]
	delete(m.bridges, id)
	m.mu.Unlock()
	if b == nil {
		return fmt.Errorf("bridge: unknown bridge %q", id)
	}
	b.mu.Lock()
	cancel, done := b.cancel, b.done
	b.cancel, b.done = nil, nil
	b.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	if err := os.Remove(b.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("bridge: remove journal: %w", err)
	}
	return nil
}

func statusOf(st *journalState) Status {
	out := Status{BridgeID: st.ID, Status: st.Status, CreatedAt: st.CreatedAt, Error: st.Error}
	for _, b := range st.Buckets {
		out.Buckets = append(out.Buckets, BucketStatus{
			Name:         b.Name,
			ObjectsTotal: b.objectsTotal(),
			Migrated:     b.Migrated,
			Failed:       b.Failed,
			Skipped:      b.Skipped,
			Bytes:        b.Bytes,
			Completed:    b.Completed,
		})
	}
	return out
}

func dedupeBuckets(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, name := range in {
		name = trimBucket(name)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

func trimBucket(name string) string {
	for len(name) > 0 && (name[0] == ' ' || name[0] == '\t') {
		name = name[1:]
	}
	for len(name) > 0 && (name[len(name)-1] == ' ' || name[len(name)-1] == '\t') {
		name = name[:len(name)-1]
	}
	return name
}

func newBridgeID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("br-%d", time.Now().UnixNano())
	}
	return "br-" + hex.EncodeToString(b[:])
}

// HTTPClient with no overall timeout: object transfers are long-lived and every
// request carries its own context.
var _ = http.Client{}
