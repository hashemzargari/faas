package coordclient_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/fass-storage/fass/internal/agent/coordclient"
	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/ec"
)

type recorder struct {
	mu       sync.Mutex
	requests map[string][]byte
	statuses []int
}

func newRecorder() *recorder {
	return &recorder{requests: make(map[string][]byte)}
}

func (r *recorder) record(path string, body []byte) {
	r.mu.Lock()
	r.requests[path] = append([]byte(nil), body...)
	r.mu.Unlock()
}

func (r *recorder) body(t *testing.T, path string) []byte {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.requests[path]
}

// fakeCoordinator mirrors the coordinator's docs/07 §1.6 handler shapes.
func fakeCoordinator(t *testing.T, rec *recorder, job *contract.RepairJob, commitStatus int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/agents/announce", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec.record(r.URL.Path, body)
		var req contract.AnnounceRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("announce body is not contract.AnnounceRequest: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(contract.AnnounceResult{
			AgentID: "agent-1", NexusID: "nexus-1", State: "pending",
			RingIDs: []contract.RingID{"ring-1"},
		})
	})
	mux.HandleFunc("POST /v1/agents/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec.record(r.URL.Path, body)
		var hb contract.Heartbeat
		if err := json.Unmarshal(body, &hb); err != nil {
			t.Errorf("heartbeat body is not contract.Heartbeat: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/agents/shard-status", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec.record(r.URL.Path, body)
		var req struct {
			Items []contract.ShardStatus `json:"items"`
		}
		if err := json.Unmarshal(body, &req); err != nil || len(req.Items) == 0 {
			t.Errorf("bad shard-status body: %v (%s)", err, body)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/repair/claim", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec.record(r.URL.Path, body)
		if job == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(job)
	})
	mux.HandleFunc("POST /v1/repair/commit", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec.record(r.URL.Path, body)
		if commitStatus != 0 {
			w.WriteHeader(commitStatus)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestAnnounceHeartbeatShardStatus(t *testing.T) {
	rec := newRecorder()
	srv := fakeCoordinator(t, rec, nil, 0)
	c, err := coordclient.New(srv.URL, coordclient.Options{Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}

	res, err := c.Announce(context.Background(), contract.AnnounceRequest{
		PublicKey: []byte{1, 2, 3}, Secret: "s3cret",
		NodeID: "node-1", DiskID: "disk-1", Port: 7100,
		CapacityBytes: 1 << 40, Version: "test", Hostname: "host-1",
	})
	if err != nil {
		t.Fatalf("Announce: %v", err)
	}
	if res.AgentID != "agent-1" || res.NexusID != "nexus-1" || res.State != "pending" {
		t.Fatalf("announce result = %+v", res)
	}
	// PublicKey must be base64 on the wire, not a JSON array of numbers.
	if body := rec.body(t, "/v1/agents/announce"); !bytes.Contains(body, []byte(`"public_key":"AQID"`)) {
		t.Fatalf("announce body = %s", body)
	}

	if err := c.Heartbeat(context.Background(), contract.Heartbeat{
		AgentID: "agent-1", FreeBytes: 10, UsedBytes: 20, ShardCount: 3,
	}); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if body := rec.body(t, "/v1/agents/heartbeat"); !bytes.Contains(body, []byte(`"agent_id":"agent-1"`)) {
		t.Fatalf("heartbeat body = %s", body)
	}

	if err := c.ReportShardStatus(context.Background(), []contract.ShardStatus{
		{AgentID: "agent-1", ShardSetID: "set-1", Slot: 5, State: "CORRUPT"},
	}); err != nil {
		t.Fatalf("ReportShardStatus: %v", err)
	}
	if body := rec.body(t, "/v1/agents/shard-status"); !bytes.Contains(body, []byte(`"items":[`)) ||
		!bytes.Contains(body, []byte(`"shard_set_id":"set-1"`)) {
		t.Fatalf("shard-status body = %s", body)
	}
}

func TestClaimRepairJobAndCommit(t *testing.T) {
	job := &contract.RepairJob{
		JobID:      "job-1",
		Type:       "local",
		ShardSetID: "set-1",
		ChunkIndex: 2,
		Generation: 4,
		Params:     ec.Params{GeoN: 2, GeoK: 1, LocalN: 16, LocalK: 4},
		Sources: []contract.Slot{
			{GeoGroup: 0, LocalIndex: 1, AgentID: "a1", Endpoint: "10.0.0.1:7100"},
		},
		Targets: []contract.Slot{
			{GeoGroup: 0, LocalIndex: 0, AgentID: "a2", Endpoint: "10.0.0.2:7100"},
		},
		MaxMbps: 200,
	}
	rec := newRecorder()
	srv := fakeCoordinator(t, rec, job, 0)
	c, err := coordclient.New(srv.URL, coordclient.Options{Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}

	got, err := c.ClaimRepairJob(context.Background(), "agent-7")
	if err != nil {
		t.Fatalf("ClaimRepairJob: %v", err)
	}
	if got == nil {
		t.Fatal("ClaimRepairJob returned nil job")
	}
	if got.JobID != "job-1" || got.Params != job.Params || got.Generation != 4 ||
		len(got.Sources) != 1 || got.Sources[0].Endpoint != "10.0.0.1:7100" ||
		len(got.Targets) != 1 || got.MaxMbps != 200 {
		t.Fatalf("decoded job = %+v", got)
	}
	if body := rec.body(t, "/v1/repair/claim"); !bytes.Contains(body, []byte(`"worker":"agent-7"`)) {
		t.Fatalf("claim body = %s", body)
	}

	err = c.CommitRepair(context.Background(), contract.RepairResult{
		JobID: "job-1", ShardSetID: "set-1", Generation: 4, OK: true,
		Checksums: []uint64{1, 2},
	})
	if err != nil {
		t.Fatalf("CommitRepair: %v", err)
	}
	if body := rec.body(t, "/v1/repair/commit"); !bytes.Contains(body, []byte(`"job_id":"job-1"`)) ||
		!bytes.Contains(body, []byte(`"ok":true`)) {
		t.Fatalf("commit body = %s", body)
	}
}

func TestClaimRepairJobNoWork(t *testing.T) {
	rec := newRecorder()
	srv := fakeCoordinator(t, rec, nil, 0)
	c, err := coordclient.New(srv.URL, coordclient.Options{Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	job, err := c.ClaimRepairJob(context.Background(), "agent-7")
	if err != nil {
		t.Fatalf("ClaimRepairJob: %v", err)
	}
	if job != nil {
		t.Fatalf("job = %+v, want nil", job)
	}
}

func TestCommitRepairConflictIsCASLoss(t *testing.T) {
	rec := newRecorder()
	srv := fakeCoordinator(t, rec, nil, http.StatusConflict)
	c, err := coordclient.New(srv.URL, coordclient.Options{Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	err = c.CommitRepair(context.Background(), contract.RepairResult{JobID: "job-1"})
	if !errors.Is(err, contract.ErrConflict) {
		t.Fatalf("CommitRepair err = %v, want contract.ErrConflict", err)
	}
}

func TestCoordinatorURLAcceptsHostPort(t *testing.T) {
	rec := newRecorder()
	srv := fakeCoordinator(t, rec, nil, 0)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c, err := coordclient.New(u.Host, coordclient.Options{Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Heartbeat(context.Background(), contract.Heartbeat{AgentID: "a"}); err != nil {
		t.Fatalf("Heartbeat with host:port base: %v", err)
	}
}

func TestNewRejectsEmptyURL(t *testing.T) {
	if _, err := coordclient.New("", coordclient.Options{}); err == nil {
		t.Fatal("New accepted empty coordinator URL")
	}
	if _, err := coordclient.New("   ", coordclient.Options{}); err == nil {
		t.Fatal("New accepted blank coordinator URL")
	}
}
