package recovery_test

import (
	"testing"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/coord/recovery"
	"github.com/fass-storage/fass/internal/ec"
)

func newService(t *testing.T) (*recovery.Service, *time.Time) {
	t.Helper()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	svc := recovery.New(recovery.Config{
		Now:       func() time.Time { return now },
		Retention: 24 * time.Hour,
	})
	return svc, &now
}

// TestQueueCounterAccounting covers the job lifecycle counters and the rolling
// byte window. Every number the endpoint reports is updated by these calls, never
// computed by scanning.
func TestQueueCounterAccounting(t *testing.T) {
	svc, now := newService(t)

	if err := svc.Enqueue(recovery.Job{ID: "j1", Bytes: 100}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := svc.Enqueue(recovery.Job{ID: "j2", Bytes: 50}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	st := svc.Status(*now, nil)
	if st.Queue.Pending != 2 || st.Queue.Running != 0 || st.Queue.Failed != 0 {
		t.Fatalf("after enqueue queue = %+v", st.Queue)
	}
	if st.OldestPendingAgeSecond == nil || *st.OldestPendingAgeSecond != 0 {
		t.Fatalf("oldest pending age = %v, want 0", st.OldestPendingAgeSecond)
	}
	if st.BytesRepairedLast24h == nil || *st.BytesRepairedLast24h != 0 {
		t.Fatalf("bytes = %v, want tracked 0", st.BytesRepairedLast24h)
	}
	if st.ShardSets != nil {
		t.Fatalf("shardsets should be null until the inventory is refreshed: %+v", st.ShardSets)
	}
	if st.LastError != nil {
		t.Fatalf("last_error = %v, want null", *st.LastError)
	}

	*now = now.Add(10 * time.Second)
	st = svc.Status(*now, nil)
	if st.OldestPendingAgeSecond == nil || *st.OldestPendingAgeSecond != 10 {
		t.Fatalf("oldest pending age = %v, want 10", st.OldestPendingAgeSecond)
	}

	job, ok := svc.Claim("agent-7")
	if !ok || job.ID != "j1" {
		t.Fatalf("Claim = %+v, %v", job, ok)
	}
	st = svc.Status(*now, nil)
	if st.Queue.Pending != 1 || st.Queue.Running != 1 {
		t.Fatalf("after claim queue = %+v", st.Queue)
	}

	*now = now.Add(5 * time.Minute)
	if err := svc.Complete("j1"); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	st = svc.Status(*now, nil)
	if st.Queue.Pending != 1 || st.Queue.Running != 0 {
		t.Fatalf("after complete queue = %+v", st.Queue)
	}
	if st.BytesRepairedLast24h == nil || *st.BytesRepairedLast24h != 100 {
		t.Fatalf("bytes = %v, want 100", st.BytesRepairedLast24h)
	}
	// MTTR is exposed on the same source the metrics endpoint uses.
	if mttr := svc.Metrics()["mttr_seconds"]; mttr != 300 {
		t.Fatalf("mttr = %v, want 300", mttr)
	}

	if _, ok := svc.Claim("agent-8"); !ok {
		t.Fatalf("second claim failed")
	}
	if err := svc.Fail("j2", "shard fetch timeout: agent 3f2a"); err != nil {
		t.Fatalf("Fail: %v", err)
	}
	st = svc.Status(*now, nil)
	if st.Queue.Failed != 1 || st.Queue.Running != 0 {
		t.Fatalf("after failure queue = %+v", st.Queue)
	}
	if st.LastError == nil || *st.LastError != "shard fetch timeout: agent 3f2a" {
		t.Fatalf("last_error = %v", st.LastError)
	}
	if err := svc.Retry("j2"); err != nil {
		t.Fatalf("Retry: %v", err)
	}
	if st := svc.Status(*now, nil); st.Queue.Failed != 0 || st.Queue.Pending != 1 {
		t.Fatalf("after retry queue = %+v", st.Queue)
	}

	// The rolling window drops repaired bytes once they age out.
	*now = now.Add(25 * time.Hour)
	st = svc.Status(*now, nil)
	if st.BytesRepairedLast24h == nil || *st.BytesRepairedLast24h != 0 {
		t.Fatalf("bytes after 25h = %v, want 0 (window dropped)", st.BytesRepairedLast24h)
	}
}

// TestThrottleAndBudgetHonesty: an unconfigured budget is null (unknown), and a
// configured budget reports null until the scheduler has actually reported state.
func TestThrottleAndBudgetHonesty(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	svc := recovery.New(recovery.Config{Now: func() time.Time { return now }})
	st := svc.Status(now, nil)
	if st.PerSiteBudgetMbps != nil || st.Throttled != nil {
		t.Fatalf("unconfigured budget = %v/%v, want null/null", st.PerSiteBudgetMbps, st.Throttled)
	}

	svc = recovery.New(recovery.Config{PerSiteBudgetMBps: 200, Now: func() time.Time { return now }})
	st = svc.Status(now, nil)
	if st.PerSiteBudgetMbps == nil || *st.PerSiteBudgetMbps != 200 {
		t.Fatalf("budget = %v, want 200", st.PerSiteBudgetMbps)
	}
	if st.Throttled != nil {
		t.Fatalf("throttled = %v, want null until the scheduler reports", *st.Throttled)
	}
	svc.SetThrottled(true)
	st = svc.Status(now, nil)
	if st.Throttled == nil || !*st.Throttled {
		t.Fatalf("throttled = %v, want true", st.Throttled)
	}
}

func agentIDs(names ...string) []contract.AgentID {
	out := make([]contract.AgentID, 0, len(names))
	for _, n := range names {
		out = append(out, contract.AgentID(n))
	}
	return out
}

// TestDeficitSeveritiesFromTopology is the "kill a Nexus" test: the three
// severities are computed from actual reachable-shard counts per geo group, and
// losing a Nexus raises the watermark before anything becomes unrecoverable.
func TestDeficitSeveritiesFromTopology(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	svc := recovery.New(recovery.Config{Now: func() time.Time { return now }})
	params := ec.Params{GeoN: 2, GeoK: 1, LocalN: 3, LocalK: 1}
	// Three geo groups (nexus-a/b/c) with three local shards each, plus one
	// object's worth of shard sets to make the counting non-trivial.
	state := recovery.ShardSetState{
		ID:     contract.ShardSetID("ss-1"),
		Params: params,
		Groups: map[int][]contract.AgentID{
			0: agentIDs("a1", "a2", "a3"),
			1: agentIDs("b1", "b2", "b3"),
			2: agentIDs("c1", "c2", "c3"),
		},
	}
	svc.UpdateShardSets([]recovery.ShardSetState{state})

	reachable := map[contract.AgentID]bool{"a1": true, "a2": true, "a3": true, "b1": true, "b2": true, "b3": true, "c1": true, "c2": true, "c3": true}
	d := svc.Status(now, func(id contract.AgentID) bool { return reachable[id] }).ShardSets
	if d == nil || *d != (recovery.Deficits{}) {
		t.Fatalf("all reachable deficits = %+v, want all zero", d)
	}

	// Kill nexus-a entirely: 2 usable groups == geo_n, one more loss is fatal.
	for _, id := range []contract.AgentID{"a1", "a2", "a3"} {
		reachable[id] = false
	}
	d = svc.Status(now, func(id contract.AgentID) bool { return reachable[id] }).ShardSets
	if d == nil || d.BelowThreshold != 0 || d.BelowRepairWatermark != 1 || d.Unrecoverable != 0 {
		t.Fatalf("one nexus lost deficits = %+v, want {0 1 0}", d)
	}

	// Kill nexus-b too: fewer than geo_n usable groups is data loss.
	for _, id := range []contract.AgentID{"b1", "b2", "b3"} {
		reachable[id] = false
	}
	d = svc.Status(now, func(id contract.AgentID) bool { return reachable[id] }).ShardSets
	if d == nil || d.BelowThreshold != 1 || d.BelowRepairWatermark != 0 || d.Unrecoverable != 1 {
		t.Fatalf("two nexuses lost deficits = %+v, want {1 0 1}", d)
	}

	// A partially reachable group (fewer than local_n shards) counts as lost too.
	reachable = map[contract.AgentID]bool{"a1": true, "a2": true, "b1": true, "b2": true, "b3": true, "c1": true, "c2": true, "c3": true}
	d = svc.Status(now, func(id contract.AgentID) bool { return reachable[id] }).ShardSets
	if d == nil || d.BelowRepairWatermark != 1 || d.Unrecoverable != 0 {
		t.Fatalf("partial group deficits = %+v, want {0 1 0}", d)
	}
}
