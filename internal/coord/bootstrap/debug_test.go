package bootstrap_test

import (
	"context"
	"testing"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/coord/bootstrap"
	"github.com/fass-storage/fass/internal/coord/membership"
	"github.com/fass-storage/fass/internal/storage"
)

func TestDebugEnsurePending(t *testing.T) {
	f := newFixture(t)
	cfg := bootstrap.DevConfig(t.TempDir())
	ctx := context.Background()
	first := f.run(t, cfg)
	_ = f.db.View(ctx, func(tx *storage.ReadTx) error {
		return tx.Scan([]byte("agents_by_location"), nil, func(k, v []byte) error {
			if len(k) > 7 && string(k[:7]) == "node-a1" {
				t.Logf("after first run loc key=%q -> %s", k, v)
			}
			return nil
		})
	})
	// simulate provisioning of the first slot
	target := first.Agents[0]
	agentID, secret, minted, err := f.mem.EnsurePending(ctx, membership.PendingRegistration{
		NodeID: target.NodeID, Slot: target.DiskID, CapacityBytes: bootstrap.DevAgentCapacity,
	})
	if err != nil || !minted {
		t.Fatalf("ensure: %v minted=%v", err, minted)
	}
	if _, err := f.mem.Announce(ctx, contract.AnnounceRequest{
		PublicKey: []byte("pk"), Secret: secret, NodeID: target.NodeID,
		DiskID: "real-disk-uuid", Port: 7101, CapacityBytes: bootstrap.DevAgentCapacity, Hostname: "127.0.0.1",
	}); err != nil {
		t.Fatalf("announce: %v", err)
	}
	if _, err := f.mem.Activate(ctx, agentID); err != nil {
		t.Fatalf("activate: %v", err)
	}
	ag, _ := f.mem.GetAgent(ctx, agentID)
	t.Logf("after activate: id=%s node=%s disk=%s state=%s slot=%s", ag.ID, ag.NodeID, ag.DiskID, ag.State, target.DiskID)
	// direct EnsurePending probe
	id2, secret2, minted2, err := f.mem.EnsurePending(ctx, membership.PendingRegistration{
		NodeID: target.NodeID, Slot: target.DiskID, CapacityBytes: bootstrap.DevAgentCapacity,
	})
	t.Logf("probe: id=%s (same=%v) minted=%v secretEmpty=%v err=%v", id2, id2 == agentID, minted2, secret2 == "", err)
	// Dump agent records for node-a1 before second run.
	dump := func(when string) {
		_ = f.db.View(ctx, func(tx *storage.ReadTx) error {
			return storage.ScanJSON[membership.Agent](tx, []byte("agents"), nil, func(_ []byte, ag membership.Agent) error {
				if ag.NodeID == target.NodeID {
					t.Logf("%s: agent id=%s node=%s disk=%s state=%s slotkeys?", when, ag.ID, ag.NodeID, ag.DiskID, ag.State)
				}
				return nil
			})
		})
	}
	dump("before second run")
	second := f.run(t, cfg)
	dump("after second run")
	_ = f.db.View(ctx, func(tx *storage.ReadTx) error {
		return tx.Scan([]byte("agents_by_location"), nil, func(k, v []byte) error {
			if string(k[:7]) == "node-a1" {
				t.Logf("loc key=%q -> %s", k, v)
			}
			return nil
		})
	})
	for _, a := range second.Agents {
		if a.NodeID == target.NodeID {
			t.Logf("second payload slot %q secretEmpty=%v", a.DiskID, a.Secret == "")
		}
	}
}
