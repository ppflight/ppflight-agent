package meter

import (
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/inventory"
	"github.com/ppflight/ppflight-agent/internal/observation"
	"github.com/ppflight/ppflight-agent/internal/store"
)

func TestObservePersistsEpochAndDetectsReset(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	cutover := now.Add(-time.Hour)
	assignments := inventory.NewStore(inventory.Document{SchemaVersion: 1, Revision: "rev-1", IssuedAt: now, Assignments: []inventory.Assignment{{ServiceRef: "service-1", ClusterRef: "cluster-1", VMID: 101, Generation: 2, InstanceUUID: "instance-1", GuestType: "qemu", BillingState: "active", CutoverAt: &cutover}}})
	queue, err := store.Open(store.Config{Root: t.TempDir(), Destination: "website", Kind: store.Metering})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := Open(Config{Directory: t.TempDir(), Mode: "test", AgentRef: "agent-1", CollectorRef: "collector-1", SourceRef: "source-1", ClusterRef: "cluster-1", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	first := testSnapshot(now, 100, 200)
	batch1, ok, err := manager.Observe(first, assignments, queue)
	if err != nil || !ok {
		t.Fatalf("first observe: %v %v", ok, err)
	}
	if batch1.Events[0].BillingState != "shadow" {
		t.Fatal("test mode emitted active billing")
	}
	epoch := batch1.Events[0].CounterEpoch
	batch2, ok, err := manager.Observe(testSnapshot(now.Add(time.Minute), 150, 260), assignments, queue)
	if err != nil || !ok || batch2.Events[0].CounterEpoch != epoch {
		t.Fatalf("monotonic observation changed epoch: %#v %v", batch2, err)
	}
	batch3, ok, err := manager.Observe(testSnapshot(now.Add(2*time.Minute), 5, 8), assignments, queue)
	if err != nil || !ok || batch3.Events[0].CounterEpoch == epoch {
		t.Fatalf("counter reset did not change epoch: %#v %v", batch3, err)
	}
}

func TestUnmappedGuestDoesNotMeter(t *testing.T) {
	now := time.Now().UTC()
	assignments := inventory.NewStore(inventory.Document{SchemaVersion: 1, Revision: "rev-1", IssuedAt: now})
	queue, err := store.Open(store.Config{Root: t.TempDir(), Destination: "website", Kind: store.Metering})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := Open(Config{Directory: t.TempDir(), Mode: "test", AgentRef: "agent-1", CollectorRef: "collector-1", SourceRef: "source-1", ClusterRef: "cluster-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := manager.Observe(testSnapshot(now, 1, 2), assignments, queue); err != nil || ok || queue.Len() != 0 {
		t.Fatalf("unmapped guest was metered: ok=%v err=%v len=%d", ok, err, queue.Len())
	}
}

func TestMultiNICAggregateCannotBecomeActiveUnlessEveryNICIsMetered(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	cutover := now.Add(-time.Hour)
	bindings := []inventory.NICBinding{
		{Interface: "net0", Role: "public", Primary: true, Metered: true, Monitoring: true, ExpectedMAC: "02:00:00:00:01:01", Bridge: "vmbr0", IPFilterPolicy: "required"},
		{Interface: "net1", Role: "private", Metered: false, ExpectedMAC: "02:00:00:00:01:02", Bridge: "vmbr1", IPFilterPolicy: "required"},
	}
	assignment := inventory.Assignment{ServiceRef: "service-1", ClusterRef: "cluster-1", VMID: 101, Generation: 2, InstanceUUID: "instance-1", GuestType: "qemu", BillingState: "active", CutoverAt: &cutover, NICBindings: bindings}
	observe := func(t *testing.T, candidate inventory.Assignment) string {
		t.Helper()
		assignments := inventory.NewStore(inventory.Document{SchemaVersion: 1, Revision: "rev", IssuedAt: now, Assignments: []inventory.Assignment{candidate}})
		queue, err := store.Open(store.Config{Root: t.TempDir(), Destination: "website", Kind: store.Metering})
		if err != nil {
			t.Fatal(err)
		}
		manager, err := Open(Config{Directory: t.TempDir(), Mode: "production", AgentRef: "agent-1", CollectorRef: "collector-1", SourceRef: "source-1", ClusterRef: "cluster-1"})
		if err != nil {
			t.Fatal(err)
		}
		batch, ok, err := manager.Observe(testSnapshot(now, 100, 200), assignments, queue)
		if err != nil || !ok || len(batch.Events) != 1 {
			t.Fatalf("observe: ok=%v err=%v batch=%#v", ok, err, batch)
		}
		return batch.Events[0].BillingState
	}
	if state := observe(t, assignment); state != "shadow" {
		t.Fatalf("mixed public/private metering became %q", state)
	}
	assignment.NICBindings[1].Metered = true
	if state := observe(t, assignment); state != "active" {
		t.Fatalf("explicit all-NIC metering did not become active: %q", state)
	}
}

func testSnapshot(now time.Time, ingress, egress uint64) observation.Snapshot {
	return observation.Snapshot{ClusterRef: "cluster-1", ObservedAt: now, Guests: []observation.Guest{{
		VMID: 101, GuestType: "qemu", Node: "pve-1", PVE: observation.PVEGuestView{
			Availability: observation.Availability{Available: true, ObservedAt: now}, IngressBytes: &ingress, EgressBytes: &egress,
		},
	}}}
}
