package meter

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/exporter"
	"github.com/ppflight/ppflight-agent/internal/inventory"
	"github.com/ppflight/ppflight-agent/internal/observation"
	"github.com/ppflight/ppflight-agent/internal/store"
)

// A normal production node is sized for at most 384 VPSs.  This is a real
// per-NIC metering batch (not a synthetic encoder-only fixture): it proves a
// one-public-NIC fleet stays below the website's 1,000-event admission limit,
// well below the 64 MiB durable queue budget, and keeps its checkpoints after
// an Agent process restart.
func TestCapacity384PerNICMeteringBatchAndRestart(t *testing.T) {
	now := time.Date(2026, 9, 5, 8, 0, 0, 0, time.UTC)
	cutover := now.Add(-time.Hour)
	items := make([]inventory.Assignment, 0, 384)
	guests := make([]observation.Guest, 0, 384)
	interfaces := make([]exporter.InterfaceObservation, 0, 384)
	for offset := 0; offset < 384; offset++ {
		vmid := 1000 + offset
		mac := fmt.Sprintf("02:00:00:%02X:%02X:%02X", (offset>>16)&0xff, (offset>>8)&0xff, offset&0xff)
		items = append(items, inventory.Assignment{
			ServiceRef: fmt.Sprintf("service-%d", vmid), ClusterRef: "cluster-1", NodeRef: "pve-1",
			VMID: vmid, Generation: 1, InstanceUUID: fmt.Sprintf("instance-%d", vmid), GuestType: "qemu",
			BillingState: "active", CutoverAt: &cutover,
			NICBindings: []inventory.NICBinding{{Interface: "net0", Role: "public", Primary: true, Metered: true, Monitoring: true, ExpectedMAC: mac, Bridge: "vmbr0", IPFilterPolicy: "required"}},
		})
		aggregateIn, aggregateOut := uint64(vmid), uint64(vmid+1)
		guests = append(guests, observation.Guest{
			VMID: vmid, GuestType: "qemu", Node: "pve-1", Networks: []observation.Network{{Index: 0, Interface: "net0", MAC: mac}},
			PVE: observation.PVEGuestView{Availability: observation.Availability{Available: true, ObservedAt: now}, IngressBytes: &aggregateIn, EgressBytes: &aggregateOut},
		})
		interfaces = append(interfaces, testHostInterface(fmt.Sprintf("tap%di0", vmid), fmt.Sprint(vmid+10), fmt.Sprint(vmid+20)))
	}
	assignments := inventory.NewStore(inventory.Document{SchemaVersion: 1, Revision: "capacity-384", IssuedAt: now, Assignments: items})
	queueRoot, meterRoot := t.TempDir(), t.TempDir()
	queue, err := store.Open(store.Config{Root: queueRoot, Destination: "website", Kind: store.Metering, Policy: store.Policy{MaxBytes: 64 << 20}})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := Open(Config{Directory: meterRoot, Mode: "production", AgentRef: "agent-1", CollectorRef: "collector-1", SourceRef: "source-1", ClusterRef: "cluster-1"})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := observation.Snapshot{ClusterRef: "cluster-1", ObservedAt: now, Guests: guests, Host: &exporter.HostObservation{ObservedAt: now, Interfaces: interfaces}}
	batch, created, err := manager.Observe(snapshot, assignments, queue)
	if err != nil || !created || len(batch.Events) != 384 || queue.Len() != 1 {
		t.Fatalf("384-vps first observation created=%v events=%d queue=%d err=%v", created, len(batch.Events), queue.Len(), err)
	}
	payload, err := json.Marshal(batch)
	if err != nil || len(payload) >= 1<<20 {
		t.Fatalf("384-vps batch payload=%d err=%v, want <1MiB", len(payload), err)
	}
	t.Logf("384-vps per-NIC metering batch: %d events, %d bytes; 64MiB durable queue holds at least %d such batches", len(batch.Events), len(payload), (64<<20)/len(payload))

	// Reopen from the persisted checkpoints to model the systemd restart path.
	restarted, err := Open(Config{Directory: meterRoot, Mode: "production", AgentRef: "agent-1", CollectorRef: "collector-1", SourceRef: "source-1", ClusterRef: "cluster-1"})
	if err != nil {
		t.Fatal(err)
	}
	snapshot.ObservedAt = now.Add(time.Minute)
	snapshot.Host.ObservedAt = snapshot.ObservedAt
	for index := range snapshot.Host.Interfaces {
		vmid := 1000 + index
		snapshot.Host.Interfaces[index] = testHostInterface(fmt.Sprintf("tap%di0", vmid), fmt.Sprint(vmid+110), fmt.Sprint(vmid+220))
	}
	second, created, err := restarted.Observe(snapshot, assignments, queue)
	if err != nil || !created || len(second.Events) != 384 || second.Sequence <= batch.Sequence || second.Events[0].CounterEpoch != batch.Events[0].CounterEpoch {
		t.Fatalf("384-vps restart observation created=%v events=%d sequence=%d epoch=%q err=%v", created, len(second.Events), second.Sequence, second.Events[0].CounterEpoch, err)
	}
}

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

func TestMixedPublicPrivateUsesOnlyHostBackedPublicNIC(t *testing.T) {
	now := time.Date(2026, 9, 2, 1, 2, 3, 0, time.UTC)
	cutover := now.Add(-time.Hour)
	assignment := inventory.Assignment{ServiceRef: "service-1", ClusterRef: "cluster-1", NodeRef: "pve-1", VMID: 101, Generation: 9, InstanceUUID: "instance-1", GuestType: "qemu", BillingState: "active", CutoverAt: &cutover, NICBindings: []inventory.NICBinding{
		{Interface: "net0", Role: "public", Primary: true, Metered: true, Monitoring: true, ExpectedMAC: "02:00:00:00:01:01", Bridge: "vmbr0", IPFilterPolicy: "required"},
		{Interface: "net1", Role: "private", Metered: false, ExpectedMAC: "02:00:00:00:01:02", Bridge: "vmbr1", IPFilterPolicy: "disabled"},
	}}
	assignments := inventory.NewStore(inventory.Document{SchemaVersion: 1, Revision: "rev", IssuedAt: now, Assignments: []inventory.Assignment{assignment}})
	queue, err := store.Open(store.Config{Root: t.TempDir(), Destination: "website", Kind: store.Metering})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := Open(Config{Directory: t.TempDir(), Mode: "production", AgentRef: "agent-1", CollectorRef: "collector-1", SourceRef: "source-1", ClusterRef: "cluster-1"})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := testSnapshot(now, 999999, 888888)
	snapshot.Guests[0].Networks = []observation.Network{{Index: 0, Interface: "net0", MAC: "02:00:00:00:01:01"}, {Index: 1, Interface: "net1", MAC: "02:00:00:00:01:02"}}
	snapshot.Host = &exporter.HostObservation{ObservedAt: now, Interfaces: []exporter.InterfaceObservation{
		testHostInterface("tap101i0", "18446744073709551610", "9007199254740993"),
		testHostInterface("tap101i1", "777", "888"),
	}}
	batch, ok, err := manager.Observe(snapshot, assignments, queue)
	if err != nil || !ok || len(batch.Events) != 1 {
		t.Fatalf("per-NIC observe: ok=%v err=%v batch=%#v", ok, err, batch)
	}
	event := batch.Events[0]
	if event.InterfaceRef != "net0" || event.CanonicalMAC != "02:00:00:00:01:01" || event.Source != "pve-host-netdev" || event.NetworkRole != "public" || !event.Metered || event.BillingState != "active" {
		t.Fatalf("public NIC identity=%#v", event)
	}
	if uint64(event.IngressBytes) != 9007199254740993 || uint64(event.EgressBytes) != 18446744073709551610 {
		t.Fatalf("host direction or exact uint64 lost: %#v", event)
	}
}

func TestPrivateOnlyGuestProducesNoUsageEvent(t *testing.T) {
	now := time.Date(2026, 9, 2, 2, 30, 0, 0, time.UTC)
	cutover := now.Add(-time.Hour)
	assignment := inventory.Assignment{ServiceRef: "service-1", ClusterRef: "cluster-1", NodeRef: "pve-1", VMID: 101, Generation: 1, InstanceUUID: "instance-1", GuestType: "qemu", BillingState: "active", CutoverAt: &cutover, NICBindings: []inventory.NICBinding{
		{Interface: "net0", Role: "private", Metered: false, ExpectedMAC: "02:00:00:00:01:01", Bridge: "vmbr1", IPFilterPolicy: "disabled"},
	}}
	assignments := inventory.NewStore(inventory.Document{SchemaVersion: 1, Revision: "rev", IssuedAt: now, Assignments: []inventory.Assignment{assignment}})
	queue, err := store.Open(store.Config{Root: t.TempDir(), Destination: "website", Kind: store.Metering})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := Open(Config{Directory: t.TempDir(), Mode: "production", AgentRef: "agent-1", CollectorRef: "collector-1", SourceRef: "source-1", ClusterRef: "cluster-1"})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := testSnapshot(now, 999, 888)
	snapshot.Guests[0].Networks = []observation.Network{{Index: 0, Interface: "net0", MAC: "02:00:00:00:01:01"}}
	snapshot.Host = &exporter.HostObservation{ObservedAt: now, Interfaces: []exporter.InterfaceObservation{testHostInterface("tap101i0", "100", "200")}}
	batch, created, err := manager.Observe(snapshot, assignments, queue)
	if err != nil || created || len(batch.Events) != 0 || queue.Len() != 0 {
		t.Fatalf("private-only guest generated usage: created=%v events=%d queue=%d err=%v", created, len(batch.Events), queue.Len(), err)
	}
}

func TestPerNICCounterResetRotatesOnlyThatEpoch(t *testing.T) {
	now := time.Date(2026, 9, 2, 2, 0, 0, 0, time.UTC)
	cutover := now.Add(-time.Hour)
	assignment := inventory.Assignment{ServiceRef: "service-1", ClusterRef: "cluster-1", NodeRef: "pve-1", VMID: 101, Generation: 2, InstanceUUID: "instance-1", GuestType: "qemu", BillingState: "active", CutoverAt: &cutover, NICBindings: []inventory.NICBinding{{Interface: "net0", Role: "public", Primary: true, Metered: true, Monitoring: true, ExpectedMAC: "02:00:00:00:01:01", Bridge: "vmbr0", IPFilterPolicy: "required"}}}
	assignments := inventory.NewStore(inventory.Document{SchemaVersion: 1, Revision: "rev", IssuedAt: now, Assignments: []inventory.Assignment{assignment}})
	queue, _ := store.Open(store.Config{Root: t.TempDir(), Destination: "website", Kind: store.Metering})
	manager, _ := Open(Config{Directory: t.TempDir(), Mode: "production", AgentRef: "agent-1", CollectorRef: "collector-1", SourceRef: "source-1", ClusterRef: "cluster-1"})
	makeSnapshot := func(at time.Time, rx, tx string) observation.Snapshot {
		value := testSnapshot(at, 0, 0)
		value.Guests[0].Networks = []observation.Network{{Index: 0, Interface: "net0", MAC: "02:00:00:00:01:01"}}
		value.Host = &exporter.HostObservation{ObservedAt: at, Interfaces: []exporter.InterfaceObservation{testHostInterface("tap101i0", rx, tx)}}
		return value
	}
	first, _, _ := manager.Observe(makeSnapshot(now, "100", "200"), assignments, queue)
	second, _, _ := manager.Observe(makeSnapshot(now.Add(time.Minute), "120", "240"), assignments, queue)
	third, _, _ := manager.Observe(makeSnapshot(now.Add(2*time.Minute), "1", "2"), assignments, queue)
	if first.Events[0].CounterEpoch != second.Events[0].CounterEpoch || second.Events[0].CounterEpoch == third.Events[0].CounterEpoch {
		t.Fatalf("epochs did not track reset: %q %q %q", first.Events[0].CounterEpoch, second.Events[0].CounterEpoch, third.Events[0].CounterEpoch)
	}
}

func TestLXCPerNICUsesVethCounters(t *testing.T) {
	now := time.Date(2026, 9, 2, 3, 0, 0, 0, time.UTC)
	cutover := now.Add(-time.Hour)
	assignment := inventory.Assignment{ServiceRef: "service-1", ClusterRef: "cluster-1", NodeRef: "pve-1", VMID: 202, Generation: 4, InstanceUUID: "instance-2", GuestType: "lxc", BillingState: "active", CutoverAt: &cutover, NICBindings: []inventory.NICBinding{
		{Interface: "net0", Role: "public", Primary: true, Metered: true, Monitoring: true, ExpectedMAC: "02:00:00:00:02:01", Bridge: "vmbr0", IPFilterPolicy: "required"},
	}}
	assignments := inventory.NewStore(inventory.Document{SchemaVersion: 1, Revision: "rev", IssuedAt: now, Assignments: []inventory.Assignment{assignment}})
	queue, _ := store.Open(store.Config{Root: t.TempDir(), Destination: "website", Kind: store.Metering})
	manager, _ := Open(Config{Directory: t.TempDir(), Mode: "production", AgentRef: "agent-1", CollectorRef: "collector-1", SourceRef: "source-1", ClusterRef: "cluster-1"})
	ingress, egress := uint64(999), uint64(888)
	snapshot := observation.Snapshot{ClusterRef: "cluster-1", ObservedAt: now, Host: &exporter.HostObservation{ObservedAt: now, Interfaces: []exporter.InterfaceObservation{testHostInterface("veth202i0", "300", "400")}}, Guests: []observation.Guest{{
		VMID: 202, GuestType: "lxc", Node: "pve-1", Networks: []observation.Network{{Index: 0, Interface: "net0", MAC: "02:00:00:00:02:01"}}, PVE: observation.PVEGuestView{Availability: observation.Availability{Available: true, ObservedAt: now}, IngressBytes: &ingress, EgressBytes: &egress},
	}}}
	batch, created, err := manager.Observe(snapshot, assignments, queue)
	if err != nil || !created || len(batch.Events) != 1 {
		t.Fatalf("LXC per-NIC observe failed: created=%v events=%d err=%v", created, len(batch.Events), err)
	}
	event := batch.Events[0]
	if event.Source != "pve-host-netdev" || event.InterfaceRef != "net0" || uint64(event.IngressBytes) != 400 || uint64(event.EgressBytes) != 300 {
		t.Fatalf("LXC did not use authoritative veth counters: %#v", event)
	}
}

func TestPerNICIdentityChangeRotatesCounterEpoch(t *testing.T) {
	now := time.Date(2026, 9, 2, 4, 0, 0, 0, time.UTC)
	cutover := now.Add(-time.Hour)
	makeAssignment := func(generation uint64, mac string) inventory.Assignment {
		return inventory.Assignment{ServiceRef: "service-1", ClusterRef: "cluster-1", NodeRef: "pve-1", VMID: 101, Generation: generation, InstanceUUID: "instance-1", GuestType: "qemu", BillingState: "active", CutoverAt: &cutover, NICBindings: []inventory.NICBinding{{Interface: "net0", Role: "public", Primary: true, Metered: true, Monitoring: true, ExpectedMAC: mac, Bridge: "vmbr0", IPFilterPolicy: "required"}}}
	}
	makeSnapshot := func(at time.Time, mac, rx, tx string) observation.Snapshot {
		value := testSnapshot(at, 0, 0)
		value.Guests[0].Networks = []observation.Network{{Index: 0, Interface: "net0", MAC: mac}}
		value.Host = &exporter.HostObservation{ObservedAt: at, Interfaces: []exporter.InterfaceObservation{testHostInterface("tap101i0", rx, tx)}}
		return value
	}
	queue, _ := store.Open(store.Config{Root: t.TempDir(), Destination: "website", Kind: store.Metering})
	manager, _ := Open(Config{Directory: t.TempDir(), Mode: "production", AgentRef: "agent-1", CollectorRef: "collector-1", SourceRef: "source-1", ClusterRef: "cluster-1"})
	firstAssignments := inventory.NewStore(inventory.Document{SchemaVersion: 1, Revision: "rev-1", IssuedAt: now, Assignments: []inventory.Assignment{makeAssignment(2, "02:00:00:00:01:01")}})
	first, _, err := manager.Observe(makeSnapshot(now, "02:00:00:00:01:01", "100", "200"), firstAssignments, queue)
	if err != nil {
		t.Fatal(err)
	}
	hotplugAssignments := inventory.NewStore(inventory.Document{SchemaVersion: 1, Revision: "rev-2", IssuedAt: now.Add(time.Minute), Assignments: []inventory.Assignment{makeAssignment(2, "02:00:00:00:01:02")}})
	hotplug, _, err := manager.Observe(makeSnapshot(now.Add(time.Minute), "02:00:00:00:01:02", "120", "220"), hotplugAssignments, queue)
	if err != nil {
		t.Fatal(err)
	}
	newGenerationAssignments := inventory.NewStore(inventory.Document{SchemaVersion: 1, Revision: "rev-3", IssuedAt: now.Add(2 * time.Minute), Assignments: []inventory.Assignment{makeAssignment(3, "02:00:00:00:01:02")}})
	regenerated, _, err := manager.Observe(makeSnapshot(now.Add(2*time.Minute), "02:00:00:00:01:02", "140", "240"), newGenerationAssignments, queue)
	if err != nil {
		t.Fatal(err)
	}
	if first.Events[0].CounterEpoch == hotplug.Events[0].CounterEpoch || hotplug.Events[0].CounterEpoch == regenerated.Events[0].CounterEpoch {
		t.Fatalf("identity change reused epoch: %q %q %q", first.Events[0].CounterEpoch, hotplug.Events[0].CounterEpoch, regenerated.Events[0].CounterEpoch)
	}
}

func testHostInterface(name, receive, transmit string) exporter.InterfaceObservation {
	value := 1.0
	return exporter.InterfaceObservation{Device: name, ReceiveBytes: exporter.Value{Value: &value, Raw: receive}, TransmitBytes: exporter.Value{Value: &value, Raw: transmit}}
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

func TestMultiNICAggregateCanNeverBecomeActive(t *testing.T) {
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
	assignment.NICBindings[1].Role = "public"
	assignment.NICBindings[1].Metered = true
	if state := observe(t, assignment); state != "shadow" {
		t.Fatalf("multi-NIC guest aggregate became %q", state)
	}
}

func testSnapshot(now time.Time, ingress, egress uint64) observation.Snapshot {
	return observation.Snapshot{ClusterRef: "cluster-1", ObservedAt: now, Guests: []observation.Guest{{
		VMID: 101, GuestType: "qemu", Node: "pve-1", PVE: observation.PVEGuestView{
			Availability: observation.Availability{Available: true, ObservedAt: now}, IngressBytes: &ingress, EgressBytes: &egress,
		},
	}}}
}
