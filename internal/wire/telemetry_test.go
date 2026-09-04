package wire

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/inventory"
	"github.com/ppflight/ppflight-agent/internal/observation"
)

func TestLegacyBillingCountersAlwaysComeFromPVE(t *testing.T) {
	now := time.Now().UTC()
	pveRX, pveTX, qgaRX, qgaTX := uint64(1000), uint64(2000), uint64(1), uint64(2)
	snapshot := observation.Snapshot{AgentRef: "agent", CollectorRef: "collector", ClusterRef: "cluster", NodeRef: "pve", Site: "lab", ObservedAt: now, Components: map[string]observation.Availability{"pve": {Available: true}}, Guests: []observation.Guest{{VMID: 101, GuestType: "qemu", Name: "vm", Node: "pve", ObservedAt: now, PVE: observation.PVEGuestView{Status: "running", IngressBytes: &pveRX, EgressBytes: &pveTX}, QGA: observation.QGAView{Availability: observation.Availability{Available: true}, Interfaces: nil}}}}
	_ = qgaRX
	_ = qgaTX
	envelope, err := BuildLegacy(snapshot, nil, "boot", 1, "test", now)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Instances[0].NetworkRXBytes != "1000" || envelope.Instances[0].NetworkTXBytes != "2000" {
		t.Fatalf("unexpected counters: %#v", envelope.Instances[0])
	}
}

func TestWebsiteTelemetryStringEncodesCumulativeCounters(t *testing.T) {
	now := time.Now().UTC()
	large := uint64(9_007_199_254_740_993)
	snapshot := observation.Snapshot{Mode: "test", AgentRef: "agent", CollectorRef: "collector", ClusterRef: "cluster", ObservedAt: now, Guests: []observation.Guest{{VMID: 101, GuestType: "qemu", PVE: observation.PVEGuestView{IngressBytes: &large, EgressBytes: &large, DiskRead: &large}}}}
	batch, err := BuildWebsiteTelemetry(snapshot, nil, "source", 1)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"ingressBytesTotal":"9007199254740993"`) || !strings.Contains(string(raw), `"diskReadBytesTotal":"9007199254740993"`) {
		t.Fatalf("counters were not string encoded: %s", raw)
	}
}

func TestWebsiteTelemetryCarriesObservedAndSentTimes(t *testing.T) {
	observed := time.Date(2026, 8, 30, 1, 2, 3, 987654321, time.FixedZone("test-offset", 8*60*60))
	sent := observed.Add(45*time.Second + 123*time.Millisecond)
	snapshot := observation.Snapshot{Mode: "production", AgentRef: "agent", CollectorRef: "collector", ClusterRef: "cluster", ObservedAt: observed,
		Components: map[string]observation.Availability{"pve": {Available: true, ObservedAt: observed, FreshUntil: observed.Add(time.Minute)}}}
	batch, err := BuildWebsiteTelemetryAt(snapshot, nil, "source", 7, sent)
	if err != nil {
		t.Fatal(err)
	}
	wantObserved := observed.UTC().Truncate(time.Second)
	wantSent := sent.UTC().Truncate(time.Second)
	if !batch.ObservedAt.Equal(wantObserved) || !batch.SentAt.Equal(wantSent) || uint64(batch.Sequence) != 7 {
		t.Fatalf("unexpected time/sequence contract: %#v", batch)
	}
	if !batch.Components["pve"].ObservedAt.Equal(wantObserved) || batch.Components["pve"].FreshUntil.Nanosecond() != 0 {
		t.Fatalf("website component timestamps were not canonicalized: %#v", batch.Components["pve"])
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"sequence":"7"`)) || !bytes.Contains(raw, []byte(`"observedAt":"2026-08-29T17:02:03Z"`)) ||
		!bytes.Contains(raw, []byte(`"sentAt":"2026-08-29T17:02:49Z"`)) || bytes.Contains(raw, []byte(".987")) {
		t.Fatalf("wire contract missing string sequence/sentAt: %s", raw)
	}
}

func TestWebsiteTelemetryForAgentCarriesRunningVersion(t *testing.T) {
	now := time.Date(2026, 9, 4, 9, 20, 0, 0, time.UTC)
	snapshot := observation.Snapshot{Mode: "production", AgentRef: "agent", CollectorRef: "collector", ClusterRef: "cluster", ObservedAt: now}
	batch, err := BuildWebsiteTelemetryAtForAgent(snapshot, nil, "source", "0.1.1-rc.23", 8, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	if batch.AgentVersion != "0.1.1-rc.23" || !bytes.Contains(raw, []byte(`"agentVersion":"0.1.1-rc.23"`)) {
		t.Fatalf("running Agent version missing from website telemetry: %s", raw)
	}
}

func TestWebsiteTelemetryCarriesManagedIdentity(t *testing.T) {
	now := time.Now().UTC()
	store := inventory.NewStore(inventory.Document{SchemaVersion: 1, Revision: "rev", IssuedAt: now, Assignments: []inventory.Assignment{{ServiceRef: "service", ClusterRef: "cluster", VMID: 101, Generation: 1, InstanceUUID: "instance", GuestType: "qemu", BillingState: "shadow"}}})
	snapshot := observation.Snapshot{Mode: "test", AgentRef: "agent", CollectorRef: "collector", ClusterRef: "cluster", ObservedAt: now, Guests: []observation.Guest{{VMID: 101, GuestType: "qemu"}}}
	batch, err := BuildWebsiteTelemetry(snapshot, store, "source", 1)
	if err != nil {
		t.Fatal(err)
	}
	if !batch.Guests[0].Managed || batch.Guests[0].Identity.ServiceRef != "service" {
		t.Fatalf("identity missing: %#v", batch.Guests[0])
	}
}

func TestWebsiteTelemetryExposesNICPolicyAndSafeMeteringCapability(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	mtu := 1500
	store := inventory.NewStore(inventory.Document{SchemaVersion: 1, Revision: "rev", IssuedAt: now, Assignments: []inventory.Assignment{{
		ServiceRef: "service", ClusterRef: "cluster", VMID: 101, Generation: 1, InstanceUUID: "instance", GuestType: "qemu", BillingState: "shadow",
		NICBindings: []inventory.NICBinding{
			{Interface: "net0", Role: "public", Primary: true, Metered: true, Monitoring: true, ExpectedMAC: "02:00:00:00:01:01", Bridge: "vmbr0", MTU: &mtu, IPFilterPolicy: "required"},
			{Interface: "net1", Role: "private", Metered: false, ExpectedMAC: "02:00:00:00:01:02", Bridge: "vmbr1", IPFilterPolicy: "required"},
		},
	}}})
	snapshot := observation.Snapshot{Mode: "production", AgentRef: "agent", CollectorRef: "collector", ClusterRef: "cluster", ObservedAt: now, Guests: []observation.Guest{{
		VMID: 101, GuestType: "qemu", ObservedAt: now,
		Networks: []observation.Network{{Index: 0, Interface: "net0", MAC: "02:00:00:00:01:01", Bridge: "vmbr0", MTU: "1500", Firewall: "1"}, {Index: 1, Interface: "net1", MAC: "02:00:00:00:01:02", Bridge: "vmbr1", Firewall: "1"}},
	}}}
	batch, err := BuildWebsiteTelemetryAt(snapshot, store, "source", 1, now)
	if err != nil {
		t.Fatal(err)
	}
	guest := batch.Guests[0]
	if !guest.Capabilities.Metering.Supported || guest.Capabilities.Metering.Source != "pve-host-netdev" {
		t.Fatalf("mixed NIC policy did not advertise safe per-NIC metering: %#v", guest.Capabilities.Metering)
	}
	if len(guest.Networks) != 2 || guest.Networks[0].Binding == nil || guest.Networks[0].Binding.Role != "public" || !guest.Networks[0].PolicyMatch.Supported {
		t.Fatalf("NIC binding was not correlated with PVE config: %#v", guest.Networks)
	}
}

func TestQGARemovalFreezesDependentActionsButNotLifecycle(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	store := inventory.NewStore(inventory.Document{SchemaVersion: 1, Revision: "rev", IssuedAt: now, Assignments: []inventory.Assignment{{ServiceRef: "service", ClusterRef: "cluster", VMID: 101, Generation: 1, InstanceUUID: "instance", GuestType: "qemu", BillingState: "shadow"}}})
	snapshot := observation.Snapshot{Mode: "production", AgentRef: "agent", CollectorRef: "collector", ClusterRef: "cluster", ObservedAt: now, Guests: []observation.Guest{{
		VMID: 101, GuestType: "qemu", ObservedAt: now,
		QGA: observation.QGAView{Availability: observation.Availability{Available: false, ObservedAt: now, UnavailableReason: "guest-agent-unavailable"}},
	}}}
	batch, err := BuildWebsiteTelemetryAt(snapshot, store, "source", 1, now)
	if err != nil {
		t.Fatal(err)
	}
	capabilities := batch.Guests[0].Capabilities
	if !capabilities.Lifecycle.Available || capabilities.RootPasswordReset.Available || capabilities.GuestNetworkVerify.Available || capabilities.RootPasswordReset.Reason != "guest-agent-unavailable" {
		t.Fatalf("unexpected QGA action gate: %#v", capabilities)
	}

	freshUntil := now.Add(time.Minute)
	snapshot.Guests[0].QGA.Availability = observation.Availability{Available: true, ObservedAt: now, FreshUntil: freshUntil}
	batch, err = BuildWebsiteTelemetryAt(snapshot, store, "source", 2, now)
	if err != nil {
		t.Fatal(err)
	}
	if !batch.Guests[0].Capabilities.RootPasswordReset.Available || !batch.Guests[0].Capabilities.RootPasswordReset.ExecutionPreflight {
		t.Fatalf("fresh QGA capability missing: %#v", batch.Guests[0].Capabilities)
	}
	batch, err = BuildWebsiteTelemetryAt(snapshot, store, "source", 3, freshUntil.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if batch.Guests[0].Capabilities.RootPasswordReset.Available || batch.Guests[0].Capabilities.RootPasswordReset.Reason != "qga_stale" {
		t.Fatalf("stale QGA did not freeze reset: %#v", batch.Guests[0].Capabilities)
	}
}

func TestLegacyTestModeCannotFeedBillingCounters(t *testing.T) {
	now := time.Now().UTC()
	rx, tx := uint64(1000), uint64(2000)
	snapshot := observation.Snapshot{Mode: "test", AgentRef: "agent", CollectorRef: "collector", ClusterRef: "cluster", NodeRef: "pve", ObservedAt: now, Components: map[string]observation.Availability{"pve": {Available: true}}, Guests: []observation.Guest{{VMID: 101, GuestType: "qemu", Node: "pve", ObservedAt: now, PVE: observation.PVEGuestView{IngressBytes: &rx, EgressBytes: &tx}}}}
	envelope, err := BuildLegacy(snapshot, nil, "boot", 1, "test", now)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Instances[0].NetworkRXBytes != "" || envelope.Instances[0].NetworkTXBytes != "" {
		t.Fatalf("test counters leaked: %#v", envelope.Instances[0])
	}
}
