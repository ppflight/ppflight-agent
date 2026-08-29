package wire

import (
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
