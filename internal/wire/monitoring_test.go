package wire

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/exporter"
	"github.com/ppflight/ppflight-agent/internal/inventory"
	"github.com/ppflight/ppflight-agent/internal/observation"
	"github.com/ppflight/ppflight-agent/internal/protocol"
	"github.com/ppflight/ppflight-agent/internal/pve"
)

func TestMonitoringTelemetryPreservesAllLargeValuesAsStrings(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	large := uint64(9007199254740993)
	metricFloat := float64(9007199254740992)
	snapshot := observation.Snapshot{
		SchemaVersion: 1, Mode: "production", AgentRef: "agent-01", CollectorRef: "collector-01", ClusterRef: "cluster-01", NodeRef: "node-01", Site: "primary", ObservedAt: now,
		PVEVersion: pve.Version{Version: "9.0", Release: "9.0", RepoID: "repo-01"}, Components: map[string]observation.Availability{"pve": {Available: true, ObservedAt: now}},
		Nodes:    []observation.Node{{Name: "node-01", Status: "online", MemoryUsed: &large, MemoryTotal: &large, SwapUsed: &large, SwapTotal: &large, RootUsed: &large, RootTotal: &large, UptimeSeconds: &large, ObservedAt: now}},
		Storages: []observation.Storage{{Node: "node-01", Name: "local-zfs", Kind: "zfspool", Status: "available", UsedBytes: &large, TotalBytes: &large, FreeBytes: &large, ObservedAt: now}},
		Guests: []observation.Guest{{VMID: 101, GuestType: "qemu", Name: "guest-01", Node: "node-01", ObservedAt: now,
			PVE: observation.PVEGuestView{Availability: observation.Availability{Available: true, ObservedAt: now}, Status: "running", MemoryUsed: &large, MemoryTotal: &large, DiskUsed: &large, DiskTotal: &large, DiskRead: &large, DiskWrite: &large, IngressBytes: &large, EgressBytes: &large, UptimeSeconds: &large},
			QGA: observation.QGAView{Availability: observation.Availability{Available: true, ObservedAt: now, FreshUntil: now.Add(time.Minute)},
				Filesystems: []pve.GuestFilesystem{{Name: "root", Mountpoint: "/", Type: "ext4", TotalBytes: &large, UsedBytes: &large}},
				Interfaces:  []pve.GuestInterface{{Name: "eth0", HardwareAddress: "02:00:00:00:00:01", Statistics: &pve.GuestInterfaceStats{RxBytes: &large, TxBytes: &large, RxPackets: &large, TxPackets: &large}}}},
		}},
		Host:  &exporter.HostObservation{ObservedAt: now, MemoryTotalBytes: exporter.Value{Value: &metricFloat, Raw: "9007199254740993"}, Interfaces: []exporter.InterfaceObservation{{Device: "eth0", ReceiveBytes: exporter.Value{Value: &metricFloat, Raw: "9007199254740993"}}}},
		SMART: &exporter.SmartObservation{ObservedAt: now, Devices: []exporter.SmartDeviceObservation{{Device: "/dev/sda", CapacityBytes: exporter.Value{Value: &metricFloat, Raw: "9007199254740993"}}}},
	}
	assignments := inventory.NewStore(inventory.Document{SchemaVersion: 1, Revision: "revision-01", IssuedAt: now, Assignments: []inventory.Assignment{{ServiceRef: "service-01", ClusterRef: "cluster-01", NodeRef: "node-01", VMID: 101, Generation: large, InstanceUUID: "instance-01", GuestType: "qemu", BillingState: "shadow"}}})
	batch, err := BuildMonitoringTelemetry(snapshot, assignments, MonitoringBuildContext{
		BindingID: "550e8400-e29b-41d4-a716-446655440001", MonitoringAgentRef: "monitor-agent-01", DeviceID: "device-01", CredentialEpoch: large,
		BootID: "550e8400-e29b-41d4-a716-446655440002", Sequence: large, AgentVersion: "1.0.0", SourceRef: "source-01", SentAt: now,
		AgentHealth: MonitoringAgentHealth{AuditQueue: MonitoringQueueState{PendingItems: protocol.Counter(large), PendingBytes: protocol.Counter(large)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	batch.BatchID = "550e8400-e29b-41d4-a716-446655440003"
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(`:9007199254740993`)) {
		t.Fatalf("large integer escaped string encoding: %s", raw)
	}
	for _, field := range []string{"credentialEpoch", "sequence", "generation", "memoryUsedBytes", "diskReadBytesTotal", "totalBytes", "rxBytes", "pendingBytes", "decimal"} {
		needle := []byte(`"` + field + `":"9007199254740993"`)
		if field == "decimal" {
			needle = []byte(`"decimal":"9007199254740993"`)
		}
		if !bytes.Contains(raw, needle) {
			t.Fatalf("field %s did not preserve exact decimal value: %s", field, raw)
		}
	}
}

func TestMonitoringTelemetryRejectsMissingBindingAuthority(t *testing.T) {
	_, err := BuildMonitoringTelemetry(observation.Snapshot{ObservedAt: time.Now().UTC()}, nil, MonitoringBuildContext{})
	if err == nil {
		t.Fatal("missing monitoring binding authority was accepted")
	}
}
