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

func TestMonitoringPayloadNormalizesRequiredArrays(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 30, 0, 0, time.UTC)
	// This is a deliberately hand-written observation fixture.  The released
	// collector never fabricates a PVE snapshot; it only reads the local API.
	// Keep the nil values here because a real PVE/QGA response may omit them.
	snapshot := observation.Snapshot{
		SchemaVersion: 1, Mode: "production", AgentRef: "agent-fixture", CollectorRef: "collector-fixture",
		ClusterRef: "cluster-fixture", NodeRef: "node-fixture", Site: "test-site", ObservedAt: now,
		PVEVersion: pve.Version{Version: "9.0", Release: "9.0", RepoID: "pve-no-subscription"},
		Components: map[string]observation.Availability{
			"pve":              {Available: true, ObservedAt: now, FreshUntil: now.Add(time.Minute)},
			"smartctlExporter": {Available: true, ObservedAt: now, FreshUntil: now.Add(5 * time.Minute)},
		},
		Tasks: nil,
		Guests: []observation.Guest{
			{VMID: 101, GuestType: "qemu", Name: "guest-with-qga", Node: "node-fixture", ObservedAt: now,
				PVE: observation.PVEGuestView{Availability: observation.Availability{Available: true, ObservedAt: now}, Status: "running"},
				QGA: observation.QGAView{Availability: observation.Availability{Available: true, ObservedAt: now, FreshUntil: now.Add(time.Minute)}, Info: &pve.GuestAgentInfo{Version: "8.2.0"}}},
			{VMID: 102, GuestType: "qemu", Name: "guest-without-qga", Node: "node-fixture", ObservedAt: now,
				PVE: observation.PVEGuestView{Availability: observation.Availability{Available: true, ObservedAt: now}, Status: "running"},
				QGA: observation.QGAView{Availability: observation.Availability{Available: false, ObservedAt: now, UnavailableReason: "guest-agent-unavailable"}}},
		},
	}
	originalInfo := snapshot.Guests[0].QGA.Info
	if originalInfo == nil || originalInfo.SupportedCommands != nil {
		t.Fatalf("fixture no longer exercises nil supported_commands: %#v", originalInfo)
	}

	batch, err := BuildMonitoringTelemetry(snapshot, nil, MonitoringBuildContext{
		BindingID: "550e8400-e29b-41d4-a716-446655440001", MonitoringAgentRef: "monitor-agent-fixture",
		DeviceID: "device-fixture", CredentialEpoch: 1, BootID: "550e8400-e29b-41d4-a716-446655440002",
		Sequence: 1, AgentVersion: "0.1.0-rc.13", SourceRef: "source-fixture", SentAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if originalInfo.SupportedCommands != nil {
		t.Fatal("monitoring projection mutated the collector snapshot")
	}
	if got := batch.Components["smartctlExporter"].FreshUntil; got == nil || !got.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("monitoring projection changed the collector freshness horizon: %v", got)
	}
	if got := batch.Guests[1].QGA.Availability; got.ObservedAt == nil || !got.ObservedAt.Equal(now) || got.FreshUntil != nil {
		t.Fatalf("unavailable QGA timestamps were not canonicalized: %#v", got)
	}
	if got := batch.Guests[1].Capabilities.Lifecycle; got.ObservedAt != nil || got.FreshUntil != nil {
		t.Fatalf("zero capability timestamps were not omitted: %#v", got)
	}

	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(`"supported_commands":null`)) {
		t.Fatalf("monitoring payload still contains null supported_commands: %s", raw)
	}
	if !bytes.Contains(raw, []byte(`"supported_commands":[]`)) {
		t.Fatalf("monitoring payload does not contain the required empty array: %s", raw)
	}
	if !bytes.Contains(raw, []byte(`"tasks":[]`)) {
		t.Fatalf("monitoring payload does not normalize nil tasks to []: %s", raw)
	}
	if bytes.Contains(raw, []byte(`"components":null`)) {
		t.Fatalf("monitoring payload contains a null required object: %s", raw)
	}
	if bytes.Contains(raw, []byte(`0001-01-01`)) {
		t.Fatalf("monitoring payload contains a Go zero timestamp: %s", raw)
	}
}

func TestMonitoringGuestAgentInfoPreservesSupportedCommands(t *testing.T) {
	input := &pve.GuestAgentInfo{Version: "8.2.0", SupportedCommands: []pve.GuestAgentCommand{{Name: "guest-ping", Enabled: true}}}
	output := monitoringGuestAgentInfo(input)
	if output == input {
		t.Fatal("monitoring projection reused the collector-owned info pointer")
	}
	if len(output.SupportedCommands) != 1 || output.SupportedCommands[0] != input.SupportedCommands[0] {
		t.Fatalf("supported command was not preserved: %#v", output.SupportedCommands)
	}
	output.SupportedCommands[0].Name = "changed"
	if input.SupportedCommands[0].Name != "guest-ping" {
		t.Fatal("monitoring projection reused the collector-owned supported command slice")
	}
}

func TestMonitoringGuestAgentInfoNormalizesPVENullAndMissingCommands(t *testing.T) {
	for _, input := range []string{
		`{"version":"8.2.0"}`,
		`{"version":"8.2.0","supported_commands":null}`,
	} {
		var info pve.GuestAgentInfo
		if err := json.Unmarshal([]byte(input), &info); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(monitoringGuestAgentInfo(&info))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(raw, []byte(`"supported_commands":[]`)) {
			t.Fatalf("PVE info %s was not normalized for monitoring: %s", input, raw)
		}
	}
}
