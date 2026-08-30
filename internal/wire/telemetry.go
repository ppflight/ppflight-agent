// Package wire builds the new dual-source telemetry payload and the existing
// moniter.ppflight.com CollectorEnvelope compatibility bridge.
package wire

import (
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ppflight/ppflight-agent/internal/inventory"
	"github.com/ppflight/ppflight-agent/internal/observation"
	"github.com/ppflight/ppflight-agent/internal/protocol"
)

type WebsiteTelemetryBatch struct {
	SchemaVersion int              `json:"schemaVersion"`
	BatchID       string           `json:"batchId"`
	AgentRef      string           `json:"agentRef"`
	CollectorRef  string           `json:"collectorRef"`
	SourceRef     string           `json:"sourceRef"`
	ClusterRef    string           `json:"clusterRef"`
	Mode          string           `json:"mode"`
	Sequence      protocol.Counter `json:"sequence"`
	ObservedAt    time.Time        `json:"observedAt"`
	// SentAt is fixed when the durable payload is created. The receiver adds
	// receivedAt; retries keep the same body and batch ID.
	SentAt     time.Time                           `json:"sentAt"`
	PVEVersion any                                 `json:"pveVersion"`
	Components map[string]observation.Availability `json:"components"`
	Nodes      []observation.Node                  `json:"nodes"`
	Storages   []observation.Storage               `json:"storages"`
	Tasks      []observation.Task                  `json:"tasks"`
	Guests     []WebsiteGuest                      `json:"guests"`
	Host       any                                 `json:"host,omitempty"`
	SMART      any                                 `json:"smart,omitempty"`
}

type WebsiteGuest struct {
	Managed      bool                  `json:"managed"`
	Identity     *inventory.Assignment `json:"identity,omitempty"`
	VMID         int                   `json:"vmid"`
	GuestType    string                `json:"guestType"`
	Name         string                `json:"name"`
	Node         string                `json:"node"`
	Template     bool                  `json:"template"`
	PVE          WebsitePVEGuestView   `json:"pveObserved"`
	QGA          observation.QGAView   `json:"guestObserved"`
	Networks     []WebsiteNetwork      `json:"networks,omitempty"`
	Capabilities GuestCapabilities     `json:"capabilities"`
	ObservedAt   time.Time             `json:"observedAt"`
}

type WebsiteNetwork struct {
	observation.Network
	Binding     *inventory.NICBinding `json:"binding,omitempty"`
	PolicyMatch inventory.Capability  `json:"policyMatch"`
}

type GuestCapabilities struct {
	Lifecycle          ActionCapability     `json:"lifecycle"`
	RootPasswordReset  ActionCapability     `json:"rootPasswordReset"`
	GuestNetworkVerify ActionCapability     `json:"guestNetworkVerify"`
	Metering           inventory.Capability `json:"metering"`
}

// ActionCapability is an APP-facing availability snapshot. The command worker
// performs a fresh QGA preflight again immediately before every mutation.
type ActionCapability struct {
	Available          bool      `json:"available"`
	Reason             string    `json:"reason,omitempty"`
	ObservedAt         time.Time `json:"observedAt,omitempty"`
	FreshUntil         time.Time `json:"freshUntil,omitempty"`
	ExecutionPreflight bool      `json:"executionPreflight"`
}

// WebsitePVEGuestView string-encodes cumulative counters so a JavaScript API
// cannot lose precision before the values reach storage. Capacity/gauge values
// remain ordinary JSON numbers and are never used by the billing ledger.
type WebsitePVEGuestView struct {
	Availability  observation.Availability `json:"availability"`
	Status        string                   `json:"status"`
	CPU           *float64                 `json:"cpuRatio,omitempty"`
	CPUCount      *float64                 `json:"cpuCount,omitempty"`
	MemoryUsed    *uint64                  `json:"memoryUsedBytes,omitempty"`
	MemoryTotal   *uint64                  `json:"memoryTotalBytes,omitempty"`
	DiskUsed      *uint64                  `json:"diskUsedBytes,omitempty"`
	DiskTotal     *uint64                  `json:"diskTotalBytes,omitempty"`
	DiskRead      *protocol.Counter        `json:"diskReadBytesTotal,omitempty"`
	DiskWrite     *protocol.Counter        `json:"diskWriteBytesTotal,omitempty"`
	IngressBytes  *protocol.Counter        `json:"ingressBytesTotal,omitempty"`
	EgressBytes   *protocol.Counter        `json:"egressBytesTotal,omitempty"`
	UptimeSeconds *uint64                  `json:"uptimeSeconds,omitempty"`
}

func BuildWebsiteTelemetry(snapshot observation.Snapshot, assignments *inventory.Store, sourceRef string, sequence uint64) (WebsiteTelemetryBatch, error) {
	return BuildWebsiteTelemetryAt(snapshot, assignments, sourceRef, sequence, time.Now().UTC())
}

// BuildWebsiteTelemetryAt is the deterministic form used when the caller has
// already captured the payload creation timestamp.
func BuildWebsiteTelemetryAt(snapshot observation.Snapshot, assignments *inventory.Store, sourceRef string, sequence uint64, sentAt time.Time) (WebsiteTelemetryBatch, error) {
	if sentAt.IsZero() {
		return WebsiteTelemetryBatch{}, fmt.Errorf("telemetry sentAt is required")
	}
	batchID, err := protocol.NewID()
	if err != nil {
		return WebsiteTelemetryBatch{}, err
	}
	result := WebsiteTelemetryBatch{
		SchemaVersion: 1, BatchID: batchID, AgentRef: snapshot.AgentRef, CollectorRef: snapshot.CollectorRef,
		SourceRef: sourceRef, ClusterRef: snapshot.ClusterRef, Mode: snapshot.Mode,
		Sequence: protocol.Counter(sequence), ObservedAt: snapshot.ObservedAt, SentAt: sentAt.UTC(), PVEVersion: snapshot.PVEVersion,
		Components: snapshot.Components, Nodes: snapshot.Nodes, Storages: snapshot.Storages,
		Tasks: snapshot.Tasks, Host: snapshot.Host, SMART: snapshot.SMART,
	}
	for _, guest := range snapshot.Guests {
		item := WebsiteGuest{VMID: guest.VMID, GuestType: guest.GuestType, Name: guest.Name, Node: guest.Node, Template: guest.Template, PVE: websitePVEView(guest.PVE), QGA: guest.QGA, Networks: websiteNetworks(guest.Networks, nil), Capabilities: guestCapabilities(guest, nil, sentAt), ObservedAt: guest.ObservedAt}
		if assignments != nil {
			if assignment, ok := assignments.Lookup(snapshot.ClusterRef, guest.GuestType, guest.VMID); ok {
				copyValue := assignment
				item.Managed, item.Identity = true, &copyValue
				item.Networks = websiteNetworks(guest.Networks, assignment.NICBindings)
				item.Capabilities = guestCapabilities(guest, &assignment, sentAt)
			}
		}
		result.Guests = append(result.Guests, item)
	}
	return result, nil
}

func guestCapabilities(guest observation.Guest, assignment *inventory.Assignment, now time.Time) GuestCapabilities {
	result := GuestCapabilities{Lifecycle: ActionCapability{Available: true}}
	if assignment == nil {
		result.Metering = inventory.Capability{Reason: "assignment_required", Source: "pve-guest-aggregate"}
	} else {
		result.Metering = assignment.AggregateMeteringCapability()
	}
	if guest.GuestType != "qemu" {
		result.RootPasswordReset = ActionCapability{Reason: "lxc_password_reset_not_implemented"}
		result.GuestNetworkVerify = ActionCapability{Reason: "qga_not_applicable"}
		return result
	}
	availability := guest.QGA.Availability
	qga := ActionCapability{ObservedAt: availability.ObservedAt, FreshUntil: availability.FreshUntil, ExecutionPreflight: true}
	switch {
	case !availability.Available:
		qga.Reason = firstNonempty(availability.UnavailableReason, "qga_unavailable")
	case availability.FreshUntil.IsZero():
		qga.Reason = "qga_freshness_unknown"
	case now.After(availability.FreshUntil):
		qga.Reason = "qga_stale"
	default:
		qga.Available = true
	}
	result.RootPasswordReset, result.GuestNetworkVerify = qga, qga
	return result
}

func websiteNetworks(observed []observation.Network, bindings []inventory.NICBinding) []WebsiteNetwork {
	result := make([]WebsiteNetwork, 0, len(observed)+len(bindings))
	byInterface := make(map[string]inventory.NICBinding, len(bindings))
	for _, binding := range bindings {
		byInterface[binding.Interface] = binding
	}
	seen := make(map[string]bool, len(observed))
	for _, network := range observed {
		if network.Interface == "" {
			network.Interface = "net" + strconv.Itoa(network.Index)
		}
		item := WebsiteNetwork{Network: network, PolicyMatch: inventory.Capability{Reason: "binding_missing", Source: "pve-config"}}
		if binding, ok := byInterface[network.Interface]; ok {
			copyValue := binding
			item.Binding = &copyValue
			item.PolicyMatch = matchNetworkPolicy(network, binding)
			seen[network.Interface] = true
		}
		result = append(result, item)
	}
	for _, binding := range bindings {
		if seen[binding.Interface] {
			continue
		}
		copyValue := binding
		result = append(result, WebsiteNetwork{
			Network: observation.Network{Interface: binding.Interface}, Binding: &copyValue,
			PolicyMatch: inventory.Capability{Reason: "interface_missing", Source: "pve-config"},
		})
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].Interface < result[j].Interface })
	return result
}

func matchNetworkPolicy(observed observation.Network, binding inventory.NICBinding) inventory.Capability {
	attachment := binding.Bridge
	if binding.VNet != "" {
		attachment = binding.VNet
	}
	switch {
	case !strings.EqualFold(observed.MAC, binding.ExpectedMAC):
		return inventory.Capability{Reason: "mac_mismatch", Source: "pve-config"}
	case observed.Bridge != attachment:
		return inventory.Capability{Reason: "attachment_mismatch", Source: "pve-config"}
	case binding.VLAN != nil && observed.VLAN != strconv.Itoa(*binding.VLAN):
		return inventory.Capability{Reason: "vlan_mismatch", Source: "pve-config"}
	case binding.MTU != nil && observed.MTU != strconv.Itoa(*binding.MTU):
		return inventory.Capability{Reason: "mtu_mismatch", Source: "pve-config"}
	case binding.IPFilterPolicy == "required" && observed.Firewall != "1":
		return inventory.Capability{Reason: "nic_firewall_disabled", Source: "pve-config"}
	default:
		return inventory.Capability{Supported: true, Source: "pve-config"}
	}
}

func websitePVEView(value observation.PVEGuestView) WebsitePVEGuestView {
	return WebsitePVEGuestView{
		Availability: value.Availability, Status: value.Status, CPU: value.CPU, CPUCount: value.CPUCount,
		MemoryUsed: value.MemoryUsed, MemoryTotal: value.MemoryTotal, DiskUsed: value.DiskUsed, DiskTotal: value.DiskTotal,
		DiskRead: counterPointer(value.DiskRead), DiskWrite: counterPointer(value.DiskWrite),
		IngressBytes: counterPointer(value.IngressBytes), EgressBytes: counterPointer(value.EgressBytes), UptimeSeconds: value.UptimeSeconds,
	}
}

func counterPointer(value *uint64) *protocol.Counter {
	if value == nil {
		return nil
	}
	result := protocol.Counter(*value)
	return &result
}

// The following structs intentionally mirror control-plane/lib/contracts.ts.
type LegacyEnvelope struct {
	SchemaVersion int               `json:"schemaVersion"`
	BatchID       string            `json:"batchId"`
	BootID        string            `json:"bootId"`
	Sequence      uint64            `json:"sequence"`
	ObservedAt    time.Time         `json:"observedAt"`
	SentAt        time.Time         `json:"sentAt"`
	Collector     LegacyCollector   `json:"collector"`
	Devices       []LegacyDevice    `json:"devices"`
	Nodes         []LegacyNode      `json:"nodes"`
	Storages      []LegacyStorage   `json:"storages"`
	Drives        []LegacyDrive     `json:"drives"`
	Interfaces    []LegacyInterface `json:"interfaces"`
	BGPSessions   []any             `json:"bgpSessions"`
	Instances     []LegacyInstance  `json:"instances"`
	Probes        []any             `json:"probes"`
	Alerts        []LegacyAlert     `json:"alerts"`
}

type LegacyCollector struct {
	ID               string  `json:"id"`
	Version          string  `json:"version"`
	Status           string  `json:"status"`
	SamplesPerSecond float64 `json:"samplesPerSecond"`
	ConfigRevision   int     `json:"configRevision"`
}
type LegacyDevice struct {
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	Kind     string         `json:"kind"`
	Address  string         `json:"address"`
	Site     string         `json:"site,omitempty"`
	Status   string         `json:"status,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}
type LegacyNode struct {
	ID, DeviceID, Cluster, Name, Role, Status string
	CPURatio                                  float64
	MemoryUsedBytes, MemoryTotalBytes         uint64
	SwapUsedBytes, UptimeSeconds              uint64
	Metadata                                  map[string]any
	ObservedAt                                time.Time
}

func (n LegacyNode) MarshalJSON() ([]byte, error) {
	type node struct {
		ID               string         `json:"id"`
		DeviceID         string         `json:"deviceId"`
		Cluster          string         `json:"cluster,omitempty"`
		Name             string         `json:"name"`
		Role             string         `json:"role,omitempty"`
		Status           string         `json:"status,omitempty"`
		CPURatio         float64        `json:"cpuRatio,omitempty"`
		MemoryUsedBytes  uint64         `json:"memoryUsedBytes,omitempty"`
		MemoryTotalBytes uint64         `json:"memoryTotalBytes,omitempty"`
		SwapUsedBytes    uint64         `json:"swapUsedBytes,omitempty"`
		UptimeSeconds    uint64         `json:"uptimeSeconds,omitempty"`
		Metadata         map[string]any `json:"metadata,omitempty"`
		ObservedAt       time.Time      `json:"observedAt"`
	}
	return marshal(node{n.ID, n.DeviceID, n.Cluster, n.Name, n.Role, n.Status, n.CPURatio, n.MemoryUsedBytes, n.MemoryTotalBytes, n.SwapUsedBytes, n.UptimeSeconds, n.Metadata, n.ObservedAt})
}

type LegacyStorage struct {
	ID         string         `json:"id"`
	DeviceID   string         `json:"deviceId"`
	Cluster    string         `json:"cluster,omitempty"`
	Node       string         `json:"node,omitempty"`
	Name       string         `json:"name"`
	Kind       string         `json:"kind,omitempty"`
	Status     string         `json:"status,omitempty"`
	UsedBytes  uint64         `json:"usedBytes,omitempty"`
	TotalBytes uint64         `json:"totalBytes,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	ObservedAt time.Time      `json:"observedAt"`
}
type LegacyDrive struct {
	ID                 string         `json:"id"`
	DeviceID           string         `json:"deviceId"`
	Node               string         `json:"node,omitempty"`
	Name               string         `json:"name"`
	DevicePath         string         `json:"devicePath"`
	SerialNumber       string         `json:"serialNumber,omitempty"`
	Model              string         `json:"model,omitempty"`
	Protocol           string         `json:"protocol,omitempty"`
	Status             string         `json:"status,omitempty"`
	SmartPassed        *bool          `json:"smartPassed,omitempty"`
	TemperatureCelsius *float64       `json:"temperatureCelsius,omitempty"`
	MediaErrors        *float64       `json:"mediaErrors,omitempty"`
	PercentageUsed     *float64       `json:"percentageUsed,omitempty"`
	CapacityBytes      *float64       `json:"capacityBytes,omitempty"`
	Metadata           map[string]any `json:"metadata,omitempty"`
	ObservedAt         time.Time      `json:"observedAt"`
}
type LegacyInterface struct {
	ID         string         `json:"id"`
	DeviceID   string         `json:"deviceId"`
	Name       string         `json:"name"`
	Scope      string         `json:"scope,omitempty"`
	Status     string         `json:"status,omitempty"`
	RXBytes    string         `json:"rxBytes,omitempty"`
	TXBytes    string         `json:"txBytes,omitempty"`
	RXErrors   float64        `json:"rxErrors,omitempty"`
	TXErrors   float64        `json:"txErrors,omitempty"`
	RXDrops    float64        `json:"rxDrops,omitempty"`
	TXDrops    float64        `json:"txDrops,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	ObservedAt time.Time      `json:"observedAt"`
}
type LegacyInstance struct {
	ID               string          `json:"id"`
	DeviceID         string          `json:"deviceId"`
	Site             string          `json:"site,omitempty"`
	VMID             int             `json:"vmid"`
	Name             string          `json:"name"`
	PrimaryIP        string          `json:"primaryIp,omitempty"`
	Addresses        []LegacyAddress `json:"addresses,omitempty"`
	InstanceType     string          `json:"instanceType,omitempty"`
	Cluster          string          `json:"cluster"`
	Node             string          `json:"node"`
	Status           string          `json:"status,omitempty"`
	Metadata         map[string]any  `json:"metadata,omitempty"`
	CollectedAt      time.Time       `json:"collectedAt"`
	CPURatio         float64         `json:"cpuRatio,omitempty"`
	MemoryUsedBytes  uint64          `json:"memoryUsedBytes,omitempty"`
	MemoryTotalBytes uint64          `json:"memoryTotalBytes,omitempty"`
	DiskUsedBytes    uint64          `json:"diskUsedBytes,omitempty"`
	DiskTotalBytes   uint64          `json:"diskTotalBytes,omitempty"`
	DiskReadBytes    uint64          `json:"diskReadBytes,omitempty"`
	DiskWriteBytes   uint64          `json:"diskWriteBytes,omitempty"`
	NetworkRXBytes   string          `json:"networkRxBytes,omitempty"`
	NetworkTXBytes   string          `json:"networkTxBytes,omitempty"`
	UptimeSeconds    uint64          `json:"uptimeSeconds,omitempty"`
}
type LegacyAddress struct {
	Address string `json:"address"`
	Role    string `json:"role,omitempty"`
	Source  string `json:"source,omitempty"`
}
type LegacyAlert struct {
	Fingerprint string `json:"fingerprint"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Source      string `json:"source"`
	Detail      string `json:"detail,omitempty"`
	Kind        string `json:"kind,omitempty"`
	Status      string `json:"status,omitempty"`
}

func BuildLegacy(snapshot observation.Snapshot, assignments *inventory.Store, bootID string, sequence uint64, version string, now time.Time) (LegacyEnvelope, error) {
	if sequence > 1<<53-1 {
		return LegacyEnvelope{}, fmt.Errorf("legacy sequence exceeds JavaScript safe integer")
	}
	batchID, err := protocol.NewID()
	if err != nil {
		return LegacyEnvelope{}, err
	}
	deviceID := snapshot.CollectorRef + ":pve:" + snapshot.ClusterRef
	status := "healthy"
	if pveState, ok := snapshot.Components["pve"]; !ok || !pveState.Available {
		status = "degraded"
	}
	result := LegacyEnvelope{
		SchemaVersion: 1, BatchID: batchID, BootID: bootID, Sequence: sequence,
		ObservedAt: snapshot.ObservedAt, SentAt: now.UTC(),
		Collector:   LegacyCollector{ID: snapshot.CollectorRef, Version: version, Status: status, ConfigRevision: 1},
		Devices:     []LegacyDevice{{ID: deviceID, Name: snapshot.ClusterRef, Kind: "proxmox", Address: "local-agent", Site: snapshot.Site, Status: status, Metadata: map[string]any{"agentRef": snapshot.AgentRef, "nodeRef": snapshot.NodeRef, "sourceRef": "ppflight-agent"}}},
		BGPSessions: []any{}, Probes: []any{},
	}
	for _, node := range snapshot.Nodes {
		item := LegacyNode{ID: deviceID + ":node:" + node.Name, DeviceID: deviceID, Cluster: snapshot.ClusterRef, Name: node.Name, Role: "compute", Status: node.Status, ObservedAt: node.ObservedAt, Metadata: map[string]any{"cpuModel": node.CPUModel, "pveVersion": node.PVEVersion, "loadAverage": node.LoadAverage}}
		item.CPURatio, item.MemoryUsedBytes, item.MemoryTotalBytes, item.SwapUsedBytes, item.UptimeSeconds = floatValue(node.CPU), uintValue(node.MemoryUsed), uintValue(node.MemoryTotal), uintValue(node.SwapUsed), uintValue(node.UptimeSeconds)
		result.Nodes = append(result.Nodes, item)
	}
	for _, storage := range snapshot.Storages {
		result.Storages = append(result.Storages, LegacyStorage{ID: deviceID + ":storage:" + safeID(storage.Node) + ":" + safeID(storage.Name), DeviceID: deviceID, Cluster: snapshot.ClusterRef, Node: storage.Node, Name: storage.Name, Kind: storage.Kind, Status: storage.Status, UsedBytes: uintValue(storage.UsedBytes), TotalBytes: uintValue(storage.TotalBytes), Metadata: map[string]any{"shared": storage.Shared, "content": storage.Content}, ObservedAt: storage.ObservedAt})
	}
	if snapshot.SMART != nil {
		for _, drive := range snapshot.SMART.Devices {
			passed := boolFromMetric(drive.Healthy.Value)
			status := "unknown"
			if passed != nil && *passed {
				status = "online"
			} else if passed != nil {
				status = "failed"
			}
			result.Drives = append(result.Drives, LegacyDrive{ID: deviceID + ":drive:" + safeID(firstNonempty(drive.Serial, drive.Device)), DeviceID: deviceID, Node: snapshot.NodeRef, Name: firstNonempty(drive.Model, drive.Device), DevicePath: drive.Device, SerialNumber: drive.Serial, Model: drive.Model, Protocol: drive.Protocol, Status: status, SmartPassed: passed, TemperatureCelsius: drive.TemperatureCelsius.Value, MediaErrors: drive.MediaErrors.Value, PercentageUsed: drive.PercentageUsed.Value, CapacityBytes: drive.CapacityBytes.Value, Metadata: map[string]any{"source": "smartctl_exporter"}, ObservedAt: snapshot.SMART.ObservedAt})
		}
	}
	if snapshot.Host != nil {
		for _, item := range snapshot.Host.Interfaces {
			state := "unknown"
			if item.LinkUp.Value != nil && *item.LinkUp.Value == 1 {
				state = "online"
			} else if item.LinkUp.Value != nil {
				state = "down"
			}
			result.Interfaces = append(result.Interfaces, LegacyInterface{ID: deviceID + ":interface:" + safeID(item.Device), DeviceID: deviceID, Name: item.Device, Scope: "internal", Status: state, RXBytes: decimalMetric(item.ReceiveBytes.Value), TXBytes: decimalMetric(item.TransmitBytes.Value), RXErrors: metric(item.ReceiveErrors.Value), TXErrors: metric(item.TransmitErrors.Value), RXDrops: metric(item.ReceiveDrops.Value), TXDrops: metric(item.TransmitDrops.Value), Metadata: map[string]any{"source": "node_exporter"}, ObservedAt: snapshot.Host.ObservedAt})
		}
	}
	for _, guest := range snapshot.Guests {
		identityID := fmt.Sprintf("unmanaged:%s:%d", guest.GuestType, guest.VMID)
		metadata := map[string]any{"managed": false, "pveSource": "pve", "qgaAvailable": guest.QGA.Availability.Available, "generation": 0}
		if assignments != nil {
			if assignment, ok := assignments.Lookup(snapshot.ClusterRef, guest.GuestType, guest.VMID); ok {
				identityID = assignment.InstanceUUID
				metadata = map[string]any{"managed": true, "serviceRef": assignment.ServiceRef, "instanceUuid": assignment.InstanceUUID, "generation": assignment.Generation, "billingState": assignment.BillingState, "pveSource": "pve", "qgaAvailable": guest.QGA.Availability.Available}
			}
		}
		addresses := guestAddresses(guest)
		primary := ""
		if len(addresses) > 0 {
			primary = addresses[0].Address
		}
		networkRX, networkTX := "", ""
		if snapshot.Mode != "test" {
			networkRX, networkTX = decimal(guest.PVE.IngressBytes), decimal(guest.PVE.EgressBytes)
		}
		result.Instances = append(result.Instances, LegacyInstance{
			ID: deviceID + ":instance:" + identityID, DeviceID: deviceID, Site: snapshot.Site, VMID: guest.VMID, Name: guest.Name,
			PrimaryIP: primary, Addresses: addresses, InstanceType: guest.GuestType, Cluster: snapshot.ClusterRef, Node: guest.Node,
			Status: guest.PVE.Status, Metadata: metadata, CollectedAt: guest.ObservedAt,
			CPURatio: floatValue(guest.PVE.CPU), MemoryUsedBytes: uintValue(guest.PVE.MemoryUsed), MemoryTotalBytes: uintValue(guest.PVE.MemoryTotal),
			DiskUsedBytes: uintValue(guest.PVE.DiskUsed), DiskTotalBytes: uintValue(guest.PVE.DiskTotal), DiskReadBytes: uintValue(guest.PVE.DiskRead), DiskWriteBytes: uintValue(guest.PVE.DiskWrite),
			NetworkRXBytes: networkRX, NetworkTXBytes: networkTX, UptimeSeconds: uintValue(guest.PVE.UptimeSeconds),
		})
	}
	for component, state := range snapshot.Components {
		if state.Available {
			continue
		}
		result.Alerts = append(result.Alerts, LegacyAlert{Fingerprint: "ppflight-agent-component:" + snapshot.AgentRef + ":" + component, Severity: "warning", Title: component + "采集不可用", Source: snapshot.AgentRef, Detail: state.UnavailableReason, Kind: "collector", Status: "firing"})
	}
	return result, nil
}

func guestAddresses(guest observation.Guest) []LegacyAddress {
	seen := map[string]bool{}
	var result []LegacyAddress
	for _, iface := range guest.QGA.Interfaces {
		for _, address := range iface.IPAddresses {
			ip := net.ParseIP(address.Address)
			if ip == nil || ip.IsLoopback() || seen[address.Address] {
				continue
			}
			seen[address.Address] = true
			role := "additional"
			if len(result) == 0 {
				role = "primary"
			}
			result = append(result, LegacyAddress{Address: address.Address, Role: role, Source: "qga"})
		}
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Role == result[j].Role {
			return result[i].Address < result[j].Address
		}
		return result[i].Role == "primary"
	})
	return result
}

func decimal(value *uint64) string {
	if value == nil {
		return ""
	}
	return strconv.FormatUint(*value, 10)
}
func decimalMetric(value *float64) string {
	if value == nil || *value < 0 || *value > math.MaxUint64 {
		return ""
	}
	return strconv.FormatUint(uint64(*value), 10)
}
func uintValue(value *uint64) uint64 {
	if value == nil {
		return 0
	}
	return *value
}
func floatValue(value *float64) float64 {
	if value == nil {
		return 0
	}
	return *value
}
func metric(value *float64) float64 {
	if value == nil {
		return 0
	}
	return *value
}
func boolFromMetric(value *float64) *bool {
	if value == nil {
		return nil
	}
	result := *value == 1
	return &result
}
func safeID(value string) string {
	result := ""
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			result += string(r)
		} else {
			result += "-"
		}
	}
	if result == "" {
		return "unknown"
	}
	return result
}
func firstNonempty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return "unknown"
}
