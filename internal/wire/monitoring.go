package wire

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ppflight/ppflight-agent/internal/exporter"
	"github.com/ppflight/ppflight-agent/internal/inventory"
	"github.com/ppflight/ppflight-agent/internal/observation"
	"github.com/ppflight/ppflight-agent/internal/protocol"
	"github.com/ppflight/ppflight-agent/internal/pve"
)

var (
	monitoringSafeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{1,191}$`)
	monitoringUUID   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
)

// MonitoringBuildContext carries the monitoring trust-domain identity.  The
// website identity is deliberately nested as Source below and is never used
// by the monitoring receiver for authorization.
type MonitoringBuildContext struct {
	BindingID          string
	MonitoringAgentRef string
	DeviceID           string
	CredentialEpoch    uint64
	BootID             string
	Sequence           uint64
	AgentVersion       string
	SourceRef          string
	SentAt             time.Time
	AgentHealth        MonitoringAgentHealth
}

type MonitoringTelemetryBatch struct {
	SchemaVersion      int                               `json:"schemaVersion"`
	BatchID            string                            `json:"batchId"`
	BindingID          string                            `json:"bindingId"`
	MonitoringAgentRef string                            `json:"monitoringAgentRef"`
	DeviceID           string                            `json:"deviceId"`
	CredentialEpoch    protocol.Counter                  `json:"credentialEpoch"`
	BootID             string                            `json:"bootId"`
	Sequence           protocol.Counter                  `json:"sequence"`
	ObservedAt         time.Time                         `json:"observedAt"`
	SentAt             time.Time                         `json:"sentAt"`
	Source             MonitoringSource                  `json:"source"`
	PVEVersion         pve.Version                       `json:"pveVersion"`
	Components         map[string]MonitoringAvailability `json:"components"`
	Nodes              []MonitoringNode                  `json:"nodes"`
	Storages           []MonitoringStorage               `json:"storages"`
	Tasks              []observation.Task                `json:"tasks"`
	Guests             []MonitoringGuest                 `json:"guests"`
	Host               *MonitoringHost                   `json:"host,omitempty"`
	SMART              *MonitoringSMART                  `json:"smart,omitempty"`
	AgentHealth        MonitoringAgentHealth             `json:"agentHealth"`
}

// MonitoringAvailability is the canonical telemetry-v1 representation. Go's
// time.Time zero value is not removed by omitempty, so pointers are required
// to distinguish an absent observation/freshness timestamp from year 1.
type MonitoringAvailability struct {
	Available         bool       `json:"available"`
	ObservedAt        *time.Time `json:"observedAt,omitempty"`
	FreshUntil        *time.Time `json:"freshUntil,omitempty"`
	UnavailableReason string     `json:"unavailableReason,omitempty"`
}

type MonitoringSource struct {
	WebsiteAgentRef string `json:"websiteAgentRef"`
	CollectorRef    string `json:"collectorRef"`
	SourceRef       string `json:"sourceRef"`
	ClusterRef      string `json:"clusterRef"`
	NodeRef         string `json:"nodeRef"`
	Site            string `json:"site"`
	Mode            string `json:"mode"`
	AgentVersion    string `json:"agentVersion"`
}

// Every PVE byte/capacity/uptime value is a Counter, including gauges.  This
// avoids an accidental JavaScript number round-trip in the monitoring API.
type MonitoringNode struct {
	Name          string            `json:"name"`
	Status        string            `json:"status"`
	CPU           *float64          `json:"cpuRatio,omitempty"`
	CPUCount      *int              `json:"cpuCount,omitempty"`
	CPUModel      string            `json:"cpuModel,omitempty"`
	MemoryUsed    *protocol.Counter `json:"memoryUsedBytes,omitempty"`
	MemoryTotal   *protocol.Counter `json:"memoryTotalBytes,omitempty"`
	SwapUsed      *protocol.Counter `json:"swapUsedBytes,omitempty"`
	SwapTotal     *protocol.Counter `json:"swapTotalBytes,omitempty"`
	RootUsed      *protocol.Counter `json:"rootUsedBytes,omitempty"`
	RootTotal     *protocol.Counter `json:"rootTotalBytes,omitempty"`
	LoadAverage   []float64         `json:"loadAverage,omitempty"`
	UptimeSeconds *protocol.Counter `json:"uptimeSeconds,omitempty"`
	IOWaitRatio   *float64          `json:"ioWaitRatio,omitempty"`
	PVEVersion    string            `json:"pveVersion,omitempty"`
	ObservedAt    time.Time         `json:"observedAt"`
}

type MonitoringStorage struct {
	Node       string            `json:"node"`
	Name       string            `json:"name"`
	Kind       string            `json:"kind"`
	Content    string            `json:"content,omitempty"`
	Status     string            `json:"status"`
	Shared     bool              `json:"shared"`
	UsedBytes  *protocol.Counter `json:"usedBytes,omitempty"`
	TotalBytes *protocol.Counter `json:"totalBytes,omitempty"`
	FreeBytes  *protocol.Counter `json:"freeBytes,omitempty"`
	ObservedAt time.Time         `json:"observedAt"`
}

type MonitoringAssignment struct {
	ServiceRef   string                 `json:"serviceRef"`
	ClusterRef   string                 `json:"clusterRef"`
	NodeRef      string                 `json:"nodeRef,omitempty"`
	VMID         int                    `json:"vmid"`
	Generation   protocol.Counter       `json:"generation"`
	InstanceUUID string                 `json:"instanceUuid"`
	GuestType    string                 `json:"guestType"`
	BillingState string                 `json:"billingState"`
	CutoverAt    *time.Time             `json:"cutoverAt,omitempty"`
	NICBindings  []inventory.NICBinding `json:"nicBindings,omitempty"`
}

type MonitoringGuest struct {
	Managed           bool                        `json:"managed"`
	Identity          *MonitoringAssignment       `json:"identity,omitempty"`
	VMID              int                         `json:"vmid"`
	GuestType         string                      `json:"guestType"`
	Name              string                      `json:"name"`
	Node              string                      `json:"node"`
	Template          bool                        `json:"template"`
	PVE               MonitoringPVEGuest          `json:"pveObserved"`
	QGA               MonitoringQGA               `json:"guestObserved"`
	Networks          []WebsiteNetwork            `json:"networks"`
	Capabilities      MonitoringGuestCapabilities `json:"capabilities"`
	ObservedAt        time.Time                   `json:"observedAt"`
	NetworkProjection MonitoringNetworkProjection `json:"networkProjection"`
}

type MonitoringNetworkProjection struct {
	SchemaVersion           int                                `json:"schemaVersion"`
	Interfaces              []MonitoringProjectedInterface     `json:"interfaces"`
	UnmappedGuestInterfaces []MonitoringUnmappedGuestInterface `json:"unmappedGuestInterfaces"`
}

type MonitoringProjectedInterface struct {
	InterfaceRef         string                            `json:"interfaceRef"`
	MappingStatus        string                            `json:"mappingStatus"`
	Source               string                            `json:"source"`
	GuestInterfaceName   string                            `json:"guestInterfaceName,omitempty"`
	CanonicalMAC         string                            `json:"canonicalMac,omitempty"`
	MappingReason        string                            `json:"mappingReason,omitempty"`
	Addresses            []MonitoringGuestAddress          `json:"addresses"`
	ConfiguredAddressing *observation.ConfiguredAddressing `json:"configuredAddressing,omitempty"`
	Counters             MonitoringNICCounterAvailability  `json:"counters"`
}

type MonitoringNICCounterAvailability struct {
	Available bool              `json:"available"`
	Source    string            `json:"source"`
	Reason    string            `json:"reason,omitempty"`
	RXBytes   *protocol.Counter `json:"rxBytes,omitempty"`
	TXBytes   *protocol.Counter `json:"txBytes,omitempty"`
	RXPackets *protocol.Counter `json:"rxPackets,omitempty"`
	TXPackets *protocol.Counter `json:"txPackets,omitempty"`
}

type MonitoringUnmappedGuestInterface struct {
	Name            string                   `json:"name"`
	HardwareAddress string                   `json:"hardwareAddress"`
	CanonicalMAC    string                   `json:"canonicalMac,omitempty"`
	MappingStatus   string                   `json:"mappingStatus"`
	Reason          string                   `json:"reason"`
	Addresses       []MonitoringGuestAddress `json:"addresses"`
	Statistics      *MonitoringGuestNICStats `json:"statistics,omitempty"`
}

type MonitoringPVEGuest struct {
	Availability  MonitoringAvailability `json:"availability"`
	Status        string                 `json:"status"`
	CPU           *float64               `json:"cpuRatio,omitempty"`
	CPUCount      *float64               `json:"cpuCount,omitempty"`
	MemoryUsed    *protocol.Counter      `json:"memoryUsedBytes,omitempty"`
	MemoryTotal   *protocol.Counter      `json:"memoryTotalBytes,omitempty"`
	DiskUsed      *protocol.Counter      `json:"diskUsedBytes,omitempty"`
	DiskTotal     *protocol.Counter      `json:"diskTotalBytes,omitempty"`
	DiskRead      *protocol.Counter      `json:"diskReadBytesTotal,omitempty"`
	DiskWrite     *protocol.Counter      `json:"diskWriteBytesTotal,omitempty"`
	IngressBytes  *protocol.Counter      `json:"ingressBytesTotal,omitempty"`
	EgressBytes   *protocol.Counter      `json:"egressBytesTotal,omitempty"`
	UptimeSeconds *protocol.Counter      `json:"uptimeSeconds,omitempty"`
}

type MonitoringQGA struct {
	Availability MonitoringAvailability      `json:"availability"`
	Info         *pve.GuestAgentInfo         `json:"info,omitempty"`
	OS           *pve.GuestOSInfo            `json:"os,omitempty"`
	Filesystems  []MonitoringGuestFilesystem `json:"filesystems,omitempty"`
	Interfaces   []MonitoringGuestInterface  `json:"interfaces,omitempty"`
	Capabilities map[string]pve.Availability `json:"capabilities,omitempty"`
}

type MonitoringGuestCapabilities struct {
	Lifecycle          MonitoringActionCapability `json:"lifecycle"`
	RootPasswordReset  MonitoringActionCapability `json:"rootPasswordReset"`
	GuestNetworkVerify MonitoringActionCapability `json:"guestNetworkVerify"`
	Metering           inventory.Capability       `json:"metering"`
}

type MonitoringActionCapability struct {
	Available          bool       `json:"available"`
	Reason             string     `json:"reason,omitempty"`
	ObservedAt         *time.Time `json:"observedAt,omitempty"`
	FreshUntil         *time.Time `json:"freshUntil,omitempty"`
	ExecutionPreflight bool       `json:"executionPreflight"`
}

type MonitoringGuestFilesystem struct {
	Name       string            `json:"name"`
	Mountpoint string            `json:"mountpoint"`
	Type       string            `json:"type"`
	TotalBytes *protocol.Counter `json:"totalBytes,omitempty"`
	UsedBytes  *protocol.Counter `json:"usedBytes,omitempty"`
}

type MonitoringGuestInterface struct {
	Name            string                   `json:"name"`
	HardwareAddress string                   `json:"hardwareAddress"`
	IPAddresses     []MonitoringGuestAddress `json:"ipAddresses"`
	Statistics      *MonitoringGuestNICStats `json:"statistics,omitempty"`
}

type MonitoringGuestAddress struct {
	Address string `json:"address"`
	Prefix  int    `json:"prefix"`
	Type    string `json:"type"`
}

type MonitoringGuestNICStats struct {
	RXBytes   *protocol.Counter `json:"rxBytes,omitempty"`
	TXBytes   *protocol.Counter `json:"txBytes,omitempty"`
	RXPackets *protocol.Counter `json:"rxPackets,omitempty"`
	TXPackets *protocol.Counter `json:"txPackets,omitempty"`
}

// Exporter metrics stay decimal strings.  Raw Prometheus text is retained by
// exporter.Value, so a value above 2^53 is never reconstructed from float64.
type MonitoringMetric struct {
	Decimal string `json:"decimal"`
}

type MonitoringHost struct {
	ObservedAt           time.Time                  `json:"observedAt"`
	Load1                *MonitoringMetric          `json:"load1,omitempty"`
	MemoryTotalBytes     *MonitoringMetric          `json:"memoryTotalBytes,omitempty"`
	MemoryAvailableBytes *MonitoringMetric          `json:"memoryAvailableBytes,omitempty"`
	SwapTotalBytes       *MonitoringMetric          `json:"swapTotalBytes,omitempty"`
	SwapFreeBytes        *MonitoringMetric          `json:"swapFreeBytes,omitempty"`
	CPUSeconds           []MonitoringCPUSeconds     `json:"cpuSeconds,omitempty"`
	Filesystems          []MonitoringHostFilesystem `json:"filesystems,omitempty"`
	Interfaces           []MonitoringHostInterface  `json:"interfaces,omitempty"`
	Disks                []MonitoringHostDisk       `json:"disks,omitempty"`
	Pressure             []MonitoringPressure       `json:"pressure,omitempty"`
	HardwareTemperatures []MonitoringTemperature    `json:"hardwareTemperatures,omitempty"`
	ZFSPools             []MonitoringZFSPool        `json:"zfsPools,omitempty"`
}

type MonitoringCPUSeconds struct {
	CPU     string            `json:"cpu"`
	Mode    string            `json:"mode"`
	Seconds *MonitoringMetric `json:"seconds,omitempty"`
}
type MonitoringHostFilesystem struct {
	Device         string            `json:"device"`
	Mountpoint     string            `json:"mountpoint"`
	FSType         string            `json:"fsType,omitempty"`
	SizeBytes      *MonitoringMetric `json:"sizeBytes,omitempty"`
	AvailableBytes *MonitoringMetric `json:"availableBytes,omitempty"`
	ReadOnly       *MonitoringMetric `json:"readOnly,omitempty"`
}
type MonitoringHostInterface struct {
	Device         string            `json:"device"`
	ReceiveBytes   *MonitoringMetric `json:"receiveBytes,omitempty"`
	TransmitBytes  *MonitoringMetric `json:"transmitBytes,omitempty"`
	ReceiveErrors  *MonitoringMetric `json:"receiveErrors,omitempty"`
	TransmitErrors *MonitoringMetric `json:"transmitErrors,omitempty"`
	ReceiveDrops   *MonitoringMetric `json:"receiveDrops,omitempty"`
	TransmitDrops  *MonitoringMetric `json:"transmitDrops,omitempty"`
	LinkUp         *MonitoringMetric `json:"linkUp,omitempty"`
}
type MonitoringHostDisk struct {
	Device          string            `json:"device"`
	ReadBytes       *MonitoringMetric `json:"readBytes,omitempty"`
	WrittenBytes    *MonitoringMetric `json:"writtenBytes,omitempty"`
	ReadsCompleted  *MonitoringMetric `json:"readsCompleted,omitempty"`
	WritesCompleted *MonitoringMetric `json:"writesCompleted,omitempty"`
	IOTimeSeconds   *MonitoringMetric `json:"ioTimeSeconds,omitempty"`
}
type MonitoringPressure struct {
	Resource     string            `json:"resource"`
	State        string            `json:"state"`
	SecondsTotal *MonitoringMetric `json:"secondsTotal,omitempty"`
}
type MonitoringTemperature struct {
	Chip    string            `json:"chip"`
	Sensor  string            `json:"sensor"`
	Celsius *MonitoringMetric `json:"celsius,omitempty"`
}
type MonitoringZFSPool struct {
	Pool           string            `json:"pool"`
	SizeBytes      *MonitoringMetric `json:"sizeBytes,omitempty"`
	AllocatedBytes *MonitoringMetric `json:"allocatedBytes,omitempty"`
	FreeBytes      *MonitoringMetric `json:"freeBytes,omitempty"`
	Healthy        *MonitoringMetric `json:"healthy,omitempty"`
}

type MonitoringSMART struct {
	ObservedAt time.Time               `json:"observedAt"`
	Devices    []MonitoringSMARTDevice `json:"devices,omitempty"`
}
type MonitoringSMARTDevice struct {
	Device             string            `json:"device"`
	Healthy            *MonitoringMetric `json:"healthy,omitempty"`
	TemperatureCelsius *MonitoringMetric `json:"temperatureCelsius,omitempty"`
	PowerOnHours       *MonitoringMetric `json:"powerOnHours,omitempty"`
	DataUnitsRead      *MonitoringMetric `json:"dataUnitsRead,omitempty"`
	DataUnitsWritten   *MonitoringMetric `json:"dataUnitsWritten,omitempty"`
	MediaErrors        *MonitoringMetric `json:"mediaErrors,omitempty"`
	PercentageUsed     *MonitoringMetric `json:"percentageUsed,omitempty"`
	CapacityBytes      *MonitoringMetric `json:"capacityBytes,omitempty"`
	Model              string            `json:"model,omitempty"`
	Serial             string            `json:"serial,omitempty"`
	Protocol           string            `json:"protocol,omitempty"`
}

type MonitoringAgentHealth struct {
	AuditQueue MonitoringQueueState `json:"auditQueue"`
}
type MonitoringQueueState struct {
	PendingItems      protocol.Counter `json:"pendingItems"`
	PendingBytes      protocol.Counter `json:"pendingBytes"`
	DeadLetterItems   protocol.Counter `json:"deadLetterItems"`
	DroppedItems      protocol.Counter `json:"droppedItems"`
	AuthBlocked       bool             `json:"authBlocked"`
	AuthBlockedSince  *time.Time       `json:"authBlockedSince,omitempty"`
	LastDeliveryError string           `json:"lastDeliveryError,omitempty"`
	OldestObservedAt  *time.Time       `json:"oldestObservedAt,omitempty"`
}

func BuildMonitoringTelemetry(snapshot observation.Snapshot, assignments *inventory.Store, cfg MonitoringBuildContext) (MonitoringTelemetryBatch, error) {
	if !monitoringUUID.MatchString(cfg.BindingID) || !monitoringUUID.MatchString(cfg.BootID) ||
		!monitoringSafeID.MatchString(cfg.MonitoringAgentRef) || !monitoringSafeID.MatchString(cfg.DeviceID) ||
		!monitoringSafeID.MatchString(cfg.AgentVersion) || !monitoringSafeID.MatchString(cfg.SourceRef) ||
		cfg.CredentialEpoch == 0 || cfg.Sequence == 0 || cfg.SentAt.IsZero() || snapshot.ObservedAt.IsZero() {
		return MonitoringTelemetryBatch{}, fmt.Errorf("monitoring telemetry identity, sequence and timestamps are required")
	}
	batchID, err := protocol.NewID()
	if err != nil {
		return MonitoringTelemetryBatch{}, err
	}
	result := MonitoringTelemetryBatch{
		SchemaVersion: 1, BatchID: batchID, BindingID: cfg.BindingID, MonitoringAgentRef: cfg.MonitoringAgentRef,
		DeviceID: cfg.DeviceID, CredentialEpoch: protocol.Counter(cfg.CredentialEpoch), BootID: cfg.BootID,
		Sequence: protocol.Counter(cfg.Sequence), ObservedAt: snapshot.ObservedAt.UTC(), SentAt: cfg.SentAt.UTC(),
		Source: MonitoringSource{WebsiteAgentRef: snapshot.AgentRef, CollectorRef: snapshot.CollectorRef, SourceRef: cfg.SourceRef,
			ClusterRef: snapshot.ClusterRef, NodeRef: snapshot.NodeRef, Site: snapshot.Site, Mode: snapshot.Mode, AgentVersion: cfg.AgentVersion},
		PVEVersion: snapshot.PVEVersion, Components: monitoringComponents(snapshot.Components), Tasks: append([]observation.Task{}, snapshot.Tasks...),
		Nodes: []MonitoringNode{}, Storages: []MonitoringStorage{}, Guests: []MonitoringGuest{}, AgentHealth: cfg.AgentHealth,
	}
	for _, node := range snapshot.Nodes {
		result.Nodes = append(result.Nodes, monitoringNode(node))
	}
	for _, storage := range snapshot.Storages {
		result.Storages = append(result.Storages, monitoringStorage(storage))
	}
	for _, guest := range snapshot.Guests {
		result.Guests = append(result.Guests, monitoringGuest(snapshot.ClusterRef, guest, assignments, cfg.SentAt))
	}
	if snapshot.Host != nil {
		value := monitoringHost(*snapshot.Host)
		result.Host = &value
	}
	if snapshot.SMART != nil {
		value := monitoringSMART(*snapshot.SMART)
		result.SMART = &value
	}
	return result, nil
}

func monitoringNode(value observation.Node) MonitoringNode {
	return MonitoringNode{Name: value.Name, Status: value.Status, CPU: value.CPU, CPUCount: value.CPUCount, CPUModel: value.CPUModel,
		MemoryUsed: counterPointer(value.MemoryUsed), MemoryTotal: counterPointer(value.MemoryTotal), SwapUsed: counterPointer(value.SwapUsed), SwapTotal: counterPointer(value.SwapTotal),
		RootUsed: counterPointer(value.RootUsed), RootTotal: counterPointer(value.RootTotal), LoadAverage: value.LoadAverage, UptimeSeconds: counterPointer(value.UptimeSeconds),
		IOWaitRatio: value.IOWaitRatio, PVEVersion: value.PVEVersion, ObservedAt: value.ObservedAt}
}
func monitoringStorage(value observation.Storage) MonitoringStorage {
	return MonitoringStorage{Node: value.Node, Name: value.Name, Kind: value.Kind, Content: value.Content, Status: value.Status, Shared: value.Shared,
		UsedBytes: counterPointer(value.UsedBytes), TotalBytes: counterPointer(value.TotalBytes), FreeBytes: counterPointer(value.FreeBytes), ObservedAt: value.ObservedAt}
}
func monitoringGuest(cluster string, guest observation.Guest, assignments *inventory.Store, now time.Time) MonitoringGuest {
	item := MonitoringGuest{VMID: guest.VMID, GuestType: guest.GuestType, Name: guest.Name, Node: guest.Node, Template: guest.Template,
		PVE: monitoringPVEGuest(guest.PVE), QGA: monitoringQGA(guest.QGA), Networks: websiteNetworks(guest.Networks, nil), Capabilities: monitoringGuestCapabilities(guestCapabilities(guest, nil, now)), ObservedAt: guest.ObservedAt,
		NetworkProjection: monitoringNetworkProjection(guest)}
	if assignments != nil {
		if assignment, ok := assignments.Lookup(cluster, guest.GuestType, guest.VMID); ok {
			item.Managed = true
			item.Identity = monitoringAssignment(assignment)
			item.Networks = websiteNetworks(guest.Networks, assignment.NICBindings)
			item.Capabilities = monitoringGuestCapabilities(guestCapabilities(guest, &assignment, now))
		}
	}
	if item.Networks == nil {
		item.Networks = []WebsiteNetwork{}
	}
	return item
}
func monitoringAssignment(value inventory.Assignment) *MonitoringAssignment {
	return &MonitoringAssignment{ServiceRef: value.ServiceRef, ClusterRef: value.ClusterRef, NodeRef: value.NodeRef, VMID: value.VMID,
		Generation: protocol.Counter(value.Generation), InstanceUUID: value.InstanceUUID, GuestType: value.GuestType, BillingState: value.BillingState,
		CutoverAt: value.CutoverAt, NICBindings: append([]inventory.NICBinding(nil), value.NICBindings...)}
}
func monitoringPVEGuest(value observation.PVEGuestView) MonitoringPVEGuest {
	return MonitoringPVEGuest{Availability: monitoringAvailability(value.Availability), Status: value.Status, CPU: value.CPU, CPUCount: value.CPUCount,
		MemoryUsed: counterPointer(value.MemoryUsed), MemoryTotal: counterPointer(value.MemoryTotal), DiskUsed: counterPointer(value.DiskUsed), DiskTotal: counterPointer(value.DiskTotal),
		DiskRead: counterPointer(value.DiskRead), DiskWrite: counterPointer(value.DiskWrite), IngressBytes: counterPointer(value.IngressBytes), EgressBytes: counterPointer(value.EgressBytes), UptimeSeconds: counterPointer(value.UptimeSeconds)}
}
func monitoringQGA(value observation.QGAView) MonitoringQGA {
	result := MonitoringQGA{Availability: monitoringAvailability(value.Availability), Info: monitoringGuestAgentInfo(value.Info), OS: value.OS, Capabilities: value.Capabilities}
	for _, fs := range value.Filesystems {
		result.Filesystems = append(result.Filesystems, MonitoringGuestFilesystem{Name: fs.Name, Mountpoint: fs.Mountpoint, Type: fs.Type, TotalBytes: counterPointer(fs.TotalBytes), UsedBytes: counterPointer(fs.UsedBytes)})
	}
	for _, nic := range value.Interfaces {
		item := MonitoringGuestInterface{Name: nic.Name, HardwareAddress: nic.HardwareAddress, IPAddresses: []MonitoringGuestAddress{}}
		for _, address := range nic.IPAddresses {
			item.IPAddresses = append(item.IPAddresses, MonitoringGuestAddress{Address: address.Address, Prefix: address.Prefix, Type: address.Type})
		}
		if nic.Statistics != nil {
			item.Statistics = &MonitoringGuestNICStats{RXBytes: counterPointer(nic.Statistics.RxBytes), TXBytes: counterPointer(nic.Statistics.TxBytes), RXPackets: counterPointer(nic.Statistics.RxPackets), TXPackets: counterPointer(nic.Statistics.TxPackets)}
		}
		result.Interfaces = append(result.Interfaces, item)
	}
	return result
}

func monitoringNetworkProjection(guest observation.Guest) MonitoringNetworkProjection {
	result := MonitoringNetworkProjection{SchemaVersion: 1, Interfaces: []MonitoringProjectedInterface{}, UnmappedGuestInterfaces: []MonitoringUnmappedGuestInterface{}}
	networks := append([]observation.Network(nil), guest.Networks...)
	sort.SliceStable(networks, func(i, j int) bool { return networks[i].Index < networks[j].Index })
	type qgaInterface struct {
		value     pve.GuestInterface
		canonical string
		problem   string
		mapped    bool
	}
	qga := make([]qgaInterface, len(guest.QGA.Interfaces))
	qgaCounts, pveCounts := map[string]int{}, map[string]int{}
	for index, item := range guest.QGA.Interfaces {
		canonical, problem := monitoringCanonicalMAC(item.HardwareAddress, "qga")
		qga[index] = qgaInterface{value: item, canonical: canonical, problem: problem}
		if canonical != "" {
			qgaCounts[canonical]++
		}
	}
	for _, item := range networks {
		if canonical, _ := monitoringCanonicalMAC(item.MAC, "pve"); canonical != "" {
			pveCounts[canonical]++
		}
	}
	for _, network := range networks {
		if network.Index < 0 || network.Index > 31 {
			continue
		}
		projected := MonitoringProjectedInterface{InterfaceRef: "net" + strconv.Itoa(network.Index), MappingStatus: "unmapped", Source: "unavailable", Addresses: []MonitoringGuestAddress{}, Counters: MonitoringNICCounterAvailability{Source: "unavailable", Reason: "qga_counters_missing"}}
		canonical, pveProblem := monitoringCanonicalMAC(network.MAC, "pve")
		projected.CanonicalMAC = canonical
		if guest.GuestType == "lxc" {
			projected.MappingStatus, projected.Source = "mapped", "pve-config"
			projected.GuestInterfaceName = network.GuestName
			projected.ConfiguredAddressing = cloneConfiguredAddressing(network.ConfiguredAddressing)
			projected.Counters.Reason = "lxc_per_nic_counters_unavailable"
			result.Interfaces = append(result.Interfaces, projected)
			continue
		}
		qgaInterfacesAvailable := len(guest.QGA.Interfaces) > 0 || guest.QGA.Capabilities["interfaces"] == pve.Available
		switch {
		case !guest.QGA.Availability.Available || !qgaInterfacesAvailable:
			projected.MappingReason = "qga_interfaces_unavailable"
		case pveProblem != "":
			projected.MappingReason = pveProblem
		case pveCounts[canonical] > 1:
			projected.MappingReason = "ambiguous_pve_mac"
		case qgaCounts[canonical] > 1:
			projected.MappingReason = "duplicate_qga_mac"
		default:
			match := -1
			for index := range qga {
				if qga[index].canonical == canonical {
					match = index
					break
				}
			}
			if match < 0 {
				projected.MappingReason = "qga_interface_not_found"
			} else {
				qga[match].mapped = true
				projected.MappingStatus, projected.Source = "mapped", "qga"
				projected.GuestInterfaceName = qga[match].value.Name
				projected.Addresses = monitoringGuestAddresses(qga[match].value.IPAddresses)
				projected.Counters = monitoringNICCounters(qga[match].value.Statistics)
			}
		}
		result.Interfaces = append(result.Interfaces, projected)
	}
	for _, item := range qga {
		if item.mapped {
			continue
		}
		reason := item.problem
		switch {
		case reason != "":
		case qgaCounts[item.canonical] > 1:
			reason = "duplicate_qga_mac"
		case pveCounts[item.canonical] > 1:
			reason = "ambiguous_pve_mac"
		default:
			reason = "pve_interface_not_found"
		}
		unmapped := MonitoringUnmappedGuestInterface{Name: item.value.Name, HardwareAddress: item.value.HardwareAddress, CanonicalMAC: item.canonical, MappingStatus: "unmapped", Reason: reason, Addresses: monitoringGuestAddresses(item.value.IPAddresses)}
		if item.value.Statistics != nil {
			unmapped.Statistics = &MonitoringGuestNICStats{RXBytes: counterPointer(item.value.Statistics.RxBytes), TXBytes: counterPointer(item.value.Statistics.TxBytes), RXPackets: counterPointer(item.value.Statistics.RxPackets), TXPackets: counterPointer(item.value.Statistics.TxPackets)}
		}
		result.UnmappedGuestInterfaces = append(result.UnmappedGuestInterfaces, unmapped)
	}
	sort.SliceStable(result.UnmappedGuestInterfaces, func(i, j int) bool {
		left, right := result.UnmappedGuestInterfaces[i], result.UnmappedGuestInterfaces[j]
		if left.CanonicalMAC != right.CanonicalMAC {
			return left.CanonicalMAC < right.CanonicalMAC
		}
		return left.Name < right.Name
	})
	return result
}

func monitoringCanonicalMAC(value, source string) (string, string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", source + "_mac_missing"
	}
	hardware, err := net.ParseMAC(value)
	if err != nil || len(hardware) != 6 || hardware[0]&1 != 0 {
		return "", source + "_mac_invalid"
	}
	allZero := true
	for _, part := range hardware {
		allZero = allZero && part == 0
	}
	if allZero {
		return "", source + "_mac_invalid"
	}
	return strings.ToLower(hardware.String()), ""
}

func monitoringGuestAddresses(values []pve.GuestIPAddress) []MonitoringGuestAddress {
	result := []MonitoringGuestAddress{}
	for _, value := range values {
		address := net.ParseIP(strings.TrimSpace(value.Address))
		if address == nil {
			continue
		}
		kind, maxPrefix := "ipv6", 128
		if address.To4() != nil {
			kind, maxPrefix, address = "ipv4", 32, address.To4()
		}
		if value.Prefix < 0 || value.Prefix > maxPrefix {
			continue
		}
		result = append(result, MonitoringGuestAddress{Address: address.String(), Prefix: value.Prefix, Type: kind})
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Type != result[j].Type {
			return result[i].Type < result[j].Type
		}
		if result[i].Address != result[j].Address {
			return result[i].Address < result[j].Address
		}
		return result[i].Prefix < result[j].Prefix
	})
	return result
}

func monitoringNICCounters(value *pve.GuestInterfaceStats) MonitoringNICCounterAvailability {
	result := MonitoringNICCounterAvailability{Source: "qga"}
	if value == nil {
		result.Source, result.Reason = "unavailable", "qga_counters_missing"
		return result
	}
	result.RXBytes, result.TXBytes = counterPointer(value.RxBytes), counterPointer(value.TxBytes)
	result.RXPackets, result.TXPackets = counterPointer(value.RxPackets), counterPointer(value.TxPackets)
	if value.RxBytes == nil && value.TxBytes == nil && value.RxPackets == nil && value.TxPackets == nil {
		result.Source, result.Reason = "unavailable", "qga_counters_missing"
		return result
	}
	if value.RxBytes == nil || value.TxBytes == nil {
		result.Source, result.Reason = "unavailable", "qga_counters_incomplete"
		return result
	}
	result.Available = true
	return result
}

func cloneConfiguredAddressing(value *observation.ConfiguredAddressing) *observation.ConfiguredAddressing {
	if value == nil {
		return nil
	}
	result := *value
	if value.IPv4 != nil {
		copyValue := *value.IPv4
		if value.IPv4.Prefix != nil {
			prefix := *value.IPv4.Prefix
			copyValue.Prefix = &prefix
		}
		result.IPv4 = &copyValue
	}
	if value.IPv6 != nil {
		copyValue := *value.IPv6
		if value.IPv6.Prefix != nil {
			prefix := *value.IPv6.Prefix
			copyValue.Prefix = &prefix
		}
		result.IPv6 = &copyValue
	}
	return &result
}

// monitoringGuestAgentInfo keeps the monitoring wire contract independent
// from the PVE API's nil-slice representation. The monitoring receiver
// requires supported_commands to be an array whenever info is present, so an
// unavailable/empty command list must serialize as [] rather than null. The
// copy also avoids mutating the collector snapshot shared with other outputs.
func monitoringGuestAgentInfo(value *pve.GuestAgentInfo) *pve.GuestAgentInfo {
	if value == nil {
		return nil
	}
	result := *value
	result.SupportedCommands = append([]pve.GuestAgentCommand{}, value.SupportedCommands...)
	return &result
}

func monitoringComponents(value map[string]observation.Availability) map[string]MonitoringAvailability {
	result := make(map[string]MonitoringAvailability, len(value))
	for name, availability := range value {
		result[name] = monitoringAvailability(availability)
	}
	return result
}

func monitoringAvailability(value observation.Availability) MonitoringAvailability {
	result := MonitoringAvailability{Available: value.Available, UnavailableReason: value.UnavailableReason}
	if value.ObservedAt.IsZero() {
		return result
	}
	observedAt := value.ObservedAt.UTC()
	result.ObservedAt = &observedAt
	if value.FreshUntil.IsZero() || value.FreshUntil.Before(value.ObservedAt) {
		return result
	}
	freshUntil := value.FreshUntil.UTC()
	result.FreshUntil = &freshUntil
	return result
}

func monitoringGuestCapabilities(value GuestCapabilities) MonitoringGuestCapabilities {
	return MonitoringGuestCapabilities{
		Lifecycle:          monitoringActionCapability(value.Lifecycle),
		RootPasswordReset:  monitoringActionCapability(value.RootPasswordReset),
		GuestNetworkVerify: monitoringActionCapability(value.GuestNetworkVerify),
		Metering:           value.Metering,
	}
}

func monitoringActionCapability(value ActionCapability) MonitoringActionCapability {
	availability := monitoringAvailability(observation.Availability{
		Available: value.Available, ObservedAt: value.ObservedAt,
		FreshUntil: value.FreshUntil, UnavailableReason: value.Reason,
	})
	return MonitoringActionCapability{
		Available: value.Available, Reason: value.Reason, ObservedAt: availability.ObservedAt,
		FreshUntil: availability.FreshUntil, ExecutionPreflight: value.ExecutionPreflight,
	}
}

func monitoringMetric(value exporter.Value) *MonitoringMetric {
	if value.Value == nil {
		return nil
	}
	raw := strings.TrimSpace(value.Raw)
	if raw == "" {
		raw = strconv.FormatFloat(*value.Value, 'g', -1, 64)
	}
	if canonical, ok := exporter.CanonicalUnsignedInteger(raw); ok {
		raw = canonical
	}
	return &MonitoringMetric{Decimal: raw}
}
func monitoringHost(value exporter.HostObservation) MonitoringHost {
	result := MonitoringHost{ObservedAt: value.ObservedAt, Load1: monitoringMetric(value.Load1), MemoryTotalBytes: monitoringMetric(value.MemoryTotalBytes), MemoryAvailableBytes: monitoringMetric(value.MemoryAvailableBytes), SwapTotalBytes: monitoringMetric(value.SwapTotalBytes), SwapFreeBytes: monitoringMetric(value.SwapFreeBytes)}
	for _, item := range value.CPUSeconds {
		result.CPUSeconds = append(result.CPUSeconds, MonitoringCPUSeconds{CPU: item.CPU, Mode: item.Mode, Seconds: monitoringMetric(item.Seconds)})
	}
	for _, item := range value.Filesystems {
		result.Filesystems = append(result.Filesystems, MonitoringHostFilesystem{Device: item.Device, Mountpoint: item.Mountpoint, FSType: item.FSType, SizeBytes: monitoringMetric(item.SizeBytes), AvailableBytes: monitoringMetric(item.AvailableBytes), ReadOnly: monitoringMetric(item.ReadOnly)})
	}
	for _, item := range value.Interfaces {
		result.Interfaces = append(result.Interfaces, MonitoringHostInterface{Device: item.Device, ReceiveBytes: monitoringMetric(item.ReceiveBytes), TransmitBytes: monitoringMetric(item.TransmitBytes), ReceiveErrors: monitoringMetric(item.ReceiveErrors), TransmitErrors: monitoringMetric(item.TransmitErrors), ReceiveDrops: monitoringMetric(item.ReceiveDrops), TransmitDrops: monitoringMetric(item.TransmitDrops), LinkUp: monitoringMetric(item.LinkUp)})
	}
	for _, item := range value.Disks {
		result.Disks = append(result.Disks, MonitoringHostDisk{Device: item.Device, ReadBytes: monitoringMetric(item.ReadBytes), WrittenBytes: monitoringMetric(item.WrittenBytes), ReadsCompleted: monitoringMetric(item.ReadsCompleted), WritesCompleted: monitoringMetric(item.WritesCompleted), IOTimeSeconds: monitoringMetric(item.IOTimeSeconds)})
	}
	for _, item := range value.Pressure {
		result.Pressure = append(result.Pressure, MonitoringPressure{Resource: item.Resource, State: item.State, SecondsTotal: monitoringMetric(item.SecondsTotal)})
	}
	for _, item := range value.HardwareTemperatures {
		result.HardwareTemperatures = append(result.HardwareTemperatures, MonitoringTemperature{Chip: item.Chip, Sensor: item.Sensor, Celsius: monitoringMetric(item.Celsius)})
	}
	for _, item := range value.ZFSPools {
		result.ZFSPools = append(result.ZFSPools, MonitoringZFSPool{Pool: item.Pool, SizeBytes: monitoringMetric(item.SizeBytes), AllocatedBytes: monitoringMetric(item.AllocatedBytes), FreeBytes: monitoringMetric(item.FreeBytes), Healthy: monitoringMetric(item.Healthy)})
	}
	return result
}
func monitoringSMART(value exporter.SmartObservation) MonitoringSMART {
	result := MonitoringSMART{ObservedAt: value.ObservedAt}
	for _, item := range value.Devices {
		result.Devices = append(result.Devices, MonitoringSMARTDevice{Device: item.Device, Healthy: monitoringMetric(item.Healthy), TemperatureCelsius: monitoringMetric(item.TemperatureCelsius), PowerOnHours: monitoringMetric(item.PowerOnHours), DataUnitsRead: monitoringMetric(item.DataUnitsRead), DataUnitsWritten: monitoringMetric(item.DataUnitsWritten), MediaErrors: monitoringMetric(item.MediaErrors), PercentageUsed: monitoringMetric(item.PercentageUsed), CapacityBytes: monitoringMetric(item.CapacityBytes), Model: item.Model, Serial: item.Serial, Protocol: item.Protocol})
	}
	return result
}
