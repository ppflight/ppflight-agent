// Package observation defines the normalized, source-labelled state collected
// on a PVE node. It intentionally keeps PVE and QGA views separate.
package observation

import (
	"time"

	"github.com/ppflight/ppflight-agent/internal/exporter"
	"github.com/ppflight/ppflight-agent/internal/pve"
)

type Availability struct {
	Available         bool      `json:"available"`
	ObservedAt        time.Time `json:"observedAt,omitempty"`
	FreshUntil        time.Time `json:"freshUntil,omitempty"`
	UnavailableReason string    `json:"unavailableReason,omitempty"`
}

type Snapshot struct {
	SchemaVersion int                        `json:"schemaVersion"`
	Mode          string                     `json:"mode"`
	AgentRef      string                     `json:"agentRef"`
	CollectorRef  string                     `json:"collectorRef"`
	ClusterRef    string                     `json:"clusterRef"`
	NodeRef       string                     `json:"nodeRef"`
	Site          string                     `json:"site"`
	ObservedAt    time.Time                  `json:"observedAt"`
	PVEVersion    pve.Version                `json:"pveVersion"`
	Components    map[string]Availability    `json:"components"`
	Nodes         []Node                     `json:"nodes"`
	Storages      []Storage                  `json:"storages"`
	Tasks         []Task                     `json:"tasks"`
	Guests        []Guest                    `json:"guests"`
	Host          *exporter.HostObservation  `json:"host,omitempty"`
	SMART         *exporter.SmartObservation `json:"smart,omitempty"`
}

type Node struct {
	Name          string    `json:"name"`
	Status        string    `json:"status"`
	CPU           *float64  `json:"cpuRatio,omitempty"`
	CPUCount      *int      `json:"cpuCount,omitempty"`
	CPUModel      string    `json:"cpuModel,omitempty"`
	MemoryUsed    *uint64   `json:"memoryUsedBytes,omitempty"`
	MemoryTotal   *uint64   `json:"memoryTotalBytes,omitempty"`
	SwapUsed      *uint64   `json:"swapUsedBytes,omitempty"`
	SwapTotal     *uint64   `json:"swapTotalBytes,omitempty"`
	RootUsed      *uint64   `json:"rootUsedBytes,omitempty"`
	RootTotal     *uint64   `json:"rootTotalBytes,omitempty"`
	LoadAverage   []float64 `json:"loadAverage,omitempty"`
	UptimeSeconds *uint64   `json:"uptimeSeconds,omitempty"`
	IOWaitRatio   *float64  `json:"ioWaitRatio,omitempty"`
	PVEVersion    string    `json:"pveVersion,omitempty"`
	ObservedAt    time.Time `json:"observedAt"`
}

type Storage struct {
	Node       string    `json:"node"`
	Name       string    `json:"name"`
	Kind       string    `json:"kind"`
	Content    string    `json:"content,omitempty"`
	Status     string    `json:"status"`
	Shared     bool      `json:"shared"`
	UsedBytes  *uint64   `json:"usedBytes,omitempty"`
	TotalBytes *uint64   `json:"totalBytes,omitempty"`
	FreeBytes  *uint64   `json:"freeBytes,omitempty"`
	ObservedAt time.Time `json:"observedAt"`
}

type Task struct {
	Node       string     `json:"node"`
	Type       string     `json:"type"`
	ResourceID string     `json:"resourceId,omitempty"`
	Status     string     `json:"status"`
	StartedAt  time.Time  `json:"startedAt"`
	EndedAt    *time.Time `json:"endedAt,omitempty"`
}

type Guest struct {
	VMID       int          `json:"vmid"`
	GuestType  string       `json:"guestType"`
	Name       string       `json:"name"`
	Node       string       `json:"node"`
	Template   bool         `json:"template"`
	PVE        PVEGuestView `json:"pve"`
	QGA        QGAView      `json:"qga"`
	Networks   []Network    `json:"networks,omitempty"`
	ObservedAt time.Time    `json:"observedAt"`
}

type PVEGuestView struct {
	Availability  Availability `json:"availability"`
	Status        string       `json:"status"`
	CPU           *float64     `json:"cpuRatio,omitempty"`
	CPUCount      *float64     `json:"cpuCount,omitempty"`
	MemoryUsed    *uint64      `json:"memoryUsedBytes,omitempty"`
	MemoryTotal   *uint64      `json:"memoryTotalBytes,omitempty"`
	DiskUsed      *uint64      `json:"diskUsedBytes,omitempty"`
	DiskTotal     *uint64      `json:"diskTotalBytes,omitempty"`
	DiskRead      *uint64      `json:"diskReadBytesTotal,omitempty"`
	DiskWrite     *uint64      `json:"diskWriteBytesTotal,omitempty"`
	IngressBytes  *uint64      `json:"ingressBytesTotal,omitempty"`
	EgressBytes   *uint64      `json:"egressBytesTotal,omitempty"`
	UptimeSeconds *uint64      `json:"uptimeSeconds,omitempty"`
}

type QGAView struct {
	Availability Availability                `json:"availability"`
	Info         *pve.GuestAgentInfo         `json:"info,omitempty"`
	OS           *pve.GuestOSInfo            `json:"os,omitempty"`
	Filesystems  []pve.GuestFilesystem       `json:"filesystems,omitempty"`
	Interfaces   []pve.GuestInterface        `json:"interfaces,omitempty"`
	Capabilities map[string]pve.Availability `json:"capabilities,omitempty"`
}

type Network struct {
	Index     int    `json:"index"`
	Interface string `json:"interface"`
	GuestName string `json:"guestName,omitempty"`
	Model     string `json:"model,omitempty"`
	MAC       string `json:"mac,omitempty"`
	Bridge    string `json:"bridge,omitempty"`
	VLAN      string `json:"vlan,omitempty"`
	MTU       string `json:"mtu,omitempty"`
	RateMbps  string `json:"rateMbps,omitempty"`
	Firewall  string `json:"firewall,omitempty"`
	LinkDown  string `json:"linkDown,omitempty"`
	// ConfiguredAddressing is monitoring-only normalized LXC configuration.
	// It is deliberately excluded from the legacy website payload so the new
	// strict contract can be rolled out independently.
	ConfiguredAddressing *ConfiguredAddressing `json:"-"`
}

type ConfiguredAddressing struct {
	IPv4 *ConfiguredAddress `json:"ipv4,omitempty"`
	IPv6 *ConfiguredAddress `json:"ipv6,omitempty"`
}

type ConfiguredAddress struct {
	Mode    string `json:"mode"`
	Address string `json:"address,omitempty"`
	Prefix  *int   `json:"prefix,omitempty"`
	Reason  string `json:"reason,omitempty"`
}
