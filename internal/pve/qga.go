package pve

import (
	"context"
	"strings"
)

// Availability deliberately distinguishes a missing guest-agent field from a
// numeric zero. Serialisers should omit nil fields and carry this state.
type Availability string

const (
	Available   Availability = "available"
	Unavailable Availability = "unavailable"
)

type GuestAgentInfo struct {
	Version           string              `json:"version"`
	SupportedCommands []GuestAgentCommand `json:"supported_commands"`
}
type GuestAgentCommand struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}
type GuestOSInfo struct {
	Name          string `json:"name"`
	PrettyName    string `json:"pretty-name"`
	Version       string `json:"version"`
	VersionID     string `json:"version-id"`
	KernelRelease string `json:"kernel-release"`
	KernelVersion string `json:"kernel-version"`
	Machine       string `json:"machine"`
}
type GuestFilesystem struct {
	Name       string  `json:"name"`
	Mountpoint string  `json:"mountpoint"`
	Type       string  `json:"type"`
	TotalBytes *uint64 `json:"total-bytes,omitempty"`
	UsedBytes  *uint64 `json:"used-bytes,omitempty"`
}
type GuestInterface struct {
	Name            string               `json:"name"`
	HardwareAddress string               `json:"hardware-address"`
	IPAddresses     []GuestIPAddress     `json:"ip-addresses"`
	Statistics      *GuestInterfaceStats `json:"statistics,omitempty"`
}
type GuestIPAddress struct {
	Address string `json:"ip-address"`
	Prefix  int    `json:"prefix"`
	Type    string `json:"ip-address-type"`
}
type GuestInterfaceStats struct {
	RxBytes   *uint64 `json:"rx-bytes,omitempty"`
	TxBytes   *uint64 `json:"tx-bytes,omitempty"`
	RxPackets *uint64 `json:"rx-packets,omitempty"`
	TxPackets *uint64 `json:"tx-packets,omitempty"`
}

// GuestAgentObservation contains only non-mutating QEMU Guest Agent data.
// Availability always has an entry for every attempted logical collection.
// An unavailable endpoint never produces a synthetic zero value.
type GuestAgentObservation struct {
	Info         *GuestAgentInfo         `json:"info,omitempty"`
	OS           *GuestOSInfo            `json:"os,omitempty"`
	Filesystems  []GuestFilesystem       `json:"filesystems,omitempty"`
	Interfaces   []GuestInterface        `json:"interfaces,omitempty"`
	Availability map[string]Availability `json:"availability"`
}

// ProbeGuestAgent safely probes read-only QGA endpoints. It never invokes
// guest-exec, filesystem freeze/thaw, password, shutdown, or any other write.
// A missing/disabled agent is represented as unavailable rather than an error,
// which lets the caller retain other PVE observations.
func (c *Client) ProbeGuestAgent(ctx context.Context, node string, vmid int) (GuestAgentObservation, error) {
	base, err := guestPath("qemu", node, vmid)
	if err != nil {
		return GuestAgentObservation{}, err
	}
	result := GuestAgentObservation{Availability: map[string]Availability{
		"info": Unavailable, "os": Unavailable, "filesystems": Unavailable, "interfaces": Unavailable,
	}}
	var info GuestAgentInfo
	if err := c.get(ctx, base+"/agent/info", nil, &info); err != nil {
		// Agent absent and endpoint incompatibilities are normal states. Network
		// failures are also deliberately contained here so a single VM cannot
		// fail a node collection cycle.
		return result, nil
	}
	result.Info, result.Availability["info"] = &info, Available
	supported := supportedReadCommands(info)
	if supported["guest-get-osinfo"] {
		var v GuestOSInfo
		if c.get(ctx, base+"/agent/get-osinfo", nil, &v) == nil {
			result.OS, result.Availability["os"] = &v, Available
		}
	}
	if supported["guest-get-fsinfo"] {
		var v []GuestFilesystem
		if c.get(ctx, base+"/agent/get-fsinfo", nil, &v) == nil {
			result.Filesystems, result.Availability["filesystems"] = v, Available
		}
	}
	if supported["guest-network-get-interfaces"] {
		var v []GuestInterface
		if c.get(ctx, base+"/agent/network-get-interfaces", nil, &v) == nil {
			result.Interfaces, result.Availability["interfaces"] = v, Available
		}
	}
	return result, nil
}

func supportedReadCommands(info GuestAgentInfo) map[string]bool {
	result := make(map[string]bool, len(info.SupportedCommands))
	for _, command := range info.SupportedCommands {
		name := strings.TrimSpace(command.Name)
		if command.Enabled && (name == "guest-get-osinfo" || name == "guest-get-fsinfo" || name == "guest-network-get-interfaces") {
			result[name] = true
		}
	}
	return result
}
