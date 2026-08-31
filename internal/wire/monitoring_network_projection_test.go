package wire

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ppflight/ppflight-agent/internal/observation"
	"github.com/ppflight/ppflight-agent/internal/pve"
)

func uint64ptr(value uint64) *uint64 { return &value }

func TestMonitoringNetworkProjectionMapsMultipleNICsByCanonicalMAC(t *testing.T) {
	guest := observation.Guest{GuestType: "qemu",
		Networks: []observation.Network{{Index: 1, Interface: "net1", MAC: "02:00:00:00:00:02"}, {Index: 0, Interface: "net0", MAC: "02-00-00-00-00-01"}},
		QGA: observation.QGAView{Availability: observation.Availability{Available: true}, Capabilities: map[string]pve.Availability{"interfaces": pve.Available}, Interfaces: []pve.GuestInterface{
			{Name: "ens19", HardwareAddress: "02:00:00:00:00:02", IPAddresses: []pve.GuestIPAddress{{Address: "2001:0db8::2", Prefix: 64, Type: "ipv6"}}, Statistics: &pve.GuestInterfaceStats{RxBytes: uint64ptr(22), TxBytes: uint64ptr(23)}},
			{Name: "ens18", HardwareAddress: "02:00:00:00:00:01", IPAddresses: []pve.GuestIPAddress{{Address: "192.0.2.10", Prefix: 24, Type: "ipv4"}}, Statistics: &pve.GuestInterfaceStats{RxBytes: uint64ptr(12), TxBytes: uint64ptr(13)}},
		}},
	}
	got := monitoringNetworkProjection(guest)
	if len(got.Interfaces) != 2 || got.Interfaces[0].InterfaceRef != "net0" || got.Interfaces[0].GuestInterfaceName != "ens18" || got.Interfaces[1].InterfaceRef != "net1" || got.Interfaces[1].GuestInterfaceName != "ens19" {
		t.Fatalf("projection=%#v", got)
	}
	if got.Interfaces[0].CanonicalMAC != "02:00:00:00:00:01" || !got.Interfaces[0].Counters.Available || uint64(*got.Interfaces[0].Counters.RXBytes) != 12 {
		t.Fatalf("net0=%#v", got.Interfaces[0])
	}
	if len(got.Interfaces[1].Addresses) != 1 || got.Interfaces[1].Addresses[0].Address != "2001:db8::2" || got.Interfaces[1].Addresses[0].Type != "ipv6" {
		t.Fatalf("net1 addresses=%#v", got.Interfaces[1].Addresses)
	}
}

func TestMonitoringNetworkProjectionQGAMissingIsExplicit(t *testing.T) {
	guest := observation.Guest{GuestType: "qemu", Networks: []observation.Network{{Index: 0, Interface: "net0", MAC: "02:00:00:00:00:01"}}, QGA: observation.QGAView{Availability: observation.Availability{Available: false}}}
	got := monitoringNetworkProjection(guest)
	if len(got.Interfaces) != 1 || got.Interfaces[0].MappingStatus != "unmapped" || got.Interfaces[0].MappingReason != "qga_interfaces_unavailable" || got.Interfaces[0].Counters.Available {
		t.Fatalf("projection=%#v", got)
	}
}

func TestMonitoringNetworkProjectionRejectsEmptyInvalidAndDuplicateMACs(t *testing.T) {
	guest := observation.Guest{GuestType: "qemu",
		Networks: []observation.Network{{Index: 0, Interface: "net0", MAC: "02:00:00:00:00:01"}},
		QGA: observation.QGAView{Availability: observation.Availability{Available: true}, Capabilities: map[string]pve.Availability{"interfaces": pve.Available}, Interfaces: []pve.GuestInterface{
			{Name: "empty", HardwareAddress: ""}, {Name: "zero", HardwareAddress: "00:00:00:00:00:00"},
			{Name: "dup-a", HardwareAddress: "02:00:00:00:00:01"}, {Name: "dup-b", HardwareAddress: "02:00:00:00:00:01"},
		}},
	}
	got := monitoringNetworkProjection(guest)
	if got.Interfaces[0].MappingReason != "duplicate_qga_mac" || len(got.UnmappedGuestInterfaces) != 4 {
		t.Fatalf("projection=%#v", got)
	}
	reasons := map[string]string{}
	for _, item := range got.UnmappedGuestInterfaces {
		reasons[item.Name] = item.Reason
	}
	if reasons["empty"] != "qga_mac_missing" || reasons["zero"] != "qga_mac_invalid" || reasons["dup-a"] != "duplicate_qga_mac" || reasons["dup-b"] != "duplicate_qga_mac" {
		t.Fatalf("reasons=%#v", reasons)
	}
}

func TestMonitoringNetworkProjectionRejectsMissingAndAmbiguousPVEMACs(t *testing.T) {
	guest := observation.Guest{GuestType: "qemu",
		Networks: []observation.Network{{Index: 0, Interface: "net0", MAC: ""}, {Index: 1, Interface: "net1", MAC: "02:00:00:00:00:09"}, {Index: 2, Interface: "net2", MAC: "02:00:00:00:00:09"}},
		QGA:      observation.QGAView{Availability: observation.Availability{Available: true}, Capabilities: map[string]pve.Availability{"interfaces": pve.Available}, Interfaces: []pve.GuestInterface{{Name: "ens20", HardwareAddress: "02:00:00:00:00:09"}}},
	}
	got := monitoringNetworkProjection(guest)
	if len(got.Interfaces) != 3 || got.Interfaces[0].MappingReason != "pve_mac_missing" || got.Interfaces[1].MappingReason != "ambiguous_pve_mac" || got.Interfaces[2].MappingReason != "ambiguous_pve_mac" {
		t.Fatalf("projection=%#v", got)
	}
	if len(got.UnmappedGuestInterfaces) != 1 || got.UnmappedGuestInterfaces[0].Reason != "ambiguous_pve_mac" {
		t.Fatalf("unmapped=%#v", got.UnmappedGuestInterfaces)
	}
}

func TestMonitoringNetworkProjectionMarksIncompleteCountersUnavailable(t *testing.T) {
	got := monitoringNICCounters(&pve.GuestInterfaceStats{RxBytes: uint64ptr(7)})
	if got.Available || got.Source != "unavailable" || got.Reason != "qga_counters_incomplete" || got.RXBytes == nil || uint64(*got.RXBytes) != 7 || got.TXBytes != nil {
		t.Fatalf("counters=%#v", got)
	}
}

func TestMonitoringNetworkProjectionHotplugKeepsExistingInterfaceRef(t *testing.T) {
	base := observation.Guest{GuestType: "qemu", Networks: []observation.Network{{Index: 1, Interface: "net1", MAC: "02:00:00:00:00:02"}}, QGA: observation.QGAView{Availability: observation.Availability{Available: true}, Capabilities: map[string]pve.Availability{"interfaces": pve.Available}, Interfaces: []pve.GuestInterface{{Name: "ens19", HardwareAddress: "02:00:00:00:00:02"}}}}
	before := monitoringNetworkProjection(base)
	base.Networks = append(base.Networks, observation.Network{Index: 0, Interface: "net0", MAC: "02:00:00:00:00:01"})
	base.QGA.Interfaces = append(base.QGA.Interfaces, pve.GuestInterface{Name: "ens18", HardwareAddress: "02:00:00:00:00:01"})
	after := monitoringNetworkProjection(base)
	if before.Interfaces[0].InterfaceRef != "net1" || after.Interfaces[1].InterfaceRef != "net1" || after.Interfaces[1].GuestInterfaceName != "ens19" {
		t.Fatalf("before=%#v after=%#v", before, after)
	}
}

func TestMonitoringNetworkProjectionCounterResetIsNotClamped(t *testing.T) {
	first := monitoringNICCounters(&pve.GuestInterfaceStats{RxBytes: uint64ptr(100), TxBytes: uint64ptr(200)})
	reset := monitoringNICCounters(&pve.GuestInterfaceStats{RxBytes: uint64ptr(3), TxBytes: uint64ptr(4)})
	if !first.Available || !reset.Available || uint64(*reset.RXBytes) != 3 || uint64(*reset.TXBytes) != 4 {
		t.Fatalf("first=%#v reset=%#v", first, reset)
	}
}

func TestMonitoringNetworkProjectionLXCGolden(t *testing.T) {
	prefix := 24
	guest := observation.Guest{GuestType: "lxc", Networks: []observation.Network{{Index: 0, Interface: "net0", GuestName: "eth0", MAC: "02:00:00:00:00:02", ConfiguredAddressing: &observation.ConfiguredAddressing{IPv4: &observation.ConfiguredAddress{Mode: "static", Address: "10.0.0.2", Prefix: &prefix}, IPv6: &observation.ConfiguredAddress{Mode: "auto"}}}}}
	raw, err := json.Marshal(monitoringNetworkProjection(guest))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schemaVersion":1,"interfaces":[{"interfaceRef":"net0","mappingStatus":"mapped","source":"pve-config","guestInterfaceName":"eth0","canonicalMac":"02:00:00:00:00:02","addresses":[],"configuredAddressing":{"ipv4":{"mode":"static","address":"10.0.0.2","prefix":24},"ipv6":{"mode":"auto"}},"counters":{"available":false,"source":"unavailable","reason":"lxc_per_nic_counters_unavailable"}}],"unmappedGuestInterfaces":[]}`
	if string(raw) != want {
		t.Fatalf("golden mismatch\n got: %s\nwant: %s", raw, want)
	}
	if strings.Contains(string(raw), "netin") || strings.Contains(string(raw), "netout") {
		t.Fatal("per-NIC projection leaked PVE aggregate counters")
	}
}
