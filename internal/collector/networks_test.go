package collector

import (
	"encoding/json"
	"testing"
)

func TestSafeNetworksParsesLXCConfiguredIPv4AndIPv6(t *testing.T) {
	raw := map[string]json.RawMessage{
		"net0": json.RawMessage(`"name=eth0,bridge=vmbr0,hwaddr=02:00:00:00:00:01,ip=192.0.2.10/24,ip6=2001:db8::10/64"`),
		"net1": json.RawMessage(`"name=eth1,bridge=vmbr1,hwaddr=02:00:00:00:00:02,ip=dhcp,ip6=auto"`),
	}
	got := safeNetworks(raw, "lxc")
	if len(got) != 2 || got[0].ConfiguredAddressing == nil || got[1].ConfiguredAddressing == nil {
		t.Fatalf("networks=%#v", got)
	}
	if v := got[0].ConfiguredAddressing.IPv4; v == nil || v.Mode != "static" || v.Address != "192.0.2.10" || v.Prefix == nil || *v.Prefix != 24 {
		t.Fatalf("ipv4=%#v", v)
	}
	if v := got[0].ConfiguredAddressing.IPv6; v == nil || v.Mode != "static" || v.Address != "2001:db8::10" || v.Prefix == nil || *v.Prefix != 64 {
		t.Fatalf("ipv6=%#v", v)
	}
	if got[1].ConfiguredAddressing.IPv4.Mode != "dhcp" || got[1].ConfiguredAddressing.IPv6.Mode != "auto" {
		t.Fatalf("dynamic addressing=%#v", got[1].ConfiguredAddressing)
	}
}

func TestSafeNetworksDoesNotEchoInvalidLXCAddress(t *testing.T) {
	raw := map[string]json.RawMessage{
		"net0": json.RawMessage(`"name=eth0,bridge=vmbr0,hwaddr=02:00:00:00:00:01,ip=not-an-address,ip6=192.0.2.1/24"`),
	}
	got := safeNetworks(raw, "lxc")
	if len(got) != 1 || got[0].ConfiguredAddressing == nil {
		t.Fatalf("networks=%#v", got)
	}
	for _, value := range []*struct {
		Mode, Address, Reason string
	}{
		{got[0].ConfiguredAddressing.IPv4.Mode, got[0].ConfiguredAddressing.IPv4.Address, got[0].ConfiguredAddressing.IPv4.Reason},
		{got[0].ConfiguredAddressing.IPv6.Mode, got[0].ConfiguredAddressing.IPv6.Address, got[0].ConfiguredAddressing.IPv6.Reason},
	} {
		if value.Mode != "unavailable" || value.Address != "" || value.Reason != "invalid_pve_config" {
			t.Fatalf("invalid address was not redacted: %#v", value)
		}
	}
}
