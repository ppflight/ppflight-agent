package pve

import (
	"context"
	"fmt"
	"net/http"
	"testing"
)

func TestDiscoveryReadMethodsUseOnlyFixedGETPaths(t *testing.T) {
	seen := map[string]bool{}
	c, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method %s", r.Method)
		}
		seen[r.URL.Path] = true
		switch r.URL.Path {
		case "/api2/json/access/permissions":
			fmt.Fprint(w, `{"data":{"/":{"Sys.Audit":1}}}`)
		case "/api2/json/nodes/pve1/network":
			fmt.Fprint(w, `{"data":[{"iface":"vmbr0","type":"bridge","active":1,"bridge_ports":"eno1","hwaddress":"02:00:00:00:00:01","cidr":"192.0.2.10/24","gateway":"192.0.2.1","mtu":1500,"bridge_vlan_aware":1,"comments":"public uplink"}]}`)
		case "/api2/json/cluster/sdn":
			fmt.Fprint(w, `{"data":[{"type":"vnet","vnet":"blue","ipam":"pve"}]}`)
		case "/api2/json/nodes/pve1/qemu/101/config":
			fmt.Fprint(w, `{"data":{"ide2":"local:cloudinit","net0":"virtio=aa"}}`)
		case "/api2/json/cluster/resources":
			if r.URL.Query().Get("type") != "vm" || r.URL.Query().Get("start") != "0" || r.URL.Query().Get("limit") != "10" {
				t.Errorf("unexpected page query %s", r.URL.RawQuery)
			}
			fmt.Fprint(w, `{"data":[]}`)
		case "/api2/json/cluster/firewall/options", "/api2/json/nodes/pve1/firewall/options", "/api2/json/nodes/pve1/qemu/101/firewall/options":
			fmt.Fprint(w, `{"data":{"enable":1}}`)
		case "/api2/json/cluster/firewall/rules", "/api2/json/nodes/pve1/firewall/rules", "/api2/json/nodes/pve1/qemu/101/firewall/rules":
			fmt.Fprint(w, `{"data":[{"pos":0,"type":"in","action":"ACCEPT"}]}`)
		case "/api2/json/cluster/firewall/ipset", "/api2/json/nodes/pve1/firewall/ipset", "/api2/json/nodes/pve1/qemu/101/firewall/ipset":
			fmt.Fprint(w, `{"data":[{"name":"trusted"}]}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	ctx := context.Background()
	if got, err := c.EffectivePermissions(ctx); err != nil || got.Paths["/"]["Sys.Audit"] != 1 {
		t.Fatalf("permissions %#v: %v", got, err)
	}
	if got, err := c.NodeNetworks(ctx, "pve1"); err != nil || len(got) != 1 || got[0].Type != "bridge" || got[0].BridgePorts != "eno1" || got[0].HardwareAddress != "02:00:00:00:00:01" || got[0].MTU == nil || *got[0].MTU != 1500 || got[0].BridgeVLANAware == nil || *got[0].BridgeVLANAware != 1 {
		t.Fatalf("networks %#v: %v", got, err)
	}
	if got, err := c.ClusterSDN(ctx); err != nil || len(got) != 1 || got[0].IPAM != "pve" {
		t.Fatalf("sdn %#v: %v", got, err)
	}
	if got, err := c.TemplateInfo(ctx, "qemu", "pve1", 101, "golden"); err != nil || !got.CloudInit || got.NetworkCount != 1 {
		t.Fatalf("template %#v: %v", got, err)
	}
	if _, err := c.ClusterResourcesPage(ctx, 0, 10); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []FirewallRef{{}, {Node: "pve1"}, {Node: "pve1", Kind: "qemu", VMID: 101}} {
		if _, err := c.FirewallOptions(ctx, ref); err != nil {
			t.Fatal(err)
		}
		if _, err := c.FirewallRules(ctx, ref); err != nil {
			t.Fatal(err)
		}
		if _, err := c.FirewallIPSets(ctx, ref); err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 14 {
		t.Fatalf("saw %d fixed paths, want 14", len(seen))
	}
}

func TestClusterResourcesPageBoundsArguments(t *testing.T) {
	c, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"data":[]}`) }))
	defer server.Close()
	for _, value := range []struct{ start, limit int }{{-1, 1}, {0, 0}, {0, 101}} {
		if _, err := c.ClusterResourcesPage(context.Background(), value.start, value.limit); err == nil {
			t.Fatalf("accepted %#v", value)
		}
	}
}
