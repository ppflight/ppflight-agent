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
		case "/api2/json/cluster/sdn/vnets":
			fmt.Fprint(w, `{"data":[{"vnet":"blue","zone":"public"}]}`)
		case "/api2/json/nodes/pve1/qemu/101/config":
			fmt.Fprint(w, `{"data":{"cores":2,"sockets":1,"memory":1024,"scsi0":"local-lvm:vm-101-disk-0,size=8G","ide2":"local:cloudinit,media=cdrom","net0":"virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=0","agent":"enabled=1"}}`)
		case "/api2/json/cluster/resources":
			if r.URL.Query().Get("type") != "vm" || r.URL.Query().Has("start") || r.URL.Query().Has("limit") {
				t.Errorf("unexpected page query %s", r.URL.RawQuery)
			}
			fmt.Fprint(w, `{"data":[{"id":"qemu/100","type":"qemu","vmid":100},{"id":"qemu/101","type":"qemu","vmid":101}]}`)
		case "/api2/json/cluster/firewall/options", "/api2/json/nodes/pve1/firewall/options", "/api2/json/nodes/pve1/qemu/101/firewall/options":
			fmt.Fprint(w, `{"data":{"enable":1}}`)
		case "/api2/json/cluster/firewall/rules", "/api2/json/nodes/pve1/firewall/rules", "/api2/json/nodes/pve1/qemu/101/firewall/rules":
			fmt.Fprint(w, `{"data":[{"pos":0,"type":"in","action":"ACCEPT"}]}`)
		case "/api2/json/cluster/firewall/ipset", "/api2/json/nodes/pve1/qemu/101/firewall/ipset":
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
	if got, err := c.ClusterSDN(ctx); err != nil || len(got) != 1 || got[0].Type != "vnet" || got[0].VNet != "blue" || got[0].Zone != "public" {
		t.Fatalf("sdn %#v: %v", got, err)
	}
	if got, err := c.TemplateInfo(ctx, "qemu", "pve1", 101, "golden"); err != nil || !got.CloudInit || got.NetworkCount != 1 || got.Baseline == nil || got.Baseline.BootDisk.SizeGiB != 8 || got.ConfigSHA256 == "" {
		t.Fatalf("template %#v: %v", got, err)
	}
	if got, err := c.ClusterResourcesPage(ctx, 1, 1); err != nil || len(got) != 1 || got[0].VMID != 101 {
		t.Fatalf("local resource page %#v: %v", got, err)
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
	if seen["/api2/json/nodes/pve1/firewall/ipset"] {
		t.Fatal("requested the non-existent node firewall IPSet collection")
	}
	if len(seen) != 13 {
		t.Fatalf("saw %d fixed paths, want 13", len(seen))
	}
}

func TestNodeFirewallIPSetsAreNotAnAPICollection(t *testing.T) {
	requested := false
	c, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requested = true
		http.Error(w, "node firewall has no ipset child", http.StatusNotFound)
	}))
	defer server.Close()
	got, err := c.FirewallIPSets(context.Background(), FirewallRef{Node: "pve1"})
	if err != nil || len(got) != 0 {
		t.Fatalf("node firewall IP sets = %#v, %v", got, err)
	}
	if requested {
		t.Fatal("node firewall IPSet lookup reached the PVE API")
	}
}

func TestFirewallOptionsProjectsScopeSpecificEnableDefaults(t *testing.T) {
	c, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api2/json/cluster/firewall/options",
			"/api2/json/nodes/pve1/firewall/options",
			"/api2/json/nodes/pve1/qemu/101/firewall/options":
			fmt.Fprint(w, `{"data":{"digest":"ignored"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	tests := []struct {
		name string
		ref  FirewallRef
		want int
	}{
		{name: "cluster defaults disabled", ref: FirewallRef{}, want: 0},
		{name: "node defaults enabled", ref: FirewallRef{Node: "pve1"}, want: 1},
		{name: "guest defaults disabled", ref: FirewallRef{Node: "pve1", Kind: "qemu", VMID: 101}, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.FirewallOptions(context.Background(), tt.ref)
			if err != nil || got.Enable == nil || *got.Enable != tt.want {
				t.Fatalf("options = %#v, %v; want enable=%d", got, err, tt.want)
			}
		})
	}
}

func TestFirewallOptionsRejectsInvalidExplicitEnable(t *testing.T) {
	c, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"data":{"enable":2}}`)
	}))
	defer server.Close()
	if _, err := c.FirewallOptions(context.Background(), FirewallRef{}); err == nil {
		t.Fatal("accepted invalid explicit firewall enable value")
	}
}

func TestClusterSDNReadsVNetCollectionNotAPIDirectory(t *testing.T) {
	calledRoot := false
	c, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api2/json/cluster/sdn":
			calledRoot = true
			fmt.Fprint(w, `{"data":[{"id":"vnets"},{"id":"zones"},{"id":"controllers"},{"id":"ipams"},{"id":"dns"}]}`)
		case "/api2/json/cluster/sdn/vnets":
			fmt.Fprint(w, `{"data":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	got, err := c.ClusterSDN(context.Background())
	if err != nil || len(got) != 0 {
		t.Fatalf("empty SDN VNet catalog = %#v, %v", got, err)
	}
	if calledRoot {
		t.Fatal("ClusterSDN read the /cluster/sdn API directory")
	}
}

func TestClusterSDNRejectsVNetWithoutIdentity(t *testing.T) {
	c, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"data":[{"zone":"public"}]}`)
	}))
	defer server.Close()
	if _, err := c.ClusterSDN(context.Background()); err == nil {
		t.Fatal("ClusterSDN accepted a VNet row without vnet")
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
