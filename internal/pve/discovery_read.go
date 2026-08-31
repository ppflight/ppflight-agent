package pve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// Permissions is the effective privilege view returned by /access/permissions.
// Paths and privilege names are PVE-defined, but their values are always a
// numeric allow marker. It is intentionally not an arbitrary JSON payload.
type Permissions struct {
	Paths map[string]map[string]int `json:"paths"`
}

// EffectivePermissions returns the token's effective PVE privileges.
func (c *Client) EffectivePermissions(ctx context.Context) (Permissions, error) {
	var paths map[string]map[string]int
	if err := c.get(ctx, "/access/permissions", nil, &paths); err != nil {
		return Permissions{}, err
	}
	return Permissions{Paths: paths}, nil
}

// NetworkInterface is the public, read-only node network configuration. The
// optional fields occur across PVE 8 and 9 and are deliberately pointers where
// a missing field must not be confused with zero.
type NetworkInterface struct {
	Iface           string `json:"iface"`
	Type            string `json:"type"`
	Active          *int   `json:"active,omitempty"`
	Autostart       *int   `json:"autostart,omitempty"`
	BridgePorts     string `json:"bridge_ports,omitempty"`
	BondSlaves      string `json:"slaves,omitempty"`
	HardwareAddress string `json:"hwaddress,omitempty"`
	Address         string `json:"address,omitempty"`
	CIDR            string `json:"cidr,omitempty"`
	Netmask         string `json:"netmask,omitempty"`
	Gateway         string `json:"gateway,omitempty"`
	Address6        string `json:"address6,omitempty"`
	CIDR6           string `json:"cidr6,omitempty"`
	Gateway6        string `json:"gateway6,omitempty"`
	Method          string `json:"method,omitempty"`
	Method6         string `json:"method6,omitempty"`
	MTU             *int   `json:"mtu,omitempty"`
	VLANAware       *int   `json:"vlan_aware,omitempty"`
	BridgeVLANAware *int   `json:"bridge_vlan_aware,omitempty"`
	Comments        string `json:"comments,omitempty"`
}

func (c *Client) NodeNetworks(ctx context.Context, node string) ([]NetworkInterface, error) {
	part, err := segment(node)
	if err != nil {
		return nil, err
	}
	var result []NetworkInterface
	err = c.get(ctx, "/nodes/"+part+"/network", nil, &result)
	return result, err
}

// SDNConfig is one configured cluster SDN VNet. Type is a wire discriminator
// set by the Agent; PVE's /cluster/sdn/vnets response does not consistently
// include a type field across supported releases.
type SDNConfig struct {
	Type string `json:"type"`
	Zone string `json:"zone,omitempty"`
	VNet string `json:"vnet,omitempty"`
}

func (c *Client) ClusterSDN(ctx context.Context) ([]SDNConfig, error) {
	// /cluster/sdn is an API directory. On PVE 8 it returns rows such as
	// {"id":"vnets"}, {"id":"zones"}, ... rather than configured SDN
	// resources. Decoding that directory as SDNConfig produced meaningless
	// {"type":""} rows. Read the fixed VNet collection endpoint instead: it
	// is the resource the website needs to match a configured Zone/VNet and it
	// returns an empty list when SDN is not configured.
	var rows []struct {
		Zone string `json:"zone"`
		VNet string `json:"vnet"`
	}
	if err := c.get(ctx, "/cluster/sdn/vnets", nil, &rows); err != nil {
		return nil, err
	}
	result := make([]SDNConfig, 0, len(rows))
	for _, row := range rows {
		if strings.TrimSpace(row.VNet) == "" {
			return nil, fmt.Errorf("PVE SDN VNet response is missing vnet")
		}
		result = append(result, SDNConfig{Type: "vnet", Zone: row.Zone, VNet: row.VNet})
	}
	return result, nil
}

// TemplateInfo is a template inventory row. CloudInit is inferred from the
// fixed guest config endpoint without exposing secrets such as sshkeys or
// cipassword. Kind is always qemu or lxc.
type TemplateInfo struct {
	Kind         string `json:"kind"`
	Node         string `json:"node"`
	VMID         int    `json:"vmid"`
	Name         string `json:"name,omitempty"`
	CloudInit    bool   `json:"cloudInit"`
	NetworkCount int    `json:"networkCount"`
}

func (c *Client) TemplateInfo(ctx context.Context, kind, node string, vmid int, name string) (TemplateInfo, error) {
	config, err := c.GuestConfig(ctx, kind, node, vmid)
	if err != nil {
		return TemplateInfo{}, err
	}
	info := TemplateInfo{Kind: kind, Node: node, VMID: vmid, Name: name}
	for key, value := range config.Raw {
		var text string
		if json.Unmarshal(value, &text) != nil {
			continue
		}
		if strings.HasPrefix(key, "net") {
			info.NetworkCount++
		}
		if strings.Contains(strings.ToLower(text), "cloudinit") {
			info.CloudInit = true
		}
	}
	return info, nil
}

// FirewallRef permits only the cluster, a node, or a particular QEMU/LXC
// guest. It cannot represent an arbitrary PVE API path.
type FirewallRef struct {
	Node string
	Kind string
	VMID int
}

// FirewallOptions, FirewallRule and FirewallIPSet form a safe configuration
// view. They omit PVE digest/concurrency fields and any IP-set entry contents.
type FirewallOptions struct {
	Enable      *int   `json:"enable,omitempty"`
	PolicyIn    string `json:"policy_in,omitempty"`
	PolicyOut   string `json:"policy_out,omitempty"`
	LogLevelIn  string `json:"log_level_in,omitempty"`
	LogLevelOut string `json:"log_level_out,omitempty"`
	DHCP        *int   `json:"dhcp,omitempty"`
	NDP         *int   `json:"ndp,omitempty"`
	Radv        *int   `json:"radv,omitempty"`
	MACFilter   *int   `json:"macfilter,omitempty"`
}

type FirewallRule struct {
	Pos       int    `json:"pos"`
	Type      string `json:"type"`
	Action    string `json:"action,omitempty"`
	Enable    *int   `json:"enable,omitempty"`
	Direction string `json:"direction,omitempty"`
	Interface string `json:"iface,omitempty"`
	Source    string `json:"source,omitempty"`
	Dest      string `json:"dest,omitempty"`
	Proto     string `json:"proto,omitempty"`
	DPort     string `json:"dport,omitempty"`
	SPort     string `json:"sport,omitempty"`
	Comment   string `json:"comment,omitempty"`
}

type FirewallIPSet struct {
	Name    string `json:"name"`
	Comment string `json:"comment,omitempty"`
}

func (c *Client) FirewallOptions(ctx context.Context, ref FirewallRef) (FirewallOptions, error) {
	base, err := firewallBase(ref)
	if err != nil {
		return FirewallOptions{}, err
	}
	var result FirewallOptions
	err = c.get(ctx, base+"/options", nil, &result)
	return result, err
}

func (c *Client) FirewallRules(ctx context.Context, ref FirewallRef) ([]FirewallRule, error) {
	base, err := firewallBase(ref)
	if err != nil {
		return nil, err
	}
	var result []FirewallRule
	err = c.get(ctx, base+"/rules", nil, &result)
	return result, err
}

func (c *Client) FirewallIPSets(ctx context.Context, ref FirewallRef) ([]FirewallIPSet, error) {
	base, err := firewallBase(ref)
	if err != nil {
		return nil, err
	}
	var result []FirewallIPSet
	err = c.get(ctx, base+"/ipset", nil, &result)
	return result, err
}

func firewallBase(ref FirewallRef) (string, error) {
	if ref.Node == "" {
		if ref.Kind != "" || ref.VMID != 0 {
			return "", fmt.Errorf("cluster firewall scope has a target")
		}
		return "/cluster/firewall", nil
	}
	node, err := segment(ref.Node)
	if err != nil {
		return "", err
	}
	if ref.Kind == "" && ref.VMID == 0 {
		return "/nodes/" + node + "/firewall", nil
	}
	guest, err := guestPath(ref.Kind, ref.Node, ref.VMID)
	if err != nil {
		return "", err
	}
	return guest + "/firewall", nil
}

// ClusterResourcesPage returns a locally bounded slice of VM/LXC resources.
// /cluster/resources does not accept the generic start/limit parameters on
// supported PVE releases, so the client fetches its bounded API response and
// applies the discovery cursor locally.
func (c *Client) ClusterResourcesPage(ctx context.Context, start, limit int) ([]Resource, error) {
	if start < 0 || limit < 1 || limit > 100 {
		return nil, fmt.Errorf("invalid resource page")
	}
	var result []Resource
	if err := c.get(ctx, "/cluster/resources", url.Values{"type": {"vm"}}, &result); err != nil {
		return nil, err
	}
	if start >= len(result) {
		return []Resource{}, nil
	}
	end := start + limit
	if end > len(result) {
		end = len(result)
	}
	return append([]Resource(nil), result[start:end]...), nil
}
