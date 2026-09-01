package pve

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
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
	Kind         string            `json:"kind"`
	Node         string            `json:"node"`
	VMID         int               `json:"vmid"`
	Name         string            `json:"name,omitempty"`
	CloudInit    bool              `json:"cloudInit"`
	NetworkCount int               `json:"networkCount"`
	Baseline     *TemplateBaseline `json:"baseline,omitempty"`
	ConfigSHA256 string            `json:"configSha256,omitempty"`
}

type TemplateBaseline struct {
	Cores              int               `json:"cores"`
	Sockets            int               `json:"sockets"`
	MemoryMiB          int               `json:"memoryMiB"`
	BootDisk           TemplateBootDisk  `json:"bootDisk"`
	Networks           []TemplateNetwork `json:"networks"`
	CloudInitDrive     bool              `json:"cloudInitDrive"`
	QGADeviceEnabled   bool              `json:"qgaDeviceEnabled"`
	GuestFirewallEmpty bool              `json:"guestFirewallEmpty"`
}
type TemplateBootDisk struct {
	Interface string `json:"interface"`
	SizeGiB   int    `json:"sizeGiB"`
}
type TemplateNetwork struct {
	Interface string `json:"interface"`
	Bridge    string `json:"bridge"`
	Model     string `json:"model"`
	Firewall  bool   `json:"firewall"`
}

// ErrTemplateBaselineInvalid marks a locally validated PVE template whose
// configuration cannot satisfy the frozen clone baseline. It is distinct from
// transport unavailability so callers do not report a malformed template as a
// connection outage. The wrapped detail is for local diagnostics only.
var ErrTemplateBaselineInvalid = errors.New("PVE template baseline is invalid")

func (c *Client) TemplateInfo(ctx context.Context, kind, node string, vmid int, name string) (TemplateInfo, error) {
	config, err := c.GuestConfig(ctx, kind, node, vmid)
	if err != nil {
		return TemplateInfo{}, err
	}
	if kind != "qemu" {
		cloudInit, networkCount := false, 0
		for key := range config.Raw {
			value, _ := templateConfigString(config.Raw, key)
			cloudInit = cloudInit || strings.Contains(strings.ToLower(value), "cloudinit")
			if templateNetRE.MatchString(key) {
				networkCount++
			}
		}
		return TemplateInfo{Kind: kind, Node: node, VMID: vmid, Name: name, CloudInit: cloudInit, NetworkCount: networkCount}, nil
	}
	baseline, err := templateBaseline(config.Raw)
	if err != nil {
		return TemplateInfo{}, fmt.Errorf("%w: %v", ErrTemplateBaselineInvalid, err)
	}
	rules, err := c.FirewallRules(ctx, FirewallRef{Node: node, Kind: kind, VMID: vmid})
	if err != nil {
		return TemplateInfo{}, err
	}
	ipsets, err := c.FirewallIPSets(ctx, FirewallRef{Node: node, Kind: kind, VMID: vmid})
	if err != nil {
		return TemplateInfo{}, err
	}
	baseline.GuestFirewallEmpty = len(rules) == 0 && len(ipsets) == 0
	canonical, err := json.Marshal(baseline)
	if err != nil {
		return TemplateInfo{}, err
	}
	digest := sha256.Sum256(canonical)
	info := TemplateInfo{Kind: kind, Node: node, VMID: vmid, Name: name, CloudInit: baseline.CloudInitDrive, NetworkCount: len(baseline.Networks), Baseline: &baseline, ConfigSHA256: fmt.Sprintf("%x", digest)}
	return info, nil
}

var templateDiskRE = regexp.MustCompile(`^(scsi|virtio|sata|ide)[0-9]{1,2}$`)
var templateNetRE = regexp.MustCompile(`^net([0-9]|[12][0-9]|3[01])$`)

func templateBaseline(raw map[string]json.RawMessage) (TemplateBaseline, error) {
	cores, ok := templateConfigInt(raw, "cores")
	if !ok || cores < 1 || cores > 128 {
		return TemplateBaseline{}, errors.New("template cores baseline is unavailable")
	}
	// PVE's QEMU schema defines an omitted sockets property as one socket.
	// Canonicalize that documented default so templates created by older
	// PPFlight bundles remain attestable without mutating the PVE guest config.
	sockets := 1
	if configuredSockets, present := templateConfigInt(raw, "sockets"); present {
		sockets = configuredSockets
	}
	if sockets < 1 || sockets > 16 {
		return TemplateBaseline{}, errors.New("template sockets baseline is unavailable")
	}
	memory, ok := templateConfigInt(raw, "memory")
	if !ok || memory < 128 || memory > 4194304 {
		return TemplateBaseline{}, errors.New("template memory baseline is unavailable")
	}
	baseline := TemplateBaseline{Cores: cores, Sockets: sockets, MemoryMiB: memory, Networks: []TemplateNetwork{}}
	diskKeys, networkKeys := []string{}, []string{}
	for key := range raw {
		if templateDiskRE.MatchString(key) {
			diskKeys = append(diskKeys, key)
		}
		if templateNetRE.MatchString(key) {
			networkKeys = append(networkKeys, key)
		}
	}
	sort.Strings(diskKeys)
	sort.Strings(networkKeys)
	for _, key := range diskKeys {
		value, ok := templateConfigString(raw, key)
		if !ok {
			continue
		}
		if strings.Contains(strings.ToLower(value), "cloudinit") {
			baseline.CloudInitDrive = true
			continue
		}
		if baseline.BootDisk.Interface == "" {
			size, err := templateDiskGiB(value)
			if err != nil {
				return TemplateBaseline{}, err
			}
			baseline.BootDisk = TemplateBootDisk{Interface: key, SizeGiB: size}
		}
	}
	if baseline.BootDisk.Interface == "" {
		return TemplateBaseline{}, errors.New("template boot disk baseline is unavailable")
	}
	if !baseline.CloudInitDrive {
		return TemplateBaseline{}, errors.New("template Cloud-Init drive is unavailable")
	}
	for _, key := range networkKeys {
		value, ok := templateConfigString(raw, key)
		if !ok {
			return TemplateBaseline{}, errors.New("template network baseline is invalid")
		}
		network, err := templateNetwork(key, value)
		if err != nil {
			return TemplateBaseline{}, err
		}
		baseline.Networks = append(baseline.Networks, network)
	}
	if len(baseline.Networks) < 1 || len(baseline.Networks) > 8 {
		return TemplateBaseline{}, errors.New("template network baseline is unavailable")
	}
	agent, ok := templateConfigString(raw, "agent")
	baseline.QGADeviceEnabled = ok && (agent == "1" || strings.Contains(agent, "enabled=1"))
	if !baseline.QGADeviceEnabled {
		return TemplateBaseline{}, errors.New("template QGA device is not enabled")
	}
	return baseline, nil
}

func templateConfigString(raw map[string]json.RawMessage, key string) (string, bool) {
	value, ok := raw[key]
	if !ok {
		return "", false
	}
	var text string
	if json.Unmarshal(value, &text) == nil {
		return text, true
	}
	return "", false
}
func templateConfigInt(raw map[string]json.RawMessage, key string) (int, bool) {
	value, ok := raw[key]
	if !ok {
		return 0, false
	}
	var integer int
	if json.Unmarshal(value, &integer) == nil {
		return integer, true
	}
	var text string
	if json.Unmarshal(value, &text) != nil {
		return 0, false
	}
	integer, err := strconv.Atoi(text)
	return integer, err == nil
}
func templateDiskGiB(value string) (int, error) {
	for _, segment := range strings.Split(value, ",") {
		key, size, ok := strings.Cut(strings.TrimSpace(segment), "=")
		if !ok || key != "size" {
			continue
		}
		match := regexp.MustCompile(`^([0-9]+)([KMGT])$`).FindStringSubmatch(size)
		if len(match) != 3 {
			return 0, errors.New("template boot disk size is invalid")
		}
		amount, err := strconv.ParseUint(match[1], 10, 64)
		if err != nil || amount == 0 {
			return 0, errors.New("template boot disk size is invalid")
		}
		shift := map[string]uint{"K": 10, "M": 20, "G": 30, "T": 40}[match[2]]
		bytes := amount << shift
		gib := (bytes + (1 << 30) - 1) >> 30
		if gib < 1 || gib > 1048576 {
			return 0, errors.New("template boot disk size is outside the supported range")
		}
		return int(gib), nil
	}
	return 0, errors.New("template boot disk size is unavailable")
}
func templateNetwork(key, value string) (TemplateNetwork, error) {
	result := TemplateNetwork{Interface: key}
	for _, segment := range strings.Split(value, ",") {
		name, candidate, ok := strings.Cut(strings.TrimSpace(segment), "=")
		if !ok {
			return TemplateNetwork{}, errors.New("template network is invalid")
		}
		switch name {
		case "virtio", "e1000", "e1000e", "vmxnet3", "rtl8139":
			result.Model = name
		case "bridge":
			result.Bridge = candidate
		case "firewall":
			result.Firewall = candidate == "1"
		}
	}
	if result.Model == "" || result.Bridge == "" || !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`).MatchString(result.Bridge) {
		return TemplateNetwork{}, errors.New("template network baseline is incomplete")
	}
	return result, nil
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

type FirewallIPSetEntry struct {
	CIDR    string `json:"cidr"`
	NoMatch *int   `json:"nomatch,omitempty"`
}

func (c *Client) FirewallOptions(ctx context.Context, ref FirewallRef) (FirewallOptions, error) {
	base, err := firewallBase(ref)
	if err != nil {
		return FirewallOptions{}, err
	}
	var result FirewallOptions
	if err := c.get(ctx, base+"/options", nil, &result); err != nil {
		return FirewallOptions{}, err
	}
	if result.Enable != nil {
		if *result.Enable != 0 && *result.Enable != 1 {
			return FirewallOptions{}, fmt.Errorf("invalid firewall enable value")
		}
		return result, nil
	}

	// PVE omits options that still have their schema default. Those defaults
	// are deliberately different for the three firewall scopes: the cluster
	// master switch and guest firewall default to disabled, while host firewall
	// rules default to enabled. Project the effective value explicitly so a
	// strict remote consumer cannot mistake an omitted host value for disabled
	// and enable the cluster master switch under an unsafe SSH assumption.
	effective := 0
	if ref.Node != "" && ref.Kind == "" && ref.VMID == 0 {
		effective = 1
	}
	result.Enable = &effective
	return result, nil
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
	// PVE exposes IPSet collections for the cluster and for QEMU/LXC guests,
	// but not below /nodes/{node}/firewall. Host firewall rules reference the
	// cluster IPSet collection. Treat the node-local collection as empty rather
	// than requesting the API directory's non-existent /ipset child.
	if ref.Node != "" && ref.Kind == "" && ref.VMID == 0 {
		return []FirewallIPSet{}, nil
	}
	base, err := firewallBase(ref)
	if err != nil {
		return nil, err
	}
	var result []FirewallIPSet
	err = c.get(ctx, base+"/ipset", nil, &result)
	return result, err
}

func (c *Client) FirewallIPSetEntries(ctx context.Context, ref FirewallRef, name string) ([]FirewallIPSetEntry, error) {
	base, err := firewallBase(ref)
	if err != nil {
		return nil, err
	}
	part, err := segment(name)
	if err != nil {
		return nil, err
	}
	var result []FirewallIPSetEntry
	err = c.get(ctx, base+"/ipset/"+part, nil, &result)
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
