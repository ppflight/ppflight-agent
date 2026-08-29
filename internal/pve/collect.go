package pve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Resource is a member of the cluster resource inventory. The fields work for
// PVE 8 and 9 QEMU/LXC responses; optional API fields remain nil/empty.
type Resource struct {
	ID        string  `json:"id"`
	Type      string  `json:"type"`
	Node      string  `json:"node"`
	VMID      int     `json:"vmid"`
	Name      string  `json:"name"`
	Status    string  `json:"status"`
	Template  int     `json:"template"`
	CPU       float64 `json:"cpu"`
	MaxCPU    float64 `json:"maxcpu"`
	Mem       float64 `json:"mem"`
	MaxMem    float64 `json:"maxmem"`
	Disk      float64 `json:"disk"`
	MaxDisk   float64 `json:"maxdisk"`
	DiskRead  *uint64 `json:"diskread,omitempty"`
	DiskWrite *uint64 `json:"diskwrite,omitempty"`
	NetIn     *uint64 `json:"netin,omitempty"`
	NetOut    *uint64 `json:"netout,omitempty"`
	Uptime    *uint64 `json:"uptime,omitempty"`
}

// Version describes the public PVE API implementation. Unknown fields are
// intentionally ignored so this remains compatible across PVE 8.x and 9.x.
type Version struct {
	Version string `json:"version"`
	Release string `json:"release"`
	RepoID  string `json:"repoid"`
}

func (c *Client) Version(ctx context.Context) (Version, error) {
	var result Version
	if err := c.get(ctx, "/version", nil, &result); err != nil {
		return Version{}, err
	}
	return result, nil
}

// NodeStatus reports host status. PVE reports several numerical fields as
// JSON numbers, hence float64 is used where fractional CPU usage is expected.
type NodeStatus struct {
	CPU        float64      `json:"cpu"`
	CPUInfo    CPUInfo      `json:"cpuinfo"`
	KSM        KSMInfo      `json:"ksm"`
	LoadAvg    NumericSlice `json:"loadavg"`
	Memory     Memory       `json:"memory"`
	RootFS     Memory       `json:"rootfs"`
	Swap       Memory       `json:"swap"`
	Uptime     uint64       `json:"uptime"`
	PVEVersion string       `json:"pveversion"`
	Wait       float64      `json:"wait"`
}

// NumericSlice accepts PVE's historically inconsistent loadavg response:
// depending on endpoint/version it can be a JSON number or a quoted number.
type NumericSlice []float64

func (v *NumericSlice) UnmarshalJSON(data []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	result := make(NumericSlice, 0, len(raw))
	for _, item := range raw {
		var n float64
		if err := json.Unmarshal(item, &n); err != nil {
			var s string
			if strErr := json.Unmarshal(item, &s); strErr != nil {
				return err
			}
			parsed, parseErr := strconv.ParseFloat(s, 64)
			if parseErr != nil {
				return parseErr
			}
			n = parsed
		}
		result = append(result, n)
	}
	*v = result
	return nil
}

type CPUInfo struct {
	CPUs    int    `json:"cpus"`
	Model   string `json:"model"`
	Sockets int    `json:"sockets"`
}
type KSMInfo struct {
	Shared uint64 `json:"shared"`
}
type Memory struct {
	Total     uint64  `json:"total"`
	Used      uint64  `json:"used"`
	Free      uint64  `json:"free"`
	Available *uint64 `json:"available,omitempty"`
}

type Storage struct {
	Storage string  `json:"storage"`
	Type    string  `json:"type"`
	Content string  `json:"content"`
	Active  int     `json:"active"`
	Enabled int     `json:"enabled"`
	Shared  int     `json:"shared"`
	Total   *uint64 `json:"total,omitempty"`
	Used    *uint64 `json:"used,omitempty"`
	Avail   *uint64 `json:"avail,omitempty"`
}

// Node is the cluster inventory representation returned by /nodes.
type Node struct {
	Node   string   `json:"node"`
	Status string   `json:"status"`
	Level  string   `json:"level"`
	CPU    *float64 `json:"cpu,omitempty"`
	MaxCPU *int     `json:"maxcpu,omitempty"`
	Mem    *uint64  `json:"mem,omitempty"`
	MaxMem *uint64  `json:"maxmem,omitempty"`
	Uptime *uint64  `json:"uptime,omitempty"`
}

// Task is a recent asynchronous PVE job. EndTime remains nil while it runs.
type Task struct {
	UPID      string `json:"upid"`
	Node      string `json:"node"`
	PID       int    `json:"pid"`
	Type      string `json:"type"`
	ID        string `json:"id"`
	User      string `json:"user"`
	Status    string `json:"status"`
	StartTime int64  `json:"starttime"`
	EndTime   *int64 `json:"endtime,omitempty"`
}

// GuestCurrent is returned by both QEMU and LXC status/current endpoints.
// It preserves unknown PVE-version-specific fields in Raw for forward
// compatibility without making false zero-value observations.
type GuestCurrent struct {
	Status  string                     `json:"status"`
	CPU     *float64                   `json:"cpu,omitempty"`
	Mem     *uint64                    `json:"mem,omitempty"`
	MaxMem  *uint64                    `json:"maxmem,omitempty"`
	MaxDisk *uint64                    `json:"maxdisk,omitempty"`
	Disk    *uint64                    `json:"disk,omitempty"`
	NetIn   *uint64                    `json:"netin,omitempty"`
	NetOut  *uint64                    `json:"netout,omitempty"`
	Uptime  *uint64                    `json:"uptime,omitempty"`
	Raw     map[string]json.RawMessage `json:"-"`
}

func (g *GuestCurrent) UnmarshalJSON(data []byte) error {
	type alias GuestCurrent
	var plain alias
	if err := json.Unmarshal(data, &plain); err != nil {
		return err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*g = GuestCurrent(plain)
	g.Raw = raw
	return nil
}

// GuestConfig preserves the config as JSON. Different guest kinds and PVE
// releases have divergent config schemas; Raw avoids lossy assumptions.
type GuestConfig struct {
	Digest string                     `json:"digest"`
	Raw    map[string]json.RawMessage `json:"-"`
}

func (g *GuestConfig) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	g.Raw = raw
	if v, ok := raw["digest"]; ok {
		_ = json.Unmarshal(v, &g.Digest)
	}
	return nil
}

func (c *Client) ClusterResources(ctx context.Context) ([]Resource, error) {
	var result []Resource
	if err := c.get(ctx, "/cluster/resources", url.Values{"type": {"vm"}}, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// Nodes returns all known cluster nodes, including nodes without a guest.
func (c *Client) Nodes(ctx context.Context) ([]Node, error) {
	var result []Node
	if err := c.get(ctx, "/nodes", nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}
func (c *Client) NodeStatus(ctx context.Context, node string) (NodeStatus, error) {
	part, err := segment(node)
	if err != nil {
		return NodeStatus{}, err
	}
	var result NodeStatus
	err = c.get(ctx, "/nodes/"+part+"/status", nil, &result)
	return result, err
}
func (c *Client) NodeStorage(ctx context.Context, node string) ([]Storage, error) {
	part, err := segment(node)
	if err != nil {
		return nil, err
	}
	var result []Storage
	err = c.get(ctx, "/nodes/"+part+"/storage", nil, &result)
	return result, err
}
func (c *Client) NodeTasks(ctx context.Context, node string, limit int) ([]Task, error) {
	part, err := segment(node)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	var result []Task
	err = c.get(ctx, "/nodes/"+part+"/tasks", url.Values{"limit": {strconv.Itoa(limit)}}, &result)
	return result, err
}
func (c *Client) GuestCurrent(ctx context.Context, kind, node string, vmid int) (GuestCurrent, error) {
	var result GuestCurrent
	guest, err := guestPath(kind, node, vmid)
	if err != nil {
		return result, err
	}
	err = c.get(ctx, guest+"/status/current", nil, &result)
	return result, err
}
func (c *Client) GuestConfig(ctx context.Context, kind, node string, vmid int) (GuestConfig, error) {
	var result GuestConfig
	guest, err := guestPath(kind, node, vmid)
	if err != nil {
		return result, err
	}
	err = c.get(ctx, guest+"/config", nil, &result)
	return result, err
}

// TaskStatus gets an individual task state. The UPID is path escaped and is
// never interpolated into a request path verbatim.
func (c *Client) TaskStatus(ctx context.Context, node, upid string) (Task, error) {
	if strings.TrimSpace(upid) == "" {
		return Task{}, fmt.Errorf("task UPID is required")
	}
	var result Task
	part, err := segment(node)
	if err != nil {
		return result, err
	}
	if strings.ContainsAny(upid, "/\\\x00") {
		return result, errors.New("invalid task UPID")
	}
	err = c.get(ctx, "/nodes/"+part+"/tasks/"+upid+"/status", nil, &result)
	return result, err
}

func guestPath(kind, node string, vmid int) (string, error) {
	if vmid < 1 || vmid > 999999999 {
		return "", fmt.Errorf("invalid guest VMID %d", vmid)
	}
	if kind != "qemu" && kind != "lxc" {
		return "", fmt.Errorf("unsupported guest kind %q", kind)
	}
	part, err := segment(node)
	if err != nil {
		return "", err
	}
	return "/nodes/" + part + "/" + kind + "/" + strconv.Itoa(vmid), nil
}
func segment(s string) (string, error) {
	if strings.TrimSpace(s) == "" || strings.ContainsAny(s, "/\\\x00") {
		return "", errors.New("invalid PVE path segment")
	}
	// The value is placed into URL.Path (rather than interpolated into a URL
	// string), so net/url performs the one required escaping pass. Escaping here
	// as well would encode '%' a second time and break PVE UPIDs/hostnames.
	return s, nil
}
