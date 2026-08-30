// Package collector orchestrates PVE, QGA and local exporter collection while
// keeping unavailable fields distinct from measured zero values.
package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ppflight/ppflight-agent/internal/config"
	"github.com/ppflight/ppflight-agent/internal/exporter"
	"github.com/ppflight/ppflight-agent/internal/observation"
	"github.com/ppflight/ppflight-agent/internal/pve"
)

type Due struct {
	Inventory bool
	Guest     bool
	Host      bool
	SMART     bool
}

type Source interface {
	Collect(context.Context, time.Time, Due) (observation.Snapshot, error)
	PVEClient() *pve.Client
}

// ProgressSource lets the Agent watchdog observe bounded forward progress
// inside a long collection round. The callback carries no data and may be
// invoked concurrently by per-node/per-guest workers.
type ProgressSource interface {
	SetProgressReporter(func())
}

func New(cfg config.Config, secrets config.Secrets) (Source, error) {
	if cfg.PVE.Source != "api" {
		return nil, errors.New("PVE collection is disabled; complete AG local PVE preparation before starting the agent")
	}
	client, err := pve.NewClient(pve.Config{
		Endpoint: cfg.PVE.Endpoint, TokenID: secrets.PVETokenID, TokenSecret: secrets.PVETokenSecret,
		CAFile: cfg.PVE.CAFile, TLSServerName: cfg.PVE.TLSServerName, InsecureSkipTLS: cfg.PVE.InsecureSkipTLS,
		Timeout: cfg.PVE.Timeout.Duration, MaxResponseBytes: cfg.PVE.MaxResponseBytes,
	})
	if err != nil {
		return nil, err
	}
	localNode := cfg.PVE.LocalNode
	if localNode == "" || localNode == "auto" {
		localNode, err = os.Hostname()
		if err != nil || strings.TrimSpace(localNode) == "" {
			return nil, errors.New("cannot determine local PVE node name")
		}
	}
	return &PVECollector{
		cfg: cfg, client: client, localNode: localNode,
		qga: make(map[string]observation.QGAView), networks: make(map[string][]observation.Network),
		components: make(map[string]observation.Availability),
	}, nil
}

type PVECollector struct {
	mu         sync.Mutex
	cfg        config.Config
	client     *pve.Client
	localNode  string
	version    pve.Version
	nodes      []observation.Node
	storages   []observation.Storage
	tasks      []observation.Task
	qga        map[string]observation.QGAView
	networks   map[string][]observation.Network
	host       *exporter.HostObservation
	smart      *exporter.SmartObservation
	components map[string]observation.Availability
	progress   func()
}

func (c *PVECollector) PVEClient() *pve.Client { return c.client }

func (c *PVECollector) SetProgressReporter(reporter func()) {
	c.progress = reporter
	c.client.SetProgressReporter(reporter)
}

func (c *PVECollector) madeProgress() {
	if c.progress != nil {
		c.progress()
	}
}

func (c *PVECollector) Collect(ctx context.Context, now time.Time, due Due) (observation.Snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.madeProgress()
	now = now.UTC()
	if c.version.Version == "" || due.Inventory {
		if version, err := c.client.Version(ctx); err == nil {
			c.version = version
			c.setAvailable("pveVersion", now, c.cfg.Collection.InventoryInterval.Duration)
		} else {
			c.setUnavailable("pveVersion", now, safeReason(err))
		}
		c.madeProgress()
	}
	resources, err := c.client.ClusterResources(ctx)
	c.madeProgress()
	if err != nil {
		c.setUnavailable("pve", now, safeReason(err))
		return c.snapshot(now, nil), fmt.Errorf("collect PVE resources: %w", err)
	}
	c.setAvailable("pve", now, c.cfg.Collection.SampleInterval.Duration*3)
	resources = c.localResources(resources)
	if due.Inventory || len(c.nodes) == 0 {
		c.collectInventory(ctx, now)
	}
	if due.Guest {
		c.collectGuestDetails(ctx, now, resources)
	}
	if due.Host && c.cfg.Exporters.Node.Enabled {
		c.collectHost(ctx, now)
	}
	if due.SMART && c.cfg.Exporters.SMART.Enabled {
		c.collectSMART(ctx, now)
	}
	guests := make([]observation.Guest, 0, len(resources))
	for _, resource := range resources {
		if resource.Type != "qemu" && resource.Type != "lxc" {
			continue
		}
		key := guestKey(resource.Type, resource.VMID)
		guest := observation.Guest{
			VMID: resource.VMID, GuestType: resource.Type, Name: resource.Name, Node: resource.Node,
			Template: resource.Template != 0, QGA: c.qga[key], Networks: cloneNetworks(c.networks[key]), ObservedAt: now,
			PVE: observation.PVEGuestView{
				Availability: observation.Availability{Available: true, ObservedAt: now, FreshUntil: now.Add(c.cfg.Collection.SampleInterval.Duration * 3)},
				Status:       resource.Status, CPU: floatPointer(resource.CPU), CPUCount: floatPointer(resource.MaxCPU),
				MemoryUsed: uintPointer(resource.Mem), MemoryTotal: uintPointer(resource.MaxMem),
				DiskUsed: uintPointer(resource.Disk), DiskTotal: uintPointer(resource.MaxDisk),
				DiskRead: cloneUint(resource.DiskRead), DiskWrite: cloneUint(resource.DiskWrite),
				IngressBytes: cloneUint(resource.NetIn), EgressBytes: cloneUint(resource.NetOut), UptimeSeconds: cloneUint(resource.Uptime),
			},
		}
		if resource.Type != "qemu" {
			guest.QGA = observation.QGAView{Availability: observation.Availability{Available: false, ObservedAt: now, UnavailableReason: "not-applicable-to-lxc"}}
		} else if guest.QGA.Availability.ObservedAt.IsZero() {
			guest.QGA = observation.QGAView{Availability: observation.Availability{Available: false, ObservedAt: now, UnavailableReason: "not-yet-probed"}}
		}
		guests = append(guests, guest)
	}
	sort.Slice(guests, func(i, j int) bool {
		if guests[i].Node == guests[j].Node {
			return guests[i].VMID < guests[j].VMID
		}
		return guests[i].Node < guests[j].Node
	})
	return c.snapshot(now, guests), nil
}

func (c *PVECollector) localResources(resources []pve.Resource) []pve.Resource {
	if c.cfg.PVE.CollectClusterWide {
		return resources
	}
	result := make([]pve.Resource, 0, len(resources))
	for _, resource := range resources {
		if resource.Node == c.localNode {
			result = append(result, resource)
		}
	}
	return result
}

func (c *PVECollector) collectInventory(ctx context.Context, now time.Time) {
	nodes, err := c.client.Nodes(ctx)
	c.madeProgress()
	if err != nil {
		c.setUnavailable("pveNodes", now, safeReason(err))
		return
	}
	if !c.cfg.PVE.CollectClusterWide {
		filtered := nodes[:0]
		for _, node := range nodes {
			if node.Node == c.localNode {
				filtered = append(filtered, node)
			}
		}
		nodes = filtered
	}
	type nodeResult struct {
		index    int
		status   pve.NodeStatus
		storages []pve.Storage
		tasks    []pve.Task
		err      error
	}
	results := make([]nodeResult, len(nodes))
	sem := make(chan struct{}, c.cfg.Collection.RequestConcurrency)
	var group sync.WaitGroup
	for index, node := range nodes {
		index, node := index, node
		group.Add(1)
		go func() {
			defer group.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			status, statusErr := c.client.NodeStatus(ctx, node.Node)
			c.madeProgress()
			storageRows, storageErr := c.client.NodeStorage(ctx, node.Node)
			c.madeProgress()
			tasks, taskErr := c.client.NodeTasks(ctx, node.Node, 100)
			c.madeProgress()
			results[index] = nodeResult{index: index, status: status, storages: storageRows, tasks: tasks, err: errors.Join(statusErr, storageErr, taskErr)}
		}()
	}
	group.Wait()
	collectedNodes := make([]observation.Node, 0, len(nodes))
	var collectedStorage []observation.Storage
	var collectedTasks []observation.Task
	for index, node := range nodes {
		result := results[index]
		status := result.status
		entry := observation.Node{Name: node.Node, Status: node.Status, ObservedAt: now}
		if result.err == nil || status.PVEVersion != "" || status.Memory.Total > 0 {
			entry.CPU = floatPointer(status.CPU)
			entry.CPUCount = intPointer(status.CPUInfo.CPUs)
			entry.CPUModel = status.CPUInfo.Model
			entry.MemoryUsed, entry.MemoryTotal = &status.Memory.Used, &status.Memory.Total
			entry.SwapUsed, entry.SwapTotal = &status.Swap.Used, &status.Swap.Total
			entry.RootUsed, entry.RootTotal = &status.RootFS.Used, &status.RootFS.Total
			entry.LoadAverage = append([]float64(nil), status.LoadAvg...)
			entry.UptimeSeconds, entry.IOWaitRatio, entry.PVEVersion = &status.Uptime, floatPointer(status.Wait), status.PVEVersion
		} else {
			entry.CPU, entry.CPUCount, entry.MemoryUsed, entry.MemoryTotal, entry.UptimeSeconds = cloneFloat(node.CPU), cloneInt(node.MaxCPU), cloneUint(node.Mem), cloneUint(node.MaxMem), cloneUint(node.Uptime)
		}
		collectedNodes = append(collectedNodes, entry)
		for _, storage := range result.storages {
			state := "offline"
			if storage.Enabled != 0 && storage.Active != 0 {
				state = "online"
			}
			collectedStorage = append(collectedStorage, observation.Storage{
				Node: node.Node, Name: storage.Storage, Kind: storage.Type, Content: storage.Content,
				Status: state, Shared: storage.Shared != 0, UsedBytes: cloneUint(storage.Used),
				TotalBytes: cloneUint(storage.Total), FreeBytes: cloneUint(storage.Avail), ObservedAt: now,
			})
		}
		for _, task := range result.tasks {
			started := time.Unix(task.StartTime, 0).UTC()
			var ended *time.Time
			if task.EndTime != nil {
				value := time.Unix(*task.EndTime, 0).UTC()
				ended = &value
			}
			collectedTasks = append(collectedTasks, observation.Task{
				Node: node.Node, Type: task.Type, ResourceID: task.ID, Status: task.Status, StartedAt: started, EndedAt: ended,
			})
		}
	}
	c.nodes, c.storages, c.tasks = collectedNodes, collectedStorage, collectedTasks
	c.setAvailable("pveNodes", now, c.cfg.Collection.InventoryInterval.Duration*2)
}

func (c *PVECollector) collectGuestDetails(ctx context.Context, now time.Time, resources []pve.Resource) {
	type result struct {
		key      string
		qga      observation.QGAView
		networks []observation.Network
	}
	results := make(chan result, len(resources))
	sem := make(chan struct{}, c.cfg.Collection.GuestRequestConcurrency)
	var group sync.WaitGroup
	for _, resource := range resources {
		if resource.Template != 0 || resource.Type != "qemu" && resource.Type != "lxc" {
			continue
		}
		resource := resource
		group.Add(1)
		go func() {
			defer group.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			key := guestKey(resource.Type, resource.VMID)
			configValue, configErr := c.client.GuestConfig(ctx, resource.Type, resource.Node, resource.VMID)
			c.madeProgress()
			networks := []observation.Network(nil)
			if configErr == nil {
				networks = safeNetworks(configValue.Raw, resource.Type)
			}
			qgaView := observation.QGAView{Availability: observation.Availability{Available: false, ObservedAt: now, FreshUntil: now.Add(c.cfg.Collection.GuestInterval.Duration), UnavailableReason: "not-applicable-to-lxc"}}
			if resource.Type == "qemu" && resource.Status == "running" {
				guest, _ := c.client.ProbeGuestAgent(ctx, resource.Node, resource.VMID)
				c.madeProgress()
				available := guest.Availability["info"] == pve.Available
				reason := "guest-agent-unavailable"
				if available {
					reason = ""
				}
				qgaView = observation.QGAView{
					Availability: observation.Availability{Available: available, ObservedAt: now, FreshUntil: now.Add(c.cfg.Collection.GuestInterval.Duration * 2), UnavailableReason: reason},
					Info:         guest.Info, OS: guest.OS, Filesystems: guest.Filesystems, Interfaces: guest.Interfaces, Capabilities: guest.Availability,
				}
			} else if resource.Type == "qemu" {
				qgaView.Availability.UnavailableReason = "guest-not-running"
			}
			results <- result{key: key, qga: qgaView, networks: networks}
		}()
	}
	group.Wait()
	close(results)
	for result := range results {
		c.qga[result.key], c.networks[result.key] = result.qga, result.networks
	}
	c.setAvailable("qga", now, c.cfg.Collection.GuestInterval.Duration*2)
}

func (c *PVECollector) collectHost(ctx context.Context, now time.Time) {
	samples, err := exporter.Fetch(ctx, exporter.FetchConfig{URL: c.cfg.Exporters.Node.URL, Timeout: c.cfg.Exporters.Node.Timeout.Duration, MaxBodyBytes: c.cfg.Exporters.Node.MaxResponseBytes})
	c.madeProgress()
	if err != nil {
		c.setUnavailable("nodeExporter", now, safeReason(err))
		return
	}
	value := exporter.NormalizeHost(samples, now)
	c.host = &value
	c.setAvailable("nodeExporter", now, c.cfg.Collection.MonitoringInterval.Duration*3)
}

func (c *PVECollector) collectSMART(ctx context.Context, now time.Time) {
	samples, err := exporter.Fetch(ctx, exporter.FetchConfig{URL: c.cfg.Exporters.SMART.URL, Timeout: c.cfg.Exporters.SMART.Timeout.Duration, MaxBodyBytes: c.cfg.Exporters.SMART.MaxResponseBytes})
	c.madeProgress()
	if err != nil {
		c.setUnavailable("smartctlExporter", now, safeReason(err))
		return
	}
	value := exporter.NormalizeSMART(samples, now)
	c.smart = &value
	c.setAvailable("smartctlExporter", now, c.cfg.Collection.SMARTInterval.Duration*2)
}

func (c *PVECollector) snapshot(now time.Time, guests []observation.Guest) observation.Snapshot {
	components := make(map[string]observation.Availability, len(c.components))
	for key, value := range c.components {
		components[key] = value
	}
	return observation.Snapshot{
		SchemaVersion: 1, Mode: c.cfg.Mode, AgentRef: c.cfg.Identity.AgentRef,
		CollectorRef: c.cfg.Identity.CollectorRef, ClusterRef: c.cfg.Identity.ClusterRef,
		NodeRef: c.nodeRef(), Site: c.cfg.Identity.Site, ObservedAt: now, PVEVersion: c.version,
		Components: components, Nodes: append([]observation.Node(nil), c.nodes...),
		Storages: append([]observation.Storage(nil), c.storages...), Tasks: append([]observation.Task(nil), c.tasks...),
		Guests: guests, Host: cloneHost(c.host), SMART: cloneSMART(c.smart),
	}
}

func (c *PVECollector) nodeRef() string {
	if c.cfg.Identity.NodeRef == "auto" || c.cfg.Identity.NodeRef == "" {
		return c.localNode
	}
	return c.cfg.Identity.NodeRef
}

func (c *PVECollector) setAvailable(component string, now time.Time, freshness time.Duration) {
	c.components[component] = observation.Availability{Available: true, ObservedAt: now, FreshUntil: now.Add(freshness)}
}
func (c *PVECollector) setUnavailable(component string, now time.Time, reason string) {
	c.components[component] = observation.Availability{Available: false, ObservedAt: now, UnavailableReason: reason}
}

func guestKey(kind string, vmid int) string { return kind + "/" + strconv.Itoa(vmid) }

func safeNetworks(raw map[string]json.RawMessage, guestType string) []observation.Network {
	var result []observation.Network
	for index := 0; index < 32; index++ {
		value, ok := raw["net"+strconv.Itoa(index)]
		if !ok {
			continue
		}
		var text string
		if json.Unmarshal(value, &text) != nil || len(text) > 4096 {
			continue
		}
		network := observation.Network{Index: index, Interface: "net" + strconv.Itoa(index)}
		for position, part := range strings.Split(text, ",") {
			pieces := strings.SplitN(part, "=", 2)
			if len(pieces) != 2 {
				continue
			}
			key, item := strings.TrimSpace(pieces[0]), strings.TrimSpace(pieces[1])
			if guestType == "qemu" && position == 0 {
				network.Model, network.MAC = safeText(key, 32), safeText(item, 64)
				continue
			}
			switch key {
			case "name":
				network.GuestName = safeText(item, 32)
			case "type":
				network.Model = safeText(item, 32)
			case "hwaddr":
				network.MAC = safeText(item, 64)
			case "bridge":
				network.Bridge = safeText(item, 64)
			case "tag":
				network.VLAN = safeText(item, 16)
			case "mtu":
				network.MTU = safeText(item, 16)
			case "rate":
				network.RateMbps = safeText(item, 32)
			case "firewall":
				network.Firewall = safeText(item, 8)
			case "link_down":
				network.LinkDown = safeText(item, 8)
			}
		}
		result = append(result, network)
	}
	return result
}

func safeText(value string, max int) string {
	value = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, value)
	if len(value) > max {
		return value[:max]
	}
	return value
}

func safeReason(err error) string {
	if err == nil {
		return "unavailable"
	}
	var httpErr *pve.HTTPError
	if errors.As(err, &httpErr) {
		return fmt.Sprintf("pve-http-%d", httpErr.StatusCode)
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "timeout") || strings.Contains(text, "deadline"):
		return "timeout"
	case strings.Contains(text, "certificate") || strings.Contains(text, "tls"):
		return "tls-error"
	default:
		return "connection-error"
	}
}

func uintPointer(value float64) *uint64 {
	if value < 0 || value > float64(^uint64(0)) {
		return nil
	}
	result := uint64(value)
	return &result
}
func floatPointer(value float64) *float64 { result := value; return &result }
func intPointer(value int) *int           { result := value; return &result }
func cloneUint(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}
func cloneFloat(value *float64) *float64 {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}
func cloneInt(value *int) *int {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}
func cloneNetworks(value []observation.Network) []observation.Network {
	return append([]observation.Network(nil), value...)
}
func cloneHost(value *exporter.HostObservation) *exporter.HostObservation {
	if value == nil {
		return nil
	}
	copyValue := *value
	copyValue.CPUSeconds = append([]exporter.CPUSecondsObservation(nil), value.CPUSeconds...)
	copyValue.Filesystems = append([]exporter.FilesystemObservation(nil), value.Filesystems...)
	copyValue.Interfaces = append([]exporter.InterfaceObservation(nil), value.Interfaces...)
	copyValue.Pressure = append([]exporter.PressureObservation(nil), value.Pressure...)
	copyValue.HardwareTemperatures = append([]exporter.HardwareTemperatureObservation(nil), value.HardwareTemperatures...)
	copyValue.ZFSPools = append([]exporter.ZFSPoolObservation(nil), value.ZFSPools...)
	return &copyValue
}
func cloneSMART(value *exporter.SmartObservation) *exporter.SmartObservation {
	if value == nil {
		return nil
	}
	copyValue := *value
	copyValue.Devices = append([]exporter.SmartDeviceObservation(nil), value.Devices...)
	return &copyValue
}
