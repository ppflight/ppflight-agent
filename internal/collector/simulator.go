package collector

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ppflight/ppflight-agent/internal/config"
	"github.com/ppflight/ppflight-agent/internal/exporter"
	"github.com/ppflight/ppflight-agent/internal/observation"
	"github.com/ppflight/ppflight-agent/internal/pve"
)

type Simulator struct {
	mu      sync.Mutex
	cfg     config.Config
	tick    uint64
	rx      uint64
	tx      uint64
	started time.Time
}

func NewSimulator(cfg config.Config) *Simulator {
	return &Simulator{cfg: cfg, rx: 12_000_000_000, tx: 34_000_000_000, started: time.Now().UTC()}
}

func (s *Simulator) PVEClient() *pve.Client { return nil }

func (s *Simulator) Collect(_ context.Context, now time.Time, _ Due) (observation.Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tick++
	s.rx += 1_250_000
	s.tx += 2_500_000
	now = now.UTC()
	if s.tick == 121 { // deterministic long-running reset fixture
		s.rx, s.tx = 1000, 2000
	}
	value := func(v float64) exporter.Value { return exporter.Value{Value: &v} }
	memoryTotal, memoryUsed := uint64(128<<30), uint64(53<<30)
	swapTotal, swapUsed := uint64(8<<30), uint64(1<<30)
	rootTotal, rootUsed := uint64(256<<30), uint64(91<<30)
	uptime := uint64(now.Sub(s.started).Seconds())
	cpu, wait, cpus := 0.23, 0.01, 32
	qgaTotal, qgaUsed := uint64(80_000_000_000), uint64(32_000_000_000)
	qgaRX, qgaTX := s.rx-4096, s.tx-8192
	snapshot := observation.Snapshot{
		SchemaVersion: 1, Mode: s.cfg.Mode, AgentRef: s.cfg.Identity.AgentRef,
		CollectorRef: s.cfg.Identity.CollectorRef, ClusterRef: s.cfg.Identity.ClusterRef,
		NodeRef: "pve-sim-01", Site: s.cfg.Identity.Site, ObservedAt: now,
		PVEVersion: pve.Version{Version: "8.4.1", Release: "8.4", RepoID: "simulator"},
		Components: map[string]observation.Availability{
			"pve":              {Available: true, ObservedAt: now, FreshUntil: now.Add(time.Minute)},
			"qga":              {Available: true, ObservedAt: now, FreshUntil: now.Add(5 * time.Minute)},
			"nodeExporter":     {Available: true, ObservedAt: now, FreshUntil: now.Add(time.Minute)},
			"smartctlExporter": {Available: true, ObservedAt: now, FreshUntil: now.Add(10 * time.Minute)},
		},
		Nodes: []observation.Node{{
			Name: "pve-sim-01", Status: "online", CPU: &cpu, CPUCount: &cpus, CPUModel: "PPFlight Simulator CPU",
			MemoryUsed: &memoryUsed, MemoryTotal: &memoryTotal, SwapUsed: &swapUsed, SwapTotal: &swapTotal,
			RootUsed: &rootUsed, RootTotal: &rootTotal, LoadAverage: []float64{0.42, 0.31, 0.25},
			UptimeSeconds: &uptime, IOWaitRatio: &wait, PVEVersion: "pve-manager/8.4.1", ObservedAt: now,
		}},
		Storages: []observation.Storage{{Node: "pve-sim-01", Name: "local-zfs", Kind: "zfspool", Status: "online", UsedBytes: &rootUsed, TotalBytes: &rootTotal, ObservedAt: now}},
		Tasks:    []observation.Task{{Node: "pve-sim-01", Type: "vzdump", ResourceID: "101", Status: "OK", StartedAt: now.Add(-time.Hour)}},
		Guests: []observation.Guest{
			{
				VMID: 101, GuestType: "qemu", Name: "sim-qga-vps", Node: "pve-sim-01", ObservedAt: now,
				PVE: observation.PVEGuestView{Availability: observation.Availability{Available: true, ObservedAt: now, FreshUntil: now.Add(time.Minute)}, Status: "running", CPU: pointer(0.18), CPUCount: pointer(4), MemoryUsed: pointerU(3 << 30), MemoryTotal: pointerU(8 << 30), DiskUsed: pointerU(20 << 30), DiskTotal: pointerU(80 << 30), DiskRead: pointerU(s.tick * 4096), DiskWrite: pointerU(s.tick * 8192), IngressBytes: pointerU(s.rx), EgressBytes: pointerU(s.tx), UptimeSeconds: &uptime},
				QGA: observation.QGAView{
					Availability: observation.Availability{Available: true, ObservedAt: now, FreshUntil: now.Add(5 * time.Minute)},
					Info:         &pve.GuestAgentInfo{Version: "8.2.0"}, OS: &pve.GuestOSInfo{Name: "Debian GNU/Linux", PrettyName: "Debian 12", VersionID: "12", Machine: "x86_64"},
					Filesystems: []pve.GuestFilesystem{{Name: "/dev/vda1", Mountpoint: "/", Type: "ext4", TotalBytes: &qgaTotal, UsedBytes: &qgaUsed}},
					Interfaces:  []pve.GuestInterface{{Name: "eth0", HardwareAddress: "02:00:00:00:01:01", IPAddresses: []pve.GuestIPAddress{{Address: "192.0.2.101", Prefix: 24, Type: "ipv4"}}, Statistics: &pve.GuestInterfaceStats{RxBytes: &qgaRX, TxBytes: &qgaTX}}},
				},
				Networks: []observation.Network{{Index: 0, Model: "virtio", MAC: "02:00:00:00:01:01", Bridge: "vmbr0", VLAN: "100", RateMbps: "180"}},
			},
			{
				VMID: 102, GuestType: "qemu", Name: "sim-no-qga-vps", Node: "pve-sim-01", ObservedAt: now,
				PVE: observation.PVEGuestView{Availability: observation.Availability{Available: true, ObservedAt: now, FreshUntil: now.Add(time.Minute)}, Status: "running", CPU: pointer(0.07), CPUCount: pointer(2), MemoryUsed: pointerU(1 << 30), MemoryTotal: pointerU(4 << 30), DiskTotal: pointerU(40 << 30), IngressBytes: pointerU(s.rx / 2), EgressBytes: pointerU(s.tx / 2), UptimeSeconds: &uptime},
				QGA: observation.QGAView{Availability: observation.Availability{Available: false, ObservedAt: now, UnavailableReason: "guest-agent-unavailable"}},
			},
		},
	}
	snapshot.Host = &exporter.HostObservation{
		ObservedAt: now, Load1: value(0.42), MemoryTotalBytes: value(float64(memoryTotal)), MemoryAvailableBytes: value(float64(memoryTotal - memoryUsed)),
		SwapTotalBytes: value(float64(swapTotal)), SwapFreeBytes: value(float64(swapTotal - swapUsed)),
		Filesystems: []exporter.FilesystemObservation{{Device: "rpool/ROOT/pve-1", Mountpoint: "/", FSType: "zfs", SizeBytes: value(float64(rootTotal)), AvailableBytes: value(float64(rootTotal - rootUsed)), ReadOnly: value(0)}},
		Interfaces:  []exporter.InterfaceObservation{{Device: "vmbr0", ReceiveBytes: value(float64(s.rx)), TransmitBytes: value(float64(s.tx)), LinkUp: value(1)}},
		ZFSPools:    []exporter.ZFSPoolObservation{{Pool: "rpool", SizeBytes: value(float64(rootTotal)), AllocatedBytes: value(float64(rootUsed)), FreeBytes: value(float64(rootTotal - rootUsed)), Healthy: value(1)}},
	}
	snapshot.SMART = &exporter.SmartObservation{ObservedAt: now, Devices: []exporter.SmartDeviceObservation{{Device: "/dev/nvme0", Healthy: value(1), TemperatureCelsius: value(39), PercentageUsed: value(4), MediaErrors: value(0), CapacityBytes: value(1_920_000_000_000), Model: "SIM-NVME", Serial: "SIM0001", Protocol: "NVMe"}}}
	return snapshot, nil
}

func pointer(value float64) *float64 { return &value }
func pointerU(value uint64) *uint64  { return &value }

func (s *Simulator) String() string { return fmt.Sprintf("simulator(tick=%d)", s.tick) }
