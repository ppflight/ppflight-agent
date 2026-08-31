package scripts

import (
	"strings"
	"testing"
)

func TestExporterUnitsUseCrossKernelCompatibleSyscallDenyList(t *testing.T) {
	for _, name := range []string{
		"../packaging/systemd/ppflight-node-exporter.service",
		"../packaging/systemd/ppflight-smartctl-exporter.service",
	} {
		source := readDeploymentFile(t, name)
		if strings.Contains(source, "SystemCallFilter=@system-service") {
			t.Fatalf("%s uses a brittle positive syscall allow-list", name)
		}
		if !strings.Contains(source, "SystemCallFilter=~") {
			t.Fatalf("%s must retain a syscall deny-list", name)
		}
	}
}

func TestNodeExporterUnitEnablesOnlyAgentMetricCollectors(t *testing.T) {
	source := readDeploymentFile(t, "../packaging/systemd/ppflight-node-exporter.service")
	for _, required := range []string{
		"--collector.disable-defaults",
		"--collector.cpu",
		"--collector.diskstats",
		"--collector.filesystem",
		"--collector.hwmon",
		"--collector.loadavg",
		"--collector.meminfo",
		"--collector.netclass",
		"--collector.netdev",
		"--collector.pressure",
		"--collector.zfs",
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("node exporter unit is missing %q", required)
		}
	}
	for _, forbidden := range []string{"--collector.systemd", "--collector.processes", "--collector.timex"} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("node exporter unit unnecessarily enables %q", forbidden)
		}
	}
}
