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
