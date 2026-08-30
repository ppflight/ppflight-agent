package scripts

import (
	"strings"
	"testing"
)

func TestUninstallerProvesPrimaryAgentStoppedBeforeRemoval(t *testing.T) {
	source := readDeploymentFile(t, "uninstall.sh")
	for _, required := range []string{
		"stop_required_unit()",
		"systemctl disable --now \"$unit\"",
		"--property=MainPID --value \"$unit\"",
		"[[ \"$main_pid\" != '0'",
		"ppflight-agent-upgrade.path ppflight-agent-upgrade.service ppflight-agent.service",
		"stop_required_unit \"$required_unit\" || exit 1",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("uninstaller is missing required fail-closed stop contract %q", required)
		}
	}
	if strings.Contains(source, "ppflight-agent.service ppflight-node-exporter.service ppflight-smartctl-exporter.service; do\n  systemctl disable --now \"$unit\" 2>/dev/null || true") {
		t.Fatal("uninstaller still masks primary Agent stop failures")
	}
	stop := strings.Index(source, "stop_required_unit \"$required_unit\" || exit 1")
	remove := strings.Index(source, "rm -f -- /etc/systemd/system/ppflight-agent.service")
	purge := strings.Index(source, "rm -rf -- /etc/ppflight-agent /var/lib/ppflight-agent")
	if stop < 0 || remove < stop || purge < stop {
		t.Fatal("uninstaller can remove Agent files or credential state before proving the primary unit is stopped")
	}
}
