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
		"[[ \"$unit\" == *.service ]]",
		"\"$unit\" == *.service && -n \"$main_pid\" && \"$main_pid\" != '0'",
		"ppflight-agent-upgrade.path ppflight-agent-upgrade.service ppflight-agent.service",
		"stop_required_unit \"$required_unit\" || exit 1",
		"PVE_CREDENTIAL_REMOVER='/usr/local/lib/ppflight-agent/remove-pve-credentials.sh'",
		"\"$PVE_CREDENTIAL_REMOVER\" || {",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("uninstaller is missing required fail-closed stop contract %q", required)
		}
	}
	if strings.Contains(source, "ppflight-agent.service ppflight-node-exporter.service ppflight-smartctl-exporter.service; do\n  systemctl disable --now \"$unit\" 2>/dev/null || true") {
		t.Fatal("uninstaller still masks primary Agent stop failures")
	}
	stop := strings.Index(source, "stop_required_unit \"$required_unit\" || exit 1")
	revoke := strings.Index(source, "\"$PVE_CREDENTIAL_REMOVER\" || {")
	remove := strings.Index(source, "rm -f -- /etc/systemd/system/ppflight-agent.service")
	reload := strings.Index(source, "systemctl daemon-reload")
	purge := strings.Index(source, "rm -rf -- /etc/ppflight-agent /var/lib/ppflight-agent")
	binaryRemove := strings.Index(source, "rm -f -- /usr/local/bin/ppflight-agent")
	if stop < 0 || revoke < stop || remove < revoke || reload < remove || purge < reload || binaryRemove < purge {
		t.Fatal("uninstaller can remove Agent/PVE credentials or files before proving the primary unit is stopped")
	}
	serviceGuard := strings.Index(source, "if [[ \"$unit\" == *.service ]]")
	pidQuery := strings.Index(source, "main_pid=\"$(systemctl show --property=MainPID --value \"$unit\"")
	if serviceGuard < 0 || pidQuery < serviceGuard {
		t.Fatal("uninstaller queries MainPID before restricting that check to service units")
	}
}
