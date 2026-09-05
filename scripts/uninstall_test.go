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
		"list_upgrade_postflight_units()",
		"stop_upgrade_postflight_unit()",
		"stop_upgrade_postflight_units()",
		"systemctl list-units --all --type=service --no-legend --no-pager --full --plain 'ppflight-agent-upgrade-postflight-*.service'",
		`^ppflight-agent-upgrade-postflight-[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\.service$`,
		`systemctl stop "$unit"`,
		`main_pid="$(systemctl show --property=MainPID --value "$unit"`,
		`"$main_pid" != '0'`,
		"for pass in 1 2; do",
		"stop_upgrade_postflight_units || exit 1",
		"stop_required_unit ppflight-host-firewall.service || exit 1",
		"PVE_CREDENTIAL_REMOVER='/usr/local/lib/ppflight-agent/remove-pve-credentials.sh'",
		"HOST_FIREWALL_JOURNAL='/var/lib/ppflight-agent/host-firewall/transaction.json'",
		`"$HOST_FIREWALL_HELPER" host-firewall rollback --uninstall`,
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
	stopPostflight := strings.Index(source, "stop_upgrade_postflight_units || exit 1")
	firewallRollback := strings.Index(source, `"$HOST_FIREWALL_HELPER" host-firewall rollback --uninstall`)
	stopFirewall := strings.Index(source, "stop_required_unit ppflight-host-firewall.service || exit 1")
	revoke := strings.Index(source, "\"$PVE_CREDENTIAL_REMOVER\" || {")
	remove := strings.Index(source, "rm -f -- /etc/systemd/system/ppflight-agent.service")
	reload := strings.Index(source, "systemctl daemon-reload")
	purge := strings.Index(source, "rm -rf -- /etc/ppflight-agent /var/lib/ppflight-agent")
	binaryRemove := strings.Index(source, "rm -f -- /usr/local/bin/ppflight-agent")
	if stop < 0 || stopPostflight < stop || firewallRollback < stopPostflight || stopFirewall < firewallRollback || revoke < stopFirewall || remove < revoke || reload < remove || purge < reload || binaryRemove < purge {
		t.Fatal("uninstaller can remove Agent/PVE credentials or files before proving the primary unit is stopped")
	}
	serviceGuard := strings.Index(source, "if [[ \"$unit\" == *.service ]]")
	pidQuery := strings.Index(source, "main_pid=\"$(systemctl show --property=MainPID --value \"$unit\"")
	if serviceGuard < 0 || pidQuery < serviceGuard {
		t.Fatal("uninstaller queries MainPID before restricting that check to service units")
	}
}
