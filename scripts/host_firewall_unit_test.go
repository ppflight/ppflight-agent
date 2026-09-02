package scripts

import (
	"strings"
	"testing"
)

func TestHostFirewallSupervisorOrdersAroundPVEAndFailsClosed(t *testing.T) {
	unit := readDeploymentFile(t, "..", "packaging", "systemd", "ppflight-host-firewall.service")
	for _, required := range []string{
		"After=network-online.target pve-firewall.service proxmox-firewall.service ufw.service firewalld.service bt.service",
		"PartOf=pve-firewall.service",
		"StartLimitIntervalSec=300s",
		"StartLimitBurst=3",
		"ExecStartPre=/usr/local/bin/ppflight-agent host-firewall enforce",
		"ExecStart=/usr/local/bin/ppflight-agent host-firewall supervise",
		"RestartSec=10s",
		"WantedBy=multi-user.target pve-firewall.service",
	} {
		if !strings.Contains(unit, required) {
			t.Fatalf("host firewall unit is missing lifecycle contract %q", required)
		}
	}
	if strings.Contains(unit, "/bin/sh") || strings.Contains(unit, "bash") {
		t.Fatal("root host firewall supervisor must not execute through a shell")
	}
	if strings.Contains(unit, "ExecStop=") || strings.Contains(unit, "ExecStopPost=") || strings.Contains(unit, "host-firewall suspend") {
		t.Fatal("stopping the native-hook supervisor must not move or remove PVE's hook")
	}
}
