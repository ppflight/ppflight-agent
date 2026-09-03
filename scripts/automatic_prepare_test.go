package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestQuickInstallPinsRepositoryVersionAndPublishedAssetDigests(t *testing.T) {
	const (
		repositoryVersion = "0.1.0-rc.30"
		nodeAMD64         = "b51d8a76aa2a9156a55d501aca6276fae09e262259a5e4e831d2c2222f084e63"
		nodeARM64         = "ad35b605f9954b9f1ffddf5ba054bdc5a98d790b9eae5291e1eeb83f1ecbd0e7"
		smartAMD64        = "875983cd27affc5a682401930e5a8eea3f06c325fe6d6a7228c5547d882685b3"
		smartARM64        = "27353b3adca7f54dd486417412041a17260709c724ea63f5138df2612ecf4299"
	)
	if version := strings.TrimSpace(readDeploymentFile(t, "..", "VERSION")); version != repositoryVersion {
		t.Fatalf("repository VERSION=%q, want release candidate %q", version, repositoryVersion)
	}
	quickInstall := readDeploymentFile(t, "quick-install.sh")
	for _, required := range []string{
		"readonly RELEASE_CHANNEL='main'",
		"readonly RELEASE_BASE='https://raw.githubusercontent.com/ppflight/ppflight-agent/rolling-main'",
		`readonly ARCHIVE="ppflight-agent-main-linux-${RELEASE_ARCH}.tar.gz"`,
		`rolling_cache_key="$(date -u +%s%N)-$$-$rolling_attempt"`,
		`SHA256SUMS?ppflight_cache=$rolling_cache_key`,
		`$ARCHIVE?ppflight_cache=$rolling_cache_key`,
		`--header 'Cache-Control: no-cache'`,
		`grep -Evq '^[0-9a-f]{64}  ppflight-agent-main-linux-(amd64|arm64)\.tar\.gz$' SHA256SUMS`,
		`sha256sum --check --status -`,
		"readonly NODE_EXPORTER_VERSION='1.12.1'",
		"readonly SMARTCTL_EXPORTER_VERSION='0.14.0'",
		"readonly NODE_EXPORTER_SHA256='" + nodeAMD64 + "'",
		"readonly NODE_EXPORTER_SHA256='" + nodeARM64 + "'",
		"readonly SMARTCTL_EXPORTER_SHA256='" + smartAMD64 + "'",
		"readonly SMARTCTL_EXPORTER_SHA256='" + smartARM64 + "'",
	} {
		if !strings.Contains(quickInstall, required) {
			t.Fatalf("quick installer is not pinned to verified published value %q", required)
		}
	}
	for _, forbidden := range []string{"github.com/ppflight/ppflight-agent/releases/download", "readonly RELEASE_TAG=", "readonly RELEASE_SHA256="} {
		if strings.Contains(quickInstall, forbidden) {
			t.Fatalf("rolling installer still depends on versioned GitHub Release material %q", forbidden)
		}
	}
}

func TestWorkflowPublishesRollingMainWithoutCreatingRelease(t *testing.T) {
	workflow := readDeploymentFile(t, "..", ".github", "workflows", "release.yml")
	for _, required := range []string{
		"publish-rolling-main:",
		"github.ref == 'refs/heads/main'",
		"HEAD:refs/heads/rolling-main",
		"manifest.json",
		"ppflight-agent-main-linux-amd64.tar.gz",
		"ppflight-agent-main-linux-arm64.tar.gz",
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("rolling-main publisher is missing %q", required)
		}
	}
}

// TestQuickInstallAutomaticallyPreparesPVEAndVerifiesServices locks the
// non-interactive bootstrap contract.  The released installer owns the
// initial --enable operation; quick-install must then verify real network
// counters and make the installed AG perform a real local PVE readiness check
// before it claims success.
func TestQuickInstallAutomaticallyPreparesPVEAndVerifiesServices(t *testing.T) {
	quickInstall := readDeploymentFile(t, "quick-install.sh")
	compact := compactShell(quickInstall)

	installAt := strings.Index(compact, "scripts/install.sh")
	prepareAt := strings.Index(compact, "/usr/local/bin/ag-pve pve prepare --local-only")
	if installAt < 0 || prepareAt < 0 {
		t.Fatalf("quick installer must install first and then run installed AG local preparation:\n%s", quickInstall)
	}
	if installAt >= prepareAt {
		t.Fatal("quick installer attempted PVE preparation before the Agent was installed")
	}
	installInvocation := compact[installAt:prepareAt]
	if !strings.Contains(installInvocation, "--enable") {
		t.Fatal("quick installer must install the Agent with boot enablement before local preparation")
	}
	if strings.Contains(installInvocation, "--start") {
		t.Fatal("quick installer must not start a disabled/unprepared Agent through install.sh")
	}
	for _, required := range []string{"--install-exporters", "--node-exporter-archive", "--node-exporter-sha256", "--smartctl-exporter-archive", "--smartctl-exporter-sha256"} {
		if !strings.Contains(installInvocation, required) {
			t.Fatalf("quick installer omitted exporter bootstrap option %q", required)
		}
	}
	for _, required := range []string{
		"https://deb.debian.org/debian",
		"https://security.debian.org/debian-security",
		"Dir::Etc::sourcelist=",
		"Dir::Etc::sourceparts=-",
		"Acquire::ForceIPv4=true",
		`apt-get "${apt_options[@]}" update`,
	} {
		if !strings.Contains(quickInstall, required) {
			t.Fatalf("quick installer is missing isolated official smartmontools source contract %q", required)
		}
	}
	if strings.Contains(quickInstall, "DEBIAN_FRONTEND=noninteractive apt-get update") {
		t.Fatal("quick installer must never update the operator's configured Proxmox repositories")
	}
	for _, metric := range []string{"node_network_receive_bytes_total", "node_network_transmit_bytes_total", "node_disk_read_bytes_total", "node_disk_written_bytes_total"} {
		if !strings.Contains(compact, metric) {
			t.Fatalf("quick installer must verify real node_exporter metric %q before reporting success", metric)
		}
	}
	if !strings.Contains(compact, "systemctl restart ppflight-node-exporter.service ppflight-smartctl-exporter.service") {
		t.Fatal("quick installer must restart exporters so updated systemd hardening is applied")
	}
	if !strings.Contains(quickInstall, "journalctl --no-pager -u") {
		t.Fatal("quick installer must expose bounded exporter diagnostics after readiness failure")
	}
	if !strings.Contains(compact, "smartctl_device_(info|smart_status)") || !strings.Contains(compact, "127.0.0.1:9633/metrics") {
		t.Fatal("quick installer must verify at least one real SMART device before reporting success")
	}
	if strings.Contains(compact, "source=simulator") || strings.Contains(compact, "--source simulator") {
		t.Fatal("quick installer must never select a simulator collection path")
	}

	afterPrepare := compact[prepareAt+len("/usr/local/bin/ag-pve pve prepare --local-only"):]
	if !containsStartOfUpgradePath(afterPrepare) {
		t.Fatal("quick installer must start ppflight-agent-upgrade.path after successful local preparation")
	}
	if !containsUnitVerification(afterPrepare, "is-enabled") {
		t.Fatal("quick installer must verify that both Agent units are enabled")
	}
	if !containsUnitVerification(afterPrepare, "is-active") {
		t.Fatal("quick installer must verify that both Agent units are active")
	}

	// Keep a human-facing success message on the success side of preparation.
	// The old installer printed this before the node was ready, which made a
	// failed PVE bootstrap look successful to an operator.
	for _, success := range []string{"安装或更新完成", "自动安装完成"} {
		if position := strings.Index(quickInstall, success); position >= 0 {
			originalPrepare := strings.Index(quickInstall, "/usr/local/bin/ag-pve pve prepare --local-only")
			if originalPrepare >= 0 && position < originalPrepare {
				t.Fatalf("success message %q is printed before local PVE preparation", success)
			}
		}
	}
}

func TestQuickInstallFreshOnlyHostFirewallTransactionOrder(t *testing.T) {
	quickInstall := readDeploymentFile(t, "quick-install.sh")
	classify := strings.Index(quickInstall, `INSTALL_MODE="$(./ppflight-agent host-firewall classify)"`)
	aptMutation := strings.LastIndex(quickInstall, "install_smartmontools")
	installMutation := strings.Index(quickInstall, "\nscripts/install.sh \\")
	prepare := strings.Index(quickInstall, "/usr/local/bin/ag-pve pve prepare --local-only")
	lastServiceCheck := strings.LastIndex(quickInstall, "systemctl is-active --quiet ppflight-smartctl-exporter.service")
	activate := strings.Index(quickInstall, "/usr/local/bin/ppflight-agent host-firewall activate")
	reconcile := strings.Index(quickInstall, "/usr/local/bin/ppflight-agent host-firewall reconcile")
	success := strings.LastIndex(quickInstall, "安装或更新完成")
	if classify < 0 || aptMutation < 0 || installMutation < 0 || prepare < 0 || lastServiceCheck < 0 || activate < 0 || reconcile < 0 || success < 0 {
		t.Fatalf("quick installer is missing host firewall lifecycle anchors")
	}
	if !(classify < aptMutation && classify < installMutation && installMutation < prepare && prepare < lastServiceCheck && lastServiceCheck < activate && activate < success) {
		t.Fatalf("host firewall lifecycle order is unsafe: classify=%d apt=%d install=%d prepare=%d checks=%d activate=%d success=%d", classify, aptMutation, installMutation, prepare, lastServiceCheck, activate, success)
	}
	for _, required := range []string{
		`case "$INSTALL_MODE" in`,
		`if [[ "$INSTALL_MODE" == 'fresh' || "$INSTALL_MODE" == 'resume' ]]; then`,
		`/usr/local/bin/ppflight-agent host-firewall reconcile`,
		"现有安装更新已完成；Cluster/Node/VM/CT 防火墙状态均保持不变",
		"Agent、官网、监控、控制和更新均使用出站连接；状态和 exporter 仍仅监听 127.0.0.1",
	} {
		if !strings.Contains(quickInstall, required) {
			t.Fatalf("quick installer is missing fresh/update firewall contract %q", required)
		}
	}
	for _, forbidden := range []string{"cloudflared", "Cloudflare Tunnel", "Zero Trust", "8888", "sshd_config"} {
		if strings.Contains(quickInstall, forbidden) {
			t.Fatalf("quick installer must not inspect or configure external access prerequisite %q", forbidden)
		}
	}
}

func compactShell(value string) string {
	value = strings.ReplaceAll(value, "\"", "")
	value = strings.ReplaceAll(value, "'", "")
	return strings.Join(strings.Fields(value), " ")
}

func containsStartOfUpgradePath(value string) bool {
	return strings.Contains(value, "systemctl start ppflight-agent-upgrade.path") ||
		strings.Contains(value, "systemctl start ppflight-agent.service ppflight-agent-upgrade.path")
}

func containsUnitVerification(value, action string) bool {
	directAgent := "systemctl " + action + " --quiet ppflight-agent.service"
	directPath := "systemctl " + action + " --quiet ppflight-agent-upgrade.path"
	if strings.Contains(value, directAgent) && strings.Contains(value, directPath) {
		return true
	}
	// A small loop is less repetitive, but it must still cover both units.
	return strings.Contains(value, "for unit in ppflight-agent.service ppflight-agent-upgrade.path") &&
		strings.Contains(value, "systemctl "+action+" --quiet $unit")
}

func TestQuickInstallDoesNotMaskLocalPreparationFailure(t *testing.T) {
	quickInstall := readDeploymentFile(t, "quick-install.sh")
	compact := compactShell(quickInstall)
	prepare := "/usr/local/bin/ag-pve pve prepare --local-only"
	position := strings.Index(compact, prepare)
	if position < 0 {
		t.Fatalf("quick installer is missing %q", prepare)
	}

	// `set -e` is sufficient for a standalone command; an explicit guard is
	// also valid.  What is not valid is swallowing this failure and continuing
	// into a start/verification or a success message.
	line := lineContaining(quickInstall, "/usr/local/bin/ag-pve pve prepare --local-only")
	if strings.Contains(line, "|| true") {
		t.Fatal("quick installer masks a failed local PVE preparation")
	}
	if !strings.Contains(quickInstall, "set -Eeuo pipefail") {
		t.Fatal("quick installer needs fail-fast shell settings for PVE preparation")
	}
}

func TestQuickInstallPreparationFailureDoesNotStartOrReportSuccess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the isolated quick-install shell fixture uses POSIX PATH semantics")
	}
	output, log, err := runQuickInstallFixture(t, 23)
	if err == nil {
		t.Fatalf("quick installer succeeded after local PVE preparation failed: output=%s log=%s", output, log)
	}
	if strings.Contains(output, "安装或更新完成") {
		t.Fatalf("quick installer reported success after failed local preparation: %s", output)
	}
	if strings.Contains(log, "ppflight-agent-upgrade.path") || strings.Contains(log, "systemctl:is-active --quiet ppflight-agent.service") {
		t.Fatalf("quick installer advanced Agent activation after failed local preparation:\n%s", log)
	}
}

func TestQuickInstallStartsAndVerifiesBothUnitsAfterLocalPreparation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the isolated quick-install shell fixture uses POSIX PATH semantics")
	}
	output, log, err := runQuickInstallFixture(t, 0)
	if err != nil {
		t.Fatalf("quick installer failed after successful local preparation: %v\noutput=%s\nlog=%s", err, output, log)
	}
	install := strings.Index(log, "install:")
	prepare := strings.Index(log, "prepare:pve prepare --local-only")
	start := strings.Index(log, "systemctl:start ppflight-agent-upgrade.path")
	if install < 0 || prepare < 0 || start < 0 || install >= prepare || prepare >= start {
		t.Fatalf("quick installer lifecycle order is wrong:\n%s", log)
	}
	installLine := strings.Split(strings.TrimPrefix(log[install:], "install:"), "\n")[0]
	if !strings.Contains(installLine, "--enable") || strings.Contains(installLine, "--start") {
		t.Fatalf("installer activation flags=%q, want --enable without --start", installLine)
	}
	for _, command := range []string{
		"systemctl:is-enabled --quiet ppflight-agent.service",
		"systemctl:is-enabled --quiet ppflight-agent-upgrade.path",
		"systemctl:is-enabled --quiet ppflight-node-exporter.service",
		"systemctl:is-enabled --quiet ppflight-smartctl-exporter.service",
		"systemctl:is-active --quiet ppflight-agent.service",
		"systemctl:is-active --quiet ppflight-agent-upgrade.path",
		"systemctl:is-active --quiet ppflight-node-exporter.service",
		"systemctl:is-active --quiet ppflight-smartctl-exporter.service",
	} {
		if !strings.Contains(log, command) {
			t.Fatalf("quick installer did not verify %q:\n%s", command, log)
		}
	}
	if !strings.Contains(output, "安装或更新完成") {
		t.Fatalf("quick installer omitted its success confirmation: %s", output)
	}
}

func runQuickInstallFixture(t *testing.T, prepareExit int) (string, string, error) {
	t.Helper()
	root := t.TempDir()
	log := filepath.Join(root, "commands.log")
	mockDir := filepath.Join(root, "bin")
	if err := os.Mkdir(mockDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ag := filepath.Join(root, "ag-pve")
	writeQuickInstallMock(t, ag, "#!/usr/bin/env bash\nprintf 'prepare:%s\\n' \"$*\" >>\"${TEST_QUICK_LOG:?}\"\nexit \"${TEST_PREPARE_EXIT:?}\"\n")
	smartctl := filepath.Join(root, "smartctl")
	writeQuickInstallMock(t, smartctl, "#!/usr/bin/env bash\nexit 0\n")
	writeQuickInstallMock(t, filepath.Join(mockDir, "curl"), "#!/usr/bin/env bash\nset -Eeuo pipefail\nout=''\nwhile [[ $# -gt 0 ]]; do\n  case \"$1\" in\n    --output) out=$2; shift 2 ;;\n    *) shift ;;\n  esac\ndone\n[[ -n $out ]]\nif [[ ${out##*/} == SHA256SUMS ]]; then\n  printf '%064d  ppflight-agent-main-linux-amd64.tar.gz\\n%064d  ppflight-agent-main-linux-arm64.tar.gz\\n' 0 0 >\"$out\"\nelse\n  printf 'node_network_receive_bytes_total{device=\"eth0\"} 1\\nnode_network_transmit_bytes_total{device=\"eth0\"} 2\\nnode_disk_read_bytes_total{device=\"sda\"} 3\\nnode_disk_written_bytes_total{device=\"sda\"} 4\\nsmartctl_device_info{device=\"/dev/sda\"} 1\\n' >\"$out\"\nfi\n")
	writeQuickInstallMock(t, filepath.Join(mockDir, "sha256sum"), "#!/usr/bin/env bash\ncase \" $* \" in *' --check '*) exit 0 ;; esac\nexit 97\n")
	writeQuickInstallMock(t, filepath.Join(mockDir, "tar"), "#!/usr/bin/env bash\nset -Eeuo pipefail\nmkdir -p ppflight-agent/scripts\nprintf '#!/usr/bin/env bash\\nprintf \\\"install:%%s\\\\n\\\" \\\"$*\\\" >>\\\"${TEST_QUICK_LOG:?}\\\"\\n' >ppflight-agent/scripts/install.sh\nchmod 0700 ppflight-agent/scripts/install.sh\nprintf '#!/usr/bin/env bash\\nif [[ $1 == host-firewall && $2 == classify ]]; then printf \\\"update\\\\n\\\"; exit 0; fi\\nif [[ $1 == host-firewall && $2 == reconcile ]]; then exit 0; fi\\nexit 97\\n' >ppflight-agent/ppflight-agent\nchmod 0700 ppflight-agent/ppflight-agent\nprintf 'hash  ppflight-agent\\n' >ppflight-agent/ppflight-agent.sha256\n")
	writeQuickInstallMock(t, filepath.Join(mockDir, "systemctl"), "#!/usr/bin/env bash\nprintf 'systemctl:%s\\n' \"$*\" >>\"${TEST_QUICK_LOG:?}\"\n")
	writeQuickInstallMock(t, filepath.Join(mockDir, "pveversion"), "#!/usr/bin/env bash\nprintf 'pve-manager/8.4.0/fixture\\n'\n")
	writeQuickInstallMock(t, filepath.Join(mockDir, "apt-get"), "#!/usr/bin/env bash\nprintf 'apt-get:%s\\n' \"$*\" >>\"${TEST_QUICK_LOG:?}\"\n")

	raw := readDeploymentFile(t, "quick-install.sh")
	const rootCheck = "[[ ${EUID:-$(id -u)} -eq 0 ]] || die '请在 PVE root 终端执行'"
	patched := strings.Replace(raw, rootCheck, ": # isolated fixture bypasses host root check", 1)
	if patched == raw {
		t.Fatal("could not isolate quick installer root check")
	}
	patched = strings.Replace(patched, "/usr/local/bin/ag-pve", ag, 1)
	patched = strings.Replace(patched, "/usr/local/bin/ppflight-agent host-firewall reconcile", "./ppflight-agent host-firewall reconcile", 1)
	patched = strings.ReplaceAll(patched, "/usr/sbin/smartctl", smartctl)
	if !strings.Contains(patched, ag+" pve prepare --local-only") {
		t.Fatal("could not redirect installed AG command into quick-install fixture")
	}
	script := filepath.Join(root, "quick-install.sh")
	if err := os.WriteFile(script, []byte(patched), 0o700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(testBash(t), script)
	command.Env = append(os.Environ(),
		"PATH="+mockDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"TEST_QUICK_LOG="+log,
		"TEST_PREPARE_EXIT="+strconv.Itoa(prepareExit),
	)
	output, err := command.CombinedOutput()
	logRaw, readErr := os.ReadFile(log)
	if readErr != nil && !os.IsNotExist(readErr) {
		t.Fatal(readErr)
	}
	return string(output), string(logRaw), err
}

func writeQuickInstallMock(t *testing.T, filename, body string) {
	t.Helper()
	if err := os.WriteFile(filename, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
}

func lineContaining(value, needle string) string {
	for _, line := range strings.Split(value, "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	return ""
}
