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
		repositoryVersion = "0.1.0-rc.18"
		// quick-install is advanced only after the immutable GitHub assets for
		// the repository version exist and their complete archive digests have
		// been verified. During the release commit it therefore still pins the
		// most recent published version.
		quickInstallVersion = "0.1.0-rc.18"
		expectedAMD64       = "4836b8508776173a18b5659dc87321b3893f1a812cab154a346f1c61967cf73d"
		expectedARM64       = "284805c5218d7f89aa32bad71462c84ba528e899637200b196acb99a6717d6d4"
		nodeAMD64           = "b51d8a76aa2a9156a55d501aca6276fae09e262259a5e4e831d2c2222f084e63"
		nodeARM64           = "ad35b605f9954b9f1ffddf5ba054bdc5a98d790b9eae5291e1eeb83f1ecbd0e7"
		smartAMD64          = "875983cd27affc5a682401930e5a8eea3f06c325fe6d6a7228c5547d882685b3"
		smartARM64          = "27353b3adca7f54dd486417412041a17260709c724ea63f5138df2612ecf4299"
	)
	if version := strings.TrimSpace(readDeploymentFile(t, "..", "VERSION")); version != repositoryVersion {
		t.Fatalf("repository VERSION=%q, want release candidate %q", version, repositoryVersion)
	}
	quickInstall := readDeploymentFile(t, "quick-install.sh")
	for _, required := range []string{
		"readonly RELEASE_TAG='v" + quickInstallVersion + "'",
		"readonly RELEASE_VERSION='" + quickInstallVersion + "'",
		"readonly RELEASE_SHA256='" + expectedAMD64 + "'",
		"readonly RELEASE_SHA256='" + expectedARM64 + "'",
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
	for _, required := range []string{"--install-exporters", "--node-exporter-archive", "--node-exporter-sha256", "--smartctl-exporter-archive", "--smartctl-exporter-sha256", "--install-smartmontools"} {
		if !strings.Contains(installInvocation, required) {
			t.Fatalf("quick installer omitted exporter bootstrap option %q", required)
		}
	}
	for _, metric := range []string{"node_network_receive_bytes_total", "node_network_transmit_bytes_total", "node_disk_read_bytes_total", "node_disk_written_bytes_total"} {
		if !strings.Contains(compact, metric) {
			t.Fatalf("quick installer must verify real node_exporter metric %q before reporting success", metric)
		}
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
	writeQuickInstallMock(t, filepath.Join(mockDir, "curl"), "#!/usr/bin/env bash\nset -Eeuo pipefail\nout=''\nwhile [[ $# -gt 0 ]]; do\n  case \"$1\" in\n    --output) out=$2; shift 2 ;;\n    *) shift ;;\n  esac\ndone\n[[ -n $out ]]\nprintf 'node_network_receive_bytes_total{device=\"eth0\"} 1\\nnode_network_transmit_bytes_total{device=\"eth0\"} 2\\nnode_disk_read_bytes_total{device=\"sda\"} 3\\nnode_disk_written_bytes_total{device=\"sda\"} 4\\nsmartctl_device_info{device=\"/dev/sda\"} 1\\n' >\"$out\"\n")
	writeQuickInstallMock(t, filepath.Join(mockDir, "sha256sum"), "#!/usr/bin/env bash\ncase \" $* \" in *' --check '*) exit 0 ;; esac\nexit 97\n")
	writeQuickInstallMock(t, filepath.Join(mockDir, "tar"), "#!/usr/bin/env bash\nset -Eeuo pipefail\nmkdir -p ppflight-agent/scripts\nprintf '#!/usr/bin/env bash\\nprintf \\\"install:%%s\\\\n\\\" \\\"$*\\\" >>\\\"${TEST_QUICK_LOG:?}\\\"\\n' >ppflight-agent/scripts/install.sh\nchmod 0700 ppflight-agent/scripts/install.sh\nprintf 'binary\\n' >ppflight-agent/ppflight-agent\nprintf 'hash  ppflight-agent\\n' >ppflight-agent/ppflight-agent.sha256\n")
	writeQuickInstallMock(t, filepath.Join(mockDir, "systemctl"), "#!/usr/bin/env bash\nprintf 'systemctl:%s\\n' \"$*\" >>\"${TEST_QUICK_LOG:?}\"\n")

	raw := readDeploymentFile(t, "quick-install.sh")
	const rootCheck = "[[ ${EUID:-$(id -u)} -eq 0 ]] || die '请在 PVE root 终端执行'"
	patched := strings.Replace(raw, rootCheck, ": # isolated fixture bypasses host root check", 1)
	if patched == raw {
		t.Fatal("could not isolate quick installer root check")
	}
	patched = strings.Replace(patched, "/usr/local/bin/ag-pve", ag, 1)
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
