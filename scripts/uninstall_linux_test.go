//go:build !windows

package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestUninstallPathUnitAcceptsInactiveWithoutMainPIDQuery(t *testing.T) {
	output, log, err := runStopRequiredUnit(t, "ppflight-agent-upgrade.path", "loaded", "inactive", "unexpected-path-pid")
	if err != nil {
		t.Fatalf("inactive path unit was rejected: %v\noutput=%s\nlog=%s", err, output, log)
	}
	for _, command := range []string{
		"show --property=LoadState --value ppflight-agent-upgrade.path",
		"disable --now ppflight-agent-upgrade.path",
		"show --property=ActiveState --value ppflight-agent-upgrade.path",
	} {
		if !strings.Contains(log, command) {
			t.Fatalf("path stop did not invoke %q:\n%s", command, log)
		}
	}
	if strings.Contains(log, "--property=MainPID") {
		t.Fatalf("path stop queried an inapplicable MainPID:\n%s", log)
	}
}

func TestUninstallServiceRequiresExplicitZeroMainPID(t *testing.T) {
	for _, test := range []struct {
		name    string
		mainPID string
		wantErr bool
	}{
		{name: "empty pid", mainPID: "", wantErr: true},
		{name: "live pid", mainPID: "741", wantErr: true},
		{name: "zero pid", mainPID: "0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			output, log, err := runStopRequiredUnit(t, "ppflight-agent.service", "loaded", "inactive", test.mainPID)
			if (err != nil) != test.wantErr {
				t.Fatalf("MainPID=%q err=%v wantErr=%t\noutput=%s\nlog=%s", test.mainPID, err, test.wantErr, output, log)
			}
			if !strings.Contains(log, "show --property=MainPID --value ppflight-agent.service") {
				t.Fatalf("service stop did not verify MainPID=%q:\n%s", test.mainPID, log)
			}
		})
	}
}

func TestUninstallRefusesActivePathUnitWithoutMainPIDFallback(t *testing.T) {
	output, log, err := runStopRequiredUnit(t, "ppflight-agent-upgrade.path", "loaded", "active", "")
	if err == nil {
		t.Fatalf("active path unit was accepted: output=%s log=%s", output, log)
	}
	if strings.Contains(log, "--property=MainPID") {
		t.Fatalf("active path unit fell back to an inapplicable MainPID query:\n%s", log)
	}
}

func runStopRequiredUnit(t *testing.T, unit, loadState, activeState, mainPID string) (string, string, error) {
	t.Helper()
	root := t.TempDir()
	log := filepath.Join(root, "systemctl.log")
	mockDir := filepath.Join(root, "bin")
	if err := os.Mkdir(mockDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeUninstallMock(t, filepath.Join(mockDir, "systemctl"), `#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$*" >>"${MOCK_SYSTEMCTL_LOG:?}"
case "$1" in
  show)
    case "$2" in
      --property=LoadState) printf '%s\n' "${MOCK_LOAD_STATE:?}" ;;
      --property=ActiveState) printf '%s\n' "${MOCK_ACTIVE_STATE:?}" ;;
      --property=MainPID) printf '%s\n' "${MOCK_MAIN_PID-}" ;;
      *) exit 97 ;;
    esac
    ;;
  disable) exit 0 ;;
  *) exit 97 ;;
esac
`)

	source := readDeploymentFile(t, "uninstall.sh")
	start := strings.Index(source, "stop_required_unit() {")
	if start < 0 {
		t.Fatal("could not isolate stop_required_unit from uninstaller")
	}
	end := strings.Index(source[start:], "\n\n# The upgrade path/service")
	if end < 0 {
		t.Fatal("could not isolate stop_required_unit from uninstaller")
	}
	harness := "set -Eeuo pipefail\nIFS=$'\\n\\t'\n" + source[start:start+end] + "\nstop_required_unit \"${TEST_UNIT:?}\"\n"
	filename := filepath.Join(root, "stop-required-unit.sh")
	if err := os.WriteFile(filename, []byte(harness), 0o700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(testBash(t), filename)
	command.Env = append(os.Environ(),
		"PATH="+mockDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"MOCK_SYSTEMCTL_LOG="+log,
		"MOCK_LOAD_STATE="+loadState,
		"MOCK_ACTIVE_STATE="+activeState,
		"MOCK_MAIN_PID="+mainPID,
		"TEST_UNIT="+unit,
	)
	output, err := command.CombinedOutput()
	logRaw, readErr := os.ReadFile(log)
	if readErr != nil && !os.IsNotExist(readErr) {
		t.Fatal(readErr)
	}
	return string(output), string(logRaw), err
}

func writeUninstallMock(t *testing.T, filename, body string) {
	t.Helper()
	if err := os.WriteFile(filename, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
}
