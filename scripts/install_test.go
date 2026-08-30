package scripts

import (
	"os"
	"os/exec"
	pathpkg "path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestTmpfilesOwnershipTransitionsDoNotCrossFromAgentToRoot(t *testing.T) {
	tmpfiles := readDeploymentFile(t, "..", "packaging", "tmpfiles.d", "ppflight-agent.conf")
	owners := map[string]string{}
	for _, line := range strings.Split(tmpfiles, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 5 && !strings.HasPrefix(fields[0], "#") {
			owners[fields[1]] = fields[3]
		}
	}
	for child, childOwner := range owners {
		if childOwner != "root" {
			continue
		}
		for ancestor := pathpkg.Dir(child); ancestor != "/" && ancestor != "."; ancestor = pathpkg.Dir(ancestor) {
			if owner, ok := owners[ancestor]; ok && owner != "root" {
				t.Fatalf("unsafe tmpfiles owner transition %s (%s) -> %s (%s)", ancestor, owner, child, childOwner)
			}
		}
	}
}

func TestInstalledStateOwnershipContract(t *testing.T) {
	installer := readDeploymentFile(t, "install.sh")
	for _, required := range []string{
		`readonly AGENT_STATE_DIR="$STATE_DIR/agent"`,
		`readonly BINDINGS_DIR="$STATE_DIR/bindings"`,
		`readonly ASSIGNMENTS_PATH="$ASSIGNMENTS_DIR/assignments.json"`,
		`install -d -o root -g ppflight-agent -m 0750 "$BINDINGS_DIR"`,
		`install -d -o root -g ppflight-agent -m 0750 "$STATE_DIR"`,
		`install -d -o ppflight-agent -g ppflight-agent -m 0700 "$AGENT_STATE_DIR"`,
		`install -d -o ppflight-agent -g ppflight-agent -m 0750 "$ASSIGNMENTS_DIR"`,
		`for legacy_name in .agent.lock queues meter run-state.json control lifecycle-state.json; do`,
		`ensure_regular_metadata "$ASSIGNMENTS_PATH" 0640 ppflight-agent ppflight-agent`,
		`systemd-tmpfiles --create "$TMPFILES_PATH"`,
		`[[ "$service_user" == 'ppflight-agent' ]]`,
		`readonly TEMPLATE_BUNDLES_DIR="$LIB_DIR/template-bundles"`,
		`readonly PVE_BOOTSTRAP_HELPER="$LIB_DIR/create-pve-tokens.sh"`,
		`readonly UNINSTALL_HELPER="$LIB_DIR/uninstall.sh"`,
		`install -o root -g root -m 0700 "$REPO_DIR/scripts/create-pve-tokens.sh" "$PVE_BOOTSTRAP_HELPER"`,
		`install -o root -g root -m 0700 "$REPO_DIR/scripts/uninstall.sh" "$UNINSTALL_HELPER"`,
		`python3 -I "$TEMPLATE_VERIFIER" verify "$TEMPLATE_SOURCE"`,
		`TEMPLATE_STAGE="$(mktemp -d "$TEMPLATE_BUNDLES_DIR/.template-bootstrap-stage.XXXXXX")"`,
		`python3 -I "$TEMPLATE_VERIFIER" verify "$TEMPLATE_STAGE"`,
		`mv -Tf -- "$template_link_stage" "$TEMPLATE_LINK"`,
		`PVE_PREPARATION_REQUIRED=1`,
		`migrate_legacy_source()`,
		`if source == "simulator" or mode == "test":`,
		`document["mode"] = "production"`,
		`document["pve"]["source"] = "disabled"`,
		`if mode != "production":`,
		`PVE collection is disabled and the service remains stopped`,
	} {
		if !strings.Contains(installer, required) {
			t.Fatalf("installer is missing deployment contract %q", required)
		}
	}

	uninstaller := readDeploymentFile(t, "uninstall.sh")
	for _, required := range []string{
		`rm -f -- /usr/local/lib/ppflight-agent/template-bootstrap`,
		`rm -f -- /usr/local/lib/ppflight-agent/create-pve-tokens.sh`,
		`rm -f -- /usr/local/lib/ppflight-agent/uninstall.sh`,
		`rm -rf -- /usr/local/lib/ppflight-agent`,
		`rm -rf -- /usr/local/lib/ppflight-agent/template-bundles`,
	} {
		if !strings.Contains(uninstaller, required) {
			t.Fatalf("uninstaller is missing template cleanup contract %q", required)
		}
	}

	tmpfiles := readDeploymentFile(t, "..", "packaging", "tmpfiles.d", "ppflight-agent.conf")
	for _, required := range []string{
		"d /var/lib/ppflight-agent 0750 root ppflight-agent -",
		"d /var/lib/ppflight-agent/agent 0700 ppflight-agent ppflight-agent -",
		"d /var/lib/ppflight-agent/bindings 0750 root ppflight-agent -",
		"z /var/lib/ppflight-agent/bindings/binding-state.json 0640 root ppflight-agent -",
		"z /var/lib/ppflight-agent/bindings/monitoring-binding-state.json 0640 root ppflight-agent -",
		"d /var/lib/ppflight-agent/assignments 0750 ppflight-agent ppflight-agent -",
		"z /var/lib/ppflight-agent/assignments/assignments.json 0640 ppflight-agent ppflight-agent -",
	} {
		if !strings.Contains(tmpfiles, required) {
			t.Fatalf("tmpfiles config is missing deployment contract %q", required)
		}
	}

	unit := readDeploymentFile(t, "..", "packaging", "systemd", "ppflight-agent.service")
	for _, required := range []string{
		"Type=notify",
		"NotifyAccess=main",
		"WatchdogSec=60s",
		"Restart=always",
		"RestartSec=3s",
		"RestartPreventExitStatus=78",
		"StartLimitIntervalSec=0",
		"TimeoutStopSec=30s",
		"User=ppflight-agent",
		"RestrictAddressFamilies=AF_UNIX AF_INET",
		"ReadWritePaths=/var/lib/ppflight-agent",
		"ReadOnlyPaths=/etc/ppflight-agent /var/lib/ppflight-agent/bindings",
	} {
		if !strings.Contains(unit, required) {
			t.Fatalf("systemd unit is missing deployment contract %q", required)
		}
	}
	if strings.Contains(unit, "ReadWritePaths=/etc/ppflight-agent") {
		t.Fatal("systemd unit must not make /etc/ppflight-agent writable")
	}
	for _, forbidden := range []string{
		"RefuseManualStop=true",
		"ExecStopPost=systemctl start",
		"ExecStopPost=/bin/systemctl start",
		"ExecStopPost=/usr/bin/systemctl start",
	} {
		if strings.Contains(unit, forbidden) {
			t.Fatalf("systemd unit interferes with an administrator stop: %q", forbidden)
		}
	}
}

func TestTemplateBundleInstallStagesBeforeAtomicSymlinkSwitch(t *testing.T) {
	installer := readDeploymentFile(t, "install.sh")
	ordered := []string{
		`python3 -I "$TEMPLATE_VERIFIER" verify "$TEMPLATE_SOURCE"`,
		`TEMPLATE_STAGE="$(mktemp -d "$TEMPLATE_BUNDLES_DIR/.template-bootstrap-stage.XXXXXX")"`,
		`python3 -I "$TEMPLATE_VERIFIER" verify "$TEMPLATE_STAGE"`,
		`mv -- "$TEMPLATE_STAGE" "$TEMPLATE_TARGET"`,
		`ln -s -- "$TEMPLATE_TARGET" "$template_link_stage"`,
		`mv -Tf -- "$template_link_stage" "$TEMPLATE_LINK"`,
	}
	previous := -1
	for _, fragment := range ordered {
		position := strings.Index(installer, fragment)
		if position < 0 {
			t.Fatalf("installer is missing atomic template step %q", fragment)
		}
		if position <= previous {
			t.Fatalf("template install step %q is out of order", fragment)
		}
		previous = position
	}
}

func TestInstallerDoesNotRequireExecutableSourceMode(t *testing.T) {
	installer := readDeploymentFile(t, "install.sh")
	if strings.Contains(installer, `[[ -f "$BINARY" && -x "$BINARY" ]]`) {
		t.Fatal("installer must accept a hash-verified 0600/0644 release download")
	}
	for _, required := range []string{
		`verify_sha256 "$BINARY" "$RELEASE_SHA256"`,
		`[[ -f "$BINARY" ]] || die "agent binary is not a regular file: $BINARY"`,
		`install -m 0755 "$BINARY" "$BIN_PATH"`,
	} {
		if !strings.Contains(installer, required) {
			t.Fatalf("installer is missing verified binary deployment step %q", required)
		}
	}
}

func TestPVEBootstrapExistenceChecksPreserveTriState(t *testing.T) {
	bootstrap := readDeploymentFile(t, "create-pve-tokens.sh")
	for _, required := range []string{
		`json_list_has "$out" roleid "$1" || status=$?`,
		`json_list_has "$out" userid "$1" || status=$?`,
		`json_list_has "$out" tokenid "$token" "$user!$token" || status=$?`,
		`[[ $status -eq 0 ]] && return 0`,
		`[[ $status -eq 1 ]] && return 1`,
	} {
		if !strings.Contains(bootstrap, required) {
			t.Fatalf("PVE bootstrap must preserve found/not-found/parse-error state: missing %q", required)
		}
	}
}

func TestPVEBootstrapExistenceChecksExecuteNotFound(t *testing.T) {
	bootstrap := readDeploymentFile(t, "create-pve-tokens.sh")
	start := strings.Index(bootstrap, "role_exists() {")
	end := strings.Index(bootstrap, "\nensure_role() {")
	if start < 0 || end <= start {
		t.Fatal("cannot isolate PVE existence-check functions")
	}
	bash := testBash(t)
	harness := `set -u
TMPDIR_BOOTSTRAP="$(mktemp -d)"
trap 'rm -rf -- "$TMPDIR_BOOTSTRAP"' EXIT
die() { return 42; }
list_json() { local out=$1; printf '[]\n' >"$out"; }
json_list_has() { return "$MOCK_STATUS"; }
` + bootstrap[start:end] + `
MOCK_STATUS=1
role_exists missing; [[ $? -eq 1 ]] || exit 11
user_exists missing@pve; [[ $? -eq 1 ]] || exit 12
token_exists missing@pve token; [[ $? -eq 1 ]] || exit 13
MOCK_STATUS=0
role_exists present; [[ $? -eq 0 ]] || exit 14
user_exists present@pve; [[ $? -eq 0 ]] || exit 15
token_exists present@pve token; [[ $? -eq 0 ]] || exit 16
MOCK_STATUS=2
role_exists malformed; [[ $? -eq 42 ]] || exit 17
`
	filename := filepath.Join(t.TempDir(), "existence-checks.sh")
	if err := os.WriteFile(filename, []byte(harness), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(bash, filename).CombinedOutput(); err != nil {
		t.Fatalf("PVE existence checks failed under bash: %v\n%s", err, output)
	}
}

func testBash(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		for _, candidate := range []string{
			`C:\Program Files\Git\bin\bash.exe`,
			`C:\Program Files\Git\usr\bin\bash.exe`,
		} {
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate
			}
		}
	}
	path, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is unavailable")
	}
	return path
}

func readDeploymentFile(t *testing.T, parts ...string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(parts...))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
