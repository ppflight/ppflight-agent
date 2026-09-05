package hostfirewall

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const ufwInstalledFiles = `/etc/default/ufw
/usr/lib/systemd/system/ufw.service
/usr/lib/ufw/ufw-init
/usr/lib/ufw/ufw-init-functions
/usr/sbin/ufw
`

const ufwDirtySave = `*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
:PVEFW-INPUT - [0:0]
:PVEFW-FORWARD - [0:0]
:CUSTOM-FORWARD - [0:0]
:ufw-before-input - [0:0]
:ufw-before-forward - [0:0]
-A INPUT -j PVEFW-INPUT
-A INPUT -j ufw-before-input
-A FORWARD -j ufw-before-forward
-A FORWARD -j PVEFW-FORWARD
-A FORWARD -j CUSTOM-FORWARD
-A CUSTOM-FORWARD -m comment --comment keep-me -j ACCEPT
-A ufw-before-input -j DROP
-A ufw-before-forward -j DROP
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:CUSTOM-NAT - [0:0]
:ufw-user-nat - [0:0]
-A PREROUTING -j ufw-user-nat
-A POSTROUTING -j CUSTOM-NAT
-A CUSTOM-NAT -m comment --comment preserve-nat -j RETURN
COMMIT
`

const ufwCleanSave = `*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:PVEFW-INPUT - [0:0]
:PVEFW-FORWARD - [0:0]
:CUSTOM-FORWARD - [0:0]
-A INPUT -j PVEFW-INPUT
-A FORWARD -j PVEFW-FORWARD
-A FORWARD -j CUSTOM-FORWARD
-A CUSTOM-FORWARD -m comment --comment keep-me -j ACCEPT
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:CUSTOM-NAT - [0:0]
-A POSTROUTING -j CUSTOM-NAT
-A CUSTOM-NAT -m comment --comment preserve-nat -j RETURN
COMMIT
`

func TestBuildUFWCleanupDeletesOnlyUFWNamespaceAndPromotesPVE(t *testing.T) {
	payloads, changed, err := buildUFWCleanupPayloads("ipv4", []byte(ufwDirtySave))
	if err != nil || !changed {
		t.Fatalf("cleanup plan = changed %t, %v", changed, err)
	}
	joined := ""
	for _, payload := range payloads {
		joined += string(payload)
	}
	for _, required := range []string{
		"-D INPUT -j ufw-before-input",
		"-D FORWARD -j ufw-before-forward",
		"-F ufw-before-input",
		"-X ufw-before-forward",
		"-D PREROUTING -j ufw-user-nat",
		"-D FORWARD -j PVEFW-FORWARD",
		"-I FORWARD 1 -j PVEFW-FORWARD",
		"-P INPUT ACCEPT",
		"-P OUTPUT ACCEPT",
		"-P FORWARD ACCEPT",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("cleanup payload lacks %q:\n%s", required, joined)
		}
	}
	for _, forbidden := range []string{
		"-D FORWARD -j CUSTOM-FORWARD",
		"-D POSTROUTING -j CUSTOM-NAT",
		"-F CUSTOM-FORWARD",
		"-X CUSTOM-NAT",
		"--comment keep-me",
		"--comment preserve-nat",
		"-F PVEFW-INPUT",
		"-X PVEFW-FORWARD",
	} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("cleanup payload touches non-UFW state %q:\n%s", forbidden, joined)
		}
	}
}

func TestUFWCleanupIsIdempotentAndRequiresPVEReplacement(t *testing.T) {
	payloads, changed, err := buildUFWCleanupPayloads("ipv6", []byte(ufwCleanSave))
	if err != nil || changed || len(payloads) != 0 {
		t.Fatalf("clean plan = %#v, changed=%t, err=%v", payloads, changed, err)
	}
	unsafe := strings.Replace(ufwDirtySave, "-A INPUT -j PVEFW-INPUT\n", "", 1)
	if _, _, err := buildUFWCleanupPayloads("ipv4", []byte(unsafe)); err == nil {
		t.Fatal("UFW cleanup was planned without live PVE INPUT replacement protection")
	}
	duplicate := strings.Replace(ufwDirtySave, "-A FORWARD -j PVEFW-FORWARD\n", "-A FORWARD -j PVEFW-FORWARD\n-A FORWARD -j PVEFW-FORWARD\n", 1)
	if _, _, err := buildUFWCleanupPayloads("ipv4", []byte(duplicate)); err == nil {
		t.Fatal("UFW cleanup accepted duplicate PVE forwarding hooks")
	}
	adminDrop := strings.Replace(ufwCleanSave, ":FORWARD ACCEPT", ":FORWARD DROP", 1)
	if _, _, err := buildUFWCleanupPayloads("ipv4", []byte(adminDrop)); err == nil || !strings.Contains(err.Error(), "without UFW ownership evidence") {
		t.Fatalf("independent administrator DROP policy was overwritten or ambiguously accepted: %v", err)
	}
	independentHostPolicies := strings.NewReplacer(":INPUT ACCEPT", ":INPUT DROP", ":OUTPUT ACCEPT", ":OUTPUT DROP").Replace(ufwCleanSave)
	payloads, changed, err = buildUFWCleanupPayloads("ipv4", []byte(independentHostPolicies))
	if err != nil || changed || len(payloads) != 0 {
		t.Fatalf("independent INPUT/OUTPUT policies were not preserved: payloads=%q changed=%t err=%v", payloads, changed, err)
	}
	if err := verifyUFWFreePVEState("ipv4", []byte(independentHostPolicies)); err != nil {
		t.Fatalf("strict UFW absence rejected preserved independent host policies: %v", err)
	}
}

func TestRewriteUFWEnabledIsExactAndIdempotent(t *testing.T) {
	raw := []byte("# /etc/ufw/ufw.conf\n  ENABLED=yes\nLOGLEVEL=low\n")
	rewritten, changed, err := rewriteUFWEnabled(raw)
	if err != nil || !changed {
		t.Fatalf("rewrite = %q, %t, %v", rewritten, changed, err)
	}
	if string(rewritten) != "# /etc/ufw/ufw.conf\n  ENABLED=no\nLOGLEVEL=low\n" {
		t.Fatalf("unexpected rewrite: %q", rewritten)
	}
	second, changed, err := rewriteUFWEnabled(rewritten)
	if err != nil || changed || string(second) != string(rewritten) {
		t.Fatalf("idempotent rewrite = %q, %t, %v", second, changed, err)
	}
	for _, invalid := range []string{
		"LOGLEVEL=low\n",
		"ENABLED=maybe\n",
		"ENABLED=yes\nENABLED=no\n",
		"touch /tmp/pwned\nENABLED=yes\n",
		"ENABLED=$(id)\n",
		"ENABLED=yes\nEVIL=value\n",
		"ENABLED=yes # hidden shell comment\n",
	} {
		if _, _, err := rewriteUFWEnabled([]byte(invalid)); err == nil {
			t.Fatalf("invalid UFW configuration was accepted: %q", invalid)
		}
	}
}

func TestParseSafeUFWDefaultsRejectsShellAndUnknownAssignments(t *testing.T) {
	valid := []byte(`IPV6=yes
DEFAULT_INPUT_POLICY="DROP"
DEFAULT_OUTPUT_POLICY="ACCEPT"
DEFAULT_FORWARD_POLICY="DROP"
DEFAULT_APPLICATION_POLICY="SKIP"
MANAGE_BUILTINS=no
IPT_SYSCTL=/etc/ufw/sysctl.conf
IPT_MODULES="nf_conntrack_ftp nf_nat_ftp"
`)
	if value, err := parseSafeUFWDefaults(valid); err != nil || value != "no" {
		t.Fatalf("safe UFW defaults = %q, %v", value, err)
	}
	yes := strings.Replace(string(valid), "MANAGE_BUILTINS=no", "MANAGE_BUILTINS='yes'", 1)
	if value, err := parseSafeUFWDefaults([]byte(yes)); err != nil || value != "yes" {
		t.Fatalf("safe MANAGE_BUILTINS=yes = %q, %v", value, err)
	}
	for _, malicious := range []string{
		"MANAGE_BUILTINS=no\ntouch /tmp/pwned\n",
		"MANAGE_BUILTINS=$(id)\n",
		"MANAGE_BUILTINS=no\nUNKNOWN=value\n",
		"MANAGE_BUILTINS=no; id\n",
		"MANAGE_BUILTINS=no\nIPT_SYSCTL=../../tmp/pwned\n",
		"MANAGE_BUILTINS=no\nIPT_MODULES='safe;id'\n",
	} {
		if _, err := parseSafeUFWDefaults([]byte(malicious)); err == nil {
			t.Fatalf("unsafe sourced UFW defaults were accepted: %q", malicious)
		}
	}
}

type ufwStateRunner struct {
	packageStatus  string
	installedFiles string
	unit           systemdUnitState
	unitDefinition string
	saves          map[string]string
	commands       []recordedCommand
	fail           map[string]error
	restoreCalls   int
}

func (runner *ufwStateRunner) commandKey(name string, args ...string) string {
	return strings.TrimSpace(name + " " + strings.Join(args, " "))
}

func (runner *ufwStateRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	runner.commands = append(runner.commands, recordedCommand{name: name, args: append([]string(nil), args...)})
	key := runner.commandKey(name, args...)
	if err := runner.fail[key]; err != nil {
		return nil, err
	}
	switch {
	case name == "/usr/bin/dpkg-query" && len(args) > 0 && args[0] == "--show":
		if runner.packageStatus == "" {
			return []byte("bash\tii \n"), nil
		}
		return []byte("bash\tii \nufw\t" + runner.packageStatus + "\nzlib1g\tii \n"), nil
	case name == "/usr/bin/dpkg-query" && len(args) > 0 && args[0] == "--listfiles":
		return []byte(runner.installedFiles), nil
	case name == "systemctl" && len(args) > 1 && args[0] == "show" && args[1] == "--property=FragmentPath":
		return []byte(runner.unitDefinition), nil
	case name == "systemctl" && len(args) > 0 && args[0] == "show":
		return []byte(fmt.Sprintf("LoadState=%s\nUnitFileState=%s\nActiveState=%s\nMainPID=%d\n",
			runner.unit.LoadState, runner.unit.UnitFileState, runner.unit.ActiveState, runner.unit.MainPID)), nil
	case name == "systemctl" && len(args) == 3 && args[0] == "disable":
		runner.unit.ActiveState = "inactive"
		runner.unit.UnitFileState = "disabled"
		runner.unit.MainPID = 0
		return nil, nil
	case name == "/usr/bin/dpkg" && len(args) == 2 && args[0] == "--purge":
		runner.packageStatus = ""
		return nil, nil
	case name == "systemctl" && len(args) == 1 && args[0] == "daemon-reload":
		runner.unit = systemdUnitState{LoadState: "not-found", ActiveState: "inactive"}
		return nil, nil
	case strings.HasSuffix(name, "tables-legacy-save"):
		return []byte(runner.saves[name]), nil
	default:
		return nil, nil
	}
}

func (runner *ufwStateRunner) RunInput(_ context.Context, input []byte, name string, args ...string) ([]byte, error) {
	runner.commands = append(runner.commands, recordedCommand{name: name, args: append([]string(nil), args...), input: append([]byte(nil), input...)})
	key := runner.commandKey(name, args...)
	if err := runner.fail[key]; err != nil {
		return nil, err
	}
	runner.restoreCalls++
	if strings.HasPrefix(name, "/usr/sbin/ip6tables") {
		runner.saves["/usr/sbin/ip6tables-legacy-save"] = ufwCleanSave
	} else {
		runner.saves["/usr/sbin/iptables-legacy-save"] = ufwCleanSave
	}
	return nil, nil
}

func newUFWStateBackend() (*commandBackend, *ufwStateRunner, *int) {
	runner := &ufwStateRunner{
		packageStatus:  "ii ",
		installedFiles: ufwInstalledFiles,
		unit:           systemdUnitState{LoadState: "loaded", UnitFileState: "enabled", ActiveState: "active"},
		unitDefinition: "FragmentPath=/usr/lib/systemd/system/ufw.service\n" +
			"DropInPaths=\n" +
			"ExecStop={ path=/usr/lib/ufw/ufw-init ; argv[]=/usr/lib/ufw/ufw-init stop ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n",
		saves: map[string]string{
			"/usr/sbin/iptables-legacy-save":  ufwDirtySave,
			"/usr/sbin/ip6tables-legacy-save": ufwDirtySave,
		},
		fail: map[string]error{},
	}
	disables := 0
	backend := &commandBackend{
		runner:           runner,
		ufwPreflight:     func(string) error { return nil },
		disableUFWConfig: func() error { disables++; return nil },
	}
	return backend, runner, &disables
}

func TestUFWPreflightAcceptsBookwormLibPackageLayout(t *testing.T) {
	backend, runner, _ := newUFWStateBackend()
	runner.installedFiles = strings.NewReplacer(
		"/usr/lib/systemd", "/lib/systemd",
		"/usr/lib/ufw", "/lib/ufw",
	).Replace(ufwInstalledFiles)
	runner.unitDefinition = strings.NewReplacer(
		"/usr/lib/systemd", "/lib/systemd",
		"/usr/lib/ufw", "/lib/ufw",
	).Replace(runner.unitDefinition)
	if err := backend.PreflightUFW(context.Background()); err != nil {
		t.Fatalf("PVE 8/bookworm UFW package layout was rejected: %v", err)
	}
}

func TestUFWPreflightRejectsUnitDropInBeforeMutation(t *testing.T) {
	backend, runner, disables := newUFWStateBackend()
	runner.unitDefinition = strings.Replace(runner.unitDefinition, "DropInPaths=", "DropInPaths=/etc/systemd/system/ufw.service.d/override.conf", 1)
	if err := backend.PreflightUFW(context.Background()); err == nil || !strings.Contains(err.Error(), "drop-in") {
		t.Fatalf("unit drop-in preflight error = %v", err)
	}
	if *disables != 0 || runner.restoreCalls != 0 || commandCount(runner.commands, "/usr/bin/dpkg", "--purge", "ufw") != 0 {
		t.Fatalf("preflight mutated state: disables=%d restores=%d commands=%#v", *disables, runner.restoreCalls, runner.commands)
	}
}

func TestRemoveUFWUsesExactDpkgPurgeAndIsIdempotent(t *testing.T) {
	backend, runner, disables := newUFWStateBackend()
	changed, err := backend.RemoveUFW(context.Background())
	if err != nil || !changed {
		t.Fatalf("RemoveUFW = %t, %v", changed, err)
	}
	if *disables != 1 || runner.packageStatus != "" || runner.unit.LoadState != "not-found" {
		t.Fatalf("UFW state was not purged: disables=%d package=%q unit=%+v", *disables, runner.packageStatus, runner.unit)
	}
	for _, command := range runner.commands {
		joined := runner.commandKey(command.name, command.args...)
		if strings.Contains(joined, "apt") || strings.Contains(joined, "/usr/sbin/ufw") || strings.Contains(joined, "force-stop") {
			t.Fatalf("unsafe UFW removal command executed: %s", joined)
		}
	}
	if commandCount(runner.commands, "/usr/bin/dpkg", "--no-act", "--purge", "ufw") != 1 ||
		commandCount(runner.commands, "/usr/bin/dpkg", "--purge", "ufw") != 1 {
		t.Fatalf("exact dpkg validation/purge was not used: %#v", runner.commands)
	}
	restores := runner.restoreCalls
	changed, err = backend.RemoveUFW(context.Background())
	if err != nil || changed {
		t.Fatalf("idempotent RemoveUFW = %t, %v", changed, err)
	}
	if runner.restoreCalls != restores || *disables != 1 {
		t.Fatalf("idempotent removal mutated state: restores=%d->%d disables=%d", restores, runner.restoreCalls, *disables)
	}
}

func TestRemoveUFWNoActFailurePreventsRealPurge(t *testing.T) {
	backend, runner, _ := newUFWStateBackend()
	runner.fail[runner.commandKey("/usr/bin/dpkg", "--no-act", "--purge", "ufw")] = errors.New("injected validation failure")
	if _, err := backend.RemoveUFW(context.Background()); err == nil || !strings.Contains(err.Error(), "validation failed") {
		t.Fatalf("no-act failure = %v", err)
	}
	if commandCount(runner.commands, "/usr/bin/dpkg", "--purge", "ufw") != 0 || runner.packageStatus == "" {
		t.Fatalf("real purge ran after no-act failure: package=%q commands=%#v", runner.packageStatus, runner.commands)
	}
}

func TestRemoveUFWRealPurgeFailureIsImmediate(t *testing.T) {
	backend, runner, _ := newUFWStateBackend()
	runner.fail[runner.commandKey("/usr/bin/dpkg", "--purge", "ufw")] = errors.New("injected purge failure")
	if _, err := backend.RemoveUFW(context.Background()); err == nil || !strings.Contains(err.Error(), "purge failed") {
		t.Fatalf("purge failure = %v", err)
	}
	if runner.packageStatus == "" || commandCount(runner.commands, "systemctl", "daemon-reload") != 0 {
		t.Fatalf("removal advanced after purge failure: package=%q commands=%#v", runner.packageStatus, runner.commands)
	}
}

func TestRemoveUFWRecoversOnlyInertPackagedUnitCacheAfterPurgeCrash(t *testing.T) {
	backend, runner, disables := newUFWStateBackend()
	runner.packageStatus = ""
	runner.unit = systemdUnitState{LoadState: "loaded", UnitFileState: "disabled", ActiveState: "inactive"}
	runner.saves["/usr/sbin/iptables-legacy-save"] = ufwCleanSave
	runner.saves["/usr/sbin/ip6tables-legacy-save"] = ufwCleanSave

	if err := backend.PreflightUFW(context.Background()); err == nil || !strings.Contains(err.Error(), "unowned") {
		t.Fatalf("standalone preflight accepted package-less cached unit: %v", err)
	}
	if commandCount(runner.commands, "systemctl", "daemon-reload") != 0 {
		t.Fatal("read-only preflight mutated the cached unit state")
	}

	changed, err := backend.RemoveUFW(context.Background())
	if err != nil || !changed {
		t.Fatalf("purge crash recovery = changed %t, %v", changed, err)
	}
	if runner.unit.LoadState != "not-found" || commandCount(runner.commands, "systemctl", "daemon-reload") != 1 {
		t.Fatalf("cached packaged unit was not discarded exactly once: unit=%+v commands=%#v", runner.unit, runner.commands)
	}
	if *disables != 0 || runner.restoreCalls != 0 || commandCount(runner.commands, "/usr/bin/dpkg", "--purge", "ufw") != 0 {
		t.Fatalf("purge recovery repeated irreversible work: disables=%d restores=%d commands=%#v", *disables, runner.restoreCalls, runner.commands)
	}

	backend, runner, _ = newUFWStateBackend()
	runner.packageStatus = ""
	runner.unit = systemdUnitState{LoadState: "loaded", UnitFileState: "disabled", ActiveState: "active", MainPID: 42}
	runner.saves["/usr/sbin/iptables-legacy-save"] = ufwCleanSave
	runner.saves["/usr/sbin/ip6tables-legacy-save"] = ufwCleanSave
	if _, err := backend.RemoveUFW(context.Background()); err == nil || !strings.Contains(err.Error(), "not inert") {
		t.Fatalf("active package-less unit was accepted for recovery: %v", err)
	}
	if commandCount(runner.commands, "systemctl", "daemon-reload") != 0 {
		t.Fatal("unsafe cached unit was mutated")
	}
}

func commandCount(commands []recordedCommand, name string, args ...string) int {
	count := 0
	for _, command := range commands {
		if command.name == name && strings.Join(command.args, "\x00") == strings.Join(args, "\x00") {
			count++
		}
	}
	return count
}

func TestUFWFailureAfterPVECommitResumesWithoutRollback(t *testing.T) {
	fake := newFakeBackend()
	fake.ufwPresent = true
	fake.ufwErr = errors.New("injected UFW purge failure")
	service := testService(t, fake)
	if _, err := service.Classify(); err != nil {
		t.Fatal(err)
	}
	if err := service.Activate(context.Background()); err == nil {
		t.Fatal("activation succeeded despite UFW purge failure")
	}
	journal, err := service.store.load()
	if err != nil || journal.Phase != PhaseCommitted || journal.UFWPhase != UFWPhaseRemoving {
		t.Fatalf("failed UFW migration journal = %#v, %v", journal, err)
	}
	if !fake.guard || !fake.persistent || len(fake.rules) != len(fake.interfaces) || eventIndex(fake.events, "guard-remove") >= 0 {
		t.Fatalf("PVE replacement was rolled back after UFW failure: %#v", fake)
	}
	fake.ufwErr = nil
	if err := service.Activate(context.Background()); err != nil {
		t.Fatalf("UFW retry failed: %v", err)
	}
	journal, err = service.store.load()
	if err != nil || journal.UFWPhase != UFWPhaseRemoved || fake.ufwPresent {
		t.Fatalf("UFW retry did not commit: %#v, present=%t, %v", journal, fake.ufwPresent, err)
	}
}
