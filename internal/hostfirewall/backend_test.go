package hostfirewall

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type recordedCommand struct {
	name  string
	args  []string
	input []byte
}

type recordingRunner struct {
	outputs  [][]byte
	errs     []error
	commands []recordedCommand
}

func (runner *recordingRunner) result() ([]byte, error) {
	var output []byte
	if len(runner.outputs) > 0 {
		output = runner.outputs[0]
		runner.outputs = runner.outputs[1:]
	}
	var err error
	if len(runner.errs) > 0 {
		err = runner.errs[0]
		runner.errs = runner.errs[1:]
	}
	return output, err
}

func (runner *recordingRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	runner.commands = append(runner.commands, recordedCommand{name: name, args: append([]string(nil), args...)})
	return runner.result()
}

func (runner *recordingRunner) RunInput(_ context.Context, input []byte, name string, args ...string) ([]byte, error) {
	runner.commands = append(runner.commands, recordedCommand{
		name: name, args: append([]string(nil), args...), input: append([]byte(nil), input...),
	})
	return runner.result()
}

func TestCommandBackendUsesFirewallRuleListDigest(t *testing.T) {
	const digest = "0123456789abcdef0123456789abcdef01234567"
	runner := &recordingRunner{outputs: [][]byte{[]byte(`[
  {"pos":0,"type":"in","action":"ACCEPT","enable":1,"comment":"admin","digest":"` + digest + `"},
  {"pos":1,"type":"in","action":"DROP","iface":"vmbr0","enable":0,"comment":"owned","digest":"` + digest + `"}
]`)}}
	backend := &commandBackend{runner: runner}
	rules, err := backend.NodeRules(context.Background(), "pve")
	if err != nil {
		t.Fatal(err)
	}
	if rules.Digest != digest || len(rules.Items) != 2 {
		t.Fatalf("rule set=%+v, want two rules with list digest %s", rules, digest)
	}
}

func TestCommandBackendUsesCanonicalEmptyRuleDigest(t *testing.T) {
	runner := &recordingRunner{outputs: [][]byte{[]byte(`[]`)}}
	backend := &commandBackend{runner: runner}
	rules, err := backend.NodeRules(context.Background(), "pve")
	if err != nil {
		t.Fatal(err)
	}
	if rules.Digest != "da39a3ee5e6b4b0d3255bfef95601890afd80709" || len(rules.Items) != 0 {
		t.Fatalf("empty rule set=%+v", rules)
	}
}

func TestCommandBackendRejectsInconsistentRuleDigests(t *testing.T) {
	runner := &recordingRunner{outputs: [][]byte{[]byte(`[
  {"pos":0,"type":"in","action":"DROP","enable":0,"digest":"0123456789abcdef0123456789abcdef01234567"},
  {"pos":1,"type":"in","action":"DROP","enable":0,"digest":"1123456789abcdef0123456789abcdef01234567"}
]`)}}
	backend := &commandBackend{runner: runner}
	if _, err := backend.NodeRules(context.Background(), "pve"); err == nil {
		t.Fatal("inconsistent PVE rule digests were accepted")
	}
}

func TestCommandBackendRuleWritesPassExactListDigest(t *testing.T) {
	const digest = "0123456789abcdef0123456789abcdef01234567"
	runner := &recordingRunner{}
	backend := &commandBackend{runner: runner}
	comment := "PPFlight host firewall:0123456789abcdef0123456789abcdef:vmbr0"
	if err := backend.CreateNodeRule(context.Background(), "pve", "vmbr0", comment, false, 0, digest); err != nil {
		t.Fatal(err)
	}
	if err := backend.SetNodeRuleEnabled(context.Background(), "pve", 0, true, digest); err != nil {
		t.Fatal(err)
	}
	if err := backend.DeleteNodeRule(context.Background(), "pve", 0, digest); err != nil {
		t.Fatal(err)
	}
	want := []recordedCommand{
		{name: "pvesh", args: []string{"create", "/nodes/pve/firewall/rules", "--type", "in", "--action", "DROP", "--iface", "vmbr0", "--enable", "0", "--pos", "0", "--comment", comment, "--digest", digest}},
		{name: "pvesh", args: []string{"set", "/nodes/pve/firewall/rules/0", "--enable", "1", "--digest", digest}},
		{name: "pvesh", args: []string{"delete", "/nodes/pve/firewall/rules/0", "--digest", digest}},
	}
	if !reflect.DeepEqual(runner.commands, want) {
		t.Fatalf("commands=%#v, want %#v", runner.commands, want)
	}
}

func TestValidateLoopbackListenersRejectsPublicOrDuplicateBindings(t *testing.T) {
	valid := []byte("LISTEN 0 4096 127.0.0.1:9745 0.0.0.0:*\nLISTEN 0 4096 127.0.0.1:9100 0.0.0.0:*\nLISTEN 0 4096 127.0.0.1:9633 0.0.0.0:*\n")
	if err := validateLoopbackListeners(valid); err != nil {
		t.Fatalf("valid loopback listeners rejected: %v", err)
	}
	public := []byte("LISTEN 0 4096 127.0.0.1:9745 0.0.0.0:*\nLISTEN 0 4096 0.0.0.0:9100 0.0.0.0:*\nLISTEN 0 4096 127.0.0.1:9633 0.0.0.0:*\n")
	if err := validateLoopbackListeners(public); err == nil {
		t.Fatal("public exporter listener was accepted")
	}
	duplicate := append(append([]byte(nil), valid...), []byte("LISTEN 0 4096 127.0.0.1:9100 0.0.0.0:*\n")...)
	if err := validateLoopbackListeners(duplicate); err == nil {
		t.Fatal("duplicate exporter listener was accepted")
	}
}

func nativeJournal() Journal {
	return Journal{NativeHooks: []nativeInputHookSnapshot{
		{Family: "ipv4", Captured: true, WasTail: true},
		{Family: "ipv6", Captured: true, WasTail: true},
	}}
}

func inputRules(rules ...string) []byte {
	return []byte("-P INPUT ACCEPT\n" + strings.Join(rules, "\n") + "\n")
}

func TestCaptureNativeHookRequiresUniqueCanonicalTail(t *testing.T) {
	tail := inputRules("-A INPUT -j IN_BT", "-A INPUT -j ufw-before-input", "-A INPUT -j PVEFW-INPUT")
	runner := &recordingRunner{outputs: [][]byte{tail, tail}}
	backend := &commandBackend{runner: runner}
	snapshots, err := backend.CaptureIngressGuard(context.Background())
	if err != nil || len(snapshots) != 2 || !snapshots[0].WasTail || !snapshots[1].WasTail {
		t.Fatalf("capture=%#v, %v", snapshots, err)
	}
	for _, invalid := range [][]byte{
		inputRules("-A INPUT -j PVEFW-INPUT", "-A INPUT -j IN_BT"),
		inputRules("-A INPUT -j IN_BT"),
		inputRules("-A INPUT -j PVEFW-INPUT", "-A INPUT -j PVEFW-INPUT"),
		inputRules("-A INPUT -m comment --comment unexpected -j PVEFW-INPUT"),
		inputRules("-A INPUT -g PVEFW-INPUT"),
	} {
		backend := &commandBackend{runner: &recordingRunner{outputs: [][]byte{invalid}}}
		if _, err := backend.CaptureIngressGuard(context.Background()); err == nil {
			t.Fatalf("invalid native hook inventory accepted: %s", invalid)
		}
	}
}

func TestEnsureMovesOnlyNativeHookWithAtomicLegacyRestore(t *testing.T) {
	unsafe := inputRules("-A INPUT -j IN_BT", "-A INPUT -j ufw-before-input", "-A INPUT -j PVEFW-INPUT")
	guarded := inputRules("-A INPUT -j PVEFW-INPUT", "-A INPUT -j IN_BT", "-A INPUT -j ufw-before-input")
	runner := &recordingRunner{outputs: [][]byte{unsafe, nil, guarded, unsafe, nil, guarded}}
	backend := &commandBackend{runner: runner}
	if err := backend.EnsureIngressGuard(context.Background(), nativeJournal()); err != nil {
		t.Fatal(err)
	}
	wantPayload := "*filter\n-D INPUT -j PVEFW-INPUT\n-I INPUT 1 -j PVEFW-INPUT\nCOMMIT\n"
	if len(runner.commands) != 6 {
		t.Fatalf("commands=%#v", runner.commands)
	}
	for _, index := range []int{1, 4} {
		command := runner.commands[index]
		if !strings.HasSuffix(command.name, "tables-legacy-restore") || strings.Join(command.args, " ") != "-w 10 -n" || string(command.input) != wantPayload {
			t.Fatalf("non-atomic native hook move: %#v", command)
		}
	}
	for _, command := range runner.commands {
		if strings.Contains(string(command.input), "--comment") || strings.Contains(string(command.input), "ppflight-host-priority") {
			t.Fatalf("a second/commented PVE hook was attempted: %#v", command)
		}
	}
}

func TestSupervisorWaitsDuringPVEDisableAndPromotesAfterReenable(t *testing.T) {
	missing := inputRules("-A INPUT -j IN_BT")
	runner := &recordingRunner{outputs: [][]byte{missing, missing}}
	backend := &commandBackend{runner: runner}
	changed, err := backend.MaintainIngressGuard(context.Background(), nativeJournal())
	if err != nil || changed || len(runner.commands) != 2 {
		t.Fatalf("disabled PVE maintenance=%t, %v, commands=%#v", changed, err, runner.commands)
	}
	unsafe := inputRules("-A INPUT -j IN_BT", "-A INPUT -j PVEFW-INPUT")
	guarded := inputRules("-A INPUT -j PVEFW-INPUT", "-A INPUT -j IN_BT")
	runner = &recordingRunner{outputs: [][]byte{unsafe, nil, guarded, unsafe, nil, guarded}}
	backend = &commandBackend{runner: runner}
	changed, err = backend.MaintainIngressGuard(context.Background(), nativeJournal())
	if err != nil || !changed {
		t.Fatalf("reenabled PVE maintenance=%t, %v", changed, err)
	}
}

func TestSteadySupervisorReadsOnlyLegacyInputOncePerFamily(t *testing.T) {
	guarded := inputRules("-A INPUT -j PVEFW-INPUT", "-A INPUT -j IN_BT")
	runner := &recordingRunner{outputs: [][]byte{guarded, guarded}}
	backend := &commandBackend{runner: runner}
	changed, err := backend.MaintainIngressGuard(context.Background(), nativeJournal())
	if err != nil || changed {
		t.Fatalf("steady maintenance=%t, %v", changed, err)
	}
	want := []recordedCommand{
		{name: "/usr/sbin/iptables-legacy", args: []string{"-w", "10", "-S", "INPUT"}},
		{name: "/usr/sbin/ip6tables-legacy", args: []string{"-w", "10", "-S", "INPUT"}},
	}
	if !reflect.DeepEqual(runner.commands, want) {
		t.Fatalf("steady supervisor commands=%#v", runner.commands)
	}
}

func TestRollbackRestoresNativeHookToTailAtomically(t *testing.T) {
	guarded := inputRules("-A INPUT -j PVEFW-INPUT", "-A INPUT -j IN_BT", "-A INPUT -j ufw-before-input")
	tail := inputRules("-A INPUT -j IN_BT", "-A INPUT -j ufw-before-input", "-A INPUT -j PVEFW-INPUT")
	runner := &recordingRunner{outputs: [][]byte{guarded, guarded, nil, nil, tail, tail}}
	backend := &commandBackend{runner: runner}
	if err := backend.RemoveIngressGuard(context.Background(), nativeJournal()); err != nil {
		t.Fatal(err)
	}
	wantPayload := "*filter\n-D INPUT -j PVEFW-INPUT\n-A INPUT -j PVEFW-INPUT\nCOMMIT\n"
	for _, index := range []int{2, 3} {
		if string(runner.commands[index].input) != wantPayload {
			t.Fatalf("native tail restore is not atomic: %#v", runner.commands[index])
		}
	}
}

func TestRollbackCrossFamilyFailureRePromotesEarlierHook(t *testing.T) {
	guarded := inputRules("-A INPUT -j PVEFW-INPUT", "-A INPUT -j IN_BT")
	tail := inputRules("-A INPUT -j IN_BT", "-A INPUT -j PVEFW-INPUT")
	runner := &recordingRunner{
		outputs: [][]byte{guarded, guarded, nil, nil, tail, nil, guarded, guarded},
		errs:    []error{nil, nil, nil, errors.New("injected IPv6 restore failure")},
	}
	backend := &commandBackend{runner: runner}
	if err := backend.RemoveIngressGuard(context.Background(), nativeJournal()); err == nil || !strings.Contains(err.Error(), "injected IPv6") {
		t.Fatalf("cross-family rollback error=%v", err)
	}
	wantPromote := "*filter\n-D INPUT -j PVEFW-INPUT\n-I INPUT 1 -j PVEFW-INPUT\nCOMMIT\n"
	found := false
	for _, command := range runner.commands[4:] {
		if string(command.input) == wantPromote && command.name == "/usr/sbin/iptables-legacy-restore" {
			found = true
		}
	}
	if !found {
		t.Fatalf("IPv4 hook was not compensated to first position: %#v", runner.commands)
	}
}

func TestRuntimeDropBlockAllowsOfficialPVEPrelude(t *testing.T) {
	raw := []byte(`-N PVEFW-HOST-IN
-A PVEFW-HOST-IN -i lo -j ACCEPT
-A PVEFW-HOST-IN -m conntrack --ctstate INVALID -j DROP
-A PVEFW-HOST-IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A PVEFW-HOST-IN -p igmp -j RETURN
-A PVEFW-HOST-IN -i eno1 -j DROP
-A PVEFW-HOST-IN -i vmbr0 -j DROP
-A PVEFW-HOST-IN -m set --match-set PVEFW-0-management-v4 src -p tcp --dport 8006 -j RETURN
`)
	expected := map[string]bool{"eno1": true, "vmbr0": true}
	if err := validateRuntimeIngressDrops("ipv4", raw, expected); err != nil {
		t.Fatal(err)
	}
	bad := []byte(strings.Replace(string(raw), "-A PVEFW-HOST-IN -i vmbr0 -j DROP\n", "-A PVEFW-HOST-IN -j ACCEPT\n-A PVEFW-HOST-IN -i vmbr0 -j DROP\n", 1))
	if err := validateRuntimeIngressDrops("ipv4", bad, expected); err == nil {
		t.Fatal("non-contiguous runtime DROP block was accepted")
	}
	broadAccept := []byte(strings.Replace(string(raw), "-A PVEFW-HOST-IN -i eno1 -j DROP\n", "-A PVEFW-HOST-IN -j ACCEPT\n-A PVEFW-HOST-IN -i eno1 -j DROP\n", 1))
	if err := validateRuntimeIngressDrops("ipv4", broadAccept, expected); err == nil {
		t.Fatal("broad ACCEPT before the owned DROP block was accepted")
	}
	duplicate := append(append([]byte(nil), raw...), []byte("-A PVEFW-HOST-IN -i eno1 -j DROP\n")...)
	if err := validateRuntimeIngressDrops("ipv4", duplicate, expected); err == nil {
		t.Fatal("duplicate owned interface DROP was accepted")
	}
}

func TestRuntimePreludeRequiresCompleteIPv6NDPGrammar(t *testing.T) {
	rules := []string{
		"-A PVEFW-HOST-IN -i lo -j ACCEPT",
		"-A PVEFW-HOST-IN -m conntrack --ctstate INVALID -j DROP",
		"-A PVEFW-HOST-IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
		"-A PVEFW-HOST-IN -p ipv6-icmp -m icmp6 --icmpv6-type 133 -j RETURN",
		"-A PVEFW-HOST-IN -p ipv6-icmp -m icmp6 --icmpv6-type 134 -j RETURN",
		"-A PVEFW-HOST-IN -p ipv6-icmp -m icmp6 --icmpv6-type 135 -j RETURN",
		"-A PVEFW-HOST-IN -p ipv6-icmp -m icmp6 --icmpv6-type 136 -j RETURN",
		"-A PVEFW-HOST-IN -p igmp -j RETURN",
	}
	if cursor, err := validateRuntimePrelude("ipv6", rules); err != nil || cursor != len(rules) {
		t.Fatalf("valid IPv6 prelude cursor=%d, err=%v", cursor, err)
	}
	broken := append([]string(nil), rules[:6]...)
	broken = append(broken, rules[7:]...)
	if _, err := validateRuntimePrelude("ipv6", broken); err == nil {
		t.Fatal("partial IPv6 NDP prelude was accepted")
	}
}

func TestPVEInputMustBeginWithSingleExactHostJump(t *testing.T) {
	if err := validatePVEInputHostJump("ipv4", []byte("-N PVEFW-INPUT\n-A PVEFW-INPUT -j PVEFW-HOST-IN\n")); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{
		"-N PVEFW-INPUT\n-A PVEFW-INPUT -j ACCEPT\n-A PVEFW-INPUT -j PVEFW-HOST-IN\n",
		"-N PVEFW-INPUT\n-A PVEFW-INPUT -j PVEFW-HOST-IN\n-A PVEFW-INPUT -j PVEFW-HOST-IN\n",
		"-N PVEFW-INPUT\n-A PVEFW-INPUT -m comment --comment altered -j PVEFW-HOST-IN\n",
	} {
		if err := validatePVEInputHostJump("ipv4", []byte(invalid)); err == nil {
			t.Fatalf("invalid PVEFW-INPUT accepted: %q", invalid)
		}
	}
}

func TestPersistenceUsesStartAndStrictSystemdReadback(t *testing.T) {
	state := []byte("LoadState=loaded\nUnitFileState=enabled\nActiveState=active\nMainPID=123\n")
	runner := &recordingRunner{outputs: [][]byte{nil, nil, state}}
	backend := &commandBackend{runner: runner}
	if err := backend.EnableIngressGuardPersistence(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 3 || runner.commands[1].name != "systemctl" || strings.Join(runner.commands[1].args, " ") != "start ppflight-host-firewall.service" {
		t.Fatalf("persistence must start without restart: %#v", runner.commands)
	}
	failing := &commandBackend{runner: &recordingRunner{errs: []error{errors.New("query failed")}}}
	if err := failing.VerifyIngressGuardPersistence(context.Background()); err == nil {
		t.Fatal("failed systemd query was accepted")
	}
}

func TestLegacyBackendAllowsConcurrentProxmoxDaemonWhenLegacySelected(t *testing.T) {
	pve := []byte("LoadState=loaded\nUnitFileState=enabled\nActiveState=active\nMainPID=100\n")
	nftActive := []byte("LoadState=loaded\nUnitFileState=enabled\nActiveState=active\nMainPID=200\n")
	nftMissing := []byte("LoadState=not-found\nUnitFileState=\nActiveState=inactive\nMainPID=0\n")
	status := []byte(`[{"type":"node","name":"pve","local":1}]`)
	options := []byte(`{"digest":"0123456789abcdef0123456789abcdef01234567","nftables":0}`)
	cluster := []byte(`{"digest":"0123456789abcdef0123456789abcdef01234567","enable":1}`)
	runner := &recordingRunner{outputs: [][]byte{[]byte("iptables v1.8.9 (legacy)"), []byte("ip6tables v1.8.9 (legacy)"), pve, nftActive, status, options, cluster}}
	backend := &commandBackend{runner: runner, pathProbe: func(path string) (bool, error) {
		return path == "/run/proxmox-nftables-firewall-force-disable" || path == "/usr/libexec/proxmox/proxmox-firewall", nil
	}}
	if err := backend.VerifyIngressBackend(context.Background()); err != nil {
		t.Fatal(err)
	}
	runner = &recordingRunner{outputs: [][]byte{[]byte("iptables v1.8.9 (legacy)"), []byte("ip6tables v1.8.9 (legacy)"), pve, nftMissing, status, options, cluster}}
	backend = &commandBackend{runner: runner, pathProbe: func(string) (bool, error) { return false, nil }}
	if err := backend.VerifyIngressBackend(context.Background()); err != nil {
		t.Fatalf("PVE8 without the Rust daemon was rejected: %v", err)
	}
	clusterOff := []byte(`{"digest":"0123456789abcdef0123456789abcdef01234567","enable":0}`)
	runner = &recordingRunner{outputs: [][]byte{[]byte("iptables v1.8.9 (legacy)"), []byte("ip6tables v1.8.9 (legacy)"), pve, nftActive, status, options, clusterOff}}
	backend = &commandBackend{runner: runner, pathProbe: func(path string) (bool, error) {
		return path == "/usr/libexec/proxmox/proxmox-firewall", nil
	}}
	if err := backend.VerifyIngressBackend(context.Background()); err != nil {
		t.Fatalf("fresh cluster-off legacy precheck rejected a delayed force-disable flag: %v", err)
	}
	if legacyNodeSelector(map[string]any{"nftables": "1"}) || legacyNodeSelector(map[string]any{"nftables": "invalid"}) {
		t.Fatal("nft or ambiguous node selector was accepted")
	}
	if legacyRuntimeSelector(false, true) || !legacyRuntimeSelector(true, true) || !legacyRuntimeSelector(false, false) {
		t.Fatal("legacy force-disable/Rust binary selector is incorrect")
	}
}
