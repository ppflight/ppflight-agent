package hostfirewall

import (
	"context"
	"reflect"
	"testing"
)

type recordedCommand struct {
	name string
	args []string
}

type recordingRunner struct {
	outputs  [][]byte
	commands []recordedCommand
}

func (runner *recordingRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	runner.commands = append(runner.commands, recordedCommand{name: name, args: append([]string(nil), args...)})
	if len(runner.outputs) == 0 {
		return nil, nil
	}
	result := runner.outputs[0]
	runner.outputs = runner.outputs[1:]
	return result, nil
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
