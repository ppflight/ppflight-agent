package hostfirewall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

func testService(t *testing.T, fake *fakeBackend) *Service {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "host-firewall")
	return &Service{
		store: store{
			stateDirectory: directory,
			journalPath:    filepath.Join(directory, "transaction.json"),
			requireRoot:    false,
			now:            func() time.Time { return time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC) },
		},
		backend:  fake,
		evidence: []string{filepath.Join(filepath.Dir(directory), "missing-agent")},
	}
}

func TestClassifyFreshResumeAndExistingUpdate(t *testing.T) {
	service := testService(t, newFakeBackend())
	mode, err := service.Classify()
	if err != nil || mode != ModeFresh {
		t.Fatalf("fresh classify = %q, %v", mode, err)
	}
	info, err := os.Stat(service.store.journalPath)
	if err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Fatalf("journal metadata = %#v, %v", info, err)
	}
	mode, err = service.Classify()
	if err != nil || mode != ModeResume {
		t.Fatalf("resume classify = %q, %v", mode, err)
	}

	other := testService(t, newFakeBackend())
	evidence := filepath.Join(t.TempDir(), "ppflight-agent")
	if err := os.WriteFile(evidence, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	other.evidence = []string{evidence}
	mode, err = other.Classify()
	if err != nil || mode != ModeUpdate {
		t.Fatalf("existing classify = %q, %v", mode, err)
	}
	if _, err := os.Stat(other.store.journalPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("update classification created a journal: %v", err)
	}
}

func TestFreshActivationOrdersDisabledRulesBeforeOptionsAndCommit(t *testing.T) {
	fake := newFakeBackend()
	service := testService(t, fake)
	if mode, err := service.Classify(); err != nil || mode != ModeFresh {
		t.Fatalf("classify = %q, %v", mode, err)
	}
	if err := service.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	journal, err := service.store.load()
	if err != nil || journal.Phase != PhaseCommitted {
		t.Fatalf("journal phase = %q, %v", journal.Phase, err)
	}
	for key, want := range map[string]string{"enable": "1", "policy_in": "DROP", "policy_out": "ACCEPT"} {
		if got := fmt.Sprint(fake.cluster[key]); got != want {
			t.Fatalf("cluster %s = %q, want %q", key, got, want)
		}
	}
	if got := fmt.Sprint(fake.node["enable"]); got != "1" {
		t.Fatalf("node enable = %q", got)
	}
	if len(fake.rules) != 2 {
		t.Fatalf("rules = %#v", fake.rules)
	}
	for _, rule := range fake.rules {
		if !rule.Enabled || rule.Direction != "in" || rule.Action != "DROP" {
			t.Fatalf("invalid committed rule: %#v", rule)
		}
	}
	firstCreate := eventIndex(fake.events, "create:")
	clusterSet := eventIndex(fake.events, "cluster-options:")
	firstEnable := eventIndex(fake.events, "rule-enable:true")
	health := eventIndex(fake.events, "health")
	if firstCreate < 0 || clusterSet <= firstCreate || firstEnable <= clusterSet || health <= firstEnable {
		t.Fatalf("unsafe activation order: %v", fake.events)
	}
}

func TestActivationHealthFailureRestoresExactPreimage(t *testing.T) {
	fake := newFakeBackend()
	fake.cluster = map[string]any{"enable": "0", "policy_in": "ACCEPT"}
	fake.node = map[string]any{}
	fake.healthErr = errors.New("injected loopback failure")
	service := testService(t, fake)
	if _, err := service.Classify(); err != nil {
		t.Fatal(err)
	}
	if err := service.Activate(context.Background()); err == nil || !strings.Contains(err.Error(), "injected loopback failure") {
		t.Fatalf("activation error = %v", err)
	}
	journal, err := service.store.load()
	if err != nil || journal.Phase != PhaseRolledBack {
		t.Fatalf("rollback journal = %q, %v", journal.Phase, err)
	}
	if len(fake.rules) != 0 {
		t.Fatalf("rollback retained rules: %#v", fake.rules)
	}
	if got := fmt.Sprint(fake.cluster["enable"]); got != "0" {
		t.Fatalf("cluster enable not restored: %#v", fake.cluster)
	}
	if got := fmt.Sprint(fake.cluster["policy_in"]); got != "ACCEPT" {
		t.Fatalf("cluster policy_in not restored: %#v", fake.cluster)
	}
	if _, exists := fake.cluster["policy_out"]; exists {
		t.Fatalf("absent cluster policy_out was not deleted: %#v", fake.cluster)
	}
	if _, exists := fake.node["enable"]; exists {
		t.Fatalf("absent node enable was not deleted: %#v", fake.node)
	}
}

func TestMultiNodeActivationFailsBeforeAnyPVEWrite(t *testing.T) {
	fake := newFakeBackend()
	fake.nodes = []string{"pve1", "pve2"}
	fake.cluster["enable"] = "0"
	service := testService(t, fake)
	if _, err := service.Classify(); err != nil {
		t.Fatal(err)
	}
	if err := service.Activate(context.Background()); err == nil || !strings.Contains(err.Error(), "multi-node") {
		t.Fatalf("activation error = %v", err)
	}
	for _, event := range fake.events {
		if strings.HasPrefix(event, "create:") || strings.Contains(event, "options:") || strings.HasPrefix(event, "rule-") {
			t.Fatalf("multi-node refusal mutated PVE: %v", fake.events)
		}
	}
}

func TestRollbackPreservesConcurrentAdministratorOptionChange(t *testing.T) {
	fake := newFakeBackend()
	fake.healthErr = errors.New("injected health failure")
	fake.onHealth = func() { fake.cluster["policy_in"] = "REJECT" }
	service := testService(t, fake)
	if _, err := service.Classify(); err != nil {
		t.Fatal(err)
	}
	err := service.Activate(context.Background())
	if err == nil || !strings.Contains(err.Error(), "automatic rollback also failed") {
		t.Fatalf("activation drift error = %v", err)
	}
	if got := fmt.Sprint(fake.cluster["policy_in"]); got != "REJECT" {
		t.Fatalf("administrator policy was overwritten: %q", got)
	}
	journal, loadErr := service.store.load()
	if loadErr != nil || journal.Phase != PhaseRollbackPending {
		t.Fatalf("drift journal = %q, %v", journal.Phase, loadErr)
	}
}

func TestDefaultRouteParserHandlesMultipathAndRejectsUnsafeInterfaces(t *testing.T) {
	parsed, err := parseDefaultRouteInterfaces([]byte(`[
  {"dst":"default","dev":"vmbr0"},
  {"dst":"default","nexthops":[{"dev":"bond0.10"},{"dev":"vmbr0"}]}
]`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := sortedInterfaces(parsed)
	if err != nil || strings.Join(got, ",") != "bond0.10,vmbr0" {
		t.Fatalf("interfaces = %v, %v", got, err)
	}
	if _, err := sortedInterfaces([]string{"lo"}); err == nil {
		t.Fatal("loopback-only default route was accepted")
	}
	if _, err := sortedInterfaces([]string{"vmbr0;reboot"}); err == nil {
		t.Fatal("unsafe interface was accepted")
	}
}

func eventIndex(events []string, prefix string) int {
	for index, event := range events {
		if strings.HasPrefix(event, prefix) {
			return index
		}
	}
	return -1
}

type fakeBackend struct {
	cluster    map[string]any
	node       map[string]any
	nodes      []string
	interfaces []string
	rules      []firewallRule
	digest     int
	events     []string
	healthErr  error
	onHealth   func()
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{
		cluster:    map[string]any{},
		node:       map[string]any{},
		nodes:      []string{"pve1"},
		interfaces: []string{"eno1", "vmbr0"},
		digest:     1,
	}
}

func (fake *fakeBackend) nextDigest() string {
	return fmt.Sprintf("%040x", fake.digest)
}

func (fake *fakeBackend) mutate() { fake.digest++ }

func (fake *fakeBackend) LocalNode(context.Context) (string, error) { return "pve1", nil }

func (fake *fakeBackend) ClusterNodes(context.Context) ([]string, error) {
	return append([]string(nil), fake.nodes...), nil
}

func (fake *fakeBackend) DefaultRouteInterfaces(context.Context) ([]string, error) {
	return sortedInterfaces(fake.interfaces)
}

func (fake *fakeBackend) ClusterOptions(context.Context) (firewallOptions, error) {
	return firewallOptions{Values: cloneMap(fake.cluster), Digest: fake.nextDigest()}, nil
}

func (fake *fakeBackend) SetClusterOptions(_ context.Context, values map[string]string, deleted []string, _ string) error {
	fake.events = append(fake.events, "cluster-options:"+fmt.Sprint(values)+":"+strings.Join(deleted, ","))
	applyFakeOptions(fake.cluster, values, deleted)
	fake.mutate()
	return nil
}

func (fake *fakeBackend) NodeOptions(context.Context, string) (firewallOptions, error) {
	return firewallOptions{Values: cloneMap(fake.node), Digest: fake.nextDigest()}, nil
}

func (fake *fakeBackend) SetNodeOptions(_ context.Context, _ string, values map[string]string, deleted []string, _ string) error {
	fake.events = append(fake.events, "node-options:"+fmt.Sprint(values)+":"+strings.Join(deleted, ","))
	applyFakeOptions(fake.node, values, deleted)
	fake.mutate()
	return nil
}

func (fake *fakeBackend) NodeRules(context.Context, string) (firewallRuleSet, error) {
	result := append([]firewallRule(nil), fake.rules...)
	sort.Slice(result, func(left, right int) bool { return result[left].Position < result[right].Position })
	return firewallRuleSet{Items: result, Digest: fake.nextDigest()}, nil
}

func (fake *fakeBackend) CreateNodeRule(_ context.Context, _ string, iface, comment string, enabled bool, position int, _ string) error {
	fake.events = append(fake.events, fmt.Sprintf("create:%s:%t", iface, enabled))
	for index := range fake.rules {
		if fake.rules[index].Position >= position {
			fake.rules[index].Position++
		}
	}
	fake.rules = append(fake.rules, firewallRule{Position: position, Direction: "in", Action: "DROP", Interface: iface, Enabled: enabled, Comment: comment})
	fake.mutate()
	return nil
}

func (fake *fakeBackend) SetNodeRuleEnabled(_ context.Context, _ string, position int, enabled bool, _ string) error {
	fake.events = append(fake.events, fmt.Sprintf("rule-enable:%t:%d", enabled, position))
	for index := range fake.rules {
		if fake.rules[index].Position == position {
			fake.rules[index].Enabled = enabled
			fake.mutate()
			return nil
		}
	}
	return errors.New("rule missing")
}

func (fake *fakeBackend) DeleteNodeRule(_ context.Context, _ string, position int, _ string) error {
	fake.events = append(fake.events, fmt.Sprintf("rule-delete:%d", position))
	removed := false
	kept := fake.rules[:0]
	for _, rule := range fake.rules {
		if rule.Position == position {
			removed = true
			continue
		}
		kept = append(kept, rule)
	}
	if !removed {
		return errors.New("rule missing")
	}
	fake.rules = kept
	sort.Slice(fake.rules, func(left, right int) bool { return fake.rules[left].Position < fake.rules[right].Position })
	for index := range fake.rules {
		fake.rules[index].Position = index
	}
	fake.mutate()
	return nil
}

func (fake *fakeBackend) Health(context.Context) error {
	fake.events = append(fake.events, "health")
	if fake.onHealth != nil {
		fake.onHealth()
	}
	return fake.healthErr
}

func cloneMap(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func applyFakeOptions(target map[string]any, values map[string]string, deleted []string) {
	for key, value := range values {
		target[key] = value
	}
	for _, key := range deleted {
		delete(target, key)
	}
}
