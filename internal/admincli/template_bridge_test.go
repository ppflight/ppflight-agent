package admincli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ppflight/ppflight-agent/internal/fsutil"
	"github.com/ppflight/ppflight-agent/internal/templatebootstrap"
)

type fakeTemplateBridgeManager struct {
	inspect      []templateBridgeState
	inspectErr   error
	created      templateBridgeState
	createErr    error
	inspectCalls int
	createCalls  int
	events       *[]string
}

func (f *fakeTemplateBridgeManager) Inspect(_ context.Context, _ string) (templateBridgeState, error) {
	f.inspectCalls++
	if f.events != nil {
		*f.events = append(*f.events, "inspect")
	}
	if f.inspectErr != nil {
		return templateBridgeState{}, f.inspectErr
	}
	if len(f.inspect) == 0 {
		return templateBridgeState{}, nil
	}
	state := f.inspect[0]
	if len(f.inspect) > 1 {
		f.inspect = f.inspect[1:]
	}
	return state, nil
}

func (f *fakeTemplateBridgeManager) Create(_ context.Context, _ string) (templateBridgeState, error) {
	f.createCalls++
	if f.events != nil {
		*f.events = append(*f.events, "create")
	}
	return f.created, f.createErr
}

func safeCreatedBridgeState() templateBridgeState {
	return templateBridgeState{
		Exists: true, Iface: "vmbr1", Type: "bridge", Autostart: true, BridgePorts: "none",
		BridgeSTP: "off", BridgeFD: "0", Method: "manual", Method6: "manual",
		Comments: templateBridgeOwnershipComment, KernelPresent: true, KernelType: "bridge", KernelUp: true,
	}
}

func templateInitFixture(t *testing.T, input string, bridges templateBridgeManager, events *[]string) (*cli, *int, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	storage := templateStorage{StorageID: "local", Type: "dir", ContentTypes: []string{"iso", "snippets", "images"}, Enabled: true, Active: true, AvailableBytes: "100000000000", AvailableBytesKnown: true, Remediations: []templateRemediation{}}
	storage.RoleEligibility.Image = templateRole{Allowed: true, Reasons: []string{}}
	storage.RoleEligibility.Template = templateRole{Allowed: true, Reasons: []string{}}
	storage.RoleEligibility.Backup = templateRole{Allowed: false, Reasons: []string{"MISSING_CONTENT_BACKUP"}}
	discoveryRaw, err := json.Marshal(templateDiscovery{SchemaVersion: "ppflight.template-bootstrap-result/v1", Mode: "discover", State: "succeeded", Storages: []templateStorage{storage}})
	if err != nil {
		t.Fatal(err)
	}
	catalogRaw := []byte(`{"catalogSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","catalog":{"catalogRevision":"test-1","items":[{"templateRef":"ubuntu-24.04","version":"24.04","displayName":"Ubuntu 24.04","aliases":[],"target":{"vmid":9001}}]}}`)
	planRaw := []byte(`{"state":"ready","executable":true,"catalog":{"catalogRevision":"test-1","catalogSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`)
	bootstrapCalls := 0
	var output, stderr bytes.Buffer
	instance := &cli{
		in: inputReader(input), out: &output, errOut: &stderr, version: "test", templateBridges: bridges,
		templateRun: func(_ context.Context, args []string, _ io.Writer) (templatebootstrap.Result, error) {
			switch args[0] {
			case "discover":
				return templatebootstrap.Result{ExitCode: 0, Stdout: discoveryRaw}, nil
			case "catalog":
				return templatebootstrap.Result{ExitCode: 0, Stdout: catalogRaw}, nil
			case "bootstrap":
				bootstrapCalls++
				if events != nil {
					*events = append(*events, "plan")
				}
				return templatebootstrap.Result{ExitCode: 0, Stdout: planRaw}, nil
			default:
				t.Fatalf("unexpected helper args: %v", args)
				return templatebootstrap.Result{}, nil
			}
		},
	}
	return instance, &bootstrapCalls, &output, &stderr
}

func inputReader(value string) io.Reader { return strings.NewReader(value) }

func TestTemplateInitCreatesMissingInternalBridgeBeforePlan(t *testing.T) {
	events := []string{}
	manager := &fakeTemplateBridgeManager{created: safeCreatedBridgeState(), events: &events}
	instance, bootstrapCalls, output, stderr := templateInitFixture(t, "\n1\n1\nn\n\ny\n\ny\n\n", manager, &events)
	if code := instance.templateInit(); code != 0 {
		t.Fatalf("code=%d stderr=%s output=%s", code, stderr.String(), output.String())
	}
	if manager.createCalls != 1 || *bootstrapCalls != 1 {
		t.Fatalf("create=%d bootstrap=%d", manager.createCalls, *bootstrapCalls)
	}
	if createIndex, planIndex := slices.Index(events, "create"), slices.Index(events, "plan"); createIndex < 0 || planIndex <= createIndex {
		t.Fatalf("events=%v", events)
	}
	for _, expected := range []string{"内网网桥 vmbr1 当前不存在", "bridge-ports none", "确认创建内网网桥 vmbr1", "已创建并通过 PVE 配置与内核接口回读", "未执行任何模板变更"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("output missing %q: %s", expected, output.String())
		}
	}
}

func TestTemplateInitDeclinesMissingInternalBridgeWithoutPlan(t *testing.T) {
	manager := &fakeTemplateBridgeManager{}
	instance, bootstrapCalls, output, stderr := templateInitFixture(t, "\n1\n1\nn\n\ny\n\nn\n", manager, nil)
	if code := instance.templateInit(); code != 0 {
		t.Fatalf("code=%d stderr=%s output=%s", code, stderr.String(), output.String())
	}
	if manager.createCalls != 0 || *bootstrapCalls != 0 {
		t.Fatalf("create=%d bootstrap=%d", manager.createCalls, *bootstrapCalls)
	}
	if !strings.Contains(output.String(), "已取消创建内网网桥；未执行任何模板变更") {
		t.Fatalf("output=%s", output.String())
	}
}

func TestTemplateInitBridgeCreateFailureNeverPlansTemplates(t *testing.T) {
	manager := &fakeTemplateBridgeManager{createErr: errors.New("reload failed")}
	instance, bootstrapCalls, output, stderr := templateInitFixture(t, "\n1\n1\nn\n\ny\n\ny\n", manager, nil)
	if code := instance.templateInit(); code != 1 {
		t.Fatalf("code=%d stderr=%s output=%s", code, stderr.String(), output.String())
	}
	if *bootstrapCalls != 0 {
		t.Fatalf("bootstrap=%d", *bootstrapCalls)
	}
	if !strings.Contains(stderr.String(), "创建或应用 PVE 网桥失败") || !strings.Contains(output.String(), "未执行任何模板变更") {
		t.Fatalf("stderr=%s output=%s", stderr.String(), output.String())
	}
}

func TestTemplateInitReusesExistingBridgeWithoutModification(t *testing.T) {
	existing := safeCreatedBridgeState()
	manager := &fakeTemplateBridgeManager{inspect: []templateBridgeState{existing}}
	instance, bootstrapCalls, output, stderr := templateInitFixture(t, "\n1\n1\nn\n\ny\n\n\n", manager, nil)
	if code := instance.templateInit(); code != 0 {
		t.Fatalf("code=%d stderr=%s output=%s", code, stderr.String(), output.String())
	}
	if manager.createCalls != 0 || *bootstrapCalls != 1 {
		t.Fatalf("create=%d bootstrap=%d", manager.createCalls, *bootstrapCalls)
	}
	if !strings.Contains(output.String(), "将原样使用，不修改其端口、IP 或网关配置") {
		t.Fatalf("output=%s", output.String())
	}
}

func TestTemplateInitRejectsUnsafeExistingBridgeWithoutModification(t *testing.T) {
	existing := safeCreatedBridgeState()
	existing.BridgePorts = "eno2"
	existing.Address = "10.10.0.1"
	existing.Gateway = "10.10.0.254"
	manager := &fakeTemplateBridgeManager{inspect: []templateBridgeState{existing}}
	instance, bootstrapCalls, output, stderr := templateInitFixture(t, "\n1\n1\nn\n\ny\n\n", manager, nil)
	if code := instance.templateInit(); code != 1 {
		t.Fatalf("code=%d stderr=%s output=%s", code, stderr.String(), output.String())
	}
	if manager.createCalls != 0 || *bootstrapCalls != 0 {
		t.Fatalf("create=%d bootstrap=%d", manager.createCalls, *bootstrapCalls)
	}
	if !strings.Contains(stderr.String(), "不是安全隔离的 PPFlight 内网桥") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestExistingInternalBridgeAllowsOnlyKernelIPv6LinkLocal(t *testing.T) {
	state := safeCreatedBridgeState()
	state.KernelAddress = []templateBridgeKernelAddress{{Family: "inet6", Local: "fe80::1234", Scope: "link"}}
	if err := validateExistingTemplateBridge("vmbr1", state); err != nil {
		t.Fatalf("link-local rejected: %v", err)
	}
	state.KernelAddress = []templateBridgeKernelAddress{{Family: "inet", Local: "10.10.0.1", Scope: "global"}}
	if err := validateExistingTemplateBridge("vmbr1", state); err == nil {
		t.Fatal("kernel IPv4 address was accepted")
	}
}

func TestExistingInternalBridgeRejectsRuntimeMemberPort(t *testing.T) {
	state := safeCreatedBridgeState()
	state.KernelMembers = []string{"eno2"}
	if err := validateExistingTemplateBridge("vmbr1", state); err == nil || !strings.Contains(err.Error(), "仍挂载端口 eno2") {
		t.Fatalf("err=%v", err)
	}
}

type bridgeContextBoundaryManager struct {
	inspectCtx context.Context
}

func (m *bridgeContextBoundaryManager) Inspect(ctx context.Context, _ string) (templateBridgeState, error) {
	m.inspectCtx = ctx
	return templateBridgeState{}, nil
}

func (m *bridgeContextBoundaryManager) Create(ctx context.Context, _ string) (templateBridgeState, error) {
	if m.inspectCtx == ctx {
		return templateBridgeState{}, errors.New("inspect 与 create 错误复用了同一 context")
	}
	select {
	case <-m.inspectCtx.Done():
	default:
		return templateBridgeState{}, errors.New("inspect context 未在确认前释放")
	}
	select {
	case <-ctx.Done():
		return templateBridgeState{}, errors.New("create context 在创建开始前已过期")
	default:
	}
	return safeCreatedBridgeState(), nil
}

func TestTemplateBridgePromptSeparatesInspectAndCreateDeadlines(t *testing.T) {
	manager := &bridgeContextBoundaryManager{}
	instance := &cli{in: strings.NewReader("y\n"), out: io.Discard, errOut: io.Discard, templateBridges: manager}
	reader := bufio.NewReader(instance.in)
	ready, err := instance.ensureTemplateInternalBridge(context.Background(), reader, "vmbr1")
	if err != nil || !ready {
		t.Fatalf("ready=%v err=%v", ready, err)
	}
}

func TestTemplateInitRejectsExistingNonBridgeWithoutPlan(t *testing.T) {
	manager := &fakeTemplateBridgeManager{inspect: []templateBridgeState{{Exists: true, Iface: "vmbr1", Type: "eth", KernelPresent: true, KernelType: "ether", KernelUp: true}}}
	instance, bootstrapCalls, output, stderr := templateInitFixture(t, "\n1\n1\nn\n\ny\n\n", manager, nil)
	if code := instance.templateInit(); code != 1 {
		t.Fatalf("code=%d stderr=%s output=%s", code, stderr.String(), output.String())
	}
	if manager.createCalls != 0 || *bootstrapCalls != 0 {
		t.Fatalf("create=%d bootstrap=%d", manager.createCalls, *bootstrapCalls)
	}
}

func TestTemplateInitRejectsUnmanagedKernelNameCollisionWithoutPlan(t *testing.T) {
	manager := &fakeTemplateBridgeManager{inspect: []templateBridgeState{{KernelPresent: true}}}
	instance, bootstrapCalls, output, stderr := templateInitFixture(t, "\n1\n1\nn\n\ny\n\n", manager, nil)
	if code := instance.templateInit(); code != 1 {
		t.Fatalf("code=%d stderr=%s output=%s", code, stderr.String(), output.String())
	}
	if manager.createCalls != 0 || *bootstrapCalls != 0 {
		t.Fatalf("create=%d bootstrap=%d", manager.createCalls, *bootstrapCalls)
	}
	if !strings.Contains(stderr.String(), "内核已有同名接口") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

type bridgeRunResult struct {
	program string
	args    []string
	output  string
	err     error
	before  func()
}

type scriptedBridgeRunner struct {
	t                      *testing.T
	results                []bridgeRunResult
	calls                  []bridgeRunResult
	networkSemanticByInput map[string]string
}

func (r *scriptedBridgeRunner) Run(_ context.Context, program string, args ...string) ([]byte, error) {
	r.t.Helper()
	if program == templateBridgePerl {
		expectedArgs := []string{"-MPVE::INotify", "-MJSON::PP", "-MIO::File", "-e", templateBridgePerlParser, "--"}
		if len(args) != len(expectedArgs)+1 || !slices.Equal(args[:len(expectedArgs)], expectedArgs) {
			r.t.Fatalf("unexpected parser command: %s %v", program, args)
		}
		raw, err := os.ReadFile(args[len(args)-1])
		if err != nil {
			return nil, err
		}
		output, ok := r.networkSemanticByInput[string(raw)]
		if !ok {
			r.t.Fatalf("no semantic fixture for %q", string(raw))
		}
		r.calls = append(r.calls, bridgeRunResult{program: program, args: append([]string(nil), args...)})
		return []byte(output), nil
	}
	if len(r.results) == 0 {
		r.t.Fatalf("unexpected command: %s %v", program, args)
	}
	expected := r.results[0]
	r.results = r.results[1:]
	if program != expected.program || !slices.Equal(args, expected.args) {
		r.t.Fatalf("command=%s %v expected=%s %v", program, args, expected.program, expected.args)
	}
	r.calls = append(r.calls, bridgeRunResult{program: program, args: append([]string(nil), args...)})
	if expected.before != nil {
		expected.before()
	}
	return []byte(expected.output), expected.err
}

func TestTemplateBridgePerlParserSupportsPVE8AndPVE9PublicContracts(t *testing.T) {
	perl, err := exec.LookPath("perl")
	if err != nil {
		t.Skip("perl is unavailable")
	}
	networkPath := filepath.Join(t.TempDir(), "interfaces")
	if err := os.WriteFile(networkPath, []byte("auto vmbr0\niface vmbr0 inet manual\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	contracts := map[string]string{
		"PVE8-proc-net-dev-handle": `package PVE::INotify;
use strict; use warnings; use IO::File;
sub __read_etc_network_interfaces {
    my ($fh, $proc_net_dev, $active) = @_;
    die "legacy helper did not receive a file handle" if !defined(fileno($proc_net_dev));
    my $line = <$fh>;
    return { ifaces => { vmbr0 => { type => 'bridge', source => $line } }, options => [] };
}
sub read_etc_network_interfaces {
    my ($filename, $fh) = @_;
    my $proc_net_dev = IO::File->new($filename, 'r') or die "fixture open";
    return __read_etc_network_interfaces($fh, $proc_net_dev, []);
}
1;
`,
		"PVE9-ip-link-hash": `package PVE::INotify;
use strict; use warnings;
sub __read_etc_network_interfaces {
    my ($fh, $ip_links, $active) = @_;
    die "new helper did not receive an ip-link hash" if ref($ip_links) ne 'HASH';
    my $line = <$fh>;
    return { ifaces => { vmbr0 => { type => 'bridge', source => $line } }, options => [] };
}
sub read_etc_network_interfaces {
    my ($filename, $fh) = @_;
    return __read_etc_network_interfaces($fh, {}, []);
}
1;
`,
	}

	for name, module := range contracts {
		t.Run(name, func(t *testing.T) {
			moduleRoot := t.TempDir()
			moduleDir := filepath.Join(moduleRoot, "PVE")
			if err := os.MkdirAll(moduleDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(moduleDir, "INotify.pm"), []byte(module), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(perl,
				"-I", moduleRoot,
				"-MPVE::INotify", "-MJSON::PP", "-MIO::File",
				"-e", templateBridgePerlParser, "--", networkPath,
			)
			raw, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("parser failed: %v: %s", err, raw)
			}
			semantic, err := decodeTemplateBridgeNetworkSemantic(raw)
			if err != nil {
				t.Fatalf("invalid parser output: %v: %s", err, raw)
			}
			if _, ok := templateBridgeSemanticIface(semantic, "vmbr0"); !ok {
				t.Fatalf("vmbr0 missing from parser output: %s", raw)
			}
		})
	}
}

const (
	testNetworkBase       = "BASE\n"
	testNetworkOwned      = "BASE+OWNED\n"
	testNetworkAdminOnly  = "BASE+VMbr0-GATEWAY\n"
	testNetworkConcurrent = "BASE+OWNED+VMbr0-GATEWAY\n"
)

func testNetworkSemantics() map[string]string {
	base := `{"ifaces":{"lo":{"priority":1,"method":"loopback","method6":"manual","type":"loopback","autostart":1,"families":["inet"]},"vmbr0":{"priority":2,"method":"static","method6":"manual","type":"bridge","autostart":1,"families":["inet"],"address":"192.0.2.10","netmask":"255.255.255.0","cidr":"192.0.2.10/24","gateway":"192.0.2.1","bridge_ports":"eno1","bridge_stp":"off","bridge_fd":0}},"options":[]}`
	owned := `{"ifaces":{"lo":{"priority":1,"method":"loopback","method6":"manual","type":"loopback","autostart":1,"families":["inet"]},"vmbr0":{"priority":2,"method":"static","method6":"manual","type":"bridge","autostart":1,"families":["inet"],"address":"192.0.2.10","netmask":"255.255.255.0","cidr":"192.0.2.10/24","gateway":"192.0.2.1","bridge_ports":"eno1","bridge_stp":"off","bridge_fd":0},"vmbr1":{"priority":3,"method":"manual","method6":"manual","type":"bridge","autostart":1,"families":["inet"],"comments":"PPFlight private template bridge\n","bridge_ports":"","bridge_stp":"off","bridge_fd":0}},"options":[]}`
	adminOnly := `{"ifaces":{"lo":{"priority":1,"method":"loopback","method6":"manual","type":"loopback","autostart":1,"families":["inet"]},"vmbr0":{"priority":2,"method":"static","method6":"manual","type":"bridge","autostart":1,"families":["inet"],"address":"192.0.2.10","netmask":"255.255.255.0","cidr":"192.0.2.10/24","gateway":"198.51.100.1","bridge_ports":"eno1","bridge_stp":"off","bridge_fd":0}},"options":[]}`
	concurrent := `{"ifaces":{"lo":{"priority":1,"method":"loopback","method6":"manual","type":"loopback","autostart":1,"families":["inet"]},"vmbr0":{"priority":2,"method":"static","method6":"manual","type":"bridge","autostart":1,"families":["inet"],"address":"192.0.2.10","netmask":"255.255.255.0","cidr":"192.0.2.10/24","gateway":"198.51.100.1","bridge_ports":"eno1","bridge_stp":"off","bridge_fd":0},"vmbr1":{"priority":3,"method":"manual","method6":"manual","type":"bridge","autostart":1,"families":["inet"],"comments":"PPFlight private template bridge\n","bridge_ports":"","bridge_stp":"off","bridge_fd":0}},"options":[]}`
	return map[string]string{testNetworkBase: base, testNetworkOwned: owned, testNetworkAdminOnly: adminOnly, testNetworkConcurrent: concurrent}
}

func testBridgeNetworkPaths(t *testing.T) (active, pending, lock string) {
	t.Helper()
	directory := t.TempDir()
	active = filepath.Join(directory, "interfaces")
	pending = filepath.Join(directory, "interfaces.new")
	lock = filepath.Join(directory, ".pve-interfaces.lock")
	if err := os.WriteFile(active, []byte(testNetworkBase), 0o600); err != nil {
		t.Fatal(err)
	}
	return active, pending, lock
}

func TestPVETemplateBridgeCreateUsesFixedSafeArgumentsAndStrictReadback(t *testing.T) {
	upid := "UPID:pve:00000001:00000002:00000003:srvreload:networking:root@pam:"
	path := "/nodes/pve/network"
	active, pending, lockPath := testBridgeNetworkPaths(t)
	lockWasHeldAcrossReload := false
	runner := &scriptedBridgeRunner{t: t, networkSemanticByInput: testNetworkSemantics(), results: []bridgeRunResult{
		{program: templateBridgePVESh, args: []string{"create", path, "--iface", "vmbr1", "--type", "bridge", "--autostart", "1", "--bridge_ports", "none", "--comments", templateBridgeOwnershipComment}, output: "null\n", before: func() {
			if err := os.WriteFile(pending, []byte(testNetworkOwned), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{program: templateBridgePVESh, args: []string{"get", path, "--output-format", "json"}, output: `[{"iface":"vmbr1","type":"bridge"}]`},
		{program: templateBridgePVESh, args: []string{"get", path + "/vmbr1", "--output-format", "json"}, output: `{"iface":"vmbr1","type":"bridge","autostart":1,"bridge_ports":"none","bridge_stp":0,"bridge_fd":0,"method":"manual","method6":"manual","comments":"PPFlight private template bridge"}`},
		{program: templateBridgeIP, args: []string{"-json", "-details", "link", "show", "dev", "vmbr1"}, err: errors.New("not found")},
		{program: templateBridgePVESh, args: []string{"set", path, "--output-format", "json"}, output: `"` + upid + `"`, before: func() {
			competing, err := fsutil.AcquireExclusive(lockPath)
			if err == nil {
				_ = competing.Close()
				t.Fatal("PVE network lock was not held across reload launch")
			}
			lockWasHeldAcrossReload = true
		}},
		{program: templateBridgePVESh, args: []string{"get", "/nodes/pve/tasks/" + upid + "/status", "--output-format", "json"}, output: `{"status":"stopped","exitstatus":"OK"}`, before: func() {
			if err := os.Remove(pending); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(active, []byte(testNetworkOwned), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{program: templateBridgePVESh, args: []string{"get", path, "--output-format", "json"}, output: `[{"iface":"vmbr1","type":"bridge"}]`},
		{program: templateBridgePVESh, args: []string{"get", path + "/vmbr1", "--output-format", "json"}, output: `{"iface":"vmbr1","type":"bridge","autostart":1,"bridge_ports":"none","bridge_stp":0,"bridge_fd":0,"method":"manual","method6":"manual","comments":"PPFlight private template bridge"}`},
		{program: templateBridgeIP, args: []string{"-json", "-details", "link", "show", "dev", "vmbr1"}, output: `[{"ifname":"vmbr1","flags":["BROADCAST","UP"],"linkinfo":{"info_kind":"bridge"}}]`},
		{program: templateBridgeIP, args: []string{"-json", "address", "show", "dev", "vmbr1"}, output: `[{"ifname":"vmbr1","addr_info":[{"family":"inet6","local":"fe80::1","scope":"link"}]}]`},
	}}
	manager := &pveTemplateBridgeManager{node: "pve", runner: runner, activeNetworkPath: active, pendingNetworkPath: pending, networkLockPath: lockPath}
	state, err := manager.Create(context.Background(), "vmbr1")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCreatedTemplateBridge("vmbr1", state); err != nil {
		t.Fatal(err)
	}
	if len(runner.results) != 0 {
		t.Fatalf("unconsumed results=%d", len(runner.results))
	}
	if !lockWasHeldAcrossReload {
		t.Fatal("reload lock assertion did not run")
	}
}

func TestPVETemplateBridgeCreateRefusesPendingNetworkChanges(t *testing.T) {
	active, pending, lockPath := testBridgeNetworkPaths(t)
	if err := os.WriteFile(pending, []byte("pending"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &scriptedBridgeRunner{t: t}
	manager := &pveTemplateBridgeManager{node: "pve", runner: runner, activeNetworkPath: active, pendingNetworkPath: pending, networkLockPath: lockPath}
	if _, err := manager.Create(context.Background(), "vmbr1"); err == nil || !strings.Contains(err.Error(), "尚未应用的网络配置") {
		t.Fatalf("err=%v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("calls=%v", runner.calls)
	}
}

func TestPVETemplateBridgeInspectRejectsUnmanagedKernelNameCollision(t *testing.T) {
	runner := &scriptedBridgeRunner{t: t, results: []bridgeRunResult{{
		program: templateBridgePVESh, args: []string{"get", "/nodes/pve/network", "--output-format", "json"}, output: `[]`,
	}}}
	manager := &pveTemplateBridgeManager{
		node: "pve", runner: runner,
		kernelProbe: func(name string) (bool, error) { return name == "vmbr1", nil },
	}
	state, err := manager.Inspect(context.Background(), "vmbr1")
	if err != nil || state.Exists || !state.KernelPresent {
		t.Fatalf("state=%#v err=%v", state, err)
	}
}

func TestPVETemplateBridgeCreateRefusesKernelRaceBeforeReload(t *testing.T) {
	path := "/nodes/pve/network"
	active, pending, lockPath := testBridgeNetworkPaths(t)
	runner := &scriptedBridgeRunner{t: t, networkSemanticByInput: testNetworkSemantics(), results: []bridgeRunResult{
		{program: templateBridgePVESh, args: []string{"create", path, "--iface", "vmbr1", "--type", "bridge", "--autostart", "1", "--bridge_ports", "none", "--comments", templateBridgeOwnershipComment}, before: func() {
			if err := os.WriteFile(pending, []byte(testNetworkOwned), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	}}
	probes := 0
	manager := &pveTemplateBridgeManager{
		node: "pve", runner: runner, activeNetworkPath: active, pendingNetworkPath: pending, networkLockPath: lockPath,
		kernelProbe: func(string) (bool, error) {
			probes++
			return probes > 1, nil
		},
	}
	if _, err := manager.Create(context.Background(), "vmbr1"); err == nil || !strings.Contains(err.Error(), "创建窗口出现同名内核接口") {
		t.Fatalf("err=%v", err)
	}
	for _, call := range runner.calls {
		if call.program == templateBridgePVESh && len(call.args) > 0 && call.args[0] == "set" {
			t.Fatalf("kernel collision was reloaded: calls=%v", runner.calls)
		}
	}
}

func TestPVETemplateBridgeCreateRefusesConcurrentPendingMutationBeforeReload(t *testing.T) {
	path := "/nodes/pve/network"
	active, pending, lockPath := testBridgeNetworkPaths(t)
	runner := &scriptedBridgeRunner{t: t, networkSemanticByInput: testNetworkSemantics(), results: []bridgeRunResult{
		{program: templateBridgePVESh, args: []string{"create", path, "--iface", "vmbr1", "--type", "bridge", "--autostart", "1", "--bridge_ports", "none", "--comments", templateBridgeOwnershipComment}, before: func() {
			if err := os.WriteFile(pending, []byte(testNetworkConcurrent), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	}}
	manager := &pveTemplateBridgeManager{node: "pve", runner: runner, activeNetworkPath: active, pendingNetworkPath: pending, networkLockPath: lockPath}
	if _, err := manager.Create(context.Background(), "vmbr1"); err == nil || !strings.Contains(err.Error(), "仅新增自有隔离桥") {
		t.Fatalf("err=%v", err)
	}
	if len(runner.results) != 0 {
		t.Fatalf("unconsumed results=%d", len(runner.results))
	}
}

func TestPVETemplateBridgeCreateRefusesActiveMutationInBaselineToPOSTWindow(t *testing.T) {
	path := "/nodes/pve/network"
	active, pending, lockPath := testBridgeNetworkPaths(t)
	runner := &scriptedBridgeRunner{t: t, networkSemanticByInput: testNetworkSemantics(), results: []bridgeRunResult{
		{program: templateBridgePVESh, args: []string{"create", path, "--iface", "vmbr1", "--type", "bridge", "--autostart", "1", "--bridge_ports", "none", "--comments", templateBridgeOwnershipComment}, before: func() {
			if err := os.WriteFile(active, []byte(testNetworkAdminOnly), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(pending, []byte(testNetworkConcurrent), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	}}
	manager := &pveTemplateBridgeManager{node: "pve", runner: runner, activeNetworkPath: active, pendingNetworkPath: pending, networkLockPath: lockPath}
	if _, err := manager.Create(context.Background(), "vmbr1"); err == nil || !strings.Contains(err.Error(), "active network 在创建窗口发生变化") {
		t.Fatalf("err=%v", err)
	}
	for _, call := range runner.calls {
		if call.program == templateBridgePVESh && len(call.args) > 0 && call.args[0] == "set" {
			t.Fatalf("concurrent vmbr0/gateway mutation was reloaded: calls=%v", runner.calls)
		}
	}
}

func TestPVETemplateBridgeCreateKeepsOwnedBridgeForManualRecoveryAfterStoppedReloadFailure(t *testing.T) {
	path := "/nodes/pve/network"
	active, pending, lockPath := testBridgeNetworkPaths(t)
	applyUPID := "UPID:pve:1:2:3:srvreload:networking:root@pam:"
	safeList := `[{"iface":"vmbr1","type":"bridge"}]`
	safeDetail := `{"iface":"vmbr1","type":"bridge","autostart":1,"bridge_ports":"none","bridge_stp":0,"bridge_fd":0,"method":"manual","method6":"manual","comments":"PPFlight private template bridge"}`
	runner := &scriptedBridgeRunner{t: t, networkSemanticByInput: testNetworkSemantics(), results: []bridgeRunResult{
		{program: templateBridgePVESh, args: []string{"create", path, "--iface", "vmbr1", "--type", "bridge", "--autostart", "1", "--bridge_ports", "none", "--comments", templateBridgeOwnershipComment}, before: func() {
			if err := os.WriteFile(pending, []byte(testNetworkOwned), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{program: templateBridgePVESh, args: []string{"get", path, "--output-format", "json"}, output: safeList},
		{program: templateBridgePVESh, args: []string{"get", path + "/vmbr1", "--output-format", "json"}, output: safeDetail},
		{program: templateBridgeIP, args: []string{"-json", "-details", "link", "show", "dev", "vmbr1"}, err: errors.New("not found")},
		{program: templateBridgePVESh, args: []string{"set", path, "--output-format", "json"}, output: `"` + applyUPID + `"`},
		{program: templateBridgePVESh, args: []string{"get", "/nodes/pve/tasks/" + applyUPID + "/status", "--output-format", "json"}, output: `{"status":"stopped","exitstatus":"ERROR"}`, before: func() {
			if err := os.Remove(pending); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(active, []byte(testNetworkOwned), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	}}
	manager := &pveTemplateBridgeManager{node: "pve", runner: runner, activeNetworkPath: active, pendingNetworkPath: pending, networkLockPath: lockPath}
	if _, err := manager.Create(context.Background(), "vmbr1"); err == nil || !strings.Contains(err.Error(), "未自动回滚") {
		t.Fatalf("err=%v", err)
	}
	if raw, err := os.ReadFile(active); err != nil || string(raw) != testNetworkOwned {
		t.Fatalf("owned bridge state was unexpectedly removed: raw=%q err=%v", string(raw), err)
	}
	if len(runner.results) != 0 {
		t.Fatalf("unconsumed results=%d", len(runner.results))
	}
}

func TestPVETemplateBridgeInspectAllowsValidLongPVENodeName(t *testing.T) {
	node := "pve-production-node-01"
	runner := &scriptedBridgeRunner{t: t, results: []bridgeRunResult{{
		program: templateBridgePVESh, args: []string{"get", "/nodes/" + node + "/network", "--output-format", "json"}, output: `[]`,
	}}}
	manager := &pveTemplateBridgeManager{node: node, runner: runner}
	state, err := manager.Inspect(context.Background(), "vmbr1")
	if err != nil || state.Exists {
		t.Fatalf("state=%#v err=%v", state, err)
	}
}

func TestSafeTemplateBridgeNameHonorsLinuxInterfaceLimit(t *testing.T) {
	for _, value := range []string{"vmbr1", "private-bridge1"} {
		if !safeTemplateBridgeName(value) {
			t.Fatalf("valid bridge rejected: %q", value)
		}
	}
	for _, value := range []string{"", "-vmbr1", "vmbr 1", "1234567890123456", "vmbr1\n--type"} {
		if safeTemplateBridgeName(value) {
			t.Fatalf("invalid bridge accepted: %q", value)
		}
	}
}

func TestProductionTemplateBridgeManagerRequiresRootOwnedNetworkFiles(t *testing.T) {
	manager := newPVETemplateBridgeManager("pve", &scriptedBridgeRunner{t: t})
	if !manager.requireRootFiles || manager.kernelMembers == nil {
		t.Fatal("production bridge manager omitted root ownership or Linux bridge-member enforcement")
	}
}

func TestTemplateBridgeRunnerRejectsUnexpectedProgram(t *testing.T) {
	if _, err := (templateBridgeExecRunner{}).Run(context.Background(), "/bin/sh", "-c", "true"); err == nil || !strings.Contains(err.Error(), "不允许") {
		t.Fatalf("err=%v", err)
	}
}

func TestTemplateBridgeCappedBufferFailsClosed(t *testing.T) {
	buffer := &templateBridgeCappedBuffer{maximum: 4}
	if written, err := buffer.Write([]byte("abcdef")); err != nil || written != 6 {
		t.Fatalf("written=%d err=%v", written, err)
	}
	if !buffer.overflow || buffer.String() != "abcd" {
		t.Fatalf("overflow=%v output=%q", buffer.overflow, buffer.String())
	}
}

func TestParseTemplateBridgeUPIDRequiresStrictJSONAndSafeAlphabet(t *testing.T) {
	valid := `"UPID:pve:1:2:3:srvreload:networking:root@pam:"`
	if value, err := parseTemplateBridgeUPID([]byte(valid)); err != nil || value != strings.Trim(valid, `"`) {
		t.Fatalf("value=%q err=%v", value, err)
	}
	for _, raw := range []string{
		`UPID:pve:1`,
		`"UPID:pve:1?query"`,
		`"UPID:pve:1" {}`,
		`"UPID:pve/other:1"`,
	} {
		if _, err := parseTemplateBridgeUPID([]byte(raw)); err == nil {
			t.Fatalf("unsafe UPID accepted: %q", raw)
		}
	}
}
