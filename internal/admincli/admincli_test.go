package admincli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/assignment"
	"github.com/ppflight/ppflight-agent/internal/bindstate"
	"github.com/ppflight/ppflight-agent/internal/config"
	"github.com/ppflight/ppflight-agent/internal/enrollment"
	"github.com/ppflight/ppflight-agent/internal/monitorenrollment"
	"github.com/ppflight/ppflight-agent/internal/netpolicy"
	"github.com/ppflight/ppflight-agent/internal/protocol"
	"github.com/ppflight/ppflight-agent/internal/templatebootstrap"
)

func writeTestConfig(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	raw := []byte(`{"schemaVersion":1,"mode":"test","identity":{"agentRef":"agent-test","collectorRef":"collector-test","sourceRef":"source-test","clusterRef":"cluster-test","nodeRef":"auto","site":"test"},"runtime":{"stateDirectory":"/tmp/ppflight-admin-test","listenAddress":"127.0.0.1:9745","shutdownGrace":"15s","logLevel":"info"},"destinations":{"websiteMetering":{"enabled":false},"websiteTelemetry":{"enabled":false},"monitoring":{"enabled":false}},"control":{"enabled":true,"pollUrl":"","resultUrl":"","productionExecution":false}}`)
	cfg, err := config.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(root, "agent.yaml")
	if err := os.WriteFile(filename, encoded, 0o640); err != nil {
		t.Fatal(err)
	}
	return filename
}

func runMonitoringBindForTest(args []string, version string, in io.Reader, out, errOut io.Writer) int {
	c := &cli{
		in:      in,
		out:     out,
		errOut:  errOut,
		version: version,
		pveVersion: func(context.Context) (string, error) {
			return "9.0.8", nil
		},
		activateBinding: func(_ context.Context, cfg config.Config, expected bindingActivationExpectation) error {
			if expected.BindingID == "" {
				return nil
			}
			state, err := bindstate.LoadMonitoring(cfg.Runtime.StateDirectory)
			if err != nil {
				return err
			}
			if expected.Domain != "monitoring" || state.BindingID != expected.BindingID || state.CredentialEpoch != expected.CredentialEpoch {
				return errors.New("new monitoring binding was not loaded")
			}
			return nil
		},
	}
	return c.run(args)
}

func TestUsageListsWebsiteBindAndStatus(t *testing.T) {
	var output, stderr bytes.Buffer
	if code := Run([]string{"help"}, "test", &output, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	usage := output.String()
	for _, command := range []string{"website bind --endpoint", "website status", "monitoring preflight --endpoint"} {
		if !strings.Contains(usage, command) {
			t.Fatalf("usage does not contain %q: %s", command, usage)
		}
	}
}

type preflightResolver func(context.Context, string, string) ([]net.IP, error)

func (f preflightResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	return f(ctx, network, host)
}

func TestMonitoringPreflightProducesExplicitTLSVerifiedIPv4Evidence(t *testing.T) {
	resolvedAt := time.Date(2026, 8, 30, 4, 5, 6, 0, time.UTC)
	resolver := preflightResolver(func(_ context.Context, network, host string) ([]net.IP, error) {
		if network != "ip4" || host != "moniter.ppflight.com" {
			t.Fatalf("lookup network=%q host=%q", network, host)
		}
		return []net.IP{net.ParseIP("172.67.140.237"), net.ParseIP("104.21.27.23"), net.ParseIP("2001:db8::1"), net.ParseIP("104.21.27.23")}, nil
	})
	var dialed []string
	dial := func(_ context.Context, address, hostname string, _ time.Duration) (tls.ConnectionState, error) {
		dialed = append(dialed, address)
		if hostname != "moniter.ppflight.com" {
			t.Fatalf("TLS hostname=%q", hostname)
		}
		return tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{{NotAfter: resolvedAt.Add(24 * time.Hour)}}}, nil
	}
	result, err := buildMonitoringPreflight(context.Background(), "https://moniter.ppflight.com/internal/v1/monitoring/agents/bind", time.Second, resolver, dial, func() time.Time { return resolvedAt })
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"104.21.27.23", "172.67.140.237"}
	if !slices.Equal(result.ResolvedA, want) {
		t.Fatalf("result=%#v", result)
	}
	if !slices.Equal(dialed, []string{"104.21.27.23:443", "172.67.140.237:443"}) {
		t.Fatalf("dialed=%v", dialed)
	}
	for _, check := range result.Checks {
		if check.Status != "verified" || check.TLSVersion != "TLS1.3" || check.ErrorCode != "" {
			t.Fatalf("check=%#v", check)
		}
	}
}

func TestMonitoringPreflightRecordsPerAddressTLSErrorWithoutApprovalGate(t *testing.T) {
	resolver := preflightResolver(func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")}, nil
	})
	dial := func(_ context.Context, address, _ string, _ time.Duration) (tls.ConnectionState, error) {
		if strings.HasPrefix(address, "192.0.2.2:") {
			return tls.ConnectionState{}, errors.New("test failure")
		}
		return tls.ConnectionState{Version: tls.VersionTLS12}, nil
	}
	result, err := buildMonitoringPreflight(context.Background(), "https://monitor.example/bind", time.Second, resolver, dial, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Checks) != 2 || result.Checks[0].Status != "verified" || result.Checks[1].ErrorCode != "TCP4_TLS_VERIFICATION_FAILED" {
		t.Fatalf("result=%#v", result)
	}
}

func TestNoArgumentsShowsSixItemMenu(t *testing.T) {
	var output, stderr bytes.Buffer
	if code := RunWithInput(nil, "test", strings.NewReader("0\n"), &output, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	for _, text := range []string{"1) 初始化/克隆", "2) 使用一次性绑定码绑定 PPFlight 官网", "3) 使用独立一次性绑定码绑定监控站", "4) 查看 PPFlight 官网通信状态", "5) 查看监控站通信状态", "6) 完全卸载 PPFlight Agent"} {
		if !strings.Contains(output.String(), text) {
			t.Fatalf("menu does not contain %q: %s", text, output.String())
		}
	}
}

func TestMenuCompleteUninstallRequiresExactConfirmation(t *testing.T) {
	var output, stderr bytes.Buffer
	called := false
	instance := &cli{
		in: strings.NewReader("6\nYES\n"), out: &output, errOut: &stderr,
		effectiveUID:      func() int { return 0 },
		completeUninstall: func(context.Context) error { called = true; return nil },
	}
	if code := instance.menu("unused"); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if called || !strings.Contains(output.String(), "已取消") {
		t.Fatalf("inexact confirmation executed uninstall: called=%v output=%s", called, output.String())
	}
}

func TestMenuCompleteUninstallExecutesPurgeAfterExactConfirmation(t *testing.T) {
	var output, stderr bytes.Buffer
	called := false
	instance := &cli{
		in: strings.NewReader("6\nUNINSTALL\n"), out: &output, errOut: &stderr,
		effectiveUID:      func() int { return 0 },
		completeUninstall: func(context.Context) error { called = true; return nil },
	}
	if code := instance.menu("unused"); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !called || !strings.Contains(output.String(), "已完全卸载") || !strings.Contains(output.String(), "不会删除 PVE 虚拟机") {
		t.Fatalf("complete uninstall contract missing: called=%v output=%s", called, output.String())
	}
}

func TestMenuCompleteUninstallRequiresRoot(t *testing.T) {
	var output, stderr bytes.Buffer
	instance := &cli{in: strings.NewReader("6\nUNINSTALL\n"), out: &output, errOut: &stderr, effectiveUID: func() int { return 1000 }}
	if code := instance.menu("unused"); code == 0 {
		t.Fatal("non-root complete uninstall succeeded")
	}
	if !strings.Contains(stderr.String(), "必须由 PVE root") {
		t.Fatalf("missing root-only error: %s", stderr.String())
	}
}

func TestMenuPVEVersionValidation(t *testing.T) {
	for _, value := range []string{"8.4.1", "9.0.0+test", "pve-8:1"} {
		if !safeMenuVersion(value) {
			t.Fatalf("valid PVE version rejected: %q", value)
		}
	}
	for _, value := range []string{"", ".8.4", "8/4", "8 4", strings.Repeat("a", 129)} {
		if safeMenuVersion(value) {
			t.Fatalf("invalid PVE version accepted: %q", value)
		}
	}
}

func TestTemplateStorageRemediationPreservesExistingContent(t *testing.T) {
	automatic := false
	storage := templateStorage{StorageID: "local", Type: "dir", ContentTypes: []string{"backup", "iso", "vztmpl"}, Enabled: true, Active: true}
	storage.RoleEligibility.Image = templateRole{Allowed: false, Reasons: []string{"MISSING_CONTENT_SNIPPETS"}}
	storage.Remediations = []templateRemediation{{
		Code: "ENABLE_STORAGE_CONTENT", StorageID: "local", CurrentContent: "backup,iso,vztmpl", RequiredContent: "snippets", ProposedContent: "backup,iso,snippets,vztmpl", Automatic: &automatic,
		Command: templateRemediationCommand{Program: "pvesm", Argv: []string{"pvesm", "set", "local", "--content", "backup,iso,snippets,vztmpl"}},
	}}
	var output, stderr bytes.Buffer
	instance := &cli{in: strings.NewReader(""), out: &output, errOut: &stderr, version: "test"}
	choice, err := instance.promptTemplateStorage(bufio.NewReader(strings.NewReader("1\n")), []templateStorage{storage}, "image", "选择镜像缓存存储")
	if err != nil || choice.StorageID != "local" || choice.Remediation == nil {
		t.Fatalf("safe auto-configuration candidate was not selectable: choice=%#v err=%v", choice, err)
	}
	value := output.String()
	if !strings.Contains(value, "选择后新增：Cloud-Init 配置 (snippets)") || !strings.Contains(value, "不会删除现有能力") {
		t.Fatalf("safe automatic configuration candidate missing: %s", value)
	}
}

func TestTemplateStorageDisplayUsesReadableCapacityAndLabels(t *testing.T) {
	if got := humanAvailableBytes("229425152000", true); got != "213.7 GiB" {
		t.Fatalf("capacity=%q", got)
	}
	if got := humanStorageContentCSV("backup,iso,snippets,vztmpl"); got != "备份 (backup)、ISO 镜像 (iso)、Cloud-Init 配置 (snippets)、LXC 模板 (vztmpl)" {
		t.Fatalf("content=%q", got)
	}
}

func TestPromptYesNoRejectsInvalidAndControlCharacterInput(t *testing.T) {
	for _, input := range []string{"b^H\ny\n", "b\x08\nY\n"} {
		var output bytes.Buffer
		instance := &cli{out: &output, errOut: io.Discard}
		answer, err := instance.promptYesNo(bufio.NewReader(strings.NewReader(input)), "确认？[Y/n]: ", true)
		if err != nil || !answer {
			t.Fatalf("input=%q answer=%t err=%v", input, answer, err)
		}
		if !strings.Contains(output.String(), "输入无效") || strings.Count(output.String(), "确认？") != 2 {
			t.Fatalf("invalid input was not rejected and reprompted: %q", output.String())
		}
	}
}

func TestPromptPlanExecutionAcceptsYesOrNoAndRejectsOtherInput(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      bool
		invalid   bool
		promptCnt int
	}{
		{name: "yes", input: "YES\n", want: true, promptCnt: 1},
		{name: "no", input: "no\n", want: false, promptCnt: 1},
		{name: "empty cancels", input: "\n", want: false, promptCnt: 1},
		{name: "invalid then yes", input: "EXECUTE\nYES\n", want: true, invalid: true, promptCnt: 2},
		{name: "control character then no", input: "b\x08\nno\n", want: false, invalid: true, promptCnt: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			instance := &cli{out: &output, errOut: io.Discard}
			got, err := instance.promptPlanExecution(bufio.NewReader(strings.NewReader(test.input)))
			if err != nil || got != test.want {
				t.Fatalf("got=%t want=%t err=%v", got, test.want, err)
			}
			if strings.Contains(output.String(), "输入无效") != test.invalid {
				t.Fatalf("invalid message mismatch: %q", output.String())
			}
			if count := strings.Count(output.String(), "确认执行以上模板计划？"); count != test.promptCnt {
				t.Fatalf("prompt count=%d want=%d output=%q", count, test.promptCnt, output.String())
			}
		})
	}
}

func TestTemplateStorageRejectsMismatchedFrozenRemediation(t *testing.T) {
	automatic := false
	storage := templateStorage{StorageID: "local", Type: "dir", ContentTypes: []string{"iso"}, Enabled: true, Active: true}
	storage.RoleEligibility.Image = templateRole{Allowed: false, Reasons: []string{"MISSING_CONTENT_SNIPPETS"}}
	storage.Remediations = []templateRemediation{{
		Code: "ENABLE_STORAGE_CONTENT", StorageID: "local", CurrentContent: "iso", RequiredContent: "snippets", ProposedContent: "iso,snippets", Automatic: &automatic,
		Command: templateRemediationCommand{Program: "pvesm", Argv: []string{"pvesm", "set", "local", "--content", "iso,images"}},
	}}
	var output bytes.Buffer
	instance := &cli{in: strings.NewReader(""), out: &output, errOut: io.Discard, version: "test"}
	if _, err := instance.promptTemplateStorage(bufio.NewReader(strings.NewReader("")), []templateStorage{storage}, "image", "选择镜像缓存存储"); err == nil {
		t.Fatal("ineligible image storage was accepted")
	}
	if strings.Contains(output.String(), "sudo pvesm") || !strings.Contains(output.String(), "已拒绝使用") {
		t.Fatalf("mismatched frozen remediation was rendered: %s", output.String())
	}
}

func TestChooseTemplateStorageAppliesExactContentAndRediscovers(t *testing.T) {
	automatic := false
	storage := templateStorage{StorageID: "local", Type: "dir", ContentTypes: []string{"backup", "iso", "vztmpl"}, Enabled: true, Active: true}
	storage.RoleEligibility.Image = templateRole{Allowed: false, Reasons: []string{"MISSING_CONTENT_SNIPPETS"}}
	storage.Remediations = []templateRemediation{{
		Code: "ENABLE_STORAGE_CONTENT", StorageID: "local", CurrentContent: "backup,iso,vztmpl", RequiredContent: "snippets", ProposedContent: "backup,iso,snippets,vztmpl", Automatic: &automatic,
		Command: templateRemediationCommand{Program: "pvesm", Argv: []string{"pvesm", "set", "local", "--content", "backup,iso,snippets,vztmpl"}},
	}}
	refreshed := storage
	refreshed.ContentTypes = []string{"backup", "iso", "snippets", "vztmpl"}
	refreshed.RoleEligibility.Image = templateRole{Allowed: true, Reasons: []string{}}
	refreshed.Remediations = []templateRemediation{}
	discoveryRaw, err := json.Marshal(templateDiscovery{SchemaVersion: "ppflight.template-bootstrap-result/v1", Mode: "discover", State: "succeeded", Storages: []templateStorage{refreshed}})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	var gotStorage, gotContent string
	instance := &cli{
		in: strings.NewReader(""), out: &output, errOut: io.Discard, version: "test",
		pvesmSetContent: func(_ context.Context, storageID, content string) error {
			gotStorage, gotContent = storageID, content
			return nil
		},
		templateRun: func(_ context.Context, args []string, _ io.Writer) (templatebootstrap.Result, error) {
			if !slices.Equal(args, []string{"discover"}) {
				t.Fatalf("unexpected helper args: %v", args)
			}
			return templatebootstrap.Result{ExitCode: 0, Stdout: discoveryRaw}, nil
		},
	}
	selected, storages, err := instance.chooseTemplateStorage(context.Background(), bufio.NewReader(strings.NewReader("1\ny\n")), []templateStorage{storage}, "image", "选择镜像缓存存储")
	if err != nil || selected != "local" || len(storages) != 1 || !storages[0].RoleEligibility.Image.Allowed {
		t.Fatalf("selected=%q storages=%#v err=%v", selected, storages, err)
	}
	if gotStorage != "local" || gotContent != "backup,iso,snippets,vztmpl" {
		t.Fatalf("pvesm set got storage=%q content=%q", gotStorage, gotContent)
	}
	for _, expected := range []string{"输入 Y", "当前能力：备份 (backup)", "需要新增：Cloud-Init 配置 (snippets)", "pvesm set local", "--content backup,iso,snippets,vztmpl", "已配置并通过重新检测"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("output missing %q: %s", expected, output.String())
		}
	}
}

func TestTemplateInitAllSelectsImageTemplateAndBackupStorages(t *testing.T) {
	automatic := false
	local := templateStorage{StorageID: "local", Type: "dir", ContentTypes: []string{"backup", "iso", "vztmpl"}, Enabled: true, Active: true, AvailableBytes: "1000", AvailableBytesKnown: true, Remediations: []templateRemediation{}}
	local.RoleEligibility.Image = templateRole{Allowed: false, Reasons: []string{"MISSING_CONTENT_SNIPPETS"}}
	local.RoleEligibility.Template = templateRole{Allowed: false, Reasons: []string{"MISSING_CONTENT_IMAGES"}}
	local.RoleEligibility.Backup = templateRole{Allowed: true, Reasons: []string{}}
	local.Remediations = []templateRemediation{{
		Code: "ENABLE_STORAGE_CONTENT", StorageID: "local", CurrentContent: "backup,iso,vztmpl", RequiredContent: "snippets", ProposedContent: "backup,iso,snippets,vztmpl", Automatic: &automatic,
		Command: templateRemediationCommand{Program: "pvesm", Argv: []string{"pvesm", "set", "local", "--content", "backup,iso,snippets,vztmpl"}},
	}}
	localZFS := templateStorage{StorageID: "local-zfs", Type: "zfspool", ContentTypes: []string{"images", "rootdir"}, Enabled: true, Active: true, AvailableBytes: "2000", AvailableBytesKnown: true, Remediations: []templateRemediation{}}
	localZFS.RoleEligibility.Image = templateRole{Allowed: false, Reasons: []string{"MISSING_CONTENT_ISO", "MISSING_CONTENT_SNIPPETS"}}
	localZFS.RoleEligibility.Template = templateRole{Allowed: true, Reasons: []string{}}
	localZFS.RoleEligibility.Backup = templateRole{Allowed: false, Reasons: []string{"MISSING_CONTENT_BACKUP"}}
	initialRaw, err := json.Marshal(templateDiscovery{SchemaVersion: "ppflight.template-bootstrap-result/v1", Mode: "discover", State: "succeeded", Storages: []templateStorage{local, localZFS}})
	if err != nil {
		t.Fatal(err)
	}
	refreshedLocal := local
	refreshedLocal.ContentTypes = []string{"backup", "iso", "snippets", "vztmpl"}
	refreshedLocal.RoleEligibility.Image = templateRole{Allowed: true, Reasons: []string{}}
	refreshedLocal.Remediations = []templateRemediation{}
	refreshedRaw, err := json.Marshal(templateDiscovery{SchemaVersion: "ppflight.template-bootstrap-result/v1", Mode: "discover", State: "succeeded", Storages: []templateStorage{refreshedLocal, localZFS}})
	if err != nil {
		t.Fatal(err)
	}
	catalogRaw := []byte(`{"catalogSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","catalog":{"catalogRevision":"test-1","items":[{"templateRef":"ubuntu-24.04","version":"24.04","displayName":"Ubuntu 24.04","aliases":[],"target":{"vmid":9001}}]}}`)
	planRaw := []byte(`{"state":"ready","executable":true,"catalog":{"catalogRevision":"test-1","catalogSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`)
	discoverCalls := 0
	var bootstrapArgs []string
	var output, stderr bytes.Buffer
	instance := &cli{
		in: strings.NewReader("\n1\nY\n1\n\n1\nvmbr0\nY\nvmbr0\nvmbr1\n\n"), out: &output, errOut: &stderr, version: "test",
		pvesmSetContent: func(_ context.Context, storageID, content string) error {
			if storageID != "local" || content != "backup,iso,snippets,vztmpl" {
				t.Fatalf("unexpected storage content update: %s %s", storageID, content)
			}
			return nil
		},
		templateRun: func(_ context.Context, args []string, _ io.Writer) (templatebootstrap.Result, error) {
			switch args[0] {
			case "discover":
				discoverCalls++
				raw := initialRaw
				if discoverCalls > 1 {
					raw = refreshedRaw
				}
				return templatebootstrap.Result{ExitCode: 0, Stdout: raw}, nil
			case "catalog":
				return templatebootstrap.Result{ExitCode: 0, Stdout: catalogRaw}, nil
			case "bootstrap":
				bootstrapArgs = append([]string(nil), args...)
				return templatebootstrap.Result{ExitCode: 0, Stdout: planRaw}, nil
			default:
				t.Fatalf("unexpected helper args: %v", args)
				return templatebootstrap.Result{}, nil
			}
		},
	}
	if code := instance.templateInit(); code != 0 {
		t.Fatalf("code=%d stderr=%s output=%s", code, stderr.String(), output.String())
	}
	if discoverCalls != 2 {
		t.Fatalf("discover calls=%d", discoverCalls)
	}
	joined := strings.Join(bootstrapArgs, " ")
	for _, expected := range []string{"--items all", "--image-storage local", "--template-storage local-zfs", "--backup-policy required", "--backup-storage local", "--bridge vmbr0", "--internal-bridge vmbr1"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("bootstrap args missing %q: %v", expected, bootstrapArgs)
		}
	}
	for _, expected := range []string{"选择镜像缓存存储", "选择模板磁盘存储", "选择模板备份存储", "内网网桥不能与外网网桥相同", "外网 net0 -> vmbr0", "内网 net1 -> vmbr1", "未执行任何模板变更"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("output missing %q: %s", expected, output.String())
		}
	}
}

func TestDecodeTemplateDiscoveryRequiresExactFrozenRemediation(t *testing.T) {
	automatic := false
	storage := templateStorage{StorageID: "local", Type: "dir", ContentTypes: []string{"iso"}, Enabled: true, Active: true, AvailableBytes: "1024", AvailableBytesKnown: true}
	storage.RoleEligibility.Image = templateRole{Allowed: false, Reasons: []string{"MISSING_CONTENT_SNIPPETS"}}
	storage.RoleEligibility.Template = templateRole{Allowed: false, Reasons: []string{"MISSING_CONTENT_IMAGES"}}
	storage.RoleEligibility.Backup = templateRole{Allowed: false, Reasons: []string{"MISSING_CONTENT_BACKUP"}}
	storage.Remediations = []templateRemediation{{
		Code: "ENABLE_STORAGE_CONTENT", StorageID: "local", CurrentContent: "iso", RequiredContent: "snippets", ProposedContent: "iso,snippets", Automatic: &automatic,
		Command: templateRemediationCommand{Program: "pvesm", Argv: []string{"pvesm", "set", "local", "--content", "iso,snippets"}},
	}}
	discovery := templateDiscovery{SchemaVersion: "ppflight.template-bootstrap-result/v1", Mode: "discover", State: "succeeded", Storages: []templateStorage{storage}}
	raw, err := json.Marshal(discovery)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeTemplateDiscovery(raw); err != nil {
		t.Fatalf("valid discovery rejected: %v", err)
	}
	discovery.Storages[0].Remediations[0].Command.Argv[4] = "iso,images"
	raw, err = json.Marshal(discovery)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeTemplateDiscovery(raw); err == nil {
		t.Fatal("mismatched remediation command was accepted")
	}
}

func TestMonitoringSetCreatesBackupAndPreservesSafeFormat(t *testing.T) {
	filename := writeTestConfig(t)
	var output, errors bytes.Buffer
	code := Run([]string{"--config", filename, "monitoring", "set", "--enabled=true", "--url=http://127.0.0.1:18080/api/ingest", "--auth-mode=none", "--payload-format=legacy-ingest-v1"}, "test", &output, &errors)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errors.String())
	}
	cfg, err := config.LoadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Destinations.Monitoring.Enabled || cfg.Destinations.Monitoring.PayloadFormat != "legacy-ingest-v1" {
		t.Fatalf("monitoring=%#v", cfg.Destinations.Monitoring)
	}
	matches, err := filepath.Glob(filename + ".bak.*")
	if err != nil || len(matches) != 1 {
		t.Fatalf("backups=%v err=%v", matches, err)
	}
}

func TestShowContainsOnlyEnvironmentNames(t *testing.T) {
	filename := writeTestConfig(t)
	var output, errors bytes.Buffer
	if code := Run([]string{"--config", filename, "website", "show"}, "test", &output, &errors); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errors.String())
	}
	if strings.Contains(output.String(), "TOKEN-SECRET-VALUE") {
		t.Fatal("secret value leaked")
	}
}

func TestAtomicUpdateRejectsSymlink(t *testing.T) {
	filename := writeTestConfig(t)
	link := filepath.Join(filepath.Dir(filename), "linked.yaml")
	if err := os.Symlink(filename, link); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := atomicUpdate(link, cfg); err == nil {
		t.Fatal("symlink update was accepted")
	}
}

func bindingResponse(serverURL string) enrollment.Response {
	secret := enrollment.Secret(base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")))
	credential := enrollment.HMACCredential{KeyID: "key-01", Secret: secret}
	return enrollment.Response{
		SchemaVersion: enrollment.SchemaVersion, BindingID: "123e4567-e89b-42d3-a456-426614174001",
		AgentRef: "agent-01", CollectorRef: "collector-01", SourceRef: "source-01", ClusterRef: "cluster-01", NodeRef: "node-01", Site: "site-01",
		Endpoints:                enrollment.Endpoints{Metering: serverURL + "/metering", Telemetry: serverURL + "/telemetry", Assignments: serverURL + "/assignments", Commands: serverURL + "/commands", Receipts: serverURL + "/receipts"},
		HMACCredentials:          enrollment.HMACCredentials{Metering: credential, Telemetry: credential, Assignments: credential, Commands: credential, Receipts: credential},
		CommandSigningCredential: enrollment.CommandSigningCredential{KeyID: "command-key-01", Algorithm: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32))},
		AllowedActions:           []string{"vm.start", "vm.shutdown"},
		AssignmentDocument:       json.RawMessage(`{"schemaVersion":1,"revision":"rev-01","issuedAt":"2026-08-30T00:00:00Z","assignments":[]}`),
		NetworkPolicy:            netpolicy.NetworkPolicy{AgentObservedIPv4: "127.0.0.1", ServerIPv4Allowlist: []string{"127.0.0.1"}},
		CredentialEpoch:          1, IssuedAt: time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC),
	}
}

func prepareBindConfig(t *testing.T) string {
	t.Helper()
	filename := writeTestConfig(t)
	cfg, err := config.LoadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Dir(filename)
	cfg.Runtime.StateDirectory = filepath.Join(root, "state")
	cfg.Assignments.File = filepath.Join(root, "assignments.json")
	// Binding must not change these independently managed PVE credentials.
	cfg.PVE.TokenSecretEnv = "PVE_READ_SECRET_MUST_STAY"
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, raw, 0o640); err != nil {
		t.Fatal(err)
	}
	return filename
}

func TestBindReadsCodeOnlyFromInputAndPersistsPrivateState(t *testing.T) {
	filename := prepareBindConfig(t)
	requests := 0
	var received enrollment.Request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		response := bindingResponse("http://" + r.Host)
		response.DeviceID = received.DeviceID
		response.CredentialEpoch = uint64(requests)
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
	secret := "0123456789abcdef"
	var output, errors bytes.Buffer
	code := RunWithInput([]string{"--config", filename, "website", "bind", "--endpoint", server.URL + "/v1/bind", "--pve-version", "8.2.2", "--hostname", "pve-test"}, "1.2.3", strings.NewReader("BINDING-123456\n"), &output, &errors)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errors.String())
	}
	if received.BindingCode != "BINDING-123456" || received.DeviceID == "" {
		t.Fatalf("request=%#v", received)
	}
	if strings.Contains(strings.Join(received.Capabilities, ","), "pve.control.v1") {
		t.Fatalf("simulator binding claimed unverified control capability: %v", received.Capabilities)
	}
	if strings.Contains(output.String(), "BINDING-123456") || strings.Contains(output.String(), secret) || strings.Contains(errors.String(), secret) {
		t.Fatalf("binding output leaked secret: %q / %q", output.String(), errors.String())
	}
	cfg, err := config.LoadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Destinations.WebsiteMetering.Enabled || !cfg.Destinations.WebsiteTelemetry.Enabled || cfg.Destinations.Monitoring.Enabled || cfg.Control.ProductionExecution || cfg.PVE.TokenSecretEnv != "PVE_READ_SECRET_MUST_STAY" {
		t.Fatalf("unsafe config mutation: %#v", cfg)
	}
	if cfg.Identity.AgentRef != "agent-01" || cfg.Control.PollURL == "" || cfg.Control.ResultURL == "" {
		t.Fatalf("response public fields were not saved: %#v", cfg.Identity)
	}
	state, err := bindstate.Load(cfg.Runtime.StateDirectory)
	if err != nil || string(state.HMACCredentials.Commands.Secret) == "" || state.CredentialEpoch != 1 {
		t.Fatalf("state=%#v err=%v", state.Identity, err)
	}
	if _, err := os.Stat(cfg.Assignments.File); err != nil {
		t.Fatalf("initial assignment not written: %v", err)
	}
	if requests != 1 {
		t.Fatalf("requests=%d", requests)
	}

	output.Reset()
	errors.Reset()
	code = RunWithInput([]string{"--config", filename, "bind", "--endpoint", server.URL, "--pve-version", "8.2.2"}, "1.2.3", strings.NewReader("BINDING-654321\n"), &output, &errors)
	if code == 0 || requests != 1 {
		t.Fatalf("repeat binding code=%d requests=%d stderr=%s", code, requests, errors.String())
	}
	output.Reset()
	errors.Reset()
	code = RunWithInput([]string{"--config", filename, "bind", "--endpoint", server.URL, "--pve-version", "8.2.2", "--replace"}, "1.2.3", strings.NewReader("BINDING-654321\n"), &output, &errors)
	if code != 0 || requests != 2 {
		t.Fatalf("replace binding code=%d requests=%d stderr=%s", code, requests, errors.String())
	}
}

func TestWebsiteStatusShowsOnlyRedactedLocalAndRemoteViews(t *testing.T) {
	filename := prepareBindConfig(t)
	now := time.Now().UTC().Truncate(time.Second)
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			t.Errorf("local path=%s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"schemaVersion":1,"version":"test","mode":"test","agentRef":"agent-01","clusterRef":"cluster-01","nodeRef":"node-01","startedAt":"2026-08-30T00:00:00Z","ready":true,"collection":{"authBlocked":false},"deliveries":{},"control":{"enabled":true,"configured":true,"productionExecution":false},"assignments":0,"queues":{}}`))
	}))
	defer local.Close()
	secret := []byte("commands-secret-0123456789abcdef")
	var remote *httptest.Server
	remote = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != enrollment.StatusPath || r.URL.RawQuery != "" {
			t.Errorf("remote request=%s %s", r.Method, r.URL.String())
		}
		if err := protocol.VerifyRequest(r, nil, func(keyID string) ([]byte, error) {
			if keyID != "commands-key-01" {
				return nil, errors.New("wrong commands key")
			}
			return secret, nil
		}, protocol.VerifyOptions{Now: now}); err != nil {
			t.Errorf("status HMAC: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(enrollment.StatusResponse{
			SchemaVersion: 1, BindingID: "123e4567-e89b-42d3-a456-426614174001", DeviceID: "device-status-01", AgentRef: "agent-01",
			Status: "active", CredentialEpoch: 7, AssignmentRevision: 19, CommandChannelStale: false, ServerTime: now,
		})
	}))
	defer remote.Close()

	cfg, err := config.LoadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Runtime.ListenAddress = strings.TrimPrefix(local.URL, "http://")
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, raw, 0o640); err != nil {
		t.Fatal(err)
	}
	response := bindingResponse(remote.URL)
	response.DeviceID, response.CredentialEpoch = "device-status-01", 7
	response.HMACCredentials.Commands = enrollment.HMACCredential{KeyID: "commands-key-01", Secret: enrollment.Secret(base64.StdEncoding.EncodeToString(secret))}
	if err := bindstate.Save(cfg.Runtime.StateDirectory, bindstate.FromResponse(remote.URL+"/internal/v1/agents/bind", response.DeviceID, response)); err != nil {
		t.Fatal(err)
	}
	if err := assignment.SaveState(filepath.Join(cfg.Runtime.StateDirectory, "assignments", "refresh-state.json"), assignment.State{Revision: 19, Cursor: "cursor-19"}); err != nil {
		t.Fatal(err)
	}

	var output, stderr bytes.Buffer
	code := Run([]string{"--config", filename, "website", "status"}, "test", &output, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s output=%s", code, stderr.String(), output.String())
	}
	if strings.Contains(output.String(), string(response.HMACCredentials.Commands.Secret)) || strings.Contains(output.String(), string(secret)) || strings.Contains(stderr.String(), string(secret)) {
		t.Fatalf("status leaked credential: %s / %s", output.String(), stderr.String())
	}
	var view map[string]json.RawMessage
	if err := json.Unmarshal(output.Bytes(), &view); err != nil || view["binding"] == nil || view["localAgent"] == nil || view["remoteWebsite"] == nil {
		t.Fatalf("view=%v err=%v", view, err)
	}
	var remoteView enrollment.StatusResponse
	if err := json.Unmarshal(view["remoteWebsite"], &remoteView); err != nil || remoteView.Status != "active" || remoteView.AssignmentRevision != 19 {
		t.Fatalf("remote=%#v err=%v", remoteView, err)
	}
}

func TestWebsiteStatusFailurePrintsOnlySafeCode(t *testing.T) {
	filename := prepareBindConfig(t)
	secret := []byte("commands-secret-0123456789abcdef")
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("SECRET-UPSTREAM-BODY"))
	}))
	defer remote.Close()
	cfg, err := config.LoadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	response := bindingResponse(remote.URL)
	response.DeviceID, response.CredentialEpoch = "device-status-01", 7
	response.HMACCredentials.Commands = enrollment.HMACCredential{KeyID: "commands-key-01", Secret: enrollment.Secret(base64.StdEncoding.EncodeToString(secret))}
	if err := bindstate.Save(cfg.Runtime.StateDirectory, bindstate.FromResponse(remote.URL+"/bind", response.DeviceID, response)); err != nil {
		t.Fatal(err)
	}
	if err := assignment.SaveState(filepath.Join(cfg.Runtime.StateDirectory, "assignments", "refresh-state.json"), assignment.State{Revision: 19, Cursor: "cursor-19"}); err != nil {
		t.Fatal(err)
	}
	var output, stderr bytes.Buffer
	if code := Run([]string{"--config", filename, "website", "status"}, "test", &output, &stderr); code != 1 {
		t.Fatalf("code=%d output=%s stderr=%s", code, output.String(), stderr.String())
	}
	combined := output.String() + stderr.String()
	if strings.Contains(combined, "SECRET-UPSTREAM-BODY") || strings.Contains(combined, string(secret)) || !strings.Contains(combined, "REMOTE_STATUS_UNAVAILABLE") {
		t.Fatalf("unsafe failure output=%s", combined)
	}
}

func TestBindRejectsCodeArgumentAndUnsafeCodeFile(t *testing.T) {
	filename := prepareBindConfig(t)
	var output, errors bytes.Buffer
	if code := RunWithInput([]string{"--config", filename, "bind", "--endpoint", "https://service.example", "--pve-version", "8.2.2", "BINDING-123456"}, "1.2.3", strings.NewReader(""), &output, &errors); code != 2 {
		t.Fatalf("binding code argv accepted: %d (%s)", code, errors.String())
	}
	codeFile := filepath.Join(filepath.Dir(filename), "code")
	if err := os.WriteFile(codeFile, []byte("BINDING-123456\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(filename), "code-link")
	if err := os.Symlink(codeFile, link); err != nil {
		t.Fatal(err)
	}
	if code := RunWithInput([]string{"--config", filename, "bind", "--endpoint", "https://service.example", "--pve-version", "8.2.2", "--code-file", link}, "1.2.3", strings.NewReader(""), &output, &errors); code == 0 {
		t.Fatal("symlink code file was accepted")
	}
}

func TestMonitoringBindUsesIndependentStateAndDoesNotOverwriteWebsite(t *testing.T) {
	filename := prepareBindConfig(t)
	cfg, err := config.LoadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	website := bindingResponse("https://website.example")
	deviceID, err := bindstate.LoadOrCreateDeviceID(cfg.Runtime.StateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	website.DeviceID = deviceID
	if err := bindstate.Save(cfg.Runtime.StateDirectory, bindstate.FromResponse("https://website.example/bind", website.DeviceID, website)); err != nil {
		t.Fatal(err)
	}
	var received monitorenrollment.Request
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		secret := enrollment.Secret(base64.StdEncoding.EncodeToString([]byte("monitoring-secret")))
		response := monitorenrollment.Response{SchemaVersion: 1, BindingID: "123e4567-e89b-42d3-a456-426614174003", DeviceID: received.DeviceID, MonitoringAgentRef: "monitor-agent-01", IngestEndpoint: server.URL + "/internal/v1/monitoring/telemetry/batches", HMACCredential: monitorenrollment.HMACCredential{Algorithm: "hmac-sha256", KeyID: "monitor-key-01", SecretEncoding: "base64", Secret: secret}, Telemetry: monitorenrollment.TelemetryContract{PayloadFormat: "telemetry-v1", Compression: "gzip", MaxCompressedBytes: 8 << 20, MaxUncompressedBytes: 32 << 20}, NetworkPolicy: netpolicy.NetworkPolicy{AgentObservedIPv4: "127.0.0.1", ServerIPv4Allowlist: []string{"127.0.0.1"}}, CredentialEpoch: 1, IssuedAt: time.Now().UTC()}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
	var output, stderr bytes.Buffer
	code := runMonitoringBindForTest([]string{"--config", filename, "monitoring", "bind", "--endpoint", server.URL + "/internal/v1/monitoring/agents/bind", "--hostname", "pve-test"}, "1.2.3", strings.NewReader("MONITOR-123456\n"), &output, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	updated, err := config.LoadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if !updated.Destinations.Monitoring.Enabled || updated.Destinations.Monitoring.PayloadFormat != "telemetry-v1" || updated.Destinations.Monitoring.Auth.KeyIDEnv != "PPFLIGHT_MONITORING_BINDING_KEY_ID" {
		t.Fatalf("monitoring=%#v", updated.Destinations.Monitoring)
	}
	loadedWebsite, err := bindstate.Load(cfg.Runtime.StateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	loadedMonitoring, err := bindstate.LoadMonitoring(cfg.Runtime.StateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if loadedWebsite.BindingID != website.BindingID || loadedMonitoring.MonitoringAgentRef != "monitor-agent-01" || received.RequestID == "" {
		t.Fatalf("website=%#v monitoring=%#v request=%#v", loadedWebsite, loadedMonitoring, received)
	}
	if received.NodeClaim.PVEVersion != "9.0.8" {
		t.Fatalf("automatically discovered PVE version=%q", received.NodeClaim.PVEVersion)
	}
	if strings.Contains(output.String(), "systemctl restart") || !strings.Contains(output.String(), "自动生效") {
		t.Fatalf("unexpected activation output: %s", output.String())
	}
}

func TestMonitoringBindActivationFailureRollsBackAndKeepsRetryState(t *testing.T) {
	filename := prepareBindConfig(t)
	original, err := config.LoadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request monitorenrollment.Request
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		response := monitorenrollment.Response{
			SchemaVersion:      1,
			BindingID:          "123e4567-e89b-42d3-a456-426614174004",
			DeviceID:           request.DeviceID,
			MonitoringAgentRef: "monitor-agent-rollback",
			IngestEndpoint:     server.URL + monitorenrollment.TelemetryPath,
			HMACCredential: monitorenrollment.HMACCredential{
				Algorithm: "hmac-sha256", KeyID: "monitor-key-rollback", SecretEncoding: "base64",
				Secret: enrollment.Secret(base64.StdEncoding.EncodeToString([]byte("never-print-this-secret"))),
			},
			Telemetry:       monitorenrollment.TelemetryContract{PayloadFormat: "telemetry-v1", Compression: "gzip", MaxCompressedBytes: 8 << 20, MaxUncompressedBytes: 32 << 20},
			NetworkPolicy:   netpolicy.NetworkPolicy{AgentObservedIPv4: "127.0.0.1"},
			CredentialEpoch: 1,
			IssuedAt:        time.Now().UTC(),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	recoveryCalled := false
	var stdout, stderr bytes.Buffer
	c := &cli{
		in: strings.NewReader("MONITOR-ROLLBACK-123456\n"), out: &stdout, errOut: &stderr, version: "test",
		pveVersion: func(context.Context) (string, error) { return "9.0.8", nil },
		activateBinding: func(_ context.Context, _ config.Config, expected bindingActivationExpectation) error {
			if expected.BindingID == "" {
				recoveryCalled = true
				return nil
			}
			return errors.New("service did not load binding")
		},
	}
	code := c.run([]string{"--config", filename, "monitoring", "bind", "--endpoint", server.URL + "/internal/v1/monitoring/agents/bind", "--hostname", "pve-test"})
	if code == 0 || !recoveryCalled {
		t.Fatalf("code=%d recoveryCalled=%v", code, recoveryCalled)
	}
	restored, err := config.LoadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Destinations.Monitoring.Enabled != original.Destinations.Monitoring.Enabled || restored.Destinations.MonitoringAudit.Enabled != original.Destinations.MonitoringAudit.Enabled {
		t.Fatalf("monitoring config was not rolled back: %#v", restored.Destinations)
	}
	if _, err := bindstate.LoadMonitoring(restored.Runtime.StateDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("first-time monitoring state remains after rollback: %v", err)
	}
	if !strings.Contains(stderr.String(), "MONITORING_BIND_ACTIVATION_FAILED") || strings.Contains(stderr.String(), "never-print-this-secret") {
		t.Fatalf("unsafe or unclear stderr: %s", stderr.String())
	}
	pendingPath := bindstate.PendingPath(restored.Runtime.StateDirectory, "monitoring")
	if _, err := os.Stat(pendingPath); err != nil {
		t.Fatalf("retry request state was not preserved: %v", err)
	}
}

func TestMonitoringBindRejectsUserSuppliedPVEVersion(t *testing.T) {
	filename := prepareBindConfig(t)
	called := false
	var stdout, stderr bytes.Buffer
	c := &cli{
		in: strings.NewReader("MONITOR-123456\n"), out: &stdout, errOut: &stderr, version: "test",
		pveVersion: func(context.Context) (string, error) { called = true; return "9.0.8", nil },
	}
	code := c.run([]string{"--config", filename, "monitoring", "bind", "--endpoint", "https://moniter.ppflight.com/internal/v1/monitoring/agents/bind", "--pve-version", "9.0.8"})
	if code != 2 || called {
		t.Fatalf("code=%d discoveryCalled=%v stderr=%s", code, called, stderr.String())
	}
}

func TestMonitoringMenuDoesNotPromptForPVEVersionOrCodeBeforeDiscovery(t *testing.T) {
	filename := prepareBindConfig(t)
	var stdout, stderr bytes.Buffer
	c := &cli{
		in:  strings.NewReader("3\nhttps://moniter.ppflight.com/internal/v1/monitoring/agents/bind\nSHOULD-NOT-BE-READ\n"),
		out: &stdout, errOut: &stderr, version: "test",
		pveVersion: func(context.Context) (string, error) { return "", errors.New("not a PVE host") },
	}
	if code := c.run([]string{"--config", filename}); code == 0 {
		t.Fatal("menu accepted failed trusted PVE discovery")
	}
	if strings.Contains(stdout.String(), "PVE 版本") || strings.Contains(stdout.String(), "输入一次性绑定码") {
		t.Fatalf("monitoring menu prompted before discovery: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "PVE_VERSION_DISCOVERY_FAILED") {
		t.Fatalf("missing safe discovery error: %s", stderr.String())
	}
}
