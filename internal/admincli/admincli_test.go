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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/assignment"
	"github.com/ppflight/ppflight-agent/internal/bindingoverlay"
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

func TestResetAssignmentRefreshAuthorityRemovesOnlyExactStateFile(t *testing.T) {
	stateDirectory := t.TempDir()
	stateFile := filepath.Join(stateDirectory, "assignments", "refresh-state.json")
	if err := assignment.SaveState(stateFile, assignment.State{Revision: 7, Cursor: "cursor-7"}); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(stateDirectory, "assignments", "assignments.json")
	if err := os.WriteFile(sentinel, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := resetAssignmentRefreshAuthority(stateDirectory); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stateFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refresh authority still exists or stat failed: %v", err)
	}
	if contents, err := os.ReadFile(sentinel); err != nil || string(contents) != "sentinel" {
		t.Fatalf("unrelated assignment file changed: %q %v", contents, err)
	}
	if err := resetAssignmentRefreshAuthority(stateDirectory); err != nil {
		t.Fatalf("missing refresh authority was not idempotent: %v", err)
	}
}

// allowManagedWriteForTest is the explicit test-only boundary for mutations
// against temporary configs. Production CLI instances keep this nil so Linux
// continues to require the installed configuration and state root.
func allowManagedWriteForTest(string, config.Config) error { return nil }

// allowBindingRuntimeValidationForTest keeps fixture-only credential material
// out of the host environment. Production leaves the validator nil and always
// performs the real disk and environment-overlay readback.
func allowBindingRuntimeValidationForTest(string, config.Config, bindingActivationExpectation) error {
	return nil
}

func runMonitoringBindForTest(args []string, version string, in io.Reader, out, errOut io.Writer) int {
	c := &cli{
		in:      in,
		out:     out,
		errOut:  errOut,
		version: version,
		bindingPVE: func(_ context.Context, _ string, cfg config.Config) (config.Config, error) {
			return cfg, nil
		},
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
		managedWritePolicy:      allowManagedWriteForTest,
		bindingRuntimeValidator: allowBindingRuntimeValidationForTest,
	}
	return c.run(args)
}

func runWebsiteBindForTest(args []string, version string, in io.Reader, out, errOut io.Writer) int {
	c := &cli{
		in: in, out: out, errOut: errOut, version: version,
		bindingPVE: func(_ context.Context, _ string, cfg config.Config) (config.Config, error) {
			return cfg, nil
		},
		pveVersion: func(context.Context) (string, error) { return "9.0.8", nil },
		activateBinding: func(_ context.Context, cfg config.Config, expected bindingActivationExpectation) error {
			if expected.BindingID == "" {
				return nil
			}
			state, err := bindstate.Load(cfg.Runtime.StateDirectory)
			if err != nil {
				return err
			}
			if expected.Domain != "website" || state.BindingID != expected.BindingID || state.CredentialEpoch != expected.CredentialEpoch {
				return errors.New("new website binding was not loaded")
			}
			return nil
		},
		managedWritePolicy:      allowManagedWriteForTest,
		bindingRuntimeValidator: allowBindingRuntimeValidationForTest,
	}
	return c.run(args)
}

// runMutationForTest is the explicit internal test boundary for the Linux
// production write-target gate. Tests must opt in rather than weakening the
// real exported CLI for arbitrary --config paths.
func runMutationForTest(args []string, version string, out, errOut io.Writer) int {
	return (&cli{in: strings.NewReader(""), out: out, errOut: errOut, version: version, managedWritePolicy: allowManagedWriteForTest}).run(args)
}

type readTrackingReader struct{ read bool }

func (r *readTrackingReader) Read([]byte) (int, error) {
	r.read = true
	return 0, io.EOF
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

func TestNoArgumentsShowsUpdateAndUninstallMenu(t *testing.T) {
	var output, stderr bytes.Buffer
	if code := RunWithInput(nil, "test", strings.NewReader("0\n"), &output, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	for _, text := range []string{"1) 初始化/克隆", "2) 官网绑定设置", "3) 监控绑定设置", "4) 系统概况", "5) 一键更新 PPFlight Agent", "6) 完全卸载 PPFlight Agent"} {
		if !strings.Contains(output.String(), text) {
			t.Fatalf("menu does not contain %q: %s", text, output.String())
		}
	}
	for _, removed := range []string{"查看 PPFlight 官网通信状态", "查看监控站通信状态"} {
		if strings.Contains(output.String(), removed) {
			t.Fatalf("old top-level item %q remains: %s", removed, output.String())
		}
	}
}

func TestBindingSettingsSubmenusMoveStatusAndShowContextualActions(t *testing.T) {
	filename := prepareBindConfig(t)
	var output, stderr bytes.Buffer
	instance := &cli{in: strings.NewReader("2\n0\n0\n"), out: &output, errOut: &stderr}
	if code := instance.menu(filename); code != 0 {
		t.Fatalf("unbound website submenu code=%d stderr=%s", code, stderr.String())
	}
	text := output.String()
	for _, expected := range []string{"官网绑定设置", "当前状态：未绑定", "1) 查看绑定与通信状态", "2) 添加绑定", "0) 返回主菜单"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("unbound submenu missing %q: %s", expected, text)
		}
	}
	if strings.Contains(text, "2) 删除绑定") {
		t.Fatalf("unbound submenu exposed delete: %s", text)
	}

	cfg, err := config.LoadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	deviceID, err := bindstate.LoadOrCreateDeviceID(cfg.Runtime.StateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	response := bindingResponse("https://website.example")
	response.DeviceID = deviceID
	if err := bindstate.Save(cfg.Runtime.StateDirectory, bindstate.FromResponse("https://website.example/internal/v1/agents/bind", deviceID, response)); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	stderr.Reset()
	instance.in = strings.NewReader("2\n0\n0\n")
	if code := instance.menu(filename); code != 0 {
		t.Fatalf("bound website submenu code=%d stderr=%s", code, stderr.String())
	}
	text = output.String()
	for _, expected := range []string{"当前状态：已绑定", "2) 删除绑定"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("bound submenu missing %q: %s", expected, text)
		}
	}
	if strings.Contains(text, "重新绑定") || strings.Contains(text, "添加绑定") {
		t.Fatalf("bound submenu exposed a second binding path: %s", text)
	}
}

func TestBindingSettingsExplicitlyDiscardRevokedWebsitePendingWithoutTouchingMonitoring(t *testing.T) {
	filename := prepareBindConfig(t)
	cfg, err := config.LoadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	websiteHash, _ := bindstate.RequestFingerprint(map[string]string{"bindingCode": "website-old-code"})
	_, _, websiteLock, err := bindstate.PreparePending(cfg.Runtime.StateDirectory, "website", websiteHash, pendingTemplateForTest(t, cfg, "website"))
	if err != nil {
		t.Fatal(err)
	}
	_ = websiteLock.Close()
	monitoringHash, _ := bindstate.RequestFingerprint(map[string]string{"bindingCode": "monitoring-pending-code"})
	_, _, monitoringLock, err := bindstate.PreparePending(cfg.Runtime.StateDirectory, "monitoring", monitoringHash, pendingTemplateForTest(t, cfg, "monitoring"))
	if err != nil {
		t.Fatal(err)
	}
	_ = monitoringLock.Close()

	var output, stderr bytes.Buffer
	instance := &cli{
		in:           strings.NewReader("2\n3\ny\n0\n"),
		out:          &output,
		errOut:       &stderr,
		effectiveUID: func() int { return 0 },
		managedWritePolicy: func(string, config.Config) error {
			return nil
		},
	}
	if code := instance.menu(filename); code != 0 {
		t.Fatalf("code=%d stderr=%s output=%s", code, stderr.String(), output.String())
	}
	for _, expected := range []string{
		"存在上一次结果未确定的绑定请求",
		"3) 清除未决绑定请求",
		"PPFlight 官网未决绑定请求已清除",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("output missing %q: %s", expected, output.String())
		}
	}
	if pending, err := bindstate.PendingRequestExists(cfg.Runtime.StateDirectory, "website"); err != nil || pending {
		t.Fatalf("website pending remains: pending=%v err=%v", pending, err)
	}
	if pending, err := bindstate.PendingRequestExists(cfg.Runtime.StateDirectory, "monitoring"); err != nil || !pending {
		t.Fatalf("monitoring pending was changed: pending=%v err=%v", pending, err)
	}
}

func TestSystemOverviewShowsCoreSectionsWithoutSecrets(t *testing.T) {
	filename := prepareBindConfig(t)
	var output, stderr bytes.Buffer
	instance := &cli{in: strings.NewReader("4\n0\n"), out: &output, errOut: &stderr, effectiveUID: func() int { return 0 }}
	if code := instance.menu(filename); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	text := output.String()
	for _, expected := range []string{"PPFlight 系统概况", "[Agent]", "[PVE 本地读取]", "网卡/宿主机采集", "SMART 采集", "[PVE 主机防火墙]", "现有安装更新保持防火墙原状", "[PPFlight 官网]", "[监控站]", "[高可用与升级]", "绑定：未绑定"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("overview missing %q: %s", expected, text)
		}
	}
	if strings.Contains(text, "Secret") || strings.Contains(text, "Bearer") {
		t.Fatalf("overview exposed credential material: %s", text)
	}
}

func TestMenuCompleteUninstallDefaultsToNo(t *testing.T) {
	var output, stderr bytes.Buffer
	called := false
	instance := &cli{
		in: strings.NewReader("6\n\n"), out: &output, errOut: &stderr,
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

func TestMenuOneClickUpdateUsesVerifiedInstalledFlow(t *testing.T) {
	var output, stderr bytes.Buffer
	called := false
	instance := &cli{
		in: strings.NewReader("5\n"), out: &output, errOut: &stderr,
		effectiveUID: func() int { return 0 },
		completeUpdate: func(context.Context) (string, error) {
			called = true
			return "0.1.0-rc.22", nil
		},
	}
	if code := instance.menu("unused"); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !called || !strings.Contains(output.String(), "一键更新完成并已回验：Agent 0.1.0-rc.22") {
		t.Fatalf("called=%v output=%s", called, output.String())
	}
}

func TestOneClickUpdateFailsClosedWithoutVerifiedVersion(t *testing.T) {
	var output, stderr bytes.Buffer
	instance := &cli{out: &output, errOut: &stderr, effectiveUID: func() int { return 0 }, completeUpdate: func(context.Context) (string, error) { return "", nil }}
	if code := instance.update(nil); code == 0 {
		t.Fatal("update without verified version succeeded")
	}
	if strings.Contains(output.String(), "更新完成") || !strings.Contains(stderr.String(), "未报告成功") {
		t.Fatalf("output=%s stderr=%s", output.String(), stderr.String())
	}
}

func TestMenuCompleteUninstallExecutesPurgeAfterYes(t *testing.T) {
	filename := prepareBindConfig(t)
	var output, stderr bytes.Buffer
	called := false
	instance := &cli{
		in: strings.NewReader("6\ny\n"), out: &output, errOut: &stderr,
		effectiveUID:       func() int { return 0 },
		completeUninstall:  func(context.Context) error { called = true; return nil },
		managedWritePolicy: allowManagedWriteForTest,
	}
	if code := instance.menu(filename); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !called || !strings.Contains(output.String(), "已完全卸载") || !strings.Contains(output.String(), "不会删除 PVE 虚拟机") {
		t.Fatalf("complete uninstall contract missing: called=%v output=%s", called, output.String())
	}
}

func TestMenuCompleteUninstallRequiresRoot(t *testing.T) {
	var output, stderr bytes.Buffer
	instance := &cli{in: strings.NewReader("6\ny\n"), out: &output, errOut: &stderr, effectiveUID: func() int { return 1000 }}
	if code := instance.menu("unused"); code == 0 {
		t.Fatal("non-root complete uninstall succeeded")
	}
	if !strings.Contains(stderr.String(), "必须由 PVE root") {
		t.Fatalf("missing root-only error: %s", stderr.String())
	}
}

func TestWebsiteBindingRemovalKeepsMonitoringTrustDomain(t *testing.T) {
	filename := prepareBindConfig(t)
	cfg, websiteState, monitoringState := seedDualBindings(t, filename)
	monitoringBefore := cfg.Destinations.Monitoring
	monitoringAuditBefore := cfg.Destinations.MonitoringAudit
	var output, stderr bytes.Buffer
	activated := false
	instance := &cli{
		in: strings.NewReader("y\n"), out: &output, errOut: &stderr,
		effectiveUID:       func() int { return 0 },
		managedWritePolicy: allowManagedWriteForTest,
		activateBinding: func(_ context.Context, loaded config.Config, expected bindingActivationExpectation) error {
			activated = true
			if expected.Domain != "website" || !expected.Absent || expected.BindingID != "" || expected.CredentialEpoch != 0 {
				return errors.New("unexpected removal expectation")
			}
			if _, err := bindstate.Load(loaded.Runtime.StateDirectory); !errors.Is(err, os.ErrNotExist) {
				return errors.New("website state still present")
			}
			if got, err := bindstate.LoadMonitoring(loaded.Runtime.StateDirectory); err != nil || got.BindingID != monitoringState.BindingID {
				return errors.New("monitoring state changed")
			}
			return nil
		},
	}
	if code := instance.menuRemoveBinding(bufio.NewReader(strings.NewReader("y\n")), filename, false); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !activated {
		t.Fatal("website removal was not activated")
	}
	updated, err := config.LoadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Destinations.WebsiteMetering.Enabled || updated.Destinations.WebsiteTelemetry.Enabled || updated.Assignments.RefreshURL != "" || updated.Control.Enabled || updated.Control.ProductionExecution {
		t.Fatalf("website-derived config remains active: %#v", updated)
	}
	if updated.Destinations.Monitoring != monitoringBefore || updated.Destinations.MonitoringAudit != monitoringAuditBefore {
		t.Fatalf("monitoring config changed: before=%#v/%#v after=%#v/%#v", monitoringBefore, monitoringAuditBefore, updated.Destinations.Monitoring, updated.Destinations.MonitoringAudit)
	}
	if _, err := bindstate.Load(updated.Runtime.StateDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("website state remains: %v", err)
	}
	if got, err := bindstate.LoadMonitoring(updated.Runtime.StateDirectory); err != nil || got.BindingID != monitoringState.BindingID {
		t.Fatalf("monitoring state was not preserved: %#v err=%v", got, err)
	}
	if strings.Contains(output.String(), string(websiteState.HMACCredentials.Commands.Secret)) {
		t.Fatal("website secret leaked during removal")
	}
}

func TestMonitoringBindingRemovalKeepsWebsiteTrustDomain(t *testing.T) {
	filename := prepareBindConfig(t)
	cfg, websiteState, monitoringState := seedDualBindings(t, filename)
	websiteMeteringBefore := cfg.Destinations.WebsiteMetering
	websiteTelemetryBefore := cfg.Destinations.WebsiteTelemetry
	controlBefore := cfg.Control
	var output, stderr bytes.Buffer
	instance := &cli{
		out: &output, errOut: &stderr, effectiveUID: func() int { return 0 },
		managedWritePolicy: allowManagedWriteForTest,
		activateBinding: func(_ context.Context, loaded config.Config, expected bindingActivationExpectation) error {
			if expected.Domain != "monitoring" || !expected.Absent {
				return errors.New("unexpected removal expectation")
			}
			if _, err := bindstate.LoadMonitoring(loaded.Runtime.StateDirectory); !errors.Is(err, os.ErrNotExist) {
				return errors.New("monitoring state still present")
			}
			if got, err := bindstate.Load(loaded.Runtime.StateDirectory); err != nil || got.BindingID != websiteState.BindingID {
				return errors.New("website state changed")
			}
			return nil
		},
	}
	if code := instance.menuRemoveBinding(bufio.NewReader(strings.NewReader("y\n")), filename, true); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	updated, err := config.LoadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Destinations.Monitoring.Enabled || updated.Destinations.MonitoringAudit.Enabled {
		t.Fatalf("monitoring config remains active: %#v", updated.Destinations)
	}
	if updated.Destinations.WebsiteMetering != websiteMeteringBefore || updated.Destinations.WebsiteTelemetry != websiteTelemetryBefore || !reflect.DeepEqual(updated.Control, controlBefore) {
		t.Fatalf("website config changed during monitoring removal")
	}
	if got, err := bindstate.Load(updated.Runtime.StateDirectory); err != nil || got.BindingID != websiteState.BindingID {
		t.Fatalf("website state was not preserved: %#v err=%v", got, err)
	}
	if _, err := bindstate.LoadMonitoring(updated.Runtime.StateDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("monitoring state remains: %v", err)
	}
	if strings.Contains(output.String(), string(monitoringState.HMACCredential.Secret)) {
		t.Fatal("monitoring secret leaked during removal")
	}
}

func TestBindingRemovalRequiresRootExactConfirmationAndRollsBackActivationFailure(t *testing.T) {
	filename := prepareBindConfig(t)
	_, websiteState, _ := seedDualBindings(t, filename)
	var output, stderr bytes.Buffer
	nonRoot := &cli{out: &output, errOut: &stderr, effectiveUID: func() int { return 1000 }}
	if code := nonRoot.menuRemoveBinding(bufio.NewReader(strings.NewReader("y\n")), filename, false); code == 0 {
		t.Fatal("non-root removed binding")
	}
	if _, err := bindstate.Load(filepath.Join(filepath.Dir(filename), "state")); err != nil {
		t.Fatalf("non-root changed state: %v", err)
	}

	output.Reset()
	stderr.Reset()
	wrong := &cli{out: &output, errOut: &stderr, effectiveUID: func() int { return 0 }}
	if code := wrong.menuRemoveBinding(bufio.NewReader(strings.NewReader("\n")), filename, false); code != 0 {
		t.Fatalf("wrong confirmation code=%d", code)
	}
	if _, err := bindstate.Load(filepath.Join(filepath.Dir(filename), "state")); err != nil {
		t.Fatalf("wrong confirmation changed state: %v", err)
	}

	output.Reset()
	stderr.Reset()
	recovered := false
	failing := &cli{
		out: &output, errOut: &stderr, effectiveUID: func() int { return 0 },
		managedWritePolicy: allowManagedWriteForTest,
		activateBinding: func(_ context.Context, _ config.Config, expected bindingActivationExpectation) error {
			if expected.Absent {
				return errors.New("service did not load removal")
			}
			recovered = true
			return nil
		},
	}
	if code := failing.menuRemoveBinding(bufio.NewReader(strings.NewReader("y\n")), filename, false); code == 0 {
		t.Fatal("activation failure reported success")
	}
	if !recovered {
		t.Fatal("old service was not recovered")
	}
	restored, err := bindstate.Load(filepath.Join(filepath.Dir(filename), "state"))
	if err != nil || restored.BindingID != websiteState.BindingID {
		t.Fatalf("website state not restored: %#v err=%v", restored, err)
	}
	restoredConfig, err := config.LoadFile(filename)
	if err != nil || !restoredConfig.Destinations.WebsiteMetering.Enabled || !restoredConfig.Control.Enabled {
		t.Fatalf("website config not restored: %#v err=%v", restoredConfig, err)
	}
	if !strings.Contains(stderr.String(), "WEBSITE_BINDING_REMOVAL_ACTIVATION_FAILED") {
		t.Fatalf("missing safe rollback error: %s", stderr.String())
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
		answer, err := instance.promptYesNo(bufio.NewReader(strings.NewReader(input)), "确认？", true)
		if err != nil || !answer {
			t.Fatalf("input=%q answer=%t err=%v", input, answer, err)
		}
		if !strings.Contains(output.String(), "输入无效") || strings.Count(output.String(), "确认？") != 2 {
			t.Fatalf("invalid input was not rejected and reprompted: %q", output.String())
		}
	}
}

func TestPromptPlanExecutionAcceptsYOrNAndRejectsOtherInput(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      bool
		invalid   bool
		promptCnt int
	}{
		{name: "yes", input: "Y\n", want: true, promptCnt: 1},
		{name: "no", input: "n\n", want: false, promptCnt: 1},
		{name: "empty confirms displayed default", input: "\n", want: true, promptCnt: 1},
		{name: "invalid then yes", input: "YES\ny\n", want: true, invalid: true, promptCnt: 2},
		{name: "control character then no", input: "b\x08\nn\n", want: false, invalid: true, promptCnt: 2},
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
			if !strings.Contains(output.String(), "[y/n]（回车默认：y）") {
				t.Fatalf("plan prompt did not display default y: %q", output.String())
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
	selected, storages, err := instance.chooseTemplateStorage(context.Background(), bufio.NewReader(strings.NewReader("1\n")), []templateStorage{storage}, "image", "选择镜像缓存存储")
	if err != nil || selected != "local" || len(storages) != 1 || !storages[0].RoleEligibility.Image.Allowed {
		t.Fatalf("selected=%q storages=%#v err=%v", selected, storages, err)
	}
	if gotStorage != "local" || gotContent != "backup,iso,snippets,vztmpl" {
		t.Fatalf("pvesm set got storage=%q content=%q", gotStorage, gotContent)
	}
	for _, expected := range []string{"无需人工确认", "当前能力：备份 (backup)", "需要新增：Cloud-Init 配置 (snippets)", "pvesm set local", "--content backup,iso,snippets,vztmpl", "已配置并通过重新检测"} {
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
		in: strings.NewReader("\n1\n1\ny\n1\nvmbr0\ny\nvmbr0\nvmbr1\nn\n"), out: &output, errOut: &stderr, version: "test",
		templateBridges: &fakeTemplateBridgeManager{inspect: []templateBridgeState{safeCreatedBridgeState()}},
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
	code := runMutationForTest([]string{"--config", filename, "monitoring", "set", "--enabled=true", "--url=http://127.0.0.1:18080/api/ingest", "--auth-mode=none", "--payload-format=legacy-ingest-v1"}, "test", &output, &errors)
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

func TestPublicConfigurationMutationsRefusePendingCommitAndTransactionLock(t *testing.T) {
	filename := prepareBindConfig(t)
	cfg, err := config.LoadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := bindstate.RequestFingerprint(map[string]string{"request": "same"})
	if err != nil {
		t.Fatal(err)
	}
	_, _, pendingLock, err := bindstate.PreparePending(cfg.Runtime.StateDirectory, "website", fingerprint, pendingTemplateForTest(t, cfg, "website"))
	if err != nil {
		t.Fatal(err)
	}
	if err := pendingLock.Close(); err != nil {
		t.Fatal(err)
	}

	for _, args := range [][]string{
		{"--config", filename, "monitoring", "set", "--enabled=true", "--url=http://127.0.0.1:18080/api/ingest", "--auth-mode=none", "--payload-format=legacy-ingest-v1"},
		{"--config", filename, "website", "telemetry", "set", "--enabled=true", "--url=http://127.0.0.1:18080/telemetry", "--auth-mode=none", "--payload-format=legacy-ingest-v1"},
		{"--config", filename, "website", "control", "set", "--enabled=false"},
	} {
		var output, stderr bytes.Buffer
		if code := runMutationForTest(args, "test", &output, &stderr); code == 0 {
			t.Fatalf("pending binding allowed mutation args=%v output=%s stderr=%s", args, output.String(), stderr.String())
		}
		after, readErr := os.ReadFile(filename)
		if readErr != nil || !bytes.Equal(before, after) {
			t.Fatalf("pending binding changed config args=%v err=%v", args, readErr)
		}
	}
	if err := bindstate.ClearPending(cfg.Runtime.StateDirectory, "website"); err != nil {
		t.Fatal(err)
	}
	if err := bindstate.BeginMonitoringCommit(cfg.Runtime.StateDirectory, "123e4567-e89b-42d3-a456-426614174001", 1); err != nil {
		t.Fatal(err)
	}
	var output, stderr bytes.Buffer
	if code := runMutationForTest([]string{"--config", filename, "monitoring", "set", "--enabled=true", "--url=http://127.0.0.1:18080/api/ingest", "--auth-mode=none", "--payload-format=legacy-ingest-v1"}, "test", &output, &stderr); code == 0 {
		t.Fatalf("commit marker allowed mutation output=%s stderr=%s", output.String(), stderr.String())
	}
	after, err := os.ReadFile(filename)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("commit marker changed config err=%v", err)
	}
	if err := bindstate.FinishMonitoringCommit(cfg.Runtime.StateDirectory); err != nil {
		t.Fatal(err)
	}

	transaction, err := bindstate.AcquireTransaction(cfg.Runtime.StateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Close()
	output.Reset()
	stderr.Reset()
	if code := runMutationForTest([]string{"--config", filename, "monitoring", "set", "--enabled=true", "--url=http://127.0.0.1:18080/api/ingest", "--auth-mode=none", "--payload-format=legacy-ingest-v1"}, "test", &output, &stderr); code == 0 {
		t.Fatalf("held transaction allowed concurrent mutation output=%s stderr=%s", output.String(), stderr.String())
	}
	after, err = os.ReadFile(filename)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("concurrent mutation changed config err=%v", err)
	}
}

func TestPVEPrepareAndUnbindRefuseButCompleteUninstallPurgesIncompleteBindingTransaction(t *testing.T) {
	filename := prepareBindConfig(t)
	cfg, websiteState, _ := seedDualBindings(t, filename)
	if err := bindstate.BeginMonitoringCommit(cfg.Runtime.StateDirectory, "123e4567-e89b-42d3-a456-426614174001", 1); err != nil {
		t.Fatal(err)
	}

	pveTouched := false
	pveCLI := &cli{
		out: io.Discard, errOut: io.Discard, effectiveUID: func() int { return 0 },
		pveBootstrap:       func(context.Context) error { pveTouched = true; return nil },
		managedWritePolicy: allowManagedWriteForTest,
	}
	if code := pveCLI.pve(filename, []string{"prepare", "--tls-server-name", "pve01.example.test", "--ca-file", managedPVECAFile}); code == 0 || pveTouched {
		t.Fatalf("incomplete binding allowed PVE prepare: code=%d touched=%t", code, pveTouched)
	}

	var output, stderr bytes.Buffer
	unbindCLI := &cli{in: strings.NewReader("y\n"), out: &output, errOut: &stderr, effectiveUID: func() int { return 0 }, managedWritePolicy: allowManagedWriteForTest}
	if code := unbindCLI.menuRemoveBinding(bufio.NewReader(unbindCLI.in), filename, false); code == 0 {
		t.Fatalf("incomplete binding allowed unbind output=%s stderr=%s", output.String(), stderr.String())
	}
	if current, err := bindstate.Load(cfg.Runtime.StateDirectory); err != nil || current.BindingID != websiteState.BindingID {
		t.Fatalf("incomplete binding altered website state: state=%#v err=%v", current, err)
	}

	called := false
	output.Reset()
	stderr.Reset()
	uninstallCLI := &cli{
		out: &output, errOut: &stderr, effectiveUID: func() int { return 0 },
		completeUninstall:  func(context.Context) error { called = true; return nil },
		managedWritePolicy: allowManagedWriteForTest,
	}
	if code := uninstallCLI.menuCompleteUninstallAt(bufio.NewReader(strings.NewReader("y\n")), filename); code != 0 || !called {
		t.Fatalf("confirmed complete uninstall did not purge incomplete binding state: code=%d called=%t output=%s stderr=%s", code, called, output.String(), stderr.String())
	}
}

func TestUnbindRefusesPendingRequestInEitherBindingDomain(t *testing.T) {
	for _, pendingDomain := range []string{"website", "monitoring"} {
		t.Run(pendingDomain, func(t *testing.T) {
			filename := prepareBindConfig(t)
			cfg, websiteState, monitoringState := seedDualBindings(t, filename)
			fingerprint, err := bindstate.RequestFingerprint(map[string]string{"bindingCode": "unresolved-code", "domain": pendingDomain})
			if err != nil {
				t.Fatal(err)
			}
			_, _, lock, err := bindstate.PreparePending(cfg.Runtime.StateDirectory, pendingDomain, fingerprint, pendingTemplateForTest(t, cfg, pendingDomain))
			if err != nil {
				t.Fatal(err)
			}
			if err := lock.Close(); err != nil {
				t.Fatal(err)
			}
			// Delete the other domain: the shared transaction guard must still
			// protect an unresolved request in this one.
			removeMonitoring := pendingDomain == "website"
			confirmation := "y\n"
			if removeMonitoring {
				confirmation = "y\n"
			}
			var output, stderr bytes.Buffer
			instance := &cli{
				in: strings.NewReader(confirmation), out: &output, errOut: &stderr,
				effectiveUID:       func() int { return 0 },
				managedWritePolicy: allowManagedWriteForTest,
				quiesceBinding: func(context.Context) error {
					t.Fatal("pending binding request reached service stop")
					return nil
				},
			}
			if code := instance.menuRemoveBinding(bufio.NewReader(instance.in), filename, removeMonitoring); code == 0 {
				t.Fatalf("pending %s request allowed unbind output=%s stderr=%s", pendingDomain, output.String(), stderr.String())
			}
			if pending, err := bindstate.PendingRequestExists(cfg.Runtime.StateDirectory, pendingDomain); err != nil || !pending {
				t.Fatalf("pending %s request was cleared: pending=%v err=%v", pendingDomain, pending, err)
			}
			if current, err := bindstate.Load(cfg.Runtime.StateDirectory); err != nil || current.BindingID != websiteState.BindingID {
				t.Fatalf("website binding changed while %s pending: state=%#v err=%v", pendingDomain, current, err)
			}
			if current, err := bindstate.LoadMonitoring(cfg.Runtime.StateDirectory); err != nil || current.BindingID != monitoringState.BindingID {
				t.Fatalf("monitoring binding changed while %s pending: state=%#v err=%v", pendingDomain, current, err)
			}
		})
	}
}

func TestSaveMutationRejectsStaleConfigurationSnapshot(t *testing.T) {
	filename := prepareBindConfig(t)
	before, err := config.LoadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	concurrent := before
	concurrent.Identity.Site = "concurrent-change"
	if _, err := atomicUpdate(filename, concurrent); err != nil {
		t.Fatal(err)
	}
	after := before
	after.Destinations.Monitoring.Enabled = true
	var output, stderr bytes.Buffer
	instance := &cli{out: &output, errOut: &stderr}
	if code := instance.saveMutation(filename, before, after); code == 0 {
		t.Fatalf("stale save succeeded output=%s stderr=%s", output.String(), stderr.String())
	}
	current, err := config.LoadFile(filename)
	if err != nil || current.Identity.Site != "concurrent-change" || current.Destinations.Monitoring.Enabled {
		t.Fatalf("stale save overwrote concurrent config: config=%#v err=%v", current, err)
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

func promoteBindConfigToAPI(t *testing.T, filename string) config.Config {
	t.Helper()
	cfg, err := config.LoadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	cfg.PVE.Source = "api"
	cfg.PVE.Endpoint = config.LocalPVEEndpoint
	cfg.PVE.TLSServerName = "pve01.example.test"
	cfg.PVE.CAFile = managedPVECAFile
	cfg.PVE.TokenIDEnv = config.PVEReadTokenIDEnv
	cfg.PVE.TokenSecretEnv = config.PVEReadTokenSecretEnv
	cfg.Control.PVETokenIDEnv = config.PVEControlTokenIDEnv
	cfg.Control.PVETokenSecretEnv = config.PVEControlTokenSecretEnv
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, append(raw, '\n'), 0o640); err != nil {
		t.Fatal(err)
	}
	t.Setenv(config.PVEReadTokenIDEnv, "root@pam!ppflight-read")
	t.Setenv(config.PVEReadTokenSecretEnv, "01234567-89ab-cdef-0123-456789abcdef")
	return cfg
}

func preparePendingBindRequest(t *testing.T, cfg config.Config, domain, endpoint, code string) string {
	t.Helper()
	deviceID, err := bindstate.LoadOrCreateDeviceID(cfg.Runtime.StateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	var request any
	var capabilities []string
	switch domain {
	case "website":
		capabilities = []string{"pve.discovery.v1", "pve.telemetry.v1"}
		request = enrollment.Request{
			SchemaVersion: enrollment.SchemaVersion, BindingCode: code, DeviceID: deviceID, AgentVersion: "test", Hostname: "pve-test",
			NodeClaim: enrollment.NodeClaim{NodeRef: cfg.Identity.NodeRef, PVEVersion: "9.0.8"}, Capabilities: capabilities,
		}
	case "monitoring":
		capabilities = []string{"telemetry-v1", "audit-v1", "delivery-state-v1", "ipv4-only", "mutual-whitelist-v1"}
		request = monitorenrollment.Request{
			SchemaVersion: monitorenrollment.SchemaVersion, BindingCode: code, DeviceID: deviceID, AgentVersion: "test", Hostname: "pve-test",
			NodeClaim: enrollment.NodeClaim{NodeRef: cfg.Identity.NodeRef, PVEVersion: "9.0.8"}, Capabilities: capabilities,
		}
	default:
		t.Fatalf("unsupported pending domain %q", domain)
	}
	fingerprint, err := bindstate.BindingRequestFingerprint(domain, endpoint, request)
	if err != nil {
		t.Fatal(err)
	}
	template, err := bindstate.NewBindingRequestTemplate(domain, endpoint, deviceID, "test", "pve-test", enrollment.NodeClaim{NodeRef: cfg.Identity.NodeRef, PVEVersion: "9.0.8"}, capabilities)
	if err != nil {
		t.Fatal(err)
	}
	requestID, _, lock, err := bindstate.PreparePending(cfg.Runtime.StateDirectory, domain, fingerprint, template)
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	return requestID
}

func pendingTemplateForTest(t *testing.T, cfg config.Config, domain string) bindstate.BindingRequestTemplate {
	t.Helper()
	deviceID, err := bindstate.LoadOrCreateDeviceID(cfg.Runtime.StateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	capabilities := []string{"pve.discovery.v1", "pve.telemetry.v1"}
	if domain == "monitoring" {
		capabilities = []string{"telemetry-v1"}
	}
	template, err := bindstate.NewBindingRequestTemplate(domain, "https://pending.example.test/internal/v1/agents/bind", deviceID, "test", "pve-test", enrollment.NodeClaim{NodeRef: cfg.Identity.NodeRef, PVEVersion: "9.0.8"}, capabilities)
	if err != nil {
		t.Fatal(err)
	}
	return template
}

func prepareFinalizationFixture(t *testing.T, domain string) (string, config.Config, bindingActivationExpectation) {
	t.Helper()
	filename := prepareBindConfig(t)
	cfg, websiteState, monitoringState := seedDualBindings(t, filename)
	expected := bindingActivationExpectation{Domain: domain}
	if domain == "website" {
		if err := bindstate.WriteAssignment(cfg.Assignments.File, websiteState.AssignmentDocument); err != nil {
			t.Fatal(err)
		}
		expected.BindingID, expected.CredentialEpoch = websiteState.BindingID, websiteState.CredentialEpoch
	} else if domain == "monitoring" {
		expected.BindingID, expected.CredentialEpoch = monitoringState.BindingID, monitoringState.CredentialEpoch
	} else {
		t.Fatalf("unsupported finalization domain %q", domain)
	}
	fingerprint, err := bindstate.BindingRequestFingerprint(domain, "https://resume.example.test/internal/v1/agents/bind", map[string]string{"fixture": "pending", "domain": domain})
	if err != nil {
		t.Fatal(err)
	}
	_, _, lock, err := bindstate.PreparePending(cfg.Runtime.StateDirectory, domain, fingerprint, pendingTemplateForTest(t, cfg, domain))
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if domain == "website" {
		err = bindstate.BeginWebsiteCommit(cfg.Runtime.StateDirectory, expected.BindingID, expected.CredentialEpoch)
	} else {
		err = bindstate.BeginMonitoringCommit(cfg.Runtime.StateDirectory, expected.BindingID, expected.CredentialEpoch)
	}
	if err != nil {
		t.Fatal(err)
	}
	return filename, cfg, expected
}

func finalizationMarkerState(t *testing.T, stateDirectory, domain string) bool {
	t.Helper()
	if domain == "website" {
		_, found, err := bindstate.ReadWebsiteCommit(stateDirectory)
		if err != nil {
			t.Fatal(err)
		}
		return found
	}
	_, found, err := bindstate.ReadMonitoringCommit(stateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func finalizeBindingForTest(c *cli, filename string, cfg config.Config, expected bindingActivationExpectation) error {
	if expected.Domain == "website" {
		return c.finalizeWebsiteBindingCommit(filename, cfg, expected)
	}
	return c.finalizeMonitoringBindingCommit(filename, cfg, expected)
}

func seedDualBindings(t *testing.T, filename string) (config.Config, bindstate.State, bindstate.MonitoringState) {
	t.Helper()
	cfg, err := config.LoadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	deviceID, err := bindstate.LoadOrCreateDeviceID(cfg.Runtime.StateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	websiteResponse := bindingResponse("https://website.example")
	websiteResponse.DeviceID = deviceID
	websiteState := bindstate.FromResponse("https://website.example/internal/v1/agents/bind", deviceID, websiteResponse)
	if err := bindstate.Save(cfg.Runtime.StateDirectory, websiteState); err != nil {
		t.Fatal(err)
	}
	applyBinding(&cfg, websiteResponse)

	monitorSecret := enrollment.Secret(base64.StdEncoding.EncodeToString([]byte("monitoring-secret-01")))
	monitorResponse := monitorenrollment.Response{
		SchemaVersion: monitorenrollment.SchemaVersion, BindingID: "123e4567-e89b-42d3-a456-426614174099", DeviceID: deviceID,
		MonitoringAgentRef: "monitor-agent-01", IngestEndpoint: "https://monitor.example/internal/v1/monitoring/telemetry/batches",
		HMACCredential: monitorenrollment.HMACCredential{Algorithm: "hmac-sha256", KeyID: "monitor-key-01", SecretEncoding: "base64", Secret: monitorSecret},
		Telemetry:      monitorenrollment.TelemetryContract{PayloadFormat: "telemetry-v1", Compression: "gzip", MaxCompressedBytes: 8 << 20, MaxUncompressedBytes: 32 << 20},
		NetworkPolicy:  netpolicy.NetworkPolicy{AgentObservedIPv4: "127.0.0.1"}, CredentialEpoch: 4, IssuedAt: time.Now().UTC(),
	}
	monitoringState := bindstate.MonitoringFromResponse("https://monitor.example/internal/v1/monitoring/agents/bind", deviceID, monitorResponse)
	if err := bindstate.SaveMonitoring(cfg.Runtime.StateDirectory, monitoringState); err != nil {
		t.Fatal(err)
	}
	cfg.Destinations.Monitoring.Enabled = true
	cfg.Destinations.Monitoring.URL = monitorResponse.IngestEndpoint
	cfg.Destinations.Monitoring.Auth = config.AuthConfig{Mode: "hmac-sha256", KeyIDEnv: "PPFLIGHT_MONITORING_BINDING_KEY_ID", SecretEnv: "PPFLIGHT_MONITORING_BINDING_SECRET"}
	cfg.Destinations.Monitoring.PayloadFormat = "telemetry-v1"
	cfg.Destinations.Monitoring.Compression = "gzip"
	cfg.Destinations.Monitoring.MaxCompressedBytes = monitorResponse.Telemetry.MaxCompressedBytes
	cfg.Destinations.Monitoring.MaxUncompressedBytes = monitorResponse.Telemetry.MaxUncompressedBytes
	auditEndpoint, err := monitorenrollment.AuditEndpoint(monitorResponse.IngestEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Destinations.MonitoringAudit.Enabled = true
	cfg.Destinations.MonitoringAudit.URL = auditEndpoint
	cfg.Destinations.MonitoringAudit.Auth = config.AuthConfig{Mode: "hmac-sha256", KeyIDEnv: "PPFLIGHT_MONITORING_BINDING_KEY_ID", SecretEnv: "PPFLIGHT_MONITORING_BINDING_SECRET"}
	cfg.Destinations.MonitoringAudit.PayloadFormat = "audit-v1"
	cfg.Destinations.MonitoringAudit.Compression = "gzip"
	cfg.Destinations.MonitoringAudit.MaxCompressedBytes = monitorenrollment.AuditMaxCompressedBytes
	cfg.Destinations.MonitoringAudit.MaxUncompressedBytes = monitorenrollment.AuditMaxUncompressedBytes
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, append(raw, '\n'), 0o640); err != nil {
		t.Fatal(err)
	}
	return cfg, websiteState, monitoringState
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
	code := runWebsiteBindForTest([]string{"--config", filename, "website", "bind", "--endpoint", server.URL + "/v1/bind", "--hostname", "pve-test"}, "1.2.3", strings.NewReader("BINDING-123456\n"), &output, &errors)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errors.String())
	}
	if received.BindingCode != "BINDING-123456" || received.DeviceID == "" {
		t.Fatalf("request=%#v", received)
	}
	if received.NodeClaim.PVEVersion != "9.0.8" {
		t.Fatalf("trusted automatic PVE version=%q", received.NodeClaim.PVEVersion)
	}
	if strings.Contains(strings.Join(received.Capabilities, ","), "pve.control.v1") {
		t.Fatalf("simulator binding claimed unverified control capability: %v", received.Capabilities)
	}
	if strings.Contains(output.String(), "BINDING-123456") || strings.Contains(output.String(), secret) || strings.Contains(errors.String(), secret) {
		t.Fatalf("binding output leaked secret: %q / %q", output.String(), errors.String())
	}
	if strings.Contains(output.String(), "systemctl restart") || strings.Contains(output.String(), "PVE 版本") || !strings.Contains(output.String(), "自动生效") || !strings.Contains(output.String(), "上传与任务轮询已启动") {
		t.Fatalf("website binding did not activate automatically: %s", output.String())
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
	code = runWebsiteBindForTest([]string{"--config", filename, "bind", "--endpoint", server.URL}, "1.2.3", strings.NewReader("BINDING-654321\n"), &output, &errors)
	if code == 0 || requests != 1 {
		t.Fatalf("repeat binding code=%d requests=%d stderr=%s", code, requests, errors.String())
	}
	output.Reset()
	errors.Reset()
	code = runWebsiteBindForTest([]string{"--config", filename, "bind", "--endpoint", server.URL, "--replace"}, "1.2.3", strings.NewReader("BINDING-654321\n"), &output, &errors)
	if code != 0 || requests != 2 {
		t.Fatalf("replace binding code=%d requests=%d stderr=%s", code, requests, errors.String())
	}
}

func TestWebsiteBindResumesDurableCommitBeforeRestartReadiness(t *testing.T) {
	filename := prepareBindConfig(t)
	cfg := promoteBindConfigToAPI(t, filename)
	responseID := "123e4567-e89b-42d3-a456-426614174001"
	var receivedRequestID string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request enrollment.Request
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		receivedRequestID = request.RequestID
		response := bindingResponse(server.URL)
		response.DeviceID = request.DeviceID
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
	deviceID, err := bindstate.LoadOrCreateDeviceID(cfg.Runtime.StateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	request := enrollment.Request{
		SchemaVersion: enrollment.SchemaVersion, BindingCode: "WEBSITE-RESUME-123456", DeviceID: deviceID,
		AgentVersion: "test", Hostname: "pve-test", NodeClaim: enrollment.NodeClaim{NodeRef: cfg.Identity.NodeRef, PVEVersion: "9.0.8"},
		Capabilities: []string{"pve.discovery.v1", "pve.telemetry.v1"},
	}
	fingerprint, err := bindstate.BindingRequestFingerprint("website", server.URL, request)
	if err != nil {
		t.Fatal(err)
	}
	template, err := bindstate.NewBindingRequestTemplate("website", server.URL, deviceID, "test", "pve-test", enrollment.NodeClaim{NodeRef: cfg.Identity.NodeRef, PVEVersion: "9.0.8"}, []string{"pve.discovery.v1", "pve.telemetry.v1"})
	if err != nil {
		t.Fatal(err)
	}
	_, _, lock, err := bindstate.PreparePending(cfg.Runtime.StateDirectory, "website", fingerprint, template)
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	var pending struct {
		RequestID string `json:"requestId"`
	}
	rawPending, err := os.ReadFile(bindstate.PendingPath(cfg.Runtime.StateDirectory, "website"))
	if err != nil || json.Unmarshal(rawPending, &pending) != nil || pending.RequestID == "" {
		t.Fatalf("read durable website pending request: %v", err)
	}
	if err := bindstate.BeginWebsiteCommit(cfg.Runtime.StateDirectory, responseID, 1); err != nil {
		t.Fatal(err)
	}
	var output, stderr bytes.Buffer
	code := runWebsiteBindForTest([]string{"--config", filename, "website", "bind", "--endpoint", server.URL, "--hostname", "pve-test"}, "test", strings.NewReader("WEBSITE-RESUME-123456\n"), &output, &stderr)
	if code != 0 {
		t.Fatalf("resume code=%d stderr=%s", code, stderr.String())
	}
	if receivedRequestID != pending.RequestID {
		t.Fatalf("website recovery changed durable request ID: got=%q want=%q", receivedRequestID, pending.RequestID)
	}
	if marker, found, err := bindstate.ReadWebsiteCommit(cfg.Runtime.StateDirectory); err != nil || found {
		t.Fatalf("website marker remained after resume: marker=%#v found=%v err=%v", marker, found, err)
	}
	state, err := bindstate.Load(cfg.Runtime.StateDirectory)
	if err != nil || state.BindingID != responseID || state.CredentialEpoch != 1 {
		t.Fatalf("resumed website state=%#v err=%v", state, err)
	}
}

func TestMonitoringBindResumesDurableCommitBeforeRestartReadiness(t *testing.T) {
	filename := prepareBindConfig(t)
	cfg := promoteBindConfigToAPI(t, filename)
	responseID := "123e4567-e89b-42d3-a456-426614174004"
	var receivedRequestID string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request monitorenrollment.Request
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		receivedRequestID = request.RequestID
		response := monitorenrollment.Response{
			SchemaVersion: 1, BindingID: responseID, DeviceID: request.DeviceID, MonitoringAgentRef: "monitor-agent-resume",
			IngestEndpoint: server.URL + monitorenrollment.TelemetryPath,
			HMACCredential: monitorenrollment.HMACCredential{Algorithm: "hmac-sha256", KeyID: "monitor-key-resume", SecretEncoding: "base64", Secret: enrollment.Secret(base64.StdEncoding.EncodeToString([]byte("monitoring-secret-resume")))},
			Telemetry:      monitorenrollment.TelemetryContract{PayloadFormat: "telemetry-v1", Compression: "gzip", MaxCompressedBytes: 8 << 20, MaxUncompressedBytes: 32 << 20},
			NetworkPolicy:  netpolicy.NetworkPolicy{AgentObservedIPv4: "127.0.0.1"}, CredentialEpoch: 1, IssuedAt: time.Now().UTC(),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
	deviceID, err := bindstate.LoadOrCreateDeviceID(cfg.Runtime.StateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	request := monitorenrollment.Request{
		SchemaVersion: monitorenrollment.SchemaVersion, BindingCode: "MONITOR-RESUME-123456", DeviceID: deviceID,
		AgentVersion: "test", Hostname: "pve-test", NodeClaim: enrollment.NodeClaim{NodeRef: cfg.Identity.NodeRef, PVEVersion: "9.0.8"},
		Capabilities: []string{"telemetry-v1", "audit-v1", "delivery-state-v1", "ipv4-only", "mutual-whitelist-v1"},
	}
	fingerprint, err := bindstate.BindingRequestFingerprint("monitoring", server.URL, request)
	if err != nil {
		t.Fatal(err)
	}
	template, err := bindstate.NewBindingRequestTemplate("monitoring", server.URL, deviceID, "test", "pve-test", enrollment.NodeClaim{NodeRef: cfg.Identity.NodeRef, PVEVersion: "9.0.8"}, []string{"telemetry-v1", "audit-v1", "delivery-state-v1", "ipv4-only", "mutual-whitelist-v1"})
	if err != nil {
		t.Fatal(err)
	}
	_, _, lock, err := bindstate.PreparePending(cfg.Runtime.StateDirectory, "monitoring", fingerprint, template)
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	var pending struct {
		RequestID string `json:"requestId"`
	}
	rawPending, err := os.ReadFile(bindstate.PendingPath(cfg.Runtime.StateDirectory, "monitoring"))
	if err != nil || json.Unmarshal(rawPending, &pending) != nil || pending.RequestID == "" {
		t.Fatalf("read durable monitoring pending request: %v", err)
	}
	if err := bindstate.BeginMonitoringCommit(cfg.Runtime.StateDirectory, responseID, 1); err != nil {
		t.Fatal(err)
	}
	var output, stderr bytes.Buffer
	code := runMonitoringBindForTest([]string{"--config", filename, "monitoring", "bind", "--endpoint", server.URL, "--hostname", "pve-test"}, "test", strings.NewReader("MONITOR-RESUME-123456\n"), &output, &stderr)
	if code != 0 {
		t.Fatalf("resume code=%d stderr=%s", code, stderr.String())
	}
	if receivedRequestID != pending.RequestID {
		t.Fatalf("monitoring recovery changed durable request ID: got=%q want=%q", receivedRequestID, pending.RequestID)
	}
	if marker, found, err := bindstate.ReadMonitoringCommit(cfg.Runtime.StateDirectory); err != nil || found {
		t.Fatalf("monitoring marker remained after resume: marker=%#v found=%v err=%v", marker, found, err)
	}
	state, err := bindstate.LoadMonitoring(cfg.Runtime.StateDirectory)
	if err != nil || state.BindingID != responseID || state.CredentialEpoch != 1 {
		t.Fatalf("resumed monitoring state=%#v err=%v", state, err)
	}
}

func TestWebsiteBindActivationFailurePreservesServerIssuedState(t *testing.T) {
	filename := prepareBindConfig(t)
	originalConfig, originalWebsite, originalMonitoring := seedDualBindings(t, filename)
	if err := bindstate.WriteAssignment(originalConfig.Assignments.File, originalWebsite.AssignmentDocument); err != nil {
		t.Fatal(err)
	}
	refreshStatePath := filepath.Join(originalConfig.Runtime.StateDirectory, "assignments", "refresh-state.json")
	if err := assignment.SaveState(refreshStatePath, assignment.State{Revision: 19, Cursor: "old-binding-cursor"}); err != nil {
		t.Fatal(err)
	}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request enrollment.Request
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		response := bindingResponse(server.URL)
		response.BindingID = "123e4567-e89b-42d3-a456-426614174077"
		response.DeviceID = request.DeviceID
		response.CredentialEpoch = originalWebsite.CredentialEpoch + 1
		response.AssignmentDocument = json.RawMessage(`{"schemaVersion":1,"revision":"rev-new","issuedAt":"2026-08-30T00:01:00Z","assignments":[]}`)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	recoveryCalled := false
	var stdout, stderr bytes.Buffer
	c := &cli{
		in: strings.NewReader("WEBSITE-ROLLBACK-123456\n"), out: &stdout, errOut: &stderr, version: "test",
		managedWritePolicy:      allowManagedWriteForTest,
		bindingRuntimeValidator: allowBindingRuntimeValidationForTest,
		bindingPVE:              func(_ context.Context, _ string, cfg config.Config) (config.Config, error) { return cfg, nil },
		pveVersion:              func(context.Context) (string, error) { return "9.0.8", nil },
		activateBinding: func(_ context.Context, _ config.Config, expected bindingActivationExpectation) error {
			if expected.BindingID == "" {
				recoveryCalled = true
				return nil
			}
			return errors.New("service did not load website binding")
		},
	}
	code := c.run([]string{"--config", filename, "website", "bind", "--endpoint", server.URL + "/internal/v1/agents/bind", "--hostname", "pve-test", "--replace"})
	if code == 0 || recoveryCalled || !strings.Contains(stderr.String(), "WEBSITE_BIND_ACTIVATION_FAILED") {
		t.Fatalf("code=%d recovery=%v stderr=%s", code, recoveryCalled, stderr.String())
	}
	committedConfig, err := config.LoadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(committedConfig, originalConfig) {
		t.Fatal("server-issued website config was incorrectly rolled back")
	}
	committedWebsite, err := bindstate.Load(originalConfig.Runtime.StateDirectory)
	if err != nil || committedWebsite.BindingID != "123e4567-e89b-42d3-a456-426614174077" || committedWebsite.CredentialEpoch != originalWebsite.CredentialEpoch+1 {
		t.Fatalf("website state=%#v err=%v", committedWebsite, err)
	}
	restoredMonitoring, err := bindstate.LoadMonitoring(originalConfig.Runtime.StateDirectory)
	if err != nil || restoredMonitoring.BindingID != originalMonitoring.BindingID || restoredMonitoring.CredentialEpoch != originalMonitoring.CredentialEpoch {
		t.Fatalf("monitoring state changed: %#v err=%v", restoredMonitoring, err)
	}
	assignment, err := os.ReadFile(originalConfig.Assignments.File)
	if err != nil {
		t.Fatal(err)
	}
	wantAssignment, _ := compactJSON(json.RawMessage(`{"schemaVersion":1,"revision":"rev-new","issuedAt":"2026-08-30T00:01:00Z","assignments":[]}`))
	gotAssignment, _ := compactJSON(assignment)
	if !bytes.Equal(gotAssignment, wantAssignment) {
		t.Fatalf("new assignment was not preserved: %s", assignment)
	}
	if _, err := os.Stat(refreshStatePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old binding refresh authority survived replacement: %v", err)
	}
	if _, err := os.Stat(bindstate.PendingPath(originalConfig.Runtime.StateDirectory, "website")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed server-issued binding kept stale pending state: %v", err)
	}
	if pending, err := bindstate.WebsiteCommitPending(originalConfig.Runtime.StateDirectory); err != nil || pending {
		t.Fatalf("website commit marker survived complete durable commit: pending=%v err=%v", pending, err)
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
	if code := runWebsiteBindForTest([]string{"--config", filename, "bind", "--endpoint", "https://service.example", "BINDING-123456"}, "1.2.3", strings.NewReader(""), &output, &errors); code != 2 {
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
	if code := runWebsiteBindForTest([]string{"--config", filename, "bind", "--endpoint", "https://service.example", "--code-file", link}, "1.2.3", strings.NewReader(""), &output, &errors); code == 0 {
		t.Fatal("symlink code file was accepted")
	}
}

func TestMalformedBindingCodesDoNotPreparePersistQuiesceOrSend(t *testing.T) {
	for _, domain := range []string{"website", "monitoring"} {
		t.Run(domain, func(t *testing.T) {
			filename := prepareBindConfig(t)
			cfg, err := config.LoadFile(filename)
			if err != nil {
				t.Fatal(err)
			}
			requests, quiesces := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				requests++
			}))
			defer server.Close()
			var output, stderr bytes.Buffer
			instance := &cli{
				in: strings.NewReader("b^H\n"), out: &output, errOut: &stderr, version: "test",
				managedWritePolicy: allowManagedWriteForTest,
				bindingPVE:         func(_ context.Context, _ string, value config.Config) (config.Config, error) { return value, nil },
				pveVersion:         func(context.Context) (string, error) { return "9.0.8", nil },
				quiesceBinding: func(context.Context) error {
					quiesces++
					return nil
				},
			}
			args := []string{"--config", filename, "website", "bind", "--endpoint", server.URL, "--hostname", "pve-test"}
			if domain == "monitoring" {
				args = []string{"--config", filename, "monitoring", "bind", "--endpoint", server.URL, "--hostname", "pve-test"}
			}
			if code := instance.run(args); code != 2 {
				t.Fatalf("malformed %s code result=%d output=%s stderr=%s", domain, code, output.String(), stderr.String())
			}
			if quiesces != 0 || requests != 0 {
				t.Fatalf("malformed %s code crossed unsafe lifecycle boundary: quiesces=%d requests=%d", domain, quiesces, requests)
			}
			if pending, err := bindstate.PendingRequestExists(cfg.Runtime.StateDirectory, domain); err != nil || pending {
				t.Fatalf("malformed %s code wrote pending state: pending=%v err=%v", domain, pending, err)
			}
			if strings.Contains(output.String()+stderr.String(), "b^H") {
				t.Fatalf("malformed %s code leaked in output", domain)
			}
		})
	}
}

func TestAmbiguousBindingCannotReuseRequestIDAtDifferentEndpoint(t *testing.T) {
	for _, domain := range []string{"website", "monitoring"} {
		t.Run(domain, func(t *testing.T) {
			filename := prepareBindConfig(t)
			cfg, err := config.LoadFile(filename)
			if err != nil {
				t.Fatal(err)
			}
			firstRequests, changedEndpointRequests, quiesces := 0, 0, 0
			first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				firstRequests++
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer first.Close()
			changed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				changedEndpointRequests++
			}))
			defer changed.Close()
			codeValue := "PPF.WEBSITE-AMBIGUOUS-123456"
			if domain == "monitoring" {
				codeValue = "PPF.MONITOR-AMBIGUOUS-123456"
			}
			var output, stderr bytes.Buffer
			instance := &cli{
				out: &output, errOut: &stderr, version: "test",
				managedWritePolicy: allowManagedWriteForTest,
				bindingPVE:         func(_ context.Context, _ string, value config.Config) (config.Config, error) { return value, nil },
				pveVersion:         func(context.Context) (string, error) { return "9.0.8", nil },
				quiesceBinding: func(context.Context) error {
					quiesces++
					return nil
				},
			}
			argsFor := func(endpoint string) []string {
				if domain == "monitoring" {
					return []string{"--config", filename, "monitoring", "bind", "--endpoint", endpoint, "--hostname", "pve-test"}
				}
				return []string{"--config", filename, "website", "bind", "--endpoint", endpoint, "--hostname", "pve-test"}
			}
			instance.in = strings.NewReader(codeValue + "\n")
			if got := instance.run(argsFor(first.URL)); got != 1 || firstRequests != 1 || quiesces != 1 {
				t.Fatalf("first %s ambiguous bind got=%d firstRequests=%d quiesces=%d stderr=%s", domain, got, firstRequests, quiesces, stderr.String())
			}
			output.Reset()
			stderr.Reset()
			instance.in = strings.NewReader(codeValue + "\n")
			if got := instance.run(argsFor(changed.URL)); got == 0 {
				t.Fatalf("changed %s endpoint unexpectedly resumed binding", domain)
			}
			if changedEndpointRequests != 0 || quiesces != 1 {
				t.Fatalf("changed %s endpoint reached unsafe boundary: requests=%d quiesces=%d stderr=%s", domain, changedEndpointRequests, quiesces, stderr.String())
			}
			if pending, err := bindstate.PendingRequestExists(cfg.Runtime.StateDirectory, domain); err != nil || !pending {
				t.Fatalf("changed %s endpoint removed pending intent: pending=%v err=%v", domain, pending, err)
			}
		})
	}
}

func TestBindingFinalizeFailureWindowsRemainRecoverable(t *testing.T) {
	for _, domain := range []string{"website", "monitoring"} {
		domain := domain
		t.Run(domain, func(t *testing.T) {
			t.Run("clear-pending-failure-keeps-both-markers", func(t *testing.T) {
				filename, cfg, expected := prepareFinalizationFixture(t, domain)
				arms := 0
				instance := &cli{
					managedWritePolicy: allowManagedWriteForTest,
					armBinding: func(context.Context) error {
						arms++
						return nil
					},
					clearBindingPending: func(string, string) error {
						return errors.New("injected pending clear failure")
					},
				}
				if err := finalizeBindingForTest(instance, filename, cfg, expected); err == nil {
					t.Fatal("finalization unexpectedly succeeded after injected pending clear failure")
				}
				if arms != 1 {
					t.Fatalf("activation arm calls=%d want=1", arms)
				}
				if !finalizationMarkerState(t, cfg.Runtime.StateDirectory, domain) {
					t.Fatal("commit marker was removed after pending clear failure")
				}
				if pending, err := bindstate.PendingRequestExists(cfg.Runtime.StateDirectory, domain); err != nil || !pending {
					t.Fatalf("pending retry intent was lost: pending=%v err=%v", pending, err)
				}
			})

			t.Run("finish-marker-failure-recovers-locally-without-code-or-http", func(t *testing.T) {
				filename, cfg, expected := prepareFinalizationFixture(t, domain)
				arms := 0
				instance := &cli{
					managedWritePolicy:      allowManagedWriteForTest,
					bindingRuntimeValidator: allowBindingRuntimeValidationForTest,
					armBinding: func(context.Context) error {
						arms++
						return nil
					},
					finishBindingCommit: func(string, string) error {
						return errors.New("injected commit marker finish failure")
					},
				}
				if err := finalizeBindingForTest(instance, filename, cfg, expected); err == nil {
					t.Fatal("finalization unexpectedly succeeded after injected marker finish failure")
				}
				if arms != 1 {
					t.Fatalf("activation arm calls=%d want=1", arms)
				}
				if !finalizationMarkerState(t, cfg.Runtime.StateDirectory, domain) {
					t.Fatal("commit marker was removed after injected marker finish failure")
				}
				if pending, err := bindstate.PendingRequestExists(cfg.Runtime.StateDirectory, domain); err != nil || pending {
					t.Fatalf("pending intent remained after its successful clear: pending=%v err=%v", pending, err)
				}

				requests, activations := 0, 0
				resumeServer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					requests++
				}))
				defer resumeServer.Close()
				input := &readTrackingReader{}
				var output, stderr bytes.Buffer
				instance.in, instance.out, instance.errOut = input, &output, &stderr
				instance.bindingPVE = func(context.Context, string, config.Config) (config.Config, error) {
					t.Fatal("marker-only recovery attempted PVE preparation")
					return config.Config{}, errors.New("unexpected PVE preparation")
				}
				instance.finishBindingCommit = nil
				instance.activateBinding = func(_ context.Context, got config.Config, received bindingActivationExpectation) error {
					if received != expected || got.Runtime.StateDirectory != cfg.Runtime.StateDirectory {
						return errors.New("marker-only recovery activated an unexpected binding")
					}
					activations++
					return nil
				}
				args := []string{"--config", filename, "website", "bind", "--endpoint", resumeServer.URL}
				if domain == "monitoring" {
					args = []string{"--config", filename, "monitoring", "bind", "--endpoint", resumeServer.URL}
				}
				if code := instance.run(args); code != 0 {
					t.Fatalf("marker-only %s recovery code=%d stderr=%s", domain, code, stderr.String())
				}
				if input.read || requests != 0 || activations != 1 || arms != 2 {
					t.Fatalf("marker-only %s recovery crossed an unsafe boundary: input=%v requests=%d activations=%d arms=%d", domain, input.read, requests, activations, arms)
				}
				if finalizationMarkerState(t, cfg.Runtime.StateDirectory, domain) {
					t.Fatal("marker-only recovery did not finish the durable commit")
				}
				if pending, err := bindstate.PendingRequestExists(cfg.Runtime.StateDirectory, domain); err != nil || pending {
					t.Fatalf("marker-only recovery left a pending request: pending=%v err=%v", pending, err)
				}
			})
		})
	}
}

func TestPendingOnlyBindingRetryReusesRequestIDAndCompletes(t *testing.T) {
	for _, domain := range []string{"website", "monitoring"} {
		domain := domain
		t.Run(domain, func(t *testing.T) {
			filename := prepareBindConfig(t)
			_ = promoteBindConfigToAPI(t, filename)
			var requestIDs []string
			attempts, quiesces, arms, activations := 0, 0, 0, 0
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts++
				if domain == "website" {
					var request enrollment.Request
					if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
						t.Error(err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					requestIDs = append(requestIDs, request.RequestID)
					if attempts == 1 {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					response := bindingResponse(server.URL)
					response.DeviceID = request.DeviceID
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(response)
					return
				}
				var request monitorenrollment.Request
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				requestIDs = append(requestIDs, request.RequestID)
				if attempts == 1 {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				response := monitorenrollment.Response{
					SchemaVersion: monitorenrollment.SchemaVersion, BindingID: "123e4567-e89b-42d3-a456-426614174099", DeviceID: request.DeviceID,
					MonitoringAgentRef: "monitor-agent-replay", IngestEndpoint: server.URL + monitorenrollment.TelemetryPath,
					HMACCredential: monitorenrollment.HMACCredential{Algorithm: "hmac-sha256", KeyID: "monitor-key-replay", SecretEncoding: "base64", Secret: enrollment.Secret(base64.StdEncoding.EncodeToString([]byte("monitoring-secret-replay")))},
					Telemetry:      monitorenrollment.TelemetryContract{PayloadFormat: "telemetry-v1", Compression: "gzip", MaxCompressedBytes: 8 << 20, MaxUncompressedBytes: 32 << 20},
					NetworkPolicy:  netpolicy.NetworkPolicy{AgentObservedIPv4: "127.0.0.1"}, CredentialEpoch: 1, IssuedAt: time.Now().UTC(),
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()

			codeValue := "PPF.WEBSITE-REPLAY-123456"
			if domain == "monitoring" {
				codeValue = "PPF.MONITOR-REPLAY-123456"
			}
			var output, stderr bytes.Buffer
			instance := &cli{
				out: &output, errOut: &stderr, version: "test", effectiveUID: func() int { return 1000 },
				bindingRuntimeValidator: allowBindingRuntimeValidationForTest,
				bindingPVE:              func(_ context.Context, _ string, value config.Config) (config.Config, error) { return value, nil },
				pveVersion:              func(context.Context) (string, error) { return "9.0.8", nil },
				quiesceBinding: func(context.Context) error {
					quiesces++
					return nil
				},
				armBinding: func(context.Context) error {
					arms++
					return nil
				},
				activateBinding: func(_ context.Context, value config.Config, expected bindingActivationExpectation) error {
					if expected.Domain != domain || expected.BindingID == "" || expected.CredentialEpoch == 0 || value.Runtime.StateDirectory == "" {
						return errors.New("retry activation expectation is invalid")
					}
					activations++
					return nil
				},
			}
			args := []string{"--config", filename, "website", "bind", "--endpoint", server.URL, "--hostname", "pve-test"}
			if domain == "monitoring" {
				args = []string{"--config", filename, "monitoring", "bind", "--endpoint", server.URL, "--hostname", "pve-test"}
			}
			instance.in = strings.NewReader(codeValue + "\n")
			if code := instance.run(args); code != 1 {
				t.Fatalf("first %s ambiguous bind code=%d stderr=%s", domain, code, stderr.String())
			}
			stateDirectory, err := config.LoadFile(filename)
			if err != nil {
				t.Fatal(err)
			}
			if pending, err := bindstate.PendingRequestExists(stateDirectory.Runtime.StateDirectory, domain); err != nil || !pending {
				t.Fatalf("first %s retry intent missing: pending=%v err=%v", domain, pending, err)
			}
			output.Reset()
			stderr.Reset()
			instance.in = strings.NewReader(codeValue + "\n")
			if code := instance.run(args); code != 0 {
				t.Fatalf("same %s retry code=%d stderr=%s", domain, code, stderr.String())
			}
			if attempts != 2 || len(requestIDs) != 2 || requestIDs[0] == "" || requestIDs[0] != requestIDs[1] {
				t.Fatalf("same %s retry did not reuse durable request ID: attempts=%d ids=%v", domain, attempts, requestIDs)
			}
			if quiesces != 2 || arms != 1 || activations != 1 {
				t.Fatalf("same %s retry lifecycle unexpected: quiesces=%d arms=%d activations=%d", domain, quiesces, arms, activations)
			}
			if pending, err := bindstate.PendingRequestExists(stateDirectory.Runtime.StateDirectory, domain); err != nil || pending {
				t.Fatalf("completed %s retry retained pending request: pending=%v err=%v", domain, pending, err)
			}
			if finalizationMarkerState(t, stateDirectory.Runtime.StateDirectory, domain) {
				t.Fatalf("completed %s retry retained commit marker", domain)
			}
		})
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

func TestMonitoringBindActivationFailurePreservesServerIssuedState(t *testing.T) {
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
		managedWritePolicy:      allowManagedWriteForTest,
		bindingRuntimeValidator: allowBindingRuntimeValidationForTest,
		pveVersion:              func(context.Context) (string, error) { return "9.0.8", nil },
		bindingPVE:              func(_ context.Context, _ string, cfg config.Config) (config.Config, error) { return cfg, nil },
		activateBinding: func(_ context.Context, _ config.Config, expected bindingActivationExpectation) error {
			if expected.BindingID == "" {
				recoveryCalled = true
				return nil
			}
			return errors.New("service did not load binding")
		},
	}
	code := c.run([]string{"--config", filename, "monitoring", "bind", "--endpoint", server.URL + "/internal/v1/monitoring/agents/bind", "--hostname", "pve-test"})
	if code == 0 || recoveryCalled {
		t.Fatalf("code=%d recoveryCalled=%v", code, recoveryCalled)
	}
	committed, err := config.LoadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if !committed.Destinations.Monitoring.Enabled || !committed.Destinations.MonitoringAudit.Enabled || original.Destinations.Monitoring.Enabled {
		t.Fatalf("server-issued monitoring config was not preserved: %#v", committed.Destinations)
	}
	state, err := bindstate.LoadMonitoring(committed.Runtime.StateDirectory)
	if err != nil || state.BindingID != "123e4567-e89b-42d3-a456-426614174004" || state.CredentialEpoch != 1 {
		t.Fatalf("server-issued monitoring state missing: state=%#v err=%v", state, err)
	}
	if !strings.Contains(stderr.String(), "MONITORING_BIND_ACTIVATION_FAILED") || strings.Contains(stderr.String(), "never-print-this-secret") {
		t.Fatalf("unsafe or unclear stderr: %s", stderr.String())
	}
	pendingPath := bindstate.PendingPath(committed.Runtime.StateDirectory, "monitoring")
	if _, err := os.Stat(pendingPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed server-issued binding kept stale pending state: %v", err)
	}
}

func TestWebsiteActiveBindingRejectionClearsPendingAndRestoresPreviousService(t *testing.T) {
	filename := prepareBindConfig(t)
	cfg, websiteState, monitoringState := seedDualBindings(t, filename)
	quiesced, recovered := false, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !quiesced {
			t.Error("binding request reached the server before the Agent was quiesced")
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":{"code":"binding_already_active","message":"server detail must not be printed"}}`))
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	instance := &cli{
		in: strings.NewReader("ACTIVE-BINDING-REJECT-123456\n"), out: &stdout, errOut: &stderr, version: "test",
		managedWritePolicy: allowManagedWriteForTest,
		bindingPVE:         func(_ context.Context, _ string, value config.Config) (config.Config, error) { return value, nil },
		pveVersion:         func(context.Context) (string, error) { return "9.0.8", nil },
		quiesceBinding: func(context.Context) error {
			quiesced = true
			return nil
		},
		activateBinding: func(_ context.Context, loaded config.Config, expected bindingActivationExpectation) error {
			if expected.BindingID != "" {
				return errors.New("a rejected request must not activate a new binding")
			}
			secrets, err := bindingoverlay.Resolve(loaded, func(string) (string, bool) { return "", false })
			if err != nil {
				return err
			}
			if secrets.MonitoringBindingID != monitoringState.BindingID || secrets.Monitoring.CredentialEpoch != monitoringState.CredentialEpoch {
				return errors.New("website rejection changed monitoring binding")
			}
			recovered++
			return nil
		},
	}
	code := instance.run([]string{"--config", filename, "website", "bind", "--endpoint", server.URL, "--hostname", "pve-test", "--replace"})
	if code != 1 || !quiesced || recovered != 1 {
		t.Fatalf("code=%d quiesced=%v recovered=%d stderr=%s", code, quiesced, recovered, stderr.String())
	}
	if _, err := os.Stat(bindstate.PendingPath(cfg.Runtime.StateDirectory, "website")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("definitive rejection kept pending intent: %v", err)
	}
	websiteCurrent, err := bindstate.Load(cfg.Runtime.StateDirectory)
	if err != nil || websiteCurrent.BindingID != websiteState.BindingID || websiteCurrent.CredentialEpoch != websiteState.CredentialEpoch {
		t.Fatalf("old website state changed: %#v err=%v", websiteCurrent, err)
	}
	monitoringCurrent, err := bindstate.LoadMonitoring(cfg.Runtime.StateDirectory)
	if err != nil || monitoringCurrent.BindingID != monitoringState.BindingID || monitoringCurrent.CredentialEpoch != monitoringState.CredentialEpoch {
		t.Fatalf("monitoring state changed: %#v err=%v", monitoringCurrent, err)
	}
	if !strings.Contains(stderr.String(), "仍有未归档的有效绑定") || !strings.Contains(stderr.String(), "绑定码未消费") || strings.Contains(stderr.String(), "server detail") {
		t.Fatalf("unsafe or unclear rejection message: %s", stderr.String())
	}
}

func TestBindingFourXXNeverClearsIntentAndRestoresPreviousService(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{name: "proxy-html-400", status: http.StatusBadRequest, body: "<html><title>proxy error</title></html>"},
		{name: "malformed-json-401", status: http.StatusUnauthorized, body: `{"error":`},
		{name: "claimed-service-code-403", status: http.StatusForbidden, body: `{"error":{"code":"BINDING_REJECTED","message":"not authoritative"}}`},
	}
	for _, domain := range []string{"website", "monitoring"} {
		for _, responseCase := range cases {
			responseCase := responseCase
			t.Run(fmt.Sprintf("%s-%s", domain, responseCase.name), func(t *testing.T) {
				filename := prepareBindConfig(t)
				cfg, websiteState, monitoringState := seedDualBindings(t, filename)
				quiesced, recovered := false, 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					if !quiesced {
						t.Error("binding request reached the server before the Agent was quiesced")
					}
					w.Header().Set("Content-Type", "text/html")
					w.WriteHeader(responseCase.status)
					_, _ = w.Write([]byte(responseCase.body))
				}))
				defer server.Close()
				var stdout, stderr bytes.Buffer
				instance := &cli{
					in: strings.NewReader("DEFINITE-REJECT-123456\n"), out: &stdout, errOut: &stderr, version: "test",
					managedWritePolicy: allowManagedWriteForTest,
					bindingPVE:         func(_ context.Context, _ string, value config.Config) (config.Config, error) { return value, nil },
					pveVersion:         func(context.Context) (string, error) { return "9.0.8", nil },
					quiesceBinding: func(context.Context) error {
						quiesced = true
						return nil
					},
					activateBinding: func(_ context.Context, loaded config.Config, expected bindingActivationExpectation) error {
						if expected.BindingID != "" {
							return errors.New("a rejected request must not activate a new binding")
						}
						// A pending retry in one trust domain must not make the last
						// complete credentials of either domain unavailable. This is
						// the runtime condition that keeps a bad website code from
						// taking monitoring offline (and vice versa).
						secrets, err := bindingoverlay.Resolve(loaded, func(string) (string, bool) { return "", false })
						if err != nil {
							return fmt.Errorf("old binding overlay did not recover: %w", err)
						}
						if domain == "website" && (secrets.MonitoringBindingID != monitoringState.BindingID || secrets.Monitoring.CredentialEpoch != monitoringState.CredentialEpoch) {
							return errors.New("website rejection made monitoring binding unavailable")
						}
						if domain == "monitoring" && (secrets.WebsiteBindingID != websiteState.BindingID || secrets.WebsiteCredentialEpoch != websiteState.CredentialEpoch) {
							return errors.New("monitoring rejection made website binding unavailable")
						}
						recovered++
						return nil
					},
				}
				args := []string{"--config", filename, "website", "bind", "--endpoint", server.URL, "--hostname", "pve-test", "--replace"}
				if domain == "monitoring" {
					args = []string{"--config", filename, "monitoring", "bind", "--endpoint", server.URL, "--hostname", "pve-test", "--replace"}
				}
				if code := instance.run(args); code != 1 || !quiesced || recovered != 1 {
					t.Fatalf("code=%d quiesced=%v recovered=%d stderr=%s", code, quiesced, recovered, stderr.String())
				}
				if _, err := os.Stat(bindstate.PendingPath(cfg.Runtime.StateDirectory, domain)); err != nil {
					t.Fatalf("ambiguous %s %s response lost pending intent: %v", domain, responseCase.name, err)
				}
				if !strings.Contains(stderr.String(), "结果未确定") {
					t.Fatalf("ambiguous %s %s response did not state recovery requirement: %s", domain, responseCase.name, stderr.String())
				}
				if domain == "website" {
					websiteCurrent, err := bindstate.Load(cfg.Runtime.StateDirectory)
					if err != nil || websiteCurrent.BindingID != websiteState.BindingID || websiteCurrent.CredentialEpoch != websiteState.CredentialEpoch {
						t.Fatalf("website old state was changed: %#v err=%v", websiteCurrent, err)
					}
					monitoringCurrent, err := bindstate.LoadMonitoring(cfg.Runtime.StateDirectory)
					if err != nil || monitoringCurrent.BindingID != monitoringState.BindingID || monitoringCurrent.CredentialEpoch != monitoringState.CredentialEpoch {
						t.Fatalf("website rejection changed monitoring state: %#v err=%v", monitoringCurrent, err)
					}
				} else {
					monitoringCurrent, err := bindstate.LoadMonitoring(cfg.Runtime.StateDirectory)
					if err != nil || monitoringCurrent.BindingID != monitoringState.BindingID || monitoringCurrent.CredentialEpoch != monitoringState.CredentialEpoch {
						t.Fatalf("monitoring old state was changed: %#v err=%v", monitoringCurrent, err)
					}
					websiteCurrent, err := bindstate.Load(cfg.Runtime.StateDirectory)
					if err != nil || websiteCurrent.BindingID != websiteState.BindingID || websiteCurrent.CredentialEpoch != websiteState.CredentialEpoch {
						t.Fatalf("monitoring rejection changed website state: %#v err=%v", websiteCurrent, err)
					}
				}
			})
		}
	}
}

func TestBindingAmbiguousFailureRetainsIntentAndKeepsAgentQuiesced(t *testing.T) {
	for _, domain := range []string{"website", "monitoring"} {
		t.Run(domain, func(t *testing.T) {
			filename := prepareBindConfig(t)
			cfg, _, _ := seedDualBindings(t, filename)
			quiesced, recovered := false, false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if !quiesced {
					t.Error("binding request reached the server before the Agent was quiesced")
				}
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer server.Close()
			var stdout, stderr bytes.Buffer
			instance := &cli{
				in: strings.NewReader("AMBIGUOUS-FAILURE-123456\n"), out: &stdout, errOut: &stderr, version: "test",
				managedWritePolicy: allowManagedWriteForTest,
				bindingPVE:         func(_ context.Context, _ string, value config.Config) (config.Config, error) { return value, nil },
				pveVersion:         func(context.Context) (string, error) { return "9.0.8", nil },
				quiesceBinding: func(context.Context) error {
					quiesced = true
					return nil
				},
				activateBinding: func(_ context.Context, _ config.Config, expected bindingActivationExpectation) error {
					if expected.BindingID == "" {
						recovered = true
					}
					return nil
				},
			}
			args := []string{"--config", filename, "website", "bind", "--endpoint", server.URL, "--hostname", "pve-test", "--replace"}
			if domain == "monitoring" {
				args = []string{"--config", filename, "monitoring", "bind", "--endpoint", server.URL, "--hostname", "pve-test", "--replace"}
			}
			if code := instance.run(args); code != 1 || !quiesced || !recovered {
				t.Fatalf("code=%d quiesced=%v recovered=%v stderr=%s", code, quiesced, recovered, stderr.String())
			}
			if _, err := os.Stat(bindstate.PendingPath(cfg.Runtime.StateDirectory, domain)); err != nil {
				t.Fatalf("ambiguous %s request did not retain pending intent: %v", domain, err)
			}
			if !strings.Contains(stderr.String(), "结果未确定") {
				t.Fatalf("ambiguous failure did not state fail-closed recovery requirement: %s", stderr.String())
			}
		})
	}
}

func TestCommittedBindingFourXXDoesNotAuthorizeRollback(t *testing.T) {
	for _, domain := range []string{"website", "monitoring"} {
		t.Run(domain, func(t *testing.T) {
			filename := prepareBindConfig(t)
			cfg := promoteBindConfigToAPI(t, filename)
			codeValue := "COMMITTED-FOURXX-123456"
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			}))
			defer server.Close()
			preparePendingBindRequest(t, cfg, domain, server.URL, codeValue)
			bindingID := "123e4567-e89b-42d3-a456-426614174088"
			var markerErr error
			if domain == "website" {
				markerErr = bindstate.BeginWebsiteCommit(cfg.Runtime.StateDirectory, bindingID, 1)
			} else {
				markerErr = bindstate.BeginMonitoringCommit(cfg.Runtime.StateDirectory, bindingID, 1)
			}
			if markerErr != nil {
				t.Fatal(markerErr)
			}
			recovered := false
			var stdout, stderr bytes.Buffer
			instance := &cli{
				in: strings.NewReader(codeValue + "\n"), out: &stdout, errOut: &stderr, version: "test",
				managedWritePolicy: allowManagedWriteForTest,
				bindingPVE:         func(_ context.Context, _ string, value config.Config) (config.Config, error) { return value, nil },
				pveVersion:         func(context.Context) (string, error) { return "9.0.8", nil },
				quiesceBinding: func(context.Context) error {
					return nil
				},
				activateBinding: func(_ context.Context, _ config.Config, expected bindingActivationExpectation) error {
					if expected.BindingID == "" {
						recovered = true
					}
					return nil
				},
			}
			args := []string{"--config", filename, "website", "bind", "--endpoint", server.URL, "--hostname", "pve-test"}
			if domain == "monitoring" {
				args = []string{"--config", filename, "monitoring", "bind", "--endpoint", server.URL, "--hostname", "pve-test"}
			}
			if got := instance.run(args); got != 1 || recovered {
				t.Fatalf("code=%d recovered=%v stderr=%s", got, recovered, stderr.String())
			}
			if _, err := os.Stat(bindstate.PendingPath(cfg.Runtime.StateDirectory, domain)); err != nil {
				t.Fatalf("committed %s fourxx cleared pending intent: %v", domain, err)
			}
			if domain == "website" {
				marker, found, err := bindstate.ReadWebsiteCommit(cfg.Runtime.StateDirectory)
				if err != nil || !found || marker.BindingID != bindingID {
					t.Fatalf("website commit marker was lost: %#v found=%v err=%v", marker, found, err)
				}
			} else {
				marker, found, err := bindstate.ReadMonitoringCommit(cfg.Runtime.StateDirectory)
				if err != nil || !found || marker.BindingID != bindingID {
					t.Fatalf("monitoring commit marker was lost: %#v found=%v err=%v", marker, found, err)
				}
			}
		})
	}
}

func TestMonitoringBindRejectsUserSuppliedPVEVersion(t *testing.T) {
	filename := prepareBindConfig(t)
	called := false
	var stdout, stderr bytes.Buffer
	c := &cli{
		in: strings.NewReader("MONITOR-123456\n"), out: &stdout, errOut: &stderr, version: "test",
		managedWritePolicy: allowManagedWriteForTest,
		pveVersion:         func(context.Context) (string, error) { called = true; return "9.0.8", nil },
	}
	code := c.run([]string{"--config", filename, "monitoring", "bind", "--endpoint", "https://moniter.ppflight.com/internal/v1/monitoring/agents/bind", "--pve-version", "9.0.8"})
	if code != 2 || called {
		t.Fatalf("code=%d discoveryCalled=%v stderr=%s", code, called, stderr.String())
	}
}

func TestWebsiteBindRejectsUserSuppliedPVEVersion(t *testing.T) {
	filename := prepareBindConfig(t)
	var stdout, stderr bytes.Buffer
	code := runWebsiteBindForTest([]string{"--config", filename, "website", "bind", "--endpoint", "https://www.ppflight.com/api/pve-agent/v1/enrollments/redeem", "--pve-version", "9.0.8"}, "test", strings.NewReader("SHOULD-NOT-BE-READ\n"), &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
}

func TestWebsiteBindFailsRealPVEReadinessBeforeReadingCode(t *testing.T) {
	filename := prepareBindConfig(t)
	reader := &readTrackingReader{}
	versionCalled := false
	var stdout, stderr bytes.Buffer
	c := &cli{
		in: reader, out: &stdout, errOut: &stderr, version: "test",
		managedWritePolicy: allowManagedWriteForTest,
		bindingPVE: func(context.Context, string, config.Config) (config.Config, error) {
			return config.Config{}, errors.New("simulator is forbidden")
		},
		pveVersion: func(context.Context) (string, error) {
			versionCalled = true
			return "9.0.8", nil
		},
	}
	code := c.run([]string{"--config", filename, "website", "bind", "--endpoint", "https://www.ppflight.com/api/pve-agent/v1/enrollments/redeem"})
	if code == 0 || reader.read || versionCalled || !strings.Contains(stderr.String(), "PVE_REAL_READINESS_FAILED") {
		t.Fatalf("code=%d read=%v versionCalled=%v stderr=%s", code, reader.read, versionCalled, stderr.String())
	}
	cfg, err := config.LoadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(bindstate.PendingPath(cfg.Runtime.StateDirectory, "website")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("readiness failure created pending request: %v", err)
	}
}

func TestProductionBindingEndpointFailsBeforePVEReadinessOrCode(t *testing.T) {
	filename := prepareBindConfig(t)
	for _, args := range [][]string{
		{"--config", filename, "website", "bind", "--endpoint", "http://example.com/internal/v1/agents/bind"},
		{"--config", filename, "monitoring", "bind", "--endpoint", "http://example.com/internal/v1/monitoring/agents/bind"},
	} {
		reader := &readTrackingReader{}
		readinessCalled := false
		instance := &cli{
			in: reader, out: io.Discard, errOut: io.Discard, version: "test",
			managedWritePolicy: allowManagedWriteForTest,
			activatePVE:        func(context.Context, config.Config) error { readinessCalled = true; return nil },
		}
		if code := instance.run(args); code != 2 {
			t.Fatalf("unsafe endpoint exit=%d args=%v", code, args)
		}
		if reader.read || readinessCalled {
			t.Fatalf("unsafe endpoint touched code or PVE readiness: read=%v readiness=%v", reader.read, readinessCalled)
		}
	}
}

func TestMonitoringMenuDoesNotPromptForPVEVersionOrCodeBeforeDiscovery(t *testing.T) {
	filename := prepareBindConfig(t)
	var stdout, stderr bytes.Buffer
	c := &cli{
		in:  strings.NewReader("3\n2\nhttps://moniter.ppflight.com/internal/v1/monitoring/agents/bind\nSHOULD-NOT-BE-READ\n"),
		out: &stdout, errOut: &stderr, version: "test",
		managedWritePolicy: allowManagedWriteForTest,
		pveVersion:         func(context.Context) (string, error) { return "", errors.New("not a PVE host") },
	}
	if code := c.run([]string{"--config", filename}); code == 0 {
		t.Fatal("menu accepted failed trusted PVE discovery")
	}
	if strings.Contains(stdout.String(), "PVE 版本") || strings.Contains(stdout.String(), "输入一次性绑定码") {
		t.Fatalf("monitoring menu prompted before discovery: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "PVE_REAL_READINESS_FAILED") {
		t.Fatalf("missing safe discovery error: %s", stderr.String())
	}
}

func TestWebsiteMenuDoesNotPromptForPVEVersionOrCodeBeforeDiscovery(t *testing.T) {
	filename := prepareBindConfig(t)
	var stdout, stderr bytes.Buffer
	c := &cli{
		in:  strings.NewReader("2\n2\nhttps://www.ppflight.com/api/pve-agent/v1/enrollments/redeem\nSHOULD-NOT-BE-READ\n"),
		out: &stdout, errOut: &stderr, version: "test",
		managedWritePolicy: allowManagedWriteForTest,
		pveVersion:         func(context.Context) (string, error) { return "", errors.New("not a PVE host") },
	}
	if code := c.run([]string{"--config", filename}); code == 0 {
		t.Fatal("menu accepted failed trusted PVE discovery")
	}
	if strings.Contains(stdout.String(), "PVE 版本") || strings.Contains(stdout.String(), "输入一次性绑定码") {
		t.Fatalf("website menu prompted before discovery: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "PVE_REAL_READINESS_FAILED") {
		t.Fatalf("missing safe discovery error: %s", stderr.String())
	}
}
