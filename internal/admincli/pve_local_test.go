package admincli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ppflight/ppflight-agent/internal/config"
	"github.com/ppflight/ppflight-agent/internal/pve"
)

func localPVEEnvironmentForTest() map[string]string {
	return map[string]string{
		config.PVEReadTokenIDEnv:        "ppflight-agent@pve!collector",
		config.PVEReadTokenSecretEnv:    "read-secret-0123456789",
		config.PVEControlTokenIDEnv:     "ppflight-control@pve!executor",
		config.PVEControlTokenSecretEnv: "control-secret-0123456789",
	}
}

func prepareProbe(controlPermissions bool) func(context.Context, pve.Config, bool) (rawCredentialProbe, error) {
	return func(_ context.Context, cfg pve.Config, includeVersion bool) (rawCredentialProbe, error) {
		if cfg.Endpoint != config.LocalPVEEndpoint || cfg.TLSServerName != "pve01.example.test" || cfg.InsecureSkipTLS || cfg.CAFile != "/trusted/pve-root-ca.pem" {
			return rawCredentialProbe{}, io.ErrUnexpectedEOF
		}
		result := rawCredentialProbe{permissions: pve.Permissions{Paths: map[string]map[string]int{}}}
		if includeVersion {
			if cfg.TokenID != "ppflight-agent@pve!collector" || cfg.TokenSecret != "read-secret-0123456789" {
				return rawCredentialProbe{}, io.ErrUnexpectedEOF
			}
			result.version = pve.Version{Version: "9.0.3", Release: "9.0"}
			result.permissions.Paths["/"] = map[string]int{"Sys.Audit": 1}
		} else if controlPermissions {
			if cfg.TokenID != "ppflight-control@pve!executor" || cfg.TokenSecret != "control-secret-0123456789" {
				return rawCredentialProbe{}, io.ErrUnexpectedEOF
			}
			result.permissions.Paths["/pool/ppflight"] = map[string]int{"VM.PowerMgmt": 1}
		}
		return result, nil
	}
}

func TestPVEPrepareProbesThenOnlyEnablesReadAPISource(t *testing.T) {
	filename := writeTestConfig(t)
	var output, stderr bytes.Buffer
	instance := &cli{
		in: strings.NewReader(""), out: &output, errOut: &stderr, version: "test",
		effectiveUID:   func() int { return 0 },
		pveEnvironment: func(string) (map[string]string, error) { return localPVEEnvironmentForTest(), nil },
		pveProbe:       prepareProbe(false),
	}
	code := instance.pve(filename, []string{"prepare", "--tls-server-name", "pve01.example.test", "--ca-file", "/trusted/pve-root-ca.pem"})
	if code != 0 {
		t.Fatalf("code=%d stderr=%s output=%s", code, stderr.String(), output.String())
	}
	cfg, err := config.LoadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PVE.Source != "api" || cfg.PVE.Endpoint != config.LocalPVEEndpoint || cfg.PVE.TLSServerName != "pve01.example.test" || cfg.PVE.InsecureSkipTLS || cfg.Mode != "test" || cfg.Control.ProductionExecution {
		t.Fatalf("unsafe prepared config: %#v", cfg)
	}
	if cfg.PVE.TokenIDEnv != config.PVEReadTokenIDEnv || cfg.Control.PVETokenIDEnv != config.PVEControlTokenIDEnv {
		t.Fatalf("unexpected environment names: %#v %#v", cfg.PVE, cfg.Control)
	}
	combined := output.String() + stderr.String()
	for _, secret := range []string{"read-secret-0123456789", "control-secret-0123456789"} {
		if strings.Contains(combined, secret) {
			t.Fatalf("secret leaked: %s", combined)
		}
	}
	if !strings.Contains(output.String(), "不会声明 pve.control.v1") || !strings.Contains(output.String(), "productionExecution 仍保持 false") && cfg.Control.ProductionExecution {
		t.Fatalf("safe control state not reported: %s", output.String())
	}
	backups, _ := filepath.Glob(filename + ".bak.*")
	if len(backups) != 1 {
		t.Fatalf("backup count=%d", len(backups))
	}
}

func TestPVEPrepareFailureDoesNotMutateConfig(t *testing.T) {
	filename := writeTestConfig(t)
	before, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	instance := &cli{
		in: strings.NewReader(""), out: io.Discard, errOut: io.Discard, version: "test",
		effectiveUID:   func() int { return 0 },
		pveEnvironment: func(string) (map[string]string, error) { return localPVEEnvironmentForTest(), nil },
		pveProbe: func(context.Context, pve.Config, bool) (rawCredentialProbe, error) {
			return rawCredentialProbe{}, io.ErrUnexpectedEOF
		},
	}
	if code := instance.pve(filename, []string{"prepare", "--tls-server-name", "pve01.example.test", "--ca-file", "/trusted/pve-root-ca.pem"}); code == 0 {
		t.Fatal("failed probe enabled the API source")
	}
	after, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("configuration changed after failed probe")
	}
}

func TestSimulatorStatusFailsClosedWithoutProbing(t *testing.T) {
	cfg, err := config.LoadFile(writeTestConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	instance := &cli{
		out: io.Discard, errOut: io.Discard,
		effectiveUID: func() int { return 0 },
		pveProbe: func(context.Context, pve.Config, bool) (rawCredentialProbe, error) {
			t.Fatal("simulator attempted a PVE probe")
			return rawCredentialProbe{}, nil
		},
	}
	status, code := instance.inspectLocalPVE(cfg)
	if code == 0 || status.Read.CredentialReady || status.Control.CredentialReady || status.ProductionReady || status.Read.Code != "SOURCE_SIMULATOR" {
		t.Fatalf("simulator reported ready: %#v", status)
	}
}

func TestPVEStatusRequiresRootBeforeLoadingOrProbing(t *testing.T) {
	var output, stderr bytes.Buffer
	instance := &cli{out: &output, errOut: &stderr, effectiveUID: func() int { return 1000 }}
	if code := instance.pve("missing-config.json", []string{"status"}); code == 0 {
		t.Fatal("non-root pve status was accepted")
	}
	if !strings.Contains(stderr.String(), "必须由 root") {
		t.Fatalf("root-only status was not explained: %s", stderr.String())
	}
}

func TestMenuKeepsFiveItemsAndMarksSimulatorNotReady(t *testing.T) {
	filename := writeTestConfig(t)
	var output, stderr bytes.Buffer
	instance := &cli{in: strings.NewReader("0\n"), out: &output, errOut: &stderr, effectiveUID: func() int { return 0 }}
	if code := instance.menu(filename); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	menu := output.String()
	if !strings.Contains(menu, "source=simulator") || !strings.Contains(menu, "productionReady=false") {
		t.Fatalf("simulator readiness missing: %s", menu)
	}
	for item := 1; item <= 5; item++ {
		if !strings.Contains(menu, fmt.Sprintf("%d)", item)) {
			t.Fatalf("five-item menu lost item %d: %s", item, menu)
		}
	}
}

func TestWebsiteControlCapabilityRequiresLiveNonemptyPermissions(t *testing.T) {
	cfg, err := config.LoadFile(writeTestConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	base := &cli{effectiveUID: func() int { return 0 }, pveEnvironment: func(string) (map[string]string, error) { return localPVEEnvironmentForTest(), nil }}
	base.pveProbe = func(context.Context, pve.Config, bool) (rawCredentialProbe, error) {
		t.Fatal("simulator probed")
		return rawCredentialProbe{}, nil
	}
	capabilities, err := base.websiteCapabilities(cfg, "", false)
	if err != nil || strings.Join(capabilities, ",") != "pve.discovery.v1,pve.telemetry.v1" {
		t.Fatalf("simulator capabilities=%v err=%v", capabilities, err)
	}

	cfg.PVE.Source, cfg.PVE.Endpoint, cfg.PVE.TLSServerName = "api", config.LocalPVEEndpoint, "pve01.example.test"
	cfg.PVE.TokenIDEnv, cfg.PVE.TokenSecretEnv = config.PVEReadTokenIDEnv, config.PVEReadTokenSecretEnv
	cfg.PVE.CAFile = "/trusted/pve-root-ca.pem"
	cfg.Control.PVETokenIDEnv, cfg.Control.PVETokenSecretEnv = config.PVEControlTokenIDEnv, config.PVEControlTokenSecretEnv
	base.pveProbe = prepareProbe(false)
	capabilities, err = base.websiteCapabilities(cfg, "", false)
	if err != nil || strings.Contains(strings.Join(capabilities, ","), "pve.control.v1") {
		t.Fatalf("empty permissions claimed control: %v err=%v", capabilities, err)
	}
	if _, err := base.websiteCapabilities(cfg, "pve.discovery.v1,pve.control.v1", true); err == nil {
		t.Fatal("explicit unsupported local control claim was accepted")
	}
	base.pveProbe = prepareProbe(true)
	capabilities, err = base.websiteCapabilities(cfg, "", false)
	if err != nil || !strings.Contains(strings.Join(capabilities, ","), "pve.control.v1") {
		t.Fatalf("verified control capability missing: %v err=%v", capabilities, err)
	}
	if _, err := base.websiteCapabilities(cfg, "pve.discovery.v1,arbitrary.future.v1", true); err == nil {
		t.Fatal("unexplainable explicit capability was accepted")
	}
}

func TestPVEStatusIsRedactedAndSeparatesCredentialFromProductionReadiness(t *testing.T) {
	filename := writeTestConfig(t)
	cfg, err := config.LoadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	cfg.PVE.Source, cfg.PVE.Endpoint, cfg.PVE.TLSServerName = "api", config.LocalPVEEndpoint, "pve01.example.test"
	cfg.PVE.TokenIDEnv, cfg.PVE.TokenSecretEnv = config.PVEReadTokenIDEnv, config.PVEReadTokenSecretEnv
	cfg.PVE.CAFile = "/trusted/pve-root-ca.pem"
	cfg.Control.PVETokenIDEnv, cfg.Control.PVETokenSecretEnv = config.PVEControlTokenIDEnv, config.PVEControlTokenSecretEnv
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, raw, 0o640); err != nil {
		t.Fatal(err)
	}
	var output, stderr bytes.Buffer
	instance := &cli{
		out: &output, errOut: &stderr, effectiveUID: func() int { return 0 },
		pveEnvironment: func(string) (map[string]string, error) { return localPVEEnvironmentForTest(), nil }, pveProbe: prepareProbe(true),
	}
	if code := instance.pve(filename, []string{"status"}); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var status localPVEStatus
	if err := json.Unmarshal(output.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if !status.Read.CredentialReady || !status.Control.CredentialReady || status.ProductionReady || status.ProductionExecution {
		t.Fatalf("status=%#v", status)
	}
	combined := output.String() + stderr.String()
	for _, value := range localPVEEnvironmentForTest() {
		if strings.Contains(combined, value) {
			t.Fatal("PVE credential leaked from status")
		}
	}
}
