package admincli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/bindstate"
	"github.com/ppflight/ppflight-agent/internal/config"
	"github.com/ppflight/ppflight-agent/internal/health"
)

func TestPVEPrepareLocalOnlyAcceptsFreshRealPVEWithoutSimulator(t *testing.T) {
	filename := writeTestConfig(t)
	var output, stderr bytes.Buffer
	instance := &cli{
		out: &output, errOut: &stderr, effectiveUID: func() int { return 0 },
		pveEnvironment:     func(string) (map[string]string, error) { return localPVEEnvironmentForTest(), nil },
		pveProbe:           prepareProbe(true),
		pveNodeName:        func() (string, error) { return "pve01", nil },
		pveVersion:         func(context.Context) (string, error) { return "9.0.3", nil },
		pveTLSPreflight:    successfulPVETLSPreflight,
		activatePVE:        func(context.Context, config.Config) error { return nil },
		managedWritePolicy: allowManagedWriteForTest,
	}
	if code := instance.pve(filename, []string{"prepare", "--local-only", "--tls-server-name", "pve01.example.test", "--ca-file", managedPVECAFile}); code != 0 {
		t.Fatalf("local-only prepare code=%d stderr=%s output=%s", code, stderr.String(), output.String())
	}
	prepared, err := config.LoadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Mode != "production" || prepared.PVE.Source != "api" || prepared.PVE.LocalNode != "pve01" {
		t.Fatalf("local-only prepare did not enable real local collection: %#v", prepared.PVE)
	}
	if prepared.PVE.Source == "simulator" || prepared.Mode == "test" {
		t.Fatalf("local-only prepare accepted a non-production source: mode=%q source=%q", prepared.Mode, prepared.PVE.Source)
	}
}

func TestPVEPrepareLocalOnlyDoesNotWaitForBoundRemoteDelivery(t *testing.T) {
	now := time.Now().UTC()
	operations := agentServiceOperations{
		Restart: func(context.Context) error { return nil },
		Active:  func(context.Context) error { return nil },
		Status: func(config.Config) (health.Status, error) {
			return health.Status{
				Mode: "production", Ready: true, StartedAt: now,
				Collection: health.EventState{LastSuccess: timePointer(now.Add(time.Second))},
				// A bound destination may be temporarily unavailable during the
				// first automatic install.  --local-only must not wait for it.
				Deliveries: map[string]health.EventState{"website-telemetry": {AuthBlocked: true}},
			}, nil
		},
		Delay: func(context.Context, time.Duration) error { return errors.New("should not wait for delivery") },
	}
	cfg := config.Config{Mode: "production", PVE: config.PVEConfig{Source: "api"}}
	cfg.Destinations.WebsiteTelemetry.Enabled = true
	if err := activateRealPVEWithRequirement(context.Background(), cfg, operations, false); err != nil {
		t.Fatalf("local-only activation waited for remote delivery: %v", err)
	}
	if err := activateRealPVEWithRequirement(context.Background(), cfg, operations, true); err == nil {
		t.Fatal("normal PVE preparation unexpectedly accepted an unconfirmed bound delivery")
	}
}

func TestPVEPrepareLocalOnlyPreservesBindingsAndArmsReadyControlOnUpgrade(t *testing.T) {
	filename := prepareBindConfig(t)
	before, website, monitoring := seedDualBindings(t, filename)
	before.Mode = "production"
	before.PVE.Source = "api"
	before.PVE.Endpoint = config.LocalPVEEndpoint
	before.PVE.TLSServerName = "pve01.example.test"
	before.PVE.CAFile = managedPVECAFile
	before.PVE.TokenIDEnv = config.PVEReadTokenIDEnv
	before.PVE.TokenSecretEnv = config.PVEReadTokenSecretEnv
	before.PVE.LocalNode = "pve01"
	before.Control.PVETokenIDEnv = config.PVEControlTokenIDEnv
	before.Control.PVETokenSecretEnv = config.PVEControlTokenSecretEnv
	if err := before.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.MarshalIndent(before, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, append(raw, '\n'), 0o640); err != nil {
		t.Fatal(err)
	}
	websiteBefore, err := os.ReadFile(bindstate.Path(before.Runtime.StateDirectory))
	if err != nil {
		t.Fatal(err)
	}
	monitoringBefore, err := os.ReadFile(bindstate.MonitoringPath(before.Runtime.StateDirectory))
	if err != nil {
		t.Fatal(err)
	}

	instance := &cli{
		out: io.Discard, errOut: io.Discard, effectiveUID: func() int { return 0 },
		pveEnvironment:     func(string) (map[string]string, error) { return localPVEEnvironmentForTest(), nil },
		pveProbe:           prepareProbe(true),
		pveNodeName:        func() (string, error) { return "pve01", nil },
		pveVersion:         func(context.Context) (string, error) { return "9.0.3", nil },
		pveTLSPreflight:    successfulPVETLSPreflight,
		activatePVE:        func(context.Context, config.Config) error { return nil },
		managedWritePolicy: allowManagedWriteForTest,
	}
	if code := instance.pve(filename, []string{"prepare", "--local-only", "--tls-server-name", "pve01.example.test", "--ca-file", managedPVECAFile}); code != 0 {
		t.Fatalf("upgrade local-only prepare code=%d", code)
	}

	configAfter, err := config.LoadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if !configAfter.Control.ProductionExecution {
		t.Fatal("dual-bound, locally verified upgrade did not automatically arm VPS control")
	}
	if !configAfter.Exporters.Node.Enabled || !configAfter.Exporters.SMART.Enabled {
		t.Fatalf("upgrade did not migrate exporter collection: %#v", configAfter.Exporters)
	}
	websiteAfter, err := os.ReadFile(bindstate.Path(before.Runtime.StateDirectory))
	if err != nil || !bytes.Equal(websiteBefore, websiteAfter) {
		t.Fatalf("local-only upgrade changed website binding: err=%v", err)
	}
	monitoringAfter, err := os.ReadFile(bindstate.MonitoringPath(before.Runtime.StateDirectory))
	if err != nil || !bytes.Equal(monitoringBefore, monitoringAfter) {
		t.Fatalf("local-only upgrade changed monitoring binding: err=%v", err)
	}
	loadedWebsite, err := bindstate.Load(before.Runtime.StateDirectory)
	if err != nil || loadedWebsite.BindingID != website.BindingID || loadedWebsite.CredentialEpoch != website.CredentialEpoch {
		t.Fatalf("website binding changed: state=%#v err=%v", loadedWebsite, err)
	}
	loadedMonitoring, err := bindstate.LoadMonitoring(before.Runtime.StateDirectory)
	if err != nil || loadedMonitoring.BindingID != monitoring.BindingID || loadedMonitoring.CredentialEpoch != monitoring.CredentialEpoch {
		t.Fatalf("monitoring binding changed: state=%#v err=%v", loadedMonitoring, err)
	}
}

func TestAutoEnableProductionExecutionRequiresMatchingDualBindings(t *testing.T) {
	filename := prepareBindConfig(t)
	cfg, website, _ := seedDualBindings(t, filename)
	cfg.Mode = "production"
	cfg.PVE.Source = "api"
	cfg.PVE.Endpoint = config.LocalPVEEndpoint
	cfg.Control.PVETokenIDEnv = config.PVEControlTokenIDEnv
	cfg.Control.PVETokenSecretEnv = config.PVEControlTokenSecretEnv

	if !autoEnableProductionExecution(&cfg, "", "") || !cfg.Control.ProductionExecution {
		t.Fatal("stable matching website and monitoring bindings did not arm control")
	}
	if autoEnableProductionExecution(&cfg, "monitoring", "00000000-0000-4000-8000-000000000001") || cfg.Control.ProductionExecution {
		t.Fatal("mismatched replacement device identity armed control")
	}
	if !autoEnableProductionExecution(&cfg, "monitoring", website.DeviceID) || !cfg.Control.ProductionExecution {
		t.Fatal("matching monitoring completion did not arm control")
	}
	if err := os.Remove(bindstate.MonitoringPath(cfg.Runtime.StateDirectory)); err != nil {
		t.Fatal(err)
	}
	if autoEnableProductionExecution(&cfg, "", "") || cfg.Control.ProductionExecution {
		t.Fatal("single-domain state armed control")
	}
}

func TestPVEPrepareLocalOnlyFailureRestoresDisabledConfigAndStopsService(t *testing.T) {
	filename := writeTestConfig(t)
	before, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	stops := 0
	instance := &cli{
		out: io.Discard, errOut: io.Discard, effectiveUID: func() int { return 0 },
		pveEnvironment:  func(string) (map[string]string, error) { return localPVEEnvironmentForTest(), nil },
		pveProbe:        prepareProbe(true),
		pveNodeName:     func() (string, error) { return "pve01", nil },
		pveVersion:      func(context.Context) (string, error) { return "9.0.3", nil },
		pveTLSPreflight: successfulPVETLSPreflight,
		activatePVE:     func(context.Context, config.Config) error { return errors.New("local collection did not become ready") },
		quiesceBinding: func(context.Context) error {
			stops++
			return nil
		},
		managedWritePolicy: allowManagedWriteForTest,
	}
	if code := instance.pve(filename, []string{"prepare", "--local-only", "--tls-server-name", "pve01.example.test", "--ca-file", managedPVECAFile}); code == 0 {
		t.Fatal("failed local-only preparation reported success")
	}
	after, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	var beforeConfig, afterConfig config.Config
	if err := json.Unmarshal(before, &beforeConfig); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(after, &afterConfig); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(beforeConfig, afterConfig) {
		t.Fatal("failed local-only preparation left the transient api configuration on disk")
	}
	if stops != 1 {
		t.Fatalf("failed local-only preparation did not stop the transient Agent: stops=%d", stops)
	}
}
