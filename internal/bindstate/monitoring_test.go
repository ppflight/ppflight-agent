package bindstate

import (
	"encoding/base64"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/enrollment"
	"github.com/ppflight/ppflight-agent/internal/monitorenrollment"
	"github.com/ppflight/ppflight-agent/internal/netpolicy"
)

func TestMonitoringStateIsIndependentFromWebsiteState(t *testing.T) {
	directory := t.TempDir()
	website := testState("https://website.example")
	if err := Save(directory, website); err != nil {
		t.Fatal(err)
	}
	response := monitorenrollment.Response{SchemaVersion: 1, BindingID: "123e4567-e89b-42d3-a456-426614174002", DeviceID: website.DeviceID, MonitoringAgentRef: "monitor-agent-01", IngestEndpoint: "https://monitor.example/internal/v1/monitoring/telemetry/batches", HMACCredential: monitorenrollment.HMACCredential{Algorithm: "hmac-sha256", KeyID: "monitor-key-01", SecretEncoding: "base64", Secret: enrollment.Secret(base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")))}, Telemetry: monitorenrollment.TelemetryContract{PayloadFormat: "telemetry-v1", Compression: "gzip", MaxCompressedBytes: 8 << 20, MaxUncompressedBytes: 32 << 20}, NetworkPolicy: netpolicy.NetworkPolicy{AgentObservedIPv4: "192.0.2.24"}, CredentialEpoch: 3, IssuedAt: time.Now().UTC()}
	monitor := MonitoringFromResponse("https://monitor.example/internal/v1/monitoring/agents/bind", website.DeviceID, response)
	if err := SaveMonitoring(directory, monitor); err != nil {
		t.Fatal(err)
	}
	loadedMonitor, err := LoadMonitoring(directory)
	if err != nil {
		t.Fatal(err)
	}
	loadedWebsite, err := Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	if loadedMonitor.MonitoringAgentRef != "monitor-agent-01" || loadedWebsite.BindingID != website.BindingID || loadedWebsite.CredentialEpoch != website.CredentialEpoch {
		t.Fatalf("states crossed trust domains: monitoring=%#v website=%#v", loadedMonitor, loadedWebsite.Identity)
	}
	if got, want := loadedWebsite.NetworkPolicy.AgentObservedIPv4, "127.0.0.1"; got != want {
		t.Fatalf("website network policy changed: %q", got)
	}
	if got, want := loadedMonitor.NetworkPolicy.AgentObservedIPv4, "192.0.2.24"; got != want {
		t.Fatalf("monitoring network policy changed: %q", got)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(MonitoringPath(directory))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o640 {
			t.Fatalf("monitoring state mode = %o", info.Mode().Perm())
		}
	}
}
