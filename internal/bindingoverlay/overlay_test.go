package bindingoverlay

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/bindstate"
	"github.com/ppflight/ppflight-agent/internal/config"
	"github.com/ppflight/ppflight-agent/internal/enrollment"
	"github.com/ppflight/ppflight-agent/internal/monitorenrollment"
	"github.com/ppflight/ppflight-agent/internal/netpolicy"
)

func TestResolveUsesIndependentEndpointCredentialsAndDecodedKeys(t *testing.T) {
	stateDir := t.TempDir()
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	website := websiteResponse(now)
	if err := bindstate.Save(stateDir, bindstate.FromResponse("https://website.example/internal/v1/agents/bind", "device-01", website)); err != nil {
		t.Fatal(err)
	}
	monitoring := monitorenrollment.Response{
		SchemaVersion: 1, BindingID: "550e8400-e29b-41d4-a716-446655440002", DeviceID: "device-01", MonitoringAgentRef: "monitor-agent-01",
		IngestEndpoint: "https://monitor.example/internal/v1/monitoring/telemetry/batches", CredentialEpoch: 7, IssuedAt: now,
		HMACCredential: monitorenrollment.HMACCredential{Algorithm: "hmac-sha256", KeyID: "monitor-key-01", SecretEncoding: "base64", Secret: enrollment.Secret(encoded(0x66))},
		Telemetry:      monitorenrollment.TelemetryContract{PayloadFormat: "telemetry-v1", Compression: "gzip", MaxCompressedBytes: 1 << 20, MaxUncompressedBytes: 4 << 20},
		NetworkPolicy:  netpolicy.NetworkPolicy{AgentObservedIPv4: "127.0.0.1", ServerIPv4Allowlist: []string{"192.0.2.2"}},
	}
	if err := bindstate.SaveMonitoring(stateDir, bindstate.MonitoringFromResponse("https://monitor.example/internal/v1/monitoring/agents/bind", "device-01", monitoring)); err != nil {
		t.Fatal(err)
	}
	cfg := boundConfig(stateDir, website, monitoring)
	secrets, err := Resolve(cfg, func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	for label, value := range map[string][]byte{
		"metering": secrets.WebsiteMetering.Secret, "telemetry": secrets.WebsiteTelemetry.Secret,
		"assignments": secrets.Assignments.Secret, "commands": secrets.ControlAPI.Secret,
		"receipts": secrets.ControlReceipts.Secret, "monitoring": secrets.Monitoring.Secret, "monitoring-audit": secrets.MonitoringAudit.Secret,
	} {
		if len(value) != 32 {
			t.Fatalf("%s secret was not base64-decoded: %q", label, value)
		}
	}
	if bytes.Equal(secrets.ControlAPI.Secret, secrets.ControlReceipts.Secret) || bytes.Equal(secrets.WebsiteTelemetry.Secret, secrets.Monitoring.Secret) {
		t.Fatal("endpoint trust domains reused credential bytes")
	}
	if secrets.ControlSigningKeyID != "command-signing-01" || len(secrets.ControlPublicKey) != 32 || secrets.DeviceID != "device-01" || secrets.MonitoringAgentRef != "monitor-agent-01" {
		t.Fatalf("missing runtime binding metadata: %#v", secrets)
	}
	if secrets.WebsiteMetering.CredentialEpoch != 4 || secrets.Monitoring.CredentialEpoch != 7 {
		t.Fatalf("credential epochs were not propagated: %#v", secrets)
	}
}

func TestResolveReservedLabelsCannotBeOverriddenByEnvironment(t *testing.T) {
	stateDir := t.TempDir()
	response := websiteResponse(time.Now().UTC())
	if err := bindstate.Save(stateDir, bindstate.FromResponse("https://website.example/internal/v1/agents/bind", "device-01", response)); err != nil {
		t.Fatal(err)
	}
	cfg := boundConfig(stateDir, response, monitorenrollment.Response{})
	cfg.Destinations.Monitoring.Enabled = false
	cfg.Destinations.Monitoring.Auth = config.AuthConfig{}
	cfg.Destinations.MonitoringAudit.Enabled = false
	cfg.Destinations.MonitoringAudit.Auth = config.AuthConfig{}
	secrets, err := Resolve(cfg, func(string) (string, bool) { return "attacker-controlled", true })
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(secrets.ControlAPI.Secret, []byte("attacker-controlled")) {
		t.Fatal("reserved binding label used the process environment")
	}
}

func TestResolveRejectsUnknownReservedLabelAndStateMismatch(t *testing.T) {
	cfg := config.Config{}
	cfg.Destinations.WebsiteTelemetry.Enabled = true
	cfg.Destinations.WebsiteTelemetry.Auth = config.AuthConfig{Mode: "hmac-sha256", KeyIDEnv: "PPFLIGHT_BINDING_UNKNOWN", SecretEnv: "manual"}
	if _, err := Resolve(cfg, func(string) (string, bool) { return "x", true }); err == nil {
		t.Fatal("unknown reserved label was accepted")
	}

	stateDir := t.TempDir()
	response := websiteResponse(time.Now().UTC())
	if err := bindstate.Save(stateDir, bindstate.FromResponse("https://website.example/internal/v1/agents/bind", "device-01", response)); err != nil {
		t.Fatal(err)
	}
	cfg = boundConfig(stateDir, response, monitorenrollment.Response{})
	cfg.Destinations.Monitoring.Enabled = false
	cfg.Destinations.Monitoring.Auth = config.AuthConfig{}
	cfg.Destinations.MonitoringAudit.Enabled = false
	cfg.Destinations.MonitoringAudit.Auth = config.AuthConfig{}
	cfg.Control.PollURL = "https://website.example/internal/v1/wrong"
	if _, err := Resolve(cfg, func(string) (string, bool) { return "", false }); err == nil {
		t.Fatal("endpoint mismatch was accepted")
	}
}

func websiteResponse(now time.Time) enrollment.Response {
	assignment, _ := json.Marshal(map[string]any{"schemaVersion": 1, "revision": "revision-01", "issuedAt": now, "assignments": []any{}})
	return enrollment.Response{
		SchemaVersion: 1, BindingID: "550e8400-e29b-41d4-a716-446655440001", DeviceID: "device-01",
		AgentRef: "agent-01", CollectorRef: "collector-01", SourceRef: "source-01", ClusterRef: "cluster-01", NodeRef: "node-01", Site: "primary",
		Endpoints: enrollment.Endpoints{
			Metering: "https://website.example/internal/v1/metering", Telemetry: "https://website.example/internal/v1/telemetry",
			Assignments: "https://website.example/internal/v1/assignments", Commands: "https://website.example/internal/v1/commands", Receipts: "https://website.example/internal/v1/receipts",
		},
		HMACCredentials: enrollment.HMACCredentials{
			Metering: credential("metering-key-01", 0x11), Telemetry: credential("telemetry-key-01", 0x22),
			Assignments: credential("assignment-key-01", 0x33), Commands: credential("command-key-01", 0x44), Receipts: credential("receipt-key-01", 0x55),
		},
		CommandSigningCredential: enrollment.CommandSigningCredential{KeyID: "command-signing-01", Algorithm: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32))},
		AllowedActions:           []string{"pve.discover", "task.status", "vm.start", "vm.reset-password"}, AssignmentDocument: assignment,
		NetworkPolicy:   netpolicy.NetworkPolicy{AgentObservedIPv4: "127.0.0.1", ServerIPv4Allowlist: []string{"192.0.2.1"}},
		CredentialEpoch: 4, IssuedAt: now,
	}
}

func boundConfig(stateDir string, website enrollment.Response, monitoring monitorenrollment.Response) config.Config {
	auditEndpoint := ""
	if monitoring.IngestEndpoint != "" {
		auditEndpoint, _ = monitorenrollment.AuditEndpoint(monitoring.IngestEndpoint)
	}
	return config.Config{
		Mode: "test", Runtime: config.RuntimeConfig{StateDirectory: stateDir},
		Identity:    config.IdentityConfig{AgentRef: website.AgentRef, CollectorRef: website.CollectorRef, SourceRef: website.SourceRef, ClusterRef: website.ClusterRef, NodeRef: website.NodeRef, Site: website.Site},
		Assignments: config.AssignmentsConfig{RefreshURL: website.Endpoints.Assignments},
		Destinations: config.DestinationsConfig{
			WebsiteMetering:  config.DestinationConfig{Enabled: true, URL: website.Endpoints.Metering, Auth: config.AuthConfig{Mode: "hmac-sha256", KeyIDEnv: WebsiteMeteringKeyIDEnv, SecretEnv: WebsiteMeteringSecretEnv}},
			WebsiteTelemetry: config.DestinationConfig{Enabled: true, URL: website.Endpoints.Telemetry, Auth: config.AuthConfig{Mode: "hmac-sha256", KeyIDEnv: WebsiteTelemetryKeyIDEnv, SecretEnv: WebsiteTelemetrySecretEnv}},
			Monitoring: config.DestinationConfig{Enabled: monitoring.IngestEndpoint != "", URL: monitoring.IngestEndpoint, Auth: config.AuthConfig{Mode: "hmac-sha256", KeyIDEnv: MonitoringKeyIDEnv, SecretEnv: MonitoringSecretEnv}, PayloadFormat: monitoring.Telemetry.PayloadFormat, Compression: monitoring.Telemetry.Compression,
				MaxCompressedBytes: monitoring.Telemetry.MaxCompressedBytes, MaxUncompressedBytes: monitoring.Telemetry.MaxUncompressedBytes},
			MonitoringAudit: config.DestinationConfig{Enabled: auditEndpoint != "", URL: auditEndpoint, Auth: config.AuthConfig{Mode: "hmac-sha256", KeyIDEnv: MonitoringKeyIDEnv, SecretEnv: MonitoringSecretEnv}, PayloadFormat: "audit-v1", Compression: monitoring.Telemetry.Compression,
				MaxCompressedBytes: monitorenrollment.AuditMaxCompressedBytes, MaxUncompressedBytes: monitorenrollment.AuditMaxUncompressedBytes},
		},
		Control: config.ControlConfig{
			Enabled: true, PollURL: website.Endpoints.Commands, ResultURL: website.Endpoints.Receipts,
			Auth:                   config.AuthConfig{Mode: "hmac-sha256", KeyIDEnv: WebsiteCommandKeyIDEnv, SecretEnv: WebsiteCommandSecretEnv},
			CommandSigningKeyIDEnv: WebsiteSigningKeyIDEnv, CommandPublicKeyEnv: WebsiteCommandPublicKeyEnv,
			AllowedActions: website.AllowedActions,
		},
	}
}

func credential(key string, fill byte) enrollment.HMACCredential {
	return enrollment.HMACCredential{KeyID: key, Secret: enrollment.Secret(encoded(fill))}
}

func encoded(fill byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
}
