package config

import (
	"strings"
	"testing"
)

func validTestConfig() string {
	return `{
  "schemaVersion": 1,
  "mode": "test",
  "identity": {
    "agentRef": "agent-test-01",
    "collectorRef": "collector-test-01",
    "sourceRef": "ppflight-agent-test",
    "clusterRef": "cluster-test-01",
    "nodeRef": "auto",
    "site": "lab"
  },
  "runtime": {"stateDirectory":"/tmp/ppflight-agent-test","listenAddress":"127.0.0.1:19745","shutdownGrace":"5s","logLevel":"debug"},
  "pve": {"source":"disabled"},
  "destinations": {
    "websiteMetering":{"enabled":false},
    "websiteTelemetry":{"enabled":false},
    "monitoring":{"enabled":false}
  },
  "control": {"enabled":true,"productionExecution":false}
}`
}

func TestParseAppliesSafeDefaults(t *testing.T) {
	cfg, err := Parse([]byte(validTestConfig()))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Control.Enabled || cfg.Collection.SampleInterval.String() != "10s" {
		t.Fatalf("defaults not applied: %#v", cfg)
	}
	if cfg.PVE.Source != "disabled" || cfg.Exporters.Node.URL != "http://127.0.0.1:9100/metrics" {
		t.Fatalf("unexpected source defaults: %#v", cfg.PVE)
	}
}

func TestRejectsUnknownField(t *testing.T) {
	input := strings.Replace(validTestConfig(), `"mode": "test"`, `"mode": "test", "typo": true`, 1)
	if _, err := Parse([]byte(input)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown field error, got %v", err)
	}
}

func TestProductionRejectsInsecurePVE(t *testing.T) {
	input := strings.Replace(validTestConfig(), `"mode": "test"`, `"mode": "production"`, 1)
	input = strings.Replace(input, `"source":"disabled"`, `"source":"api","endpoint":"https://127.0.0.1:8006","tokenIdEnv":"PVE_READ_TOKEN_ID","tokenSecretEnv":"PVE_READ_TOKEN_SECRET","insecureSkipTls":true`, 1)
	if _, err := Parse([]byte(input)); err == nil || !strings.Contains(err.Error(), "insecureSkipTls") {
		t.Fatalf("expected TLS error, got %v", err)
	}
}

func TestProductionAPIRequiresStrictTLSServerName(t *testing.T) {
	input := strings.Replace(validTestConfig(), `"mode": "test"`, `"mode": "production"`, 1)
	input = strings.Replace(input, `"source":"disabled"`, `"source":"api","endpoint":"https://127.0.0.1:8006","tokenIdEnv":"PVE_READ_TOKEN_ID","tokenSecretEnv":"PVE_READ_TOKEN_SECRET"`, 1)
	if _, err := Parse([]byte(input)); err == nil || !strings.Contains(err.Error(), "tlsServerName") {
		t.Fatalf("missing TLS server name accepted: %v", err)
	}
	input = strings.Replace(input, `"tokenSecretEnv":"PVE_READ_TOKEN_SECRET"`, `"tokenSecretEnv":"PVE_READ_TOKEN_SECRET","tlsServerName":"127.0.0.1"`, 1)
	if _, err := Parse([]byte(input)); err == nil || !strings.Contains(err.Error(), "tlsServerName") {
		t.Fatalf("IP TLS server name accepted: %v", err)
	}
}

func TestCountersRequireEnvironmentAtResolution(t *testing.T) {
	input := strings.Replace(validTestConfig(), `"source":"disabled"`, `"source":"api","endpoint":"https://127.0.0.1:8006","tokenIdEnv":"PVE_READ_TOKEN_ID","tokenSecretEnv":"PVE_READ_TOKEN_SECRET","tlsServerName":"pve.example.test"`, 1)
	cfg, err := Parse([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	_, err = cfg.ResolveSecrets(func(name string) (string, bool) {
		if name == PVEReadTokenIDEnv {
			return "monitor@pve!agent", true
		}
		return "", false
	})
	if err == nil || !strings.Contains(err.Error(), PVEReadTokenSecretEnv) {
		t.Fatalf("expected missing secret error, got %v", err)
	}
}

func TestPVERequestTimeoutIsBoundedForWatchdogProgress(t *testing.T) {
	input := strings.Replace(validTestConfig(), `"source":"disabled"`, `"source":"api","endpoint":"https://127.0.0.1:8006","tokenIdEnv":"PVE_READ_TOKEN_ID","tokenSecretEnv":"PVE_READ_TOKEN_SECRET","timeout":"31s"`, 1)
	if _, err := Parse([]byte(input)); err == nil || !strings.Contains(err.Error(), "pve.timeout") {
		t.Fatalf("expected bounded PVE timeout error, got %v", err)
	}
}

func TestAPISourceRequiresExactIPv4LoopbackEndpoint(t *testing.T) {
	for _, endpoint := range []string{"https://localhost:8006", "https://127.0.0.1:8006/", "https://127.0.0.1:8006/api2/json", "https://127.0.0.1:8006?x=1", "http://127.0.0.1:8006"} {
		input := strings.Replace(validTestConfig(), `"source":"disabled"`, `"source":"api","endpoint":"`+endpoint+`","tokenIdEnv":"PVE_READ_TOKEN_ID","tokenSecretEnv":"PVE_READ_TOKEN_SECRET","tlsServerName":"pve.example.test"`, 1)
		if _, err := Parse([]byte(input)); err == nil || !strings.Contains(err.Error(), "exactly") {
			t.Fatalf("unsafe API endpoint %q accepted: %v", endpoint, err)
		}
	}
}

func TestAPISourceAlwaysRejectsInsecureTLS(t *testing.T) {
	input := strings.Replace(validTestConfig(), `"source":"disabled"`, `"source":"api","endpoint":"https://127.0.0.1:8006","tokenIdEnv":"PVE_READ_TOKEN_ID","tokenSecretEnv":"PVE_READ_TOKEN_SECRET","tlsServerName":"pve.example.test","insecureSkipTls":true`, 1)
	if _, err := Parse([]byte(input)); err == nil || !strings.Contains(err.Error(), "insecureSkipTls") {
		t.Fatalf("insecure API source accepted in test mode: %v", err)
	}
}

func TestAPISourceRejectsAmbientPVEVariableNames(t *testing.T) {
	input := strings.Replace(validTestConfig(), `"source":"disabled"`, `"source":"api","endpoint":"https://127.0.0.1:8006","tokenIdEnv":"PVE_ID","tokenSecretEnv":"PVE_SECRET","tlsServerName":"pve.example.test"`, 1)
	if _, err := Parse([]byte(input)); err == nil || !strings.Contains(err.Error(), PVEReadTokenIDEnv) {
		t.Fatalf("custom PVE environment names bypassed secure overlay: %v", err)
	}
}

func TestExporterRequestTimeoutIsBoundedForWatchdogProgress(t *testing.T) {
	input := strings.Replace(validTestConfig(), `"pve": {"source":"disabled"}`, `"pve": {"source":"disabled"}, "exporters":{"node":{"enabled":true,"timeout":"31s"}}`, 1)
	if _, err := Parse([]byte(input)); err == nil || !strings.Contains(err.Error(), "exporters.node.timeout") {
		t.Fatalf("expected bounded exporter timeout error, got %v", err)
	}
}

func TestRejectsRemovedSimulatorSource(t *testing.T) {
	input := strings.Replace(validTestConfig(), `"source":"disabled"`, `"source":"simulator"`, 1)
	if _, err := Parse([]byte(input)); err == nil || !strings.Contains(err.Error(), "api or disabled") {
		t.Fatalf("removed simulator source was accepted: %v", err)
	}
}

func TestStateDirectoryAcceptsLinuxPathAndRejectsRoot(t *testing.T) {
	if !isAbsoluteNonRootPath("/var/lib/ppflight-agent") {
		t.Fatal("POSIX deployment path was rejected")
	}
	for _, value := range []string{"", "/", "relative/path"} {
		if isAbsoluteNonRootPath(value) {
			t.Fatalf("unsafe state directory %q was accepted", value)
		}
	}
}
