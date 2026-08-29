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
  "pve": {"source":"simulator"},
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
	if cfg.PVE.Source != "simulator" || cfg.Exporters.Node.URL != "http://127.0.0.1:9100/metrics" {
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
	input = strings.Replace(input, `"source":"simulator"`, `"source":"api","endpoint":"https://127.0.0.1:8006","tokenIdEnv":"PVE_ID","tokenSecretEnv":"PVE_SECRET","insecureSkipTls":true`, 1)
	if _, err := Parse([]byte(input)); err == nil || !strings.Contains(err.Error(), "insecureSkipTls") {
		t.Fatalf("expected TLS error, got %v", err)
	}
}

func TestCountersRequireEnvironmentAtResolution(t *testing.T) {
	input := strings.Replace(validTestConfig(), `"source":"simulator"`, `"source":"api","endpoint":"https://127.0.0.1:8006","tokenIdEnv":"PVE_ID","tokenSecretEnv":"PVE_SECRET"`, 1)
	cfg, err := Parse([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	_, err = cfg.ResolveSecrets(func(name string) (string, bool) {
		if name == "PVE_ID" {
			return "monitor@pve!agent", true
		}
		return "", false
	})
	if err == nil || !strings.Contains(err.Error(), "PVE_SECRET") {
		t.Fatalf("expected missing secret error, got %v", err)
	}
}
