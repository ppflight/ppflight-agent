package admincli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ppflight/ppflight-agent/internal/config"
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
