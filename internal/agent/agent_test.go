package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/ppflight/ppflight-agent/internal/config"
)

func TestSimulatorOnceCreatesSafeLocalState(t *testing.T) {
	root := t.TempDir()
	contents := fmt.Sprintf(`{
		"schemaVersion":1,
		"mode":"test",
		"identity":{"agentRef":"agent-test","collectorRef":"collector-test","sourceRef":"source-test","clusterRef":"cluster-test","nodeRef":"auto","site":"test"},
		"runtime":{"stateDirectory":%q,"listenAddress":"127.0.0.1:0","shutdownGrace":"2s","logLevel":"error"},
		"assignments":{"file":%q,"refreshUrl":"","refreshInterval":"1m"},
		"destinations":{"websiteMetering":{"enabled":false},"websiteTelemetry":{"enabled":false},"monitoring":{"enabled":false}},
		"control":{"enabled":true,"pollUrl":"","resultUrl":"","productionExecution":false}
	}`, filepath.Join(root, "state"), filepath.Join(root, "missing-assignments.json"))
	cfg, err := config.Parse([]byte(contents))
	if err != nil {
		t.Fatal(err)
	}
	app, err := New(cfg, config.Secrets{}, "test", slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Run(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if !app.health.Snapshot().Ready {
		t.Fatal("agent did not become ready")
	}
	if _, err := os.Stat(filepath.Join(root, "state", "run-state.json")); err != nil {
		t.Fatal(err)
	}
}
