package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/config"
	"github.com/ppflight/ppflight-agent/internal/health"
	"github.com/ppflight/ppflight-agent/internal/store"
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

func TestMonitoringAuditHealthUsesSafeState(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	queue, err := store.Open(store.Config{Root: t.TempDir(), Destination: "monitoring-audit", Kind: store.Audit, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := queue.Enqueue("11111111-1111-4111-8111-111111111111", []byte(`{"not":"an audit batch"}`)); err != nil {
		t.Fatal(err)
	}
	registry := health.New("test", "test", "agent-test", "cluster-test", "node-test", true, true, false, now)
	registry.RegisterQueue("monitoring-audit", queue)
	registry.DeliveryState("monitoring-audit", now.Add(time.Second), false, true, fmt.Errorf("raw upstream credential detail must not leave the agent"))
	app := &App{queues: map[string]*store.Queue{"monitoring-audit": queue}, health: registry}
	state := app.monitoringAuditQueueState()
	if state.PendingItems != 1 || state.PendingBytes == 0 || !state.AuthBlocked || state.AuthBlockedSince == nil || state.LastDeliveryError != "AUTH_BLOCKED" || state.OldestObservedAt == nil || !state.OldestObservedAt.Equal(now) {
		t.Fatalf("state=%#v", state)
	}
}
