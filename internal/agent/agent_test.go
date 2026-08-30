package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/collector"
	"github.com/ppflight/ppflight-agent/internal/config"
	"github.com/ppflight/ppflight-agent/internal/health"
	"github.com/ppflight/ppflight-agent/internal/observation"
	"github.com/ppflight/ppflight-agent/internal/pve"
	"github.com/ppflight/ppflight-agent/internal/store"
)

func TestFixtureOnceCreatesSafeLocalState(t *testing.T) {
	root := t.TempDir()
	contents := fmt.Sprintf(`{
		"schemaVersion":1,
		"mode":"test",
		"identity":{"agentRef":"agent-test","collectorRef":"collector-test","sourceRef":"source-test","clusterRef":"cluster-test","nodeRef":"auto","site":"test"},
		"runtime":{"stateDirectory":%q,"listenAddress":"127.0.0.1:0","shutdownGrace":"2s","logLevel":"error"},
		"pve":{"source":"api","endpoint":"https://127.0.0.1:8006","tokenIdEnv":"PVE_READ_TOKEN_ID","tokenSecretEnv":"PVE_READ_TOKEN_SECRET","tlsServerName":"pve.example.test","caFile":""},
		"assignments":{"file":%q,"refreshUrl":"","refreshInterval":"1m"},
		"destinations":{"websiteMetering":{"enabled":false},"websiteTelemetry":{"enabled":false},"monitoring":{"enabled":false}},
		"control":{"enabled":true,"pollUrl":"","resultUrl":"","productionExecution":false}
	}`, filepath.Join(root, "state"), filepath.Join(root, "missing-assignments.json"))
	cfg, err := config.Parse([]byte(contents))
	if err != nil {
		t.Fatal(err)
	}
	app, err := New(cfg, testPVESecrets(), "test", slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatal(err)
	}
	app.source = &fixtureCollectionSource{cfg: cfg}
	if err := app.Run(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if !app.health.Snapshot().Ready {
		t.Fatal("agent did not become ready")
	}
	if _, err := os.Stat(filepath.Join(RuntimeStateDirectory(filepath.Join(root, "state")), "run-state.json")); err != nil {
		t.Fatal(err)
	}
}

func TestDisabledPVEConfigurationCannotStartAgent(t *testing.T) {
	cfg, err := config.Parse([]byte(`{
      "schemaVersion":1,"mode":"production",
      "identity":{"agentRef":"agent-test","collectorRef":"collector-test","sourceRef":"source-test","clusterRef":"cluster-test","nodeRef":"node-test","site":"test"},
      "runtime":{"stateDirectory":"/tmp/ppflight-agent-disabled-test","listenAddress":"127.0.0.1:19745","shutdownGrace":"2s","logLevel":"error"},
      "pve":{"source":"disabled"},
      "destinations":{"websiteMetering":{"enabled":false},"websiteTelemetry":{"enabled":false},"monitoring":{"enabled":false}},
      "control":{"enabled":false}
    }`))
	if err != nil {
		t.Fatal(err)
	}
	if app, err := New(cfg, config.Secrets{}, "test", discardedLogger()); err == nil {
		app.releaseStateLock()
		t.Fatal("disabled PVE source started an agent")
	}
}

func testPVESecrets() config.Secrets {
	return config.Secrets{PVETokenID: "agent@pve!collector", PVETokenSecret: "fixture-secret"}
}

// fixtureCollectionSource is test-only and hand-writes a small observation;
// it is not compiled into the released Agent and cannot produce an upload on
// a real node.
type fixtureCollectionSource struct{ cfg config.Config }

func (s *fixtureCollectionSource) Collect(_ context.Context, now time.Time, _ collector.Due) (observation.Snapshot, error) {
	now = now.UTC()
	return observation.Snapshot{
		SchemaVersion: 1, Mode: s.cfg.Mode, AgentRef: s.cfg.Identity.AgentRef, CollectorRef: s.cfg.Identity.CollectorRef,
		ClusterRef: s.cfg.Identity.ClusterRef, NodeRef: s.cfg.Identity.NodeRef, Site: s.cfg.Identity.Site, ObservedAt: now,
		PVEVersion: pve.Version{Version: "9.0", Release: "9.0"},
		Components: map[string]observation.Availability{
			"pve": {Available: true, ObservedAt: now},
		},
	}, nil
}

func (*fixtureCollectionSource) PVEClient() *pve.Client { return nil }

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
