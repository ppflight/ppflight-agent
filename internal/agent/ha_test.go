package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/bindstate"
	"github.com/ppflight/ppflight-agent/internal/config"
	"github.com/ppflight/ppflight-agent/internal/control"
	"github.com/ppflight/ppflight-agent/internal/enrollment"
	"github.com/ppflight/ppflight-agent/internal/health"
	"github.com/ppflight/ppflight-agent/internal/inventory"
	"github.com/ppflight/ppflight-agent/internal/lifecycle"
	"github.com/ppflight/ppflight-agent/internal/monitorenrollment"
	"github.com/ppflight/ppflight-agent/internal/netpolicy"
	"github.com/ppflight/ppflight-agent/internal/store"
	"github.com/ppflight/ppflight-agent/internal/uploader"
)

const (
	firstLifecycleBootID  = "11111111-1111-4111-8111-111111111111"
	secondLifecycleBootID = "22222222-2222-4222-8222-222222222222"
)

func TestAgentRefusesDisabledPVEConfiguration(t *testing.T) {
	cfg := parseHAConfig(t, t.TempDir(), "127.0.0.1:0", true)
	cfg.Mode = "production"
	cfg.PVE.Source = "disabled"
	if app, err := New(cfg, config.Secrets{}, "0.1.0-rc.13", discardedLogger()); err == nil {
		app.releaseStateLock()
		t.Fatal("released Agent accepted disabled PVE source")
	} else if !strings.Contains(err.Error(), "collection is disabled") {
		t.Fatalf("unexpected disabled PVE failure: %v", err)
	}
}

func TestReleasedAgentRefusesTestModeWithRealAPISource(t *testing.T) {
	cfg := parseHAConfig(t, t.TempDir(), "127.0.0.1:0", false)
	if app, err := New(cfg, testPVESecrets(), "0.1.0-rc.13", discardedLogger()); err == nil {
		app.releaseStateLock()
		t.Fatal("released Agent accepted test mode")
	} else if !strings.Contains(err.Error(), "requires production mode") {
		t.Fatalf("unexpected test-mode failure: %v", err)
	}
}

func TestGracefulContextShutdownDoesNotCreatePreviousExitIncident(t *testing.T) {
	root := t.TempDir()
	cfg := parseHAConfig(t, root, "127.0.0.1:0", false)
	app, err := New(cfg, testPVESecrets(), "test", discardedLogger())
	if err != nil {
		t.Fatal(err)
	}
	app.source = &fixtureCollectionSource{cfg: cfg}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- app.Run(ctx, false) }()

	deadline := time.Now().Add(5 * time.Second)
	for app.health.Snapshot().Collection.LastAttempt == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if app.health.Snapshot().Collection.LastAttempt == nil {
		cancel()
		t.Fatal("agent did not complete its initial collection")
	}
	if competing, err := New(cfg, testPVESecrets(), "test", discardedLogger()); err == nil {
		competing.releaseStateLock()
		cancel()
		t.Fatal("a second process acquired the state directory during Run")
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("graceful shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("graceful shutdown did not complete")
	}

	// Once Run has persisted the clean marker, it releases the process lock and
	// the next process may safely enter without observing a false crash.
	second, err := New(cfg, testPVESecrets(), "test", discardedLogger())
	if err != nil {
		t.Fatalf("state lock was not released after clean shutdown: %v", err)
	}
	second.source = &fixtureCollectionSource{cfg: cfg}
	if err := second.Run(context.Background(), true); err != nil {
		t.Fatalf("second clean session: %v", err)
	}
	if website, monitoring := second.lifecycle.Pending(lifecycle.DomainWebsite), second.lifecycle.Pending(lifecycle.DomainMonitor); len(website) != 0 || len(monitoring) != 0 {
		t.Fatalf("next process observed a false incident: website=%#v monitoring=%#v", website, monitoring)
	}

	next, err := lifecycle.Begin(filepath.Join(RuntimeStateDirectory(filepath.Join(root, "state")), "lifecycle-state.json"), secondLifecycleBootID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if website, monitoring := next.Pending(lifecycle.DomainWebsite), next.Pending(lifecycle.DomainMonitor); len(website) != 0 || len(monitoring) != 0 {
		t.Fatalf("graceful shutdown was reported as an incident: website=%#v monitoring=%#v", website, monitoring)
	}
}

func TestPreviousExitQueuesBeforeListenAndCurrentListenFailureRemainsUnclean(t *testing.T) {
	root := t.TempDir()
	stateDirectory := filepath.Join(root, "state")
	runtimeStateDirectory := RuntimeStateDirectory(stateDirectory)
	startedAt := time.Date(2026, 8, 30, 1, 2, 3, 0, time.UTC)
	if _, err := lifecycle.Begin(filepath.Join(runtimeStateDirectory, "lifecycle-state.json"), firstLifecycleBootID, startedAt); err != nil {
		t.Fatal(err)
	}

	occupied, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	cfg := parseHAConfig(t, root, occupied.Addr().String(), true)
	secrets := config.Secrets{
		DeviceID:            "device-ha-test",
		MonitoringBindingID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		MonitoringAgentRef:  "monitor-agent-ha-test",
		Monitoring:          config.DestinationSecret{CredentialEpoch: 1},
	}
	secrets.PVETokenID, secrets.PVETokenSecret = testPVESecrets().PVETokenID, testPVESecrets().PVETokenSecret
	app, err := New(cfg, secrets, "test", discardedLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Run(context.Background(), false); err == nil || !strings.Contains(err.Error(), "listen on local health endpoint") {
		t.Fatalf("occupied listener error=%v", err)
	}

	for _, destination := range []string{"website-lifecycle", "monitoring-lifecycle"} {
		queue, err := store.Open(store.Config{
			Root:        filepath.Join(runtimeStateDirectory, "queues"),
			Destination: destination,
			Kind:        store.Metering,
			Policy:      store.Policy{MaxBytes: 16 << 20},
		})
		if err != nil {
			t.Fatalf("reopen %s: %v", destination, err)
		}
		items := queue.Snapshot()
		if len(items) != 1 {
			t.Fatalf("%s persistent items=%d want=1", destination, len(items))
		}
		var payload map[string]any
		if err := json.Unmarshal(items[0].Payload, &payload); err != nil {
			t.Fatalf("decode %s payload: %v", destination, err)
		}
		components, ok := payload["components"].(map[string]any)
		if !ok || len(components) != 1 {
			t.Fatalf("%s lifecycle components=%#v", destination, payload["components"])
		}
		for key := range components {
			if !strings.HasPrefix(key, "agent.previousExit.") {
				t.Fatalf("%s unexpected lifecycle component %q", destination, key)
			}
		}
	}

	// The old incident is now owned by both durable queues. The listen failure
	// itself deliberately remains running and becomes the next dual-domain
	// incident after systemd restarts the process.
	next, err := lifecycle.Begin(filepath.Join(runtimeStateDirectory, "lifecycle-state.json"), secondLifecycleBootID, startedAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	website, monitoring := next.Pending(lifecycle.DomainWebsite), next.Pending(lifecycle.DomainMonitor)
	if len(website) != 1 || len(monitoring) != 1 || website[0].EventID != monitoring[0].EventID {
		t.Fatalf("current failure was not retained for both domains: website=%#v monitoring=%#v", website, monitoring)
	}
}

func TestWatchdogCollectionProgressBoundary(t *testing.T) {
	startedAt := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	registry := health.New("test", "test", "agent-ha", "cluster-ha", "node-ha", false, false, false, startedAt)
	app := &App{cfg: config.Config{Collection: config.CollectionConfig{SampleInterval: config.Duration{Duration: 10 * time.Second}}}, health: registry}

	app.collectionActive.Store(true)
	if !app.watchdogCollectionHealthy(startedAt.Add(59*time.Second), startedAt, time.Minute) {
		t.Fatal("watchdog rejected a progressing active collection before its timeout")
	}
	if app.watchdogCollectionHealthy(startedAt.Add(time.Minute), startedAt, time.Minute) {
		t.Fatal("watchdog accepted an active collection with no progress for the full timeout")
	}

	app.collectionActive.Store(false)
	maximumSilence := 10*time.Second + time.Minute
	if !app.watchdogCollectionHealthy(startedAt.Add(maximumSilence-time.Nanosecond), startedAt, time.Minute) {
		t.Fatal("watchdog rejected the idle interval before the next scheduled collection plus timeout")
	}
	if app.watchdogCollectionHealthy(startedAt.Add(maximumSilence), startedAt, time.Minute) {
		t.Fatal("watchdog continued heartbeats after an idle collection loop exceeded its full allowance")
	}
	if !app.watchdogCollectionHealthy(startedAt.Add(48*time.Hour), startedAt, 0) {
		t.Fatal("disabled watchdog must not reject collection state")
	}
}

func TestWatchdogDeadlineUsesTheActualProgressTimestamp(t *testing.T) {
	progressAt := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	app := &App{
		cfg:                      config.Config{Collection: config.CollectionConfig{SampleInterval: config.Duration{Duration: 10 * time.Second}}},
		collectionProgressSignal: make(chan struct{}, 1),
	}
	app.collectionProgressAt.Store(progressAt.UnixNano())
	app.collectionActive.Store(true)
	if remaining := app.watchdogProgressRemaining(progressAt.Add(20*time.Second), progressAt.Add(-time.Hour), time.Minute); remaining != 40*time.Second {
		t.Fatalf("active remaining=%s want=40s", remaining)
	}
	app.collectionActive.Store(false)
	if remaining := app.watchdogProgressRemaining(progressAt.Add(20*time.Second), progressAt.Add(-time.Hour), time.Minute); remaining != 50*time.Second {
		t.Fatalf("idle remaining=%s want=50s", remaining)
	}

	before := time.Now().UTC()
	app.markCollectionProgress()
	after := time.Now().UTC()
	recorded := app.lastCollectionProgress(time.Time{})
	if recorded.Before(before) || recorded.After(after) {
		t.Fatalf("recorded progress=%s outside [%s,%s]", recorded, before, after)
	}
	select {
	case <-app.collectionProgressSignal:
	default:
		t.Fatal("progress did not wake the watchdog deadline loop")
	}
}

func TestControlAuditGateClosesOnPostPollReconcileFailureAndRecovers(t *testing.T) {
	directory := t.TempDir()
	journalDirectory := filepath.Join(directory, "journal")
	poller := &gateTestPoller{response: control.PollResponse{SchemaVersion: 1, Cursor: "cursor-1", Commands: []control.Command{}}}
	poller.onPoll = func() {
		if err := os.WriteFile(filepath.Join(journalDirectory, "corrupt.json"), []byte(`{"not":"a journal record"}`), 0o600); err != nil {
			t.Errorf("create post-poll journal failure: %v", err)
		}
	}
	service := newGateTestService(t, directory, poller)
	app := &App{
		control: service,
		health:  health.New("test", "test", "agent-ha", "cluster-ha", "node-ha", true, true, false, time.Now().UTC()),
		logger:  discardedLogger(),
	}
	app.controlAuditReady.Store(true)
	app.runControlLogged(context.Background())
	if app.controlAuditReady.Load() {
		t.Fatal("audit uploader remained open after post-poll reconciliation failed")
	}
	if poller.calls != 1 {
		t.Fatalf("poll calls=%d want=1", poller.calls)
	}
	if app.health.Snapshot().Control.LastError == "" {
		t.Fatal("post-poll reconciliation failure was not exposed in health")
	}

	if err := os.Remove(filepath.Join(journalDirectory, "corrupt.json")); err != nil {
		t.Fatal(err)
	}
	poller.onPoll = nil
	app.runControlLogged(context.Background())
	if !app.controlAuditReady.Load() {
		t.Fatal("audit uploader did not reopen after both reconciliations succeeded")
	}
	if poller.calls != 2 {
		t.Fatalf("poll calls=%d want=2", poller.calls)
	}
	if app.health.Snapshot().Control.LastError != "" {
		t.Fatalf("control health did not recover: %#v", app.health.Snapshot().Control)
	}
}

func TestControlAuditGateSerializesTheEntireUpload(t *testing.T) {
	requestStarted := make(chan struct{}, 1)
	releaseResponse := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestStarted <- struct{}{}
		<-releaseResponse
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	queue, err := store.Open(store.Config{
		Root:        t.TempDir(),
		Destination: "monitoring-audit-gate",
		Kind:        store.Audit,
		Policy:      store.Policy{MaxBytes: 1 << 20},
		Now:         func() time.Time { return time.Now().Add(-10 * time.Second) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := queue.Enqueue("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", []byte(`{"schemaVersion":1}`)); err != nil {
		t.Fatal(err)
	}
	u, err := uploader.New(uploader.Config{
		Destination:    uploader.Destination{ID: "monitoring-audit", Endpoint: server.URL, AuthMode: uploader.AuthNone, ServerIPv4Allowlist: []string{"127.0.0.1"}},
		Queue:          queue,
		HTTPClient:     server.Client(),
		BaseDelay:      time.Second,
		MaxDelay:       time.Second,
		RequestTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	app := &App{
		control: &control.Service{},
		health:  health.New("test", "test", "agent-ha", "cluster-ha", "node-ha", true, true, false, time.Now().UTC()),
	}
	app.controlAuditReady.Store(true)
	app.controlAuditGate.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		app.deliveryLoop(ctx, delivery{name: "monitoring-audit", uploader: u})
	}()
	select {
	case <-requestStarted:
		app.controlAuditGate.Unlock()
		cancel()
		close(releaseResponse)
		t.Fatal("audit upload crossed a closed control gate")
	case <-time.After(1200 * time.Millisecond):
	}
	app.controlAuditGate.Unlock()
	select {
	case <-requestStarted:
	case <-time.After(2 * time.Second):
		cancel()
		close(releaseResponse)
		t.Fatal("audit upload did not begin after the gate opened")
	}

	writerAcquired := make(chan struct{})
	go func() {
		app.controlAuditGate.Lock()
		close(writerAcquired)
		app.controlAuditGate.Unlock()
	}()
	select {
	case <-writerAcquired:
		cancel()
		close(releaseResponse)
		t.Fatal("control cycle entered while the audit request was in flight")
	case <-time.After(200 * time.Millisecond):
	}
	close(releaseResponse)
	select {
	case <-writerAcquired:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("control cycle did not resume after audit delivery completed")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("audit delivery loop did not stop")
	}
}

type gateTestPoller struct {
	response control.PollResponse
	onPoll   func()
	calls    int
}

func (p *gateTestPoller) Poll(context.Context, string) (control.PollResponse, error) {
	p.calls++
	if p.onPoll != nil {
		p.onPoll()
	}
	return p.response, nil
}

func newGateTestService(t *testing.T, directory string, poller control.Poller) *control.Service {
	t.Helper()
	journal, err := control.OpenJournal(filepath.Join(directory, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	receipts, err := store.Open(store.Config{Root: filepath.Join(directory, "queues"), Destination: "receipts", Kind: store.Metering})
	if err != nil {
		t.Fatal(err)
	}
	assignments := inventory.NewStore(inventory.Document{
		SchemaVersion: inventory.SchemaVersion,
		Revision:      "ha-test",
		IssuedAt:      time.Now().UTC(),
		Assignments:   []inventory.Assignment{},
	})
	service, err := control.NewService(control.ServiceConfig{
		AgentRef: "agent-ha", ClusterRef: "cluster-ha", Mode: "test",
		AllowedActions: []string{}, Assignments: assignments, Poller: poller,
		Journal: journal, Executor: control.Executor{Mode: "test"}, ReceiptQueue: receipts,
		CursorFile: filepath.Join(directory, "cursor.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func parseHAConfig(t *testing.T, root, listenAddress string, destinations bool) config.Config {
	t.Helper()
	destinationJSON := `
		"destinations":{
			"websiteMetering":{"enabled":false},
			"websiteTelemetry":{"enabled":false},
			"monitoring":{"enabled":false},
			"monitoringAudit":{"enabled":false}
		}`
	if destinations {
		destinationJSON = `
		"destinations":{
			"websiteMetering":{"enabled":false},
			"websiteTelemetry":{"enabled":true,"url":"http://127.0.0.1:18081/internal/v1/telemetry/batches","auth":{"mode":"none"},"payloadFormat":"telemetry-v1"},
			"monitoring":{"enabled":true,"url":"http://127.0.0.1:18082/internal/v1/monitoring/telemetry/batches","auth":{"mode":"none"},"payloadFormat":"telemetry-v1"},
			"monitoringAudit":{"enabled":false}
		}`
	}
	contents := fmt.Sprintf(`{
		"schemaVersion":1,
		"mode":"test",
		"identity":{"agentRef":"agent-ha-test","collectorRef":"collector-ha-test","sourceRef":"source-ha-test","clusterRef":"cluster-ha-test","nodeRef":"node-ha-test","site":"test"},
		"runtime":{"stateDirectory":%q,"listenAddress":%q,"shutdownGrace":"2s","logLevel":"error"},
		"pve":{"source":"api","endpoint":"https://127.0.0.1:8006","tokenIdEnv":"PVE_READ_TOKEN_ID","tokenSecretEnv":"PVE_READ_TOKEN_SECRET","tlsServerName":"pve.example.test","caFile":""},
		"assignments":{"file":%q,"refreshUrl":"","refreshInterval":"1m"},
		%s,
		"control":{"enabled":false}
	}`, filepath.Join(root, "state"), listenAddress, filepath.Join(root, "missing-assignments.json"), destinationJSON)
	cfg, err := config.Parse([]byte(contents))
	if err != nil {
		t.Fatal(err)
	}
	if destinations {
		writeHANetworkPolicies(t, cfg.Runtime.StateDirectory)
	}
	return cfg
}

func writeHANetworkPolicies(t *testing.T, stateDirectory string) {
	t.Helper()
	secret := enrollment.Secret(base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")))
	credential := enrollment.HMACCredential{KeyID: "ha-key-01", Secret: secret}
	policy := netpolicy.NetworkPolicy{AgentObservedIPv4: "127.0.0.1", ServerIPv4Allowlist: []string{"127.0.0.1"}}
	issuedAt := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)
	websiteResponse := enrollment.Response{
		SchemaVersion: enrollment.SchemaVersion, BindingID: "123e4567-e89b-42d3-a456-426614174001", DeviceID: "device-ha-test",
		AgentRef: "agent-ha-test", CollectorRef: "collector-ha-test", SourceRef: "source-ha-test", ClusterRef: "cluster-ha-test", NodeRef: "node-ha-test", Site: "test",
		Endpoints: enrollment.Endpoints{
			Metering: "http://127.0.0.1:18081/metering", Telemetry: "http://127.0.0.1:18081/internal/v1/telemetry/batches",
			Assignments: "http://127.0.0.1:18081/assignments", Commands: "http://127.0.0.1:18081/commands", Receipts: "http://127.0.0.1:18081/receipts",
		},
		HMACCredentials:          enrollment.HMACCredentials{Metering: credential, Telemetry: credential, Assignments: credential, Commands: credential, Receipts: credential},
		CommandSigningCredential: enrollment.CommandSigningCredential{KeyID: "ha-signing-key", Algorithm: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32))},
		AllowedActions:           []string{"vm.start"}, AssignmentDocument: json.RawMessage(`{"schemaVersion":1}`), NetworkPolicy: policy,
		CredentialEpoch: 1, IssuedAt: issuedAt,
	}
	if err := bindstate.Save(stateDirectory, bindstate.FromResponse("http://127.0.0.1:18081/internal/v1/agents/bind", "device-ha-test", websiteResponse)); err != nil {
		t.Fatalf("save website HA network policy: %v", err)
	}
	monitorResponse := monitorenrollment.Response{
		SchemaVersion: 1, BindingID: "123e4567-e89b-42d3-a456-426614174002", DeviceID: "device-ha-test", MonitoringAgentRef: "monitor-agent-ha-test",
		IngestEndpoint: "http://127.0.0.1:18082/internal/v1/monitoring/telemetry/batches",
		HMACCredential: monitorenrollment.HMACCredential{Algorithm: "hmac-sha256", KeyID: "monitor-key-01", SecretEncoding: "base64", Secret: secret},
		Telemetry:      monitorenrollment.TelemetryContract{PayloadFormat: "telemetry-v1", Compression: "none", MaxCompressedBytes: 64 << 20, MaxUncompressedBytes: 256 << 20},
		NetworkPolicy:  policy, CredentialEpoch: 1, IssuedAt: issuedAt,
	}
	if err := bindstate.SaveMonitoring(stateDirectory, bindstate.MonitoringFromResponse("http://127.0.0.1:18082/internal/v1/monitoring/agents/bind", "device-ha-test", monitorResponse)); err != nil {
		t.Fatalf("save monitoring HA network policy: %v", err)
	}
}

func discardedLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}
