// Package agent wires collection, durable queues, upload, control and health
// into one PVE-node service.
package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ppflight/ppflight-agent/internal/assignment"
	"github.com/ppflight/ppflight-agent/internal/auditlog"
	"github.com/ppflight/ppflight-agent/internal/bindingoverlay"
	"github.com/ppflight/ppflight-agent/internal/bindstate"
	"github.com/ppflight/ppflight-agent/internal/collector"
	"github.com/ppflight/ppflight-agent/internal/config"
	"github.com/ppflight/ppflight-agent/internal/control"
	"github.com/ppflight/ppflight-agent/internal/discovery"
	"github.com/ppflight/ppflight-agent/internal/enrollment"
	"github.com/ppflight/ppflight-agent/internal/fsutil"
	"github.com/ppflight/ppflight-agent/internal/health"
	"github.com/ppflight/ppflight-agent/internal/inventory"
	"github.com/ppflight/ppflight-agent/internal/lifecycle"
	"github.com/ppflight/ppflight-agent/internal/meter"
	"github.com/ppflight/ppflight-agent/internal/observation"
	"github.com/ppflight/ppflight-agent/internal/protocol"
	"github.com/ppflight/ppflight-agent/internal/pve"
	"github.com/ppflight/ppflight-agent/internal/runstate"
	"github.com/ppflight/ppflight-agent/internal/sdnotify"
	"github.com/ppflight/ppflight-agent/internal/selfupdate"
	"github.com/ppflight/ppflight-agent/internal/store"
	"github.com/ppflight/ppflight-agent/internal/uploader"
	"github.com/ppflight/ppflight-agent/internal/wire"
)

type delivery struct {
	name     string
	uploader *uploader.Uploader
}

type App struct {
	cfg                      config.Config
	version                  string
	logger                   *slog.Logger
	source                   collector.Source
	assignments              *inventory.Store
	assignmentClient         *assignment.Client
	assignmentMu             sync.RWMutex
	assignmentState          assignment.State
	assignmentStatePath      string
	assignmentDynamic        bool
	assignmentAuthorityScope assignment.AuthorityScope
	meter                    *meter.Manager
	runstate                 *runstate.State
	queues                   map[string]*store.Queue
	deliveries               []delivery
	control                  *control.Service
	controlAuditReady        atomic.Bool
	controlAuditGate         sync.RWMutex
	collectionProgressAt     atomic.Int64
	collectionActive         atomic.Bool
	collectionProgressSignal chan struct{}
	health                   *health.Registry
	server                   *http.Server
	stateLock                *fsutil.Lock
	lockOnce                 sync.Once
	deviceID                 string
	monitoringBindingID      string
	monitoringAgentRef       string
	monitoringEpoch          uint64
	lifecycle                *lifecycle.Session

	lastInventory time.Time
	lastGuest     time.Time
	lastHost      time.Time
	lastSMART     time.Time
	lastMeter     time.Time
	lastWebsite   time.Time
	lastMonitor   time.Time
}

func New(cfg config.Config, secrets config.Secrets, version string, logger *slog.Logger) (app *App, err error) {
	if logger == nil {
		logger = slog.Default()
	}
	if version == "" {
		version = "dev"
	}
	// There is no simulated source in a released binary.  A disabled source is
	// a durable installation/AG-preparation state only and must never create a
	// collector, queue an observation, or contact a destination.
	if version != "test" && cfg.Mode != "production" {
		return nil, errors.New("released agent requires production mode")
	}
	if cfg.PVE.Source != "api" {
		return nil, errors.New("PVE collection is disabled; use AG to complete local PVE preparation")
	}
	runtimeStateDirectory := RuntimeStateDirectory(cfg.Runtime.StateDirectory)
	if err := fsutil.EnsurePrivateDirectory(runtimeStateDirectory); err != nil {
		return nil, fmt.Errorf("open agent runtime state directory: %w", err)
	}
	stateLock, err := fsutil.AcquireExclusive(filepath.Join(runtimeStateDirectory, ".agent.lock"))
	if err != nil {
		return nil, fmt.Errorf("state directory is already in use: %w", err)
	}
	defer func() {
		if err != nil {
			_ = stateLock.Close()
		}
	}()
	usesWebsiteNetworkPolicy := cfg.Assignments.RefreshURL != "" ||
		cfg.Destinations.WebsiteMetering.Enabled || cfg.Destinations.WebsiteTelemetry.Enabled ||
		(cfg.Control.Enabled && cfg.Control.PollURL != "" && cfg.Control.ResultURL != "")
	if usesWebsiteNetworkPolicy {
		_, policyErr := bindingoverlay.WebsiteNetworkPolicy(cfg.Runtime.StateDirectory)
		if policyErr != nil {
			return nil, fmt.Errorf("load website destination network policy: %w", policyErr)
		}
	}
	if cfg.Destinations.Monitoring.Enabled || cfg.Destinations.MonitoringAudit.Enabled {
		_, policyErr := bindingoverlay.MonitoringNetworkPolicy(cfg.Runtime.StateDirectory)
		if policyErr != nil {
			return nil, fmt.Errorf("load monitoring destination network policy: %w", policyErr)
		}
	}
	assignmentStatePath := filepath.Join(cfg.Runtime.StateDirectory, "assignments", "refresh-state.json")
	authorityScope := assignment.AuthorityScope{BindingID: secrets.WebsiteBindingID, DeviceID: secrets.DeviceID, CredentialEpoch: secrets.WebsiteCredentialEpoch}
	var authority assignment.Authority
	if secrets.WebsiteBindingID != "" && secrets.DeviceID != "" && secrets.WebsiteCredentialEpoch != 0 {
		authority, err = assignment.LoadAuthority(assignmentStatePath, cfg.Identity.ClusterRef, authorityScope)
	} else {
		// Website unbind deliberately preserves inventory and every queue so the
		// independent monitoring domain can keep projecting the last assignment.
		// There is no command channel in this state, so the old scope is retained
		// only as inventory and will be removed before any future website rebind.
		authority, err = assignment.LoadAuthority(assignmentStatePath, cfg.Identity.ClusterRef)
	}
	if err != nil {
		return nil, err
	}
	assignmentState := authority.State
	effectiveAllowedActions := append([]string(nil), cfg.Control.AllowedActions...)
	var assignments *inventory.Store
	if authority.Present {
		if err := control.ValidateAllowedActions(authority.Document.AllowedActions); err != nil {
			return nil, fmt.Errorf("load assignment allowed actions: %w", err)
		}
		assignments = inventory.NewStore(authority.Document)
		effectiveAllowedActions = append([]string(nil), authority.Document.AllowedActions...)
	} else {
		assignments, err = loadAssignments(cfg)
		if err != nil {
			return nil, err
		}
	}
	source, err := collector.New(cfg, secrets)
	if err != nil {
		return nil, fmt.Errorf("create collector: %w", err)
	}
	queueRoot := filepath.Join(runtimeStateDirectory, "queues")
	queues := map[string]*store.Queue{}
	openQueue := func(name string, kind store.Kind, maxBytes int64, dropOldest bool) (*store.Queue, error) {
		queue, openErr := store.Open(store.Config{Root: queueRoot, Destination: name, Kind: kind, Policy: store.Policy{MaxBytes: maxBytes, DropOldest: dropOldest}})
		if openErr == nil {
			queues[name] = queue
		}
		return queue, openErr
	}
	meterQueue, err := openQueue("website-metering", store.Metering, cfg.Destinations.WebsiteMetering.MaxQueueBytes, false)
	if err != nil {
		return nil, err
	}
	websiteQueue, err := openQueue("website-telemetry", store.Telemetry, cfg.Destinations.WebsiteTelemetry.MaxQueueBytes, true)
	if err != nil {
		return nil, err
	}
	monitorQueue, err := openQueue("monitoring", store.Telemetry, cfg.Destinations.Monitoring.MaxQueueBytes, true)
	if err != nil {
		return nil, err
	}
	var websiteLifecycleQueue, monitoringLifecycleQueue *store.Queue
	if cfg.Destinations.WebsiteTelemetry.Enabled {
		websiteLifecycleQueue, err = openQueue("website-lifecycle", store.Metering, 16<<20, false)
		if err != nil {
			return nil, err
		}
	}
	if cfg.Destinations.Monitoring.Enabled {
		monitoringLifecycleQueue, err = openQueue("monitoring-lifecycle", store.Metering, 16<<20, false)
		if err != nil {
			return nil, err
		}
	}
	var auditQueue *store.Queue
	if cfg.Destinations.MonitoringAudit.Enabled {
		auditQueue, err = openQueue("monitoring-audit", store.Audit, cfg.Destinations.MonitoringAudit.MaxQueueBytes, false)
		if err != nil {
			return nil, err
		}
	}
	meterManager, err := meter.Open(meter.Config{
		Directory: filepath.Join(runtimeStateDirectory, "meter"), Mode: cfg.Mode,
		AgentRef: cfg.Identity.AgentRef, CollectorRef: cfg.Identity.CollectorRef,
		SourceRef: cfg.Identity.SourceRef, ClusterRef: cfg.Identity.ClusterRef,
	})
	if err != nil {
		return nil, err
	}
	if err := meterManager.Recover(meterQueue); err != nil {
		return nil, err
	}
	state, err := runstate.Open(filepath.Join(runtimeStateDirectory, "run-state.json"))
	if err != nil {
		return nil, err
	}
	var assignmentClient *assignment.Client
	if cfg.Assignments.RefreshURL != "" {
		assignmentClient, err = assignment.NewClient(assignment.Config{
			Endpoint: cfg.Assignments.RefreshURL, AgentRef: cfg.Identity.AgentRef, DeviceID: secrets.DeviceID, ClusterRef: cfg.Identity.ClusterRef,
			Credential:   enrollment.HMACCredential{KeyID: secrets.Assignments.KeyID, Secret: enrollment.Secret(base64.StdEncoding.EncodeToString(secrets.Assignments.Secret))},
			SigningKeyID: secrets.ControlSigningKeyID, SigningPublicKey: ed25519.PublicKey(secrets.ControlPublicKey),
			Wait: 25 * time.Second, Timeout: 30 * time.Second,
			AllowLoopbackHTTP: cfg.Mode == "test",
		})
		if err != nil {
			return nil, fmt.Errorf("create assignment refresh client: %w", err)
		}
	}
	var readClient *pve.Client
	if cfg.PVE.Source == "api" {
		readClient, err = pve.NewClient(pve.Config{
			Endpoint: cfg.PVE.Endpoint, TokenID: secrets.PVETokenID, TokenSecret: secrets.PVETokenSecret,
			CAFile: cfg.PVE.CAFile, TLSServerName: cfg.PVE.TLSServerName, InsecureSkipTLS: cfg.PVE.InsecureSkipTLS, Timeout: cfg.PVE.Timeout.Duration,
			MaxResponseBytes: cfg.PVE.MaxResponseBytes,
		})
		if err != nil {
			return nil, fmt.Errorf("create read-only PVE client: %w", err)
		}
	}
	configuredControl := cfg.Control.Enabled && cfg.Control.PollURL != "" && cfg.Control.ResultURL != ""
	registry := health.New(version, cfg.Mode, cfg.Identity.AgentRef, cfg.Identity.ClusterRef, cfg.Identity.NodeRef, cfg.Control.Enabled, configuredControl, cfg.Control.ProductionExecution, time.Now())
	registry.Bindings(secrets.DeviceID, secrets.WebsiteBindingID, secrets.WebsiteCredentialEpoch, secrets.MonitoringBindingID, secrets.Monitoring.CredentialEpoch)
	for name, queue := range queues {
		registry.RegisterQueue(name, queue)
	}
	document := assignments.Snapshot()
	registry.Assignment(document.Revision, len(document.Assignments))
	app = &App{cfg: cfg, version: version, logger: logger, source: source, assignments: assignments, assignmentClient: assignmentClient, assignmentState: assignmentState, assignmentStatePath: assignmentStatePath, assignmentDynamic: authority.Present, assignmentAuthorityScope: authorityScope, meter: meterManager, runstate: state, queues: queues, health: registry, stateLock: stateLock, collectionProgressSignal: make(chan struct{}, 1),
		deviceID: secrets.DeviceID, monitoringBindingID: secrets.MonitoringBindingID, monitoringAgentRef: secrets.MonitoringAgentRef, monitoringEpoch: secrets.Monitoring.CredentialEpoch}
	app.markCollectionProgress()
	if progressSource, ok := source.(collector.ProgressSource); ok {
		progressSource.SetProgressReporter(app.markCollectionProgress)
	}
	if cfg.Destinations.WebsiteMetering.Enabled {
		d, err := newDelivery("website-metering", cfg.Destinations.WebsiteMetering, secrets.WebsiteMetering, meterQueue)
		if err != nil {
			return nil, err
		}
		app.deliveries = append(app.deliveries, d)
	}
	if cfg.Destinations.WebsiteTelemetry.Enabled {
		d, err := newDelivery("website-telemetry", cfg.Destinations.WebsiteTelemetry, secrets.WebsiteTelemetry, websiteQueue)
		if err != nil {
			return nil, err
		}
		app.deliveries = append(app.deliveries, d)
		lifecycleDelivery, lifecycleErr := newDelivery("website-lifecycle", cfg.Destinations.WebsiteTelemetry, secrets.WebsiteTelemetry, websiteLifecycleQueue)
		if lifecycleErr != nil {
			return nil, lifecycleErr
		}
		app.deliveries = append(app.deliveries, lifecycleDelivery)
	}
	if cfg.Destinations.Monitoring.Enabled {
		d, err := newDelivery("monitoring", cfg.Destinations.Monitoring, secrets.Monitoring, monitorQueue)
		if err != nil {
			return nil, err
		}
		app.deliveries = append(app.deliveries, d)
		lifecycleDelivery, lifecycleErr := newDelivery("monitoring-lifecycle", cfg.Destinations.Monitoring, secrets.Monitoring, monitoringLifecycleQueue)
		if lifecycleErr != nil {
			return nil, lifecycleErr
		}
		app.deliveries = append(app.deliveries, lifecycleDelivery)
	}
	var auditSink auditlog.Sink
	if auditQueue != nil {
		queueSink, sinkErr := auditlog.NewQueueSink(auditlog.QueueSinkConfig{
			Queue: auditQueue,
			Builder: auditlog.BatchBuilder{
				MonitoringAgentRef: secrets.MonitoringAgentRef,
				DeviceID:           secrets.DeviceID,
				CredentialEpoch:    secrets.MonitoringAudit.CredentialEpoch,
				BootID:             state.BootID(),
				AgentVersion:       version,
				NextSequence:       state.NextMonitoringAudit,
			},
			DeliveryState: app.auditDeliveryState,
		})
		if sinkErr != nil {
			return nil, fmt.Errorf("create monitoring audit sink: %w", sinkErr)
		}
		auditSink = queueSink
		d, deliveryErr := newDelivery("monitoring-audit", cfg.Destinations.MonitoringAudit, secrets.MonitoringAudit, auditQueue)
		if deliveryErr != nil {
			return nil, deliveryErr
		}
		app.deliveries = append(app.deliveries, d)
	}
	if configuredControl {
		controlQueue, openErr := openQueue("control-results", store.Metering, 64<<20, false)
		if openErr != nil {
			return nil, openErr
		}
		registry.RegisterQueue("control-results", controlQueue)
		poller, clientErr := control.NewClient(control.ClientConfig{
			Endpoint: cfg.Control.PollURL, AgentRef: cfg.Identity.AgentRef, Limit: cfg.Control.MaxCommandsPerPoll,
			AuthMode: uploader.AuthMode(cfg.Control.Auth.Mode), KeyID: secrets.ControlAPI.KeyID,
			Secret: secrets.ControlAPI.Secret, BearerToken: secrets.ControlAPI.Bearer,
			Timeout: cfg.Control.RequestTimeout.Duration,
		})
		if clientErr != nil {
			return nil, clientErr
		}
		journal, journalErr := control.OpenJournal(filepath.Join(runtimeStateDirectory, "control", "journal"))
		if journalErr != nil {
			return nil, journalErr
		}
		var writeClient *pve.Client
		if cfg.Control.ProductionExecution {
			writeClient, err = pve.NewClient(pve.Config{
				Endpoint: cfg.PVE.Endpoint, TokenID: secrets.ControlPVETokenID, TokenSecret: secrets.ControlPVETokenSecret,
				CAFile: cfg.PVE.CAFile, TLSServerName: cfg.PVE.TLSServerName, InsecureSkipTLS: false, Timeout: cfg.Control.RequestTimeout.Duration,
				MaxResponseBytes: cfg.PVE.MaxResponseBytes,
			})
			if err != nil {
				return nil, fmt.Errorf("create control PVE client: %w", err)
			}
		}
		upgradeSubmitter, upgradeErr := selfupdate.New(selfupdate.Config{
			StateDirectory: cfg.Runtime.StateDirectory, WebsiteEndpoint: cfg.Control.PollURL, CurrentVersion: version,
		})
		if upgradeErr != nil {
			return nil, fmt.Errorf("create self-update coordinator: %w", upgradeErr)
		}
		consoleSink, consoleErr := control.NewHTTPSConsoleSessionSink(cfg.Control.ResultURL, secrets.ControlReceipts.KeyID, secrets.ControlReceipts.Secret, cfg.Control.RequestTimeout.Duration)
		if consoleErr != nil {
			return nil, fmt.Errorf("create console session broker: %w", consoleErr)
		}
		service, serviceErr := control.NewService(control.ServiceConfig{
			AgentRef: cfg.Identity.AgentRef, ClusterRef: cfg.Identity.ClusterRef,
			BindingID: secrets.WebsiteBindingID, DeviceID: secrets.DeviceID, CredentialEpoch: secrets.WebsiteCredentialEpoch,
			AssignmentRevision: app.currentAssignmentRevision, AssignmentAuthorityDynamic: authority.Present,
			AgentVersion: version, AuditSink: auditSink, Mode: cfg.Mode,
			CommandSecret: secrets.ControlCommandSecret, CommandSigningKeyID: secrets.ControlSigningKeyID,
			CommandPublicKey: ed25519.PublicKey(secrets.ControlPublicKey), AllowedActions: effectiveAllowedActions,
			Assignments: assignments, Poller: poller, Journal: journal,
			UpgradeResolver: upgradeSubmitter,
			Executor: control.Executor{
				Client: writeClient, ReadClient: readClient, Discovery: discovery.New(readClient),
				Mode: cfg.Mode, ProductionExecution: cfg.Control.ProductionExecution, UpgradeSubmitter: upgradeSubmitter,
				ConsoleSessions: consoleSink,
			},
			ReceiptQueue: controlQueue, CursorFile: filepath.Join(runtimeStateDirectory, "control", "cursor.json"),
		})
		if serviceErr != nil {
			return nil, serviceErr
		}
		app.control = service
		resultDestination := config.DestinationConfig{Enabled: true, URL: cfg.Control.ResultURL, Auth: cfg.Control.Auth, Timeout: cfg.Control.RequestTimeout, MaxResponseBytes: 2 << 20, MaxQueueBytes: 64 << 20, Compression: "none", PayloadFormat: "control-receipt-v1"}
		d, deliveryErr := newDelivery("control-results", resultDestination, secrets.ControlReceipts, controlQueue)
		if deliveryErr != nil {
			return nil, deliveryErr
		}
		app.deliveries = append(app.deliveries, d)
	}
	app.server = &http.Server{
		Addr: cfg.Runtime.ListenAddress, Handler: registry.Handler(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second,
	}
	return app, nil
}

func loadAssignments(cfg config.Config) (*inventory.Store, error) {
	document, err := inventory.LoadFile(cfg.Assignments.File, cfg.Identity.ClusterRef)
	if err == nil {
		return inventory.NewStore(document), nil
	}
	if cfg.Mode == "production" || !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("load assignments: %w", err)
	}
	return inventory.NewStore(inventory.Document{SchemaVersion: inventory.SchemaVersion, Revision: "empty-test", IssuedAt: time.Now().UTC(), Assignments: []inventory.Assignment{}}), nil
}

// RuntimeStateDirectory is the only service-user-owned subtree below the
// root-owned state root. Privileged binding and upgrade state remain siblings,
// so the unprivileged service cannot rename or replace them.
func RuntimeStateDirectory(stateRoot string) string {
	return filepath.Join(stateRoot, "agent")
}

func newDelivery(name string, cfg config.DestinationConfig, secret config.DestinationSecret, queue *store.Queue) (delivery, error) {
	instance, err := uploader.New(uploader.Config{
		Destination: uploader.Destination{ID: name, Endpoint: cfg.URL, AuthMode: uploader.AuthMode(cfg.Auth.Mode), KeyID: secret.KeyID, Secret: secret.Secret, BearerToken: secret.Bearer, CredentialEpoch: secret.CredentialEpoch, Compression: cfg.Compression},
		Queue:       queue, RequestTimeout: cfg.Timeout.Duration, MaxResponseBytes: cfg.MaxResponseBytes,
		MaxCompressedBytes: cfg.MaxCompressedBytes, MaxUncompressedBytes: cfg.MaxUncompressedBytes,
	})
	if err != nil {
		return delivery{}, fmt.Errorf("create %s uploader: %w", name, err)
	}
	return delivery{name: name, uploader: instance}, nil
}

func (a *App) monitoringAgentHealth() wire.MonitoringAgentHealth {
	return wire.MonitoringAgentHealth{AuditQueue: a.monitoringAuditQueueState()}
}

func (a *App) monitoringAuditQueueState() wire.MonitoringQueueState {
	queue := a.queues["monitoring-audit"]
	if queue == nil {
		return wire.MonitoringQueueState{}
	}
	stats := queue.Stats()
	state := wire.MonitoringQueueState{
		PendingItems:    protocol.Counter(max(int64(stats.PendingItems), 0)),
		PendingBytes:    protocol.Counter(max(stats.PendingBytes, 0)),
		DeadLetterItems: protocol.Counter(stats.DeadLetterItems),
		DroppedItems:    protocol.Counter(stats.DroppedItems),
	}
	if a.health != nil {
		deliveryState := a.health.Snapshot().Deliveries["monitoring-audit"]
		state.AuthBlocked = deliveryState.AuthBlocked
		if deliveryState.AuthBlockedSince != nil {
			value := deliveryState.AuthBlockedSince.UTC()
			state.AuthBlockedSince = &value
		}
		if deliveryState.AuthBlocked {
			state.LastDeliveryError = auditlog.DeliveryErrorAuthBlocked
		} else if deliveryState.LastError != "" {
			state.LastDeliveryError = auditlog.DeliveryErrorFailed
		}
	}
	if items := queue.Snapshot(); len(items) > 0 {
		observedAt := items[0].CreatedAt.UTC()
		var batch auditlog.Batch
		if err := json.Unmarshal(items[0].Payload, &batch); err == nil {
			observedAt = batch.ObservedAt.UTC()
		}
		state.OldestObservedAt = &observedAt
	}
	return state
}

func (a *App) auditDeliveryState() auditlog.DeliveryState {
	state := a.monitoringAuditQueueState()
	return auditlog.DeliveryState{
		PendingItems:      state.PendingItems,
		PendingBytes:      state.PendingBytes,
		LastDeliveryError: state.LastDeliveryError,
		AuthBlocked:       state.AuthBlocked,
		AuthBlockedSince:  state.AuthBlockedSince,
		OldestObservedAt:  state.OldestObservedAt,
	}
}

func (a *App) Run(ctx context.Context, once bool) error {
	defer a.releaseStateLock()
	session, err := lifecycle.Begin(filepath.Join(RuntimeStateDirectory(a.cfg.Runtime.StateDirectory), "lifecycle-state.json"), a.runstate.BootID(), time.Now().UTC())
	if err != nil {
		return fmt.Errorf("begin agent lifecycle session: %w", err)
	}
	a.lifecycle = session
	err = a.run(ctx, once)
	if err != nil {
		// Leave the session in running state. systemd restarts the process and
		// the next boot turns it into a durable previous-exit incident.
		return err
	}
	return session.MarkClean(time.Now().UTC())
}

func (a *App) run(ctx context.Context, once bool) error {
	// Queue evidence of the previous unclean exit before touching PVE. A broken
	// or hung PVE API must not prevent the HA incident from reaching either
	// independently bound trust domain after this process comes back.
	startupAt := time.Now().UTC()
	if err := a.enqueueLifecycleTelemetry(a.lifecycleBaseSnapshot(startupAt), startupAt); err != nil {
		a.logger.Warn("queue previous agent exit incident", "error", safeLogError(err))
	}
	if once {
		_, refreshErr := a.refreshAssignments(ctx)
		err := errors.Join(refreshErr, a.sample(ctx, time.Now().UTC()))
		if a.control != nil {
			a.controlAuditGate.Lock()
			a.controlAuditReady.Store(false)
			_, reconcileErr := a.control.ReconcileOnce(ctx)
			var controlErr, reconcileAfterErr error
			if reconcileErr == nil {
				_, controlErr = a.control.PollOnce(ctx)
				_, reconcileAfterErr = a.control.ReconcileOnce(ctx)
				if reconcileAfterErr == nil {
					a.controlAuditReady.Store(true)
				}
			}
			a.controlAuditGate.Unlock()
			a.health.ControlPoll(time.Now(), errors.Join(reconcileErr, controlErr, reconcileAfterErr))
			err = errors.Join(err, reconcileErr, controlErr, reconcileAfterErr)
		}
		for _, item := range a.deliveries {
			locked := item.name == "monitoring-audit" && a.control != nil
			if locked {
				a.controlAuditGate.RLock()
				if !a.controlAuditReady.Load() {
					a.controlAuditGate.RUnlock()
					continue
				}
			}
			result := item.uploader.DeliverOne(ctx)
			if locked {
				a.controlAuditGate.RUnlock()
			}
			a.health.DeliveryState(item.name, time.Now(), result.Delivered, result.AuthBlocked, result.Err)
			err = errors.Join(err, result.Err)
		}
		return err
	}
	// The audit uploader remains gated until the control loop has reconciled its
	// durable journal. Other trust domains and lifecycle incident delivery must
	// start even when the control journal is degraded.
	notifier, err := sdnotify.New()
	if err != nil {
		return fmt.Errorf("initialize systemd supervision: %w", err)
	}
	listener, err := net.Listen("tcp4", a.server.Addr)
	if err != nil {
		return fmt.Errorf("listen on local health endpoint: %w", err)
	}
	serverErrors := make(chan error, 1)
	go func() {
		err := a.server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
		}
	}()
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	watchdogErrors := make(chan error, 1)
	if notifier.WatchdogInterval() > 0 {
		if err := notifier.Watchdog(); err != nil {
			_ = listener.Close()
			return fmt.Errorf("notify initial systemd watchdog heartbeat: %w", err)
		}
	}
	a.markCollectionProgress()
	if err := notifier.Ready(); err != nil {
		_ = listener.Close()
		return fmt.Errorf("notify systemd that the agent is ready: %w", err)
	}
	var workers sync.WaitGroup
	workers.Add(1)
	go func() { defer workers.Done(); a.collectionLoop(workerCtx) }()
	workers.Add(1)
	go func() { defer workers.Done(); a.assignmentLoop(workerCtx) }()
	for _, item := range a.deliveries {
		item := item
		workers.Add(1)
		go func() { defer workers.Done(); a.deliveryLoop(workerCtx, item) }()
	}
	if a.control != nil {
		workers.Add(1)
		go func() { defer workers.Done(); a.controlLoop(workerCtx) }()
	}
	if notifier.WatchdogInterval() > 0 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			a.watchdogLoop(workerCtx, notifier, time.Now().UTC(), watchdogErrors)
		}()
	}
	var runErr error
	select {
	case <-ctx.Done():
	case err := <-serverErrors:
		runErr = err
	case err := <-watchdogErrors:
		runErr = err
	}
	cancel()
	if err := notifier.Stopping(); err != nil {
		a.logger.Warn("notify systemd that the agent is stopping", "error", safeLogError(err))
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), a.cfg.Runtime.ShutdownGrace.Duration)
	defer shutdownCancel()
	_ = a.server.Shutdown(shutdownCtx)
	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	select {
	case <-done:
		return runErr
	case <-shutdownCtx.Done():
		return shutdownCtx.Err()
	}
}

func (a *App) lifecycleBaseSnapshot(now time.Time) observation.Snapshot {
	return observation.Snapshot{
		SchemaVersion: 1,
		Mode:          a.cfg.Mode,
		AgentRef:      a.cfg.Identity.AgentRef,
		CollectorRef:  a.cfg.Identity.CollectorRef,
		ClusterRef:    a.cfg.Identity.ClusterRef,
		NodeRef:       a.cfg.Identity.NodeRef,
		Site:          a.cfg.Identity.Site,
		ObservedAt:    now.UTC(),
		Components:    map[string]observation.Availability{},
		Nodes:         []observation.Node{},
		Storages:      []observation.Storage{},
		Tasks:         []observation.Task{},
		Guests:        []observation.Guest{},
	}
}

func (a *App) watchdogLoop(ctx context.Context, notifier *sdnotify.Notifier, startedAt time.Time, failures chan<- error) {
	interval := notifier.WatchdogInterval()
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	deadline := time.NewTimer(a.watchdogProgressRemaining(time.Now().UTC(), startedAt, notifier.WatchdogTimeout()))
	defer deadline.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.collectionProgressSignal:
			resetTimer(deadline, a.watchdogProgressRemaining(time.Now().UTC(), startedAt, notifier.WatchdogTimeout()))
		case now := <-deadline.C:
			lastProgressAt := a.lastCollectionProgress(startedAt)
			if !a.watchdogCollectionHealthy(now.UTC(), lastProgressAt, notifier.WatchdogTimeout()) {
				select {
				case failures <- errors.New("collection loop stopped making progress"):
				default:
				}
				return
			}
			resetTimer(deadline, a.watchdogProgressRemaining(now.UTC(), startedAt, notifier.WatchdogTimeout()))
		case now := <-ticker.C:
			if !a.watchdogCollectionHealthy(now.UTC(), a.lastCollectionProgress(startedAt), notifier.WatchdogTimeout()) {
				select {
				case failures <- errors.New("collection loop stopped making progress"):
				default:
				}
				return
			}
			if err := notifier.Watchdog(); err != nil {
				select {
				case failures <- fmt.Errorf("send systemd watchdog heartbeat: %w", err):
				default:
				}
				return
			}
		}
	}
}

func (a *App) lastCollectionProgress(fallback time.Time) time.Time {
	nanoseconds := a.collectionProgressAt.Load()
	if nanoseconds <= 0 {
		return fallback.UTC()
	}
	return time.Unix(0, nanoseconds).UTC()
}

func (a *App) watchdogProgressRemaining(now, fallback time.Time, watchdogTimeout time.Duration) time.Duration {
	if watchdogTimeout <= 0 {
		return time.Hour
	}
	lastProgressAt := a.lastCollectionProgress(fallback)
	maximumSilence := watchdogTimeout
	if !a.collectionActive.Load() {
		maximumSilence += a.cfg.Collection.SampleInterval.Duration
	}
	remaining := lastProgressAt.Add(maximumSilence).Sub(now)
	if remaining <= 0 {
		return time.Nanosecond
	}
	return remaining
}

func resetTimer(timer *time.Timer, duration time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(duration)
}

func (a *App) watchdogCollectionHealthy(now, lastProgressAt time.Time, watchdogTimeout time.Duration) bool {
	if watchdogTimeout <= 0 {
		return true
	}
	maximumSilence := watchdogTimeout
	if !a.collectionActive.Load() {
		maximumSilence += a.cfg.Collection.SampleInterval.Duration
	}
	return now.Sub(lastProgressAt) < maximumSilence
}

func (a *App) markCollectionProgress() {
	a.collectionProgressAt.Store(time.Now().UTC().UnixNano())
	if a.collectionProgressSignal != nil {
		select {
		case a.collectionProgressSignal <- struct{}{}:
		default:
		}
	}
}

func (a *App) releaseStateLock() {
	if a.stateLock == nil {
		return
	}
	a.lockOnce.Do(func() {
		if err := a.stateLock.Close(); err != nil {
			a.logger.Warn("release state directory lock", "error", err)
		}
	})
}

func (a *App) collectionLoop(ctx context.Context) {
	a.runSampleLogged(ctx)
	ticker := time.NewTicker(a.cfg.Collection.SampleInterval.Duration)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			a.runSampleLogged(ctx, now.UTC())
		}
	}
}

func (a *App) runSampleLogged(ctx context.Context, now ...time.Time) {
	timestamp := time.Now().UTC()
	if len(now) > 0 {
		timestamp = now[0]
	}
	a.collectionActive.Store(true)
	a.markCollectionProgress()
	err := a.sample(ctx, timestamp)
	a.collectionActive.Store(false)
	a.markCollectionProgress()
	if err != nil {
		a.logger.Warn("collection cycle degraded", "error", safeLogError(err))
	}
}

func lifecycleSnapshot(snapshot observation.Snapshot, incidents []lifecycle.Incident) observation.Snapshot {
	result := snapshot
	result.Components = make(map[string]observation.Availability, len(incidents))
	for _, incident := range incidents {
		result.Components["agent.previousExit."+incident.EventID] = observation.Availability{
			Available: false, ObservedAt: incident.ObservedAt.UTC(), UnavailableReason: "previous_unclean_exit",
		}
	}
	// Missing collections mean "not included", never delete. Keeping this
	// critical batch component-only avoids replaying stale VM state.
	result.Nodes = []observation.Node{}
	result.Storages = []observation.Storage{}
	result.Tasks = []observation.Task{}
	result.Guests = []observation.Guest{}
	result.Host, result.SMART = nil, nil
	return result
}

func (a *App) enqueueLifecycleTelemetry(snapshot observation.Snapshot, now time.Time) error {
	if a.lifecycle == nil {
		return nil
	}
	var result error
	if incidents := a.lifecycle.Pending(lifecycle.DomainWebsite); len(incidents) > 0 && a.cfg.Destinations.WebsiteTelemetry.Enabled {
		sequence, err := a.runstate.NextWebsite()
		if err == nil {
			var batch wire.WebsiteTelemetryBatch
			batch, err = wire.BuildWebsiteTelemetryAtForAgent(lifecycleSnapshot(snapshot, incidents), a.assignments, a.cfg.Identity.SourceRef, a.version, sequence, now)
			if err == nil {
				var raw []byte
				raw, err = json.Marshal(batch)
				if err == nil {
					_, _, err = a.queues["website-lifecycle"].Enqueue(batch.BatchID, raw)
				}
			}
		}
		if err == nil {
			err = a.lifecycle.MarkQueued(lifecycle.DomainWebsite)
		}
		result = errors.Join(result, err)
	}
	if incidents := a.lifecycle.Pending(lifecycle.DomainMonitor); len(incidents) > 0 && a.cfg.Destinations.Monitoring.Enabled {
		sequence, err := a.runstate.NextMonitoring()
		if err == nil {
			critical := lifecycleSnapshot(snapshot, incidents)
			var batchID string
			var raw []byte
			if a.cfg.Destinations.Monitoring.PayloadFormat == "telemetry-v1" {
				var batch wire.MonitoringTelemetryBatch
				batch, err = wire.BuildMonitoringTelemetry(critical, a.assignments, wire.MonitoringBuildContext{
					BindingID: a.monitoringBindingID, MonitoringAgentRef: a.monitoringAgentRef, DeviceID: a.deviceID,
					CredentialEpoch: a.monitoringEpoch, BootID: a.runstate.BootID(), Sequence: sequence,
					AgentVersion: a.version, SourceRef: a.cfg.Identity.SourceRef, SentAt: now, AgentHealth: a.monitoringAgentHealth(),
				})
				batchID = batch.BatchID
				if err == nil {
					raw, err = json.Marshal(batch)
				}
			} else {
				var batch wire.LegacyEnvelope
				batch, err = wire.BuildLegacy(critical, a.assignments, a.runstate.BootID(), sequence, a.version, now)
				batchID = batch.BatchID
				if err == nil {
					raw, err = json.Marshal(batch)
				}
			}
			if err == nil {
				_, _, err = a.queues["monitoring-lifecycle"].Enqueue(batchID, raw)
			}
		}
		if err == nil {
			err = a.lifecycle.MarkQueued(lifecycle.DomainMonitor)
		}
		result = errors.Join(result, err)
	}
	return result
}

func (a *App) sample(ctx context.Context, now time.Time) error {
	due := collector.Due{
		Inventory: a.lastInventory.IsZero() || now.Sub(a.lastInventory) >= a.cfg.Collection.InventoryInterval.Duration,
		Guest:     a.lastGuest.IsZero() || now.Sub(a.lastGuest) >= a.cfg.Collection.GuestInterval.Duration,
		Host:      a.lastHost.IsZero() || now.Sub(a.lastHost) >= a.cfg.Collection.MonitoringInterval.Duration,
		SMART:     a.lastSMART.IsZero() || now.Sub(a.lastSMART) >= a.cfg.Collection.SMARTInterval.Duration,
	}
	snapshot, collectionErr := a.source.Collect(ctx, now, due)
	a.health.Collection(now, collectionErr)
	if due.Inventory {
		a.lastInventory = now
	}
	if due.Guest {
		a.lastGuest = now
	}
	if due.Host {
		a.lastHost = now
	}
	if due.SMART {
		a.lastSMART = now
	}
	var cycleErr error
	cycleErr = errors.Join(cycleErr, collectionErr)
	cycleErr = errors.Join(cycleErr, a.enqueueLifecycleTelemetry(snapshot, now))
	if a.lastMeter.IsZero() || now.Sub(a.lastMeter) >= a.cfg.Collection.MeteringInterval.Duration {
		_, _, err := a.meter.Observe(snapshot, a.assignments, a.queues["website-metering"])
		if err == nil {
			a.lastMeter = now
		} else {
			cycleErr = errors.Join(cycleErr, fmt.Errorf("metering: %w", err))
		}
	}
	if a.cfg.Destinations.WebsiteTelemetry.Enabled && (a.lastWebsite.IsZero() || now.Sub(a.lastWebsite) >= a.cfg.Collection.MonitoringInterval.Duration) {
		sequence, err := a.runstate.NextWebsite()
		if err == nil {
			var batch wire.WebsiteTelemetryBatch
			batch, err = wire.BuildWebsiteTelemetryForAgent(snapshot, a.assignments, a.cfg.Identity.SourceRef, a.version, sequence)
			if err == nil {
				var raw []byte
				raw, err = json.Marshal(batch)
				if err == nil {
					_, _, err = a.queues["website-telemetry"].Enqueue(batch.BatchID, raw)
				}
			}
		}
		if err == nil {
			a.lastWebsite = now
		} else {
			cycleErr = errors.Join(cycleErr, fmt.Errorf("website telemetry: %w", err))
		}
	}
	if a.cfg.Destinations.Monitoring.Enabled && (a.lastMonitor.IsZero() || now.Sub(a.lastMonitor) >= a.cfg.Collection.MonitoringInterval.Duration) {
		sequence, err := a.runstate.NextMonitoring()
		if err == nil {
			var batchID string
			var raw []byte
			if a.cfg.Destinations.Monitoring.PayloadFormat == "telemetry-v1" {
				var batch wire.MonitoringTelemetryBatch
				batch, err = wire.BuildMonitoringTelemetry(snapshot, a.assignments, wire.MonitoringBuildContext{
					BindingID: a.monitoringBindingID, MonitoringAgentRef: a.monitoringAgentRef, DeviceID: a.deviceID,
					CredentialEpoch: a.monitoringEpoch, BootID: a.runstate.BootID(), Sequence: sequence,
					AgentVersion: a.version, SourceRef: a.cfg.Identity.SourceRef, SentAt: now,
					AgentHealth: a.monitoringAgentHealth(),
				})
				batchID = batch.BatchID
				if err == nil {
					raw, err = json.Marshal(batch)
				}
			} else {
				var batch wire.LegacyEnvelope
				batch, err = wire.BuildLegacy(snapshot, a.assignments, a.runstate.BootID(), sequence, a.version, now)
				batchID = batch.BatchID
				if err == nil {
					raw, err = json.Marshal(batch)
				}
			}
			if err == nil {
				_, _, err = a.queues["monitoring"].Enqueue(batchID, raw)
			}
		}
		if err == nil {
			a.lastMonitor = now
		} else {
			cycleErr = errors.Join(cycleErr, fmt.Errorf("monitoring telemetry: %w", err))
		}
	}
	return cycleErr
}

func (a *App) assignmentLoop(ctx context.Context) {
	if a.assignmentClient != nil {
		a.remoteAssignmentLoop(ctx)
		return
	}
	ticker := time.NewTicker(a.cfg.Assignments.RefreshInterval.Duration)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			document, err := inventory.LoadFile(a.cfg.Assignments.File, a.cfg.Identity.ClusterRef)
			if err != nil {
				a.logger.Warn("assignment refresh rejected; previous revision retained", "error", safeLogError(err))
				continue
			}
			a.assignments.Replace(document)
			a.health.Assignment(document.Revision, len(document.Assignments))
		}
	}
}

func (a *App) remoteAssignmentLoop(ctx context.Context) {
	for {
		changed, err := a.refreshAssignments(ctx)
		if ctx.Err() != nil {
			return
		}
		delay := 250 * time.Millisecond
		if err != nil {
			a.logger.Warn("remote assignment refresh rejected; previous revision retained", "error", safeLogError(err))
			delay = a.cfg.Assignments.RefreshInterval.Duration
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
		} else if changed {
			a.logger.Info("assignment revision advanced", "revision", a.currentAssignmentRevision())
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (a *App) refreshAssignments(ctx context.Context) (bool, error) {
	if a.assignmentClient == nil {
		return false, nil
	}
	a.assignmentMu.RLock()
	previous := a.assignmentState
	dynamic := a.assignmentDynamic
	a.assignmentMu.RUnlock()
	result, err := a.assignmentClient.Refresh(ctx, previous)
	if errors.Is(err, assignment.ErrNoChange) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if result.Document.AllowedActions != nil {
		if err := control.ValidateAllowedActions(result.Document.AllowedActions); err != nil {
			return false, fmt.Errorf("validate refreshed assignment allowed actions: %w", err)
		}
		if err := assignment.SaveAuthority(a.assignmentStatePath, result.State, result.DocumentRaw, a.cfg.Identity.ClusterRef, a.assignmentAuthorityScope); err != nil {
			return false, fmt.Errorf("persist refreshed assignment authority: %w", err)
		}
		// This file remains for tooling and legacy readers. Version-2 runtimes
		// restart from the already-durable authority snapshot, so a failure here
		// cannot create a mixed revision/action/inventory authority.
		if err := bindstate.WriteAssignment(a.cfg.Assignments.File, result.DocumentRaw); err != nil {
			a.logger.Warn("assignment compatibility file refresh failed; atomic authority remains active", "error", safeLogError(err))
		}
		if a.control != nil {
			if err := a.control.ApplyAssignmentAuthority(result.Document, result.State.Revision, result.Document.AllowedActions); err != nil {
				return false, fmt.Errorf("apply refreshed assignment authority: %w", err)
			}
		} else {
			a.assignments.Replace(result.Document)
		}
		dynamic = true
	} else {
		if dynamic {
			return false, errors.New("refreshed assignment authority omitted allowedActions")
		}
		if err := bindstate.WriteAssignment(a.cfg.Assignments.File, result.DocumentRaw); err != nil {
			return false, fmt.Errorf("persist refreshed assignments: %w", err)
		}
		if err := assignment.SaveState(a.assignmentStatePath, result.State); err != nil {
			return false, fmt.Errorf("persist assignment refresh cursor: %w", err)
		}
		a.assignments.Replace(result.Document)
	}
	a.assignmentMu.Lock()
	a.assignmentState = result.State
	a.assignmentDynamic = dynamic
	a.assignmentMu.Unlock()
	a.health.Assignment(result.Document.Revision, len(result.Document.Assignments))
	return true, nil
}

func (a *App) currentAssignmentRevision() uint64 {
	a.assignmentMu.RLock()
	defer a.assignmentMu.RUnlock()
	return a.assignmentState.Revision
}

func (a *App) deliveryLoop(ctx context.Context, item delivery) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			locked := item.name == "monitoring-audit" && a.control != nil
			if locked {
				a.controlAuditGate.RLock()
				if !a.controlAuditReady.Load() {
					a.controlAuditGate.RUnlock()
					continue
				}
			}
			result := item.uploader.DeliverOne(ctx)
			if locked {
				a.controlAuditGate.RUnlock()
			}
			if result.BatchID != "" {
				a.health.DeliveryState(item.name, time.Now(), result.Delivered, result.AuthBlocked, result.Err)
			}
		}
	}
}

func (a *App) controlLoop(ctx context.Context) {
	a.runControlLogged(ctx)
	ticker := time.NewTicker(a.cfg.Control.PollInterval.Duration)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.runControlLogged(ctx)
		}
	}
}
func (a *App) runControlLogged(ctx context.Context) {
	a.controlAuditGate.Lock()
	defer a.controlAuditGate.Unlock()
	a.controlAuditReady.Store(false)
	reconciledBefore, reconcileBeforeErr := a.control.ReconcileOnce(ctx)
	if reconcileBeforeErr != nil {
		a.health.ControlPoll(time.Now(), reconcileBeforeErr)
		a.logger.Warn("control journal reconciliation failed; command polling remains paused", "error", safeLogError(reconcileBeforeErr))
		return
	}
	processed, pollErr := a.control.PollOnce(ctx)
	reconciledAfter, reconcileAfterErr := a.control.ReconcileOnce(ctx)
	if reconcileAfterErr == nil {
		a.controlAuditReady.Store(true)
	}
	err := errors.Join(reconcileBeforeErr, pollErr, reconcileAfterErr)
	a.health.ControlPoll(time.Now(), err)
	if err != nil {
		a.logger.Warn("control cycle degraded", "error", safeLogError(err))
	}
	if processed > 0 {
		a.logger.Info("control commands processed", "count", processed, "executionMode", a.cfg.Mode, "productionExecution", a.cfg.Control.ProductionExecution)
	}
	if reconciledBefore+reconciledAfter > 0 {
		a.logger.Info("control tasks reconciled", "count", reconciledBefore+reconciledAfter)
	}
}

func safeLogError(err error) string {
	if err == nil {
		return ""
	}
	value := err.Error()
	if len(value) > 512 {
		value = value[:512]
	}
	return value
}
