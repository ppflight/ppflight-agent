// Package agent wires collection, durable queues, upload, control and health
// into one PVE-node service.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ppflight/ppflight-agent/internal/collector"
	"github.com/ppflight/ppflight-agent/internal/config"
	"github.com/ppflight/ppflight-agent/internal/control"
	"github.com/ppflight/ppflight-agent/internal/health"
	"github.com/ppflight/ppflight-agent/internal/inventory"
	"github.com/ppflight/ppflight-agent/internal/meter"
	"github.com/ppflight/ppflight-agent/internal/pve"
	"github.com/ppflight/ppflight-agent/internal/runstate"
	"github.com/ppflight/ppflight-agent/internal/store"
	"github.com/ppflight/ppflight-agent/internal/uploader"
	"github.com/ppflight/ppflight-agent/internal/wire"
)

type delivery struct {
	name     string
	uploader *uploader.Uploader
}

type App struct {
	cfg         config.Config
	version     string
	logger      *slog.Logger
	source      collector.Source
	assignments *inventory.Store
	meter       *meter.Manager
	runstate    *runstate.State
	queues      map[string]*store.Queue
	deliveries  []delivery
	control     *control.Service
	health      *health.Registry
	server      *http.Server

	lastInventory time.Time
	lastGuest     time.Time
	lastHost      time.Time
	lastSMART     time.Time
	lastMeter     time.Time
	lastWebsite   time.Time
	lastMonitor   time.Time
}

func New(cfg config.Config, secrets config.Secrets, version string, logger *slog.Logger) (*App, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if version == "" {
		version = "dev"
	}
	if err := os.MkdirAll(cfg.Runtime.StateDirectory, 0o750); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	assignments, err := loadAssignments(cfg)
	if err != nil {
		return nil, err
	}
	source, err := collector.New(cfg, secrets)
	if err != nil {
		return nil, fmt.Errorf("create collector: %w", err)
	}
	queueRoot := filepath.Join(cfg.Runtime.StateDirectory, "queues")
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
	meterManager, err := meter.Open(meter.Config{
		Directory: filepath.Join(cfg.Runtime.StateDirectory, "meter"), Mode: cfg.Mode,
		AgentRef: cfg.Identity.AgentRef, CollectorRef: cfg.Identity.CollectorRef,
		SourceRef: cfg.Identity.SourceRef, ClusterRef: cfg.Identity.ClusterRef,
	})
	if err != nil {
		return nil, err
	}
	if err := meterManager.Recover(meterQueue); err != nil {
		return nil, err
	}
	state, err := runstate.Open(filepath.Join(cfg.Runtime.StateDirectory, "run-state.json"))
	if err != nil {
		return nil, err
	}
	configuredControl := cfg.Control.Enabled && cfg.Control.PollURL != "" && cfg.Control.ResultURL != ""
	registry := health.New(version, cfg.Mode, cfg.Identity.AgentRef, cfg.Identity.ClusterRef, cfg.Identity.NodeRef, cfg.Control.Enabled, configuredControl, cfg.Control.ProductionExecution, time.Now())
	for name, queue := range queues {
		registry.RegisterQueue(name, queue)
	}
	document := assignments.Snapshot()
	registry.Assignment(document.Revision, len(document.Assignments))
	app := &App{cfg: cfg, version: version, logger: logger, source: source, assignments: assignments, meter: meterManager, runstate: state, queues: queues, health: registry}
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
	}
	if cfg.Destinations.Monitoring.Enabled {
		d, err := newDelivery("monitoring", cfg.Destinations.Monitoring, secrets.Monitoring, monitorQueue)
		if err != nil {
			return nil, err
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
		journal, journalErr := control.OpenJournal(filepath.Join(cfg.Runtime.StateDirectory, "control", "journal"))
		if journalErr != nil {
			return nil, journalErr
		}
		var writeClient *pve.Client
		if cfg.Control.ProductionExecution {
			writeClient, err = pve.NewClient(pve.Config{
				Endpoint: cfg.PVE.Endpoint, TokenID: secrets.ControlPVETokenID, TokenSecret: secrets.ControlPVETokenSecret,
				CAFile: cfg.PVE.CAFile, InsecureSkipTLS: false, Timeout: cfg.Control.RequestTimeout.Duration,
				MaxResponseBytes: cfg.PVE.MaxResponseBytes,
			})
			if err != nil {
				return nil, fmt.Errorf("create control PVE client: %w", err)
			}
		}
		service, serviceErr := control.NewService(control.ServiceConfig{
			AgentRef: cfg.Identity.AgentRef, ClusterRef: cfg.Identity.ClusterRef, Mode: cfg.Mode,
			CommandSecret: secrets.ControlCommandSecret, AllowedActions: cfg.Control.AllowedActions,
			Assignments: assignments, Poller: poller, Journal: journal,
			Executor:     control.Executor{Client: writeClient, Mode: cfg.Mode, ProductionExecution: cfg.Control.ProductionExecution},
			ReceiptQueue: controlQueue, CursorFile: filepath.Join(cfg.Runtime.StateDirectory, "control", "cursor.json"),
		})
		if serviceErr != nil {
			return nil, serviceErr
		}
		app.control = service
		resultDestination := config.DestinationConfig{Enabled: true, URL: cfg.Control.ResultURL, Auth: cfg.Control.Auth, Timeout: cfg.Control.RequestTimeout, MaxQueueBytes: 64 << 20, Compression: "none", PayloadFormat: "control-receipt-v1"}
		d, deliveryErr := newDelivery("control-results", resultDestination, secrets.ControlAPI, controlQueue)
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

func newDelivery(name string, cfg config.DestinationConfig, secret config.DestinationSecret, queue *store.Queue) (delivery, error) {
	instance, err := uploader.New(uploader.Config{
		Destination: uploader.Destination{ID: name, Endpoint: cfg.URL, AuthMode: uploader.AuthMode(cfg.Auth.Mode), KeyID: secret.KeyID, Secret: secret.Secret, BearerToken: secret.Bearer, Compression: cfg.Compression},
		Queue:       queue, RequestTimeout: cfg.Timeout.Duration,
	})
	if err != nil {
		return delivery{}, fmt.Errorf("create %s uploader: %w", name, err)
	}
	return delivery{name: name, uploader: instance}, nil
}

func (a *App) Run(ctx context.Context, once bool) error {
	if once {
		err := a.sample(ctx, time.Now().UTC())
		if a.control != nil {
			_, controlErr := a.control.PollOnce(ctx)
			a.health.ControlPoll(time.Now(), controlErr)
			err = errors.Join(err, controlErr)
		}
		for _, item := range a.deliveries {
			result := item.uploader.DeliverOne(ctx)
			a.health.Delivery(item.name, time.Now(), result.Delivered, result.Err)
			err = errors.Join(err, result.Err)
		}
		return err
	}
	serverErrors := make(chan error, 1)
	go func() {
		err := a.server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
		}
	}()
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
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
	var runErr error
	select {
	case <-ctx.Done():
	case err := <-serverErrors:
		runErr = err
	}
	cancel()
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
	if err := a.sample(ctx, timestamp); err != nil {
		a.logger.Warn("collection cycle degraded", "error", safeLogError(err))
	}
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
			batch, err = wire.BuildWebsiteTelemetry(snapshot, a.assignments, a.cfg.Identity.SourceRef, sequence)
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
				var batch wire.WebsiteTelemetryBatch
				batch, err = wire.BuildWebsiteTelemetry(snapshot, a.assignments, a.cfg.Identity.SourceRef, sequence)
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

func (a *App) deliveryLoop(ctx context.Context, item delivery) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			result := item.uploader.DeliverOne(ctx)
			if result.BatchID != "" {
				a.health.Delivery(item.name, time.Now(), result.Delivered, result.Err)
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
	processed, err := a.control.PollOnce(ctx)
	a.health.ControlPoll(time.Now(), err)
	if err != nil {
		a.logger.Warn("control poll failed", "error", safeLogError(err))
		return
	}
	if processed > 0 {
		a.logger.Info("control commands processed", "count", processed, "executionMode", a.cfg.Mode, "productionExecution", a.cfg.Control.ProductionExecution)
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
