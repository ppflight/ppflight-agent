package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ppflight/ppflight-agent/internal/admincli"
	"github.com/ppflight/ppflight-agent/internal/agent"
	"github.com/ppflight/ppflight-agent/internal/assignment"
	"github.com/ppflight/ppflight-agent/internal/bindingoverlay"
	"github.com/ppflight/ppflight-agent/internal/config"
	"github.com/ppflight/ppflight-agent/internal/control"
	"github.com/ppflight/ppflight-agent/internal/hostfirewall"
	"github.com/ppflight/ppflight-agent/internal/inventory"
	"github.com/ppflight/ppflight-agent/internal/selfupdate"
)

var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	// This is an installer/uninstaller-only root helper. It is intentionally
	// hidden from the ordinary AG menu and cannot be reached through a signed
	// website command.
	if len(os.Args) > 1 && os.Args[1] == "host-firewall" {
		return hostfirewall.Run(os.Args[2:], os.Stdout, os.Stderr)
	}
	if base := filepath.Base(os.Args[0]); base == "ag-pve" || base == "ag" || base == "AG" {
		return admincli.Run(os.Args[1:], version, os.Stdout, os.Stderr)
	}
	if len(os.Args) > 1 && os.Args[1] == "admin" {
		return admincli.Run(os.Args[2:], version, os.Stdout, os.Stderr)
	}
	if len(os.Args) > 1 && os.Args[1] == "upgrade-helper" {
		return runUpgradeHelper(os.Args[2:])
	}
	var configFile string
	var checkConfig, once, showVersion bool
	flag.StringVar(&configFile, "config", "/etc/ppflight-agent/agent.yaml", "path to the strict JSON configuration (the filename may end in .yaml)")
	flag.BoolVar(&checkConfig, "check-config", false, "validate configuration and referenced environment secrets, then exit")
	flag.BoolVar(&once, "once", false, "collect, enqueue, attempt one delivery per endpoint, then exit")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		return 2
	}
	if showVersion {
		fmt.Println(version)
		return 0
	}
	cfg, err := config.LoadFile(configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration invalid: %v\n", err)
		return 2
	}
	// Test mode exists only as an in-process unit-test fixture.  Every built
	// executable (release and unversioned developer builds alike) must refuse it
	// before config checks, queue creation, or any outbound delivery can occur.
	if cfg.Mode != "production" {
		fmt.Fprintln(os.Stderr, "configuration invalid: executable requires production mode")
		return 2
	}
	lookup, err := config.ResolvePVEEnvironmentLookup(cfg, os.LookupEnv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration secret error: %v\n", err)
		return 2
	}
	secrets, err := bindingoverlay.Resolve(cfg, lookup)
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration secret error: %v\n", err)
		return 2
	}
	if checkConfig {
		if cfg.PVE.Source == "disabled" {
			fmt.Println("configuration staged: PVE collection is disabled until AG local PVE preparation completes")
			return 0
		}
		fmt.Printf("configuration valid: mode=%s controlEnabled=%t productionExecution=%t\n", cfg.Mode, cfg.Control.Enabled, cfg.Control.ProductionExecution)
		return 0
	}
	if cfg.PVE.Source == "disabled" {
		fmt.Fprintln(os.Stderr, "PVE collection is disabled; run AG and complete local PVE preparation before starting ppflight-agent")
		// systemd uses this stable code as RestartPreventExitStatus so an
		// intentionally unconfigured fresh install cannot become a restart loop.
		return 78
	}
	level := new(slog.LevelVar)
	switch cfg.Runtime.LogLevel {
	case "debug":
		level.Set(slog.LevelDebug)
	case "warn":
		level.Set(slog.LevelWarn)
	case "error":
		level.Set(slog.LevelError)
	default:
		level.Set(slog.LevelInfo)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)
	if cfg.Control.ProductionExecution {
		logger.Warn("PVE production control execution is enabled", "allowedActions", cfg.Control.AllowedActions)
	}
	app, err := agent.New(cfg, secrets, version, logger)
	if err != nil {
		logger.Error("agent initialization failed", "error", err.Error())
		return 1
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := app.Run(ctx, once); err != nil {
		logger.Error("agent stopped with error", "error", err.Error())
		return 1
	}
	return 0
}

func runUpgradeHelper(args []string) int {
	set := flag.NewFlagSet("upgrade-helper", flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	configFile := set.String("config", "/etc/ppflight-agent/agent.yaml", "agent configuration")
	if err := set.Parse(args); err != nil || set.NArg() != 0 {
		return 2
	}
	if !runningAsRoot() {
		fmt.Fprintln(os.Stderr, "upgrade helper must run as root")
		return 1
	}
	cfg, err := config.LoadFile(*configFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "upgrade helper configuration invalid")
		return 1
	}
	// The privileged helper uses the same structured JSON journal format as
	// the long-running Agent. It never logs config values, credentials,
	// command parameters, provider bodies, or guest output.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if err := admincli.ValidateInstalledWriteTarget(*configFile, cfg); err != nil {
		fmt.Fprintln(os.Stderr, "upgrade helper configuration or state path is unsafe")
		return 1
	}
	if cfg.Mode != "production" || cfg.PVE.Source != "api" {
		fmt.Fprintln(os.Stderr, "upgrade helper requires production local PVE configuration")
		return 1
	}
	lookup, err := config.ResolvePVEEnvironmentLookup(cfg, os.LookupEnv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "upgrade helper secret lookup failed")
		return 1
	}
	secrets, err := bindingoverlay.Resolve(cfg, lookup)
	if err != nil {
		fmt.Fprintln(os.Stderr, "upgrade helper binding validation failed")
		return 1
	}
	authority, err := assignment.LoadAuthority(filepath.Join(cfg.Runtime.StateDirectory, "assignments", "refresh-state.json"), cfg.Identity.ClusterRef,
		assignment.AuthorityScope{BindingID: secrets.WebsiteBindingID, DeviceID: secrets.DeviceID, CredentialEpoch: secrets.WebsiteCredentialEpoch})
	if err != nil || authority.State.Revision == 0 {
		fmt.Fprintln(os.Stderr, "upgrade helper assignment authority unavailable")
		return 1
	}
	document := authority.Document
	allowedActions := cfg.Control.AllowedActions
	if !authority.Present {
		document, err = inventory.LoadFile(cfg.Assignments.File, cfg.Identity.ClusterRef)
		if err != nil {
			fmt.Fprintln(os.Stderr, "upgrade helper assignment validation failed")
			return 1
		}
	} else {
		allowedActions = authority.Document.AllowedActions
	}
	if err := control.ValidateAllowedActions(allowedActions); err != nil {
		fmt.Fprintln(os.Stderr, "upgrade helper assignment action authority unavailable")
		return 1
	}
	assignmentState := authority.State
	assignments := inventory.NewStore(document)
	journal, err := control.OpenJournal(filepath.Join(agent.RuntimeStateDirectory(cfg.Runtime.StateDirectory), "control", "journal"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "upgrade helper journal unavailable")
		return 1
	}
	statusURL := "http://" + cfg.Runtime.ListenAddress + "/status"
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	err = selfupdate.RunHelper(ctx, selfupdate.HelperConfig{
		StateDirectory: cfg.Runtime.StateDirectory, BinaryPath: "/usr/local/bin/ppflight-agent", ServiceName: "ppflight-agent.service",
		StatusURL: statusURL, WebsiteEndpoint: cfg.Control.PollURL, CurrentVersion: version, Journal: journal,
		Verify: control.VerifyConfig{
			AgentRef: cfg.Identity.AgentRef, ClusterRef: cfg.Identity.ClusterRef, Mode: cfg.Mode,
			BindingID: secrets.WebsiteBindingID, DeviceID: secrets.DeviceID, CredentialEpoch: secrets.WebsiteCredentialEpoch,
			AssignmentRevision: func() uint64 { return assignmentState.Revision }, SigningKeyID: secrets.ControlSigningKeyID,
			PublicKey: ed25519.PublicKey(secrets.ControlPublicKey), Allowed: control.AllowedSet(allowedActions), Assignments: assignments,
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "upgrade helper failed: %v\n", err)
		return 1
	}
	fmt.Println("upgrade helper completed")
	return 0
}
