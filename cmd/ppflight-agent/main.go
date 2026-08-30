package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/ppflight/ppflight-agent/internal/admincli"
	"github.com/ppflight/ppflight-agent/internal/agent"
	"github.com/ppflight/ppflight-agent/internal/bindingoverlay"
	"github.com/ppflight/ppflight-agent/internal/config"
)

var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	if base := filepath.Base(os.Args[0]); base == "ag-pve" || base == "ag" || base == "AG" {
		return admincli.Run(os.Args[1:], version, os.Stdout, os.Stderr)
	}
	if len(os.Args) > 1 && os.Args[1] == "admin" {
		return admincli.Run(os.Args[2:], version, os.Stdout, os.Stderr)
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
		fmt.Printf("configuration valid: mode=%s controlEnabled=%t productionExecution=%t\n", cfg.Mode, cfg.Control.Enabled, cfg.Control.ProductionExecution)
		return 0
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
	if cfg.Mode == "test" {
		logger.Warn("agent is in test mode; metering is shadow and control execution is dry-run")
	}
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
