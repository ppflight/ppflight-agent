package admincli

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/config"
	"github.com/ppflight/ppflight-agent/internal/health"
)

func TestParsePVEVersionOutput(t *testing.T) {
	for input, wanted := range map[string]string{
		"pve-manager/8.2.2/9355359cd7afbae4 (running kernel: 6.8.12-1-pve)\n": "8.2.2",
		"pve-manager/9.0/abc123\n": "9.0",
	} {
		got, err := parsePVEVersionOutput([]byte(input))
		if err != nil || got != wanted {
			t.Fatalf("parse %q: got=%q err=%v", input, got, err)
		}
	}
	for _, input := range []string{"", "bash: pveversion: not found\n", "pve-manager/7.4-1/x\n", "9.0.8\n", "pve-manager/9.0/x\nextra\n", "pve-manager/9.0/x\x00"} {
		if got, err := parsePVEVersionOutput([]byte(input)); err == nil {
			t.Fatalf("invalid output %q accepted as %q", input, got)
		}
	}
}

func TestDiscoverPVEVersionUsesFixedProgram(t *testing.T) {
	var program string
	var args []string
	got, err := discoverPVEVersionWith(context.Background(), func(_ context.Context, executable string, values ...string) ([]byte, error) {
		program, args = executable, append([]string(nil), values...)
		return []byte("pve-manager/9.0.8/hash (running version: 9.0.8)\n"), nil
	})
	if err != nil || got != "9.0.8" || program != "/usr/bin/pveversion" || len(args) != 0 {
		t.Fatalf("got=%q err=%v program=%q args=%v", got, err, program, args)
	}
}

func TestDiscoverPVEVersionFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		run  func(context.Context, string, ...string) ([]byte, error)
	}{
		{name: "command failure", run: func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("exit 1") }},
		{name: "abnormal output", run: func(context.Context, string, ...string) ([]byte, error) { return []byte("unexpected\n"), nil }},
		{name: "non PVE", run: func(context.Context, string, ...string) ([]byte, error) { return []byte("Debian GNU/Linux 13\n"), nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got, err := discoverPVEVersionWith(context.Background(), test.run); err == nil || got != "" {
				t.Fatalf("got=%q err=%v", got, err)
			}
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	got, err := discoverPVEVersionWith(ctx, func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if err == nil || got != "" {
		t.Fatalf("timeout got=%q err=%v", got, err)
	}
}

func TestRestartAgentForUnbindRequiresReliablePIDTransition(t *testing.T) {
	t.Run("pre restart PID read failure never queues restart", func(t *testing.T) {
		restarted := false
		err := restartAgentForUnbindWith(context.Background(), func(context.Context) (string, error) {
			return "", errors.New("systemd unavailable")
		}, func(context.Context) error {
			restarted = true
			return nil
		}, func(context.Context) error { return nil })
		if err == nil || restarted {
			t.Fatalf("pre-read failure queued restart=%t err=%v", restarted, err)
		}
	})
	t.Run("unchanged PID times out", func(t *testing.T) {
		reads := 0
		err := restartAgentForUnbindWith(context.Background(), func(context.Context) (string, error) {
			reads++
			return "4242", nil
		}, func(context.Context) error { return nil }, func(context.Context) error { return errors.New("deadline") })
		if err == nil || reads < 2 {
			t.Fatalf("unchanged PID accepted: reads=%d err=%v", reads, err)
		}
	})
	for _, after := range []string{"0", "5252"} {
		t.Run("old PID exits or is replaced "+after, func(t *testing.T) {
			values := []string{"4242", after}
			err := restartAgentForUnbindWith(context.Background(), func(context.Context) (string, error) {
				value := values[0]
				if len(values) > 1 {
					values = values[1:]
				}
				return value, nil
			}, func(context.Context) error { return nil }, func(context.Context) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestActivateAgentBindingConfirmsLoadedIdentity(t *testing.T) {
	restarts := 0
	now := time.Now().UTC()
	statuses := []health.Status{
		{Bindings: health.BindingsState{Monitoring: health.BindingState{BindingID: "old", CredentialEpoch: "1"}}},
		{Mode: "production", Ready: true, StartedAt: now, Collection: health.EventState{LastSuccess: timePointer(now.Add(time.Second))},
			Deliveries: map[string]health.EventState{"monitoring": {LastSuccess: timePointer(now.Add(2 * time.Second))}},
			Bindings:   health.BindingsState{Monitoring: health.BindingState{BindingID: "new", CredentialEpoch: "2"}}},
	}
	ops := agentServiceOperations{
		Restart: func(context.Context) error { restarts++; return nil },
		Active:  func(context.Context) error { return nil },
		Status: func(config.Config) (health.Status, error) {
			result := statuses[0]
			if len(statuses) > 1 {
				statuses = statuses[1:]
			}
			return result, nil
		},
		Delay: func(context.Context, time.Duration) error { return nil },
	}
	err := activateAgentBindingWith(context.Background(), config.Config{}, bindingActivationExpectation{Domain: "monitoring", BindingID: "new", CredentialEpoch: 2}, ops)
	if err != nil || restarts != 1 || len(statuses) != 1 {
		t.Fatalf("err=%v restarts=%d statuses=%d", err, restarts, len(statuses))
	}
}

func TestActivateAgentBindingTimeoutAndRecovery(t *testing.T) {
	delayErr := errors.New("deadline")
	ops := agentServiceOperations{
		Restart: func(context.Context) error { return nil },
		Active:  func(context.Context) error { return nil },
		Status:  func(config.Config) (health.Status, error) { return health.Status{}, nil },
		Delay:   func(context.Context, time.Duration) error { return delayErr },
	}
	if err := activateAgentBindingWith(context.Background(), config.Config{}, bindingActivationExpectation{Domain: "monitoring", BindingID: "new", CredentialEpoch: 2}, ops); err == nil {
		t.Fatal("activation accepted a process that did not load the new identity")
	}

	recovery := ops
	now := time.Now().UTC()
	recovery.Status = func(config.Config) (health.Status, error) {
		return health.Status{Mode: "test", Ready: true, StartedAt: now, Collection: health.EventState{LastSuccess: timePointer(now.Add(time.Second))}}, nil
	}
	recovery.Delay = func(context.Context, time.Duration) error { return nil }
	cfg := config.Config{Mode: "test", Runtime: config.RuntimeConfig{StateDirectory: t.TempDir()}}
	if err := recoverAgentBindingWith(context.Background(), cfg, recovery); err != nil {
		t.Fatalf("recovery failed: %v", err)
	}
}

func TestBindingActivationRequiresPostRestartDomainUpload(t *testing.T) {
	now := time.Now().UTC()
	status := health.Status{
		Mode: "production", Ready: true, StartedAt: now,
		Collection: health.EventState{LastSuccess: timePointer(now.Add(time.Second))},
		Bindings:   health.BindingsState{Website: health.BindingState{BindingID: "website", CredentialEpoch: "3"}},
		Deliveries: map[string]health.EventState{"website-telemetry": {AuthBlocked: true}},
	}
	if bindingActivationMatches(status, bindingActivationExpectation{Domain: "website", BindingID: "website", CredentialEpoch: 3}) {
		t.Fatal("auth-blocked website upload was reported active")
	}
	status.Deliveries["website-telemetry"] = health.EventState{LastSuccess: timePointer(now.Add(500 * time.Millisecond))}
	if bindingActivationMatches(status, bindingActivationExpectation{Domain: "website", BindingID: "website", CredentialEpoch: 3}) {
		t.Fatal("pre-collection queued upload was reported as the new binding's first telemetry")
	}
	status.Deliveries["website-telemetry"] = health.EventState{LastSuccess: timePointer(now.Add(2 * time.Second))}
	if !bindingActivationMatches(status, bindingActivationExpectation{Domain: "website", BindingID: "website", CredentialEpoch: 3}) {
		t.Fatal("post-restart website upload was not accepted")
	}
}

func TestActivateRealPVEWaitsForSuccessfulProductionCollection(t *testing.T) {
	now := time.Now().UTC()
	statuses := []health.Status{
		{Mode: "production", StartedAt: now},
		{Mode: "production", StartedAt: now, Ready: true, Collection: health.EventState{LastSuccess: timePointer(now.Add(time.Second))}},
	}
	restarts := 0
	ops := agentServiceOperations{
		Restart: func(context.Context) error { restarts++; return nil },
		Active:  func(context.Context) error { return nil },
		Status: func(config.Config) (health.Status, error) {
			result := statuses[0]
			if len(statuses) > 1 {
				statuses = statuses[1:]
			}
			return result, nil
		},
		Delay: func(context.Context, time.Duration) error { return nil },
	}
	cfg := config.Config{Mode: "production", PVE: config.PVEConfig{Source: "api"}}
	if err := activateRealPVEWith(context.Background(), cfg, ops); err != nil || restarts != 1 {
		t.Fatalf("err=%v restarts=%d", err, restarts)
	}
}

func TestActivateRealPVERejectsSimulatorAndUnsuccessfulCollection(t *testing.T) {
	operations := agentServiceOperations{
		Restart: func(context.Context) error { return nil }, Active: func(context.Context) error { return nil },
		Status: func(config.Config) (health.Status, error) { return health.Status{Mode: "production"}, nil },
		Delay:  func(context.Context, time.Duration) error { return errors.New("deadline") },
	}
	if err := activateRealPVEWith(context.Background(), config.Config{Mode: "test", PVE: config.PVEConfig{Source: "simulator"}}, operations); err == nil {
		t.Fatal("simulator was accepted as real PVE")
	}
	if err := activateRealPVEWith(context.Background(), config.Config{Mode: "production", PVE: config.PVEConfig{Source: "api"}}, operations); err == nil {
		t.Fatal("missing successful collection was accepted")
	}
}

func TestActivateRealPVERequiresEveryAlreadyBoundTelemetryDomain(t *testing.T) {
	now := time.Now().UTC()
	status := health.Status{
		Mode: "production", Ready: true, StartedAt: now,
		Collection: health.EventState{LastSuccess: timePointer(now.Add(time.Second))},
		Deliveries: map[string]health.EventState{
			"website-telemetry": {LastSuccess: timePointer(now.Add(2 * time.Second))},
		},
	}
	operations := agentServiceOperations{
		Restart: func(context.Context) error { return nil }, Active: func(context.Context) error { return nil },
		Status: func(config.Config) (health.Status, error) { return status, nil },
		Delay:  func(context.Context, time.Duration) error { return errors.New("deadline") },
	}
	cfg := config.Config{Mode: "production", PVE: config.PVEConfig{Source: "api"}}
	cfg.Destinations.WebsiteTelemetry.Enabled = true
	cfg.Destinations.Monitoring.Enabled = true
	err := activateRealPVEWith(context.Background(), cfg, operations)
	var activationErr *realPVEActivationError
	if !errors.As(err, &activationErr) || !activationErr.localReady {
		t.Fatalf("missing monitoring delivery did not preserve local-ready state: %v", err)
	}
	status.Deliveries["monitoring"] = health.EventState{LastSuccess: timePointer(now.Add(3 * time.Second))}
	if err := activateRealPVEWith(context.Background(), cfg, operations); err != nil {
		t.Fatalf("both bound telemetry deliveries were not accepted: %v", err)
	}
}

func TestBindingReadinessIgnoresRevokedOldDestination(t *testing.T) {
	now := time.Now().UTC()
	status := health.Status{
		Mode: "production", Ready: true, StartedAt: now,
		Collection: health.EventState{LastSuccess: timePointer(now.Add(time.Second))},
		Deliveries: map[string]health.EventState{
			"website-telemetry": {AuthBlocked: true},
			"monitoring":        {AuthBlocked: true},
		},
	}
	operations := agentServiceOperations{
		Restart: func(context.Context) error { return nil }, Active: func(context.Context) error { return nil },
		Status: func(config.Config) (health.Status, error) { return status, nil },
		Delay: func(context.Context, time.Duration) error {
			return errors.New("should not wait for revoked credentials")
		},
	}
	cfg := config.Config{Mode: "production", PVE: config.PVEConfig{Source: "api"}}
	cfg.Destinations.WebsiteTelemetry.Enabled = true
	cfg.Destinations.Monitoring.Enabled = true
	if err := activateRealPVEWithRequirement(context.Background(), cfg, operations, false); err != nil {
		t.Fatalf("local binding readiness depended on revoked old destination: %v", err)
	}
}

func timePointer(value time.Time) *time.Time { return &value }

func TestBindingStatusMatchesExactDomainAndUint64Epoch(t *testing.T) {
	status := health.Status{Bindings: health.BindingsState{
		Website:    health.BindingState{BindingID: "website", CredentialEpoch: "18446744073709551615"},
		Monitoring: health.BindingState{BindingID: "monitor", CredentialEpoch: "42"},
	}}
	if !bindingStatusMatches(status, bindingActivationExpectation{Domain: "website", BindingID: "website", CredentialEpoch: ^uint64(0)}) {
		t.Fatal("website status did not match exact uint64 epoch")
	}
	if !bindingStatusMatches(status, bindingActivationExpectation{Domain: "monitoring", BindingID: "monitor", CredentialEpoch: 42}) {
		t.Fatal("monitoring status did not match")
	}
	if reflect.DeepEqual(status.Bindings.Website, status.Bindings.Monitoring) {
		t.Fatal("test setup did not preserve trust-domain separation")
	}
	removed := health.Status{Bindings: health.BindingsState{
		Website:    health.BindingState{DeviceID: "device-01"},
		Monitoring: health.BindingState{BindingID: "monitor", CredentialEpoch: "42"},
	}}
	if !bindingStatusMatches(removed, bindingActivationExpectation{Domain: "website", Absent: true}) {
		t.Fatal("website removal did not accept an empty website binding")
	}
	if bindingStatusMatches(removed, bindingActivationExpectation{Domain: "monitoring", Absent: true}) {
		t.Fatal("monitoring removal accepted a still-loaded binding")
	}
}
