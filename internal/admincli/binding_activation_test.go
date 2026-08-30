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

func TestActivateAgentBindingConfirmsLoadedIdentity(t *testing.T) {
	restarts := 0
	statuses := []health.Status{
		{Bindings: health.BindingsState{Monitoring: health.BindingState{BindingID: "old", CredentialEpoch: "1"}}},
		{Bindings: health.BindingsState{Monitoring: health.BindingState{BindingID: "new", CredentialEpoch: "2"}}},
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
	recovery.Status = func(config.Config) (health.Status, error) { return health.Status{}, nil }
	recovery.Delay = func(context.Context, time.Duration) error { return nil }
	if err := recoverAgentBindingWith(context.Background(), config.Config{}, recovery); err != nil {
		t.Fatalf("recovery failed: %v", err)
	}
}

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
