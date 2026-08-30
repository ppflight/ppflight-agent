package admincli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/ppflight/ppflight-agent/internal/config"
	"github.com/ppflight/ppflight-agent/internal/health"
)

const agentServiceUnit = "ppflight-agent.service"

var pveVersionOutput = regexp.MustCompile(`^pve-manager/((?:8|9)\.[0-9]{1,3}(?:\.[0-9]{1,3})?)(?:/[^\s]+)?(?:\s.*)?$`)

type bindingActivationExpectation struct {
	Domain          string
	BindingID       string
	CredentialEpoch uint64
	Absent          bool
}

type agentServiceOperations struct {
	Restart func(context.Context) error
	Active  func(context.Context) error
	Status  func(config.Config) (health.Status, error)
	Delay   func(context.Context, time.Duration) error
}

func (c *cli) localPVEVersion(ctx context.Context) (string, error) {
	if c.pveVersion != nil {
		return c.pveVersion(ctx)
	}
	return discoverLocalPVEVersion(ctx)
}

func discoverLocalPVEVersion(ctx context.Context) (string, error) {
	if runtime.GOOS != "linux" {
		return "", errors.New("local PVE version discovery requires Linux")
	}
	return discoverPVEVersionWith(ctx, func(ctx context.Context, program string, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, program, args...).Output()
	})
}

func discoverPVEVersionWith(ctx context.Context, run func(context.Context, string, ...string) ([]byte, error)) (string, error) {
	if run == nil {
		return "", errors.New("local PVE version runner is unavailable")
	}
	output, err := run(ctx, "/usr/bin/pveversion")
	if err != nil {
		if ctx.Err() != nil {
			return "", errors.New("local PVE version discovery timed out")
		}
		return "", errors.New("local PVE version command failed")
	}
	return parsePVEVersionOutput(output)
}

func parsePVEVersionOutput(output []byte) (string, error) {
	if len(output) == 0 || len(output) > 4096 || strings.ContainsAny(string(output), "\x00\r") {
		return "", errors.New("local PVE version output is invalid")
	}
	line := strings.TrimSpace(string(output))
	if strings.Contains(line, "\n") {
		return "", errors.New("local PVE version output is invalid")
	}
	matches := pveVersionOutput.FindStringSubmatch(line)
	if len(matches) != 2 {
		return "", errors.New("local PVE version output is not a supported PVE manager version")
	}
	return matches[1], nil
}

func (c *cli) activateAgentBinding(ctx context.Context, cfg config.Config, expected bindingActivationExpectation) error {
	if c.activateBinding != nil {
		return c.activateBinding(ctx, cfg, expected)
	}
	return activateAgentBindingWith(ctx, cfg, expected, defaultAgentServiceOperations())
}

func (c *cli) recoverAgentBinding(ctx context.Context, cfg config.Config) error {
	if c.activateBinding != nil {
		// Test and embedded callers provide one controlled activation boundary.
		// A zero expectation denotes restart-and-health confirmation after rollback.
		return c.activateBinding(ctx, cfg, bindingActivationExpectation{})
	}
	return recoverAgentBindingWith(ctx, cfg, defaultAgentServiceOperations())
}

func activateAgentBindingWith(ctx context.Context, cfg config.Config, expected bindingActivationExpectation, operations agentServiceOperations) error {
	validDomain := expected.Domain == "website" || expected.Domain == "monitoring"
	validPresent := !expected.Absent && expected.BindingID != "" && expected.CredentialEpoch != 0
	validAbsent := expected.Absent && expected.BindingID == "" && expected.CredentialEpoch == 0
	if !validDomain || (!validPresent && !validAbsent) {
		return errors.New("binding activation expectation is invalid")
	}
	if operations.Restart == nil || operations.Active == nil || operations.Status == nil || operations.Delay == nil {
		return errors.New("binding activation operations are incomplete")
	}
	if err := operations.Restart(ctx); err != nil {
		return errors.New("restart ppflight-agent service")
	}
	for {
		if err := operations.Active(ctx); err == nil {
			status, statusErr := operations.Status(cfg)
			if statusErr == nil && bindingStatusMatches(status, expected) {
				return nil
			}
		}
		if err := operations.Delay(ctx, 250*time.Millisecond); err != nil {
			return errors.New("ppflight-agent did not become active with the new binding before timeout")
		}
	}
}

func bindingStatusMatches(status health.Status, expected bindingActivationExpectation) bool {
	actual := status.Bindings.Website
	if expected.Domain == "monitoring" {
		actual = status.Bindings.Monitoring
	}
	if expected.Absent {
		return actual.BindingID == "" && actual.CredentialEpoch == ""
	}
	wantedEpoch := fmt.Sprintf("%d", expected.CredentialEpoch)
	return actual.BindingID == expected.BindingID && actual.CredentialEpoch == wantedEpoch
}

func recoverAgentBindingWith(ctx context.Context, cfg config.Config, operations agentServiceOperations) error {
	if operations.Restart == nil || operations.Active == nil || operations.Status == nil || operations.Delay == nil {
		return errors.New("binding recovery operations are incomplete")
	}
	if err := operations.Restart(ctx); err != nil {
		return errors.New("restart restored ppflight-agent service")
	}
	for {
		if err := operations.Active(ctx); err == nil {
			if _, statusErr := operations.Status(cfg); statusErr == nil {
				return nil
			}
		}
		if err := operations.Delay(ctx, 250*time.Millisecond); err != nil {
			return errors.New("restored ppflight-agent did not become healthy before timeout")
		}
	}
}

func defaultAgentServiceOperations() agentServiceOperations {
	return agentServiceOperations{
		Restart: func(ctx context.Context) error {
			if runtime.GOOS != "linux" || os.Geteuid() != 0 {
				return errors.New("systemd restart requires PVE root")
			}
			return exec.CommandContext(ctx, "/usr/bin/systemctl", "restart", agentServiceUnit).Run()
		},
		Active: func(ctx context.Context) error {
			return exec.CommandContext(ctx, "/usr/bin/systemctl", "is-active", "--quiet", agentServiceUnit).Run()
		},
		Status: fetchLocalStatus,
		Delay: func(ctx context.Context, duration time.Duration) error {
			timer := time.NewTimer(duration)
			defer timer.Stop()
			select {
			case <-timer.C:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	}
}
