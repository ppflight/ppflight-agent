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

	"github.com/ppflight/ppflight-agent/internal/bindstate"
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

type realPVEActivationError struct {
	localReady bool
}

func (e *realPVEActivationError) Error() string {
	if e.localReady {
		return "real PVE collection became ready but bound telemetry delivery was not confirmed"
	}
	return "real PVE collection did not become ready"
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

// armAgentBinding starts (but does not synchronously wait for) the unit while
// a binding commit marker still blocks credential loading. The unit has
// Restart=always, so once the marker is removed after this succeeds, either
// the already-queued start or its next restart will load the new credentials.
// This closes the crash window between durable state completion and the later
// synchronous activation/health confirmation.
func (c *cli) armAgentBinding(ctx context.Context) error {
	if c.armBinding != nil {
		return c.armBinding(ctx)
	}
	if c.activateBinding != nil {
		// Injected activation callers are a fully controlled test/embedding
		// boundary and do not manage a host systemd unit.
		return nil
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("systemd start requires PVE root")
	}
	if err := exec.CommandContext(ctx, "/usr/bin/systemctl", "start", "--no-block", agentServiceUnit).Run(); err != nil {
		return errors.New("arm ppflight-agent service restart")
	}
	return nil
}

// restartAgentForUnbind creates a systemd-owned restart job before public
// configuration or private state are removed. The durable unbind journal is
// already present at this point, so any replacement process fails closed
// rather than loading an old credential generation. Waiting for the previous
// MainPID to disappear prevents an in-memory old Agent from uploading while
// the root transaction replaces its files.
func (c *cli) restartAgentForUnbind(ctx context.Context) error {
	if c.restartUnbind != nil {
		return c.restartUnbind(ctx)
	}
	if c.activateBinding != nil {
		return nil
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("systemd unbind restart requires PVE root")
	}
	return restartAgentForUnbindWith(ctx, systemdMainPID, func(ctx context.Context) error {
		return exec.CommandContext(ctx, "/usr/bin/systemctl", "restart", "--no-block", agentServiceUnit).Run()
	}, waitForUnbindRestart)
}

// restartAgentForUnbindWith is split from the systemd shell boundary so its
// no-old-process invariant is testable.  A failed MainPID query is never
// treated as "no process": proceeding after it could leave an in-memory old
// HMAC credential uploading while the durable removal transaction edits files.
func restartAgentForUnbindWith(ctx context.Context, mainPID func(context.Context) (string, error), restart func(context.Context) error, wait func(context.Context) error) error {
	if mainPID == nil || restart == nil || wait == nil {
		return errors.New("binding removal restart operations are incomplete")
	}
	previousPID, err := mainPID(ctx)
	if err != nil {
		return errors.New("read ppflight-agent MainPID before binding removal")
	}
	if err := restart(ctx); err != nil {
		return errors.New("arm ppflight-agent restart for binding removal")
	}
	for {
		currentPID, err := mainPID(ctx)
		if err != nil {
			return errors.New("read ppflight-agent MainPID after binding removal restart")
		}
		if currentPID == "0" || currentPID != previousPID {
			return nil
		}
		if err := wait(ctx); err != nil {
			return errors.New("previous ppflight-agent process did not exit for binding removal")
		}
	}
}

func waitForUnbindRestart(ctx context.Context) error {
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func systemdMainPID(ctx context.Context) (string, error) {
	output, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", "--property=MainPID", "--value", agentServiceUnit).Output()
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(output))
	if value == "" {
		return "", errors.New("systemd MainPID is empty")
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return "", errors.New("systemd MainPID is invalid")
		}
	}
	return value, nil
}

// quiesceAgentForBinding closes the in-memory credential/control window before
// root replaces any binding files. Tests with an injected activation boundary
// are already fully controlled and do not invoke the host service manager.
func (c *cli) quiesceAgentForBinding(ctx context.Context) error {
	if c.quiesceBinding != nil {
		return c.quiesceBinding(ctx)
	}
	if c.activateBinding != nil {
		return nil
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("systemd stop requires PVE root")
	}
	if err := exec.CommandContext(ctx, "/usr/bin/systemctl", "stop", agentServiceUnit).Run(); err != nil {
		return errors.New("stop ppflight-agent service for binding transaction")
	}
	// `systemctl stop` returning success only means the stop job was accepted.
	// Do not send an enrollment request while an old process may still hold a
	// now-to-be-revoked credential or command channel.
	output, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", "--property=ActiveState", "--value", agentServiceUnit).Output()
	if err != nil || (strings.TrimSpace(string(output)) != "inactive" && strings.TrimSpace(string(output)) != "failed") {
		return errors.New("confirm ppflight-agent service is inactive for binding transaction")
	}
	return nil
}

func (c *cli) recoverAgentBinding(ctx context.Context, cfg config.Config) error {
	if c.activateBinding != nil {
		// Test and embedded callers provide one controlled activation boundary.
		// A zero expectation denotes restart-and-health confirmation after rollback.
		return c.activateBinding(ctx, cfg, bindingActivationExpectation{})
	}
	return recoverAgentBindingWith(ctx, cfg, defaultAgentServiceOperations())
}

func (c *cli) activateRealPVE(ctx context.Context, cfg config.Config) error {
	if c.activatePVE != nil {
		return c.activatePVE(ctx, cfg)
	}
	return activateRealPVEWithRequirement(ctx, cfg, defaultAgentServiceOperations(), true)
}

func activateRealPVEWith(ctx context.Context, cfg config.Config, operations agentServiceOperations) error {
	return activateRealPVEWithRequirement(ctx, cfg, operations, true)
}

// activateRealPVELocal verifies only authoritative local collection. Binding
// replacement must not depend on an old, revoked remote credential becoming
// healthy; the new destination is verified after the new binding is saved.
func (c *cli) activateRealPVELocal(ctx context.Context, cfg config.Config) error {
	if c.activatePVE != nil {
		return c.activatePVE(ctx, cfg)
	}
	return activateRealPVEWithRequirement(ctx, cfg, defaultAgentServiceOperations(), false)
}

func activateRealPVEWithRequirement(ctx context.Context, cfg config.Config, operations agentServiceOperations, requireDeliveries bool) error {
	if cfg.Mode != "production" || cfg.PVE.Source != "api" || operations.Restart == nil || operations.Active == nil || operations.Status == nil || operations.Delay == nil {
		return errors.New("real PVE activation configuration is incomplete")
	}
	if err := operations.Restart(ctx); err != nil {
		return errors.New("restart ppflight-agent service for real PVE collection")
	}
	localReady := false
	for {
		if err := operations.Active(ctx); err == nil {
			status, statusErr := operations.Status(cfg)
			if statusErr == nil && status.Mode == "production" && status.Ready && status.Collection.LastSuccess != nil && !status.Collection.LastSuccess.Before(status.StartedAt) {
				localReady = true
				if !requireDeliveries || realPVEDeliveriesReady(status, cfg) {
					return nil
				}
			}
		}
		if err := operations.Delay(ctx, 250*time.Millisecond); err != nil {
			return &realPVEActivationError{localReady: localReady}
		}
	}
}

func realPVEDeliveriesReady(status health.Status, cfg config.Config) bool {
	required := []string{}
	if cfg.Destinations.WebsiteTelemetry.Enabled {
		required = append(required, "website-telemetry")
	}
	if cfg.Destinations.Monitoring.Enabled {
		required = append(required, "monitoring")
	}
	for _, name := range required {
		delivery := status.Deliveries[name]
		if delivery.AuthBlocked || delivery.LastSuccess == nil || delivery.LastSuccess.Before(status.StartedAt) {
			return false
		}
	}
	return true
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
			if statusErr == nil && bindingActivationMatches(status, expected) {
				return nil
			}
		}
		if err := operations.Delay(ctx, 250*time.Millisecond); err != nil {
			return errors.New("ppflight-agent did not become active with the new binding before timeout")
		}
	}
}

func bindingActivationMatches(status health.Status, expected bindingActivationExpectation) bool {
	if !bindingStatusMatches(status, expected) {
		return false
	}
	if expected.Absent {
		return true
	}
	if status.Mode != "production" || !status.Ready || status.Collection.LastSuccess == nil || status.Collection.LastSuccess.Before(status.StartedAt) {
		return false
	}
	deliveryName := "website-telemetry"
	if expected.Domain == "monitoring" {
		deliveryName = "monitoring"
	}
	delivery := status.Deliveries[deliveryName]
	return !delivery.AuthBlocked && delivery.LastSuccess != nil && !delivery.LastSuccess.Before(status.StartedAt) && !delivery.LastSuccess.Before(*status.Collection.LastSuccess)
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
			if status, statusErr := operations.Status(cfg); statusErr == nil && recoveredStatusMatches(status, cfg) {
				return nil
			}
		}
		if err := operations.Delay(ctx, 250*time.Millisecond); err != nil {
			return errors.New("restored ppflight-agent did not become healthy before timeout")
		}
	}
}

func recoveredStatusMatches(status health.Status, cfg config.Config) bool {
	if status.Mode != cfg.Mode || !status.Ready || status.Collection.LastSuccess == nil || status.Collection.LastSuccess.Before(status.StartedAt) {
		return false
	}
	website, websiteErr := bindstate.Load(cfg.Runtime.StateDirectory)
	if !bindingRecovered(status.Bindings.Website, website, websiteErr) {
		return false
	}
	monitoring, monitoringErr := bindstate.LoadMonitoring(cfg.Runtime.StateDirectory)
	return monitoringBindingRecovered(status.Bindings.Monitoring, monitoring, monitoringErr)
}

func bindingRecovered(actual health.BindingState, state bindstate.State, err error) bool {
	if errors.Is(err, os.ErrNotExist) {
		return actual.BindingID == "" && actual.CredentialEpoch == ""
	}
	return err == nil && actual.BindingID == state.BindingID && actual.CredentialEpoch == fmt.Sprintf("%d", state.CredentialEpoch)
}

func monitoringBindingRecovered(actual health.BindingState, state bindstate.MonitoringState, err error) bool {
	if errors.Is(err, os.ErrNotExist) {
		return actual.BindingID == "" && actual.CredentialEpoch == ""
	}
	return err == nil && actual.BindingID == state.BindingID && actual.CredentialEpoch == fmt.Sprintf("%d", state.CredentialEpoch)
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
