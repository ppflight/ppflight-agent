package admincli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ppflight/ppflight-agent/internal/bindingoverlay"
	"github.com/ppflight/ppflight-agent/internal/bindstate"
	"github.com/ppflight/ppflight-agent/internal/config"
)

func unbindConfirmation(domain string) string {
	if domain == "monitoring" {
		return "DELETE MONITORING\n"
	}
	return "DELETE WEBSITE\n"
}

func beginUnbindForTest(t *testing.T, stateDirectory, domain string, website bindstate.State, monitoring bindstate.MonitoringState) bindstate.UnbindCommit {
	t.Helper()
	if domain == "website" {
		marker, err := bindstate.BeginWebsiteUnbind(stateDirectory, website)
		if err != nil {
			t.Fatal(err)
		}
		return marker
	}
	marker, err := bindstate.BeginMonitoringUnbind(stateDirectory, monitoring)
	if err != nil {
		t.Fatal(err)
	}
	return marker
}

func readUnbindForTest(t *testing.T, stateDirectory, domain string) (bindstate.UnbindCommit, bool) {
	t.Helper()
	if domain == "website" {
		marker, found, err := bindstate.ReadWebsiteUnbind(stateDirectory)
		if err != nil {
			t.Fatal(err)
		}
		return marker, found
	}
	marker, found, err := bindstate.ReadMonitoringUnbind(stateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	return marker, found
}

func removeBindingStateForTest(t *testing.T, stateDirectory, domain string) {
	t.Helper()
	var err error
	if domain == "website" {
		err = bindstate.RemoveWebsite(stateDirectory)
	} else {
		err = bindstate.RemoveMonitoring(stateDirectory)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func assertDualBindingsForTest(t *testing.T, stateDirectory string, website bindstate.State, monitoring bindstate.MonitoringState) {
	t.Helper()
	websiteCurrent, err := bindstate.Load(stateDirectory)
	if err != nil || websiteCurrent.BindingID != website.BindingID || websiteCurrent.CredentialEpoch != website.CredentialEpoch {
		t.Fatalf("website state was not restored: %#v err=%v", websiteCurrent, err)
	}
	monitoringCurrent, err := bindstate.LoadMonitoring(stateDirectory)
	if err != nil || monitoringCurrent.BindingID != monitoring.BindingID || monitoringCurrent.CredentialEpoch != monitoring.CredentialEpoch {
		t.Fatalf("monitoring state was not restored: %#v err=%v", monitoringCurrent, err)
	}
}

func assertTargetUnboundForTest(t *testing.T, stateDirectory, domain string) {
	t.Helper()
	if domain == "website" {
		if _, err := bindstate.Load(stateDirectory); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("website state remains after removal: %v", err)
		}
		return
	}
	if _, err := bindstate.LoadMonitoring(stateDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("monitoring state remains after removal: %v", err)
	}
}

func assertOldDualDomainOverlay(t *testing.T, cfg config.Config, website bindstate.State, monitoring bindstate.MonitoringState) {
	t.Helper()
	secrets, err := bindingoverlay.Resolve(cfg, func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatalf("old binding overlay is not available during recovery: %v", err)
	}
	if secrets.WebsiteBindingID != website.BindingID || secrets.WebsiteCredentialEpoch != website.CredentialEpoch ||
		secrets.MonitoringBindingID != monitoring.BindingID || secrets.Monitoring.CredentialEpoch != monitoring.CredentialEpoch {
		t.Fatalf("recovered overlay crossed a trust domain: %#v", secrets)
	}
}

// A completed journal must roll back every ordinary local failure.  The
// explicit recovery callback asserts that the live process can resolve both
// prior trust domains, not merely that the two state files exist on disk.
func TestBindingRemovalLocalFailuresRestoreBothTrustDomains(t *testing.T) {
	cases := []string{"restart", "config-write", "state-remove", "activation"}
	for _, domain := range []string{"website", "monitoring"} {
		for _, failure := range cases {
			domain, failure := domain, failure
			t.Run(domain+"-"+failure, func(t *testing.T) {
				filename := prepareBindConfig(t)
				cfg, website, monitoring := seedDualBindings(t, filename)
				var output, stderr bytes.Buffer
				recoveries, writes := 0, 0
				instance := &cli{
					out: &output, errOut: &stderr, effectiveUID: func() int { return 0 },
					managedWritePolicy: allowManagedWriteForTest,
					restartUnbind: func(context.Context) error {
						if failure == "restart" {
							return errors.New("injected restart arm failure")
						}
						return nil
					},
					activateBinding: func(_ context.Context, loaded config.Config, expected bindingActivationExpectation) error {
						if expected.Absent {
							if failure == "activation" {
								return errors.New("injected unbound activation failure")
							}
							return errors.New("unbound activation unexpectedly reached")
						}
						if expected != (bindingActivationExpectation{}) {
							return errors.New("rollback used a nonzero binding expectation")
						}
						recoveries++
						assertOldDualDomainOverlay(t, loaded, website, monitoring)
						return nil
					},
				}
				if failure == "config-write" {
					instance.writeUnbindConfig = func(path string, next config.Config) (string, error) {
						writes++
						if writes == 1 {
							return "", errors.New("injected config write failure")
						}
						return atomicUpdate(path, next)
					}
				}
				if failure == "state-remove" {
					instance.removeUnbindState = func(string, string) error { return errors.New("injected state removal failure") }
				}
				if code := instance.menuRemoveBinding(bufio.NewReader(strings.NewReader(unbindConfirmation(domain))), filename, domain == "monitoring"); code == 0 {
					t.Fatalf("%s %s failure unexpectedly succeeded output=%s stderr=%s", domain, failure, output.String(), stderr.String())
				}
				if recoveries != 1 {
					t.Fatalf("%s %s recoveries=%d want=1 stderr=%s", domain, failure, recoveries, stderr.String())
				}
				assertDualBindingsForTest(t, cfg.Runtime.StateDirectory, website, monitoring)
				if _, found := readUnbindForTest(t, cfg.Runtime.StateDirectory, domain); found {
					t.Fatalf("%s %s left a completed removal journal", domain, failure)
				}
			})
		}
	}
}

// If the systemd arm itself fails during rollback, neither the marker nor its
// private preimage may be cleared. Re-running the same local command requires
// no confirmation/code and safely restores the old active generation.
func TestBindingRemovalArmFailureKeepsJournalForMarkerOnlyRecovery(t *testing.T) {
	for _, domain := range []string{"website", "monitoring"} {
		domain := domain
		t.Run(domain, func(t *testing.T) {
			filename := prepareBindConfig(t)
			cfg, website, monitoring := seedDualBindings(t, filename)
			var output, stderr bytes.Buffer
			armCalls, recoveries := 0, 0
			instance := &cli{
				out: &output, errOut: &stderr, effectiveUID: func() int { return 0 },
				managedWritePolicy: allowManagedWriteForTest,
				restartUnbind:      func(context.Context) error { return nil },
				removeUnbindState:  func(string, string) error { return errors.New("injected state failure before rollback") },
				armBinding: func(context.Context) error {
					armCalls++
					if armCalls == 1 {
						return errors.New("injected rollback arm failure")
					}
					return nil
				},
				activateBinding: func(_ context.Context, loaded config.Config, expected bindingActivationExpectation) error {
					if expected != (bindingActivationExpectation{}) {
						return errors.New("marker rollback activated an unexpected binding")
					}
					recoveries++
					assertOldDualDomainOverlay(t, loaded, website, monitoring)
					return nil
				},
			}
			if code := instance.menuRemoveBinding(bufio.NewReader(strings.NewReader(unbindConfirmation(domain))), filename, domain == "monitoring"); code == 0 {
				t.Fatal("arm failure unexpectedly completed removal")
			}
			marker, found := readUnbindForTest(t, cfg.Runtime.StateDirectory, domain)
			if !found {
				t.Fatal("arm failure cleared the only durable removal journal")
			}
			if _, err := os.Stat(filepath.Join(bindstate.Directory(cfg.Runtime.StateDirectory), marker.StateBackup)); err != nil {
				t.Fatalf("arm failure removed rollback preimage: %v", err)
			}
			if recoveries != 0 {
				t.Fatalf("recovery ran despite a failed systemd arm: %d", recoveries)
			}
			assertDualBindingsForTest(t, cfg.Runtime.StateDirectory, website, monitoring)

			reader := &readTrackingReader{}
			if code := instance.menuRemoveBinding(bufio.NewReader(reader), filename, domain == "monitoring"); code != 0 {
				t.Fatalf("marker-only recovery code=%d stderr=%s", code, stderr.String())
			}
			if reader.read || recoveries != 1 || armCalls != 2 {
				t.Fatalf("marker-only recovery crossed an unsafe input/lifecycle boundary: read=%v recoveries=%d arms=%d", reader.read, recoveries, armCalls)
			}
			if _, found := readUnbindForTest(t, cfg.Runtime.StateDirectory, domain); found {
				t.Fatal("marker-only recovery left journal")
			}
			if _, err := os.Stat(filepath.Join(bindstate.Directory(cfg.Runtime.StateDirectory), marker.StateBackup)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("marker-only recovery retained private backup: %v", err)
			}
		})
	}
}

// Each durable forward write has a direct marker-only continuation. The last
// case intentionally simulates a crash after the private backup was discarded
// but before the journal was removed; forward recovery accepts that exact
// state and never resurrects the removed credentials.
func TestBindingRemovalForwardJournalRecoveryAtEveryBoundary(t *testing.T) {
	for _, domain := range []string{"website", "monitoring"} {
		for _, phase := range []string{"config-disabled", "state-removed", "backup-discarded"} {
			domain, phase := domain, phase
			t.Run(domain+"-"+phase, func(t *testing.T) {
				filename := prepareBindConfig(t)
				cfg, website, monitoring := seedDualBindings(t, filename)
				marker := beginUnbindForTest(t, cfg.Runtime.StateDirectory, domain, website, monitoring)
				disabled := cfg
				if domain == "website" {
					disableWebsiteBindingConfig(&disabled)
				} else {
					disableMonitoringBindingConfig(&disabled)
				}
				if _, err := atomicUpdate(filename, disabled); err != nil {
					t.Fatal(err)
				}
				if phase != "config-disabled" {
					removeBindingStateForTest(t, cfg.Runtime.StateDirectory, domain)
				}
				if phase == "backup-discarded" {
					if err := discardUnbindBackup(cfg.Runtime.StateDirectory, domain, marker); err != nil {
						t.Fatal(err)
					}
				}

				reader := &readTrackingReader{}
				var output, stderr bytes.Buffer
				activations := 0
				instance := &cli{
					out: &output, errOut: &stderr, effectiveUID: func() int { return 0 },
					managedWritePolicy: allowManagedWriteForTest,
					activateBinding: func(_ context.Context, loaded config.Config, expected bindingActivationExpectation) error {
						if !expected.Absent || expected.Domain != domain {
							return errors.New("forward recovery activated an unexpected binding")
						}
						if !removalConfigApplied(loaded, domain) {
							return errors.New("forward recovery re-enabled removed config")
						}
						assertTargetUnboundForTest(t, loaded.Runtime.StateDirectory, domain)
						activations++
						return nil
					},
				}
				if code := instance.menuRemoveBinding(bufio.NewReader(reader), filename, domain == "monitoring"); code != 0 {
					t.Fatalf("forward %s recovery code=%d stderr=%s", phase, code, stderr.String())
				}
				if reader.read || activations != 1 {
					t.Fatalf("forward %s recovery read=%v activations=%d", phase, reader.read, activations)
				}
				assertTargetUnboundForTest(t, cfg.Runtime.StateDirectory, domain)
				if _, found := readUnbindForTest(t, cfg.Runtime.StateDirectory, domain); found {
					t.Fatalf("forward %s recovery left journal", phase)
				}
			})
		}
	}
}

func TestBindingRemovalFinishFailureResumesForwardWithoutInput(t *testing.T) {
	for _, domain := range []string{"website", "monitoring"} {
		domain := domain
		t.Run(domain, func(t *testing.T) {
			filename := prepareBindConfig(t)
			cfg, _, _ := seedDualBindings(t, filename)
			var output, stderr bytes.Buffer
			activations := 0
			instance := &cli{
				out: &output, errOut: &stderr, effectiveUID: func() int { return 0 },
				managedWritePolicy: allowManagedWriteForTest,
				finishUnbind:       func(string, string) error { return errors.New("injected journal finish failure") },
				activateBinding: func(_ context.Context, loaded config.Config, expected bindingActivationExpectation) error {
					if !expected.Absent || expected.Domain != domain {
						return errors.New("finish failure activated an unexpected binding")
					}
					assertTargetUnboundForTest(t, loaded.Runtime.StateDirectory, domain)
					activations++
					return nil
				},
			}
			if code := instance.menuRemoveBinding(bufio.NewReader(strings.NewReader(unbindConfirmation(domain))), filename, domain == "monitoring"); code == 0 {
				t.Fatal("injected finish failure unexpectedly succeeded")
			}
			marker, found := readUnbindForTest(t, cfg.Runtime.StateDirectory, domain)
			if !found {
				t.Fatal("finish failure lost unbind journal")
			}
			if _, err := os.Stat(filepath.Join(bindstate.Directory(cfg.Runtime.StateDirectory), marker.StateBackup)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("forward finish failure unexpectedly retained backup: %v", err)
			}

			instance.finishUnbind = nil
			reader := &readTrackingReader{}
			if code := instance.menuRemoveBinding(bufio.NewReader(reader), filename, domain == "monitoring"); code != 0 {
				t.Fatalf("finish-marker-only recovery code=%d stderr=%s", code, stderr.String())
			}
			if reader.read || activations != 2 {
				t.Fatalf("finish-marker-only recovery read=%v activations=%d", reader.read, activations)
			}
			if _, found := readUnbindForTest(t, cfg.Runtime.StateDirectory, domain); found {
				t.Fatal("finish-marker-only recovery left journal")
			}
		})
	}
}

func TestBindRefusesUnbindJournalBeforeReadingCode(t *testing.T) {
	for _, caller := range []string{"website", "monitoring"} {
		caller := caller
		t.Run(caller, func(t *testing.T) {
			filename := prepareBindConfig(t)
			cfg, website, monitoring := seedDualBindings(t, filename)
			beginUnbindForTest(t, cfg.Runtime.StateDirectory, "website", website, monitoring)
			reader := &readTrackingReader{}
			var output, stderr bytes.Buffer
			instance := &cli{
				in: reader, out: &output, errOut: &stderr, version: "test",
				managedWritePolicy: allowManagedWriteForTest,
				bindingPVE: func(context.Context, string, config.Config) (config.Config, error) {
					t.Fatal("bind reached PVE preparation while an unbind journal exists")
					return config.Config{}, errors.New("unexpected")
				},
			}
			args := []string{"--config", filename, "website", "bind", "--endpoint", "http://127.0.0.1:18080/bind", "--hostname", "pve-test", "--replace"}
			if caller == "monitoring" {
				args = []string{"--config", filename, "monitoring", "bind", "--endpoint", "http://127.0.0.1:18080/bind", "--hostname", "pve-test", "--replace"}
			}
			if code := instance.run(args); code != 1 {
				t.Fatalf("bind with unbind journal code=%d stderr=%s", code, stderr.String())
			}
			if reader.read {
				t.Fatal("bind read a one-time code while unbind journal exists")
			}
		})
	}
}
