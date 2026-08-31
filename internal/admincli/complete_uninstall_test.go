package admincli

import (
	"bufio"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ppflight/ppflight-agent/internal/bindstate"
)

func TestCompleteUninstallAllowsIncompleteBindingMarkers(t *testing.T) {
	for _, marker := range []string{"bind commit", "unbind"} {
		t.Run(marker, func(t *testing.T) {
			filename := prepareBindConfig(t)
			cfg, website, _ := seedDualBindings(t, filename)
			switch marker {
			case "bind commit":
				if err := bindstate.BeginWebsiteCommit(cfg.Runtime.StateDirectory, website.BindingID, website.CredentialEpoch); err != nil {
					t.Fatal(err)
				}
			case "unbind":
				if _, err := bindstate.BeginWebsiteUnbind(cfg.Runtime.StateDirectory, website); err != nil {
					t.Fatal(err)
				}
			}

			called := false
			instance := &cli{
				out:                io.Discard,
				errOut:             io.Discard,
				effectiveUID:       func() int { return 0 },
				managedWritePolicy: allowManagedWriteForTest,
				completeUninstall: func(context.Context) error {
					called = true
					return nil
				},
			}
			if code := instance.menuCompleteUninstallAt(bufio.NewReader(strings.NewReader("UNINSTALL\n")), filename); code != 0 || !called {
				t.Fatalf("complete uninstall did not purge through incomplete %s marker: code=%d called=%t", marker, code, called)
			}
		})
	}
}

func TestCompleteUninstallRefusesHeldBindstateTransaction(t *testing.T) {
	filename := prepareBindConfig(t)
	cfg, _, _ := seedDualBindings(t, filename)
	transaction, err := bindstate.AcquireTransaction(cfg.Runtime.StateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Close()

	called := false
	instance := &cli{
		out:                io.Discard,
		errOut:             io.Discard,
		effectiveUID:       func() int { return 0 },
		managedWritePolicy: allowManagedWriteForTest,
		completeUninstall: func(context.Context) error {
			called = true
			return nil
		},
	}
	if code := instance.menuCompleteUninstallAt(bufio.NewReader(strings.NewReader("UNINSTALL\n")), filename); code == 0 || called {
		t.Fatalf("complete uninstall proceeded while binding transaction was held: code=%d called=%t", code, called)
	}
}

func TestCompleteUninstallReleasesTransactionAfterHelperFailure(t *testing.T) {
	filename := prepareBindConfig(t)
	attempts := 0
	instance := &cli{
		out:                io.Discard,
		errOut:             io.Discard,
		effectiveUID:       func() int { return 0 },
		managedWritePolicy: allowManagedWriteForTest,
		completeUninstall: func(context.Context) error {
			attempts++
			if attempts == 1 {
				return errors.New("purge failed")
			}
			return nil
		},
	}

	if code := instance.menuCompleteUninstallAt(bufio.NewReader(strings.NewReader("UNINSTALL\n")), filename); code == 0 || attempts != 1 {
		t.Fatalf("first complete uninstall did not report helper failure: code=%d attempts=%d", code, attempts)
	}
	if code := instance.menuCompleteUninstallAt(bufio.NewReader(strings.NewReader("UNINSTALL\n")), filename); code != 0 || attempts != 2 {
		t.Fatalf("complete uninstall could not retry after helper failure: code=%d attempts=%d", code, attempts)
	}
}
