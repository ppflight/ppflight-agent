//go:build windows

package hostfirewall

import (
	"context"
	"errors"
	"os"
)

func ownedByRoot(os.FileInfo) bool { return false }

func effectiveUID() int { return -1 }

func syncDirectory(*os.File) error { return nil }

func inspectFirewallSelectorPath(string) (bool, error) { return false, os.ErrNotExist }

func inspectUFWDisablePreconditions(string) error {
	return errors.New("UFW cleanup is unsupported on Windows")
}

func disableUFWAtBoot() error { return errors.New("UFW cleanup is unsupported on Windows") }

func acquireFirewallProcessLock(context.Context) (func(), error) { return func() {}, nil }

func acquireFirewallEnforcementLock(ctx context.Context) (context.Context, func(), error) {
	return context.WithValue(ctx, firewallNetfilterLockContextKey{}, true), func() {}, nil
}

func acquireFirewallTransactionLock(context.Context) (func(), error) { return func() {}, nil }
