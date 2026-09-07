package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ppflight/ppflight-agent/internal/templatecompat"
)

func TestHostFirewallReconcileRunsLegacyTemplateMigration(t *testing.T) {
	oldFirewall := runHostFirewall
	oldMigration := migrateLegacyTemplateTimezones
	t.Cleanup(func() {
		runHostFirewall = oldFirewall
		migrateLegacyTemplateTimezones = oldMigration
	})
	migrated := false
	runHostFirewall = func(args []string, _, _ io.Writer) int {
		if len(args) != 1 || args[0] != "reconcile" {
			t.Fatalf("args=%v", args)
		}
		return 0
	}
	migrateLegacyTemplateTimezones = func(context.Context) (templatecompat.Report, error) {
		migrated = true
		return templatecompat.Report{Scanned: 2, Migrated: 1, VMIDs: []int{9000}}, nil
	}
	var out, errOut bytes.Buffer
	if code := runHostFirewallPostflight([]string{"reconcile"}, &out, &errOut); code != 0 || !migrated || errOut.Len() != 0 || !strings.Contains(out.String(), "scanned=2 migrated=1 unchanged=1") {
		t.Fatalf("code=%d migrated=%t out=%q err=%q", code, migrated, out.String(), errOut.String())
	}
}

func TestHostFirewallReconcileFailsClosedWhenTemplateMigrationFails(t *testing.T) {
	oldFirewall := runHostFirewall
	oldMigration := migrateLegacyTemplateTimezones
	t.Cleanup(func() {
		runHostFirewall = oldFirewall
		migrateLegacyTemplateTimezones = oldMigration
	})
	runHostFirewall = func([]string, io.Writer, io.Writer) int { return 0 }
	migrateLegacyTemplateTimezones = func(context.Context) (templatecompat.Report, error) {
		return templatecompat.Report{}, errors.New("injected migration failure")
	}
	var out, errOut bytes.Buffer
	if code := runHostFirewallPostflight([]string{"reconcile"}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "legacy template timezone reconciliation failed") {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
}

func TestHostFirewallNonReconcileDoesNotRunTemplateMigration(t *testing.T) {
	oldFirewall := runHostFirewall
	oldMigration := migrateLegacyTemplateTimezones
	t.Cleanup(func() {
		runHostFirewall = oldFirewall
		migrateLegacyTemplateTimezones = oldMigration
	})
	runHostFirewall = func([]string, io.Writer, io.Writer) int { return 0 }
	migrateLegacyTemplateTimezones = func(context.Context) (templatecompat.Report, error) {
		t.Fatal("migration ran for non-reconcile command")
		return templatecompat.Report{}, nil
	}
	if code := runHostFirewallPostflight([]string{"prepare"}, io.Discard, io.Discard); code != 0 {
		t.Fatalf("code=%d", code)
	}
}
