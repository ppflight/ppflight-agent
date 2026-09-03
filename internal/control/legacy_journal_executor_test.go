package control

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/pve"
)

type legacyMigratorFunc func(Command, legacyJournalMigrationP, time.Time) (LegacyJournalMigrationResult, error)

func (function legacyMigratorFunc) MigrateLegacyVMJournal(command Command, parameters legacyJournalMigrationP, now time.Time) (LegacyJournalMigrationResult, error) {
	return function(command, parameters, now)
}

func TestLegacyJournalMigrationRevalidatesCurrentTemplateBeforeLocalWrite(t *testing.T) {
	baseline := pve.TemplateBaseline{Cores: 2, Sockets: 1, MemoryMiB: 1024,
		BootDisk:       pve.TemplateBootDisk{Interface: "scsi0", SizeGiB: 8},
		Networks:       []pve.TemplateNetwork{{Interface: "net0", Bridge: "vmbr0", Model: "virtio", Firewall: false}},
		CloudInitDrive: true, QGADeviceEnabled: true, GuestFirewallEmpty: true}
	canonical, _ := json.Marshal(baseline)
	digest := fmt.Sprintf("%x", sha256.Sum256(canonical))
	sourceOSType := "l26"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api2/json/cluster/resources":
			_, _ = w.Write([]byte(`{"data":[{"type":"qemu","node":"pve1","vmid":9001,"template":1}]}`))
		case "/api2/json/nodes/pve1/qemu/9001/config":
			_, _ = fmt.Fprintf(w, `{"data":{"ostype":%q,"cores":2,"sockets":1,"memory":1024,"scsi0":"local-lvm:vm-9001-disk-0,size=8G","ide2":"local:cloudinit,media=cdrom","net0":"virtio=AA:BB:CC:DD:EE:01,bridge=vmbr0,firewall=0","agent":"enabled=1"}}`, sourceOSType)
		case "/api2/json/nodes/pve1/qemu/9001/firewall/rules", "/api2/json/nodes/pve1/qemu/9001/firewall/ipset":
			_, _ = w.Write([]byte(`{"data":[]}`))
		default:
			t.Fatalf("unexpected request: %s", r.URL.Path)
		}
	}))
	defer server.Close()
	parameters := legacyJournalMigrationP{LegacyAssignmentRevision: 3, LegacyCloneCommandID: "legacy-clone-command", LegacyCloneOperationID: "legacy-clone-operation",
		LegacyCloneDigest: strings.Repeat("b", 64), TemplateRef: "ubuntu-24.04", SourceVMID: 9001,
		SourceConfigSHA256: digest, RetireIndeterminateCommandIDs: []string{}}
	raw, _ := json.Marshal(parameters)
	command := legacyAuthorityCommand("vm.migrate-legacy-journal", string(raw), "migration-command", "migration-operation")
	command.AssignmentRevision = 4
	called := false
	var migrationFailure error
	executor := Executor{Client: controlTestClient(t, server), Mode: "production", ProductionExecution: true,
		LegacyJournal: legacyMigratorFunc(func(_ Command, got legacyJournalMigrationP, _ time.Time) (LegacyJournalMigrationResult, error) {
			called = got.SourceConfigSHA256 == digest
			if migrationFailure != nil {
				return LegacyJournalMigrationResult{}, migrationFailure
			}
			return LegacyJournalMigrationResult{Migrated: true, LegacyAssignmentRevision: got.LegacyAssignmentRevision,
				LegacyCloneCommandID:   got.LegacyCloneCommandID,
				LegacyCloneOperationID: got.LegacyCloneOperationID, TemplateRef: got.TemplateRef, SourceVMID: got.SourceVMID,
				SourceConfigSHA256: got.SourceConfigSHA256, RetiredIndeterminateCommandIDs: []string{}}, nil
		})}
	receipt, err := executor.Execute(context.Background(), command, time.Now())
	if err != nil || receipt.State != "succeeded" || !called {
		t.Fatalf("receipt=%#v called=%t err=%v", receipt, called, err)
	}
	parameters.SourceConfigSHA256 = strings.Repeat("a", 64)
	raw, _ = json.Marshal(parameters)
	command.Parameters = raw
	called = false
	receipt, err = executor.Execute(context.Background(), command, time.Now())
	if err == nil || receipt.Code != "LEGACY_JOURNAL_SOURCE_REJECTED" || called {
		t.Fatalf("stale source receipt=%#v called=%t err=%v", receipt, called, err)
	}
	parameters.SourceConfigSHA256 = digest
	raw, _ = json.Marshal(parameters)
	command.Parameters = raw
	sourceOSType = "win11"
	called = false
	receipt, err = executor.Execute(context.Background(), command, time.Now())
	if err == nil || receipt.Code != "LEGACY_JOURNAL_SOURCE_REJECTED" || called {
		t.Fatalf("Windows source receipt=%#v called=%t err=%v", receipt, called, err)
	}
	sourceOSType = "l26"
	for failure, code := range map[error]string{
		ErrUnlistedActiveMutation:  "UNLISTED_ACTIVE_MUTATION",
		ErrListedRecordNotEligible: "LISTED_RECORD_NOT_ELIGIBLE",
		ErrCloneLineageMismatch:    "CLONE_LINEAGE_MISMATCH",
	} {
		migrationFailure = failure
		called = false
		receipt, err = executor.Execute(context.Background(), command, time.Now())
		if err == nil || receipt.Code != code || !called {
			t.Fatalf("failure=%v receipt=%#v called=%t err=%v", failure, receipt, called, err)
		}
	}
}
