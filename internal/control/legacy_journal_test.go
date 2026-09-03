package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func legacyAuthorityCommand(action, parameters, commandID, operationID string) Command {
	command := lineageCommand(action, parameters, commandID, operationID)
	command.SigningKeyID = "website-key-1"
	command.ApprovalRef = "approval-1"
	command.OperatorRef = "operator-1"
	command.BodySHA256 = strings.Repeat("b", 64)
	return command
}

func makeLegacyRecord(t *testing.T, journal *Journal, command Command, state, code string, now time.Time) journalRecord {
	t.Helper()
	if _, duplicate, err := journal.ClaimWithAudit(command, now, "0.1.0-rc.27"); err != nil || duplicate {
		t.Fatalf("legacy claim duplicate=%t err=%v", duplicate, err)
	}
	receipt := Receipt{SchemaVersion: 1, ReceiptID: "11111111-1111-4111-8111-111111111111", CommandID: command.CommandID,
		OperationID: command.OperationID, AgentRef: command.AgentRef, State: state, Code: code,
		ExecutionMode: "production", StartedAt: now, FinishedAt: now}
	if err := journal.Complete(command, receipt); err != nil {
		t.Fatal(err)
	}
	record, err := readJournal(journal.path(command.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	// Reproduce the rc.27 durable shape: the audit target, Agent ref, node,
	// resource key and source hash existed, while the exact authority columns
	// and clone template identity did not.
	record.IdempotencyKey = ""
	record.BindingID = ""
	record.DeviceID = ""
	record.CredentialEpoch = 0
	record.AssignmentRevision = 0
	record.ClusterRef = ""
	record.ServiceRef = ""
	record.InstanceUUID = ""
	record.GuestType = ""
	record.VMID = 0
	record.Generation = 0
	if command.Action == "vm.clone" {
		record.SourceTemplateRef = ""
		record.SourceVMID = 0
	}
	if err := writeJournal(journal.path(command.CommandID), record); err != nil {
		t.Fatal(err)
	}
	return record
}

func legacyMigrationFixture(t *testing.T) (*Journal, Command, Command, legacyJournalMigrationP, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	journal, err := OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	clone := legacyAuthorityCommand("vm.clone", `{"sourceVmid":9001,"templateRef":"ubuntu-24.04","name":"vm101","target":"pve1","storage":"local-lvm","full":true,"sourceConfigSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`, "legacy-clone-command", "legacy-clone-operation")
	cloneRecord := makeLegacyRecord(t, journal, clone, "succeeded", "SUCCEEDED", now)
	indeterminate := legacyAuthorityCommand("vm.set-resources", `{"cores":2}`, "legacy-indeterminate-command", "legacy-indeterminate-operation")
	makeLegacyRecord(t, journal, indeterminate, "indeterminate", "EXECUTION_INDETERMINATE", now.Add(time.Second))
	parameters := legacyJournalMigrationP{LegacyCloneCommandID: clone.CommandID, LegacyCloneOperationID: clone.OperationID,
		LegacyCloneDigest: cloneRecord.Digest, TemplateRef: "ubuntu-24.04", SourceVMID: 9001,
		SourceConfigSHA256: strings.Repeat("a", 64), RetireIndeterminateCommandIDs: []string{indeterminate.CommandID}}
	raw, err := json.Marshal(parameters)
	if err != nil {
		t.Fatal(err)
	}
	migration := legacyAuthorityCommand("vm.migrate-legacy-journal", string(raw), "legacy-migration-command", "legacy-migration-operation")
	return journal, clone, migration, parameters, now
}

func TestLegacyJournalMigrationBackfillsCloneRetiresNoUPIDAndSurvivesRestart(t *testing.T) {
	journal, clone, migration, parameters, now := legacyMigrationFixture(t)
	if _, duplicate, err := journal.ClaimWithAudit(migration, now.Add(2*time.Second), "0.1.0-rc.29"); err != nil || duplicate {
		t.Fatalf("migration claim duplicate=%t err=%v", duplicate, err)
	}
	result, err := journal.MigrateLegacyVMJournal(migration, parameters, now.Add(3*time.Second))
	if err != nil || !result.Migrated || len(result.RetiredIndeterminateCommandIDs) != 1 {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	cloneRecord, err := readJournal(journal.path(clone.CommandID))
	if err != nil || cloneRecord.SourceTemplateRef != parameters.TemplateRef || cloneRecord.SourceVMID != parameters.SourceVMID ||
		cloneRecord.BindingID != migration.BindingID || cloneRecord.DeviceID != migration.DeviceID ||
		cloneRecord.CredentialEpoch != migration.CredentialEpoch || cloneRecord.AssignmentRevision != migration.AssignmentRevision ||
		cloneRecord.VMID != migration.Identity.VMID || uint64(cloneRecord.Generation) != migration.Identity.Generation ||
		cloneRecord.MigratedByCommandID != migration.CommandID {
		t.Fatalf("clone after migration=%#v err=%v", cloneRecord, err)
	}
	retired, err := readJournal(journal.path(parameters.RetireIndeterminateCommandIDs[0]))
	if err != nil || retired.RetiredByCommandID != migration.CommandID || retired.PVETaskUPID != "" || recordMutationMayHaveHappened(retired) {
		t.Fatalf("retired record=%#v err=%v", retired, err)
	}
	resultRaw, _ := json.Marshal(result)
	receipt := Receipt{SchemaVersion: 1, ReceiptID: "33333333-3333-4333-8333-333333333333", CommandID: migration.CommandID,
		OperationID: migration.OperationID, AgentRef: migration.AgentRef, State: "succeeded", Code: "SUCCEEDED",
		ExecutionMode: "production", StartedAt: now.Add(2 * time.Second), FinishedAt: now.Add(3 * time.Second), Result: resultRaw}
	if err := journal.Complete(migration, receipt); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenJournal(journal.directory)
	if err != nil {
		t.Fatal(err)
	}
	replayed, duplicate, err := reopened.ClaimWithAudit(migration, now.Add(4*time.Second), "0.1.0-rc.29")
	if err != nil || !duplicate || replayed.State != "succeeded" || !bytes.Equal(replayed.Result, resultRaw) {
		t.Fatalf("replay=%#v duplicate=%t err=%v", replayed, duplicate, err)
	}
	initial := legacyAuthorityCommand("vm.set-initial-resources", initialResourcesFixture, "initial-command", "initial-operation")
	if err := reopened.AuthorizeInitialResources(initial, clone.OperationID, parameters.TemplateRef, parameters.SourceVMID, parameters.SourceConfigSHA256); err != nil {
		t.Fatalf("migrated lineage not authorized after restart: %v", err)
	}
}

func TestLegacyJournalMigrationRejectsAuthorityMismatchAndGenericClear(t *testing.T) {
	mutations := map[string]func(*journalRecord){
		"binding":    func(r *journalRecord) { r.BindingID = "22222222-2222-4222-8222-222222222222" },
		"device":     func(r *journalRecord) { r.DeviceID = "device-2" },
		"epoch":      func(r *journalRecord) { r.CredentialEpoch = 2 },
		"assignment": func(r *journalRecord) { r.AssignmentRevision = 8 },
		"vmid":       func(r *journalRecord) { r.VMID = 102 },
		"generation": func(r *journalRecord) {
			r.Generation = 2
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			journal, clone, migration, parameters, now := legacyMigrationFixture(t)
			record, err := readJournal(journal.path(clone.CommandID))
			if err != nil {
				t.Fatal(err)
			}
			mutate(&record)
			if err := writeJournal(journal.path(clone.CommandID), record); err != nil {
				t.Fatal(err)
			}
			if _, err := journal.MigrateLegacyVMJournal(migration, parameters, now); err == nil {
				t.Fatal("mismatched legacy authority was migrated")
			}
		})
	}
	command := controlCommand("vm.migrate-legacy-journal", "qemu", `{"clear":true}`)
	if err := validateParameters(command); err == nil {
		t.Fatal("generic Journal clear contract was accepted")
	}
}

func TestLegacyJournalMigrationRejectsNonTerminalCloneUPIDAndUnlistedIndeterminate(t *testing.T) {
	t.Run("clone not succeeded", func(t *testing.T) {
		journal, clone, migration, parameters, now := legacyMigrationFixture(t)
		record, _ := readJournal(journal.path(clone.CommandID))
		record.State = "submitted"
		record.Receipt.State = "submitted"
		record.Receipt.Code = "PVE_TASK_SUBMITTED"
		record.PVETaskUPID = "UPID:pve1:1:2:3:qmclone:101:root@pam!api:"
		record.Receipt.PVETaskUPID = record.PVETaskUPID
		if err := writeJournal(journal.path(clone.CommandID), record); err != nil {
			t.Fatal(err)
		}
		if _, err := journal.MigrateLegacyVMJournal(migration, parameters, now); err == nil {
			t.Fatal("non-terminal clone was migrated")
		}
	})
	t.Run("indeterminate has UPID", func(t *testing.T) {
		journal, _, migration, parameters, now := legacyMigrationFixture(t)
		path := journal.path(parameters.RetireIndeterminateCommandIDs[0])
		record, _ := readJournal(path)
		record.PVETaskUPID = "UPID:pve1:1:2:3:qmconfig:101:root@pam!api:"
		record.Receipt.PVETaskUPID = record.PVETaskUPID
		if err := writeJournal(path, record); err != nil {
			t.Fatal(err)
		}
		if _, err := journal.MigrateLegacyVMJournal(migration, parameters, now); err == nil {
			t.Fatal("UPID-bearing indeterminate record was retired")
		}
	})
	t.Run("unlisted active mutation", func(t *testing.T) {
		journal, _, migration, parameters, now := legacyMigrationFixture(t)
		parameters.RetireIndeterminateCommandIDs = []string{}
		raw, _ := json.Marshal(parameters)
		migration.Parameters = raw
		if _, _, err := journal.ClaimWithAudit(migration, now.Add(3*time.Second), "0.1.0-rc.29"); !errors.Is(err, ErrResourceBusy) {
			t.Fatalf("unlisted mutation claim err=%v", err)
		}
	})
}

func TestLegacyJournalMigrationIsOneTimeAcrossCommands(t *testing.T) {
	journal, _, migration, parameters, now := legacyMigrationFixture(t)
	if _, err := journal.MigrateLegacyVMJournal(migration, parameters, now); err != nil {
		t.Fatal(err)
	}
	second := migration
	second.CommandID = "legacy-migration-command-2"
	second.OperationID = "legacy-migration-operation-2"
	second.IdempotencyKey = "legacy-migration-command-2-idempotency"
	if _, err := journal.MigrateLegacyVMJournal(second, parameters, now.Add(time.Second)); err == nil {
		t.Fatal("legacy journal lineage was migrated by a second command")
	}
}

func TestJournalRejectsForgedMigrationOrRetirementMarkers(t *testing.T) {
	journal, clone, migration, _, now := legacyMigrationFixture(t)
	cloneRecord, _ := readJournal(journal.path(clone.CommandID))
	cloneRecord.RetiredByCommandID = migration.CommandID
	cloneRecord.RetiredAt = &now
	if err := writeJournal(journal.path(clone.CommandID), cloneRecord); err != nil {
		t.Fatal(err)
	}
	if _, err := readJournal(journal.path(clone.CommandID)); err == nil {
		t.Fatal("retirement marker on succeeded clone was accepted")
	}
}

func TestLegacyMigrationAndGuestFirewallGoldens(t *testing.T) {
	migrationRaw, err := os.ReadFile(filepath.Join("testdata", "agent-v1-vm-migrate-legacy-journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateParameters(controlCommand("vm.migrate-legacy-journal", "qemu", string(migrationRaw))); err != nil {
		t.Fatalf("legacy migration golden: %v", err)
	}
	resultRaw, err := os.ReadFile(filepath.Join("testdata", "agent-v1-vm-migrate-legacy-journal-result.json"))
	if err != nil || !validLegacyMigrationJournalResult(resultRaw) {
		t.Fatalf("legacy migration result golden err=%v", err)
	}
	listRaw, err := os.ReadFile(filepath.Join("testdata", "agent-v1-firewall-guest-rules-list-result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var list GuestFirewallRulesResult
	if err := strictParameters(listRaw, &list); err != nil {
		t.Fatal(err)
	}
	digest, err := guestFirewallRulesDigest(list.Rules)
	if err != nil || digest != list.Digest {
		t.Fatalf("firewall list golden digest=%s expected=%s err=%v", digest, list.Digest, err)
	}
	verifyRaw, err := os.ReadFile(filepath.Join("testdata", "agent-v1-firewall-guest-rules-verify.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateParameters(controlCommand("firewall.guest.rules.verify", "qemu", string(verifyRaw))); err != nil {
		t.Fatalf("firewall verify golden: %v", err)
	}
}
