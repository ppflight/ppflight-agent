package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/protocol"
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
	if _, duplicate, err := journal.ClaimWithAudit(command, now, "0.1.0-rc.26"); err != nil || duplicate {
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
	// Reproduce the rc.26 durable shape: the audit target, Agent ref, node,
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
	clone.AssignmentRevision = 3
	cloneRecord := makeLegacyRecord(t, journal, clone, "succeeded", "SUCCEEDED", now)
	indeterminate := legacyAuthorityCommand("vm.set-resources", `{"cores":2}`, "legacy-indeterminate-command", "legacy-indeterminate-operation")
	indeterminate.AssignmentRevision = 3
	makeLegacyRecord(t, journal, indeterminate, "indeterminate", "EXECUTION_INDETERMINATE", now.Add(time.Second))
	parameters := legacyJournalMigrationP{LegacyAssignmentRevision: 3, LegacyCloneCommandID: clone.CommandID, LegacyCloneOperationID: clone.OperationID,
		LegacyCloneDigest: cloneRecord.Digest, TemplateRef: "ubuntu-24.04", SourceVMID: 9001,
		SourceConfigSHA256: strings.Repeat("a", 64), RetireIndeterminateCommandIDs: []string{indeterminate.CommandID}}
	raw, err := json.Marshal(parameters)
	if err != nil {
		t.Fatal(err)
	}
	migration := legacyAuthorityCommand("vm.migrate-legacy-journal", string(raw), "legacy-migration-command", "legacy-migration-operation")
	migration.AssignmentRevision = 4
	return journal, clone, migration, parameters, now
}

func legacyInitialResourcesCommand(t *testing.T, clone, migration Command, parameters legacyJournalMigrationP, commandID, operationID string) Command {
	t.Helper()
	raw, err := json.Marshal(initialResourcesP{
		Cores: 1, Sockets: 1, MemoryMiB: 1024, CloneOperationID: clone.OperationID,
		TemplateRef: parameters.TemplateRef, SourceVMID: parameters.SourceVMID,
		VMGeneration: protocol.Counter(migration.Identity.Generation), TemplateConfigSHA256: parameters.SourceConfigSHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	initial := legacyAuthorityCommand("vm.set-initial-resources", string(raw), commandID, operationID)
	initial.AssignmentRevision = migration.AssignmentRevision
	initial.Identity = migration.Identity
	return initial
}

func legacyDeleteCommand(migration Command, commandID, operationID string) Command {
	command := legacyAuthorityCommand("vm.delete", `{"purge":true,"destroyUnreferencedDisks":true}`, commandID, operationID)
	command.AssignmentRevision = migration.AssignmentRevision
	command.Identity = migration.Identity
	return command
}

func completeAuditedLegacyRecord(t *testing.T, journal *Journal, command Command, state string, at time.Time) {
	t.Helper()
	receiptID, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	code := strings.ToUpper(state)
	if state == "succeeded" {
		code = "SUCCEEDED"
	}
	receipt := Receipt{SchemaVersion: 1, ReceiptID: receiptID, CommandID: command.CommandID,
		OperationID: command.OperationID, AgentRef: command.AgentRef, State: state, Code: code,
		ExecutionMode: "production", StartedAt: at, FinishedAt: at}
	if err := journal.Complete(command, receipt); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyJournalMigrationBackfillsCloneRetiresNoUPIDAndSurvivesRestart(t *testing.T) {
	journal, clone, migration, parameters, now := legacyMigrationFixture(t)
	if _, duplicate, err := journal.ClaimWithAudit(migration, now.Add(2*time.Second), "0.1.0-rc.31"); err != nil || duplicate {
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
	initial := legacyInitialResourcesCommand(t, clone, migration, parameters, "initial-command", "initial-operation")
	if _, duplicate, err := journal.ClaimWithAudit(initial, now.Add(4*time.Second), "0.1.1-rc.3"); err != nil || duplicate {
		t.Fatalf("initial claim remained resource-busy after completed migration: duplicate=%t err=%v", duplicate, err)
	}
	if err := journal.AuthorizeInitialResources(initial, clone.OperationID, parameters.TemplateRef, parameters.SourceVMID, parameters.SourceConfigSHA256); err != nil {
		t.Fatalf("migrated lineage not authorized: %v", err)
	}
	reopened, err := OpenJournal(journal.directory)
	if err != nil {
		t.Fatal(err)
	}
	replayed, duplicate, err := reopened.ClaimWithAudit(migration, now.Add(4*time.Second), "0.1.0-rc.31")
	if err != nil || !duplicate || replayed.State != "succeeded" || !bytes.Equal(replayed.Result, resultRaw) {
		t.Fatalf("replay=%#v duplicate=%t err=%v", replayed, duplicate, err)
	}
	if err := reopened.AuthorizeInitialResources(initial, clone.OperationID, parameters.TemplateRef, parameters.SourceVMID, parameters.SourceConfigSHA256); err != nil {
		t.Fatalf("migrated lineage not authorized after restart: %v", err)
	}
}

func TestRetirementDoesNotReleaseResourceLockBeforeMigrationCompletion(t *testing.T) {
	journal, clone, migration, parameters, now := legacyMigrationFixture(t)
	if _, duplicate, err := journal.ClaimWithAudit(migration, now.Add(2*time.Second), "0.1.1-rc.3"); err != nil || duplicate {
		t.Fatalf("migration claim duplicate=%t err=%v", duplicate, err)
	}
	if _, err := journal.MigrateLegacyVMJournal(migration, parameters, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	initial := legacyInitialResourcesCommand(t, clone, migration, parameters, "incomplete-initial-command", "incomplete-initial-operation")
	if _, _, err := journal.ClaimWithAudit(initial, now.Add(4*time.Second), "0.1.1-rc.3"); !errors.Is(err, ErrResourceBusy) {
		t.Fatalf("uncommitted migration released resource lock: %v", err)
	}
}

func TestRC26LegacyMigrationReleasesDeleteLockAfterCompletionAndRestart(t *testing.T) {
	journal, _, migration, parameters, now := legacyMigrationFixture(t)
	delete := legacyDeleteCommand(migration, "rc26-delete-command", "rc26-delete-operation")
	if _, _, err := journal.ClaimWithAudit(delete, now.Add(2*time.Second), "0.1.1-rc.3"); !errors.Is(err, ErrResourceBusy) {
		t.Fatalf("unmigrated rc26 indeterminate record did not hold delete lock: %v", err)
	}
	if _, duplicate, err := journal.ClaimWithAudit(migration, now.Add(3*time.Second), "0.1.1-rc.3"); err != nil || duplicate {
		t.Fatalf("migration claim duplicate=%t err=%v", duplicate, err)
	}
	result, err := journal.MigrateLegacyVMJournal(migration, parameters, now.Add(4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	resultRaw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	migrationReceipt := Receipt{SchemaVersion: 1, ReceiptID: "88888888-8888-4888-8888-888888888888", CommandID: migration.CommandID,
		OperationID: migration.OperationID, AgentRef: migration.AgentRef, State: "succeeded", Code: "SUCCEEDED",
		ExecutionMode: "production", StartedAt: now.Add(3 * time.Second), FinishedAt: now.Add(4 * time.Second), Result: resultRaw}
	if err := journal.Complete(migration, migrationReceipt); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenJournal(journal.directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, duplicate, err := reopened.ClaimWithAudit(delete, now.Add(5*time.Second), "0.1.1-rc.3"); err != nil || duplicate {
		t.Fatalf("completed migration still blocked delete after restart: duplicate=%t err=%v", duplicate, err)
	}
	completeAuditedLegacyRecord(t, reopened, delete, "succeeded", now.Add(6*time.Second))
	if receipt, duplicate, err := reopened.ClaimWithAudit(delete, now.Add(7*time.Second), "0.1.1-rc.3"); err != nil || !duplicate || receipt.State != "succeeded" {
		t.Fatalf("delete replay=%#v duplicate=%t err=%v", receipt, duplicate, err)
	}
}

func TestTerminalDeleteRecordsDoNotHoldResourceLock(t *testing.T) {
	for _, state := range []string{"succeeded", "failed"} {
		t.Run(state, func(t *testing.T) {
			now := time.Now().UTC()
			journal, err := OpenJournal(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			first := legacyAuthorityCommand("vm.delete", `{"purge":true,"destroyUnreferencedDisks":true}`, "terminal-delete-"+state, "terminal-delete-operation-"+state)
			if _, duplicate, err := journal.ClaimWithAudit(first, now, "0.1.1-rc.3"); err != nil || duplicate {
				t.Fatalf("first claim duplicate=%t err=%v", duplicate, err)
			}
			completeAuditedLegacyRecord(t, journal, first, state, now.Add(time.Second))
			second := legacyAuthorityCommand("vm.delete", `{"purge":true,"destroyUnreferencedDisks":true}`, "next-delete-"+state, "next-delete-operation-"+state)
			if _, duplicate, err := journal.ClaimWithAudit(second, now.Add(2*time.Second), "0.1.1-rc.3"); err != nil || duplicate {
				t.Fatalf("terminal delete held resource lock: duplicate=%t err=%v", duplicate, err)
			}
		})
	}
}

func TestMalformedOrPartialRetirementMarkersRemainFailClosed(t *testing.T) {
	tests := map[string]func(*journalRecord, Command, time.Time){
		"command only": func(record *journalRecord, migration Command, _ time.Time) {
			record.RetiredByCommandID = migration.CommandID
		},
		"time only": func(record *journalRecord, _ Command, now time.Time) {
			record.RetiredAt = &now
		},
		"malformed command": func(record *journalRecord, _ Command, now time.Time) {
			record.RetiredByCommandID = "bad command id"
			record.RetiredAt = &now
		},
		"missing migration": func(record *journalRecord, _ Command, now time.Time) {
			record.RetiredByCommandID = "missing-migration-command"
			record.RetiredAt = &now
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			journal, clone, migration, parameters, now := legacyMigrationFixture(t)
			retiredPath := journal.path(parameters.RetireIndeterminateCommandIDs[0])
			record, err := readJournal(retiredPath)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&record, migration, now.Add(3*time.Second))
			if err := writeJournal(retiredPath, record); err != nil {
				t.Fatal(err)
			}
			initial := legacyInitialResourcesCommand(t, clone, migration, parameters, "malformed-initial-command", "malformed-initial-operation")
			if _, _, err := journal.ClaimWithAudit(initial, now.Add(4*time.Second), "0.1.1-rc.3"); err == nil {
				t.Fatal("malformed retirement released resource lock")
			}
			if _, err := os.Stat(retiredPath); err != nil {
				t.Fatalf("legacy journal file changed or disappeared: %v", err)
			}
		})
	}
}

func TestRetiredRecordAuthorityMismatchStillHoldsResourceLock(t *testing.T) {
	mutations := map[string]func(*journalRecord){
		"binding":    func(record *journalRecord) { record.BindingID = "22222222-2222-4222-8222-222222222222" },
		"device":     func(record *journalRecord) { record.DeviceID = "device-2" },
		"epoch":      func(record *journalRecord) { record.CredentialEpoch++ },
		"revision":   func(record *journalRecord) { record.AssignmentRevision++ },
		"vmid":       func(record *journalRecord) { record.VMID++ },
		"generation": func(record *journalRecord) { record.Generation++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			journal, clone, migration, parameters, now := legacyMigrationFixture(t)
			if _, duplicate, err := journal.ClaimWithAudit(migration, now.Add(2*time.Second), "0.1.1-rc.3"); err != nil || duplicate {
				t.Fatalf("migration claim duplicate=%t err=%v", duplicate, err)
			}
			result, err := journal.MigrateLegacyVMJournal(migration, parameters, now.Add(3*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			resultRaw, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			receipt := Receipt{SchemaVersion: 1, ReceiptID: "77777777-7777-4777-8777-777777777777", CommandID: migration.CommandID,
				OperationID: migration.OperationID, AgentRef: migration.AgentRef, State: "succeeded", Code: "SUCCEEDED",
				ExecutionMode: "production", StartedAt: now.Add(2 * time.Second), FinishedAt: now.Add(3 * time.Second), Result: resultRaw}
			if err := journal.Complete(migration, receipt); err != nil {
				t.Fatal(err)
			}
			retiredPath := journal.path(parameters.RetireIndeterminateCommandIDs[0])
			retired, err := readJournal(retiredPath)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&retired)
			if err := writeJournal(retiredPath, retired); err != nil {
				t.Fatal(err)
			}
			initial := legacyInitialResourcesCommand(t, clone, migration, parameters, "mismatch-initial-command", "mismatch-initial-operation")
			if _, _, err := journal.ClaimWithAudit(initial, now.Add(4*time.Second), "0.1.1-rc.3"); !errors.Is(err, ErrResourceBusy) {
				t.Fatalf("retired %s mismatch released resource lock: %v", name, err)
			}
		})
	}
}

func TestLegacyJournalMigrationRejectsAuthorityMismatchAndGenericClear(t *testing.T) {
	mutations := map[string]func(*journalRecord){
		"binding":        func(r *journalRecord) { r.BindingID = "22222222-2222-4222-8222-222222222222" },
		"device":         func(r *journalRecord) { r.DeviceID = "device-2" },
		"epoch":          func(r *journalRecord) { r.CredentialEpoch = 2 },
		"assignment":     func(r *journalRecord) { r.AssignmentRevision = 8 },
		"audit revision": func(r *journalRecord) { r.AuditContext.AssignmentRevision = 2 },
		"signing key":    func(r *journalRecord) { r.AuditContext.WebsiteCommandKeyID = "website-key-2" },
		"vmid":           func(r *journalRecord) { r.VMID = 102 },
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

func TestLegacyJournalMigrationRequiresExplicitOlderExactRevision(t *testing.T) {
	for name, revision := range map[string]uint64{"missing": 0, "current": 4, "future": 5, "wrong historical": 2} {
		t.Run(name, func(t *testing.T) {
			journal, _, migration, parameters, now := legacyMigrationFixture(t)
			parameters.LegacyAssignmentRevision = protocol.Counter(revision)
			raw, err := json.Marshal(parameters)
			if err != nil {
				t.Fatal(err)
			}
			migration.Parameters = raw
			if _, err := journal.MigrateLegacyVMJournal(migration, parameters, now); err == nil {
				t.Fatalf("legacy revision %d was accepted", revision)
			}
		})
	}
}

func TestLegacyJournalMigrationIsLinuxQEMUOnly(t *testing.T) {
	_, _, migration, parameters, _ := legacyMigrationFixture(t)
	migration.Identity.GuestType = "lxc"
	if validLegacyJournalMigration(migration, parameters) {
		t.Fatal("LXC legacy migration was accepted")
	}
}

func TestLegacyJournalMigrationRejectsRetirementFromDifferentLegacyRevision(t *testing.T) {
	journal, _, migration, parameters, now := legacyMigrationFixture(t)
	path := journal.path(parameters.RetireIndeterminateCommandIDs[0])
	record, err := readJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	record.AuditContext.AssignmentRevision = 2
	if err := writeJournal(path, record); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.MigrateLegacyVMJournal(migration, parameters, now); err == nil {
		t.Fatal("retirement from another legacy revision was accepted")
	}
}

func TestLegacyJournalMigrationAcceptsOnlyExactHistoricalIndeterminateCodes(t *testing.T) {
	t.Run("PVE result indeterminate", func(t *testing.T) {
		journal, _, migration, parameters, now := legacyMigrationFixture(t)
		path := journal.path(parameters.RetireIndeterminateCommandIDs[0])
		record, err := readJournal(path)
		if err != nil {
			t.Fatal(err)
		}
		record.Receipt.Code = "PVE_RESULT_INDETERMINATE"
		if err := writeJournal(path, record); err != nil {
			t.Fatal(err)
		}
		if _, duplicate, err := journal.ClaimWithAudit(migration, now.Add(2*time.Second), "0.1.0-rc.31"); err != nil || duplicate {
			t.Fatalf("migration claim duplicate=%t err=%v", duplicate, err)
		}
		result, err := journal.MigrateLegacyVMJournal(migration, parameters, now.Add(3*time.Second))
		if err != nil || !result.Migrated || len(result.RetiredIndeterminateCommandIDs) != 1 {
			t.Fatalf("result=%#v err=%v", result, err)
		}
		record, err = readJournal(path)
		if err != nil || record.RetiredByCommandID != migration.CommandID {
			t.Fatalf("retired record=%#v err=%v", record, err)
		}
	})

	t.Run("other code", func(t *testing.T) {
		journal, _, migration, parameters, now := legacyMigrationFixture(t)
		path := journal.path(parameters.RetireIndeterminateCommandIDs[0])
		record, err := readJournal(path)
		if err != nil {
			t.Fatal(err)
		}
		record.Receipt.Code = "OTHER_INDETERMINATE"
		if err := writeJournal(path, record); err != nil {
			t.Fatal(err)
		}
		if _, _, err := journal.ClaimWithAudit(migration, now.Add(2*time.Second), "0.1.0-rc.31"); !errors.Is(err, ErrListedRecordNotEligible) {
			t.Fatalf("unsupported historical code did not retain resource lock: %v", err)
		}
	})
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
		if _, _, err := journal.ClaimWithAudit(migration, now.Add(3*time.Second), "0.1.0-rc.31"); !errors.Is(err, ErrUnlistedActiveMutation) {
			t.Fatalf("unlisted mutation claim err=%v", err)
		}
	})
}

func restoreExactHistoricalAuthority(t *testing.T, journal *Journal, command Command) {
	t.Helper()
	record, err := readJournal(journal.path(command.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	record.IdempotencyKey = command.IdempotencyKey
	record.BindingID = command.BindingID
	record.DeviceID = command.DeviceID
	record.CredentialEpoch = command.CredentialEpoch
	record.AssignmentRevision = command.AssignmentRevision
	record.ClusterRef = command.Identity.ClusterRef
	record.ServiceRef = command.Identity.ServiceRef
	record.InstanceUUID = command.Identity.InstanceUUID
	record.GuestType = command.Identity.GuestType
	record.VMID = command.Identity.VMID
	record.Generation = protocol.Counter(command.Identity.Generation)
	resourceKey, err := journalResourceKey(command)
	if err != nil {
		t.Fatal(err)
	}
	record.ResourceKey = resourceKey
	if err := writeJournal(journal.path(command.CommandID), record); err != nil {
		t.Fatal(err)
	}
}

// This is the exact production regression shape which rc.32 incorrectly
// rejected before Claim: both historical records have complete authority,
// the clone succeeded at revision 3, and the explicitly listed no-UPID
// mutation ended with the older PVE_RESULT_INDETERMINATE code. The currently
// signed migration is revision 6.
func TestLegacyJournalMigrationAcceptsCompleteHistoricalAuthorityProductionShape(t *testing.T) {
	journal, clone, migration, parameters, now := legacyMigrationFixture(t)
	migration.AssignmentRevision = 6
	migration.Identity.VMID = 100
	clone.Identity.VMID = 100
	restoreExactHistoricalAuthority(t, journal, clone)

	indeterminateID := parameters.RetireIndeterminateCommandIDs[0]
	indeterminatePath := journal.path(indeterminateID)
	indeterminate, err := readJournal(indeterminatePath)
	if err != nil {
		t.Fatal(err)
	}
	indeterminateCommand := legacyAuthorityCommand(indeterminate.Action, `{}`, indeterminate.CommandID, indeterminate.OperationID)
	indeterminateCommand.AssignmentRevision = parameters.LegacyAssignmentRevision
	indeterminateCommand.Identity.VMID = 100
	restoreExactHistoricalAuthority(t, journal, indeterminateCommand)
	indeterminate, err = readJournal(indeterminatePath)
	if err != nil {
		t.Fatal(err)
	}
	indeterminate.Receipt.Code = "PVE_RESULT_INDETERMINATE"
	if err := writeJournal(indeterminatePath, indeterminate); err != nil {
		t.Fatal(err)
	}

	if _, duplicate, err := journal.ClaimWithAudit(migration, now.Add(2*time.Second), "0.1.1-rc.1"); err != nil || duplicate {
		t.Fatalf("production migration claim duplicate=%t err=%v", duplicate, err)
	}
	result, err := journal.MigrateLegacyVMJournal(migration, parameters, now.Add(3*time.Second))
	if err != nil || !result.Migrated || len(result.RetiredIndeterminateCommandIDs) != 1 {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	retired, err := readJournal(indeterminatePath)
	if err != nil || retired.RetiredByCommandID != migration.CommandID || retired.RetiredAt == nil {
		t.Fatalf("retired record=%#v err=%v", retired, err)
	}
	if _, statErr := os.Stat(indeterminatePath); statErr != nil {
		t.Fatalf("retired journal file was deleted: %v", statErr)
	}

	resultRaw, _ := json.Marshal(result)
	receipt := Receipt{SchemaVersion: 1, ReceiptID: "44444444-4444-4444-8444-444444444444", CommandID: migration.CommandID,
		OperationID: migration.OperationID, AgentRef: migration.AgentRef, State: "succeeded", Code: "SUCCEEDED",
		ExecutionMode: "production", StartedAt: now.Add(2 * time.Second), FinishedAt: now.Add(3 * time.Second), Result: resultRaw}
	if err := journal.Complete(migration, receipt); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenJournal(journal.directory)
	if err != nil {
		t.Fatal(err)
	}
	replayed, duplicate, err := reopened.ClaimWithAudit(migration, now.Add(4*time.Second), "0.1.1-rc.1")
	if err != nil || !duplicate || replayed.Code != "SUCCEEDED" || !bytes.Equal(replayed.Result, resultRaw) {
		t.Fatalf("restart replay=%#v duplicate=%t err=%v", replayed, duplicate, err)
	}

	initial := legacyInitialResourcesCommand(t, clone, migration, parameters, "production-initial-command", "production-initial-operation")
	if _, duplicate, err := reopened.ClaimWithAudit(initial, now.Add(5*time.Second), "0.1.1-rc.3"); err != nil || duplicate {
		t.Fatalf("production initial claim duplicate=%t err=%v", duplicate, err)
	}
	if err := reopened.AuthorizeInitialResources(initial, clone.OperationID, parameters.TemplateRef, parameters.SourceVMID, parameters.SourceConfigSHA256); err != nil {
		t.Fatalf("initial resources remained blocked after migration: %v", err)
	}
}

// This reproduces the older production records observed on VMID 100: the
// record-level action and clone source identity were absent, while the signed
// audit projection retained the exact action, revision, signer and VM target.
func TestLegacyJournalMigrationRecoversMissingActionAndCloneSourceFromSignedAudit(t *testing.T) {
	journal, clone, migration, parameters, now := legacyMigrationFixture(t)
	migration.AssignmentRevision = 6

	clonePath := journal.path(clone.CommandID)
	cloneRecord, err := readJournal(clonePath)
	if err != nil {
		t.Fatal(err)
	}
	cloneRecord.Action = ""
	cloneRecord.SourceConfigSHA256 = ""
	cloneRecord.SourceTemplateRef = ""
	cloneRecord.SourceVMID = 0
	cloneRecord.PVETaskUPID = "UPID:pve1:1:2:3:qmclone:101:root@pam!api:"
	cloneRecord.Receipt.PVETaskUPID = cloneRecord.PVETaskUPID
	if err := writeJournal(clonePath, cloneRecord); err != nil {
		t.Fatal(err)
	}

	indeterminatePath := journal.path(parameters.RetireIndeterminateCommandIDs[0])
	indeterminate, err := readJournal(indeterminatePath)
	if err != nil {
		t.Fatal(err)
	}
	indeterminate.Action = ""
	indeterminate.Receipt.Code = "PVE_RESULT_INDETERMINATE"
	if err := writeJournal(indeterminatePath, indeterminate); err != nil {
		t.Fatal(err)
	}

	if _, duplicate, err := journal.ClaimWithAudit(migration, now.Add(2*time.Second), "0.1.1-rc.2"); err != nil || duplicate {
		t.Fatalf("production migration claim duplicate=%t err=%v", duplicate, err)
	}
	result, err := journal.MigrateLegacyVMJournal(migration, parameters, now.Add(3*time.Second))
	if err != nil || !result.Migrated {
		t.Fatalf("result=%#v err=%v", result, err)
	}

	cloneRecord, err = readJournal(clonePath)
	if err != nil || cloneRecord.Action != "vm.clone" || cloneRecord.SourceConfigSHA256 != parameters.SourceConfigSHA256 ||
		cloneRecord.SourceTemplateRef != parameters.TemplateRef || cloneRecord.SourceVMID != parameters.SourceVMID ||
		cloneRecord.MigratedByCommandID != migration.CommandID {
		t.Fatalf("migrated clone=%#v err=%v", cloneRecord, err)
	}
	indeterminate, err = readJournal(indeterminatePath)
	if err != nil || indeterminate.Action != "vm.set-resources" || indeterminate.RetiredByCommandID != migration.CommandID {
		t.Fatalf("retired record=%#v err=%v", indeterminate, err)
	}
	if _, err := os.Stat(clonePath); err != nil {
		t.Fatalf("clone journal file was removed: %v", err)
	}
	if _, err := os.Stat(indeterminatePath); err != nil {
		t.Fatalf("retired journal file was removed: %v", err)
	}
	resultRaw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	receipt := Receipt{SchemaVersion: 1, ReceiptID: "55555555-5555-4555-8555-555555555555", CommandID: migration.CommandID,
		OperationID: migration.OperationID, AgentRef: migration.AgentRef, State: "succeeded", Code: "SUCCEEDED",
		ExecutionMode: "production", StartedAt: now.Add(2 * time.Second), FinishedAt: now.Add(3 * time.Second), Result: resultRaw}
	if err := journal.Complete(migration, receipt); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenJournal(journal.directory)
	if err != nil {
		t.Fatal(err)
	}
	replayed, duplicate, err := reopened.ClaimWithAudit(migration, now.Add(4*time.Second), "0.1.1-rc.2")
	if err != nil || !duplicate || replayed.Code != "SUCCEEDED" || !bytes.Equal(replayed.Result, resultRaw) {
		t.Fatalf("restart replay=%#v duplicate=%t err=%v", replayed, duplicate, err)
	}

	initial := legacyAuthorityCommand("vm.set-initial-resources", initialResourcesFixture, "recovered-initial-command", "recovered-initial-operation")
	initial.AssignmentRevision = migration.AssignmentRevision
	if err := reopened.AuthorizeInitialResources(initial, clone.OperationID, parameters.TemplateRef, parameters.SourceVMID, parameters.SourceConfigSHA256); err != nil {
		t.Fatalf("recovered clone lineage did not authorize initial resources: %v", err)
	}
}

func TestLegacyJournalMigrationRejectsMissingOrUntrustedAuditAction(t *testing.T) {
	for name, auditAction := range map[string]string{
		"missing":   "",
		"read only": "vm.verify-delivery",
		"wrong":     "vm.delete",
	} {
		t.Run(name, func(t *testing.T) {
			journal, clone, migration, parameters, _ := legacyMigrationFixture(t)
			record, err := readJournal(journal.path(clone.CommandID))
			if err != nil {
				t.Fatal(err)
			}
			record.Action = ""
			record.AuditContext.Action = auditAction
			resourceKey, err := journalResourceKey(migration)
			if err != nil {
				t.Fatal(err)
			}
			if err := legacyCloneEligibilityError(record, migration, parameters, resourceKey); !errors.Is(err, ErrCloneResourceIdentityMismatch) {
				t.Fatalf("eligibility error=%v", err)
			}
		})
	}
}

func TestLegacyJournalMigrationClaimReturnsSpecificConflictClasses(t *testing.T) {
	t.Run("clone journal not found", func(t *testing.T) {
		journal, clone, migration, _, now := legacyMigrationFixture(t)
		if err := os.Remove(journal.path(clone.CommandID)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := journal.ClaimWithAudit(migration, now, "0.1.1-rc.2"); !errors.Is(err, ErrCloneJournalNotFound) {
			t.Fatalf("claim error=%v", err)
		}
	})
	t.Run("clone digest mismatch", func(t *testing.T) {
		journal, _, migration, parameters, now := legacyMigrationFixture(t)
		parameters.LegacyCloneDigest = strings.Repeat("c", 64)
		raw, _ := json.Marshal(parameters)
		migration.Parameters = raw
		if _, _, err := journal.ClaimWithAudit(migration, now, "0.1.1-rc.2"); !errors.Is(err, ErrCloneDigestMismatch) {
			t.Fatalf("claim error=%v", err)
		}
	})
	t.Run("clone resource identity mismatch", func(t *testing.T) {
		journal, clone, migration, _, now := legacyMigrationFixture(t)
		record, _ := readJournal(journal.path(clone.CommandID))
		record.ResourceKey = "vm:cluster-1:qemu:999:1"
		if err := writeJournal(journal.path(clone.CommandID), record); err != nil {
			t.Fatal(err)
		}
		if _, _, err := journal.ClaimWithAudit(migration, now, "0.1.1-rc.2"); !errors.Is(err, ErrCloneResourceIdentityMismatch) {
			t.Fatalf("claim error=%v", err)
		}
	})
	t.Run("clone terminal receipt invalid", func(t *testing.T) {
		journal, clone, migration, _, now := legacyMigrationFixture(t)
		record, _ := readJournal(journal.path(clone.CommandID))
		record.State = "failed"
		record.Receipt.State = "failed"
		record.Receipt.Code = "PVE_TASK_FAILED"
		if err := writeJournal(journal.path(clone.CommandID), record); err != nil {
			t.Fatal(err)
		}
		if _, _, err := journal.ClaimWithAudit(migration, now, "0.1.1-rc.2"); !errors.Is(err, ErrCloneTerminalReceiptInvalid) {
			t.Fatalf("claim error=%v", err)
		}
	})
	t.Run("clone legacy authority mismatch", func(t *testing.T) {
		journal, clone, migration, _, now := legacyMigrationFixture(t)
		record, _ := readJournal(journal.path(clone.CommandID))
		record.AuditContext.WebsiteCommandKeyID = "website-key-2"
		if err := writeJournal(journal.path(clone.CommandID), record); err != nil {
			t.Fatal(err)
		}
		if _, _, err := journal.ClaimWithAudit(migration, now, "0.1.1-rc.2"); !errors.Is(err, ErrCloneLegacyAuthorityMismatch) {
			t.Fatalf("claim error=%v", err)
		}
	})
	t.Run("clone already migrated", func(t *testing.T) {
		journal, _, migration, parameters, now := legacyMigrationFixture(t)
		if _, err := journal.MigrateLegacyVMJournal(migration, parameters, now); err != nil {
			t.Fatal(err)
		}
		second := migration
		second.CommandID = "second-migration-command"
		second.OperationID = "second-migration-operation"
		second.IdempotencyKey = "second-migration-idempotency"
		if _, _, err := journal.ClaimWithAudit(second, now.Add(time.Second), "0.1.1-rc.2"); !errors.Is(err, ErrCloneAlreadyMigrated) {
			t.Fatalf("claim error=%v", err)
		}
	})
	t.Run("listed record not eligible", func(t *testing.T) {
		journal, _, migration, parameters, now := legacyMigrationFixture(t)
		record, _ := readJournal(journal.path(parameters.RetireIndeterminateCommandIDs[0]))
		record.PVETaskUPID = "UPID:pve1:1:2:3:qmconfig:100:root@pam!api:"
		record.Receipt.PVETaskUPID = record.PVETaskUPID
		if err := writeJournal(journal.path(record.CommandID), record); err != nil {
			t.Fatal(err)
		}
		if _, _, err := journal.ClaimWithAudit(migration, now, "0.1.1-rc.1"); !errors.Is(err, ErrListedRecordNotEligible) {
			t.Fatalf("claim error=%v", err)
		}
	})
}

func TestLegacyJournalMigrationRetiresNewIndeterminateOnAlreadyMigratedLineage(t *testing.T) {
	journal, clone, migration, parameters, now := legacyMigrationFixture(t)
	if _, duplicate, err := journal.ClaimWithAudit(migration, now.Add(2*time.Second), "0.1.1-rc.21"); err != nil || duplicate {
		t.Fatalf("first migration claim duplicate=%t err=%v", duplicate, err)
	}
	firstResult, err := journal.MigrateLegacyVMJournal(migration, parameters, now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	firstRaw, _ := json.Marshal(firstResult)
	firstReceipt := Receipt{SchemaVersion: 1, ReceiptID: "66666666-6666-4666-8666-666666666666", CommandID: migration.CommandID,
		OperationID: migration.OperationID, AgentRef: migration.AgentRef, State: "succeeded", Code: "SUCCEEDED",
		ExecutionMode: "production", StartedAt: now.Add(2 * time.Second), FinishedAt: now.Add(3 * time.Second), Result: firstRaw}
	if err := journal.Complete(migration, firstReceipt); err != nil {
		t.Fatal(err)
	}

	indeterminate := legacyAuthorityCommand("vm.set-timezone", `{"timezone":"UTC"}`, "followup-indeterminate-command", "followup-indeterminate-operation")
	indeterminate.AssignmentRevision = migration.AssignmentRevision
	indeterminate.Identity = migration.Identity
	if _, duplicate, err := journal.ClaimWithAudit(indeterminate, now.Add(4*time.Second), "0.1.1-rc.21"); err != nil || duplicate {
		t.Fatalf("follow-up mutation claim duplicate=%t err=%v", duplicate, err)
	}
	indeterminateReceipt := Receipt{SchemaVersion: 1, ReceiptID: "77777777-7777-4777-8777-777777777777", CommandID: indeterminate.CommandID,
		OperationID: indeterminate.OperationID, AgentRef: indeterminate.AgentRef, State: "indeterminate", Code: "PVE_RESULT_INDETERMINATE",
		ExecutionMode: "production", StartedAt: now.Add(4 * time.Second), FinishedAt: now.Add(4 * time.Second)}
	if err := journal.Complete(indeterminate, indeterminateReceipt); err != nil {
		t.Fatal(err)
	}

	parameters.LegacyAssignmentRevision = migration.AssignmentRevision
	parameters.RetireIndeterminateCommandIDs = []string{indeterminate.CommandID}
	parametersRaw, _ := json.Marshal(parameters)
	second := migration
	second.CommandID = "followup-migration-command"
	second.OperationID = "followup-migration-operation"
	second.IdempotencyKey = "followup-migration-idempotency"
	second.AssignmentRevision++
	second.Parameters = parametersRaw
	if _, duplicate, err := journal.ClaimWithAudit(second, now.Add(5*time.Second), "0.1.1-rc.22"); err != nil || duplicate {
		t.Fatalf("follow-up migration claim duplicate=%t err=%v", duplicate, err)
	}
	secondResult, err := journal.MigrateLegacyVMJournal(second, parameters, now.Add(6*time.Second))
	if err != nil || !secondResult.Migrated || len(secondResult.RetiredIndeterminateCommandIDs) != 1 {
		t.Fatalf("follow-up migration result=%#v err=%v", secondResult, err)
	}
	secondRaw, _ := json.Marshal(secondResult)
	secondReceipt := Receipt{SchemaVersion: 1, ReceiptID: "99999999-9999-4999-8999-999999999999", CommandID: second.CommandID,
		OperationID: second.OperationID, AgentRef: second.AgentRef, State: "succeeded", Code: "SUCCEEDED",
		ExecutionMode: "production", StartedAt: now.Add(5 * time.Second), FinishedAt: now.Add(6 * time.Second), Result: secondRaw}
	if err := journal.Complete(second, secondReceipt); err != nil {
		t.Fatal(err)
	}
	cloneRecord, err := readJournal(journal.path(clone.CommandID))
	if err != nil || cloneRecord.MigratedByCommandID != migration.CommandID || cloneRecord.AssignmentRevision != migration.AssignmentRevision {
		t.Fatalf("original clone migration marker changed: record=%#v err=%v", cloneRecord, err)
	}
	retired, err := readJournal(journal.path(indeterminate.CommandID))
	if err != nil || retired.RetiredByCommandID != second.CommandID || retired.AssignmentRevision != second.AssignmentRevision {
		t.Fatalf("follow-up record was not retired: record=%#v err=%v", retired, err)
	}

	// A later recovery may need another read-only assignment revision between
	// the indeterminate mutation and its migration. The immutable clone marker
	// remains on the first migration authority, while the explicitly named new
	// record belongs to a later revision on the same binding and VM lineage.
	thirdIndeterminate := legacyAuthorityCommand("vm.set-timezone", `{"timezone":"America/Los_Angeles"}`, "third-indeterminate-command", "third-indeterminate-operation")
	thirdIndeterminate.AssignmentRevision = second.AssignmentRevision + 1
	thirdIndeterminate.Identity = migration.Identity
	if _, duplicate, err := journal.ClaimWithAudit(thirdIndeterminate, now.Add(7*time.Second), "0.1.1-rc.23"); err != nil || duplicate {
		t.Fatalf("third mutation claim duplicate=%t err=%v", duplicate, err)
	}
	thirdReceipt := Receipt{SchemaVersion: 1, ReceiptID: "88888888-8888-4888-8888-888888888888", CommandID: thirdIndeterminate.CommandID,
		OperationID: thirdIndeterminate.OperationID, AgentRef: thirdIndeterminate.AgentRef, State: "indeterminate", Code: "PVE_RESULT_INDETERMINATE",
		ExecutionMode: "production", StartedAt: now.Add(7 * time.Second), FinishedAt: now.Add(7 * time.Second)}
	if err := journal.Complete(thirdIndeterminate, thirdReceipt); err != nil {
		t.Fatal(err)
	}

	parameters.LegacyAssignmentRevision = thirdIndeterminate.AssignmentRevision
	parameters.RetireIndeterminateCommandIDs = []string{thirdIndeterminate.CommandID}
	thirdParametersRaw, _ := json.Marshal(parameters)
	third := second
	third.CommandID = "third-migration-command"
	third.OperationID = "third-migration-operation"
	third.IdempotencyKey = "third-migration-idempotency"
	third.AssignmentRevision = thirdIndeterminate.AssignmentRevision + 2
	third.Parameters = thirdParametersRaw
	if _, duplicate, err := journal.ClaimWithAudit(third, now.Add(8*time.Second), "0.1.1-rc.24"); err != nil || duplicate {
		t.Fatalf("third migration claim duplicate=%t err=%v", duplicate, err)
	}
	thirdResult, err := journal.MigrateLegacyVMJournal(third, parameters, now.Add(9*time.Second))
	if err != nil || !thirdResult.Migrated || len(thirdResult.RetiredIndeterminateCommandIDs) != 1 {
		t.Fatalf("third migration result=%#v err=%v", thirdResult, err)
	}
	thirdRetired, err := readJournal(journal.path(thirdIndeterminate.CommandID))
	if err != nil || thirdRetired.RetiredByCommandID != third.CommandID || thirdRetired.AssignmentRevision != third.AssignmentRevision {
		t.Fatalf("third follow-up record was not retired: record=%#v err=%v", thirdRetired, err)
	}
	cloneRecord, err = readJournal(journal.path(clone.CommandID))
	if err != nil || cloneRecord.MigratedByCommandID != migration.CommandID || cloneRecord.AssignmentRevision != migration.AssignmentRevision {
		t.Fatalf("clone migration marker changed after repeated follow-up: record=%#v err=%v", cloneRecord, err)
	}
}

func TestLegacyJournalMigrationConflictReceiptCodesAreStableAndRedacted(t *testing.T) {
	tests := []struct {
		err  error
		code string
	}{
		{fmt.Errorf("wrapped record id: %w", ErrUnlistedActiveMutation), "UNLISTED_ACTIVE_MUTATION"},
		{fmt.Errorf("wrapped record id: %w", ErrListedRecordNotEligible), "LISTED_RECORD_NOT_ELIGIBLE"},
		{fmt.Errorf("wrapped record id: %w", ErrCloneJournalNotFound), "CLONE_JOURNAL_NOT_FOUND"},
		{fmt.Errorf("wrapped record id: %w", ErrCloneDigestMismatch), "CLONE_DIGEST_MISMATCH"},
		{fmt.Errorf("wrapped record id: %w", ErrCloneResourceIdentityMismatch), "CLONE_RESOURCE_IDENTITY_MISMATCH"},
		{fmt.Errorf("wrapped record id: %w", ErrCloneTerminalReceiptInvalid), "CLONE_TERMINAL_RECEIPT_INVALID"},
		{fmt.Errorf("wrapped record id: %w", ErrCloneLegacyAuthorityMismatch), "CLONE_LEGACY_AUTHORITY_MISMATCH"},
		{fmt.Errorf("wrapped record id: %w", ErrCloneAlreadyMigrated), "CLONE_ALREADY_MIGRATED"},
	}
	for _, test := range tests {
		if got := claimRejectionCode(test.err); got != test.code || strings.Contains(got, "record id") {
			t.Fatalf("error=%v code=%q want=%q", test.err, got, test.code)
		}
	}
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
	if err != nil || !validLegacyMigrationJournalResult(&journalRecord{AssignmentRevision: 4}, resultRaw) {
		t.Fatalf("legacy migration result golden err=%v", err)
	}
	if validLegacyMigrationJournalResult(&journalRecord{AssignmentRevision: 3}, resultRaw) {
		t.Fatal("legacy migration result was accepted without an older revision")
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
