package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func delete501RecoveryFixture(t *testing.T) (*Journal, Command, delete501RecoveryP, time.Time) {
	t.Helper()
	now := time.Date(2026, 9, 3, 17, 21, 54, 0, time.UTC)
	journal, err := OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	failed := legacyAuthorityCommand("vm.delete", `{"purge":true,"destroyUnreferencedDisks":true}`, delete501CommandID, delete501OperationID)
	failed.AssignmentRevision = 6
	failed.Identity.VMID = delete501VMID
	failed.Identity.Generation = delete501Generation
	if _, duplicate, claimErr := journal.ClaimWithAudit(failed, now, delete501AffectedAgent); claimErr != nil || duplicate {
		t.Fatalf("failed claim duplicate=%t err=%v", duplicate, claimErr)
	}
	receipt := Receipt{
		SchemaVersion: SchemaVersion, ReceiptID: "11111111-1111-4111-8111-111111111111",
		CommandID: failed.CommandID, OperationID: failed.OperationID, AgentRef: failed.AgentRef,
		State: "indeterminate", Code: "PVE_ACTION_INDETERMINATE", ExecutionMode: "production",
		StartedAt: now, FinishedAt: now,
	}
	if err := journal.Complete(failed, receipt); err != nil {
		t.Fatal(err)
	}
	record, err := readJournal(journal.path(failed.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	// The exact production digest is part of the independently audited tuple.
	record.Digest = delete501CommandDigest
	if err := writeJournal(journal.path(failed.CommandID), record); err != nil {
		t.Fatal(err)
	}

	parameters := delete501RecoveryP{
		RecoveryKind: delete501RecoveryKind, FailedCommandID: delete501CommandID,
		FailedOperationID: delete501OperationID, FailedCommandDigest: delete501CommandDigest,
	}
	raw, err := json.Marshal(parameters)
	if err != nil {
		t.Fatal(err)
	}
	recovery := legacyAuthorityCommand("vm.migrate-legacy-journal", string(raw), "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333")
	recovery.AssignmentRevision = 6
	recovery.Identity = failed.Identity
	return journal, recovery, parameters, now
}

func recordWithoutRetirement(record journalRecord) journalRecord {
	record.RetiredByCommandID = ""
	record.RetiredAt = nil
	return record
}

func TestDelete501RecoveryRetiresOnlyExactRecordAndSurvivesRestart(t *testing.T) {
	journal, recovery, parameters, now := delete501RecoveryFixture(t)
	before, err := readJournal(journal.path(parameters.FailedCommandID))
	if err != nil {
		t.Fatal(err)
	}
	if _, duplicate, err := journal.ClaimWithAudit(recovery, now.Add(time.Second), "0.1.1-rc.7"); err != nil || duplicate {
		t.Fatalf("recovery claim duplicate=%t err=%v", duplicate, err)
	}
	result, err := journal.ReconcileDelete501(recovery, parameters, delete501ExpectedPVEVersion, "stopped", now.Add(2*time.Second))
	if err != nil || !validDelete501RecoveryJournalResult(&journalRecord{Action: recovery.Action}, mustJSON(t, result)) {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	after, err := readJournal(journal.path(parameters.FailedCommandID))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, recordWithoutRetirement(after)) {
		t.Fatalf("historical record changed beyond retirement markers\nbefore=%#v\nafter=%#v", before, after)
	}

	freshDelete := legacyDeleteCommand(recovery, "44444444-4444-4444-8444-444444444444", "55555555-5555-4555-8555-555555555555")
	if _, _, err := journal.ClaimWithAudit(freshDelete, now.Add(3*time.Second), "0.1.1-rc.7"); !errors.Is(err, ErrResourceBusy) {
		t.Fatalf("partial retirement released resource before recovery completion: %v", err)
	}
	resultRaw := mustJSON(t, result)
	receipt := Receipt{SchemaVersion: SchemaVersion, ReceiptID: "66666666-6666-4666-8666-666666666666",
		CommandID: recovery.CommandID, OperationID: recovery.OperationID, AgentRef: recovery.AgentRef,
		State: "succeeded", Code: "SUCCEEDED", ExecutionMode: "production", StartedAt: now.Add(time.Second),
		FinishedAt: now.Add(2 * time.Second), Result: resultRaw}
	if err := journal.Complete(recovery, receipt); err != nil {
		t.Fatal(err)
	}
	if _, duplicate, err := journal.ClaimWithAudit(freshDelete, now.Add(3*time.Second), "0.1.1-rc.7"); err != nil || duplicate {
		t.Fatalf("completed recovery did not release resource: duplicate=%t err=%v", duplicate, err)
	}
	reopened, err := OpenJournal(journal.directory)
	if err != nil {
		t.Fatal(err)
	}
	replayed, duplicate, err := reopened.ClaimWithAudit(recovery, now.Add(4*time.Second), "0.1.1-rc.7")
	if err != nil || !duplicate || replayed.State != "succeeded" || !bytes.Equal(replayed.Result, resultRaw) {
		t.Fatalf("replay=%#v duplicate=%t err=%v", replayed, duplicate, err)
	}
}

func TestDelete501RecoveryRequiresExactHistoricalTuple(t *testing.T) {
	mutations := map[string]func(*journalRecord){
		"command":      func(r *journalRecord) { r.CommandID = "wrong-command" },
		"operation":    func(r *journalRecord) { r.OperationID = "wrong-operation" },
		"digest":       func(r *journalRecord) { r.Digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
		"action":       func(r *journalRecord) { r.Action = "vm.stop" },
		"receipt code": func(r *journalRecord) { r.Receipt.Code = "EXECUTION_INDETERMINATE" },
		"upid": func(r *journalRecord) {
			r.PVETaskUPID, r.Receipt.PVETaskUPID = "UPID:pve:1:2:3:delete:100:user:", "UPID:pve:1:2:3:delete:100:user:"
		},
		"accepted":      func(r *journalRecord) { r.Receipt.Accepted = true },
		"not mutating":  func(r *journalRecord) { r.Mutating = false },
		"agent version": func(r *journalRecord) { r.AuditContext.AgentVersion = "0.1.1-rc.5" },
		"vmid":          func(r *journalRecord) { r.VMID = 101 },
		"generation":    func(r *journalRecord) { r.Generation = 2 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			journal, recovery, parameters, now := delete501RecoveryFixture(t)
			record, err := readJournal(journal.path(parameters.FailedCommandID))
			if err != nil {
				t.Fatal(err)
			}
			mutate(&record)
			if err := writeJournal(journal.path(parameters.FailedCommandID), record); err != nil {
				t.Fatal(err)
			}
			if _, _, err := journal.ClaimWithAudit(recovery, now.Add(time.Second), "0.1.1-rc.7"); err == nil {
				t.Fatal("mismatched historical record was accepted")
			}
		})
	}
}

func TestDelete501RecoveryResultMismatchDoesNotReleaseResource(t *testing.T) {
	journal, recovery, parameters, now := delete501RecoveryFixture(t)
	if _, duplicate, err := journal.ClaimWithAudit(recovery, now.Add(time.Second), "0.1.1-rc.7"); err != nil || duplicate {
		t.Fatalf("claim duplicate=%t err=%v", duplicate, err)
	}
	result, err := journal.ReconcileDelete501(recovery, parameters, delete501ExpectedPVEVersion, "stopped", now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	result.FailedCommandDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	receipt := Receipt{SchemaVersion: SchemaVersion, ReceiptID: "99999999-9999-4999-8999-999999999999",
		CommandID: recovery.CommandID, OperationID: recovery.OperationID, AgentRef: recovery.AgentRef,
		State: "succeeded", Code: "SUCCEEDED", ExecutionMode: "production", StartedAt: now.Add(time.Second),
		FinishedAt: now.Add(2 * time.Second), Result: mustJSON(t, result)}
	if err := journal.Complete(recovery, receipt); err != nil {
		t.Fatal(err)
	}
	freshDelete := legacyDeleteCommand(recovery, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
	if _, _, err := journal.ClaimWithAudit(freshDelete, now.Add(3*time.Second), "0.1.1-rc.7"); !errors.Is(err, ErrResourceBusy) {
		t.Fatalf("mismatched durable result released resource: %v", err)
	}
}

func TestDelete501RecoveryRejectsOtherActiveMutationAndBadReadProof(t *testing.T) {
	journal, recovery, parameters, now := delete501RecoveryFixture(t)
	other := legacyDeleteCommand(recovery, "77777777-7777-4777-8777-777777777777", "88888888-8888-4888-8888-888888888888")
	other.Action = "vm.stop"
	resourceKey, _ := journalResourceKey(other)
	record := journalRecord{Version: SchemaVersion, CommandID: other.CommandID, OperationID: other.OperationID,
		IdempotencyKey: other.IdempotencyKey, AgentRef: other.AgentRef, BindingID: other.BindingID, DeviceID: other.DeviceID,
		CredentialEpoch: other.CredentialEpoch, AssignmentRevision: other.AssignmentRevision, Scope: ScopeVM,
		Action: other.Action, ClusterRef: other.Identity.ClusterRef, ServiceRef: other.Identity.ServiceRef,
		InstanceUUID: other.Identity.InstanceUUID, GuestType: "qemu", VMID: delete501VMID, Generation: delete501Generation,
		Mutating: true, Digest: Digest(other), ResourceKey: resourceKey, NodeRef: other.Identity.NodeRef,
		State: "received", CreatedAt: now, UpdatedAt: now}
	if err := writeJournal(journal.path(other.CommandID), record); err != nil {
		t.Fatal(err)
	}
	if _, _, err := journal.ClaimWithAudit(recovery, now.Add(time.Second), "0.1.1-rc.7"); !errors.Is(err, ErrUnlistedActiveMutation) {
		t.Fatalf("other active mutation was not rejected: %v", err)
	}

	journal, recovery, parameters, now = delete501RecoveryFixture(t)
	if _, duplicate, err := journal.ClaimWithAudit(recovery, now.Add(time.Second), "0.1.1-rc.7"); err != nil || duplicate {
		t.Fatalf("claim duplicate=%t err=%v", duplicate, err)
	}
	if _, err := journal.ReconcileDelete501(recovery, parameters, "8.3.0", "stopped", now); err == nil {
		t.Fatal("wrong PVE version accepted")
	}
	if _, err := journal.ReconcileDelete501(recovery, parameters, delete501ExpectedPVEVersion, "running", now); err == nil {
		t.Fatal("running guest accepted")
	}
}

func TestDelete501RecoveryExecutorUsesReadOnlyPVEProof(t *testing.T) {
	journal, recovery, _, now := delete501RecoveryFixture(t)
	if _, duplicate, err := journal.ClaimWithAudit(recovery, now.Add(time.Second), "0.1.1-rc.7"); err != nil || duplicate {
		t.Fatalf("claim duplicate=%t err=%v", duplicate, err)
	}
	requests := make([]string, 0, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("recovery attempted a mutation: %s %s", r.Method, r.URL.String())
		}
		requests = append(requests, r.URL.Path)
		switch r.URL.Path {
		case "/api2/json/version":
			_, _ = fmt.Fprint(w, `{"data":{"version":"8.4.0","release":"8.4"}}`)
		case "/api2/json/nodes/pve1/qemu/100/config":
			_, _ = fmt.Fprint(w, `{"data":{"digest":"config-digest"}}`)
		case "/api2/json/nodes/pve1/qemu/100/status/current":
			_, _ = fmt.Fprint(w, `{"data":{"status":"stopped"}}`)
		default:
			t.Fatalf("unexpected request: %s", r.URL.Path)
		}
	}))
	defer server.Close()
	client := controlTestClient(t, server)
	executor := Executor{Client: client, ReadClient: client, Delete501Journal: journal, Mode: "production", ProductionExecution: true}
	receipt, err := executor.Execute(context.Background(), recovery, now.Add(2*time.Second))
	if err != nil || receipt.State != "succeeded" || receipt.Code != "SUCCEEDED" ||
		!validDelete501RecoveryJournalResult(&journalRecord{Action: recovery.Action}, receipt.Result) {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	want := []string{"/api2/json/version", "/api2/json/nodes/pve1/qemu/100/config", "/api2/json/nodes/pve1/qemu/100/status/current"}
	if !reflect.DeepEqual(requests, want) {
		t.Fatalf("requests=%v want=%v", requests, want)
	}
}

func TestDelete501RecoveryGoldenContracts(t *testing.T) {
	requestRaw, err := os.ReadFile(filepath.Join("testdata", "agent-v1-vm-migrate-delete-501.json"))
	if err != nil {
		t.Fatal(err)
	}
	command := legacyAuthorityCommand("vm.migrate-legacy-journal", string(requestRaw), "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333")
	command.AssignmentRevision = 6
	command.Identity.VMID = delete501VMID
	command.Identity.Generation = delete501Generation
	if err := validateParameters(command); err != nil {
		t.Fatalf("golden request rejected: %v", err)
	}
	resultRaw, err := os.ReadFile(filepath.Join("testdata", "agent-v1-vm-migrate-delete-501-result.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !validDelete501RecoveryJournalResult(&journalRecord{Action: command.Action}, resultRaw) {
		t.Fatal("golden result rejected")
	}
}

func mustJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
