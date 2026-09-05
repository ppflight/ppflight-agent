package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func ipFilterDeleteRecoveryFixture(t *testing.T) (*Journal, Command, ipFilterDeleteRecoveryP, time.Time) {
	t.Helper()
	now := time.Date(2026, 9, 4, 23, 6, 41, 0, time.UTC)
	journal, err := OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	failed := legacyAuthorityCommand(
		"firewall.ipset.entry.delete",
		`{"cidr":"74.91.18.94/32","name":"ipfilter-net0"}`,
		"0547b29e-f4b6-4cce-8077-e2681ef31888",
		"6dcdbab8-b3dd-433a-aa13-682523c2b72b",
	)
	failed.BodySHA256 = "aaf4d3e7b44254ea194884730a9d2b56549e10028057700ce859764588fba2e5"
	failed.AssignmentRevision = 29
	failed.Identity.Generation = 4
	if _, duplicate, claimErr := journal.ClaimWithAudit(failed, now, "0.1.1-rc.41"); claimErr != nil || duplicate {
		t.Fatalf("failed claim duplicate=%t err=%v", duplicate, claimErr)
	}
	receipt := Receipt{
		SchemaVersion: SchemaVersion, ReceiptID: "67b7585f-d608-5662-9060-c7b21481769d",
		CommandID: failed.CommandID, OperationID: failed.OperationID, AgentRef: failed.AgentRef,
		State: "indeterminate", Code: "PVE_RESULT_INDETERMINATE", ExecutionMode: "production",
		StartedAt: now, FinishedAt: now, MutationMayHaveSucceeded: true,
	}
	if err := journal.Complete(failed, receipt); err != nil {
		t.Fatal(err)
	}
	failedRecord, err := readJournal(journal.path(failed.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	parameters := ipFilterDeleteRecoveryP{
		RecoveryKind: ipFilterDeleteRecoveryKind, LegacyAssignmentRevision: 29,
		FailedCommandID: failed.CommandID, FailedOperationID: failed.OperationID,
		FailedCommandDigest: failedRecord.Digest, FailedPayloadSHA256: ipFilterDeletePayloadSHA256("ipfilter-net0", "74.91.18.94/32"),
		FailedWireBodySHA256: failed.BodySHA256,
		Name:                 "ipfilter-net0", CIDR: "74.91.18.94/32",
	}
	raw, err := json.Marshal(parameters)
	if err != nil {
		t.Fatal(err)
	}
	recovery := legacyAuthorityCommand(
		"vm.migrate-legacy-journal", string(raw),
		"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222",
	)
	recovery.AssignmentRevision = 31
	recovery.Identity = failed.Identity
	return journal, recovery, parameters, now
}

func TestIPFilterDeletePayloadSHA256KeepsCanonicalAndHistoricalWireDigestsDistinct(t *testing.T) {
	const canonical = "0811290452aa58df2e7d07c618fe0b967439d3aa2c14175b8a81f2c4771def93"
	const wire = "aaf4d3e7b44254ea194884730a9d2b56549e10028057700ce859764588fba2e5"
	if actual := ipFilterDeletePayloadSHA256("ipfilter-net0", "74.91.18.94/32"); actual != canonical {
		t.Fatalf("payload digest=%q want %q", actual, canonical)
	}
	if canonical == wire {
		t.Fatal("historical wire and canonical payload digests unexpectedly match")
	}
}

func TestIPFilterDeleteRecoveryRequiresReadProofAndDurableCompletion(t *testing.T) {
	journal, recovery, parameters, now := ipFilterDeleteRecoveryFixture(t)
	before, err := readJournal(journal.path(parameters.FailedCommandID))
	if err != nil {
		t.Fatal(err)
	}
	if _, duplicate, err := journal.ClaimWithAudit(recovery, now.Add(time.Second), "0.1.1-rc.43"); err != nil || duplicate {
		t.Fatalf("recovery claim duplicate=%t err=%v", duplicate, err)
	}
	result, err := journal.ReconcileIPFilterDelete(recovery, parameters, true, "74.91.18.94", now.Add(2*time.Second))
	if err != nil || !validIPFilterDeleteRecoveryJournalResult(&journalRecord{Action: recovery.Action, AssignmentRevision: recovery.AssignmentRevision}, mustJSON(t, result)) {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	after, err := readJournal(journal.path(parameters.FailedCommandID))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, recordWithoutRetirement(after)) {
		t.Fatalf("historical record changed beyond retirement markers\nbefore=%#v\nafter=%#v", before, after)
	}

	freshDelete := legacyAuthorityCommand("firewall.ipset.entry.delete", `{"name":"ipfilter-net0","cidr":"74.91.18.94/32"}`, "33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444")
	freshDelete.AssignmentRevision, freshDelete.Identity = recovery.AssignmentRevision, recovery.Identity
	if _, _, err := journal.ClaimWithAudit(freshDelete, now.Add(3*time.Second), "0.1.1-rc.43"); !errors.Is(err, ErrResourceBusy) {
		t.Fatalf("partial recovery released resource: %v", err)
	}
	resultRaw := mustJSON(t, result)
	receipt := Receipt{
		SchemaVersion: SchemaVersion, ReceiptID: "55555555-5555-4555-8555-555555555555",
		CommandID: recovery.CommandID, OperationID: recovery.OperationID, AgentRef: recovery.AgentRef,
		State: "succeeded", Code: "SUCCEEDED", ExecutionMode: "production",
		StartedAt: now.Add(time.Second), FinishedAt: now.Add(2 * time.Second), Result: resultRaw,
	}
	if err := journal.Complete(recovery, receipt); err != nil {
		t.Fatal(err)
	}
	if _, duplicate, err := journal.ClaimWithAudit(freshDelete, now.Add(3*time.Second), "0.1.1-rc.43"); err != nil || duplicate {
		t.Fatalf("completed recovery did not release resource: duplicate=%t err=%v", duplicate, err)
	}
	reopened, err := OpenJournal(journal.directory)
	if err != nil {
		t.Fatal(err)
	}
	replayed, duplicate, err := reopened.ClaimWithAudit(recovery, now.Add(4*time.Second), "0.1.1-rc.43")
	if err != nil || !duplicate || replayed.State != "succeeded" || !bytes.Equal(replayed.Result, resultRaw) {
		t.Fatalf("replay=%#v duplicate=%t err=%v", replayed, duplicate, err)
	}
}

func TestIPFilterDeleteRecoveryRejectsWrongIdentityAndReadProof(t *testing.T) {
	for name, mutate := range map[string]func(*ipFilterDeleteRecoveryP){
		"operation": func(p *ipFilterDeleteRecoveryP) { p.FailedOperationID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" },
		"digest": func(p *ipFilterDeleteRecoveryP) {
			p.FailedCommandDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		},
		"wire body digest": func(p *ipFilterDeleteRecoveryP) {
			p.FailedWireBodySHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		},
		"revision": func(p *ipFilterDeleteRecoveryP) { p.LegacyAssignmentRevision = 28 },
		"cidr":     func(p *ipFilterDeleteRecoveryP) { p.CIDR = "74.91.18.95/32" },
	} {
		t.Run(name, func(t *testing.T) {
			journal, recovery, parameters, now := ipFilterDeleteRecoveryFixture(t)
			mutate(&parameters)
			raw, _ := json.Marshal(parameters)
			recovery.Parameters = raw
			if _, _, err := journal.ClaimWithAudit(recovery, now.Add(time.Second), "0.1.1-rc.43"); err == nil {
				t.Fatal("mismatched recovery was accepted")
			}
		})
	}
	journal, recovery, parameters, now := ipFilterDeleteRecoveryFixture(t)
	if _, _, err := journal.ClaimWithAudit(recovery, now.Add(time.Second), "0.1.1-rc.43"); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.ReconcileIPFilterDelete(recovery, parameters, true, "74.91.18.95", now.Add(2*time.Second)); err == nil {
		t.Fatal("mismatched provider read was accepted")
	}
}

func TestIPFilterDeleteRecoveryEligibilityHasSafeSpecificReceiptCodes(t *testing.T) {
	tests := []struct {
		name string
		want string
		edit func(*journalRecord, *Command, *ipFilterDeleteRecoveryP)
	}{
		{"request", "IPFILTER_RECOVERY_REQUEST_MISMATCH", func(_ *journalRecord, _ *Command, p *ipFilterDeleteRecoveryP) { p.FailedWireBodySHA256 = "bad" }},
		{"identity", "IPFILTER_RECOVERY_IDENTITY_MISMATCH", func(r *journalRecord, _ *Command, _ *ipFilterDeleteRecoveryP) { r.Mutating = false }},
		{"receipt", "IPFILTER_RECOVERY_RECEIPT_MISMATCH", func(r *journalRecord, _ *Command, _ *ipFilterDeleteRecoveryP) { r.Receipt.Code = "FAILED" }},
		{"audit", "IPFILTER_RECOVERY_AUDIT_MISMATCH", func(r *journalRecord, _ *Command, _ *ipFilterDeleteRecoveryP) {
			r.AuditContext.PayloadDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}},
		{"target", "IPFILTER_RECOVERY_TARGET_MISMATCH", func(r *journalRecord, _ *Command, _ *ipFilterDeleteRecoveryP) {
			r.AuditContext.TargetRef = "vm:another-target"
		}},
		{"authority", "IPFILTER_RECOVERY_AUTHORITY_MISMATCH", func(r *journalRecord, _ *Command, _ *ipFilterDeleteRecoveryP) {
			r.BindingID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		}},
		{"retirement", "IPFILTER_RECOVERY_RETIREMENT_MISMATCH", func(r *journalRecord, _ *Command, _ *ipFilterDeleteRecoveryP) {
			r.RetiredByCommandID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			journal, recovery, parameters, _ := ipFilterDeleteRecoveryFixture(t)
			record, err := readJournal(journal.path(parameters.FailedCommandID))
			if err != nil {
				t.Fatal(err)
			}
			test.edit(&record, &recovery, &parameters)
			resourceKey, err := journalResourceKey(recovery)
			if err != nil {
				t.Fatal(err)
			}
			err = ipFilterDeleteRecordEligibility(record, recovery, parameters, resourceKey)
			if !errors.Is(err, ErrListedRecordNotEligible) || claimRejectionCode(err) != test.want {
				t.Fatalf("error=%v code=%q want=%q", err, claimRejectionCode(err), test.want)
			}
			if err != nil && (bytes.Contains([]byte(err.Error()), []byte(recovery.BindingID)) || bytes.Contains([]byte(err.Error()), []byte(recovery.Identity.ServiceRef))) {
				t.Fatalf("eligibility error leaked authority values: %v", err)
			}
		})
	}
}

func TestIPFilterDeleteRecoveryReleasesRC27JournalAfterRestart(t *testing.T) {
	journal, recovery, parameters, now := ipFilterDeleteRecoveryFixture(t)
	filename := journal.path(parameters.FailedCommandID)
	record, err := readJournal(filename)
	if err != nil {
		t.Fatal(err)
	}
	// rc.27 persisted signed audit evidence but not record-level lineage/action.
	record.Action = ""
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
	if err := writeJournal(filename, record); err != nil {
		t.Fatal(err)
	}
	if _, duplicate, err := journal.ClaimWithAudit(recovery, now.Add(time.Second), "0.1.1-rc.44"); err != nil || duplicate {
		t.Fatalf("recovery claim duplicate=%t err=%v", duplicate, err)
	}
	result, err := journal.ReconcileIPFilterDelete(recovery, parameters, true, "74.91.18.94", now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	receipt := Receipt{
		SchemaVersion: SchemaVersion, ReceiptID: "55555555-5555-4555-8555-555555555555",
		CommandID: recovery.CommandID, OperationID: recovery.OperationID, AgentRef: recovery.AgentRef,
		State: "succeeded", Code: "SUCCEEDED", ExecutionMode: "production",
		StartedAt: now.Add(time.Second), FinishedAt: now.Add(2 * time.Second), Result: mustJSON(t, result),
	}
	if err := journal.Complete(recovery, receipt); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenJournal(journal.directory)
	if err != nil {
		t.Fatal(err)
	}
	freshDelete := legacyAuthorityCommand("firewall.ipset.entry.delete", `{"name":"ipfilter-net0","cidr":"74.91.18.94/32"}`, "33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444")
	freshDelete.AssignmentRevision, freshDelete.Identity = recovery.AssignmentRevision, recovery.Identity
	if _, duplicate, err := reopened.ClaimWithAudit(freshDelete, now.Add(3*time.Second), "0.1.1-rc.44"); err != nil || duplicate {
		t.Fatalf("rc.27 recovery did not release lock after restart: duplicate=%t err=%v", duplicate, err)
	}
}

type ipFilterDeleteReconcilerFunc func(Command, ipFilterDeleteRecoveryP, bool, string, time.Time) (IPFilterDeleteRecoveryResult, error)

func (function ipFilterDeleteReconcilerFunc) ReconcileIPFilterDelete(command Command, parameters ipFilterDeleteRecoveryP, present bool, observed string, now time.Time) (IPFilterDeleteRecoveryResult, error) {
	return function(command, parameters, present, observed, now)
}

func TestIPFilterDeleteRecoveryExecutorReadsProviderBeforeJournalWrite(t *testing.T) {
	_, command, parameters, now := ipFilterDeleteRecoveryFixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api2/json/nodes/pve1/qemu/101/firewall/ipset/ipfilter-net0" {
			t.Fatalf("unexpected provider read: %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"data":[{"cidr":"74.91.18.94"}]}`))
	}))
	defer server.Close()
	called := false
	executor := Executor{
		ReadClient: controlTestClient(t, server), Mode: "production", ProductionExecution: true,
		IPFilterDeleteJournal: ipFilterDeleteReconcilerFunc(func(_ Command, got ipFilterDeleteRecoveryP, present bool, observed string, _ time.Time) (IPFilterDeleteRecoveryResult, error) {
			called = got == parameters && present && observed == "74.91.18.94"
			return IPFilterDeleteRecoveryResult{
				Reconciled: true, RecoveryKind: ipFilterDeleteRecoveryKind, LegacyAssignmentRevision: got.LegacyAssignmentRevision,
				FailedCommandID: got.FailedCommandID, FailedOperationID: got.FailedOperationID, FailedCommandDigest: got.FailedCommandDigest,
				FailedPayloadSHA256:  got.FailedPayloadSHA256,
				FailedWireBodySHA256: got.FailedWireBodySHA256,
				FailedReceiptCode:    "PVE_RESULT_INDETERMINATE", Name: got.Name, CIDR: got.CIDR,
				ProviderReadVerified: true, TargetPresent: true, ObservedCIDR: observed, JournalRecordRetired: true,
			}, nil
		}),
	}
	receipt, err := executor.Execute(context.Background(), command, now.Add(time.Second))
	if err != nil || receipt.State != "succeeded" || receipt.Code != "SUCCEEDED" || !called {
		t.Fatalf("receipt=%#v called=%t err=%v", receipt, called, err)
	}
}
