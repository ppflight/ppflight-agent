package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

type upgradeSubmitterFunc func(context.Context, Command) (string, error)

func (f upgradeSubmitterFunc) Prepare(ctx context.Context, command Command) (string, error) {
	return f(ctx, command)
}

func TestAgentUpgradeUsesDedicatedAsyncIdentityWithoutPVEClient(t *testing.T) {
	called := false
	executor := Executor{Mode: "production", ProductionExecution: true, UpgradeSubmitter: upgradeSubmitterFunc(func(_ context.Context, command Command) (string, error) {
		called = true
		if command.Action != "agent.upgrade" {
			t.Fatal("wrong action")
		}
		return "upgrade-01", nil
	})}
	command := controlCommand("agent.upgrade", "qemu", upgradeFixture())
	command.CommandID, command.AgentRef, command.OperatorRef = "command-01", "agent-01", "operator-01"
	receipt, err := executor.Execute(context.Background(), command, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !called || receipt.State != "submitted" || receipt.AgentUpgradeID != "upgrade-01" || receipt.PVETaskUPID != "" || receipt.Code != "AGENT_UPGRADE_SUBMITTED" {
		t.Fatalf("receipt=%#v", receipt)
	}
	if err := receipt.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestAgentUpgradePrepareFailureIsTerminalAndDoesNotClaimPVEUPID(t *testing.T) {
	executor := Executor{Mode: "production", ProductionExecution: true, UpgradeSubmitter: upgradeSubmitterFunc(func(context.Context, Command) (string, error) { return "", errors.New("manifest disabled") })}
	command := controlCommand("agent.upgrade", "qemu", upgradeFixture())
	command.CommandID, command.AgentRef, command.OperatorRef = "command-01", "agent-01", "operator-01"
	receipt, err := executor.Execute(context.Background(), command, time.Now().UTC())
	if err == nil || receipt.State != "failed" || receipt.AgentUpgradeID != "" || receipt.PVETaskUPID != "" {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
}

func TestReconciledUpgradeFailureCarriesBoundedHelperDiagnostic(t *testing.T) {
	now := time.Now().UTC()
	diagnostic := &ExecutionError{Source: "agent", Stage: "verify_archive", Reason: "release archive contains an unreviewed entry"}
	receipt, err := (&Service{}).reconciledUpgradeReceipt(SubmittedTask{
		AgentUpgradeID: "upgrade-01",
		OperationID:    "operation-01",
		Receipt: Receipt{
			SchemaVersion: 1, ReceiptID: "receipt-01", CommandID: "command-01", AgentRef: "agent-01",
			State: "submitted", Code: "AGENT_UPGRADE_SUBMITTED", ExecutionMode: "production", StartedAt: now,
		},
	}, UpgradeResolution{Status: "failed", Code: "UPGRADE_HELPER_FAILED", Error: diagnostic}, nil, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.State != "failed" || receipt.Code != "AGENT_UPGRADE_FAILED" || receipt.Error != diagnostic {
		t.Fatalf("receipt=%#v", receipt)
	}
}

func TestReconciledUpgradeSuccessPreservesLegacyAndVerifiedEvidenceCodes(t *testing.T) {
	now := time.Now().UTC()
	task := SubmittedTask{
		AgentUpgradeID: "upgrade-01",
		OperationID:    "operation-01",
		Receipt: Receipt{
			SchemaVersion: 1, ReceiptID: "receipt-01", CommandID: "command-01", AgentRef: "agent-01",
			State: "submitted", Code: "AGENT_UPGRADE_SUBMITTED", ExecutionMode: "production", StartedAt: now,
		},
	}
	for _, test := range []struct {
		name       string
		resultCode string
		wantState  string
		wantCode   string
	}{
		{name: "legacy schedules website postflight", resultCode: AgentUpgradeLegacySuccessCode, wantState: "succeeded", wantCode: AgentUpgradeLegacySuccessCode},
		{name: "host firewall verified", resultCode: AgentUpgradeHostFirewallSuccessCode, wantState: "succeeded", wantCode: AgentUpgradeHostFirewallSuccessCode},
		{name: "unknown success evidence", resultCode: "AGENT_UPGRADE_UNKNOWN_SUCCESS", wantState: "waiting", wantCode: "AGENT_UPGRADE_STATUS_INDETERMINATE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			receipt, err := (&Service{}).reconciledUpgradeReceipt(task, UpgradeResolution{Status: "succeeded", Code: test.resultCode}, nil, now.Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			if receipt.State != test.wantState || receipt.Code != test.wantCode {
				t.Fatalf("receipt=%#v", receipt)
			}
		})
	}
}

func TestJournalAuthorizesOnlyExactSubmittedUpgrade(t *testing.T) {
	journal, err := OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	command := controlCommand("agent.upgrade", "qemu", upgradeFixture())
	command.SchemaVersion = 1
	command.CommandID = "command-01"
	command.OperationID = "operation-01"
	command.AgentRef = "agent-01"
	command.OperatorRef = "operator-01"
	command.IdempotencyKey = "idem-01"
	command.Parameters = json.RawMessage(upgradeFixture())
	now := time.Now().UTC()
	if _, _, err := journal.Claim(command, now); err != nil {
		t.Fatal(err)
	}
	receipt := Receipt{SchemaVersion: 1, ReceiptID: "receipt-01", CommandID: command.CommandID, OperationID: command.OperationID, AgentRef: command.AgentRef, State: "submitted", Code: "AGENT_UPGRADE_SUBMITTED", ExecutionMode: "production", StartedAt: now, FinishedAt: now, AgentUpgradeID: "upgrade-01", OperatorRef: command.OperatorRef}
	if err := journal.Complete(command, receipt); err != nil {
		t.Fatal(err)
	}
	if err := journal.AuthorizeUpgrade(command.CommandID, Digest(command), "upgrade-01"); err != nil {
		t.Fatal(err)
	}
	if err := journal.AuthorizeUpgrade(command.CommandID, Digest(command), "upgrade-02"); !errors.Is(err, ErrCommandConflict) {
		t.Fatalf("wrong upgrade was authorized: %v", err)
	}
}

func TestUpgradeWaitingReceiptsDoNotRepeatMonitoringAudit(t *testing.T) {
	journal, err := OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	command := controlCommand("agent.upgrade", "qemu", upgradeFixture())
	command.SchemaVersion = 1
	command.CommandID = "command-upgrade-01"
	command.OperationID = "operation-upgrade-01"
	command.AgentRef = "agent-01"
	command.OperatorRef = "operator-01"
	command.IdempotencyKey = "idempotency-upgrade-01"
	command.AssignmentRevision = 19
	command.SigningKeyID = "website-signing-01"
	command.BodySHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	command.Parameters = json.RawMessage(upgradeFixture())
	now := time.Date(2026, 9, 6, 8, 0, 0, 0, time.UTC)
	if _, duplicate, err := journal.ClaimWithAudit(command, now, "0.1.7"); err != nil || duplicate {
		t.Fatalf("claim duplicate=%v err=%v", duplicate, err)
	}
	submitted := Receipt{
		SchemaVersion: 1, ReceiptID: "11111111-1111-4111-8111-111111111111",
		CommandID: command.CommandID, OperationID: command.OperationID, AgentRef: command.AgentRef,
		State: "submitted", Code: "AGENT_UPGRADE_SUBMITTED", ExecutionMode: "production",
		StartedAt: now, FinishedAt: now, AgentUpgradeID: "upgrade-01", OperatorRef: command.OperatorRef,
	}
	if err := journal.Complete(command, submitted); err != nil {
		t.Fatal(err)
	}
	event, pending, err := journal.PendingAuditForReceipt(command.CommandID, submitted.ReceiptID)
	if err != nil || !pending || event.Outcome != "submitted" {
		t.Fatalf("submitted audit=%#v pending=%v err=%v", event, pending, err)
	}
	if err := journal.MarkAuditQueued(command.CommandID, event.EventID); err != nil {
		t.Fatal(err)
	}
	if err := journal.MarkReceiptQueued(command.CommandID, submitted.ReceiptID); err != nil {
		t.Fatal(err)
	}

	for index := 0; index < 2; index++ {
		tasks, err := journal.SubmittedWaiting()
		if err != nil || len(tasks) != 1 {
			t.Fatalf("waiting tasks=%#v err=%v", tasks, err)
		}
		waiting := tasks[0].Receipt
		waiting.ReceiptID = fmt.Sprintf("22222222-2222-4222-8222-22222222222%d", index)
		waiting.State, waiting.Code = "waiting", "AGENT_UPGRADE_WAITING"
		waiting.FinishedAt = now.Add(time.Duration(index+1) * time.Second)
		if err := journal.CompleteSubmitted(tasks[0], waiting); err != nil {
			t.Fatal(err)
		}
		if _, pending, err := journal.PendingAuditForReceipt(command.CommandID, waiting.ReceiptID); err != nil || pending {
			t.Fatalf("waiting audit iteration=%d pending=%v err=%v", index, pending, err)
		}
		if err := journal.MarkReceiptQueued(command.CommandID, waiting.ReceiptID); err != nil {
			t.Fatal(err)
		}
	}

	tasks, err := journal.SubmittedWaiting()
	if err != nil || len(tasks) != 1 {
		t.Fatalf("terminal task=%#v err=%v", tasks, err)
	}
	terminal := tasks[0].Receipt
	terminal.ReceiptID = "33333333-3333-4333-8333-333333333333"
	terminal.State, terminal.Code = "succeeded", AgentUpgradeHostFirewallSuccessCode
	terminal.FinishedAt = now.Add(3 * time.Second)
	if err := journal.CompleteSubmitted(tasks[0], terminal); err != nil {
		t.Fatal(err)
	}
	event, pending, err = journal.PendingAuditForReceipt(command.CommandID, terminal.ReceiptID)
	if err != nil || !pending || event.Outcome != "succeeded" {
		t.Fatalf("terminal audit=%#v pending=%v err=%v", event, pending, err)
	}
}

func TestAgentUpgradeAuditGoldenMapping(t *testing.T) {
	now := time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC)
	command := controlCommand("agent.upgrade", "qemu", upgradeFixture())
	command.CommandID, command.OperationID, command.IdempotencyKey = "command-upgrade-01", "operation-upgrade-01", "idempotency-upgrade-01"
	command.AgentRef, command.OperatorRef, command.ApprovalRef = "agent-01", "operator-01", "approval-01"
	command.AssignmentRevision, command.SigningKeyID = 19, "website-signing-01"
	command.BodySHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	context, err := newAuditContext(command, now, "0.1.0-rc.9")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ state, code, outcome string }{
		{"submitted", "AGENT_UPGRADE_SUBMITTED", "submitted"},
		{"waiting", "AGENT_UPGRADE_WAITING", "submitted"},
		{"succeeded", "AGENT_UPGRADE_SUCCEEDED", "succeeded"},
		{"succeeded", AgentUpgradeHostFirewallSuccessCode, "succeeded"},
		{"failed", "AGENT_UPGRADE_ROLLED_BACK", "rolled_back"},
		{"failed", "AGENT_UPGRADE_FAILED", "failed"},
	}
	for index, test := range cases {
		receipt := Receipt{SchemaVersion: 1, ReceiptID: fmt.Sprintf("123e4567-e89b-42d3-a456-426614174%03d", index+20), CommandID: command.CommandID, OperationID: command.OperationID, AgentRef: command.AgentRef, State: test.state, Code: test.code, ExecutionMode: "production", StartedAt: now, FinishedAt: now.Add(time.Second), AgentUpgradeID: "upgrade-01", OperatorRef: command.OperatorRef}
		ApplyReceiptCompatibility(&receipt)
		event, err := auditEventFromReceipt(context, receipt)
		if err != nil {
			t.Fatal(err)
		}
		if event.Action != "agent.upgrade" || event.Outcome != test.outcome || event.ErrorCode != test.code || event.ApprovalRef != "approval-01" || event.UPID != "" {
			t.Fatalf("mapping[%d]=%#v", index, event)
		}
	}
}
