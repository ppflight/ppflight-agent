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
