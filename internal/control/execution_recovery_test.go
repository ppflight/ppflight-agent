package control

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/protocol"
)

func readOnlyDeliveryCommand(t *testing.T, now time.Time) Command {
	t.Helper()
	command, _ := signedCommand(t, now)
	command.Action = "vm.verify-delivery"
	command.Parameters = json.RawMessage(`{"notBefore":"2026-01-01T00:00:00Z","expected":{"cores":2,"sockets":1,"memoryMiB":1024,"disk":{"interface":"scsi0","minimumGiB":20,"limits":{"iopsRead":1000,"iopsWrite":null,"iopsReadMax":null,"iopsWriteMax":null,"iopsReadMaxLength":null,"iopsWriteMaxLength":null,"mbpsRead":100,"mbpsWrite":null,"mbpsReadMax":null,"mbpsWriteMax":null}},"networks":[{"interface":"net0","bridge":"vmbr0","mac":"AA:BB:CC:DD:EE:FF","vlan":null,"mtu":1500,"firewall":true,"rateMbps":"100","ipv4":"192.0.2.10/24","ipv6":"2001:db8::10/64","ipFilterCidrs":["192.0.2.10/32","2001:db8::10/128"]}],"timezone":"UTC"}}`)
	command.BodySHA256 = protocol.BodyHash(command.Parameters)
	command.Signature = SignCommand(command, []byte("secret"))
	return command
}

func beginRunningReadOnly(t *testing.T, journal *Journal, command Command, now time.Time) {
	t.Helper()
	if _, duplicate, err := journal.Claim(command, now); err != nil || duplicate {
		t.Fatalf("claim duplicate=%t err=%v", duplicate, err)
	}
	running := Receipt{
		SchemaVersion: SchemaVersion, ReceiptID: "running-read-only", CommandID: command.CommandID, OperationID: command.OperationID,
		AgentRef: command.AgentRef, State: "running", Code: "COMMAND_STARTED", ExecutionMode: "production",
		Accepted: true, Asynchronous: true, StartedAt: now, FinishedAt: now, OperatorRef: command.OperatorRef,
	}
	if err := journal.BeginRunning(command, running); err != nil {
		t.Fatal(err)
	}
	if err := journal.MarkReceiptQueued(command.CommandID, running.ReceiptID); err != nil {
		t.Fatal(err)
	}
}

func assertDeliveryInterruption(t *testing.T, receipt Receipt) {
	t.Helper()
	if receipt.State != "failed" || receipt.Code != "DELIVERY_NOT_READY" || receipt.Error == nil || receipt.Error.Source != "agent" {
		t.Fatalf("unexpected interruption receipt: %#v", receipt)
	}
	var result DeliveryVerificationFailureResult
	if err := json.Unmarshal(receipt.Result, &result); err != nil || result.Ready || result.FailedCheck != "provider_read" || result.ObservedAt.IsZero() {
		t.Fatalf("invalid bounded delivery failure result=%#v err=%v", result, err)
	}
}

func TestReadOnlyRunningJournalRecoversWithTerminalDeliveryFailure(t *testing.T) {
	now := time.Date(2026, 9, 6, 14, 7, 15, 0, time.UTC)
	directory := t.TempDir() + "/journal"
	journal, err := OpenJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	command := readOnlyDeliveryCommand(t, now)
	beginRunningReadOnly(t, journal, command, now)
	if recovered, err := journal.RecoverIncompleteExcept(now.Add(30*time.Second), "production", func(commandID string) bool {
		return commandID == command.CommandID
	}); err != nil || len(recovered) != 0 {
		t.Fatalf("active read-only command was terminated: recovered=%#v err=%v", recovered, err)
	}

	journal, err = OpenJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := journal.RecoverIncomplete(now.Add(time.Minute), "production")
	if err != nil || len(recovered) != 1 {
		t.Fatalf("recovered=%#v err=%v", recovered, err)
	}
	assertDeliveryInterruption(t, recovered[0])

	replayed, duplicate, err := journal.Claim(command, now.Add(2*time.Minute))
	if err != nil || !duplicate {
		t.Fatalf("replay duplicate=%t err=%v receipt=%#v", duplicate, err, replayed)
	}
	assertDeliveryInterruption(t, replayed)
}

func TestReadOnlyDeliveryExecutionAlwaysProducesTerminalReceipt(t *testing.T) {
	for _, name := range []string{"deadline", "panic"} {
		t.Run(name, func(t *testing.T) {
			now := time.Date(2026, 9, 6, 14, 7, 15, 0, time.UTC)
			journal, err := OpenJournal(t.TempDir() + "/journal")
			if err != nil {
				t.Fatal(err)
			}
			command := readOnlyDeliveryCommand(t, now)
			beginRunningReadOnly(t, journal, command, now)
			queue := &memoryReceiptQueue{}
			release := make(chan struct{})
			execute := func(context.Context, Command, time.Time) (Receipt, error) {
				if name == "panic" {
					panic("sensitive panic detail")
				}
				<-release
				return Receipt{}, nil
			}
			service := &Service{
				journal: journal, receiptQueue: queue, mode: "production", now: func() time.Time { return now.Add(time.Second) },
				executeCommand: execute, readOnlyTimeout: 10 * time.Millisecond,
			}

			service.executeDispatched(context.Background(), command)
			close(release)
			if len(queue.payloads) != 1 {
				t.Fatalf("terminal receipt count=%d", len(queue.payloads))
			}
			var receipt Receipt
			if err := json.Unmarshal(queue.payloads[0], &receipt); err != nil {
				t.Fatal(err)
			}
			assertDeliveryInterruption(t, receipt)
			if receipt.Error != nil && receipt.Error.Reason == "sensitive panic detail" {
				t.Fatal("panic detail leaked into the signed receipt")
			}
			if pending, err := journal.PendingReceipts(); err != nil || len(pending) != 0 {
				t.Fatalf("pending=%#v err=%v", pending, err)
			}
		})
	}
}

func TestMutatingExecutorPanicFailsClosedAsIndeterminate(t *testing.T) {
	now := time.Date(2026, 9, 6, 14, 7, 15, 0, time.UTC)
	command, _ := signedCommand(t, now)
	service := &Service{
		mode: "production", now: func() time.Time { return now.Add(time.Second) },
		executeCommand: func(context.Context, Command, time.Time) (Receipt, error) { panic("provider mutation panic") },
	}
	receipt, err := service.executeDispatchedCommand(context.Background(), command, now)
	if err == nil || receipt.State != "indeterminate" || receipt.Code != "EXECUTION_INDETERMINATE" || !receipt.MutationMayHaveSucceeded {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	if receipt.Error == nil || receipt.Error.Reason == "provider mutation panic" {
		t.Fatalf("unsafe panic diagnostic receipt=%#v err=%v", receipt, err)
	}
}
