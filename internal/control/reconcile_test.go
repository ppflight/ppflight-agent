package control

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/inventory"
	"github.com/ppflight/ppflight-agent/internal/store"
)

type resolverFunc func(context.Context, string, string) (TaskResolution, error)

func (f resolverFunc) ResolveTask(ctx context.Context, nodeRef, upid string) (TaskResolution, error) {
	return f(ctx, nodeRef, upid)
}

func submittedCommand(t *testing.T, journal *Journal, now time.Time) (Command, *inventory.Store) {
	t.Helper()
	command, assignments := signedCommand(t, now)
	command.OperationID = "operation-1"
	command.Signature = SignCommand(command, []byte("secret"))
	if _, duplicate, err := journal.Claim(command, now); err != nil || duplicate {
		t.Fatalf("claim duplicate=%v err=%v", duplicate, err)
	}
	receipt := Receipt{
		SchemaVersion: SchemaVersion, ReceiptID: "submitted-1", CommandID: command.CommandID, OperationID: command.OperationID,
		AgentRef: command.AgentRef, State: "submitted", Code: "PVE_TASK_SUBMITTED", ExecutionMode: "production",
		StartedAt: now, FinishedAt: now, PVETaskUPID: "UPID:pve-1:123", OperatorRef: command.OperatorRef,
	}
	if err := journal.Complete(command, receipt); err != nil {
		t.Fatal(err)
	}
	if err := journal.MarkReceiptQueued(command.CommandID, receipt.ReceiptID); err != nil {
		t.Fatal(err)
	}
	return command, assignments
}

func reconciliationService(t *testing.T, journal *Journal, assignments *inventory.Store, queue ReceiptQueue, now time.Time, resolver TaskResolver) *Service {
	t.Helper()
	publicKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	service, err := NewService(ServiceConfig{
		AgentRef: "agent-1", ClusterRef: "cluster-1", Mode: "production", CommandSigningKeyID: "key-1", CommandPublicKey: publicKey,
		BindingID: "11111111-1111-4111-8111-111111111111", DeviceID: "device-1", CredentialEpoch: 3,
		AssignmentRevision: func() uint64 { return 7 },
		AllowedActions:     []string{"vm.start"}, Assignments: assignments, Poller: fixedPoller{PollResponse{SchemaVersion: 1, Cursor: "cursor-1"}},
		Journal: journal, Executor: Executor{Mode: "production", ProductionExecution: true}, TaskResolver: resolver,
		ReceiptQueue: queue, CursorFile: t.TempDir() + "/cursor.json", Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func queuedReceipt(t *testing.T, queue *memoryReceiptQueue, index int) Receipt {
	t.Helper()
	var receipt Receipt
	if err := json.Unmarshal(queue.payloads[index], &receipt); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func TestApplyAssignmentAuthoritySwitchesRevisionActionsAndInventoryTogether(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	journal, err := OpenJournal(t.TempDir() + "/journal")
	if err != nil {
		t.Fatal(err)
	}
	_, assignments := submittedCommand(t, journal, now)
	service := reconciliationService(t, journal, assignments, &memoryReceiptQueue{}, now, resolverFunc(func(context.Context, string, string) (TaskResolution, error) {
		return TaskResolution{}, nil
	}))
	document := assignments.Snapshot()
	document.Revision = "revision-8"
	document.AllowedActions = []string{"vm.start", "vm.set-disk-io", "firewall.guest.verify-ipfilter"}
	if err := service.ApplyAssignmentAuthority(document, 8, document.AllowedActions); err != nil {
		t.Fatal(err)
	}
	if service.assignmentRevision != 8 || !service.allowed["vm.set-disk-io"] || service.assignments.Snapshot().Revision != "revision-8" {
		t.Fatalf("authority did not switch atomically: revision=%d allowed=%#v document=%s", service.assignmentRevision, service.allowed, service.assignments.Snapshot().Revision)
	}
	if err := service.ApplyAssignmentAuthority(document, 8, []string{"vm.delete"}); err == nil {
		t.Fatal("non-monotonic authority was accepted")
	}
	if err := service.ApplyAssignmentAuthority(document, 9, []string{"arbitrary.command"}); err == nil {
		t.Fatal("unknown remote action was accepted")
	}
	if service.assignmentRevision != 8 || service.allowed["vm.delete"] {
		t.Fatal("rejected authority changed active state")
	}
	legacy := reconciliationService(t, journal, assignments, &memoryReceiptQueue{}, now, resolverFunc(func(context.Context, string, string) (TaskResolution, error) {
		return TaskResolution{}, nil
	}))
	legacy.assignmentRevisionFn = func() uint64 { return 20 }
	if err := legacy.ApplyAssignmentAuthority(document, 9, document.AllowedActions); err == nil {
		t.Fatal("dynamic authority rolled back a newer legacy revision")
	}
}

func TestReconcileRunningThenSucceeded(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	journal, err := OpenJournal(t.TempDir() + "/journal")
	if err != nil {
		t.Fatal(err)
	}
	_, assignments := submittedCommand(t, journal, now)
	queue := &memoryReceiptQueue{}
	results := []TaskResolution{{Status: "running"}, {Status: "stopped", ExitStatus: "OK"}}
	calls := 0
	service := reconciliationService(t, journal, assignments, queue, now, resolverFunc(func(_ context.Context, node, upid string) (TaskResolution, error) {
		if node != "pve-1" || upid != "UPID:pve-1:123" {
			t.Fatalf("unexpected task %q/%q", node, upid)
		}
		value := results[calls]
		calls++
		return value, nil
	}))
	if count, err := service.ReconcileOnce(context.Background()); err != nil || count != 1 {
		t.Fatalf("first reconciliation count=%d err=%v", count, err)
	}
	waiting := queuedReceipt(t, queue, 0)
	if waiting.State != "waiting" || !waiting.Accepted || !waiting.Asynchronous || waiting.MutationMayHaveSucceeded {
		t.Fatalf("waiting receipt=%#v", waiting)
	}
	if count, err := service.ReconcileOnce(context.Background()); err != nil || count != 1 {
		t.Fatalf("second reconciliation count=%d err=%v", count, err)
	}
	succeeded := queuedReceipt(t, queue, 1)
	if succeeded.State != "succeeded" || succeeded.ReceiptID == waiting.ReceiptID || succeeded.OperationID != "operation-1" {
		t.Fatalf("succeeded receipt=%#v", succeeded)
	}
	if tasks, err := journal.SubmittedWaiting(); err != nil || len(tasks) != 0 {
		t.Fatalf("pending tasks=%#v err=%v", tasks, err)
	}
}

func TestReconcileTerminalFailureAndNoDuplicateTerminalReceipt(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	journal, err := OpenJournal(t.TempDir() + "/journal")
	if err != nil {
		t.Fatal(err)
	}
	_, assignments := submittedCommand(t, journal, now)
	queue := &memoryReceiptQueue{}
	service := reconciliationService(t, journal, assignments, queue, now, resolverFunc(func(context.Context, string, string) (TaskResolution, error) {
		return TaskResolution{Status: "stopped", ExitStatus: "ERROR"}, nil
	}))
	if count, err := service.ReconcileOnce(context.Background()); err != nil || count != 1 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	if receipt := queuedReceipt(t, queue, 0); receipt.State != "failed" || receipt.Code != "PVE_TASK_FAILED" {
		t.Fatalf("failure receipt=%#v", receipt)
	}
	if count, err := service.ReconcileOnce(context.Background()); err != nil || count != 0 || len(queue.payloads) != 1 {
		t.Fatalf("duplicate terminal receipt count=%d len=%d err=%v", count, len(queue.payloads), err)
	}
}

func TestReconcileRecoversAfterRestart(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	directory := t.TempDir() + "/journal"
	journal, err := OpenJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	_, assignments := submittedCommand(t, journal, now)
	// Reopen exactly as a new process would; only the UPID and safe metadata
	// in the journal are required to finish the operation.
	journal, err = OpenJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	queue := &memoryReceiptQueue{}
	service := reconciliationService(t, journal, assignments, queue, now, resolverFunc(func(context.Context, string, string) (TaskResolution, error) {
		return TaskResolution{Status: "stopped", ExitStatus: "OK"}, nil
	}))
	if count, err := service.ReconcileOnce(context.Background()); err != nil || count != 1 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	if receipt := queuedReceipt(t, queue, 0); receipt.State != "succeeded" {
		t.Fatalf("receipt=%#v", receipt)
	}
}

func TestJournalSerializesResourceAndMakesClaimCrashIndeterminate(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	journal, err := OpenJournal(t.TempDir() + "/journal")
	if err != nil {
		t.Fatal(err)
	}
	first, _ := signedCommand(t, now)
	if _, duplicate, err := journal.Claim(first, now); err != nil || duplicate {
		t.Fatalf("first claim duplicate=%v err=%v", duplicate, err)
	}
	second := first
	second.CommandID = "command-2"
	second.OperationID = "operation-2"
	second.Signature = SignCommand(second, []byte("secret"))
	if _, _, err := journal.Claim(second, now); !errors.Is(err, ErrResourceBusy) {
		t.Fatalf("resource conflict error=%v", err)
	}
	if receipt, duplicate, err := journal.Claim(first, now); err != nil || !duplicate || receipt.State != "indeterminate" {
		t.Fatalf("crash recovery receipt=%#v duplicate=%v err=%v", receipt, duplicate, err)
	}
	third := second
	third.CommandID = "command-3"
	third.OperationID = "operation-3"
	third.Signature = SignCommand(third, []byte("secret"))
	if _, _, err := journal.Claim(third, now); !errors.Is(err, ErrResourceBusy) {
		t.Fatalf("indeterminate mutation did not retain resource lock: %v", err)
	}
}

func TestJournalNeverPersistsParameters(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	journal, err := OpenJournal(t.TempDir() + "/journal")
	if err != nil {
		t.Fatal(err)
	}
	command, _ := signedCommand(t, now)
	command.Parameters = json.RawMessage(`{"password":"never-write-this","username":"root"}`)
	if _, _, err := journal.Claim(command, now); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(journal.path(command.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "parameters") || strings.Contains(string(raw), "never-write-this") {
		t.Fatalf("journal persisted sensitive parameters: %s", raw)
	}
}

func TestJournalReadOnlyScopesCanRetryAndDoNotTakeMutationLock(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	journal, err := OpenJournal(t.TempDir() + "/journal")
	if err != nil {
		t.Fatal(err)
	}
	command := Command{
		SchemaVersion: 1, CommandID: "discover-1", OperationID: "operation-1", AgentRef: "agent-1", Scope: ScopeCluster,
		Identity: Identity{ClusterRef: "cluster-1"}, Action: "pve.discover",
		Parameters: json.RawMessage(`{"operationId":"operation-1","phase":"version","limit":1}`), OperatorRef: "operator-1",
	}
	if _, duplicate, err := journal.Claim(command, now); err != nil || duplicate {
		t.Fatalf("first read claim duplicate=%v err=%v", duplicate, err)
	}
	if recovered, err := journal.RecoverIncomplete(now.Add(time.Minute), "production"); err != nil || len(recovered) != 0 {
		t.Fatalf("read-only claim became indeterminate: %#v err=%v", recovered, err)
	}
	if _, duplicate, err := journal.Claim(command, now.Add(time.Minute)); err != nil || duplicate {
		t.Fatalf("safe read retry duplicate=%v err=%v", duplicate, err)
	}
	second := command
	second.CommandID = "discover-2"
	second.OperationID = "operation-2"
	second.Parameters = json.RawMessage(`{"operationId":"operation-2","phase":"version","limit":1}`)
	if _, duplicate, err := journal.Claim(second, now); err != nil || duplicate {
		t.Fatalf("concurrent read claim duplicate=%v err=%v", duplicate, err)
	}
}

func TestReconcileRetriesTransientTaskStatusError(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	journal, err := OpenJournal(t.TempDir() + "/journal")
	if err != nil {
		t.Fatal(err)
	}
	_, assignments := submittedCommand(t, journal, now)
	queue := &memoryReceiptQueue{}
	calls := 0
	service := reconciliationService(t, journal, assignments, queue, now, resolverFunc(func(context.Context, string, string) (TaskResolution, error) {
		calls++
		if calls == 1 {
			return TaskResolution{}, errors.New("temporary read failure")
		}
		return TaskResolution{Status: "stopped", ExitStatus: "OK"}, nil
	}))
	if count, err := service.ReconcileOnce(context.Background()); err != nil || count != 1 {
		t.Fatalf("first reconciliation count=%d err=%v", count, err)
	}
	if receipt := queuedReceipt(t, queue, 0); receipt.State != "waiting" || receipt.Code != "PVE_TASK_STATUS_INDETERMINATE" {
		t.Fatalf("transient receipt=%#v", receipt)
	}
	if tasks, err := journal.SubmittedWaiting(); err != nil || len(tasks) != 1 {
		t.Fatalf("transient task was not retained: %#v err=%v", tasks, err)
	}
	if count, err := service.ReconcileOnce(context.Background()); err != nil || count != 1 {
		t.Fatalf("second reconciliation count=%d err=%v", count, err)
	}
	if receipt := queuedReceipt(t, queue, 1); receipt.State != "succeeded" {
		t.Fatalf("terminal receipt=%#v", receipt)
	}
}

type failOnceReceiptQueue struct {
	failed   bool
	payloads [][]byte
}

func (q *failOnceReceiptQueue) Enqueue(_ string, payload []byte) (store.Item, bool, error) {
	if !q.failed {
		q.failed = true
		return store.Item{}, false, errors.New("temporary queue failure")
	}
	q.payloads = append(q.payloads, append([]byte(nil), payload...))
	return store.Item{}, true, nil
}

func TestReconcileReplaysTerminalReceiptAfterQueueFailure(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	journal, err := OpenJournal(t.TempDir() + "/journal")
	if err != nil {
		t.Fatal(err)
	}
	_, assignments := submittedCommand(t, journal, now)
	queue := &failOnceReceiptQueue{}
	service := reconciliationService(t, journal, assignments, queue, now, resolverFunc(func(context.Context, string, string) (TaskResolution, error) {
		return TaskResolution{Status: "stopped", ExitStatus: "OK"}, nil
	}))
	if _, err := service.ReconcileOnce(context.Background()); err == nil {
		t.Fatal("queue failure was not reported")
	}
	if pending, err := journal.PendingReceipts(); err != nil || len(pending) != 1 || pending[0].Receipt.State != "succeeded" {
		t.Fatalf("pending=%#v err=%v", pending, err)
	}
	if count, err := service.ReconcileOnce(context.Background()); err != nil || count != 1 || len(queue.payloads) != 1 {
		t.Fatalf("replay count=%d payloads=%d err=%v", count, len(queue.payloads), err)
	}
	var receipt Receipt
	if err := json.Unmarshal(queue.payloads[0], &receipt); err != nil || receipt.State != "succeeded" {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
}
