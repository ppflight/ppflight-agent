package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/auditlog"
	"github.com/ppflight/ppflight-agent/internal/inventory"
	"github.com/ppflight/ppflight-agent/internal/runstate"
	"github.com/ppflight/ppflight-agent/internal/store"
)

type failOnceAuditSink struct {
	fail   bool
	events []auditlog.Event
}

func (s *failOnceAuditSink) Enqueue(event auditlog.Event) error {
	if s.fail {
		s.fail = false
		return errors.New("audit queue unavailable")
	}
	s.events = append(s.events, event)
	return nil
}

func auditTestService(t *testing.T, directory string, command Command, assignments *inventory.Store, receiptQueue ReceiptQueue, sink auditlog.Sink, now time.Time, allowed []string) (*Service, *Journal) {
	t.Helper()
	journal, err := OpenJournal(filepath.Join(directory, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(ServiceConfig{
		AgentRef: "agent-1", ClusterRef: "cluster-1", Mode: "test", CommandSecret: []byte("secret"),
		BindingID: command.BindingID, DeviceID: command.DeviceID, CredentialEpoch: uint64(command.CredentialEpoch),
		AssignmentRevision: func() uint64 { return 7 }, AgentVersion: "test-version", AuditSink: sink,
		AllowedActions: allowed, Assignments: assignments,
		Poller:  fixedPoller{PollResponse{SchemaVersion: 1, Cursor: "cursor-1", Commands: []Command{command}}},
		Journal: journal, Executor: Executor{Mode: "test"}, ReceiptQueue: receiptQueue,
		CursorFile: filepath.Join(directory, "cursor.json"), Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return service, journal
}

func TestAuditFailureLeavesReceiptPendingAndReconcileAfterRestart(t *testing.T) {
	now := time.Date(2026, 8, 30, 1, 2, 3, 0, time.UTC)
	command, assignments := signedCommand(t, now)
	directory := t.TempDir()
	receipts := &memoryReceiptQueue{}
	audit := &failOnceAuditSink{fail: true}
	service, journal := auditTestService(t, directory, command, assignments, receipts, audit, now, []string{command.Action})
	if processed, err := service.PollOnce(context.Background()); err == nil || processed != 0 {
		t.Fatalf("processed=%d err=%v", processed, err)
	}
	if len(receipts.payloads) != 0 {
		t.Fatal("receipt was queued before its audit event")
	}
	pendingReceipts, err := journal.PendingReceipts()
	if err != nil || len(pendingReceipts) != 1 {
		t.Fatalf("pending receipts=%#v err=%v", pendingReceipts, err)
	}
	pendingAudits, err := journal.PendingAudits()
	if err != nil || len(pendingAudits) != 1 || pendingAudits[0].Event.EventID != pendingReceipts[0].Receipt.ReceiptID {
		t.Fatalf("pending audits=%#v err=%v", pendingAudits, err)
	}
	if err := journal.MarkReceiptQueued(command.CommandID, pendingReceipts[0].Receipt.ReceiptID); err == nil {
		t.Fatal("journal acknowledged receipt while audit was pending")
	}

	// Reopen both service and journal to prove the safe projection, not command
	// parameters, is sufficient to replay the event.
	restarted, reopened := auditTestService(t, directory, command, assignments, receipts, audit, now.Add(time.Minute), []string{command.Action})
	restarted.poller = fixedPoller{PollResponse{SchemaVersion: 1, Cursor: "cursor-2"}}
	if updated, err := restarted.ReconcileOnce(context.Background()); err != nil || updated != 1 {
		t.Fatalf("updated=%d err=%v", updated, err)
	}
	if len(audit.events) != 1 || len(receipts.payloads) != 1 {
		t.Fatalf("audit=%d receipts=%d", len(audit.events), len(receipts.payloads))
	}
	if event := audit.events[0]; event.EventID != pendingReceipts[0].Receipt.ReceiptID || event.TargetRef != "vm:cluster-1:qemu:instance-1:2" || event.PolicyDecision != "allowed" || !strings.HasPrefix(event.PayloadDigest, "sha256:") || !strings.HasPrefix(event.ResultDigest, "sha256:") {
		t.Fatalf("audit event=%#v", event)
	}
	if pending, err := reopened.PendingAudits(); err != nil || len(pending) != 0 {
		t.Fatalf("pending after replay=%#v err=%v", pending, err)
	}
	if updated, err := restarted.ReconcileOnce(context.Background()); err != nil || updated != 0 || len(audit.events) != 1 {
		t.Fatalf("duplicate replay updated=%d events=%d err=%v", updated, len(audit.events), err)
	}
	raw, err := os.ReadFile(reopened.path(command.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "parameters") || strings.Contains(string(raw), "secret") || strings.Contains(string(raw), `"result"`) {
		t.Fatalf("journal persisted forbidden audit data: %s", raw)
	}
}

func TestMutatingCommandWithoutAuditSinkFailsClosedInTestMode(t *testing.T) {
	now := time.Date(2026, 8, 30, 1, 2, 3, 0, time.UTC)
	command, assignments := signedCommand(t, now)
	receipts := &memoryReceiptQueue{}
	service, journal := auditTestService(t, t.TempDir(), command, assignments, receipts, nil, now, []string{command.Action})
	if processed, err := service.PollOnce(context.Background()); err != nil || processed != 1 {
		t.Fatalf("processed=%d err=%v", processed, err)
	}
	if len(receipts.payloads) != 1 {
		t.Fatalf("receipt count=%d", len(receipts.payloads))
	}
	var receipt Receipt
	if err := json.Unmarshal(receipts.payloads[0], &receipt); err != nil || receipt.Code != "AUDIT_UNAVAILABLE" || receipt.State != "rejected" {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	if entries, err := os.ReadDir(journal.directory); err != nil || len(entries) != 0 {
		t.Fatalf("mutation was claimed without audit sink: entries=%v err=%v", entries, err)
	}
}

func TestAuthenticatedPolicyRejectionsAreAuditedButBadSignatureIsNot(t *testing.T) {
	now := time.Date(2026, 8, 30, 1, 2, 3, 0, time.UTC)
	base, assignments := signedCommand(t, now)
	tests := []struct {
		name    string
		edit    func(*Command)
		allowed []string
		audited bool
	}{
		{"expired", func(c *Command) { c.IssuedAt = now.Add(-20 * time.Minute); c.ExpiresAt = now.Add(-time.Minute) }, []string{base.Action}, true},
		{"wrong-generation", func(c *Command) { c.Identity.Generation++ }, []string{base.Action}, true},
		{"not-allowed", func(*Command) {}, []string{}, true},
		{"missing-approval", func(c *Command) { c.ApprovalRef = "" }, []string{base.Action}, true},
		{"wrong-binding", func(c *Command) { c.BindingID = "22222222-2222-4222-8222-222222222222" }, []string{base.Action}, true},
		{"bad-signature", func(c *Command) { c.Signature = strings.Repeat("0", 64) }, []string{base.Action}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := base
			test.edit(&command)
			if test.name != "bad-signature" {
				command.Signature = SignCommand(command, []byte("secret"))
			}
			sink := &memoryAuditSink{}
			receipts := &memoryReceiptQueue{}
			service, _ := auditTestService(t, t.TempDir(), command, assignments, receipts, sink, now, test.allowed)
			// The local expected binding remains the active base binding.
			service.bindingID = base.BindingID
			if processed, err := service.PollOnce(context.Background()); err != nil || processed != 1 {
				t.Fatalf("processed=%d err=%v", processed, err)
			}
			if got := len(sink.events); got != boolInt(test.audited) {
				t.Fatalf("audit count=%d", got)
			}
			if test.audited {
				event := sink.events[0]
				if event.PolicyDecision != "denied" || event.Outcome != "rejected" || event.FailureStage != "policy" || event.AcceptedAt != nil || event.StartedAt != nil {
					t.Fatalf("denied event=%#v", event)
				}
			}
		})
	}
}

func TestResourceBusyAuditIsAllowedAdmissionFailureWithRedactedVMTarget(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 18, 17, 0, time.UTC)
	command, assignments := signedCommand(t, now)
	command.Action = "vm.delete"
	command.Parameters = json.RawMessage(`{"purge":true,"destroyUnreferencedDisks":true}`)
	command.BodySHA256 = protocolHash(command.Parameters)
	command.Signature = SignCommand(command, []byte("secret"))

	directory := t.TempDir()
	sink := &memoryAuditSink{}
	receipts := &memoryReceiptQueue{}
	service, journal := auditTestService(t, directory, command, assignments, receipts, sink, now, []string{command.Action})
	busy := command
	busy.CommandID = "busy-command"
	busy.OperationID = "busy-operation"
	busy.IdempotencyKey = "busy-idempotency"
	busy.Action = "vm.set-resources"
	busy.Parameters = json.RawMessage(`{"cores":2}`)
	busy.BodySHA256 = protocolHash(busy.Parameters)
	if _, duplicate, err := journal.ClaimWithAudit(busy, now.Add(-time.Second), "test-version"); err != nil || duplicate {
		t.Fatalf("busy claim duplicate=%t err=%v", duplicate, err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api2/json/nodes/pve-1/qemu/101/config" {
			t.Fatalf("unexpected guest-name request: %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"data":{"name":"customer-vm-101"}}`))
	}))
	defer server.Close()
	service.executor.Client = controlTestClient(t, server)

	if processed, err := service.PollOnce(context.Background()); err != nil || processed != 1 {
		t.Fatalf("processed=%d err=%v", processed, err)
	}
	if len(sink.events) != 1 {
		t.Fatalf("audit events=%d", len(sink.events))
	}
	event := sink.events[0]
	if event.Action != "vm.delete" || event.ErrorCode != "RESOURCE_BUSY" || event.PolicyDecision != "allowed" ||
		event.Outcome != "failed" || event.FailureStage != "admission" || event.AcceptedAt == nil || event.StartedAt != nil ||
		event.EndedAt == nil || event.FinishedAt == nil || event.Target == nil || event.Target.ClusterRef != "cluster-1" ||
		event.Target.NodeRef != "pve-1" || event.Target.GuestType != "qemu" || event.Target.VMID != 101 ||
		event.Target.GuestName != "customer-vm-101" {
		t.Fatalf("resource-busy audit=%#v", event)
	}
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"parameters", "rawError", "PVE response", "pveTaskUpid", "UPID:", "password", "tokenSecret", "hmacSecret"} {
		if strings.Contains(strings.ToLower(string(raw)), strings.ToLower(forbidden)) {
			t.Fatalf("audit contains forbidden %q: %s", forbidden, raw)
		}
	}
}

func TestExecutionFailureAuditRemainsPolicyAllowed(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 18, 17, 0, time.UTC)
	command, _ := signedCommand(t, now)
	context, err := newAuditContext(command, now, "test-version")
	if err != nil {
		t.Fatal(err)
	}
	receipt := Receipt{SchemaVersion: 1, ReceiptID: "66666666-6666-4666-8666-666666666666", CommandID: command.CommandID,
		OperationID: command.OperationID, AgentRef: command.AgentRef, State: "failed", Code: "PVE_TASK_FAILED",
		ExecutionMode: "production", StartedAt: now.Add(time.Second), FinishedAt: now.Add(2 * time.Second)}
	event, err := auditEventFromReceipt(context, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if event.PolicyDecision != "allowed" || event.Outcome != "failed" || event.FailureStage != "execution" ||
		event.AcceptedAt == nil || event.StartedAt == nil || event.EndedAt == nil {
		t.Fatalf("execution-failure event=%#v", event)
	}
}

func TestAuditGuestNameSurvivesDurableJournalReopen(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 18, 17, 0, time.UTC)
	command, _ := signedCommand(t, now)
	directory := filepath.Join(t.TempDir(), "journal")
	journal, err := OpenJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, duplicate, err := journal.ClaimWithAudit(command, now, "test-version"); err != nil || duplicate {
		t.Fatalf("claim duplicate=%t err=%v", duplicate, err)
	}
	if err := journal.RecordAuditGuestName(command, "customer-vm-101"); err != nil {
		t.Fatal(err)
	}
	receipt := Receipt{SchemaVersion: 1, ReceiptID: "66666666-6666-4666-8666-666666666666", CommandID: command.CommandID,
		OperationID: command.OperationID, AgentRef: command.AgentRef, State: "failed", Code: "PVE_TASK_FAILED",
		ExecutionMode: "production", StartedAt: now.Add(time.Second), FinishedAt: now.Add(2 * time.Second)}
	if err := journal.Complete(command, receipt); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	event, pending, err := reopened.PendingAuditForReceipt(command.CommandID, receipt.ReceiptID)
	if err != nil || !pending {
		t.Fatalf("pending=%t err=%v", pending, err)
	}
	if event.Target == nil || event.Target.GuestName != "customer-vm-101" || event.Target.NodeRef != command.Identity.NodeRef {
		t.Fatalf("durable target=%#v", event.Target)
	}
}

func TestAuditOmitsUnknownAndNonTerminalEndTimes(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 18, 17, 0, time.UTC)
	command, _ := signedCommand(t, now)
	auditContext, err := newAuditContext(command, now, "test-version")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		state, code string
		wantStarted bool
		wantStage   string
	}{
		{"submitted", "PVE_TASK_SUBMITTED", true, ""},
		{"waiting", "PVE_TASK_WAITING", true, ""},
		{"indeterminate", "PVE_RESULT_INDETERMINATE", false, "receipt"},
	} {
		receipt := Receipt{SchemaVersion: 1, ReceiptID: "99999999-9999-4999-8999-999999999999", CommandID: command.CommandID,
			OperationID: command.OperationID, AgentRef: command.AgentRef, State: test.state, Code: test.code,
			ExecutionMode: "production", StartedAt: now.Add(time.Second), FinishedAt: now.Add(2 * time.Second)}
		event, err := auditEventFromReceipt(auditContext, receipt)
		if err != nil {
			t.Fatalf("state=%s err=%v", test.state, err)
		}
		if (event.StartedAt != nil) != test.wantStarted || event.EndedAt != nil || event.FinishedAt != nil || event.FailureStage != test.wantStage {
			t.Fatalf("state=%s event=%#v", test.state, event)
		}
	}
}

func TestAuditReceiptDigestExcludesFullResult(t *testing.T) {
	now := time.Date(2026, 8, 30, 1, 2, 3, 0, time.UTC)
	receipt := Receipt{SchemaVersion: 1, ReceiptID: "11111111-1111-4111-8111-111111111111", CommandID: "command-1", OperationID: "operation-1", AgentRef: "agent-1", State: "succeeded", Code: "SUCCEEDED", ExecutionMode: "production", StartedAt: now, FinishedAt: now}
	receipt.Result = json.RawMessage(`{"password":"first-secret"}`)
	first, err := AuditReceiptDigest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Result = json.RawMessage(`{"password":"second-secret"}`)
	second, err := AuditReceiptDigest(receipt)
	if err != nil || first != second || !strings.HasPrefix(first, "sha256:") {
		t.Fatalf("first=%q second=%q err=%v", first, second, err)
	}
}

func TestDurableAuditReplayBeforeJournalMarkDoesNotReplaceBatch(t *testing.T) {
	now := time.Date(2026, 8, 30, 1, 2, 3, 0, time.UTC)
	command, _ := signedCommand(t, now)
	directory := t.TempDir()
	journalPath := filepath.Join(directory, "journal")
	journal, err := OpenJournal(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, duplicate, err := journal.ClaimWithAudit(command, now, "test-version"); err != nil || duplicate {
		t.Fatalf("claim duplicate=%v err=%v", duplicate, err)
	}
	receipt := Receipt{
		SchemaVersion: 1, ReceiptID: "33333333-3333-4333-8333-333333333333", CommandID: command.CommandID,
		OperationID: command.OperationID, AgentRef: command.AgentRef, State: "dry_run", Code: "DRY_RUN",
		ExecutionMode: "test", DryRun: true, StartedAt: now, FinishedAt: now,
	}
	if err := journal.Complete(command, receipt); err != nil {
		t.Fatal(err)
	}
	event, pending, err := journal.PendingAuditForReceipt(command.CommandID, receipt.ReceiptID)
	if err != nil || !pending {
		t.Fatalf("pending=%v err=%v", pending, err)
	}
	queueConfig := store.Config{Root: filepath.Join(directory, "queues"), Destination: "monitoring-audit", Kind: store.Audit, Now: func() time.Time { return now }}
	queue, err := store.Open(queueConfig)
	if err != nil {
		t.Fatal(err)
	}
	runStatePath := filepath.Join(directory, "run-state.json")
	state, err := runstate.Open(runStatePath)
	if err != nil {
		t.Fatal(err)
	}
	newSink := func(queue *store.Queue, state *runstate.State) *auditlog.QueueSink {
		sink, err := auditlog.NewQueueSink(auditlog.QueueSinkConfig{Queue: queue, Builder: auditlog.BatchBuilder{
			MonitoringAgentRef: "monitor-agent-1", DeviceID: "device-1", CredentialEpoch: 4,
			BootID: state.BootID(), AgentVersion: "test-version", NextSequence: state.NextMonitoringAudit,
			Now: func() time.Time { return now },
		}})
		if err != nil {
			t.Fatal(err)
		}
		return sink
	}
	if err := newSink(queue, state).Enqueue(event); err != nil {
		t.Fatal(err)
	}
	firstPayload := append([]byte(nil), queue.Snapshot()[0].Payload...)

	// Crash before MarkAuditQueued: all three durable components are reopened.
	journal, err = OpenJournal(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	queue, err = store.Open(queueConfig)
	if err != nil {
		t.Fatal(err)
	}
	state, err = runstate.Open(runStatePath)
	if err != nil {
		t.Fatal(err)
	}
	event, pending, err = journal.PendingAuditForReceipt(command.CommandID, receipt.ReceiptID)
	if err != nil || !pending {
		t.Fatalf("reopened pending=%v err=%v", pending, err)
	}
	if err := newSink(queue, state).Enqueue(event); err != nil {
		t.Fatal(err)
	}
	items := queue.Snapshot()
	if len(items) != 1 || string(items[0].Payload) != string(firstPayload) {
		t.Fatalf("audit replay replaced durable batch: %#v", items)
	}
	if err := journal.MarkAuditQueued(command.CommandID, event.EventID); err != nil {
		t.Fatal(err)
	}
	if pending, err := journal.PendingAudits(); err != nil || len(pending) != 0 {
		t.Fatalf("pending after mark=%#v err=%v", pending, err)
	}
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
