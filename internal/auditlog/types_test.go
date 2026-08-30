package auditlog

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/protocol"
	"github.com/ppflight/ppflight-agent/internal/store"
)

func validEvent() Event {
	received := time.Date(2026, 8, 30, 1, 2, 3, 0, time.UTC)
	started := received.Add(time.Second)
	finished := received.Add(2 * time.Second)
	return Event{
		EventID: "11111111-1111-4111-8111-111111111111", AssignmentRevision: 7,
		CommandID: "command-1", IdempotencyKey: "idempotency-1", Action: "vm.start", Scope: "vm",
		TargetRef: "vm:cluster-1:qemu:instance-1:2", WebsiteCommandKeyID: "website-key-1",
		ReceivedAt: received, AcceptedAt: &received, StartedAt: &started, FinishedAt: &finished,
		Outcome: "succeeded", ErrorCode: "SUCCEEDED", UPID: "sha256:" + strings.Repeat("c", 64),
		ApprovalRef: "approval-1", RequestedByRef: "operator-1",
		PayloadDigest: "sha256:" + strings.Repeat("a", 64), ResultDigest: "sha256:" + strings.Repeat("b", 64),
		PolicyDecision: "allowed", AgentVersion: "1.2.3",
	}
}

func TestBatchGoldenJSON(t *testing.T) {
	event := validEvent()
	batch := Batch{
		SchemaVersion: 1, BatchID: event.EventID, MonitoringAgentRef: "monitor-agent-1", DeviceID: "device-1",
		CredentialEpoch: 4, Sequence: 9, BootID: "22222222-2222-4222-8222-222222222222",
		ObservedAt: *event.FinishedAt, SentAt: event.FinishedAt.Add(time.Second),
		DeliveryState: DeliveryState{PendingItems: 2, PendingBytes: 4096, LastDeliveryError: "", AuthBlocked: false},
		Events:        []Event{event},
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schemaVersion":1,"batchId":"11111111-1111-4111-8111-111111111111","monitoringAgentRef":"monitor-agent-1","deviceId":"device-1","credentialEpoch":"4","sequence":"9","bootId":"22222222-2222-4222-8222-222222222222","observedAt":"2026-08-30T01:02:05Z","sentAt":"2026-08-30T01:02:06Z","deliveryState":{"pendingItems":"2","pendingBytes":"4096","lastDeliveryError":"","authBlocked":false},"events":[{"eventId":"11111111-1111-4111-8111-111111111111","assignmentRevision":"7","commandId":"command-1","idempotencyKey":"idempotency-1","action":"vm.start","scope":"vm","targetRef":"vm:cluster-1:qemu:instance-1:2","websiteCommandKeyId":"website-key-1","receivedAt":"2026-08-30T01:02:03Z","acceptedAt":"2026-08-30T01:02:03Z","startedAt":"2026-08-30T01:02:04Z","finishedAt":"2026-08-30T01:02:05Z","outcome":"succeeded","errorCode":"SUCCEEDED","upid":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","approvalRef":"approval-1","requestedByRef":"operator-1","payloadDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","resultDigest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","policyDecision":"allowed","agentVersion":"1.2.3"}]}`
	if string(raw) != want {
		t.Fatalf("golden mismatch\n got: %s\nwant: %s", raw, want)
	}
	var decoded Batch
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
}

func TestStrictAuditJSONRejectsUnknownDuplicateNumericAndNonUTC(t *testing.T) {
	eventRaw, err := json.Marshal(validEvent())
	if err != nil {
		t.Fatal(err)
	}
	cases := []string{
		strings.Replace(string(eventRaw), `"commandId":"command-1"`, `"commandId":"command-1","unknown":true`, 1),
		strings.Replace(string(eventRaw), `"commandId":"command-1"`, `"commandId":"command-1","commandId":"command-1"`, 1),
		strings.Replace(string(eventRaw), `"assignmentRevision":"7"`, `"assignmentRevision":7`, 1),
		strings.Replace(string(eventRaw), `"receivedAt":"2026-08-30T01:02:03Z"`, `"receivedAt":"2026-08-30T01:02:03+00:00"`, 1),
	}
	for _, raw := range cases {
		var event Event
		if err := json.Unmarshal([]byte(raw), &event); err == nil {
			t.Fatalf("strict event accepted %s", raw)
		}
	}
}

func TestEventRejectsSensitiveOrNonCanonicalFields(t *testing.T) {
	checks := []func(*Event){
		func(e *Event) { e.RequestedByRef = "root@example.com" },
		func(e *Event) { e.UPID = "UPID:pve-1:1:2:3:task:101:root@pam:" },
		func(e *Event) { e.PayloadDigest = strings.Repeat("a", 64) },
		func(e *Event) { e.ResultDigest = "sha256:" + strings.Repeat("A", 64) },
		func(e *Event) { e.TargetRef = "instance-1" },
	}
	for _, edit := range checks {
		event := validEvent()
		edit(&event)
		if err := event.Validate(); err == nil {
			t.Fatalf("invalid event accepted: %#v", event)
		}
	}
	state := DeliveryState{LastDeliveryError: "HTTP 401: upstream body"}
	if err := state.Validate(); err == nil {
		t.Fatal("free-form delivery error was accepted")
	}
	state.LastDeliveryError = "SOME_FUTURE_ERROR"
	if err := state.Validate(); err == nil {
		t.Fatal("unfrozen delivery error code was accepted")
	}
}

func TestQueueSinkKeepsFirstDurablePayloadAcrossRetryAndRestart(t *testing.T) {
	now := time.Date(2026, 8, 30, 1, 2, 10, 0, time.UTC)
	root := t.TempDir()
	queueConfig := store.Config{Root: root, Destination: "monitoring-audit", Kind: store.Audit, Now: func() time.Time { return now }}
	queue, err := store.Open(queueConfig)
	if err != nil {
		t.Fatal(err)
	}
	sequence := uint64(0)
	sink, err := NewQueueSink(QueueSinkConfig{Queue: queue, Builder: BatchBuilder{
		MonitoringAgentRef: "monitor-agent-1", DeviceID: "device-1", CredentialEpoch: 4,
		BootID: "22222222-2222-4222-8222-222222222222", AgentVersion: "1.2.3",
		NextSequence: func() (uint64, error) { sequence++; return sequence, nil }, Now: func() time.Time { return now },
	}})
	if err != nil {
		t.Fatal(err)
	}
	event := validEvent()
	if err := sink.Enqueue(event); err != nil {
		t.Fatal(err)
	}
	first := queue.Snapshot()[0]
	// Simulate a crash before the journal can mark the event queued. Replaying
	// the event must reuse, not overwrite, the already durable batch.
	reopened, err := store.Open(queueConfig)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := NewQueueSink(QueueSinkConfig{Queue: reopened, Builder: sink.builder})
	if err != nil {
		t.Fatal(err)
	}
	if err := retry.Enqueue(event); err != nil {
		t.Fatal(err)
	}
	items := reopened.Snapshot()
	if len(items) != 1 || string(items[0].Payload) != string(first.Payload) || sequence != 2 {
		t.Fatalf("retry replaced durable payload: sequence=%d items=%#v", sequence, items)
	}
	var batch Batch
	if err := json.Unmarshal(items[0].Payload, &batch); err != nil || batch.Sequence != protocol.Counter(1) {
		t.Fatalf("durable batch sequence=%d err=%v", batch.Sequence, err)
	}
}
