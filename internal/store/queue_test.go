package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestQueueSurvivesReopenAndDeduplicates(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	config := Config{Root: t.TempDir(), Destination: "control-plane", Kind: Metering, Now: func() time.Time { return now }}
	queue, err := Open(config)
	if err != nil {
		t.Fatal(err)
	}
	first, inserted, err := queue.Enqueue("batch-a", []byte(`{"a":1}`))
	if err != nil || !inserted {
		t.Fatalf("enqueue = %#v %v %v", first, inserted, err)
	}
	again, inserted, err := queue.Enqueue("batch-a", []byte(`other`))
	if err != nil || inserted || again.Sequence != first.Sequence {
		t.Fatalf("dedupe = %#v %v %v", again, inserted, err)
	}
	reopened, err := Open(config)
	if err != nil {
		t.Fatal(err)
	}
	item, ok := reopened.Next(now)
	if !ok || item.BatchID != "batch-a" || item.Sequence != 1 {
		t.Fatalf("reopened item = %#v, %v", item, ok)
	}
	if err := reopened.Ack(item.BatchID); err != nil {
		t.Fatal(err)
	}
	if reopened.Len() != 0 {
		t.Fatal("ack did not remove item")
	}
}

func TestMeteringCapacityNeverEvicts(t *testing.T) {
	queue, err := Open(Config{Root: t.TempDir(), Destination: "cp", Kind: Metering, Policy: Policy{MaxItems: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := queue.Enqueue("one", []byte("one")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := queue.Enqueue("two", []byte("two")); !errors.Is(err, ErrCapacity) {
		t.Fatalf("error = %v", err)
	}
	if queue.Len() != 1 || queue.Stats().DroppedItems != 0 {
		t.Fatalf("metering was dropped: %#v", queue.Stats())
	}
}

func TestAuditQueueNeverEvictsAndSurvivesRestart(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 8, 30, 1, 2, 3, 0, time.UTC)
	config := Config{Root: root, Destination: "monitoring-audit", Kind: Audit, Policy: Policy{MaxItems: 1}, Now: func() time.Time { return now }}
	queue, err := Open(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := queue.Enqueue("event-1", []byte(`{"event":1}`)); err != nil || !created {
		t.Fatalf("first enqueue created=%v err=%v", created, err)
	}
	if _, due := queue.Next(now); due {
		t.Fatal("new audit item was deliverable before journal acknowledgement window")
	}
	if item, due := queue.Next(now.Add(AuditEnqueueDelay)); !due || item.BatchID != "event-1" {
		t.Fatalf("audit item due=%v item=%#v", due, item)
	}
	if _, _, err := queue.Enqueue("event-2", []byte(`{"event":2}`)); !errors.Is(err, ErrCapacity) {
		t.Fatalf("audit capacity err=%v", err)
	}
	if _, err := Open(Config{Root: root, Destination: "monitoring-audit-evict", Kind: Audit, Policy: Policy{DropOldest: true}}); err == nil {
		t.Fatal("audit queue accepted an eviction policy")
	}
	reopened, err := Open(config)
	if err != nil {
		t.Fatal(err)
	}
	items := reopened.Snapshot()
	if len(items) != 1 || items[0].BatchID != "event-1" || string(items[0].Payload) != `{"event":1}` {
		t.Fatalf("reopened audit queue=%#v", items)
	}
}

func TestTelemetryEvictsAndCountsDrops(t *testing.T) {
	queue, err := Open(Config{Root: t.TempDir(), Destination: "monitoring", Kind: Telemetry, Policy: Policy{MaxItems: 1, DropOldest: true}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := queue.Enqueue("one", []byte("one")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := queue.Enqueue("two", []byte("two")); err != nil {
		t.Fatal(err)
	}
	item, ok := queue.Next(time.Now())
	if !ok || item.BatchID != "two" {
		t.Fatalf("next = %#v, %v", item, ok)
	}
	if stats := queue.Stats(); stats.DroppedItems != 1 || stats.DroppedBytes != 3 {
		t.Fatalf("stats = %#v", stats)
	}
}

func TestRetryStateSurvivesReopen(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	config := Config{Root: t.TempDir(), Destination: "control", Kind: Metering, Now: func() time.Time { return now }}
	queue, err := Open(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := queue.Enqueue("batch", []byte("payload")); err != nil {
		t.Fatal(err)
	}
	next := now.Add(time.Minute)
	if err := queue.Nack("batch", next, "temporary outage"); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.Next(now); ok {
		t.Fatal("retrying item became due after reopen")
	}
	item, ok := reopened.Next(next)
	if !ok || item.Attempts != 1 || item.LastError != "temporary outage" {
		t.Fatalf("retry state = %#v, %v", item, ok)
	}
}

func TestQuarantinePersistsDeadLetter(t *testing.T) {
	queue, err := Open(Config{Root: t.TempDir(), Destination: "control", Kind: Metering})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := queue.Enqueue("rejected", []byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err := queue.Quarantine("rejected", "HTTP 401: denied"); err != nil {
		t.Fatal(err)
	}
	if queue.Len() != 0 || queue.Stats().DeadLetterItems != 1 {
		t.Fatalf("stats=%#v", queue.Stats())
	}
	entries, err := os.ReadDir(filepath.Join(queue.dir, ".dead-letter"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("dead letters=%v err=%v", entries, err)
	}
}
