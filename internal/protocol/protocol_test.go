package protocol

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestUsageRecordCountersAreDecimalStrings(t *testing.T) {
	record := UsageRecord{VMID: 100, Generation: Counter(18446744073709551615), Sequence: 7, IngressBytes: 9, EgressBytes: 11}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"generation":"18446744073709551615"`)) || !bytes.Contains(encoded, []byte(`"ingressBytes":"9"`)) {
		t.Fatalf("counters must be JSON decimal strings: %s", encoded)
	}
	var decoded UsageRecord
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Generation != record.Generation {
		t.Fatalf("generation = %d", decoded.Generation)
	}
}

func TestSignAndVerifyRequest(t *testing.T) {
	body := []byte(`{"batchId":"batch-1"}`)
	req, err := http.NewRequest(http.MethodPost, "https://example.test/v1/ingest?kind=metering", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	if err := SignRequest(req, body, "key-a", []byte("secret"), now, "0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRequest(req, body, func(keyID string) ([]byte, error) {
		if keyID != "key-a" {
			t.Fatalf("unexpected key ID %q", keyID)
		}
		return []byte("secret"), nil
	}, VerifyOptions{Now: now}); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRequest(req, []byte(`tampered`), func(string) ([]byte, error) { return []byte("secret"), nil }, VerifyOptions{Now: now}); err == nil {
		t.Fatal("tampered request verified")
	}
}

func TestBatchIdentityIsRequired(t *testing.T) {
	batch, err := NewBatch(Metering, "agent", "collector", "agent-v1", 1, []UsageRecord{})
	if err != nil {
		t.Fatal(err)
	}
	if err := batch.Validate(); err != nil {
		t.Fatal(err)
	}
	batch.SourceRef = ""
	if err := batch.Validate(); err == nil {
		t.Fatal("batch without source ref validated")
	}
}

func TestPerNICUsageIdentityIsStrictAndCanonical(t *testing.T) {
	now := time.Now().UTC()
	base := UsageBatch{SchemaVersion: 1, BatchID: "batch", AgentRef: "agent", CollectorRef: "collector", SourceRef: "source", ClusterRef: "cluster", Mode: "production", Sequence: 1, ObservedAt: now, Events: []UsageRecord{{
		ServiceRef: "service", ClusterRef: "cluster", NodeRef: "pve", VMID: 101, Generation: 1, InstanceUUID: "instance", GuestType: "qemu", EventID: "event", CounterEpoch: "epoch", Sequence: 1, Source: "pve-host-netdev", InterfaceRef: "net0", CanonicalMAC: "02:00:00:00:AB:01", NetworkRole: "public", Metered: true, BillingState: "active", ObservedAt: now,
	}}}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid per-NIC usage rejected: %v", err)
	}
	for _, mutate := range []func(*UsageRecord){
		func(event *UsageRecord) { event.InterfaceRef = "net32" },
		func(event *UsageRecord) { event.InterfaceRef = "net01" },
		func(event *UsageRecord) { event.CanonicalMAC = "02:00:00:00:ab:01" },
		func(event *UsageRecord) { event.CanonicalMAC = "03:00:00:00:01:01" },
		func(event *UsageRecord) { event.NetworkRole = "private" },
		func(event *UsageRecord) { event.Metered = false },
	} {
		candidate := base
		candidate.Events = append([]UsageRecord(nil), base.Events...)
		mutate(&candidate.Events[0])
		if err := candidate.Validate(); err == nil {
			t.Fatalf("invalid per-NIC identity accepted: %#v", candidate.Events[0])
		}
	}
}

func TestPerNICUsageGoldenPreservesUint64(t *testing.T) {
	raw, err := os.ReadFile("testdata/usage-record-per-nic-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var event UsageRecord
	if err := json.Unmarshal(raw, &event); err != nil {
		t.Fatal(err)
	}
	batch := UsageBatch{SchemaVersion: 1, BatchID: "batch", AgentRef: "agent", CollectorRef: "collector", SourceRef: "source", ClusterRef: "cluster-1", Mode: "production", Sequence: 1, ObservedAt: event.ObservedAt, Events: []UsageRecord{event}}
	if err := batch.Validate(); err != nil || uint64(event.IngressBytes) != 18446744073709551614 || uint64(event.EgressBytes) != 18446744073709551613 {
		t.Fatalf("event=%#v err=%v", event, err)
	}
}
