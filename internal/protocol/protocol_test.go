package protocol

import (
	"bytes"
	"encoding/json"
	"net/http"
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
