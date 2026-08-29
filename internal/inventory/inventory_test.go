package inventory

import (
	"encoding/json"
	"testing"
)

const assignmentJSON = `{
  "schemaVersion":1,
  "revision":"inventory-42",
  "issuedAt":"2026-08-29T12:00:00Z",
  "assignments":[{
    "serviceRef":"018f-service-uuid",
    "clusterRef":"cluster-test-01",
    "nodeRef":"pve-a",
    "vmid":101,
    "generation":3,
    "instanceUuid":"018f-instance-uuid",
    "guestType":"qemu",
    "billingState":"active",
    "cutoverAt":"2026-08-29T12:05:00Z"
  }]
}`

func TestParseAndLookup(t *testing.T) {
	document, err := Parse([]byte(assignmentJSON), "cluster-test-01")
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(document)
	item, ok := store.Lookup("cluster-test-01", "qemu", 101)
	if !ok || item.Generation != 3 || item.ServiceRef == "" {
		t.Fatalf("unexpected assignment: %#v %v", item, ok)
	}
}

func TestRejectsVMIDReuseInDocument(t *testing.T) {
	document, err := Parse([]byte(assignmentJSON), "cluster-test-01")
	if err != nil {
		t.Fatal(err)
	}
	duplicate := document.Assignments[0]
	duplicate.ServiceRef, duplicate.InstanceUUID, duplicate.Generation, duplicate.BillingState = "other-service", "other-instance", 4, "shadow"
	document.Assignments = append(document.Assignments, duplicate)
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Parse(encoded, "cluster-test-01"); err == nil {
		t.Fatalf("expected duplicate error, got %v", err)
	}
}

func TestActiveRequiresCutover(t *testing.T) {
	document, err := Parse([]byte(assignmentJSON), "cluster-test-01")
	if err != nil {
		t.Fatal(err)
	}
	document.Assignments[0].CutoverAt = nil
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Parse(encoded, "cluster-test-01"); err == nil {
		t.Fatalf("expected cutover error, got %v", err)
	}
}
