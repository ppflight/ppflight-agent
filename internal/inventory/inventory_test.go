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
    "cutoverAt":"2026-08-29T12:05:00Z",
    "nicBindings":[
      {"interface":"net0","role":"public","primary":true,"metered":true,"monitoring":true,"expectedMac":"02:00:00:00:01:01","bridge":"vmbr0","vlan":100,"mtu":1500,"ipFilterPolicy":"required"},
      {"interface":"net1","role":"private","primary":false,"metered":false,"monitoring":false,"expectedMac":"02:00:00:00:01:02","bridge":"vmbr1","ipFilterPolicy":"required"}
    ]
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
	capability := item.AggregateMeteringCapability()
	if capability.Supported || capability.Reason != "multi_nic_pve_aggregate_only" {
		t.Fatalf("private NIC was silently included in aggregate metering: %#v", capability)
	}
}

func TestNICBindingsRequireStableRolesAndPolicy(t *testing.T) {
	document, err := Parse([]byte(assignmentJSON), "cluster-test-01")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*Assignment)
	}{
		{name: "duplicate interface", mutate: func(a *Assignment) { a.NICBindings[1].Interface = "net0" }},
		{name: "ambiguous primary", mutate: func(a *Assignment) { a.NICBindings[1].Primary = true }},
		{name: "multiple monitoring", mutate: func(a *Assignment) { a.NICBindings[1].Monitoring = true }},
		{name: "multicast mac", mutate: func(a *Assignment) { a.NICBindings[0].ExpectedMAC = "03:00:00:00:00:01" }},
		{name: "attachment conflict", mutate: func(a *Assignment) { a.NICBindings[0].VNet = "public-vnet" }},
		{name: "missing policy", mutate: func(a *Assignment) { a.NICBindings[0].IPFilterPolicy = "" }},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			candidate := document
			candidate.Assignments = append([]Assignment(nil), document.Assignments...)
			candidate.Assignments[0].NICBindings = append([]NICBinding(nil), document.Assignments[0].NICBindings...)
			item.mutate(&candidate.Assignments[0])
			raw, marshalErr := json.Marshal(candidate)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if _, parseErr := Parse(raw, "cluster-test-01"); parseErr == nil {
				t.Fatal("expected invalid NIC binding to be rejected")
			}
		})
	}
}

func TestAggregateMeteringOnlyWhenEveryNICIsExplicitlyMetered(t *testing.T) {
	document, err := Parse([]byte(assignmentJSON), "cluster-test-01")
	if err != nil {
		t.Fatal(err)
	}
	assignment := document.Assignments[0]
	assignment.NICBindings[1].Metered = true
	if capability := assignment.AggregateMeteringCapability(); !capability.Supported || capability.Source != "pve-guest-aggregate" {
		t.Fatalf("all-NIC aggregate policy should be supported: %#v", capability)
	}
	assignment.NICBindings = nil
	if capability := assignment.AggregateMeteringCapability(); capability.Supported || capability.Reason != "nic_binding_required" {
		t.Fatalf("untyped NIC policy was treated as billable: %#v", capability)
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
