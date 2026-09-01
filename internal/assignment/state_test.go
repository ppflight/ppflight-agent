package assignment

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/inventory"
)

func TestDurableRefreshStateRoundTripAndMissing(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "refresh", "state.json")
	if state, err := LoadState(filename); err != nil || state != (State{}) {
		t.Fatalf("missing state: %#v %v", state, err)
	}
	want := State{Revision: 9_007_199_254_740_993, Cursor: "cursor-01"}
	if err := SaveState(filename, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadState(filename)
	if err != nil || got != want {
		t.Fatalf("round trip %#v: %v", got, err)
	}
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) == "" || !contains(raw, []byte(`"revision":"9007199254740993"`)) {
		t.Fatalf("revision was not string encoded: %s", raw)
	}
}

func TestDurableAuthorityAtomicallyRoundTripsDocumentAndActions(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "refresh", "state.json")
	scope := AuthorityScope{BindingID: "11111111-1111-4111-8111-111111111111", DeviceID: "device-10", CredentialEpoch: 2}
	document := inventory.Document{
		SchemaVersion: inventory.SchemaVersion, Revision: "document-10", IssuedAt: time.Date(2026, 9, 1, 1, 2, 3, 0, time.UTC),
		AllowedActions: []string{"pve.discover", "vm.set-disk-io", "firewall.guest.verify-ipfilter"}, Assignments: []inventory.Assignment{},
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	want := State{Revision: 10, Cursor: "cursor-10"}
	if err := SaveAuthority(filename, want, raw, "cluster-10", scope); err != nil {
		t.Fatal(err)
	}
	got, err := LoadAuthority(filename, "cluster-10", scope)
	if err != nil || !got.Present || got.State != want || len(got.Document.AllowedActions) != 3 || string(got.DocumentRaw) != string(raw) {
		t.Fatalf("authority round trip: %#v %v", got, err)
	}
	stateOnly, err := LoadState(filename)
	if err != nil || stateOnly != want {
		t.Fatalf("state compatibility: %#v %v", stateOnly, err)
	}
	mismatched := scope
	mismatched.CredentialEpoch++
	if _, err := LoadAuthority(filename, "cluster-10", mismatched); err == nil {
		t.Fatal("authority from a different binding epoch was accepted")
	}
}

func TestDurableAuthorityRejectsCorruptOrMissingActionAuthority(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "state.json")
	scope := AuthorityScope{BindingID: "11111111-1111-4111-8111-111111111111", DeviceID: "device-10", CredentialEpoch: 2}
	document := inventory.Document{SchemaVersion: 1, Revision: "document-11", IssuedAt: time.Now().UTC(), Assignments: []inventory.Assignment{}}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveAuthority(filename, State{Revision: 11, Cursor: "cursor-11"}, raw, "cluster-10", scope); err == nil {
		t.Fatal("authority without signed allowedActions was accepted")
	}

	document.AllowedActions = []string{"vm.start"}
	raw, _ = json.Marshal(document)
	if err := SaveAuthority(filename, State{Revision: 11, Cursor: "cursor-11"}, raw, "cluster-10", scope); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	var stored map[string]any
	if err := json.Unmarshal(contents, &stored); err != nil {
		t.Fatal(err)
	}
	stored["contentSha256"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	corrupt, _ := json.Marshal(stored)
	if err := os.WriteFile(filename, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAuthority(filename, "cluster-10"); err == nil {
		t.Fatal("corrupt document authority was accepted")
	}
}

func TestDurableRefreshStateRejectsRollbackLikeCorruption(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(filename, []byte(`{"version":1,"revision":"0","cursor":""}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(filename); err == nil {
		t.Fatal("invalid zero state was accepted")
	}
}

func contains(value, part []byte) bool {
	for len(value) >= len(part) {
		match := true
		for index := range part {
			match = match && value[index] == part[index]
		}
		if match {
			return true
		}
		value = value[1:]
	}
	return false
}
