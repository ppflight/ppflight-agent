package assignment

import (
	"os"
	"path/filepath"
	"testing"
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
