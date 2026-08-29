package runstate

import (
	"path/filepath"
	"testing"
)

func TestSequencesPersistAndBootChanges(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "state.json")
	first, err := Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	boot := first.BootID()
	if value, err := first.NextWebsite(); err != nil || value != 1 {
		t.Fatalf("value=%d err=%v", value, err)
	}
	if value, err := first.NextMonitoring(); err != nil || value != 1 {
		t.Fatalf("value=%d err=%v", value, err)
	}
	second, err := Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	if second.BootID() == boot {
		t.Fatal("boot ID did not change")
	}
	if value, err := second.NextWebsite(); err != nil || value != 2 {
		t.Fatalf("value=%d err=%v", value, err)
	}
	if value, err := second.NextMonitoring(); err != nil || value != 1 {
		t.Fatalf("value=%d err=%v", value, err)
	}
}
