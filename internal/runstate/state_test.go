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
	if value, err := second.NextMonitoring(); err != nil || value != 2 {
		t.Fatalf("value=%d err=%v", value, err)
	}
}

func TestMonitoringAuditSequenceIsIndependentAndPersistent(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "run-state.json")
	state, err := Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := state.NextMonitoringAudit(); err != nil || got != 1 {
		t.Fatalf("first audit sequence=%d err=%v", got, err)
	}
	if got, err := state.NextMonitoring(); err != nil || got != 1 {
		t.Fatalf("telemetry sequence=%d err=%v", got, err)
	}
	reopened, err := Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := reopened.NextMonitoringAudit(); err != nil || got != 2 {
		t.Fatalf("reopened audit sequence=%d err=%v", got, err)
	}
}
