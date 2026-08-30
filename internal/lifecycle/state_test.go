package lifecycle

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUncleanExitPersistsUntilBothTelemetryDomainsQueueIt(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "lifecycle-state.json")
	firstStart := time.Date(2026, 8, 30, 1, 0, 0, 0, time.UTC)
	first, err := Begin(filename, "11111111-1111-4111-8111-111111111111", firstStart)
	if err != nil || len(first.Pending(DomainWebsite)) != 0 {
		t.Fatalf("first=%#v err=%v", first, err)
	}
	// Do not mark the first session clean: this simulates SIGKILL or watchdog.
	second, err := Begin(filename, "22222222-2222-4222-8222-222222222222", firstStart.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	website := second.Pending(DomainWebsite)
	monitoring := second.Pending(DomainMonitor)
	if len(website) != 1 || len(monitoring) != 1 || website[0].EventID != monitoring[0].EventID || website[0].PreviousBootID != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("website=%#v monitoring=%#v", website, monitoring)
	}
	if err := second.MarkQueued(DomainWebsite); err != nil {
		t.Fatal(err)
	}
	if len(second.Pending(DomainWebsite)) != 0 || len(second.Pending(DomainMonitor)) != 1 {
		t.Fatal("one trust domain acknowledgement cleared the other")
	}
	if err := second.MarkClean(firstStart.Add(2 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	third, err := Begin(filename, "33333333-3333-4333-8333-333333333333", firstStart.Add(3*time.Minute))
	if err != nil || len(third.Pending(DomainWebsite)) != 0 || len(third.Pending(DomainMonitor)) != 1 {
		t.Fatalf("clean restart changed pending incident: website=%#v monitoring=%#v err=%v", third.Pending(DomainWebsite), third.Pending(DomainMonitor), err)
	}
	if err := third.MarkQueued(DomainMonitor); err != nil || len(third.Pending(DomainMonitor)) != 0 {
		t.Fatalf("monitor acknowledgement did not finish incident: err=%v pending=%#v", err, third.Pending(DomainMonitor))
	}
}

func TestLifecycleStateRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "lifecycle-state.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Begin(link, "11111111-1111-4111-8111-111111111111", time.Now().UTC()); err == nil {
		t.Fatal("symlink lifecycle state was accepted")
	}
}
