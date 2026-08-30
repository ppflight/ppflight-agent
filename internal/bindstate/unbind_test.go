package bindstate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestUnbindJournalsAreIndependentStrictAndRestorable(t *testing.T) {
	directory := t.TempDir()
	website := testState("https://website.example")
	monitoring := monitoringTestState(3)
	if err := Save(directory, website); err != nil {
		t.Fatal(err)
	}
	if err := SaveMonitoring(directory, monitoring); err != nil {
		t.Fatal(err)
	}

	websiteMarker, err := BeginWebsiteUnbind(directory, website)
	if err != nil {
		t.Fatal(err)
	}
	monitoringMarker, err := BeginMonitoringUnbind(directory, monitoring)
	if err != nil {
		t.Fatal(err)
	}
	if websiteMarker.Domain != "website" || monitoringMarker.Domain != "monitoring" || websiteMarker.StateBackup == monitoringMarker.StateBackup {
		t.Fatalf("unbind journals crossed domains: website=%#v monitoring=%#v", websiteMarker, monitoringMarker)
	}
	if _, found, err := ReadWebsiteUnbind(directory); err != nil || !found {
		t.Fatalf("website journal missing: found=%v err=%v", found, err)
	}
	if _, found, err := ReadMonitoringUnbind(directory); err != nil || !found {
		t.Fatalf("monitoring journal missing: found=%v err=%v", found, err)
	}
	if _, err := BeginWebsiteUnbind(directory, website); err == nil {
		t.Fatal("website journal was overwritten")
	}

	if err := RemoveWebsite(directory); err != nil {
		t.Fatal(err)
	}
	if err := RemoveMonitoring(directory); err != nil {
		t.Fatal(err)
	}
	if err := RestoreWebsiteUnbind(directory, websiteMarker); err != nil {
		t.Fatal(err)
	}
	if err := RestoreMonitoringUnbind(directory, monitoringMarker); err != nil {
		t.Fatal(err)
	}
	websiteRestored, err := Load(directory)
	if err != nil || websiteRestored.BindingID != website.BindingID || websiteRestored.CredentialEpoch != website.CredentialEpoch {
		t.Fatalf("website journal restore=%#v err=%v", websiteRestored, err)
	}
	monitoringRestored, err := LoadMonitoring(directory)
	if err != nil || monitoringRestored.BindingID != monitoring.BindingID || monitoringRestored.CredentialEpoch != monitoring.CredentialEpoch {
		t.Fatalf("monitoring journal restore=%#v err=%v", monitoringRestored, err)
	}
	if err := DiscardWebsiteUnbindBackup(directory, websiteMarker); err != nil {
		t.Fatal(err)
	}
	if err := DiscardMonitoringUnbindBackup(directory, monitoringMarker); err != nil {
		t.Fatal(err)
	}
	if err := FinishWebsiteUnbind(directory); err != nil {
		t.Fatal(err)
	}
	if err := FinishMonitoringUnbind(directory); err != nil {
		t.Fatal(err)
	}
	if _, found, err := ReadWebsiteUnbind(directory); err != nil || found {
		t.Fatalf("website journal after finish: found=%v err=%v", found, err)
	}
	if _, found, err := ReadMonitoringUnbind(directory); err != nil || found {
		t.Fatalf("monitoring journal after finish: found=%v err=%v", found, err)
	}
}

func TestUnbindJournalRejectsPathSwapAndMalformedMarker(t *testing.T) {
	directory := t.TempDir()
	website := testState("https://website.example")
	if err := Save(directory, website); err != nil {
		t.Fatal(err)
	}
	marker, err := BeginWebsiteUnbind(directory, website)
	if err != nil {
		t.Fatal(err)
	}
	if err := RestoreWebsiteUnbind(directory, UnbindCommit{
		SchemaVersion: unbindSchemaVersion, Domain: "website", BindingID: marker.BindingID, CredentialEpoch: marker.CredentialEpoch, StateBackup: "../" + marker.StateBackup,
	}); err == nil {
		t.Fatal("path-swapped journal was accepted")
	}
	if err := FinishWebsiteUnbind(directory); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(websiteUnbindCommitPath(directory), []byte(`{"schemaVersion":1,"domain":"website","bindingId":"123e4567-e89b-42d3-a456-426614174001","credentialEpoch":1,"stateBackup":"binding-state.backup.x.json","extra":true}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadWebsiteUnbind(directory); err == nil {
		t.Fatal("malformed unbind journal was accepted")
	}
	if err := FinishWebsiteUnbind(directory); err == nil {
		t.Fatal("malformed unbind journal was cleared")
	}
	if _, err := os.Stat(filepath.Join(Directory(directory), websiteUnbindCommitName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected malformed journal stat error: %v", err)
	} else if errors.Is(err, os.ErrNotExist) {
		t.Fatal("malformed unbind journal disappeared")
	}
}
