package bindstate

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/enrollment"
	"github.com/ppflight/ppflight-agent/internal/netpolicy"
)

func testState(endpoint string) State {
	secret := enrollment.Secret(base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")))
	credential := enrollment.HMACCredential{KeyID: "key-01", Secret: secret}
	response := enrollment.Response{
		SchemaVersion: enrollment.SchemaVersion, BindingID: "123e4567-e89b-42d3-a456-426614174001", DeviceID: "device-0123456789abcdef",
		AgentRef: "agent-01", CollectorRef: "collector-01", SourceRef: "source-01", ClusterRef: "cluster-01", NodeRef: "node-01", Site: "site-01",
		Endpoints:                enrollment.Endpoints{Metering: endpoint + "/metering", Telemetry: endpoint + "/telemetry", Assignments: endpoint + "/assignments", Commands: endpoint + "/commands", Receipts: endpoint + "/receipts"},
		HMACCredentials:          enrollment.HMACCredentials{Metering: credential, Telemetry: credential, Assignments: credential, Commands: credential, Receipts: credential},
		CommandSigningCredential: enrollment.CommandSigningCredential{KeyID: "command-key-01", Algorithm: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32))},
		AllowedActions:           []string{"vm.start"},
		AssignmentDocument:       json.RawMessage(`{"schemaVersion":1,"revision":"rev-01","issuedAt":"2026-08-30T00:00:00Z","assignments":[]}`),
		NetworkPolicy:            netpolicy.NetworkPolicy{AgentObservedIPv4: "127.0.0.1", ServerIPv4Allowlist: []string{"127.0.0.1"}},
		CredentialEpoch:          1, IssuedAt: time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC),
	}
	return FromResponse(endpoint+"/v1/bind", "device-0123456789abcdef", response)
}

func TestSaveLoadAndStableDeviceID(t *testing.T) {
	directory := t.TempDir()
	first, err := LoadOrCreateDeviceID(directory)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateDeviceID(directory)
	if err != nil || first != second {
		t.Fatalf("device IDs = %q, %q, %v", first, second, err)
	}
	state := testState("https://service.example")
	state.DeviceID = first
	if err := Save(directory, state); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Identity.AgentRef != "agent-01" || string(loaded.HMACCredentials.Commands.Secret) != string(state.HMACCredentials.Commands.Secret) {
		t.Fatalf("loaded state mismatch: %#v", loaded.Identity)
	}
	if runtime.GOOS != "windows" {
		for _, path := range []string{Path(directory), DeviceIDPath(directory)} {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o640 {
				t.Fatalf("%s mode = %o", path, info.Mode().Perm())
			}
		}
		info, err := os.Stat(Directory(directory))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o750 {
			t.Fatalf("binding directory mode = %o", info.Mode().Perm())
		}
	}
}

func TestRemoveWebsiteKeepsStableDeviceAndMonitoringPaths(t *testing.T) {
	directory := t.TempDir()
	deviceID, err := LoadOrCreateDeviceID(directory)
	if err != nil {
		t.Fatal(err)
	}
	state := testState("https://service.example")
	state.DeviceID = deviceID
	if err := Save(directory, state); err != nil {
		t.Fatal(err)
	}
	if err := RemoveWebsite(directory); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(directory); !os.IsNotExist(err) {
		t.Fatalf("website state remains: %v", err)
	}
	loadedDeviceID, err := LoadOrCreateDeviceID(directory)
	if err != nil || loadedDeviceID != deviceID {
		t.Fatalf("device ID changed: got=%q want=%q err=%v", loadedDeviceID, deviceID, err)
	}
	if err := RemoveWebsite(directory); err != nil {
		t.Fatalf("idempotent removal failed: %v", err)
	}
}

func TestWebsiteBackupRestoreAndFirstBindingRollback(t *testing.T) {
	directory := t.TempDir()
	original := testState("https://service.example")
	if err := Save(directory, original); err != nil {
		t.Fatal(err)
	}
	backup, err := BackupWebsite(directory)
	if err != nil || backup == "" {
		t.Fatalf("backup=%q err=%v", backup, err)
	}
	replacement := testState("https://replacement.example")
	replacement.BindingID = "123e4567-e89b-42d3-a456-426614174002"
	replacement.CredentialEpoch = 2
	if err := Save(directory, replacement); err != nil {
		t.Fatal(err)
	}
	if err := RestoreWebsite(directory, backup); err != nil {
		t.Fatal(err)
	}
	restored, err := Load(directory)
	if err != nil || restored.BindingID != original.BindingID || restored.CredentialEpoch != original.CredentialEpoch {
		t.Fatalf("restored=%#v err=%v", restored, err)
	}
	if err := DiscardWebsiteBackup(directory, backup); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Fatalf("website backup remains: %v", err)
	}

	firstDirectory := t.TempDir()
	if firstBackup, err := BackupWebsite(firstDirectory); err != nil || firstBackup != "" {
		t.Fatalf("first backup=%q err=%v", firstBackup, err)
	}
	if err := Save(firstDirectory, original); err != nil {
		t.Fatal(err)
	}
	if err := RestoreWebsite(firstDirectory, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(firstDirectory); !os.IsNotExist(err) {
		t.Fatalf("first binding state remains after rollback: %v", err)
	}
}

func TestLoadMigratesRetiredStoredServerIPv4Allowlist(t *testing.T) {
	directory := t.TempDir()
	state := testState("https://service.example")
	if err := Save(directory, state); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(Path(directory))
	if err != nil {
		t.Fatal(err)
	}
	legacy := strings.Replace(string(raw), `"agentObservedIPv4": "127.0.0.1"`, `"agentObservedIPv4": "127.0.0.1", "serverIPv4Allowlist": ["192.0.2.1"]`, 1)
	if legacy == string(raw) {
		t.Fatal("failed to create legacy state fixture")
	}
	if err := os.WriteFile(Path(directory), []byte(legacy), 0o640); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(directory)
	if err != nil {
		t.Fatalf("legacy state was not migrated: %v", err)
	}
	encoded, err := json.Marshal(loaded.NetworkPolicy)
	if err != nil || strings.Contains(string(encoded), "serverIPv4Allowlist") {
		t.Fatalf("retired field survived migration: %s err=%v", encoded, err)
	}
}

func TestPathsStayInsideControlledBindingDirectory(t *testing.T) {
	stateDirectory := filepath.Join("root", "state")
	wantDirectory := filepath.Join(stateDirectory, "bindings")
	if Directory(stateDirectory) != wantDirectory {
		t.Fatalf("Directory() = %q, want %q", Directory(stateDirectory), wantDirectory)
	}
	for _, path := range []string{Path(stateDirectory), DeviceIDPath(stateDirectory), MonitoringPath(stateDirectory), PendingPath(stateDirectory, "website")} {
		if filepath.Dir(path) != wantDirectory {
			t.Fatalf("binding path escaped controlled directory: %q", path)
		}
	}
}

func TestPrivateFilesRejectSymlinksAndBadPermissions(t *testing.T) {
	directory := t.TempDir()
	if _, err := ensureBindingDirectory(directory); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("device-0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, DeviceIDPath(directory)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateDeviceID(directory); err == nil {
		t.Fatal("accepted symlink device ID")
	}

	if runtime.GOOS != "windows" {
		path := filepath.Join(t.TempDir(), "device-id")
		if err := os.WriteFile(path, []byte("device-0123456789abcdef\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := readPrivateFile(path, 256); err == nil {
			t.Fatal("accepted world-readable private state")
		}
	}
}

func TestLoadRejectsSymlinkBindingDirectory(t *testing.T) {
	stateDirectory := t.TempDir()
	realDirectory := filepath.Join(t.TempDir(), "bindings")
	if err := os.Mkdir(realDirectory, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realDirectory, "device-id"), []byte("device-0123456789abcdef\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDirectory, Directory(stateDirectory)); err != nil {
		t.Skipf("directory symlink unavailable: %v", err)
	}
	if _, err := LoadOrCreateDeviceID(stateDirectory); err == nil {
		t.Fatal("accepted a symlink binding directory")
	}
}

func TestStateValidationDoesNotLeakCredential(t *testing.T) {
	state := testState("https://service.example")
	secret := string(state.HMACCredentials.Metering.Secret)
	state.Endpoints.Metering = "https://elsewhere.example/metering"
	err := state.Validate()
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe validation error: %v", err)
	}
}

func TestWriteAssignmentRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.json")
	if err := os.WriteFile(target, []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(directory, "assignments.json")
	if err := os.Symlink(target, filename); err != nil {
		t.Fatal(err)
	}
	if err := WriteAssignment(filename, json.RawMessage(`{"schemaVersion":1}`)); err == nil {
		t.Fatal("accepted assignment symlink")
	}
}

func TestBindingCommitMarkersAreExclusiveStrictAndIndependent(t *testing.T) {
	directory := t.TempDir()
	websiteID := "550e8400-e29b-41d4-a716-446655440001"
	monitoringID := "550e8400-e29b-41d4-a716-446655440002"
	if err := BeginWebsiteCommit(directory, websiteID, 9); err != nil {
		t.Fatal(err)
	}
	if err := BeginMonitoringCommit(directory, monitoringID, 10); err != nil {
		t.Fatal(err)
	}
	website, found, err := ReadWebsiteCommit(directory)
	if err != nil || !found || website.BindingID != websiteID || website.CredentialEpoch != 9 {
		t.Fatalf("website marker=%#v found=%v err=%v", website, found, err)
	}
	monitoring, found, err := ReadMonitoringCommit(directory)
	if err != nil || !found || monitoring.BindingID != monitoringID || monitoring.CredentialEpoch != 10 {
		t.Fatalf("monitoring marker=%#v found=%v err=%v", monitoring, found, err)
	}
	if err := BeginWebsiteCommit(directory, monitoringID, 10); err == nil {
		t.Fatal("website marker was overwritten")
	}
	if err := BeginMonitoringCommit(directory, websiteID, 9); err == nil {
		t.Fatal("monitoring marker was overwritten")
	}
	// The rejected begin must leave the original strict identity unchanged.
	website, found, err = ReadWebsiteCommit(directory)
	if err != nil || !found || website.BindingID != websiteID || website.CredentialEpoch != 9 {
		t.Fatalf("website marker changed after rejected begin: %#v found=%v err=%v", website, found, err)
	}
	monitoring, found, err = ReadMonitoringCommit(directory)
	if err != nil || !found || monitoring.BindingID != monitoringID || monitoring.CredentialEpoch != 10 {
		t.Fatalf("monitoring marker changed after rejected begin: %#v found=%v err=%v", monitoring, found, err)
	}
	if pending, err := WebsiteCommitPending(directory); err != nil || !pending {
		t.Fatalf("website pending=%v err=%v", pending, err)
	}
	if pending, err := MonitoringCommitPending(directory); err != nil || !pending {
		t.Fatalf("monitoring pending=%v err=%v", pending, err)
	}
	if err := FinishWebsiteCommit(directory); err != nil {
		t.Fatal(err)
	}
	if pending, err := WebsiteCommitPending(directory); err != nil || pending {
		t.Fatalf("website pending after finish=%v err=%v", pending, err)
	}
	if pending, err := MonitoringCommitPending(directory); err != nil || !pending {
		t.Fatalf("monitoring marker was not independent: pending=%v err=%v", pending, err)
	}
	if err := FinishMonitoringCommit(directory); err != nil {
		t.Fatal(err)
	}
	if pending, err := MonitoringCommitPending(directory); err != nil || pending {
		t.Fatalf("monitoring pending after finish=%v err=%v", pending, err)
	}
	if err := BeginWebsiteCommit(directory, "not-a-uuid", 9); err == nil {
		t.Fatal("invalid commit marker identity was accepted")
	}

	// A malformed marker cannot be read or cleared. Leaving it behind is
	// intentional: startup must fail closed until an explicit recovery path
	// verifies the interrupted transaction.
	if err := os.WriteFile(monitoringCommitPath(directory), []byte(`{"schemaVersion":1,"bindingId":"550e8400-e29b-41d4-a716-446655440002","credentialEpoch":10,"unexpected":true}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadMonitoringCommit(directory); err == nil {
		t.Fatal("unknown marker field was accepted")
	}
	if err := BeginMonitoringCommit(directory, monitoringID, 11); err == nil {
		t.Fatal("malformed existing marker was overwritten")
	}
	if err := FinishMonitoringCommit(directory); err == nil {
		t.Fatal("malformed marker was cleared")
	}
	if _, err := os.Stat(monitoringCommitPath(directory)); err != nil {
		t.Fatalf("malformed marker was removed: %v", err)
	}
}
