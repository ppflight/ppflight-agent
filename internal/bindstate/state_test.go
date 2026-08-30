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
