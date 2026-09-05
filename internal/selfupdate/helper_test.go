package selfupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/bindstate"
	"github.com/ppflight/ppflight-agent/internal/control"
	"github.com/ppflight/ppflight-agent/internal/enrollment"
	"github.com/ppflight/ppflight-agent/internal/netpolicy"
	"github.com/ppflight/ppflight-agent/internal/protocol"
	"github.com/ppflight/ppflight-agent/internal/upgradecontract"
)

func TestStageCommandSigningRotationPersistsOnlyAuthorizedReplacement(t *testing.T) {
	directory := t.TempDir()
	secret := enrollment.Secret(base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")))
	credential := enrollment.HMACCredential{KeyID: "hmac-key-01", Secret: secret}
	state := bindstate.FromResponse("https://www.ppflight.com/api/pve-agent/v1/enrollments/redeem", "device-0123456789abcdef", enrollment.Response{
		SchemaVersion: enrollment.SchemaVersion, BindingID: "123e4567-e89b-42d3-a456-426614174001", DeviceID: "device-0123456789abcdef",
		AgentRef: "agent-01", CollectorRef: "collector-01", SourceRef: "source-01", ClusterRef: "cluster-01", NodeRef: "node-01", Site: "site-01",
		Endpoints:                enrollment.Endpoints{Metering: "https://www.ppflight.com/metering", Telemetry: "https://www.ppflight.com/telemetry", Assignments: "https://www.ppflight.com/assignments", Commands: "https://www.ppflight.com/commands", Receipts: "https://www.ppflight.com/receipts"},
		HMACCredentials:          enrollment.HMACCredentials{Metering: credential, Telemetry: credential, Assignments: credential, Commands: credential, Receipts: credential},
		CommandSigningCredential: enrollment.CommandSigningCredential{KeyID: "old-key-01", Algorithm: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32))},
		AllowedActions:           []string{"agent.upgrade"}, AssignmentDocument: json.RawMessage(`{"schemaVersion":1,"revision":"rev-01","issuedAt":"2026-08-30T00:00:00Z","assignments":[]}`),
		NetworkPolicy: netpolicy.NetworkPolicy{AgentObservedIPv4: "127.0.0.1"}, CredentialEpoch: 1, IssuedAt: time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC),
	})
	if err := bindstate.Save(directory, state); err != nil {
		t.Fatal(err)
	}
	rotation := upgradecontract.CommandSigningRotation{KeyID: "new-key-02", PublicKey: base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))}
	if _, err := stageCommandSigningRotation(directory, "wrong-key", rotation); err == nil {
		t.Fatal("rotation signed by a non-active key was accepted")
	}
	previous, err := stageCommandSigningRotation(directory, "old-key-01", rotation)
	if err != nil {
		t.Fatal(err)
	}
	current, err := bindstate.Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	if previous.CommandSigningCredential.KeyID != "old-key-01" || current.CommandSigningCredential.KeyID != "new-key-02" || current.CommandSigningCredential.PublicKey != rotation.PublicKey {
		t.Fatal("binding signing credential was not atomically rotated")
	}
}

func TestVerifiedBinaryRequiresInternalVersionAndChecksum(t *testing.T) {
	binary := []byte("verified linux binary")
	archive := buildArchive(t, binary, false)
	parameters := helperParameters(t, archive)
	got, err := verifiedBinary(archive, parameters)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(binary) {
		t.Fatal("wrong binary extracted")
	}
}

func TestVerifiedBinaryRejectsLinks(t *testing.T) {
	archive := buildArchive(t, []byte("binary"), true)
	if _, err := verifiedBinary(archive, helperParameters(t, archive)); err == nil {
		t.Fatal("archive link was accepted")
	}
}

func TestReleaseAllowlistIncludesCredentialRemovalHelper(t *testing.T) {
	if !allowedReleaseEntry("ppflight-agent/scripts/remove-pve-credentials.sh", false) {
		t.Fatal("release allowlist rejected the installed PVE credential removal helper")
	}
	if allowedReleaseEntry("ppflight-agent/scripts/remove-arbitrary-pve-data.sh", false) {
		t.Fatal("release allowlist accepted an unapproved removal helper")
	}
}

func TestRootHelperAcceptsEveryEntryProducedByReleasePackager(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	output := t.TempDir()
	command := exec.Command("/usr/bin/bash", "../../scripts/package-release.sh",
		"--binary", binary, "--version", "0.1.1-rc.999", "--arch", runtime.GOARCH, "--output-dir", output)
	if combined, err := command.CombinedOutput(); err != nil {
		t.Fatalf("package release: %v: %s", err, combined)
	}
	archive := filepath.Join(output, "ppflight-agent-0.1.1-rc.999-linux-"+runtime.GOARCH+".tar.gz")
	file, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		directory := header.Typeflag == tar.TypeDir
		if !allowedReleaseEntry(header.Name, directory) {
			t.Fatalf("release packager emitted entry rejected by root helper: %s", header.Name)
		}
	}
}

func TestHostFirewallPostflightCommandIsUniqueAndExact(t *testing.T) {
	name, first, err := hostFirewallPostflightCommand("upgrade-01")
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := hostFirewallPostflightCommand("upgrade-02")
	if err != nil {
		t.Fatal(err)
	}
	if name != "/usr/bin/systemd-run" {
		t.Fatalf("command=%q", name)
	}
	joinedFirst := strings.Join(first, "\n")
	joinedSecond := strings.Join(second, "\n")
	for _, required := range []string{
		"--wait", "--pipe", "--collect", "--no-ask-password",
		"--unit=ppflight-agent-upgrade-postflight-upgrade-01.service",
		"--property=User=root", "--property=TimeoutStartSec=50s",
		"--property=PartOf=ppflight-agent-upgrade.service",
		installedAgentBinary + "\nhost-firewall\nreconcile",
	} {
		if !strings.Contains(joinedFirst, required) {
			t.Fatalf("transient postflight command omitted %q: %v", required, first)
		}
	}
	if strings.Contains(joinedFirst, "After=ppflight-agent-upgrade.service") {
		t.Fatalf("transient child would deadlock its waiting parent: %v", first)
	}
	if joinedFirst == joinedSecond || !strings.Contains(joinedSecond, "--unit=ppflight-agent-upgrade-postflight-upgrade-02.service") {
		t.Fatalf("transient units are not unique: first=%v second=%v", first, second)
	}
	if _, _, err := hostFirewallPostflightCommand("../unsafe"); err == nil {
		t.Fatal("unsafe upgrade ID was accepted as a transient unit")
	}
}

func TestHelperBudgetsFitLegacyUpgradeUnit(t *testing.T) {
	if UpgradeHelperOverallTimeout+helperRollbackTimeout >= LegacyUpgradeUnitTimeout {
		t.Fatalf("overall %v + recovery %v must fit legacy unit %v", UpgradeHelperOverallTimeout, helperRollbackTimeout, LegacyUpgradeUnitTimeout)
	}
	if hostFirewallPreflightTimeout > 35*time.Second || hostFirewallPostflightTimeout > 60*time.Second || hostFirewallTransientTimeout > hostFirewallPostflightTimeout {
		t.Fatalf("unsafe phase budgets: preflight=%v postflight=%v transient=%v", hostFirewallPreflightTimeout, hostFirewallPostflightTimeout, hostFirewallTransientTimeout)
	}
}

func TestValidateHelperRequestStopsAuthorizationRetryOnContextCancellation(t *testing.T) {
	cfg, _, _ := helperPostflightFixture(t)
	requestPath, request, err := nextRequest(cfg.StateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	emptyJournal, err := control.OpenJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Journal = emptyJournal
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	if err := validateHelperRequest(ctx, requestPath, request, cfg); !errors.Is(err, context.Canceled) {
		t.Fatalf("validateHelperRequest error=%v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("authorization retry ignored cancellation for %v", elapsed)
	}
}

func TestHostFirewallPreflightCommandIsExact(t *testing.T) {
	candidate := "/var/lib/ppflight-agent/upgrades/preflight/upgrade-01.bin"
	name, args := hostFirewallPreflightCommand(candidate)
	if name != candidate || strings.Join(args, " ") != "host-firewall prepare" {
		t.Fatalf("preflight command=%q %v", name, args)
	}
}

func TestRunHelperPreflightFailureDoesNotMutateAgent(t *testing.T) {
	cfg, upgradeID, candidate := helperPostflightFixture(t)
	original, err := os.ReadFile(cfg.BinaryPath)
	if err != nil {
		t.Fatal(err)
	}
	systemctlCalls := 0
	cfg.RunSystemctl = func(context.Context, ...string) error {
		systemctlCalls++
		return nil
	}
	postflightCalls := 0
	cfg.RunHostFirewallPostflight = func(context.Context, string) error {
		postflightCalls++
		return nil
	}
	preflightCalls := 0
	cfg.RunHostFirewallPreflight = func(ctx context.Context, candidatePath string) error {
		preflightCalls++
		if _, ok := ctx.Deadline(); !ok || ctx.Err() != nil {
			t.Fatal("preflight did not receive a fresh live timeout")
		}
		info, statErr := os.Lstat(candidatePath)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o700 || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("unsafe staged candidate: info=%v err=%v", info, statErr)
		}
		got, readErr := os.ReadFile(candidatePath)
		if readErr != nil || !bytes.Equal(got, candidate) {
			t.Fatalf("wrong staged candidate: err=%v", readErr)
		}
		return errors.New("injected candidate preflight failure")
	}

	if err := RunHelper(context.Background(), cfg); err == nil {
		t.Fatal("RunHelper accepted failed candidate preflight")
	}
	if preflightCalls != 1 || systemctlCalls != 0 || postflightCalls != 0 {
		t.Fatalf("preflight=%d systemctl=%d postflight=%d", preflightCalls, systemctlCalls, postflightCalls)
	}
	installed, err := os.ReadFile(cfg.BinaryPath)
	if err != nil || !bytes.Equal(installed, original) {
		t.Fatalf("installed binary mutated after preflight failure: err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(cfg.StateDirectory, "upgrades", "backups", upgradeID+".bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backup proves install mutation occurred: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cfg.StateDirectory, "upgrades", "preflight", upgradeID+".bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged candidate was not removed: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(cfg.StateDirectory, "upgrades", "results", upgradeID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var result Result
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "failed" || result.Error == nil || result.Error.Stage != "host_firewall_preflight" {
		t.Fatalf("result=%+v", result)
	}
}

func TestRunHelperRequiresSuccessfulHostFirewallReconcile(t *testing.T) {
	for _, test := range []struct {
		name          string
		postflightErr error
		wantRunErr    bool
		wantStatus    string
		wantCode      string
		wantStage     string
	}{
		{name: "verified pass", wantStatus: "succeeded", wantCode: control.AgentUpgradeHostFirewallSuccessCode},
		{name: "reconcile failure", postflightErr: errors.New("injected reconcile failure"), wantRunErr: true, wantStatus: "failed", wantCode: "UPGRADE_HELPER_FAILED", wantStage: "host_firewall_reconcile"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg, upgradeID, candidate := helperPostflightFixture(t)
			systemctlCalls := 0
			cfg.RunSystemctl = func(_ context.Context, args ...string) error {
				systemctlCalls++
				if strings.Join(args, " ") != "restart ppflight-agent.service" {
					t.Fatalf("systemctl args=%v", args)
				}
				return nil
			}
			postflightCalls := 0
			cfg.RunHostFirewallPostflight = func(ctx context.Context, gotID string) error {
				postflightCalls++
				if gotID != upgradeID || systemctlCalls != 1 {
					t.Fatalf("postflight id=%q systemctlCalls=%d", gotID, systemctlCalls)
				}
				if _, ok := ctx.Deadline(); !ok || ctx.Err() != nil {
					t.Fatal("postflight did not receive a fresh live timeout")
				}
				return test.postflightErr
			}

			err := RunHelper(context.Background(), cfg)
			if (err != nil) != test.wantRunErr {
				t.Fatalf("RunHelper error=%v, wantErr=%t", err, test.wantRunErr)
			}
			if systemctlCalls != 1 || postflightCalls != 1 {
				t.Fatalf("systemctlCalls=%d postflightCalls=%d", systemctlCalls, postflightCalls)
			}
			installed, readErr := os.ReadFile(cfg.BinaryPath)
			if readErr != nil || !bytes.Equal(installed, candidate) {
				t.Fatalf("healthy candidate was rolled back after postflight: readErr=%v", readErr)
			}
			raw, readErr := os.ReadFile(filepath.Join(cfg.StateDirectory, "upgrades", "results", upgradeID+".json"))
			if readErr != nil {
				t.Fatal(readErr)
			}
			var result Result
			if err := json.Unmarshal(raw, &result); err != nil {
				t.Fatal(err)
			}
			if result.Status != test.wantStatus || result.Code != test.wantCode {
				t.Fatalf("result=%+v", result)
			}
			if test.wantStage == "" {
				if result.Error != nil {
					t.Fatalf("successful result has error=%+v", result.Error)
				}
			} else if result.Error == nil || result.Error.Stage != test.wantStage {
				t.Fatalf("failure result error=%+v", result.Error)
			}
		})
	}
}

func TestRunHelperRotationDoesNotStartBeforePostflightSucceeds(t *testing.T) {
	cfg, upgradeID, _ := helperPostflightFixtureWithRotation(t, true)
	activateRestart := cfg.RunSystemctl
	systemctlCalls := 0
	cfg.RunSystemctl = func(ctx context.Context, args ...string) error {
		systemctlCalls++
		return activateRestart(ctx, args...)
	}
	cfg.RunHostFirewallPostflight = func(context.Context, string) error {
		return errors.New("injected postflight failure before rotation")
	}
	if err := RunHelper(context.Background(), cfg); err == nil {
		t.Fatal("RunHelper accepted failed postflight")
	}
	state, err := bindstate.Load(cfg.StateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if state.CommandSigningCredential.KeyID != "old-key-01" || systemctlCalls != 1 {
		t.Fatalf("rotation escaped failed postflight: key=%q systemctl=%d", state.CommandSigningCredential.KeyID, systemctlCalls)
	}
	result := readHelperResult(t, cfg.StateDirectory, upgradeID)
	if result.Status != "failed" || result.Error == nil || result.Error.Stage != "host_firewall_reconcile" {
		t.Fatalf("result=%+v", result)
	}
}

func TestRunHelperSuccessResultFailureRestoresOldSigningKey(t *testing.T) {
	cfg, upgradeID, _ := helperPostflightFixtureWithRotation(t, true)
	activateRestart := cfg.RunSystemctl
	systemctlCalls := 0
	cfg.RunSystemctl = func(ctx context.Context, args ...string) error {
		systemctlCalls++
		return activateRestart(ctx, args...)
	}
	cfg.RunHostFirewallPostflight = func(context.Context, string) error { return nil }
	cfg.SaveResult = func(stateDirectory string, result Result) error {
		if result.Status == "succeeded" {
			return errors.New("injected durable success result failure")
		}
		return saveResult(stateDirectory, result)
	}
	if err := RunHelper(context.Background(), cfg); err == nil {
		t.Fatal("RunHelper accepted failed durable success result")
	}
	state, err := bindstate.Load(cfg.StateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if state.CommandSigningCredential.KeyID != "old-key-01" {
		t.Fatalf("new signing key survived failed success result: %q", state.CommandSigningCredential.KeyID)
	}
	if systemctlCalls != 3 {
		t.Fatalf("systemctlCalls=%d, want candidate, rotated-key, and restored-key restarts", systemctlCalls)
	}
	result := readHelperResult(t, cfg.StateDirectory, upgradeID)
	if result.Status != "failed" || result.Error == nil || result.Error.Stage != "save_success_result" {
		t.Fatalf("result=%+v", result)
	}
}

func TestRunHelperRollbackUsesFreshContextAfterHealthCancellation(t *testing.T) {
	cfg, upgradeID, _ := helperPostflightFixture(t)
	outer, cancelOuter := context.WithCancel(context.Background())
	systemctlCalls := 0
	cfg.RunSystemctl = func(ctx context.Context, _ ...string) error {
		systemctlCalls++
		if systemctlCalls == 1 {
			cancelOuter()
			return nil
		}
		if ctx.Err() != nil {
			t.Fatalf("rollback inherited canceled helper context: %v", ctx.Err())
		}
		return nil
	}
	cfg.RunHostFirewallPostflight = func(context.Context, string) error {
		t.Fatal("postflight ran after candidate health cancellation")
		return nil
	}
	if err := RunHelper(outer, cfg); err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("RunHelper error=%v", err)
	}
	if systemctlCalls != 2 {
		t.Fatalf("systemctlCalls=%d, want candidate restart and rollback restart", systemctlCalls)
	}
	raw, err := os.ReadFile(filepath.Join(cfg.StateDirectory, "upgrades", "results", upgradeID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var result Result
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "rolled_back" || result.Code != "AGENT_UPGRADE_ROLLED_BACK" {
		t.Fatalf("result=%+v", result)
	}
}

func TestRunHelperReportsFailedWhenRollbackFails(t *testing.T) {
	cfg, upgradeID, _ := helperPostflightFixture(t)
	outer, cancelOuter := context.WithCancel(context.Background())
	systemctlCalls := 0
	cfg.RunSystemctl = func(context.Context, ...string) error {
		systemctlCalls++
		if systemctlCalls == 1 {
			cancelOuter()
			return nil
		}
		return errors.New("injected rollback restart failure")
	}
	if err := RunHelper(outer, cfg); err == nil || !strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("RunHelper error=%v", err)
	}
	result := readHelperResult(t, cfg.StateDirectory, upgradeID)
	if result.Status != "failed" || result.Code != "UPGRADE_HELPER_FAILED" || result.Error == nil || result.Error.Stage != "rollback" {
		t.Fatalf("result=%+v", result)
	}
}

func readHelperResult(t *testing.T, stateDirectory, upgradeID string) Result {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(stateDirectory, "upgrades", "results", upgradeID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var result Result
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func helperPostflightFixture(t *testing.T) (HelperConfig, string, []byte) {
	return helperPostflightFixtureWithRotation(t, false)
}

func helperPostflightFixtureWithRotation(t *testing.T, rotate bool) (HelperConfig, string, []byte) {
	t.Helper()
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	stateDirectory := t.TempDir()
	candidate := make([]byte, 2<<20)
	if _, err := rand.Read(candidate); err != nil {
		t.Fatal(err)
	}
	archive := buildArchive(t, candidate, false)
	parameters := helperParameters(t, archive)
	if rotate {
		parameters.CommandSigningRotation = &upgradecontract.CommandSigningRotation{
			KeyID: "new-key-02", PublicKey: base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
		}
	}
	parameters.Artifact.DownloadURL = "https://www.example.com" + upgradecontract.ArtifactPath(parameters.ReleaseTag, runtime.GOARCH)
	manifest := upgradecontract.Manifest{
		SchemaVersion: upgradecontract.SchemaVersion, ReleaseTag: parameters.ReleaseTag, Version: parameters.ReleaseTag,
		AgentCommitSHA: parameters.AgentCommitSHA, InstallerCommitSHA: strings.Repeat("c", 64), Prerelease: true,
		PublishedAt: now, UpgradeDeliveryEnabled: true, Artifacts: []upgradecontract.Artifact{parameters.Artifact},
	}
	manifestServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != upgradecontract.CurrentManifestPath {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(manifest)
	}))
	t.Cleanup(manifestServer.Close)
	transport := manifestServer.Client().Transport.(*http.Transport).Clone()
	serverAddress := manifestServer.Listener.Addr().String()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, serverAddress)
	}
	httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	bindingID := "123e4567-e89b-42d3-a456-426614174001"
	deviceID := "device-01"
	credentialEpoch := uint64(7)
	if err := bindstate.Save(stateDirectory, helperBindingState(now, bindingID, deviceID, credentialEpoch, "old-key-01")); err != nil {
		t.Fatal(err)
	}
	var activeSigningKey atomic.Value
	activeSigningKey.Store("old-key-01")
	statusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"version":"0.1.0-rc.9","control":{"signingKeyId":%q},"bindings":{"website":{"bindingId":%q,"deviceId":%q,"credentialEpoch":%q}}}`,
			activeSigningKey.Load().(string), bindingID, deviceID, fmt.Sprint(credentialEpoch))
	}))
	t.Cleanup(statusServer.Close)

	parameterRaw, err := json.Marshal(parameters)
	if err != nil {
		t.Fatal(err)
	}
	command := control.Command{
		SchemaVersion: 1, CommandID: "command-upgrade-01", OperationID: "operation-upgrade-01", IdempotencyKey: "idempotency-upgrade-01",
		AgentRef: "agent-01", BindingID: bindingID, DeviceID: deviceID, CredentialEpoch: protocol.Counter(credentialEpoch), AssignmentRevision: 9,
		Scope: control.ScopeNode, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(5 * time.Minute),
		Identity: control.Identity{ClusterRef: "cluster-01", NodeRef: "pve1"}, Action: "agent.upgrade", Parameters: parameterRaw,
		OperatorRef: "operator-01", ApprovalRef: "approval-01", BodySHA256: protocol.BodyHash(parameterRaw),
		SigningKeyID: "old-key-01",
	}
	secret := []byte("helper-test-secret")
	command.Signature = control.SignCommand(command, secret)
	upgradeID := "upgrade-postflight-01"
	pendingDirectory := filepath.Join(stateDirectory, "upgrades", "pending")
	if err := os.MkdirAll(pendingDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	archiveRaw, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pendingDirectory, upgradeID+".tar.gz"), archiveRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	request := Request{
		SchemaVersion: requestSchema, UpgradeID: upgradeID, PreparedAt: now, CurrentVersion: "0.1.0-rc.9",
		ArtifactFile: upgradeID + ".tar.gz", ArtifactSHA256: parameters.Artifact.SHA256, ArtifactBytes: parameters.Artifact.SizeBytes,
		Command: command,
	}
	requestRaw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pendingDirectory, upgradeID+".request.json"), requestRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	journal, err := control.OpenJournal(filepath.Join(stateDirectory, "control", "journal"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := journal.Claim(command, now); err != nil {
		t.Fatal(err)
	}
	submitted := control.Receipt{
		SchemaVersion: 1, ReceiptID: "receipt-upgrade-01", CommandID: command.CommandID, OperationID: command.OperationID,
		AgentRef: command.AgentRef, State: "submitted", Code: "AGENT_UPGRADE_SUBMITTED", ExecutionMode: "test",
		StartedAt: now, FinishedAt: now, AgentUpgradeID: upgradeID, OperatorRef: command.OperatorRef,
	}
	if err := journal.Complete(command, submitted); err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(t.TempDir(), "ppflight-agent")
	if err := os.WriteFile(binaryPath, []byte("old-agent-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	verify := control.VerifyConfig{
		AgentRef: command.AgentRef, ClusterRef: command.Identity.ClusterRef, BindingID: bindingID, DeviceID: deviceID,
		CredentialEpoch: credentialEpoch, AssignmentRevision: func() uint64 { return 9 }, Mode: "test", Secret: secret,
		SigningKeyID: "old-key-01",
		Allowed:      control.AllowedSet([]string{"agent.upgrade"}), Now: now,
	}
	return HelperConfig{
		StateDirectory: stateDirectory, BinaryPath: binaryPath, ServiceName: "ppflight-agent.service", StatusURL: statusServer.URL,
		WebsiteEndpoint: "https://www.example.com/internal/v1/commands", CurrentVersion: "0.1.0-rc.9", Verify: verify,
		Journal: journal, HTTPClient: httpClient, Now: func() time.Time { return now },
		RunHostFirewallPreflight: func(context.Context, string) error { return nil },
		RunSystemctl: func(context.Context, ...string) error {
			state, err := bindstate.Load(stateDirectory)
			if err == nil {
				activeSigningKey.Store(state.CommandSigningCredential.KeyID)
			}
			return err
		},
	}, upgradeID, candidate
}

func helperBindingState(now time.Time, bindingID, deviceID string, credentialEpoch uint64, signingKeyID string) bindstate.State {
	secret := enrollment.Secret(base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")))
	credential := enrollment.HMACCredential{KeyID: "hmac-key-01", Secret: secret}
	return bindstate.FromResponse("https://www.example.com/api/pve-agent/v1/enrollments/redeem", deviceID, enrollment.Response{
		SchemaVersion: enrollment.SchemaVersion, BindingID: bindingID, DeviceID: deviceID,
		AgentRef: "agent-01", CollectorRef: "collector-01", SourceRef: "source-01", ClusterRef: "cluster-01", NodeRef: "pve1", Site: "site-01",
		Endpoints:                enrollment.Endpoints{Metering: "https://www.example.com/metering", Telemetry: "https://www.example.com/telemetry", Assignments: "https://www.example.com/assignments", Commands: "https://www.example.com/commands", Receipts: "https://www.example.com/receipts"},
		HMACCredentials:          enrollment.HMACCredentials{Metering: credential, Telemetry: credential, Assignments: credential, Commands: credential, Receipts: credential},
		CommandSigningCredential: enrollment.CommandSigningCredential{KeyID: signingKeyID, Algorithm: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32))},
		AllowedActions:           []string{"agent.upgrade"}, AssignmentDocument: json.RawMessage(`{"schemaVersion":1,"revision":"rev-01","issuedAt":"2026-08-30T00:00:00Z","assignments":[]}`),
		NetworkPolicy: netpolicy.NetworkPolicy{AgentObservedIPv4: "127.0.0.1"}, CredentialEpoch: credentialEpoch, IssuedAt: now,
	})
}

func buildArchive(t *testing.T, binary []byte, link bool) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "release.tar.gz")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(file)
	tw := tar.NewWriter(gz)
	write := func(name string, body []byte) {
		t.Helper()
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	write("ppflight-agent/ppflight-agent", binary)
	sum := sha256.Sum256(binary)
	write("ppflight-agent/ppflight-agent.sha256", []byte(hex.EncodeToString(sum[:])+"  ppflight-agent\n"))
	write("ppflight-agent/VERSION", []byte("0.1.0-rc.9\n"))
	if link {
		if err := tw.WriteHeader(&tar.Header{Name: "ppflight-agent/evil", Typeflag: tar.TypeSymlink, Linkname: "/etc/shadow"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func helperParameters(t *testing.T, archive string) upgradecontract.Parameters {
	t.Helper()
	body, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	arch := runtime.GOARCH
	return upgradecontract.Parameters{SchemaVersion: 1, ReleaseTag: "v0.1.0-rc.9", AgentCommitSHA: fmt.Sprintf("%064x", 1), Artifact: upgradecontract.Artifact{Architecture: arch, AssetName: "ppflight-agent-0.1.0-rc.9-linux-" + arch + ".tar.gz", SizeBytes: fmt.Sprint(len(body)), SHA256: hex.EncodeToString(sum[:]), DownloadURL: "https://www.ppflight.com" + upgradecontract.ArtifactPath("v0.1.0-rc.9", arch)}}
}
