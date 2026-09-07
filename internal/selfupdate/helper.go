package selfupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ppflight/ppflight-agent/internal/bindstate"
	"github.com/ppflight/ppflight-agent/internal/control"
	"github.com/ppflight/ppflight-agent/internal/enrollment"
	"github.com/ppflight/ppflight-agent/internal/fsutil"
	"github.com/ppflight/ppflight-agent/internal/upgradecontract"
)

type HelperConfig struct {
	StateDirectory            string
	BinaryPath                string
	ServiceName               string
	StatusURL                 string
	WebsiteEndpoint           string
	CurrentVersion            string
	Verify                    control.VerifyConfig
	Journal                   *control.Journal
	HTTPClient                *http.Client
	Now                       func() time.Time
	RunSystemctl              func(context.Context, ...string) error
	RunHostFirewallPreflight  func(context.Context, string) error
	RunHostFirewallPostflight func(context.Context, string) error
	SaveResult                func(string, Result) error
	ValidateUpgradeRoot       func(string) error
}

const (
	// UpgradeHelperOverallTimeout plus the independent recovery budget stays
	// below the 180s TimeoutStartSec shipped by the already-installed v0.1.5 unit.
	LegacyUpgradeUnitTimeout      = 180 * time.Second
	UpgradeHelperOverallTimeout   = 140 * time.Second
	hostFirewallPreflightTimeout  = 30 * time.Second
	hostFirewallPostflightTimeout = 115 * time.Second
	hostFirewallTransientTimeout  = 110 * time.Second
	helperRollbackTimeout         = 30 * time.Second
	installedAgentBinary          = "/usr/local/bin/ppflight-agent"
	maxHelperDiagnosticBytes      = 512
	helperDiagnosticHeadBytes     = 160
)

var transientUpgradeIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$`)

type statusBinding struct {
	BindingID       string `json:"bindingId"`
	DeviceID        string `json:"deviceId"`
	CredentialEpoch string `json:"credentialEpoch"`
}

type localStatus struct {
	Version string `json:"version"`
	Control struct {
		SigningKeyID string `json:"signingKeyId"`
	} `json:"control"`
	Bindings struct {
		Website statusBinding `json:"website"`
	} `json:"bindings"`
}

func RunHelper(ctx context.Context, cfg HelperConfig) error {
	ctx, cancel := context.WithTimeout(ctx, UpgradeHelperOverallTimeout)
	defer cancel()
	if cfg.Journal == nil || cfg.StateDirectory == "" || cfg.BinaryPath == "" || cfg.WebsiteEndpoint == "" || cfg.StatusURL == "" {
		return errors.New("upgrade helper configuration is incomplete")
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = "ppflight-agent.service"
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.RunSystemctl == nil {
		cfg.RunSystemctl = func(ctx context.Context, args ...string) error {
			command := exec.CommandContext(ctx, "/usr/bin/systemctl", args...)
			command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
			output, err := command.CombinedOutput()
			if err != nil {
				return fmt.Errorf("systemctl failed: %s", safeHelperText(output))
			}
			return nil
		}
	}
	if cfg.RunHostFirewallPostflight == nil {
		cfg.RunHostFirewallPostflight = runHostFirewallPostflight
	}
	if cfg.RunHostFirewallPreflight == nil {
		cfg.RunHostFirewallPreflight = runHostFirewallPreflight
	}
	if cfg.SaveResult == nil {
		cfg.SaveResult = saveResult
	}
	if cfg.ValidateUpgradeRoot == nil {
		cfg.ValidateUpgradeRoot = validateUpgradeRoot
	}
	coordinator, err := New(Config{StateDirectory: cfg.StateDirectory, WebsiteEndpoint: cfg.WebsiteEndpoint, CurrentVersion: cfg.CurrentVersion, HTTPClient: cfg.HTTPClient, Now: cfg.Now})
	if err != nil {
		return err
	}
	if err := cfg.ValidateUpgradeRoot(filepath.Join(cfg.StateDirectory, "upgrades")); err != nil {
		return err
	}
	requestPath, request, err := nextRequest(cfg.StateDirectory)
	if err != nil {
		return err
	}
	slog.Info("agent upgrade root helper started", "upgradeId", request.UpgradeID, "operationId", request.Command.OperationID)
	result := Result{SchemaVersion: requestSchema, UpgradeID: request.UpgradeID, Status: "failed", Code: "UPGRADE_HELPER_FAILED", FinishedAt: cfg.Now().UTC()}
	writeResult := func() {
		result.FinishedAt = cfg.Now().UTC()
		if cfg.SaveResult(cfg.StateDirectory, result) == nil {
			if request.ArtifactFile == request.UpgradeID+".tar.gz" && filepath.Base(request.ArtifactFile) == request.ArtifactFile {
				_ = os.Remove(filepath.Join(filepath.Dir(requestPath), request.ArtifactFile))
			}
			if strings.TrimSuffix(filepath.Base(requestPath), ".request.json") == request.UpgradeID {
				_ = os.Remove(requestPath)
			}
		}
	}
	fail := func(stage string, cause error) error {
		result.Status, result.Code, result.Version = "failed", "UPGRADE_HELPER_FAILED", ""
		result.Error = &control.ExecutionError{Source: "agent", Stage: stage, Reason: safeHelperText([]byte(cause.Error()))}
		slog.Error("agent upgrade root helper failed", "upgradeId", request.UpgradeID, "stage", stage, "reason", result.Error.Reason)
		writeResult()
		return cause
	}
	if err := validateHelperRequest(ctx, requestPath, request, cfg); err != nil {
		return fail("validate_request", err)
	}
	parameters, _ := upgradecontract.DecodeParameters(request.Command.Parameters)
	manifestURL, _ := upgradecontract.ManifestURL(cfg.WebsiteEndpoint)
	body, err := coordinator.getExact(ctx, manifestURL, 1<<20)
	if err != nil {
		return fail("fetch_manifest", err)
	}
	manifest, err := upgradecontract.DecodeManifest(body)
	if err != nil {
		return fail("decode_manifest", err)
	}
	if err := manifest.Match(parameters); err != nil {
		return fail("match_manifest", err)
	}
	if err := validateUpgradeTransition(cfg.CurrentVersion, parameters.ReleaseTag); err != nil {
		return fail("validate_version_transition", err)
	}
	slog.Info("agent upgrade root helper reverified authority", "upgradeId", request.UpgradeID, "releaseTag", parameters.ReleaseTag)
	if err := upgradecontract.SameOrigin(cfg.WebsiteEndpoint, parameters.Artifact.DownloadURL); err != nil {
		return fail("verify_origin", err)
	}
	archivePath := filepath.Join(filepath.Dir(requestPath), request.ArtifactFile)
	binary, err := verifiedBinary(archivePath, parameters)
	if err != nil {
		return fail("verify_archive", err)
	}
	slog.Info("agent upgrade root helper verified archive", "upgradeId", request.UpgradeID, "sha256", parameters.Artifact.SHA256)
	if err := candidateHostFirewallPreflight(ctx, cfg, request.UpgradeID, binary); err != nil {
		return fail("host_firewall_preflight", err)
	}
	slog.Info("agent upgrade candidate host firewall preflight passed", "upgradeId", request.UpgradeID)
	backupPath, err := installCandidate(cfg.BinaryPath, cfg.StateDirectory, request.UpgradeID, binary)
	if err != nil {
		return fail("install_candidate", err)
	}
	slog.Info("agent upgrade candidate installed atomically", "upgradeId", request.UpgradeID, "releaseTag", parameters.ReleaseTag)
	rollback := func(cause error) error {
		slog.Error("agent upgrade health check failed; rollback started", "upgradeId", request.UpgradeID, "reason", safeHelperText([]byte(cause.Error())))
		rollbackContext, rollbackCancel := context.WithTimeout(context.Background(), helperRollbackTimeout)
		defer rollbackCancel()
		rollbackErr := restoreBackup(cfg.BinaryPath, backupPath)
		if rollbackErr == nil {
			rollbackErr = cfg.RunSystemctl(rollbackContext, "restart", cfg.ServiceName)
		}
		if rollbackErr == nil {
			// v0.1.5 does not expose the active signing key in /status.
			rollbackErr = waitForStatus(rollbackContext, cfg, cfg.CurrentVersion, "")
		}
		if rollbackErr != nil {
			result.Status, result.Code = "failed", "UPGRADE_HELPER_FAILED"
			result.Error = &control.ExecutionError{Source: "agent", Stage: "rollback", Reason: safeHelperText([]byte(fmt.Sprintf("upgrade failed (%v); rollback failed (%v)", cause, rollbackErr)))}
		} else {
			result.Status, result.Code = "rolled_back", "AGENT_UPGRADE_ROLLED_BACK"
			result.Error = &control.ExecutionError{Source: "agent", Stage: "restart_health_check", Reason: safeHelperText([]byte(cause.Error()))}
		}
		writeResult()
		slog.Warn("agent upgrade rollback completed", "upgradeId", request.UpgradeID, "rollbackSucceeded", rollbackErr == nil)
		if rollbackErr != nil {
			return fmt.Errorf("upgrade failed (%v) and rollback failed (%v)", cause, rollbackErr)
		}
		return fmt.Errorf("upgrade failed and was rolled back: %w", cause)
	}
	if err := cfg.RunSystemctl(ctx, "restart", cfg.ServiceName); err != nil {
		return rollback(err)
	}
	targetVersion := strings.TrimPrefix(parameters.ReleaseTag, "v")
	if err := waitForStatus(ctx, cfg, targetVersion, request.Command.SigningKeyID); err != nil {
		return rollback(err)
	}
	slog.Info("agent upgrade health check passed", "upgradeId", request.UpgradeID, "version", targetVersion)
	postflightContext, postflightCancel := context.WithTimeout(ctx, hostFirewallPostflightTimeout)
	postflightErr := cfg.RunHostFirewallPostflight(postflightContext, request.UpgradeID)
	postflightCancel()
	if postflightErr != nil {
		return fail("host_firewall_reconcile", postflightErr)
	}
	slog.Info("agent upgrade host firewall postflight passed", "upgradeId", request.UpgradeID)
	var previousBinding *bindstate.State
	if rotation := parameters.CommandSigningRotation; rotation != nil {
		previousBinding, err = stageCommandSigningRotation(cfg.StateDirectory, request.Command.SigningKeyID, *rotation)
		if err != nil {
			return fail("rotate_command_key", err)
		}
		recoverRotation := func(stage string, cause error) error {
			recoveryErr := restoreSigningRotation(cfg, *previousBinding, targetVersion)
			if recoveryErr != nil {
				return fail("rotate_command_key_recovery", fmt.Errorf("%s failed (%v); old signing key recovery failed (%v)", stage, cause, recoveryErr))
			}
			return fail(stage, cause)
		}
		if err := cfg.RunSystemctl(ctx, "restart", cfg.ServiceName); err != nil {
			return recoverRotation("rotate_command_key_restart", err)
		}
		if err := waitForStatus(ctx, cfg, targetVersion, rotation.KeyID); err != nil {
			return recoverRotation("rotate_command_key_health_check", err)
		}
		slog.Info("agent command signing public key rotated and activated", "upgradeId", request.UpgradeID, "keyId", rotation.KeyID)
	}
	result.Status, result.Code, result.Version = "succeeded", control.AgentUpgradeHostFirewallSuccessCode, targetVersion
	result.FinishedAt = cfg.Now().UTC()
	if err := cfg.SaveResult(cfg.StateDirectory, result); err != nil {
		if previousBinding != nil {
			if recoveryErr := restoreSigningRotation(cfg, *previousBinding, targetVersion); recoveryErr != nil {
				return fail("rotate_command_key_recovery", fmt.Errorf("save success result failed (%v); old signing key recovery failed (%v)", err, recoveryErr))
			}
		}
		return fail("save_success_result", err)
	}
	_ = os.Remove(filepath.Join(filepath.Dir(requestPath), request.ArtifactFile))
	_ = os.Remove(requestPath)
	slog.Info("agent upgrade completed", "upgradeId", request.UpgradeID, "version", targetVersion)
	return nil
}

// candidateHostFirewallPreflight durably stages the already verified candidate
// in a root-only directory, runs its read-only firewall validation, and removes
// it before any installed binary, service, or signing state can be mutated.
func candidateHostFirewallPreflight(ctx context.Context, cfg HelperConfig, upgradeID string, binary []byte) error {
	preflightDirectory, err := fsutil.EnsureControlledSubdirectory(filepath.Join(cfg.StateDirectory, "upgrades"), "preflight", 0o700)
	if err != nil {
		return err
	}
	candidatePath := filepath.Join(preflightDirectory, upgradeID+".bin")
	if err := fsutil.AtomicWriteFile(candidatePath, binary, 0o700, false); err != nil {
		return fmt.Errorf("stage candidate firewall preflight: %w", err)
	}
	preflightContext, preflightCancel := context.WithTimeout(ctx, hostFirewallPreflightTimeout)
	preflightErr := cfg.RunHostFirewallPreflight(preflightContext, candidatePath)
	preflightCancel()
	removeErr := os.Remove(candidatePath)
	if removeErr == nil {
		directory, openErr := os.Open(preflightDirectory)
		if openErr != nil {
			removeErr = openErr
		} else {
			removeErr = directory.Sync()
			_ = directory.Close()
		}
	}
	if preflightErr != nil {
		if removeErr != nil {
			return fmt.Errorf("candidate firewall preflight failed (%v); cleanup failed (%v)", preflightErr, removeErr)
		}
		return preflightErr
	}
	if removeErr != nil {
		return fmt.Errorf("clean up candidate firewall preflight: %w", removeErr)
	}
	return nil
}

func runHostFirewallPreflight(ctx context.Context, candidatePath string) error {
	name, args := hostFirewallPreflightCommand(candidatePath)
	command := exec.CommandContext(ctx, name, args...)
	command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	output, err := command.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("host firewall candidate preflight timed out: %w", ctx.Err())
		}
		return fmt.Errorf("host firewall candidate preflight failed: %s", safeHelperText(output))
	}
	return nil
}

func hostFirewallPreflightCommand(candidatePath string) (string, []string) {
	return candidatePath, []string{"host-firewall", "prepare"}
}

// runHostFirewallPostflight asks PID 1 to create one uniquely named, collected
// root worker. This escapes the downloader/helper mount sandbox without
// widening it and makes the exact candidate binary and fixed reconcile action
// the only privileged payload.
func runHostFirewallPostflight(ctx context.Context, upgradeID string) error {
	name, args, err := hostFirewallPostflightCommand(upgradeID)
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, name, args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	output, err := command.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("host firewall transient worker timed out: %w", ctx.Err())
		}
		return fmt.Errorf("host firewall transient worker failed: %s", safeHelperText(output))
	}
	return nil
}

func hostFirewallPostflightCommand(upgradeID string) (string, []string, error) {
	if !transientUpgradeIDRE.MatchString(upgradeID) {
		return "", nil, errors.New("upgrade ID is unsafe for a transient unit")
	}
	unit := "ppflight-agent-upgrade-postflight-" + upgradeID + ".service"
	args := []string{
		"--quiet", "--wait", "--pipe", "--collect", "--no-ask-password",
		"--unit=" + unit,
		"--service-type=oneshot",
		"--property=User=root",
		"--property=Group=root",
		"--property=UMask=0077",
		"--property=NoNewPrivileges=yes",
		"--property=PrivateTmp=yes",
		"--property=ProtectHome=yes",
		"--property=ProtectSystem=no",
		"--property=RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6",
		"--property=SystemCallArchitectures=native",
		"--property=LockPersonality=yes",
		"--property=RestrictRealtime=yes",
		"--property=KillMode=mixed",
		"--property=TimeoutStartSec=" + strconv.FormatInt(int64(hostFirewallTransientTimeout/time.Second), 10) + "s",
		// PartOf propagates an explicit stop/restart of the parent upgrade unit.
		// Do not add After: the parent oneshot waits for this transient unit.
		"--property=PartOf=ppflight-agent-upgrade.service",
		"--setenv=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		installedAgentBinary, "host-firewall", "reconcile",
	}
	return "/usr/bin/systemd-run", args, nil
}

func stageCommandSigningRotation(stateDirectory, authorityKeyID string, rotation upgradecontract.CommandSigningRotation) (*bindstate.State, error) {
	state, err := bindstate.Load(stateDirectory)
	if err != nil {
		return nil, err
	}
	if state.CommandSigningCredential.KeyID != authorityKeyID {
		return nil, errors.New("active command signing key does not match signed rotation authority")
	}
	decoded, err := base64.StdEncoding.DecodeString(rotation.PublicKey)
	if err != nil || len(decoded) != 32 {
		return nil, errors.New("replacement command signing key is invalid")
	}
	previous := state
	state.CommandSigningCredential = enrollment.CommandSigningCredential{KeyID: rotation.KeyID, Algorithm: "ed25519", PublicKey: rotation.PublicKey}
	if err := bindstate.Save(stateDirectory, state); err != nil {
		return nil, err
	}
	return &previous, nil
}

func restoreSigningRotation(cfg HelperConfig, previous bindstate.State, version string) error {
	recoveryContext, recoveryCancel := context.WithTimeout(context.Background(), helperRollbackTimeout)
	defer recoveryCancel()
	if err := bindstate.Save(cfg.StateDirectory, previous); err != nil {
		return fmt.Errorf("restore old signing binding: %w", err)
	}
	if err := cfg.RunSystemctl(recoveryContext, "restart", cfg.ServiceName); err != nil {
		return fmt.Errorf("restart with old signing binding: %w", err)
	}
	if err := waitForStatus(recoveryContext, cfg, version, previous.CommandSigningCredential.KeyID); err != nil {
		return fmt.Errorf("verify old signing binding: %w", err)
	}
	return nil
}

func nextRequest(stateDirectory string) (string, Request, error) {
	directory := filepath.Join(stateDirectory, "upgrades", "pending")
	entries, err := os.ReadDir(directory)
	if err != nil {
		return "", Request{}, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".request.json") {
			continue
		}
		upgradeID := strings.TrimSuffix(entry.Name(), ".request.json")
		if _, err := os.Stat(filepath.Join(stateDirectory, "upgrades", "results", upgradeID+".json")); err == nil {
			_ = os.Remove(filepath.Join(directory, upgradeID+".tar.gz"))
			_ = os.Remove(filepath.Join(directory, entry.Name()))
			continue
		}
		path := filepath.Join(directory, entry.Name())
		body, err := os.ReadFile(path)
		if err != nil || len(body) == 0 || len(body) > 2<<20 {
			return "", Request{}, errors.New("upgrade request is unreadable")
		}
		var request Request
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&request) != nil {
			return "", Request{}, errors.New("upgrade request JSON is invalid")
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			return "", Request{}, errors.New("upgrade request JSON has trailing data")
		}
		if request.UpgradeID != upgradeID {
			return "", Request{}, errors.New("upgrade request ID does not match its filename")
		}
		return path, request, nil
	}
	return "", Request{}, os.ErrNotExist
}

func validateHelperRequest(ctx context.Context, requestPath string, request Request, cfg HelperConfig) error {
	if request.SchemaVersion != requestSchema || request.UpgradeID == "" || filepath.Base(request.UpgradeID) != request.UpgradeID || filepath.Base(request.ArtifactFile) != request.ArtifactFile || request.ArtifactFile != request.UpgradeID+".tar.gz" || request.PreparedAt.IsZero() {
		return errors.New("upgrade request identity is invalid")
	}
	parameters, err := upgradecontract.DecodeParameters(request.Command.Parameters)
	if err != nil {
		return err
	}
	if request.ArtifactSHA256 != parameters.Artifact.SHA256 || request.ArtifactBytes != parameters.Artifact.SizeBytes {
		return errors.New("upgrade request artifact does not match its signed command")
	}
	verify := cfg.Verify
	verify.Now = cfg.Now().UTC()
	if err := control.Verify(request.Command, verify); err != nil {
		return fmt.Errorf("upgrade command re-verification failed: %w", err)
	}
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	retry := time.NewTicker(100 * time.Millisecond)
	defer retry.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		err = cfg.Journal.AuthorizeUpgrade(request.Command.CommandID, control.Digest(request.Command), request.UpgradeID)
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return errors.New("upgrade journal handoff was not durably submitted")
		case <-retry.C:
		}
	}
}

func verifiedBinary(archivePath string, parameters upgradecontract.Parameters) ([]byte, error) {
	file, err := openNoFollow(archivePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("staged artifact is not a regular file")
	}
	want, _ := strconv.ParseInt(parameters.Artifact.SizeBytes, 10, 64)
	if info.Size() != want {
		return nil, errors.New("staged artifact size changed")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil || hex.EncodeToString(hash.Sum(nil)) != parameters.Artifact.SHA256 {
		return nil, errors.New("staged artifact hash changed")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return nil, err
	}
	defer gzipReader.Close()
	targetVersion := strings.TrimPrefix(parameters.ReleaseTag, "v")
	root := "ppflight-agent"
	var binary, checksum, version []byte
	reader := tar.NewReader(gzipReader)
	entries := 0
	var expandedBytes int64
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		entries++
		if entries > 512 || header.Name == "" || strings.Contains(header.Name, "\\") || filepath.IsAbs(header.Name) || strings.Contains("/"+header.Name+"/", "/../") {
			return nil, errors.New("release archive path is unsafe")
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeDir {
			return nil, errors.New("release archive contains a link or special file")
		}
		if header.Uid != 0 || header.Gid != 0 || header.Mode&^0o777 != 0 || !allowedReleaseEntry(header.Name, header.Typeflag == tar.TypeDir) {
			return nil, errors.New("release archive contains an unreviewed entry")
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		expandedBytes += header.Size
		if header.Size < 0 || expandedBytes > 256<<20 {
			return nil, errors.New("release archive expands beyond its limit")
		}
		var destination *[]byte
		switch header.Name {
		case root + "/ppflight-agent":
			destination = &binary
		case root + "/ppflight-agent.sha256":
			destination = &checksum
		case root + "/VERSION":
			destination = &version
		default:
			continue
		}
		if len(*destination) != 0 || header.Size < 1 || header.Size > 64<<20 {
			return nil, errors.New("release archive contains an invalid duplicate")
		}
		*destination, err = io.ReadAll(io.LimitReader(reader, header.Size+1))
		if err != nil || int64(len(*destination)) != header.Size {
			return nil, errors.New("release archive entry is truncated")
		}
	}
	if strings.TrimSpace(string(version)) != targetVersion || len(binary) == 0 {
		return nil, errors.New("release archive version is invalid")
	}
	fields := strings.Fields(string(checksum))
	if len(fields) != 2 || fields[1] != "ppflight-agent" {
		return nil, errors.New("release binary checksum file is invalid")
	}
	sum := sha256.Sum256(binary)
	if fields[0] != hex.EncodeToString(sum[:]) {
		return nil, errors.New("release binary checksum mismatch")
	}
	return binary, nil
}

var releaseFileAllowlist = map[string]bool{
	"ppflight-agent": true, "ppflight-agent.sha256": true, "VERSION": true, "README.md": true,
	"config/README.md": true, "config/agent.env.example": true, "config/agent.example.yaml": true, "config/assignments.example.yaml": true,
	"docs/AGENT-API-V1.md": true, "docs/API.md": true, "docs/CONTRACT-REVIEW.md": true, "docs/INSTALL.md": true, "docs/SELF-UPGRADE-V1.md": true,
	"docs/MONITORING-NETWORK-PROJECTION-V1.md": true,
	"packaging/systemd/ppflight-agent.service": true, "packaging/systemd/ppflight-agent-upgrade.path": true, "packaging/systemd/ppflight-agent-upgrade.service": true,
	"packaging/systemd/ppflight-host-firewall.service": true,
	"packaging/systemd/ppflight-node-exporter.service": true, "packaging/systemd/ppflight-smartctl-exporter.service": true, "packaging/tmpfiles.d/ppflight-agent.conf": true,
	"scripts/install.sh": true, "scripts/quick-install.sh": true, "scripts/uninstall.sh": true, "scripts/create-pve-tokens.sh": true, "scripts/remove-pve-credentials.sh": true, "scripts/migrate-legacy-template-timezone.py": true, "scripts/verify-template-bundle.py": true,
	"bundles/ppflight-cloudinit/agent-vendor-manifest.v1.json": true, "bundles/ppflight-cloudinit/build-cloud-templates.sh": true,
	"bundles/ppflight-cloudinit/tools/ppflight-template-bootstrap.py": true,
	"bundles/ppflight-cloudinit/catalog/template-catalog.v1.json":     true, "bundles/ppflight-cloudinit/catalog/template-catalog.schema.json": true,
	"bundles/ppflight-cloudinit/contracts/template-bootstrap-request.schema.json": true, "bundles/ppflight-cloudinit/contracts/template-bootstrap-result.schema.json": true,
	"bundles/ppflight-cloudinit/contracts/template-storage-discovery.schema.json": true, "bundles/ppflight-cloudinit/contracts/agent-vendor-manifest.schema.json": true,
}

func allowedReleaseEntry(name string, directory bool) bool {
	const root = "ppflight-agent"
	clean := strings.TrimSuffix(name, "/")
	if clean == root {
		return directory
	}
	if !strings.HasPrefix(clean, root+"/") {
		return false
	}
	relative := strings.TrimPrefix(clean, root+"/")
	if !directory {
		return releaseFileAllowlist[relative]
	}
	prefix := relative + "/"
	for file := range releaseFileAllowlist {
		if strings.HasPrefix(file, prefix) {
			return true
		}
	}
	return false
}

func installCandidate(binaryPath, stateDirectory, upgradeID string, binary []byte) (string, error) {
	info, err := os.Lstat(binaryPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("installed agent binary path is unsafe")
	}
	current, err := os.ReadFile(binaryPath)
	if err != nil {
		return "", err
	}
	backupDirectory := filepath.Join(stateDirectory, "upgrades", "backups")
	if err := fsutil.EnsurePrivateDirectory(backupDirectory); err != nil {
		return "", err
	}
	backupPath := filepath.Join(backupDirectory, upgradeID+".bin")
	if info, statErr := os.Lstat(backupPath); errors.Is(statErr, os.ErrNotExist) {
		if err := fsutil.AtomicWriteFile(backupPath, current, 0o600, false); err != nil {
			return "", err
		}
	} else if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("upgrade backup path is unsafe")
	}
	if err := replaceBinary(binaryPath, binary); err != nil {
		if rollbackErr := restoreBackup(binaryPath, backupPath); rollbackErr != nil {
			return "", fmt.Errorf("candidate installation failed (%v) and local restore failed (%v)", err, rollbackErr)
		}
		return "", err
	}
	return backupPath, nil
}

func restoreBackup(binaryPath, backupPath string) error {
	backup, err := os.ReadFile(backupPath)
	if err != nil {
		return err
	}
	return replaceBinary(binaryPath, backup)
}

func replaceBinary(binaryPath string, binary []byte) error {
	directory := filepath.Dir(binaryPath)
	temp, err := os.CreateTemp(directory, ".ppflight-agent-upgrade-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o755); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(binary); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, binaryPath); err != nil {
		return err
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryHandle.Close()
	return directoryHandle.Sync()
}

func waitForStatus(ctx context.Context, cfg HelperConfig, version, signingKeyID string) error {
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, cfg.StatusURL, nil)
		response, err := client.Do(request)
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10))
			response.Body.Close()
			var status localStatus
			if readErr == nil && response.StatusCode == http.StatusOK && json.Unmarshal(body, &status) == nil && status.Version == version && status.Bindings.Website.BindingID == cfg.Verify.BindingID && status.Bindings.Website.DeviceID == cfg.Verify.DeviceID && status.Bindings.Website.CredentialEpoch == strconv.FormatUint(cfg.Verify.CredentialEpoch, 10) && (signingKeyID == "" || status.Control.SigningKeyID == signingKeyID) {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return errors.New("restarted agent did not pass version and binding verification")
}

func saveResult(stateDirectory string, result Result) error {
	if result.UpgradeID == "" || filepath.Base(result.UpgradeID) != result.UpgradeID {
		return errors.New("upgrade result ID is invalid")
	}
	directory := filepath.Join(stateDirectory, "upgrades", "results")
	if err := fsutil.EnsurePrivateDirectory(directory); err != nil {
		return err
	}
	payload, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return fsutil.AtomicWriteFile(filepath.Join(directory, result.UpgradeID+".json"), payload, 0o600, false)
}

func safeHelperText(value []byte) string {
	// Helper subprocesses emit controlled progress before their terminal
	// diagnostic. Preserve both ends: retaining only the first bytes hid the
	// actual systemd/UFW failure behind INFO lines on slower PVE hosts.
	clean := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, string(value))
	text := strings.Join(strings.Fields(clean), " ")
	if len(text) <= maxHelperDiagnosticBytes {
		return text
	}
	const separator = " ... "
	head := utf8SafePrefix(text, helperDiagnosticHeadBytes)
	tail := utf8SafeSuffix(text, maxHelperDiagnosticBytes-len(head)-len(separator))

	return head + separator + tail
}

func utf8SafePrefix(value string, maximumBytes int) string {
	if len(value) <= maximumBytes {
		return value
	}
	end := maximumBytes
	for end > 0 && !utf8.ValidString(value[:end]) {
		end--
	}

	return value[:end]
}

func utf8SafeSuffix(value string, maximumBytes int) string {
	if len(value) <= maximumBytes {
		return value
	}
	start := len(value) - maximumBytes
	for start < len(value) && !utf8.ValidString(value[start:]) {
		start++
	}

	return value[start:]
}
