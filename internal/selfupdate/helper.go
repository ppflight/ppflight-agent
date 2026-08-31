package selfupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ppflight/ppflight-agent/internal/control"
	"github.com/ppflight/ppflight-agent/internal/fsutil"
	"github.com/ppflight/ppflight-agent/internal/upgradecontract"
)

type HelperConfig struct {
	StateDirectory  string
	BinaryPath      string
	ServiceName     string
	StatusURL       string
	WebsiteEndpoint string
	CurrentVersion  string
	Verify          control.VerifyConfig
	Journal         *control.Journal
	HTTPClient      *http.Client
	Now             func() time.Time
	RunSystemctl    func(context.Context, ...string) error
}

type statusBinding struct {
	BindingID       string `json:"bindingId"`
	DeviceID        string `json:"deviceId"`
	CredentialEpoch string `json:"credentialEpoch"`
}

type localStatus struct {
	Version  string `json:"version"`
	Bindings struct {
		Website statusBinding `json:"website"`
	} `json:"bindings"`
}

func RunHelper(ctx context.Context, cfg HelperConfig) error {
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
	coordinator, err := New(Config{StateDirectory: cfg.StateDirectory, WebsiteEndpoint: cfg.WebsiteEndpoint, CurrentVersion: cfg.CurrentVersion, HTTPClient: cfg.HTTPClient, Now: cfg.Now})
	if err != nil {
		return err
	}
	if err := validateUpgradeRoot(filepath.Join(cfg.StateDirectory, "upgrades")); err != nil {
		return err
	}
	requestPath, request, err := nextRequest(cfg.StateDirectory)
	if err != nil {
		return err
	}
	result := Result{SchemaVersion: requestSchema, UpgradeID: request.UpgradeID, Status: "failed", Code: "UPGRADE_HELPER_FAILED", FinishedAt: cfg.Now().UTC()}
	writeResult := func() {
		result.FinishedAt = cfg.Now().UTC()
		if saveResult(cfg.StateDirectory, result) == nil {
			if request.ArtifactFile == request.UpgradeID+".tar.gz" && filepath.Base(request.ArtifactFile) == request.ArtifactFile {
				_ = os.Remove(filepath.Join(filepath.Dir(requestPath), request.ArtifactFile))
			}
			if strings.TrimSuffix(filepath.Base(requestPath), ".request.json") == request.UpgradeID {
				_ = os.Remove(requestPath)
			}
		}
	}
	if err := validateHelperRequest(requestPath, request, cfg); err != nil {
		writeResult()
		return err
	}
	parameters, _ := upgradecontract.DecodeParameters(request.Command.Parameters)
	manifestURL, _ := upgradecontract.ManifestURL(cfg.WebsiteEndpoint)
	body, err := coordinator.getExact(ctx, manifestURL, 1<<20)
	if err != nil {
		writeResult()
		return err
	}
	manifest, err := upgradecontract.DecodeManifest(body)
	if err != nil {
		writeResult()
		return err
	}
	if err := manifest.Match(parameters); err != nil {
		writeResult()
		return err
	}
	if err := upgradecontract.SameOrigin(cfg.WebsiteEndpoint, parameters.Artifact.DownloadURL); err != nil {
		writeResult()
		return err
	}
	archivePath := filepath.Join(filepath.Dir(requestPath), request.ArtifactFile)
	binary, err := verifiedBinary(archivePath, parameters)
	if err != nil {
		writeResult()
		return err
	}
	backupPath, err := installCandidate(cfg.BinaryPath, cfg.StateDirectory, request.UpgradeID, binary)
	if err != nil {
		writeResult()
		return err
	}
	rollback := func(cause error) error {
		rollbackErr := restoreBackup(cfg.BinaryPath, backupPath)
		if rollbackErr == nil {
			rollbackErr = cfg.RunSystemctl(ctx, "restart", cfg.ServiceName)
		}
		if rollbackErr == nil {
			rollbackErr = waitForStatus(ctx, cfg, cfg.CurrentVersion)
		}
		result.Status, result.Code = "rolled_back", "AGENT_UPGRADE_ROLLED_BACK"
		writeResult()
		if rollbackErr != nil {
			return fmt.Errorf("upgrade failed (%v) and rollback failed (%v)", cause, rollbackErr)
		}
		return fmt.Errorf("upgrade failed and was rolled back: %w", cause)
	}
	if err := cfg.RunSystemctl(ctx, "restart", cfg.ServiceName); err != nil {
		return rollback(err)
	}
	targetVersion := strings.TrimPrefix(parameters.ReleaseTag, "v")
	if err := waitForStatus(ctx, cfg, targetVersion); err != nil {
		return rollback(err)
	}
	result.Status, result.Code, result.Version = "succeeded", "AGENT_UPGRADE_SUCCEEDED", targetVersion
	result.FinishedAt = cfg.Now().UTC()
	if err := saveResult(cfg.StateDirectory, result); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(filepath.Dir(requestPath), request.ArtifactFile))
	_ = os.Remove(requestPath)
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

func validateHelperRequest(requestPath string, request Request, cfg HelperConfig) error {
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
	deadline := time.Now().Add(15 * time.Second)
	for {
		err = cfg.Journal.AuthorizeUpgrade(request.Command.CommandID, control.Digest(request.Command), request.UpgradeID)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("upgrade journal handoff was not durably submitted")
		}
		time.Sleep(100 * time.Millisecond)
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
	"packaging/systemd/ppflight-agent.service": true, "packaging/systemd/ppflight-agent-upgrade.path": true, "packaging/systemd/ppflight-agent-upgrade.service": true,
	"packaging/systemd/ppflight-node-exporter.service": true, "packaging/systemd/ppflight-smartctl-exporter.service": true, "packaging/tmpfiles.d/ppflight-agent.conf": true,
	"scripts/install.sh": true, "scripts/uninstall.sh": true, "scripts/create-pve-tokens.sh": true, "scripts/remove-pve-credentials.sh": true, "scripts/verify-template-bundle.py": true,
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

func waitForStatus(ctx context.Context, cfg HelperConfig, version string) error {
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, cfg.StatusURL, nil)
		response, err := client.Do(request)
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10))
			response.Body.Close()
			var status localStatus
			if readErr == nil && response.StatusCode == http.StatusOK && json.Unmarshal(body, &status) == nil && status.Version == version && status.Bindings.Website.BindingID == cfg.Verify.BindingID && status.Bindings.Website.DeviceID == cfg.Verify.DeviceID && status.Bindings.Website.CredentialEpoch == strconv.FormatUint(cfg.Verify.CredentialEpoch, 10) {
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
	text := strings.TrimSpace(string(value))
	if len(text) > 256 {
		text = text[:256]
	}
	text = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, text)
	return text
}
