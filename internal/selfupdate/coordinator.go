// Package selfupdate stages signed upgrades for a separately privileged
// systemd helper. The long-running agent never overwrites or restarts itself.
package selfupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ppflight/ppflight-agent/internal/control"
	"github.com/ppflight/ppflight-agent/internal/fsutil"
	"github.com/ppflight/ppflight-agent/internal/netpolicy"
	"github.com/ppflight/ppflight-agent/internal/protocol"
	"github.com/ppflight/ppflight-agent/internal/upgradecontract"
)

const requestSchema = 1

var resultErrorStageRE = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)
var agentVersionRE = regexp.MustCompile(`^v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:-rc\.([0-9]+))?$`)

type Config struct {
	StateDirectory  string
	WebsiteEndpoint string
	CurrentVersion  string
	HTTPClient      *http.Client
	Now             func() time.Time
	// TestOnlyAllowHTTP is intentionally unexported from production config and
	// exists solely for hermetic httptest coverage.
	TestOnlyAllowHTTP bool
}

type Coordinator struct{ cfg Config }

type Request struct {
	SchemaVersion  int             `json:"schemaVersion"`
	UpgradeID      string          `json:"upgradeId"`
	PreparedAt     time.Time       `json:"preparedAt"`
	CurrentVersion string          `json:"currentVersion"`
	ArtifactFile   string          `json:"artifactFile"`
	ArtifactSHA256 string          `json:"artifactSha256"`
	ArtifactBytes  string          `json:"artifactBytes"`
	Command        control.Command `json:"command"`
}

type Result struct {
	SchemaVersion int                     `json:"schemaVersion"`
	UpgradeID     string                  `json:"upgradeId"`
	Status        string                  `json:"status"`
	Version       string                  `json:"version,omitempty"`
	Code          string                  `json:"code"`
	Error         *control.ExecutionError `json:"error,omitempty"`
	FinishedAt    time.Time               `json:"finishedAt"`
}

func New(cfg Config) (*Coordinator, error) {
	if cfg.StateDirectory == "" || cfg.WebsiteEndpoint == "" || cfg.CurrentVersion == "" {
		return nil, errors.New("self-update configuration is incomplete")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HTTPClient == nil {
		transport := netpolicy.ApplyIPv4Only(&http.Transport{
			Proxy:           nil,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		})
		cfg.HTTPClient = &http.Client{
			Timeout:       5 * time.Minute,
			Transport:     transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return &Coordinator{cfg: cfg}, nil
}

func (c *Coordinator) Prepare(ctx context.Context, command control.Command) (string, error) {
	if command.Action != "agent.upgrade" || command.Scope != control.ScopeNode {
		return "", errors.New("self-update coordinator received a non-upgrade command")
	}
	parameters, err := upgradecontract.DecodeParameters(command.Parameters)
	if err != nil {
		return "", err
	}
	slog.Info("agent upgrade preparation started",
		"operationId", command.OperationID,
		"commandId", command.CommandID,
		"releaseTag", parameters.ReleaseTag,
		"architecture", parameters.Artifact.Architecture,
	)
	manifestURL := ""
	if c.cfg.TestOnlyAllowHTTP {
		manifestURL = testHTTPOrigin(c.cfg.WebsiteEndpoint) + upgradecontract.CurrentManifestPath
	} else {
		manifestURL, err = upgradecontract.ManifestURL(c.cfg.WebsiteEndpoint)
		if err != nil {
			return "", err
		}
	}
	manifestBody, err := c.getExact(ctx, manifestURL, 1<<20)
	if err != nil {
		return "", fmt.Errorf("fetch release manifest: %w", err)
	}
	manifest, err := upgradecontract.DecodeManifest(manifestBody)
	if err != nil {
		return "", fmt.Errorf("validate release manifest: %w", err)
	}
	if err := manifest.Match(parameters); err != nil {
		return "", err
	}
	if err := validateUpgradeTransition(c.cfg.CurrentVersion, parameters.ReleaseTag); err != nil {
		return "", err
	}
	slog.Info("agent upgrade manifest verified",
		"operationId", command.OperationID,
		"releaseTag", parameters.ReleaseTag,
		"agentCommitSha", parameters.AgentCommitSHA,
	)
	if !c.cfg.TestOnlyAllowHTTP {
		if err := upgradecontract.SameOrigin(c.cfg.WebsiteEndpoint, parameters.Artifact.DownloadURL); err != nil {
			return "", err
		}
	}
	directory := filepath.Join(c.cfg.StateDirectory, "upgrades", "pending")
	if err := fsutil.EnsurePrivateDirectory(directory); err != nil {
		return "", err
	}
	upgradeID, err := protocol.NewID()
	if err != nil {
		return "", err
	}
	artifactPath := filepath.Join(directory, upgradeID+".tar.gz")
	downloadURL := parameters.Artifact.DownloadURL
	if c.cfg.TestOnlyAllowHTTP {
		downloadURL = testHTTPOrigin(c.cfg.WebsiteEndpoint) + upgradecontract.ArtifactPath(parameters.ReleaseTag, parameters.Artifact.Architecture)
	}
	if err := c.downloadArtifact(ctx, downloadURL, artifactPath, parameters.Artifact); err != nil {
		return "", err
	}
	slog.Info("agent upgrade artifact verified",
		"operationId", command.OperationID,
		"releaseTag", parameters.ReleaseTag,
		"architecture", parameters.Artifact.Architecture,
		"sizeBytes", parameters.Artifact.SizeBytes,
		"sha256", parameters.Artifact.SHA256,
	)
	request := Request{
		SchemaVersion: requestSchema, UpgradeID: upgradeID, PreparedAt: c.cfg.Now().UTC(), CurrentVersion: c.cfg.CurrentVersion,
		ArtifactFile: filepath.Base(artifactPath), ArtifactSHA256: parameters.Artifact.SHA256, ArtifactBytes: parameters.Artifact.SizeBytes, Command: command,
	}
	payload, err := json.Marshal(request)
	if err != nil {
		_ = os.Remove(artifactPath)
		return "", err
	}
	// Do not expose the request to the root path unit until the unprivileged
	// control service has durably recorded AGENT_UPGRADE_SUBMITTED.  Older
	// releases wrote the watched *.request.json here, allowing the helper to
	// race the journal transition and fail after 15 seconds with
	// "upgrade journal handoff was not durably submitted".  ResolveUpgrade is
	// called only from reconciliation of that submitted journal record; it
	// performs the one-way activation rename below.
	if err := fsutil.AtomicWriteFile(filepath.Join(directory, upgradeID+".prepared.json"), payload, 0o600, false); err != nil {
		_ = os.Remove(artifactPath)
		return "", err
	}
	slog.Info("agent upgrade handed to root helper",
		"operationId", command.OperationID,
		"upgradeId", upgradeID,
		"releaseTag", parameters.ReleaseTag,
	)
	return upgradeID, nil
}

// validateUpgradeTransition rejects rollback while deliberately permitting an
// exact same-version handoff. The latter is required when an older helper has
// installed a new binary but cannot itself perform that binary's mandatory
// host-firewall postflight.
func validateUpgradeTransition(currentVersion, targetRelease string) error {
	current, err := parseAgentVersion(currentVersion)
	if err != nil {
		return fmt.Errorf("current agent version is invalid: %w", err)
	}
	target, err := parseAgentVersion(targetRelease)
	if err != nil {
		return fmt.Errorf("target agent version is invalid: %w", err)
	}
	for index := 0; index < 3; index++ {
		if current.numbers[index] < target.numbers[index] {
			return nil
		}
		if current.numbers[index] > target.numbers[index] {
			return errors.New("agent downgrade is forbidden")
		}
	}
	if current.release != target.release {
		if current.release {
			return errors.New("agent downgrade is forbidden")
		}
		return nil
	}
	if current.release {
		return nil
	}
	if current.rc > target.rc {
		return errors.New("agent downgrade is forbidden")
	}
	return nil
}

type agentVersion struct {
	numbers [3]uint64
	release bool
	rc      uint64
}

func parseAgentVersion(value string) (agentVersion, error) {
	matches := agentVersionRE.FindStringSubmatch(value)
	if matches == nil {
		return agentVersion{}, errors.New("version must be X.Y.Z or X.Y.Z-rc.N")
	}
	var parsed agentVersion
	for index := 0; index < 3; index++ {
		number, err := strconv.ParseUint(matches[index+1], 10, 64)
		if err != nil {
			return agentVersion{}, errors.New("version component exceeds uint64")
		}
		parsed.numbers[index] = number
	}
	parsed.release = matches[4] == ""
	if !parsed.release {
		rc, err := strconv.ParseUint(matches[4], 10, 64)
		if err != nil {
			return agentVersion{}, errors.New("release candidate component exceeds uint64")
		}
		parsed.rc = rc
	}
	return parsed, nil
}

func (c *Coordinator) ResolveUpgrade(_ context.Context, upgradeID string) (control.UpgradeResolution, error) {
	if upgradeID == "" || filepath.Base(upgradeID) != upgradeID {
		return control.UpgradeResolution{}, errors.New("upgrade ID is invalid")
	}
	filename := filepath.Join(c.cfg.StateDirectory, "upgrades", "results", upgradeID+".json")
	body, err := os.ReadFile(filename)
	if errors.Is(err, os.ErrNotExist) {
		if activateErr := activatePreparedRequest(c.cfg.StateDirectory, upgradeID); activateErr != nil {
			return control.UpgradeResolution{}, activateErr
		}
		return control.UpgradeResolution{Status: "pending"}, nil
	}
	if err != nil || len(body) == 0 || len(body) > 64<<10 {
		return control.UpgradeResolution{}, errors.New("upgrade result is unavailable")
	}
	var result Result
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil || decoder.Decode(&struct{}{}) != io.EOF || result.SchemaVersion != requestSchema || result.UpgradeID != upgradeID || result.FinishedAt.IsZero() || !validResultError(result.Error) {
		return control.UpgradeResolution{}, errors.New("upgrade result is invalid")
	}
	switch result.Status {
	case "succeeded", "rolled_back", "failed":
	default:
		return control.UpgradeResolution{}, errors.New("upgrade result status is invalid")
	}
	return control.UpgradeResolution{Status: result.Status, Version: result.Version, Code: result.Code, Error: result.Error}, nil
}

func activatePreparedRequest(stateDirectory, upgradeID string) error {
	directory := filepath.Join(stateDirectory, "upgrades", "pending")
	prepared := filepath.Join(directory, upgradeID+".prepared.json")
	request := filepath.Join(directory, upgradeID+".request.json")
	preparedInfo, err := os.Lstat(prepared)
	if errors.Is(err, os.ErrNotExist) {
		// The helper may already own or have consumed the activated request.
		return nil
	}
	if err != nil || !preparedInfo.Mode().IsRegular() || preparedInfo.Mode()&os.ModeSymlink != 0 || preparedInfo.Size() < 1 || preparedInfo.Size() > 2<<20 {
		return errors.New("prepared upgrade request is unsafe")
	}
	if requestInfo, requestErr := os.Lstat(request); requestErr == nil {
		if !requestInfo.Mode().IsRegular() || requestInfo.Mode()&os.ModeSymlink != 0 {
			return errors.New("active upgrade request is unsafe")
		}
		return errors.New("prepared and active upgrade requests both exist")
	} else if !errors.Is(requestErr, os.ErrNotExist) {
		return errors.New("active upgrade request is unavailable")
	}
	if err := os.Rename(prepared, request); err != nil {
		return fmt.Errorf("activate prepared upgrade request: %w", err)
	}
	handle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open upgrade request directory: %w", err)
	}
	defer handle.Close()
	if err := handle.Sync(); err != nil {
		return fmt.Errorf("sync upgrade request directory: %w", err)
	}
	return nil
}

func validResultError(value *control.ExecutionError) bool {
	if value == nil {
		return true
	}
	return value.Source == "agent" && resultErrorStageRE.MatchString(value.Stage) && value.Method == "" && value.Path == "" && value.HTTPStatus == 0 &&
		strings.TrimSpace(value.Reason) == value.Reason && value.Reason != "" && len(value.Reason) <= 512 &&
		!strings.ContainsAny(value.Reason, "\x00\r\n")
}

func (c *Coordinator) getExact(ctx context.Context, endpoint string, limit int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Accept-Encoding", "identity")
	response, err := c.cfg.HTTPClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.Request == nil || response.Request.URL.String() != endpoint {
		return nil, errors.New("redirected response is forbidden")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, errors.New("response exceeds the allowed size")
	}
	return body, nil
}

func (c *Coordinator) downloadArtifact(ctx context.Context, endpoint, destination string, expected upgradecontract.Artifact) (returnErr error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept-Encoding", "identity")
	response, err := c.cfg.HTTPClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.Request == nil || response.Request.URL.String() != endpoint {
		return errors.New("redirected artifact response is forbidden")
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("artifact returned HTTP status %d", response.StatusCode)
	}
	if encoding := response.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return errors.New("encoded artifact response is forbidden")
	}
	want, _ := strconv.ParseInt(expected.SizeBytes, 10, 64)
	if response.ContentLength >= 0 && response.ContentLength != want {
		return errors.New("artifact Content-Length does not match the manifest")
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := file.Close(); returnErr == nil {
			returnErr = closeErr
		}
		if returnErr != nil {
			_ = os.Remove(destination)
		}
	}()
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(response.Body, want+1))
	if err != nil || written != want {
		return errors.New("artifact body length does not match the manifest")
	}
	if hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
		return errors.New("artifact SHA-256 does not match the manifest")
	}
	return file.Sync()
}

func testHTTPOrigin(endpoint string) string {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}
