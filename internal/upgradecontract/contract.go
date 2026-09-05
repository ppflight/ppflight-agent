// Package upgradecontract defines the strict, non-extensible wire contract
// for website-authorized ppflight-agent upgrades.
package upgradecontract

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	SchemaVersion       = 1
	CurrentManifestPath = "/api/pve-agent/v1/releases/current"
	MaxArtifactBytes    = 128 << 20
	MinArtifactBytes    = 1 << 20
)

var (
	releaseTagRE = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?$`)
	hex64RE      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	assetRE      = regexp.MustCompile(`^ppflight-agent-[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?-linux-(amd64|arm64)\.tar\.gz$`)
	keyIDRE      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$`)
)

type CommandSigningRotation struct {
	KeyID     string `json:"keyId"`
	PublicKey string `json:"publicKey"`
}

type Artifact struct {
	Architecture string `json:"architecture"`
	AssetName    string `json:"assetName"`
	SizeBytes    string `json:"sizeBytes"`
	SHA256       string `json:"sha256"`
	DownloadURL  string `json:"downloadUrl"`
}

type Parameters struct {
	SchemaVersion          int                     `json:"schemaVersion"`
	ReleaseTag             string                  `json:"releaseTag"`
	AgentCommitSHA         string                  `json:"agentCommitSha"`
	Artifact               Artifact                `json:"artifact"`
	CommandSigningRotation *CommandSigningRotation `json:"commandSigningRotation,omitempty"`
}

type Manifest struct {
	SchemaVersion          int        `json:"schemaVersion"`
	ReleaseTag             string     `json:"releaseTag"`
	Version                string     `json:"version"`
	AgentCommitSHA         string     `json:"agentCommitSha"`
	InstallerCommitSHA     string     `json:"installerCommitSha"`
	Prerelease             bool       `json:"prerelease"`
	PublishedAt            time.Time  `json:"publishedAt"`
	UpgradeDeliveryEnabled bool       `json:"upgradeDeliveryEnabled"`
	FailClosedReason       string     `json:"failClosedReason,omitempty"`
	Artifacts              []Artifact `json:"artifacts"`
}

func DecodeParameters(raw []byte) (Parameters, error) {
	var value Parameters
	if err := strictDecode(raw, &value); err != nil {
		return Parameters{}, err
	}
	if err := value.Validate(runtime.GOARCH); err != nil {
		return Parameters{}, err
	}
	return value, nil
}

func DecodeManifest(raw []byte) (Manifest, error) {
	var value Manifest
	if err := strictDecode(raw, &value); err != nil {
		return Manifest{}, err
	}
	if value.SchemaVersion != SchemaVersion || !releaseTagRE.MatchString(value.ReleaseTag) || value.Version != value.ReleaseTag || !hex64RE.MatchString(value.AgentCommitSHA) || !hex64RE.MatchString(value.InstallerCommitSHA) || value.PublishedAt.IsZero() || value.PublishedAt.Location() != time.UTC || value.Prerelease != strings.Contains(value.ReleaseTag, "-rc.") || len(value.Artifacts) < 1 || len(value.Artifacts) > 2 {
		return Manifest{}, errors.New("release manifest identity is invalid")
	}
	seen := map[string]bool{}
	for _, artifact := range value.Artifacts {
		if seen[artifact.Architecture] {
			return Manifest{}, errors.New("release manifest repeats an architecture")
		}
		seen[artifact.Architecture] = true
		if err := artifact.Validate(value.ReleaseTag, artifact.Architecture); err != nil {
			return Manifest{}, err
		}
	}
	if value.UpgradeDeliveryEnabled && value.FailClosedReason != "" {
		return Manifest{}, errors.New("enabled release manifest has a fail-closed reason")
	}
	if !value.UpgradeDeliveryEnabled && strings.TrimSpace(value.FailClosedReason) == "" {
		return Manifest{}, errors.New("disabled release manifest is missing its fail-closed reason")
	}
	return value, nil
}

func (p Parameters) Validate(architecture string) error {
	if p.SchemaVersion != SchemaVersion || !releaseTagRE.MatchString(p.ReleaseTag) || !hex64RE.MatchString(p.AgentCommitSHA) {
		return errors.New("upgrade parameters identity is invalid")
	}
	if err := p.Artifact.Validate(p.ReleaseTag, architecture); err != nil {
		return err
	}
	if p.CommandSigningRotation != nil {
		decoded, err := base64.StdEncoding.DecodeString(p.CommandSigningRotation.PublicKey)
		if err != nil || len(decoded) != 32 || !keyIDRE.MatchString(p.CommandSigningRotation.KeyID) {
			return errors.New("command signing rotation is invalid")
		}
	}
	return nil
}

func (a Artifact) Validate(releaseTag, architecture string) error {
	if architecture != "amd64" && architecture != "arm64" || a.Architecture != architecture || !hex64RE.MatchString(a.SHA256) || !assetRE.MatchString(a.AssetName) {
		return errors.New("upgrade artifact identity is invalid")
	}
	expected := "ppflight-agent-" + strings.TrimPrefix(releaseTag, "v") + "-linux-" + architecture + ".tar.gz"
	if a.AssetName != expected {
		return errors.New("upgrade artifact name does not match release and architecture")
	}
	size, err := strconv.ParseUint(a.SizeBytes, 10, 64)
	if err != nil || strconv.FormatUint(size, 10) != a.SizeBytes || size < MinArtifactBytes || size > MaxArtifactBytes {
		return errors.New("upgrade artifact size is invalid")
	}
	parsed, err := url.Parse(a.DownloadURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Port() != "" {
		return errors.New("upgrade artifact URL is invalid")
	}
	expectedPath := ArtifactPath(releaseTag, architecture)
	if parsed.EscapedPath() != expectedPath || parsed.Path != expectedPath {
		return fmt.Errorf("upgrade artifact URL must use fixed path %s", expectedPath)
	}
	return nil
}

func ArtifactPath(releaseTag, architecture string) string {
	return "/api/pve-agent/v1/releases/artifacts/" + releaseTag + "/" + architecture
}

func (m Manifest) Match(p Parameters) error {
	if !m.UpgradeDeliveryEnabled {
		return fmt.Errorf("upgrade delivery is disabled: %s", m.FailClosedReason)
	}
	if m.ReleaseTag != p.ReleaseTag || m.AgentCommitSHA != p.AgentCommitSHA {
		return errors.New("signed upgrade does not match the current server manifest")
	}
	for _, artifact := range m.Artifacts {
		if artifact.Architecture == p.Artifact.Architecture {
			if artifact != p.Artifact {
				return errors.New("signed artifact does not exactly match the server manifest")
			}
			return nil
		}
	}
	return errors.New("server manifest has no artifact for this architecture")
}

func SameOrigin(endpoint, candidate string) error {
	left, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	right, err := url.Parse(candidate)
	if err != nil {
		return err
	}
	if left.Scheme != "https" || right.Scheme != "https" || !strings.EqualFold(left.Hostname(), right.Hostname()) || left.Port() != right.Port() {
		return errors.New("upgrade URL is not on the bound website origin")
	}
	return nil
}

func ManifestURL(endpoint string) (string, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
		return "", errors.New("bound website endpoint is invalid")
	}
	parsed.Path, parsed.RawPath, parsed.RawQuery, parsed.Fragment = CurrentManifestPath, "", "", ""
	return parsed.String(), nil
}

func strictDecode(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("JSON contains trailing data")
	}
	return nil
}
