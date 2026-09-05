package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/control"
	"github.com/ppflight/ppflight-agent/internal/upgradecontract"
)

func TestCoordinatorStagesOnlyExactEnabledManifestArtifact(t *testing.T) {
	artifactBody := make([]byte, upgradecontract.MinArtifactBytes)
	for index := range artifactBody {
		artifactBody[index] = byte(index)
	}
	sum := sha256.Sum256(artifactBody)
	arch := runtime.GOARCH
	artifact := upgradecontract.Artifact{Architecture: arch, AssetName: "ppflight-agent-0.1.0-rc.9-linux-" + arch + ".tar.gz", SizeBytes: "1048576", SHA256: hex.EncodeToString(sum[:]), DownloadURL: "https://website.example" + upgradecontract.ArtifactPath("v0.1.0-rc.9", arch)}
	manifest := upgradecontract.Manifest{SchemaVersion: 1, ReleaseTag: "v0.1.0-rc.9", Version: "v0.1.0-rc.9", AgentCommitSHA: strings.Repeat("a", 64), InstallerCommitSHA: strings.Repeat("c", 64), Prerelease: true, PublishedAt: time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC), UpgradeDeliveryEnabled: true, Artifacts: []upgradecontract.Artifact{artifact}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case upgradecontract.CurrentManifestPath:
			_ = json.NewEncoder(w).Encode(manifest)
		case upgradecontract.ArtifactPath(manifest.ReleaseTag, arch):
			w.Header().Set("Content-Length", artifact.SizeBytes)
			_, _ = w.Write(artifactBody)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	parameters := upgradecontract.Parameters{SchemaVersion: 1, ReleaseTag: manifest.ReleaseTag, AgentCommitSHA: manifest.AgentCommitSHA, Artifact: artifact}
	raw, _ := json.Marshal(parameters)
	coordinator, err := New(Config{StateDirectory: t.TempDir(), WebsiteEndpoint: server.URL + "/internal/v1/commands", CurrentVersion: "0.1.0-rc.9", HTTPClient: server.Client(), TestOnlyAllowHTTP: true, Now: func() time.Time { return time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	id, err := coordinator.Prepare(context.Background(), control.Command{Action: "agent.upgrade", Scope: control.ScopeNode, Parameters: raw})
	if err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(coordinator.cfg.StateDirectory, "upgrades", "pending", id+".request.json")
	requestRaw, err := os.ReadFile(requestPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(requestRaw), string(artifactBody[:64])) {
		t.Fatal("request embedded artifact bytes")
	}
	info, err := os.Stat(filepath.Join(filepath.Dir(requestPath), id+".tar.gz"))
	if err != nil || info.Size() != int64(len(artifactBody)) {
		t.Fatalf("staged artifact invalid: %v %#v", err, info)
	}
}

func TestUpgradeTransitionAllowsSameVersionAndRejectsDowngrade(t *testing.T) {
	tests := []struct {
		name    string
		current string
		target  string
		wantErr bool
	}{
		{name: "same release", current: "0.1.5", target: "v0.1.5"},
		{name: "same release candidate", current: "0.1.5-rc.2", target: "v0.1.5-rc.2"},
		{name: "newer release candidate", current: "0.1.5-rc.2", target: "v0.1.5-rc.3"},
		{name: "release after candidate", current: "0.1.5-rc.3", target: "v0.1.5"},
		{name: "patch downgrade", current: "0.1.5", target: "v0.1.4", wantErr: true},
		{name: "candidate downgrade", current: "0.1.5-rc.3", target: "v0.1.5-rc.2", wantErr: true},
		{name: "release to candidate", current: "0.1.5", target: "v0.1.5-rc.9", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateUpgradeTransition(test.current, test.target)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateUpgradeTransition(%q, %q) error=%v, wantErr=%t", test.current, test.target, err, test.wantErr)
			}
		})
	}
}

func TestCoordinatorRejectsDowngradeBeforeArtifactDownload(t *testing.T) {
	arch := runtime.GOARCH
	artifact := upgradecontract.Artifact{
		Architecture: arch, AssetName: "ppflight-agent-0.1.4-linux-" + arch + ".tar.gz", SizeBytes: "1048576",
		SHA256: strings.Repeat("b", 64), DownloadURL: "https://website.example" + upgradecontract.ArtifactPath("v0.1.4", arch),
	}
	manifest := upgradecontract.Manifest{
		SchemaVersion: 1, ReleaseTag: "v0.1.4", Version: "v0.1.4", AgentCommitSHA: strings.Repeat("a", 64),
		InstallerCommitSHA: strings.Repeat("c", 64), PublishedAt: time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC),
		UpgradeDeliveryEnabled: true, Artifacts: []upgradecontract.Artifact{artifact},
	}
	artifactRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case upgradecontract.CurrentManifestPath:
			_ = json.NewEncoder(w).Encode(manifest)
		case upgradecontract.ArtifactPath(manifest.ReleaseTag, arch):
			artifactRequests++
			http.Error(w, "must not download", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	parameters := upgradecontract.Parameters{SchemaVersion: 1, ReleaseTag: manifest.ReleaseTag, AgentCommitSHA: manifest.AgentCommitSHA, Artifact: artifact}
	raw, _ := json.Marshal(parameters)
	coordinator, err := New(Config{StateDirectory: t.TempDir(), WebsiteEndpoint: server.URL + "/commands", CurrentVersion: "0.1.5", HTTPClient: server.Client(), TestOnlyAllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Prepare(context.Background(), control.Command{Action: "agent.upgrade", Scope: control.ScopeNode, Parameters: raw}); err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("downgrade error=%v", err)
	}
	if artifactRequests != 0 {
		t.Fatalf("downgrade downloaded artifact %d times", artifactRequests)
	}
}

func TestCoordinatorFailsClosedWhenManifestDeliveryDisabled(t *testing.T) {
	arch := runtime.GOARCH
	artifact := upgradecontract.Artifact{Architecture: arch, AssetName: "ppflight-agent-0.1.0-rc.9-linux-" + arch + ".tar.gz", SizeBytes: "1048576", SHA256: strings.Repeat("b", 64), DownloadURL: "https://website.example" + upgradecontract.ArtifactPath("v0.1.0-rc.9", arch)}
	manifest := upgradecontract.Manifest{SchemaVersion: 1, ReleaseTag: "v0.1.0-rc.9", Version: "v0.1.0-rc.9", AgentCommitSHA: strings.Repeat("a", 64), InstallerCommitSHA: strings.Repeat("c", 64), Prerelease: true, PublishedAt: time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC), UpgradeDeliveryEnabled: false, FailClosedReason: "not_ready", Artifacts: []upgradecontract.Artifact{artifact}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(manifest) }))
	defer server.Close()
	parameters := upgradecontract.Parameters{SchemaVersion: 1, ReleaseTag: manifest.ReleaseTag, AgentCommitSHA: manifest.AgentCommitSHA, Artifact: artifact}
	raw, _ := json.Marshal(parameters)
	coordinator, _ := New(Config{StateDirectory: t.TempDir(), WebsiteEndpoint: server.URL + "/commands", CurrentVersion: "old", HTTPClient: server.Client(), TestOnlyAllowHTTP: true})
	if _, err := coordinator.Prepare(context.Background(), control.Command{Action: "agent.upgrade", Scope: control.ScopeNode, Parameters: raw}); err == nil {
		t.Fatal("disabled manifest was accepted")
	}
}
