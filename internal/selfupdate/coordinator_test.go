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
	coordinator, err := New(Config{StateDirectory: t.TempDir(), WebsiteEndpoint: server.URL + "/internal/v1/commands", CurrentVersion: "0.1.0-rc.8", HTTPClient: server.Client(), TestOnlyAllowHTTP: true, Now: func() time.Time { return time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC) }})
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
