package upgradecontract

import (
	"encoding/base64"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"
)

func validParameters() Parameters {
	arch := runtime.GOARCH
	return Parameters{SchemaVersion: 1, ReleaseTag: "v0.1.0-rc.9", AgentCommitSHA: strings.Repeat("a", 64), Artifact: Artifact{
		Architecture: arch, AssetName: "ppflight-agent-0.1.0-rc.9-linux-" + arch + ".tar.gz", SizeBytes: "1048576", SHA256: strings.Repeat("b", 64),
		DownloadURL: "https://www.ppflight.com" + ArtifactPath("v0.1.0-rc.9", arch),
	}}
}

func TestParametersAcceptOneStrictCommandSigningRotation(t *testing.T) {
	value := validParameters()
	value.CommandSigningRotation = &CommandSigningRotation{
		KeyID:     "pve1.binding.device-01.g2",
		PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}
	raw, _ := json.Marshal(value)
	if _, err := DecodeParameters(raw); err != nil {
		t.Fatal(err)
	}
	value.CommandSigningRotation.PublicKey = base64.StdEncoding.EncodeToString(make([]byte, 31))
	raw, _ = json.Marshal(value)
	if _, err := DecodeParameters(raw); err == nil {
		t.Fatal("short command signing public key was accepted")
	}
}

func TestParametersRejectArbitraryURLUnknownFieldsAndUnsafeIntegers(t *testing.T) {
	value := validParameters()
	for name, mutate := range map[string]func(*Parameters){
		"arbitrary URL":             func(p *Parameters) { p.Artifact.DownloadURL = "https://evil.example/payload" },
		"redirect-style GitHub URL": func(p *Parameters) { p.Artifact.DownloadURL = "https://github.com/ppflight/release.tar.gz" },
		"wrong architecture":        func(p *Parameters) { p.Artifact.Architecture = "386" },
		"noncanonical size":         func(p *Parameters) { p.Artifact.SizeBytes = "01048576" },
		"uppercase digest":          func(p *Parameters) { p.Artifact.SHA256 = strings.Repeat("A", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			copy := value
			mutate(&copy)
			raw, _ := json.Marshal(copy)
			if _, err := DecodeParameters(raw); err == nil {
				t.Fatal("unsafe parameters were accepted")
			}
		})
	}
	raw, _ := json.Marshal(value)
	raw = append(raw[:len(raw)-1], []byte(`,"command":"curl evil"}`)...)
	if _, err := DecodeParameters(raw); err == nil {
		t.Fatal("unknown command field was accepted")
	}
}

func TestManifestMustBeEnabledAndExactlyMatch(t *testing.T) {
	parameters := validParameters()
	manifest := Manifest{SchemaVersion: 1, ReleaseTag: parameters.ReleaseTag, Version: parameters.ReleaseTag, AgentCommitSHA: parameters.AgentCommitSHA, InstallerCommitSHA: strings.Repeat("c", 64), Prerelease: true, PublishedAt: time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC), UpgradeDeliveryEnabled: false, FailClosedReason: "agent_upgrade_action_not_supported", Artifacts: []Artifact{parameters.Artifact}}
	raw, _ := json.Marshal(manifest)
	decoded, err := DecodeManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := decoded.Match(parameters); err == nil {
		t.Fatal("disabled delivery was accepted")
	}
	manifest.UpgradeDeliveryEnabled, manifest.FailClosedReason = true, ""
	raw, _ = json.Marshal(manifest)
	decoded, err = DecodeManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := decoded.Match(parameters); err != nil {
		t.Fatal(err)
	}
	parameters.Artifact.SHA256 = strings.Repeat("c", 64)
	if err := decoded.Match(parameters); err == nil {
		t.Fatal("manifest mismatch was accepted")
	}
}
