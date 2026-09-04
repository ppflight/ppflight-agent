package selfupdate

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/ppflight/ppflight-agent/internal/upgradecontract"
)

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
