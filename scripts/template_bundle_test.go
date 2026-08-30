package scripts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestTemplateBundleVerifierRejectsTampering(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		python, err = exec.LookPath("python3")
	}
	if err != nil {
		t.Skip("python is unavailable")
	}
	root := t.TempDir()
	files := map[string][]byte{
		"build-cloud-templates.sh":             []byte("#!/usr/bin/env bash\nexit 0\n"),
		"tools/ppflight-template-bootstrap.py": []byte("print('{}')\n"),
		"catalog/template-catalog.v1.json":     []byte("{}\n"),
	}
	type entry struct {
		Path              string `json:"path"`
		SHA256            string `json:"sha256"`
		RequiredAtRuntime bool   `json:"requiredAtRuntime"`
	}
	entries := make([]entry, 0, len(files))
	catalogDigest := ""
	for _, relative := range []string{"build-cloud-templates.sh", "tools/ppflight-template-bootstrap.py", "catalog/template-catalog.v1.json"} {
		contents := files[relative]
		filename := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(filename), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, contents, 0o640); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(contents)
		value := hex.EncodeToString(digest[:])
		entries = append(entries, entry{Path: relative, SHA256: value, RequiredAtRuntime: true})
		if relative == "catalog/template-catalog.v1.json" {
			catalogDigest = value
		}
	}
	manifest := map[string]any{
		"schemaVersion": "ppflight.agent-vendor-manifest/v1", "bundleVersion": "3.0.0",
		"catalogRevision": "2026-08-30.1", "catalogSha256": catalogDigest,
		"entrypoint": "tools/ppflight-template-bootstrap.py", "files": entries,
		"dependencies":          map[string]any{"python": ">=3.9", "bash": ">=5", "commands": []string{"python3"}, "perlModules": []string{"JSON::PP"}},
		"networkHosts":          []string{"images.example.test"},
		"networkRedirectPolicy": map[string]any{"allowed": true, "schemes": []string{"https"}, "addressFamily": "ipv4-only", "hostPolicy": "upstream-selected", "integrityPolicy": "catalog-sha256-and-official-checksum"},
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "agent-vendor-manifest.v1.json"), raw, 0o640); err != nil {
		t.Fatal(err)
	}
	run := func() error {
		command := exec.Command(python, "-I", "verify-template-bundle.py", "verify", root)
		command.Dir = "."
		return command.Run()
	}
	if err := run(); err != nil {
		t.Fatalf("valid bundle failed verification: %v", err)
	}
	manifest["networkRedirectPolicy"].(map[string]any)["addressFamily"] = "dual-stack"
	invalidPolicy, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "agent-vendor-manifest.v1.json"), invalidPolicy, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := run(); err == nil {
		t.Fatal("non-IPv4 network redirect policy passed verification")
	}
	if err := os.WriteFile(filepath.Join(root, "agent-vendor-manifest.v1.json"), raw, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "catalog", "template-catalog.v1.json"), []byte("tampered\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := run(); err == nil {
		t.Fatal("tampered bundle passed verification")
	}
}

func TestVendoredTemplateBundleMatchesFrozenManifest(t *testing.T) {
	const expectedManifestSHA256 = "272d951a3933398849c031624b3ca84e515b99dc2ec2a49ae4fbf723a93649da"
	root := filepath.Join("..", "bundles", "ppflight-cloudinit")
	raw, err := os.ReadFile(filepath.Join(root, "agent-vendor-manifest.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if actual := hex.EncodeToString(digest[:]); actual != expectedManifestSHA256 {
		t.Fatalf("vendored manifest SHA-256=%s want=%s", actual, expectedManifestSHA256)
	}
	python, err := exec.LookPath("python")
	if err != nil {
		python, err = exec.LookPath("python3")
	}
	if err != nil {
		t.Skip("python is unavailable")
	}
	command := exec.Command(python, "-I", "verify-template-bundle.py", "verify", root)
	command.Dir = "."
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("frozen vendored bundle failed verification: %v: %s", err, output)
	}
}
