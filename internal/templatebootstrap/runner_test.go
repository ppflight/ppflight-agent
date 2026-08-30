package templatebootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunnerVerifiesImmutableBundleAndInvokesFixedEntrypoint(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		python, err = exec.LookPath("python3")
	}
	if err != nil {
		t.Skip("python is not available")
	}
	root := t.TempDir()
	files := map[string][]byte{
		"tools/ppflight-template-bootstrap.py": []byte("import json,sys\nprint(json.dumps({'mode': sys.argv[1], 'state': 'succeeded'}))\n"),
		"catalog/template-catalog.v1.json":     []byte("{\"catalog\":true}\n"),
		"build-cloud-templates.sh":             []byte("#!/usr/bin/env bash\nexit 0\n"),
	}
	manifest := Manifest{
		SchemaVersion: ManifestSchema, BundleVersion: "3.0.0", CatalogRevision: "2026-08-30.1", Entrypoint: "tools/ppflight-template-bootstrap.py",
		NetworkRedirectPolicy: NetworkRedirectPolicy{Allowed: true, Schemes: []string{"https"}, AddressFamily: "ipv4-only", HostPolicy: "upstream-selected", IntegrityPolicy: "catalog-sha256-and-official-checksum"},
	}
	for path, contents := range files {
		filename := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(filename), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, contents, 0o600); err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(contents)
		digest := hex.EncodeToString(hash[:])
		manifest.Files = append(manifest.Files, ManifestFile{Path: path, SHA256: digest, RequiredAtRuntime: true})
		if path == "catalog/template-catalog.v1.json" {
			manifest.CatalogSHA256 = digest
		}
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ManifestFilename), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	runner := Runner{Root: root, Python: python}
	result, err := runner.Run(context.Background(), []string{"catalog"}, nil)
	if err != nil || result.ExitCode != 0 || strings.TrimSpace(string(result.Stdout)) != "{\"mode\": \"catalog\", \"state\": \"succeeded\"}" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if err := os.WriteFile(filepath.Join(root, "catalog", "template-catalog.v1.json"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Verify(); err == nil {
		t.Fatal("tampered vendored file passed verification")
	}
}

func TestManifestRequiresFrozenIPv4RedirectPolicy(t *testing.T) {
	root := t.TempDir()
	files := map[string][]byte{
		"tools/ppflight-template-bootstrap.py": []byte("print('{}')\n"),
		"catalog/template-catalog.v1.json":     []byte("{}\n"),
		"build-cloud-templates.sh":             []byte("#!/usr/bin/env bash\nexit 0\n"),
	}
	manifest := Manifest{
		SchemaVersion: ManifestSchema, BundleVersion: "3.0.0", CatalogRevision: "2026-08-30.1", Entrypoint: "tools/ppflight-template-bootstrap.py",
		NetworkRedirectPolicy: NetworkRedirectPolicy{Allowed: true, Schemes: []string{"https"}, AddressFamily: "dual-stack", HostPolicy: "upstream-selected", IntegrityPolicy: "catalog-sha256-and-official-checksum"},
	}
	for relative, contents := range files {
		filename := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(filename), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, contents, 0o600); err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(contents)
		digest := hex.EncodeToString(hash[:])
		manifest.Files = append(manifest.Files, ManifestFile{Path: relative, SHA256: digest, RequiredAtRuntime: true})
		if relative == "catalog/template-catalog.v1.json" {
			manifest.CatalogSHA256 = digest
		}
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ManifestFilename), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Runner{Root: root}).Verify(); err == nil || !strings.Contains(err.Error(), "network redirect policy") {
		t.Fatalf("non-IPv4 policy was accepted: %v", err)
	}
}

func TestManifestRejectsTraversal(t *testing.T) {
	if validRelativePath("../catalog.json") || validRelativePath("/catalog.json") || validRelativePath(`catalog\\file.json`) {
		t.Fatal("unsafe bundle path was accepted")
	}
}
