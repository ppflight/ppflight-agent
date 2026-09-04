package scripts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	const expectedManifestSHA256 = "14d0870708736912f176c78bcd9995e2141317b10c385a07b9693ce65d7e2fe0"
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

func TestTemplateBuilderPinsAndVerifiesSingleSocketAndQGABaselines(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "bundles", "ppflight-cloudinit", "build-cloud-templates.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	for _, required := range []string{
		`--sockets 1 \`,
		`grep -qx 'sockets: 1' <<< "$config"`,
		`template_needs_tcg_customization()`,
		`template_needs_tcg_customization "$template_name"`,
		`LIBGUESTFS_BACKEND_SETTINGS=force_tcg`,
		`unset LIBGUESTFS_BACKEND_SETTINGS`,
		`run_virt_customize "$use_tcg" --format qcow2 --network -a "$prepared"`,
		`--install "$QGA_PACKAGE"`,
		`run_virt_customize "$use_tcg" --format qcow2 --no-network -a "$prepared"`,
		`dpkg-query -W -f='${db:Status-Status}' qemu-guest-agent`,
		`rpm -q --quiet qemu-guest-agent`,
		`systemctl is-enabled qemu-guest-agent.service`,
		`ppflight-qga-preinstalled`,
		`report_host_cpu_compatibility "$name" x86-64-v2`,
		`report_host_cpu_compatibility "$name" x86-64-v3`,
		`avx avx2 bmi1 bmi2 f16c fma abm movbe xsave`,
		`[[ "$existing_name" == "$expected_name" ]]`,
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("template builder is missing the frozen socket baseline check %q", required)
		}
	}
	if count := strings.Count(script, `run_virt_customize "$use_tcg"`); count != 2 {
		t.Fatalf("template builder must use the same selected backend for QGA installation and verification, got %d invocations", count)
	}
	if count := strings.Count(script, `export LIBGUESTFS_BACKEND_SETTINGS=force_tcg`); count != 1 {
		t.Fatalf("template builder must isolate its conditional TCG setting in one wrapper, got %d exports", count)
	}
	for _, forbidden := range []string{
		"  - qemu-guest-agent\n",
		"[systemctl, enable, --now, qemu-guest-agent]",
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("template builder must not defer QGA installation to first-boot Cloud-Init: %q", forbidden)
		}
	}
}
