package config

import (
	"io/fs"
	"strings"
	"testing"
)

const validPVEEnvironment = `# generated locally; values must never leave this node
PVE_READ_TOKEN_ID=ppflight-agent@pve!collector
PVE_READ_TOKEN_SECRET=01234567-89ab-cdef-0123-456789abcdef
PVE_CONTROL_TOKEN_ID=ppflight-control@pve!executor
PVE_CONTROL_TOKEN_SECRET=abcdef01-2345-6789-abcd-ef0123456789
`

func TestPVEEnvironmentStrictWhitelistAndEncoding(t *testing.T) {
	values, err := parsePVEEnvironment([]byte(validPVEEnvironment))
	if err != nil || values[PVEReadTokenIDEnv] != "ppflight-agent@pve!collector" {
		t.Fatalf("values=%v err=%v", values, err)
	}
	for _, invalid := range []string{
		validPVEEnvironment + "UNRELATED=value\n",
		strings.Replace(validPVEEnvironment, "PVE_READ_TOKEN_ID=", " PVE_READ_TOKEN_ID=", 1),
		strings.Replace(validPVEEnvironment, "PVE_READ_TOKEN_SECRET=", "PVE_READ_TOKEN_SECRET='", 1),
		strings.Replace(validPVEEnvironment, "PVE_READ_TOKEN_ID=", "PVE_READ_TOKEN_ID=duplicate@pve!token\nPVE_READ_TOKEN_ID=", 1),
		strings.Replace(validPVEEnvironment, "PVE_CONTROL_TOKEN_SECRET=abcdef01-2345-6789-abcd-ef0123456789\n", "", 1),
	} {
		if _, err := parsePVEEnvironment([]byte(invalid)); err == nil {
			t.Fatalf("unsafe environment accepted: %q", invalid)
		}
	}
}

func TestPVEEnvironmentMetadataFailsClosed(t *testing.T) {
	base := secureEnvironmentFile{contents: []byte(validPVEEnvironment), regular: true, ownerUID: 0, mode: fs.FileMode(0o600), linkCount: 1}
	if err := validateSecurePVEEnvironment(base); err != nil {
		t.Fatal(err)
	}
	cases := []secureEnvironmentFile{base, base, base, base}
	cases[0].regular = false
	cases[1].ownerUID = 1000
	cases[2].mode = 0o640
	cases[3].linkCount = 2
	for _, value := range cases {
		if err := validateSecurePVEEnvironment(value); err == nil {
			t.Fatalf("unsafe metadata accepted: %#v", value)
		}
	}
}

func TestPVEEnvironmentOverlayDoesNotMixCredentialSources(t *testing.T) {
	values, err := parsePVEEnvironment([]byte(validPVEEnvironment))
	if err != nil {
		t.Fatal(err)
	}
	base := func(name string) (string, bool) {
		if name == PVEReadTokenIDEnv {
			return "ambient@pve!token", true
		}
		if name == "OTHER" {
			return "preserved", true
		}
		return "", false
	}
	lookup := OverlayPVEEnvironment(base, values)
	if got, _ := lookup(PVEReadTokenIDEnv); got != values[PVEReadTokenIDEnv] {
		t.Fatal("ambient PVE value won over the validated file")
	}
	if got, _ := lookup("OTHER"); got != "preserved" {
		t.Fatal("unrelated environment was not delegated")
	}
}

func TestPVEEnvironmentLookupUsesFileForRootAndPID1EnvironmentForService(t *testing.T) {
	cfg, err := Parse([]byte(strings.Replace(validTestConfig(), `"source":"simulator"`, `"source":"api","endpoint":"https://127.0.0.1:8006","tokenIdEnv":"PVE_READ_TOKEN_ID","tokenSecretEnv":"PVE_READ_TOKEN_SECRET","tlsServerName":"pve.example.test"`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	fileValues, err := parsePVEEnvironment([]byte(validPVEEnvironment))
	if err != nil {
		t.Fatal(err)
	}
	ambient := func(name string) (string, bool) {
		values := map[string]string{PVEReadTokenIDEnv: "ambient@pve!token", PVEReadTokenSecretEnv: "ambient-secret-value"}
		value, ok := values[name]
		return value, ok
	}
	loaded := 0
	loader := func(path string) (map[string]string, error) {
		loaded++
		if path != DefaultPVEEnvironmentFile {
			t.Fatalf("path=%q", path)
		}
		return fileValues, nil
	}
	rootLookup, err := resolvePVEEnvironmentLookup(cfg, ambient, true, loader)
	if err != nil {
		t.Fatal(err)
	}
	if value, _ := rootLookup(PVEReadTokenIDEnv); value != fileValues[PVEReadTokenIDEnv] || loaded != 1 {
		t.Fatalf("root used ambient environment: value=%q loaded=%d", value, loaded)
	}
	serviceLookup, err := resolvePVEEnvironmentLookup(cfg, ambient, false, func(string) (map[string]string, error) {
		t.Fatal("service attempted to read root-only file")
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if value, _ := serviceLookup(PVEReadTokenIDEnv); value != "ambient@pve!token" {
		t.Fatalf("service environment not preserved: %q", value)
	}
	partial := func(name string) (string, bool) {
		if name == PVEReadTokenIDEnv {
			return "partial@pve!token", true
		}
		return "", false
	}
	if _, err := resolvePVEEnvironmentLookup(cfg, partial, false, loader); err == nil {
		t.Fatal("partial service-manager credential source was accepted")
	}
}
