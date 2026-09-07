package templatecompat

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type migrationFixture struct {
	t             *testing.T
	configDir     string
	snippetDir    string
	currentConfig map[int]string
	volumePaths   map[string]string
	failSetVMID   int
	setCalls      []int
}

func newMigrationFixture(t *testing.T) *migrationFixture {
	t.Helper()
	root := t.TempDir()
	return &migrationFixture{
		t: t, configDir: filepath.Join(root, "qemu-server"), snippetDir: filepath.Join(root, "snippets"),
		currentConfig: map[int]string{}, volumePaths: map[string]string{},
	}
}

func (f *migrationFixture) add(vmid int, content []byte) (string, string) {
	f.t.Helper()
	if err := os.MkdirAll(f.configDir, 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.MkdirAll(f.snippetDir, 0o755); err != nil {
		f.t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	name := "ppflight-debian-" + digest + ".yaml"
	volume := "local:snippets/" + name
	path := filepath.Join(f.snippetDir, name)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		f.t.Fatal(err)
	}
	cicustom := "vendor=" + volume
	f.currentConfig[vmid] = cicustom
	f.volumePaths[volume] = path
	if err := os.WriteFile(filepath.Join(f.configDir, strconv.Itoa(vmid)+".conf"), []byte("template: 1\ncicustom: "+cicustom+"\n"), 0o600); err != nil {
		f.t.Fatal(err)
	}
	return volume, path
}

func (f *migrationFixture) run(_ context.Context, name string, args ...string) (string, error) {
	switch {
	case name == "/usr/bin/pvesm" && len(args) == 2 && args[0] == "path":
		path, ok := f.volumePaths[args[1]]
		if !ok {
			return "", errors.New("unknown volume")
		}
		return path + "\n", nil
	case name == "/usr/sbin/qm" && len(args) == 2 && args[0] == "config":
		vmid, _ := strconv.Atoi(args[1])
		return "template: 1\ncicustom: " + f.currentConfig[vmid] + "\n", nil
	case name == "/usr/sbin/qm" && len(args) == 4 && args[0] == "set" && args[2] == "--cicustom":
		vmid, _ := strconv.Atoi(args[1])
		f.setCalls = append(f.setCalls, vmid)
		if vmid == f.failSetVMID {
			return "", errors.New("injected qm set failure")
		}
		f.currentConfig[vmid] = args[3]
		return "", nil
	default:
		return "", fmt.Errorf("unexpected command %s %v", name, args)
	}
}

func TestMigrateLegacyTemplateTimezonesCreatesContentAddressedSuccessor(t *testing.T) {
	fixture := newMigrationFixture(t)
	content := []byte("#cloud-config\ndisable_root: false\ntimezone: UTC\nntp:\n  enabled: true\n")
	oldVolume, oldPath := fixture.add(9000, content)
	m := &migrator{configDirectory: fixture.configDir, run: fixture.run}
	report, err := m.migrate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Scanned != 1 || report.Migrated != 1 || len(report.VMIDs) != 1 || report.VMIDs[0] != 9000 {
		t.Fatalf("report=%#v", report)
	}
	if _, err := os.Stat(oldPath); err != nil {
		t.Fatalf("original snippet was not retained: %v", err)
	}
	newCICustom := fixture.currentConfig[9000]
	if newCICustom == "vendor="+oldVolume || !strings.HasPrefix(newCICustom, "vendor=local:snippets/ppflight-debian-") {
		t.Fatalf("new cicustom=%q", newCICustom)
	}
	newName := strings.TrimPrefix(newCICustom, "vendor=local:snippets/")
	newContent, err := os.ReadFile(filepath.Join(fixture.snippetDir, newName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(newContent), "timezone:") || !strings.Contains(string(newContent), "ntp:") {
		t.Fatalf("sanitized content=%q", newContent)
	}
}

func TestMigrateLegacyTemplateTimezonesAcceptsPVECompatibilitySymlink(t *testing.T) {
	fixture := newMigrationFixture(t)
	root := filepath.Dir(fixture.configDir)
	realConfigDir := filepath.Join(root, "nodes", "pve", "qemu-server")
	if err := os.MkdirAll(realConfigDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("nodes/pve/qemu-server", fixture.configDir); err != nil {
		t.Fatal(err)
	}
	fixture.add(9000, []byte("#cloud-config\ntimezone: UTC\n"))

	report, err := (&migrator{configDirectory: fixture.configDir, run: fixture.run}).migrate(context.Background())
	if err != nil {
		t.Fatalf("migrate through PVE compatibility symlink: %v", err)
	}
	if report.Migrated != 1 || len(report.VMIDs) != 1 || report.VMIDs[0] != 9000 {
		t.Fatalf("unexpected report: %#v", report)
	}
}

func TestResolvePVEQEMUConfigDirectoryRejectsUnexpectedSymlink(t *testing.T) {
	for name, target := range map[string]string{
		"absolute":       "/etc/pve/nodes/pve/qemu-server",
		"traversal":      "nodes/../pve/qemu-server",
		"wrong prefix":   "local/pve/qemu-server",
		"wrong basename": "nodes/pve/lxc",
		"invalid node":   "nodes/pve node/qemu-server",
	} {
		t.Run(name, func(t *testing.T) {
			link := filepath.Join(t.TempDir(), "qemu-server")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			if _, err := resolvePVEQEMUConfigDirectory(link); err == nil {
				t.Fatalf("unexpected symlink target %q was accepted", target)
			}
		})
	}
}

func TestResolvePVEQEMUConfigDirectoryRejectsIntermediateSymlink(t *testing.T) {
	root := t.TempDir()
	realNodes := filepath.Join(root, "real-nodes")
	if err := os.MkdirAll(filepath.Join(realNodes, "pve", "qemu-server"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real-nodes", filepath.Join(root, "nodes")); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "qemu-server")
	if err := os.Symlink("nodes/pve/qemu-server", link); err != nil {
		t.Fatal(err)
	}
	if _, err := resolvePVEQEMUConfigDirectory(link); err == nil {
		t.Fatal("intermediate symlink was accepted")
	}
}

func TestMigrateLegacyTemplateTimezonesRejectsConfigSymlinkBeforeMutation(t *testing.T) {
	fixture := newMigrationFixture(t)
	if err := os.MkdirAll(fixture.configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.conf")
	if err := os.WriteFile(outside, []byte("template: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(fixture.configDir, "9000.conf")); err != nil {
		t.Fatal(err)
	}
	if _, err := (&migrator{configDirectory: fixture.configDir, run: fixture.run}).migrate(context.Background()); err == nil {
		t.Fatal("symlink QEMU config was accepted")
	}
	if len(fixture.setCalls) != 0 {
		t.Fatalf("unsafe migration mutated templates: %v", fixture.setCalls)
	}
}

func TestMigrateLegacyTemplateTimezonesRejectsHashMismatchBeforeMutation(t *testing.T) {
	fixture := newMigrationFixture(t)
	_, source := fixture.add(9000, []byte("#cloud-config\ntimezone: UTC\n"))
	if err := os.WriteFile(source, []byte("#cloud-config\ntimezone: Europe/Berlin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &migrator{configDirectory: fixture.configDir, run: fixture.run}
	if _, err := m.migrate(context.Background()); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("error=%v", err)
	}
	if len(fixture.setCalls) != 0 {
		t.Fatalf("unsafe migration mutated templates: %v", fixture.setCalls)
	}
}

func TestMigrateLegacyTemplateTimezonesRollsBackEarlierSwitches(t *testing.T) {
	fixture := newMigrationFixture(t)
	oldFirst, _ := fixture.add(9000, []byte("#cloud-config\ntimezone: UTC\nfirst: true\n"))
	oldSecond, _ := fixture.add(9001, []byte("#cloud-config\ntimezone: UTC\nsecond: true\n"))
	fixture.failSetVMID = 9001
	m := &migrator{configDirectory: fixture.configDir, run: fixture.run}
	if _, err := m.migrate(context.Background()); err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("error=%v", err)
	}
	if fixture.currentConfig[9000] != "vendor="+oldFirst || fixture.currentConfig[9001] != "vendor="+oldSecond {
		t.Fatalf("configs after rollback=%v", fixture.currentConfig)
	}
}
