package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWriteFileRejectsSymlinkTarget(t *testing.T) {
	directory := t.TempDir()
	realTarget := filepath.Join(directory, "real.json")
	if err := os.WriteFile(realTarget, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "state.json")
	if err := os.Symlink(realTarget, symlink); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := AtomicWriteFile(symlink, []byte("new"), 0o640, false); err == nil {
		t.Fatal("atomic writer accepted a symlink target")
	}
	contents, err := os.ReadFile(realTarget)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "old" {
		t.Fatalf("symlink destination was modified: %q", contents)
	}
}

func TestAtomicWriteFileRejectsSymlinkDirectory(t *testing.T) {
	root := t.TempDir()
	realDirectory := filepath.Join(root, "real")
	if err := os.Mkdir(realDirectory, 0o750); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "redirected")
	if err := os.Symlink(realDirectory, symlink); err != nil {
		t.Skipf("directory symlink unavailable: %v", err)
	}
	if err := AtomicWriteFile(filepath.Join(symlink, "state.json"), []byte("new"), 0o640, false); err == nil {
		t.Fatal("atomic writer accepted a symlink directory")
	}
	if _, err := os.Stat(filepath.Join(realDirectory, "state.json")); !os.IsNotExist(err) {
		t.Fatalf("redirected directory was modified: %v", err)
	}
}
