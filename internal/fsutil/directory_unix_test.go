//go:build unix

package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsurePrivateDirectoryRejectsSymlinkAndUnsafePermissions(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "state-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateDirectory(link); err == nil {
		t.Fatal("state directory symlink was accepted")
	}
	unsafe := filepath.Join(root, "unsafe")
	if err := os.Mkdir(unsafe, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateDirectory(unsafe); err == nil {
		t.Fatal("group/world-writable state directory was accepted")
	}
}
