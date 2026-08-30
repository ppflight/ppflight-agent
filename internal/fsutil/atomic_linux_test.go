//go:build linux

package fsutil

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestAtomicWriteFileInheritsOpenedDirectoryOwnership(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(directory, "binding-state.json")
	if err := AtomicWriteFile(filename, []byte("first"), 0o640, false); err != nil {
		t.Fatal(err)
	}
	directoryInfo, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	fileInfo, err := os.Stat(filename)
	if err != nil {
		t.Fatal(err)
	}
	directoryStat := directoryInfo.Sys().(*syscall.Stat_t)
	fileStat := fileInfo.Sys().(*syscall.Stat_t)
	if fileInfo.Mode().Perm() != 0o640 {
		t.Fatalf("atomic file mode = %o", fileInfo.Mode().Perm())
	}
	if fileStat.Uid != directoryStat.Uid || fileStat.Gid != directoryStat.Gid {
		t.Fatalf("atomic file ownership = %d:%d, directory = %d:%d", fileStat.Uid, fileStat.Gid, directoryStat.Uid, directoryStat.Gid)
	}
}

func TestAtomicWriteFilePreservesOpenedTargetMetadata(t *testing.T) {
	directory := t.TempDir()
	filename := filepath.Join(directory, "assignments.json")
	if err := os.WriteFile(filename, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filename, 0o604); err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Stat(filename)
	if err != nil {
		t.Fatal(err)
	}
	before := beforeInfo.Sys().(*syscall.Stat_t)
	if err := AtomicWriteFile(filename, []byte("new"), 0o640, true); err != nil {
		t.Fatal(err)
	}
	afterInfo, err := os.Stat(filename)
	if err != nil {
		t.Fatal(err)
	}
	after := afterInfo.Sys().(*syscall.Stat_t)
	if afterInfo.Mode().Perm() != 0o604 {
		t.Fatalf("atomic file mode = %o, want preserved 604", afterInfo.Mode().Perm())
	}
	if after.Uid != before.Uid || after.Gid != before.Gid {
		t.Fatalf("atomic file ownership changed from %d:%d to %d:%d", before.Uid, before.Gid, after.Uid, after.Gid)
	}
}

func TestControlledSubdirectoryUsesCallerAndParentGroup(t *testing.T) {
	parent := t.TempDir()
	child, err := EnsureControlledSubdirectory(parent, "bindings", 0o750)
	if err != nil {
		t.Fatal(err)
	}
	parentInfo, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	childInfo, err := os.Stat(child)
	if err != nil {
		t.Fatal(err)
	}
	parentStat := parentInfo.Sys().(*syscall.Stat_t)
	childStat := childInfo.Sys().(*syscall.Stat_t)
	if childInfo.Mode().Perm() != 0o750 {
		t.Fatalf("controlled directory mode = %o", childInfo.Mode().Perm())
	}
	if childStat.Uid != uint32(os.Geteuid()) || childStat.Gid != parentStat.Gid {
		t.Fatalf("controlled directory ownership = %d:%d, want %d:%d", childStat.Uid, childStat.Gid, os.Geteuid(), parentStat.Gid)
	}
}

func TestCopyOwnershipRejectsSymlinkTarget(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source")
	realTarget := filepath.Join(directory, "target")
	if err := os.WriteFile(source, []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(realTarget, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	sourceInfo, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "target-link")
	if err := os.Symlink(realTarget, symlink); err != nil {
		t.Fatal(err)
	}
	if err := CopyOwnership(symlink, sourceInfo); err == nil {
		t.Fatal("CopyOwnership accepted a symlink target")
	}
}
