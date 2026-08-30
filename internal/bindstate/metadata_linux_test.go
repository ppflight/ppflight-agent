//go:build linux

package bindstate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestWriteAssignmentCreatesServiceOwnedGroupReadableFile(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(directory, "assignments.json")
	if err := WriteAssignment(filename, json.RawMessage(`{"schemaVersion":1}`)); err != nil {
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
		t.Fatalf("new assignment mode = %o", fileInfo.Mode().Perm())
	}
	if fileStat.Uid != directoryStat.Uid || fileStat.Gid != directoryStat.Gid {
		t.Fatalf("new assignment ownership = %d:%d, directory = %d:%d", fileStat.Uid, fileStat.Gid, directoryStat.Uid, directoryStat.Gid)
	}
}
