//go:build unix

package bindstate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestWriteAssignmentPreservesExistingOwnershipAndMode(t *testing.T) {
	directory := t.TempDir()
	filename := filepath.Join(directory, "assignments.json")
	if err := os.WriteFile(filename, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filename, 0o644); err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Stat(filename)
	if err != nil {
		t.Fatal(err)
	}
	before := beforeInfo.Sys().(*syscall.Stat_t)
	if err := WriteAssignment(filename, json.RawMessage(`{"schemaVersion":1}`)); err != nil {
		t.Fatal(err)
	}
	afterInfo, err := os.Stat(filename)
	if err != nil {
		t.Fatal(err)
	}
	after := afterInfo.Sys().(*syscall.Stat_t)
	if afterInfo.Mode().Perm() != 0o644 {
		t.Fatalf("assignment mode = %o, want preserved 644", afterInfo.Mode().Perm())
	}
	if before.Uid != after.Uid || before.Gid != after.Gid {
		t.Fatalf("assignment ownership changed from %d:%d to %d:%d", before.Uid, before.Gid, after.Uid, after.Gid)
	}
}
