package fsutil

import (
	"path/filepath"
	"testing"
)

func TestAcquireExclusivePreventsSecondOwner(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "agent.lock")
	first, err := AcquireExclusive(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := AcquireExclusive(filename); err == nil {
		t.Fatal("second owner acquired an active lock")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := AcquireExclusive(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
}
