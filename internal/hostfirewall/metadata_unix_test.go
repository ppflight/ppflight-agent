//go:build !windows

package hostfirewall

import (
	"context"
	"errors"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestProcessFlockWaitIsBoundedByContext(t *testing.T) {
	path := t.TempDir() + "/lock"
	first, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := syscall.Flock(int(first.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(first.Fd()), syscall.LOCK_UN)

	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	if err := flockWithContext(ctx, int(second.Fd())); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("contended flock error=%v, want deadline", err)
	}
	if err := syscall.Flock(int(first.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := flockWithContext(context.Background(), int(second.Fd())); err != nil {
		t.Fatalf("flock did not recover after release: %v", err)
	}
	_ = syscall.Flock(int(second.Fd()), syscall.LOCK_UN)
}
