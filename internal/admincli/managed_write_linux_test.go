//go:build linux

package admincli

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/ppflight/ppflight-agent/internal/config"
)

func TestRootManagementWriteGateRejectsForeignConfigUnlessExplicitlyInjected(t *testing.T) {
	cfg := config.Config{Runtime: config.RuntimeConfig{StateDirectory: filepath.Join(t.TempDir(), "state")}}
	instance := &cli{effectiveUID: func() int { return 0 }}
	if err := instance.requireManagedWriteTarget(filepath.Join(t.TempDir(), "agent.yaml"), cfg); err == nil {
		t.Fatal("root management write accepted a foreign --config/state path")
	}
	instance.managedWritePolicy = func(string, config.Config) error { return nil }
	if err := instance.requireManagedWriteTarget(filepath.Join(t.TempDir(), "agent.yaml"), cfg); err != nil {
		t.Fatalf("explicit test injection was not honored: %v", err)
	}
}

func TestInstalledConfigDirectoryValidationRejectsWritableMode(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned temporary directory")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o770); err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Open(directory, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	if err := validateRootDirectoryFD(fd, os.Getgid(), true, directory); err == nil {
		t.Fatal("group-writable production configuration directory was accepted")
	}
}
