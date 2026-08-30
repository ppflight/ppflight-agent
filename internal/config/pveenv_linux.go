//go:build linux

package config

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

func openSecurePVEEnvironment(filename string, maxBytes int64) (secureEnvironmentFile, error) {
	fd, err := syscall.Open(filename, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return secureEnvironmentFile{}, fmt.Errorf("open PVE environment: %w", err)
	}
	file := os.NewFile(uintptr(fd), filename)
	if file == nil {
		_ = syscall.Close(fd)
		return secureEnvironmentFile{}, fmt.Errorf("open PVE environment: invalid file descriptor")
	}
	defer file.Close()
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return secureEnvironmentFile{}, fmt.Errorf("stat PVE environment: %w", err)
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return secureEnvironmentFile{}, fmt.Errorf("read PVE environment: %w", err)
	}
	return secureEnvironmentFile{
		contents: contents, mode: os.FileMode(stat.Mode), ownerUID: stat.Uid,
		linkCount: uint64(stat.Nlink), regular: stat.Mode&syscall.S_IFMT == syscall.S_IFREG,
	}, nil
}

func pveEnvironmentRunningAsRoot() bool { return os.Geteuid() == 0 }
