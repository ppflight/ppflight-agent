//go:build linux

package fsutil

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

func ensureControlledSubdirectory(parent, name string, mode fs.FileMode) (string, error) {
	parentFD, parentStat, err := openLinuxDirectory(parent)
	if err != nil {
		return "", err
	}
	defer syscall.Close(parentFD)
	if err := syscall.Mkdirat(parentFD, name, uint32(mode.Perm())); err != nil && !errors.Is(err, syscall.EEXIST) {
		return "", err
	}
	childFD, err := syscall.Openat(parentFD, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return "", fmt.Errorf("refusing symlink controlled directory %q", name)
		}
		return "", err
	}
	defer syscall.Close(childFD)
	var childStat syscall.Stat_t
	if err := syscall.Fstat(childFD, &childStat); err != nil {
		return "", err
	}
	if childStat.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return "", fmt.Errorf("refusing non-directory controlled path %q", name)
	}
	desiredUID, desiredGID := uint32(os.Geteuid()), parentStat.Gid
	if childStat.Uid != desiredUID || childStat.Gid != desiredGID {
		if err := syscall.Fchown(childFD, int(desiredUID), int(desiredGID)); err != nil {
			return "", fmt.Errorf("set controlled directory ownership: %w", err)
		}
	}
	if childStat.Mode&0o777 != uint32(mode.Perm()) {
		if err := syscall.Fchmod(childFD, uint32(mode.Perm())); err != nil {
			return "", fmt.Errorf("set controlled directory mode: %w", err)
		}
	}
	if err := syscall.Fsync(parentFD); err != nil {
		return "", fmt.Errorf("sync controlled directory parent: %w", err)
	}
	return filepath.Join(parent, name), nil
}
