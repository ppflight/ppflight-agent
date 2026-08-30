//go:build !linux

package selfupdate

import (
	"errors"
	"os"
)

func openNoFollow(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, os.ErrInvalid
	}
	return os.Open(path)
}

func validateUpgradeRoot(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o027 != 0 {
		return errors.New("upgrade root directory is unsafe")
	}
	return nil
}
