//go:build windows

package fsutil

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

func ensureControlledSubdirectory(parent, name string, mode fs.FileMode) (string, error) {
	parentHandle, parentInfo, err := openWindowsNoFollow(parent, true)
	if err != nil {
		return "", err
	}
	defer parentHandle.Close()
	child := filepath.Join(parent, name)
	if err := os.Mkdir(child, mode); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	childHandle, _, err := openWindowsNoFollow(child, true)
	if err != nil {
		return "", err
	}
	defer childHandle.Close()
	if err := childHandle.Chmod(mode); err != nil {
		return "", err
	}
	currentParent, currentParentInfo, err := openWindowsNoFollow(parent, true)
	if err != nil {
		return "", err
	}
	_ = currentParent.Close()
	if !os.SameFile(parentInfo, currentParentInfo) {
		return "", errors.New("controlled directory parent changed during creation")
	}
	return child, nil
}
