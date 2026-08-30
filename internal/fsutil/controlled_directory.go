package fsutil

import (
	"errors"
	"io/fs"
	"path/filepath"
)

// EnsureControlledSubdirectory creates a single child below parent and pins
// its permission bits. On Linux, the child is owned by the caller and inherits
// the parent directory's group. This lets a root-run administrative command
// create root-owned state that a service group can read without making the
// directory group-writable.
func EnsureControlledSubdirectory(parent, name string, mode fs.FileMode) (string, error) {
	if parent == "" {
		return "", errors.New("controlled directory parent is empty")
	}
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return "", errors.New("controlled directory name must be one path component")
	}
	if mode.Perm() == 0 || mode != mode.Perm() || mode.Perm()&0o022 != 0 {
		return "", errors.New("controlled directory mode must not grant group or other write access")
	}
	if err := EnsurePrivateDirectory(parent); err != nil {
		return "", err
	}
	return ensureControlledSubdirectory(parent, name, mode.Perm())
}
