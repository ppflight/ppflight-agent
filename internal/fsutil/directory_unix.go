//go:build unix

package fsutil

import (
	"errors"
	"io/fs"
)

func checkPrivateDirectoryMode(info fs.FileInfo) error {
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("directory must not be writable by group or other users")
	}
	return nil
}
