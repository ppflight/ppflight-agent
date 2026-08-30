//go:build unix

package fsutil

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// CopyOwnership applies the source file owner to target where supported.
func CopyOwnership(target string, source fs.FileInfo) error {
	file, err := OpenRegularInDirectoryNoFollow(filepath.Dir(target), filepath.Base(target))
	if err != nil {
		return err
	}
	defer file.Close()
	return CopyOwnershipToFile(file, source)
}

// CopyOwnershipToFile applies source ownership through an already-open target
// descriptor, avoiding path-based chown races.
func CopyOwnershipToFile(target *os.File, source fs.FileInfo) error {
	stat, ok := source.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	return target.Chown(int(stat.Uid), int(stat.Gid))
}
