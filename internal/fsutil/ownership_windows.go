//go:build windows

package fsutil

import (
	"io/fs"
	"os"
)

// CopyOwnership has no portable Windows equivalent for the POSIX owner IDs.
func CopyOwnership(string, fs.FileInfo) error { return nil }

// CopyOwnershipToFile has no portable Windows equivalent for POSIX IDs.
func CopyOwnershipToFile(*os.File, fs.FileInfo) error { return nil }
