//go:build windows

package fsutil

import "io/fs"

// Windows permissions are ACL based, not represented faithfully in FileMode.
func checkPrivateDirectoryMode(fs.FileInfo) error { return nil }
