//go:build !windows

package hostfirewall

import (
	"os"
	"syscall"
)

func ownedByRoot(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0
}

func effectiveUID() int {
	return os.Geteuid()
}

func syncDirectory(directory *os.File) error { return directory.Sync() }
