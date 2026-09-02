//go:build unix

package admincli

import (
	"os"
	"syscall"
)

func templateBridgeFileOwnedByRoot(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0
}

func templateBridgeFileModeSecure(info os.FileInfo) bool {
	return info.Mode().Perm()&0o022 == 0
}
