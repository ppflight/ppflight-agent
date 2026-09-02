//go:build !unix

package admincli

import "os"

// Production PVE runs on Linux. Non-Unix builds exist for contract tests; they
// cannot expose a Unix UID through os.FileInfo.Sys().
func templateBridgeFileOwnedByRoot(os.FileInfo) bool { return true }

func templateBridgeFileModeSecure(os.FileInfo) bool { return true }
