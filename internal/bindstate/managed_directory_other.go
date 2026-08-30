//go:build !linux

package bindstate

import (
	"io/fs"

	"github.com/ppflight/ppflight-agent/internal/fsutil"
)

func ensureBindingDirectoryPlatform(stateDirectory string) (string, error) {
	return fsutil.EnsureControlledSubdirectory(stateDirectory, bindingDirectoryName, 0o750)
}

// ValidateInstalledStateRoot is a Linux production hardening check. Other
// platforms do not run the root-owned PVE service manager.
func ValidateInstalledStateRoot(string) error { return nil }

func checkManagedPrivateFileMetadata(string, fs.FileInfo) error { return nil }
