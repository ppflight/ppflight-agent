package fsutil

import (
	"fmt"
	"os"
)

// EnsurePrivateDirectory creates directory when needed and rejects a symlink,
// a non-directory, or a directory writable by group or other users. Checking
// the final directory avoids trusting a redirected state root.
func EnsurePrivateDirectory(directory string) error {
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("refusing unsafe state directory %q", directory)
	}
	if err := checkPrivateDirectoryMode(info); err != nil {
		return fmt.Errorf("unsafe state directory %q: %w", directory, err)
	}
	return nil
}
