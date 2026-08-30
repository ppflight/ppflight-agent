//go:build unix

package fsutil

import "os"

// SyncDir makes a preceding rename durable on filesystems that support it.
func SyncDir(directory string) error {
	handle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}
