//go:build windows

package fsutil

// SyncDir is a no-op because Windows cannot fsync directory handles in the
// same way as Linux. File contents are still synced before rename.
func SyncDir(string) error { return nil }
