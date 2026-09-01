//go:build windows

package hostfirewall

import "os"

func ownedByRoot(os.FileInfo) bool { return false }

func effectiveUID() int { return -1 }

func syncDirectory(*os.File) error { return nil }
