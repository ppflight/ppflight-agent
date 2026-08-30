//go:build windows

package fsutil

import (
	"os"
	"syscall"
	"unsafe"
)

const (
	lockfileFailImmediately = 0x00000001
	lockfileExclusiveLock   = 0x00000002
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = kernel32.NewProc("LockFileEx")
	procUnlockFileEx = kernel32.NewProc("UnlockFileEx")
)

func lockExclusive(file *os.File) error { return lockFile(file, false) }

func tryLockExclusive(file *os.File) error { return lockFile(file, true) }

func lockFile(file *os.File, immediate bool) error {
	flags := uintptr(lockfileExclusiveLock)
	if immediate {
		flags |= lockfileFailImmediately
	}
	var overlap syscall.Overlapped
	ok, _, err := procLockFileEx.Call(file.Fd(), flags, 0, 1, 0, uintptr(unsafe.Pointer(&overlap)))
	if ok == 0 {
		return err
	}
	return nil
}

func unlock(file *os.File) error {
	var overlap syscall.Overlapped
	ok, _, err := procUnlockFileEx.Call(file.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&overlap)))
	if ok == 0 {
		return err
	}
	return nil
}
