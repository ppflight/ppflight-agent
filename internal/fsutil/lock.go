// Package fsutil contains small cross-platform filesystem safety helpers.
package fsutil

import (
	"fmt"
	"os"
	"sync"
)

// Lock serializes access to a file. Closing it releases the operating-system
// lock, so it remains safe when the process exits unexpectedly.
type Lock struct {
	file *os.File
	once sync.Once
	err  error
}

// AcquireExclusive acquires a non-blocking exclusive lock on filename.
// Call Close when the protected lifecycle ends.
func AcquireExclusive(filename string) (*Lock, error) {
	if info, err := os.Lstat(filename); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return nil, fmt.Errorf("refusing unsafe lock file %q", filename)
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := tryLockExclusive(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &Lock{file: file}, nil
}

// LockExclusive acquires a blocking exclusive lock. It is useful for short
// transactional updates such as replacing a configuration file.
func LockExclusive(file *os.File) error { return lockExclusive(file) }

// Unlock releases a lock previously acquired with LockExclusive.
func Unlock(file *os.File) error { return unlock(file) }

// Close releases the lock and closes the backing file.
func (l *Lock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	l.once.Do(func() {
		l.err = unlock(l.file)
		if err := l.file.Close(); l.err == nil {
			l.err = err
		}
	})
	return l.err
}
