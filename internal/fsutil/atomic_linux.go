//go:build linux

package fsutil

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

func atomicWriteFile(directory, base string, contents []byte, mode fs.FileMode, preserveExistingMetadata bool) error {
	directoryFD, directoryStat, err := openLinuxDirectory(directory)
	if err != nil {
		return err
	}
	defer syscall.Close(directoryFD)

	existing, existingStat, err := openLinuxRegularAt(directoryFD, base)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if existing != nil {
		defer existing.Close()
	}

	metadata := directoryStat
	targetMode := mode.Perm()
	if preserveExistingMetadata && existingStat != nil {
		metadata = existingStat
		targetMode = fs.FileMode(existingStat.Mode & 0o777)
	}

	temporaryBase, temporary, err := createLinuxTemporary(directoryFD, directory)
	if err != nil {
		return err
	}
	renamed := false
	defer func() {
		_ = temporary.Close()
		if !renamed {
			_ = syscall.Unlinkat(directoryFD, temporaryBase)
		}
	}()

	if err := temporary.Chown(int(metadata.Uid), int(metadata.Gid)); err != nil {
		return fmt.Errorf("set atomic replacement ownership: %w", err)
	}
	if err := temporary.Chmod(targetMode); err != nil {
		return fmt.Errorf("set atomic replacement mode: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		return fmt.Errorf("write atomic replacement: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync atomic replacement: %w", err)
	}

	// Metadata is captured from an opened handle. Refuse the update if the
	// destination changed before rename, rather than applying stale metadata to
	// a different path. A final symlink swap is harmless (rename never follows
	// it), but this check also makes the expected rejection explicit.
	if err := verifyLinuxTargetUnchanged(directoryFD, base, existingStat); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close atomic replacement: %w", err)
	}
	if err := syscall.Renameat(directoryFD, temporaryBase, directoryFD, base); err != nil {
		return fmt.Errorf("rename atomic replacement: %w", err)
	}
	renamed = true
	if err := syscall.Fsync(directoryFD); err != nil {
		return fmt.Errorf("sync atomic replacement directory: %w", err)
	}
	return nil
}

func openRegularInDirectoryNoFollow(directory, base string) (*os.File, error) {
	directoryFD, _, err := openLinuxDirectory(directory)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(directoryFD)
	file, _, err := openLinuxRegularAt(directoryFD, base)
	return file, err
}

func openLinuxDirectory(directory string) (int, *syscall.Stat_t, error) {
	fd, err := syscall.Open(directory, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return -1, nil, fmt.Errorf("refusing symlink directory %q", directory)
		}
		return -1, nil, err
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		_ = syscall.Close(fd)
		return -1, nil, err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		_ = syscall.Close(fd)
		return -1, nil, fmt.Errorf("refusing non-directory %q", directory)
	}
	return fd, &stat, nil
}

func openLinuxRegularAt(directoryFD int, base string) (*os.File, *syscall.Stat_t, error) {
	fd, err := syscall.Openat(directoryFD, base, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, nil, fmt.Errorf("refusing symlink target %q", base)
		}
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), base)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, nil, errors.New("open atomic target handle")
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG {
		_ = file.Close()
		return nil, nil, fmt.Errorf("refusing non-regular target %q", base)
	}
	return file, &stat, nil
}

func createLinuxTemporary(directoryFD int, directory string) (string, *os.File, error) {
	for attempts := 0; attempts < 128; attempts++ {
		base, err := atomicTemporaryBase()
		if err != nil {
			return "", nil, err
		}
		fd, err := syscall.Openat(directoryFD, base, syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
		if errors.Is(err, syscall.EEXIST) {
			continue
		}
		if err != nil {
			return "", nil, err
		}
		file := os.NewFile(uintptr(fd), filepath.Join(directory, base))
		if file == nil {
			_ = syscall.Close(fd)
			return "", nil, errors.New("create atomic replacement handle")
		}
		return base, file, nil
	}
	return "", nil, errors.New("could not allocate an atomic replacement name")
}

func verifyLinuxTargetUnchanged(directoryFD int, base string, original *syscall.Stat_t) error {
	current, stat, err := openLinuxRegularAt(directoryFD, base)
	if current != nil {
		defer current.Close()
	}
	if original == nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		return errors.New("atomic target appeared during update")
	}
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("atomic target disappeared during update")
		}
		return err
	}
	if stat.Dev != original.Dev || stat.Ino != original.Ino {
		return errors.New("atomic target changed during update")
	}
	return nil
}
