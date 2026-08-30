//go:build unix && !linux

package fsutil

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

func atomicWriteFile(directory, base string, contents []byte, mode fs.FileMode, preserveExistingMetadata bool) error {
	directoryHandle, directoryInfo, err := openPortableNoFollow(directory, true)
	if err != nil {
		return err
	}
	defer directoryHandle.Close()

	target := filepath.Join(directory, base)
	existing, existingInfo, err := openPortableNoFollow(target, false)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if existing != nil {
		defer existing.Close()
	}
	metadata := directoryInfo
	targetMode := mode.Perm()
	if preserveExistingMetadata && existingInfo != nil {
		metadata = existingInfo
		targetMode = existingInfo.Mode().Perm()
	}

	temporaryBase, temporary, err := createPortableTemporary(directory)
	if err != nil {
		return err
	}
	temporaryName := filepath.Join(directory, temporaryBase)
	renamed := false
	defer func() {
		_ = temporary.Close()
		if !renamed {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := CopyOwnershipToFile(temporary, metadata); err != nil {
		return fmt.Errorf("set atomic replacement ownership: %w", err)
	}
	if err := temporary.Chmod(targetMode); err != nil {
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}

	currentDirectory, currentDirectoryInfo, err := openPortableNoFollow(directory, true)
	if err != nil {
		return err
	}
	_ = currentDirectory.Close()
	if !os.SameFile(directoryInfo, currentDirectoryInfo) {
		return errors.New("atomic target directory changed during update")
	}
	if err := verifyPortableTargetUnchanged(target, existingInfo); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, target); err != nil {
		return err
	}
	renamed = true
	return SyncDir(directory)
}

func openRegularInDirectoryNoFollow(directory, base string) (*os.File, error) {
	directoryHandle, directoryInfo, err := openPortableNoFollow(directory, true)
	if err != nil {
		return nil, err
	}
	defer directoryHandle.Close()
	file, _, err := openPortableNoFollow(filepath.Join(directory, base), false)
	if err != nil {
		return nil, err
	}
	currentDirectory, currentDirectoryInfo, err := openPortableNoFollow(directory, true)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	_ = currentDirectory.Close()
	if !os.SameFile(directoryInfo, currentDirectoryInfo) {
		_ = file.Close()
		return nil, errors.New("regular file directory changed while opening")
	}
	return file, nil
}

func openPortableNoFollow(filename string, directory bool) (*os.File, os.FileInfo, error) {
	before, err := os.Lstat(filename)
	if err != nil {
		return nil, nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("refusing symlink path %q", filename)
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, nil, err
	}
	after, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !os.SameFile(before, after) {
		_ = file.Close()
		return nil, nil, fmt.Errorf("path changed while opening %q", filename)
	}
	if directory && !after.IsDir() {
		_ = file.Close()
		return nil, nil, fmt.Errorf("refusing non-directory %q", filename)
	}
	if !directory && !after.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, fmt.Errorf("refusing non-regular file %q", filename)
	}
	return file, after, nil
}

func verifyPortableTargetUnchanged(filename string, original os.FileInfo) error {
	current, currentInfo, err := openPortableNoFollow(filename, false)
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
	if !os.SameFile(original, currentInfo) {
		return errors.New("atomic target changed during update")
	}
	return nil
}
