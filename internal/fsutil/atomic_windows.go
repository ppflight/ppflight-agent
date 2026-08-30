//go:build windows

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
	directoryHandle, directoryInfo, err := openWindowsNoFollow(directory, true)
	if err != nil {
		return err
	}
	defer directoryHandle.Close()

	target := filepath.Join(directory, base)
	existing, existingInfo, err := openWindowsNoFollow(target, false)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if existing != nil {
		if err := existing.Close(); err != nil {
			return err
		}
	}
	targetMode := mode.Perm()
	if preserveExistingMetadata && existingInfo != nil {
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

	// Path-based creation is retained for Windows development builds, but the
	// opened directory identity must still match and reparse points are always
	// rejected.
	currentDirectory, currentDirectoryInfo, err := openWindowsNoFollow(directory, true)
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
	directoryHandle, directoryInfo, err := openWindowsNoFollow(directory, true)
	if err != nil {
		return nil, err
	}
	defer directoryHandle.Close()
	file, _, err := openWindowsNoFollow(filepath.Join(directory, base), false)
	if err != nil {
		return nil, err
	}
	currentDirectory, currentDirectoryInfo, err := openWindowsNoFollow(directory, true)
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

func openWindowsNoFollow(filename string, directory bool) (*os.File, os.FileInfo, error) {
	path, err := syscall.UTF16PtrFromString(filename)
	if err != nil {
		return nil, nil, err
	}
	flags := uint32(syscall.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= syscall.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := syscall.CreateFile(path, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, flags, 0)
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(handle), filename)
	if file == nil {
		_ = syscall.CloseHandle(handle)
		return nil, nil, errors.New("open Windows file handle")
	}
	var handleInfo syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &handleInfo); err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if handleInfo.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = file.Close()
		return nil, nil, fmt.Errorf("refusing Windows reparse point %q", filename)
	}
	isDirectory := handleInfo.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY != 0
	if directory != isDirectory {
		_ = file.Close()
		return nil, nil, fmt.Errorf("refusing unexpected file type %q", filename)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !directory && !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, fmt.Errorf("refusing non-regular file %q", filename)
	}
	return file, info, nil
}

func verifyPortableTargetUnchanged(filename string, original os.FileInfo) error {
	current, currentInfo, err := openWindowsNoFollow(filename, false)
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
