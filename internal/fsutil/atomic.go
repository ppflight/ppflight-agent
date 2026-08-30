package fsutil

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// AtomicWriteFile durably replaces filename without following a symlink at
// the destination. The temporary file is created in the destination
// directory, synced, and renamed over the old file.
//
// When preserveExistingMetadata is true, an existing regular target supplies
// the replacement's owner, group, and permission bits. Otherwise, or when the
// target does not yet exist, owner and group are inherited from the opened
// destination directory and mode supplies the permission bits. Ownership is
// always applied through the temporary file descriptor, never by path.
func AtomicWriteFile(filename string, contents []byte, mode fs.FileMode, preserveExistingMetadata bool) error {
	directory, base, err := atomicTarget(filename)
	if err != nil {
		return err
	}
	if mode.Perm() == 0 || mode != mode.Perm() {
		return errors.New("atomic file mode must contain permission bits only")
	}
	return atomicWriteFile(directory, base, contents, mode, preserveExistingMetadata)
}

// OpenRegularInDirectoryNoFollow opens base relative to an existing directory
// while refusing a symlink or Windows reparse point for both the directory and
// final file. base must contain exactly one path component.
func OpenRegularInDirectoryNoFollow(directory, base string) (*os.File, error) {
	if base == "" || base == "." || base == ".." || filepath.Base(base) != base {
		return nil, errors.New("regular file name must be one path component")
	}
	return openRegularInDirectoryNoFollow(directory, base)
}

func atomicTarget(filename string) (string, string, error) {
	if filename == "" {
		return "", "", errors.New("atomic target path is empty")
	}
	cleaned := filepath.Clean(filename)
	base := filepath.Base(cleaned)
	if base == "." || base == ".." || base == string(filepath.Separator) || base == "" {
		return "", "", errors.New("atomic target must name a file")
	}
	return filepath.Dir(cleaned), base, nil
}

func atomicTemporaryBase() (string, error) {
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return ".ppflight-" + hex.EncodeToString(random) + ".tmp", nil
}

func createPortableTemporary(directory string) (string, *os.File, error) {
	for attempts := 0; attempts < 128; attempts++ {
		base, err := atomicTemporaryBase()
		if err != nil {
			return "", nil, err
		}
		file, err := os.OpenFile(filepath.Join(directory, base), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", nil, err
		}
		return base, file, nil
	}
	return "", nil, errors.New("could not allocate an atomic replacement name")
}
