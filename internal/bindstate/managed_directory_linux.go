//go:build linux

package bindstate

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/ppflight/ppflight-agent/internal/fsutil"
)

// installedStateDirectory is intentionally not configurable for root-managed
// production mutations.  The general Agent runtime has other state below this
// root, but binding credentials are always kept in this installer-owned path.
const installedStateDirectory = "/var/lib/ppflight-agent"

func ensureBindingDirectoryPlatform(stateDirectory string) (string, error) {
	if filepath.Clean(stateDirectory) != installedStateDirectory {
		return fsutil.EnsureControlledSubdirectory(stateDirectory, bindingDirectoryName, 0o750)
	}
	return ensureInstalledBindingDirectory()
}

// ValidateInstalledStateRoot verifies the fixed root without creating or
// repairing it.  It is used by root command entrypoints before they trust a
// production configuration's stateDirectory value.
func ValidateInstalledStateRoot(stateDirectory string) error {
	if filepath.Clean(stateDirectory) != installedStateDirectory {
		return errors.New("production Agent state directory must be /var/lib/ppflight-agent")
	}
	groupID, err := ppflightAgentGroupID()
	if err != nil {
		return err
	}
	return validateInstalledStateRoot(groupID)
}

func ensureInstalledBindingDirectory() (string, error) {
	groupID, err := ppflightAgentGroupID()
	if err != nil {
		return "", err
	}
	stateFD, err := openInstalledStateRoot(groupID, os.Geteuid() == 0)
	if err != nil {
		return "", err
	}
	defer syscall.Close(stateFD)

	if err := syscall.Mkdirat(stateFD, bindingDirectoryName, 0o750); err != nil && !errors.Is(err, syscall.EEXIST) {
		return "", fmt.Errorf("create bindings state directory: %w", err)
	}
	bindingFD, err := syscall.Openat(stateFD, bindingDirectoryName, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", errors.New("open controlled bindings state directory without following links")
	}
	defer syscall.Close(bindingFD)
	var info syscall.Stat_t
	if err := syscall.Fstat(bindingFD, &info); err != nil {
		return "", err
	}
	if info.Mode&syscall.S_IFMT != syscall.S_IFDIR || info.Uid != 0 {
		return "", errors.New("bindings state directory is not root-controlled")
	}
	if info.Gid != uint32(groupID) || info.Mode&0o777 != 0o750 {
		if os.Geteuid() != 0 {
			return "", errors.New("bindings state directory ownership or mode is unsafe")
		}
		if err := syscall.Fchown(bindingFD, 0, groupID); err != nil {
			return "", errors.New("repair bindings state directory ownership")
		}
		if err := syscall.Fchmod(bindingFD, 0o750); err != nil {
			return "", errors.New("repair bindings state directory mode")
		}
	}
	if os.Geteuid() == 0 {
		if err := repairInstalledPrivateFiles(bindingFD, groupID); err != nil {
			return "", err
		}
	}
	return filepath.Join(installedStateDirectory, bindingDirectoryName), nil
}

func validateInstalledStateRoot(groupID int) error {
	fd, err := openInstalledStateRoot(groupID, false)
	if err != nil {
		return err
	}
	return syscall.Close(fd)
}

func openInstalledStateRoot(groupID int, repair bool) (int, error) {
	// Check the immutable ancestors as well.  Once these are verified
	// root-owned/non-writable, descriptor-relative traversal below them cannot
	// be redirected through a user-created link.
	for _, parent := range []string{"/var", "/var/lib"} {
		fd, err := syscall.Open(parent, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return -1, errors.New("open installed Agent state parent without following links")
		}
		var info syscall.Stat_t
		statErr := syscall.Fstat(fd, &info)
		closeErr := syscall.Close(fd)
		if statErr != nil || closeErr != nil || info.Mode&syscall.S_IFMT != syscall.S_IFDIR || info.Uid != 0 || info.Mode&0o022 != 0 {
			return -1, errors.New("installed Agent state parent ownership or mode is unsafe")
		}
	}
	fd, err := syscall.Open(installedStateDirectory, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, errors.New("open installed Agent state directory without following links")
	}
	var info syscall.Stat_t
	if err := syscall.Fstat(fd, &info); err != nil {
		_ = syscall.Close(fd)
		return -1, err
	}
	if info.Mode&syscall.S_IFMT != syscall.S_IFDIR || info.Uid != 0 {
		_ = syscall.Close(fd)
		return -1, errors.New("installed Agent state directory is not root-controlled")
	}
	if info.Gid != uint32(groupID) || info.Mode&0o777 != 0o750 {
		if !repair || os.Geteuid() != 0 {
			_ = syscall.Close(fd)
			return -1, errors.New("installed Agent state directory ownership or mode is unsafe")
		}
		if err := syscall.Fchown(fd, 0, groupID); err != nil {
			_ = syscall.Close(fd)
			return -1, errors.New("repair installed Agent state directory ownership")
		}
		if err := syscall.Fchmod(fd, 0o750); err != nil {
			_ = syscall.Close(fd)
			return -1, errors.New("repair installed Agent state directory mode")
		}
	}
	return fd, nil
}

func ppflightAgentGroupID() (int, error) {
	group, err := user.LookupGroup("ppflight-agent")
	if err != nil || group == nil || strings.TrimSpace(group.Gid) == "" {
		return 0, errors.New("ppflight-agent service group is unavailable")
	}
	groupID, err := strconv.ParseUint(group.Gid, 10, 31)
	if err != nil {
		return 0, errors.New("ppflight-agent service group is invalid")
	}
	return int(groupID), nil
}

func repairInstalledPrivateFiles(directoryFD, groupID int) error {
	// The directory is root-owned and already chmodded 0750 above.  Inspecting
	// names then reopening each one through directoryFD prevents pathname races
	// and rejects symlinks/hardlinks before any metadata repair occurs.
	directory := filepath.Join(installedStateDirectory, bindingDirectoryName)
	entries, err := os.ReadDir(directory)
	if err != nil {
		return errors.New("read controlled bindings state directory")
	}
	for _, entry := range entries {
		name := entry.Name()
		if !isInstalledPrivateBindingFile(name) {
			continue
		}
		fd, err := syscall.Openat(directoryFD, name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if errors.Is(err, syscall.ENOENT) {
			continue
		}
		if err != nil {
			return errors.New("open private binding state without following links")
		}
		var info syscall.Stat_t
		statErr := syscall.Fstat(fd, &info)
		if statErr == nil && (info.Mode&syscall.S_IFMT != syscall.S_IFREG || info.Nlink != 1 || info.Uid != 0) {
			statErr = errors.New("private binding state is not a root-owned regular single-link file")
		}
		if statErr == nil && (info.Gid != uint32(groupID) || info.Mode&0o777 != 0o640) {
			if err := syscall.Fchown(fd, 0, groupID); err != nil {
				statErr = errors.New("repair private binding state ownership")
			} else if err := syscall.Fchmod(fd, 0o640); err != nil {
				statErr = errors.New("repair private binding state mode")
			}
		}
		closeErr := syscall.Close(fd)
		if statErr != nil {
			return statErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func isInstalledPrivateBindingFile(name string) bool {
	switch name {
	case "binding-state.json", "monitoring-binding-state.json", "device-id",
		".website-binding-pending.json", ".monitoring-binding-pending.json",
		websiteCommitName, monitoringCommitName, websiteUnbindCommitName, monitoringUnbindCommitName:
		return true
	}
	return (strings.HasPrefix(name, "binding-state.backup.") || strings.HasPrefix(name, "monitoring-binding-state.backup.")) && strings.HasSuffix(name, ".json") && len(name) < 256
}

func checkManagedPrivateFileMetadata(filename string, info os.FileInfo) error {
	if filepath.Clean(filepath.Dir(filename)) != filepath.Join(installedStateDirectory, bindingDirectoryName) {
		return nil
	}
	groupID, err := ppflightAgentGroupID()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != uint32(groupID) || stat.Nlink != 1 || info.Mode().Perm() != 0o640 {
		return errors.New("private binding state ownership or mode is unsafe")
	}
	return nil
}
