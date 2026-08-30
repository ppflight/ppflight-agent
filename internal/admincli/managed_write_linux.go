//go:build linux

package admincli

import (
	"errors"
	"fmt"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/ppflight/ppflight-agent/internal/bindstate"
	"github.com/ppflight/ppflight-agent/internal/config"
)

const (
	installedAgentConfig    = "/etc/ppflight-agent/agent.yaml"
	installedAgentConfigDir = "/etc/ppflight-agent"
)

// ValidateInstalledWriteTarget validates the immutable production management
// target. It is intentionally independent of config values: a root command
// must not use a user-selected --config file to discover a state root in which
// it will later write credentials, markers, backups, or locks.
func ValidateInstalledWriteTarget(filename string, cfg config.Config) error {
	if filepath.Clean(filename) != installedAgentConfig {
		return errors.New("production Agent management requires /etc/ppflight-agent/agent.yaml")
	}
	if err := validateInstalledConfigFile(); err != nil {
		return err
	}
	if err := bindstate.ValidateInstalledStateRoot(cfg.Runtime.StateDirectory); err != nil {
		return err
	}
	return nil
}

func (c *cli) requireManagedWriteTarget(filename string, cfg config.Config) error {
	if c.managedWritePolicy != nil {
		return c.managedWritePolicy(filename, cfg)
	}
	if !c.isRoot() {
		return nil
	}
	return ValidateInstalledWriteTarget(filename, cfg)
}

func validateInstalledConfigFile() error {
	groupID, err := installedServiceGroupID()
	if err != nil {
		return err
	}
	etcFD, err := syscall.Open("/etc", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("open /etc without following links")
	}
	defer syscall.Close(etcFD)
	if err := validateRootDirectoryFD(etcFD, -1, false, "/etc"); err != nil {
		return err
	}
	dirFD, err := syscall.Openat(etcFD, "ppflight-agent", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("open /etc/ppflight-agent without following links")
	}
	defer syscall.Close(dirFD)
	if err := validateRootDirectoryFD(dirFD, groupID, true, installedAgentConfigDir); err != nil {
		return err
	}
	fileFD, err := syscall.Openat(dirFD, "agent.yaml", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("open installed Agent configuration without following links")
	}
	defer syscall.Close(fileFD)
	var info syscall.Stat_t
	if err := syscall.Fstat(fileFD, &info); err != nil {
		return err
	}
	if info.Mode&syscall.S_IFMT != syscall.S_IFREG || info.Nlink != 1 || info.Uid != 0 || info.Gid != uint32(groupID) || info.Mode&0o777 != 0o640 {
		return errors.New("installed Agent configuration ownership or mode is unsafe")
	}
	return nil
}

func validateRootDirectoryFD(fd int, requiredGroup int, exactGroup bool, label string) error {
	var info syscall.Stat_t
	if err := syscall.Fstat(fd, &info); err != nil {
		return err
	}
	if info.Mode&syscall.S_IFMT != syscall.S_IFDIR || info.Uid != 0 || info.Mode&0o022 != 0 {
		return fmt.Errorf("%s ownership or mode is unsafe", label)
	}
	if exactGroup && (info.Gid != uint32(requiredGroup) || info.Mode&0o777 != 0o750) {
		return fmt.Errorf("%s ownership or mode is unsafe", label)
	}
	return nil
}

func installedServiceGroupID() (int, error) {
	group, err := user.LookupGroup("ppflight-agent")
	if err != nil || group == nil || strings.TrimSpace(group.Gid) == "" {
		return 0, errors.New("ppflight-agent service group is unavailable")
	}
	value, err := strconv.ParseUint(group.Gid, 10, 31)
	if err != nil {
		return 0, errors.New("ppflight-agent service group is invalid")
	}
	return int(value), nil
}
