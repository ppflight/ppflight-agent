//go:build linux

package admincli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

const templateBridgeSysClassNet = "/sys/class/net"

func templateBridgeKernelInterfaceExists(name string) (bool, error) {
	if !safeTemplateBridgeName(name) {
		return false, errors.New("invalid kernel interface name")
	}
	root, err := os.Stat(templateBridgeSysClassNet)
	if err != nil || !root.IsDir() {
		return false, errors.New("Linux sysfs network inventory is unavailable")
	}
	info, err := os.Stat(filepath.Join(templateBridgeSysClassNet, name))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("cannot inspect Linux network interface: %w", err)
	}
	if !info.IsDir() {
		return false, errors.New("Linux network interface sysfs entry is invalid")
	}
	return true, nil
}

func templateBridgeKernelMembers(name string) ([]string, error) {
	if !safeTemplateBridgeName(name) {
		return nil, errors.New("invalid kernel bridge name")
	}
	entries, err := os.ReadDir(filepath.Join(templateBridgeSysClassNet, name, "brif"))
	if err != nil {
		return nil, err
	}
	members := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !safeTemplateBridgeName(entry.Name()) {
			return nil, errors.New("kernel bridge contains an invalid member name")
		}
		members = append(members, entry.Name())
	}
	sort.Strings(members)
	return members, nil
}
