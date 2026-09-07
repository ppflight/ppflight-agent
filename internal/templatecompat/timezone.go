// Package templatecompat contains narrowly-scoped, root-only compatibility
// migrations for PPFlight-managed PVE templates.
package templatecompat

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ppflight/ppflight-agent/internal/fsutil"
)

const (
	productionQEMUConfigDirectory = "/etc/pve/qemu-server"
	maximumPVEConfigBytes         = 1 << 20
	maximumSnippetBytes           = 1 << 20
)

var (
	managedVendorVolume = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9_.-]*):snippets/(ppflight-(?:debian|rpm)-)([a-f0-9]{64})\.yaml$`)
	topLevelTimezone    = regexp.MustCompile(`^timezone:[ \t]+[^#\r\n]+(?:[ \t]+#.*)?(?:\r?\n)?$`)
	vmConfigName        = regexp.MustCompile(`^[1-9][0-9]*\.conf$`)
	pveNodeName         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
)

type Report struct {
	Scanned  int
	Migrated int
	VMIDs    []int
}

type commandRunner func(context.Context, string, ...string) (string, error)

type migrator struct {
	configDirectory string
	run             commandRunner
}

type migration struct {
	vmid        int
	oldCICustom string
	newCICustom string
	newVolume   string
	newPath     string
	newContent  []byte
}

// MigrateLegacyTemplateTimezones removes only one hash-proven top-level
// timezone property from PPFlight-managed template vendor-data. The old
// content-addressed snippet is retained and all already-switched templates are
// rolled back if a later switch cannot be verified.
func MigrateLegacyTemplateTimezones(ctx context.Context) (Report, error) {
	if os.Geteuid() != 0 {
		return Report{}, errors.New("legacy template timezone migration requires root")
	}
	return (&migrator{configDirectory: productionQEMUConfigDirectory, run: runCommand}).migrate(ctx)
}

func runCommand(ctx context.Context, name string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	output, err := command.CombinedOutput()
	if err != nil {
		message := strings.Join(strings.Fields(string(output)), " ")
		if len(message) > 256 {
			message = message[:256]
		}
		if message == "" {
			message = "command failed"
		}
		return "", fmt.Errorf("%s %s: %s", filepath.Base(name), firstArgument(args), message)
	}
	return string(output), nil
}

func firstArgument(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

func (m *migrator) migrate(ctx context.Context) (Report, error) {
	plans, scanned, err := m.plan(ctx)
	if err != nil {
		return Report{}, err
	}
	for _, plan := range plans {
		if err := installSnippet(plan.newPath, plan.newContent); err != nil {
			return Report{}, err
		}
	}
	applied := make([]migration, 0, len(plans))
	for _, plan := range plans {
		if _, err := m.run(ctx, "/usr/sbin/qm", "set", strconv.Itoa(plan.vmid), "--cicustom", plan.newCICustom); err != nil {
			return Report{}, m.rollback(ctx, applied, err)
		}
		applied = append(applied, plan)
		if err := m.verify(ctx, plan.vmid, plan.newCICustom); err != nil {
			return Report{}, m.rollback(ctx, applied, err)
		}
	}
	report := Report{Scanned: scanned, Migrated: len(plans), VMIDs: make([]int, 0, len(plans))}
	for _, plan := range plans {
		report.VMIDs = append(report.VMIDs, plan.vmid)
	}
	return report, nil
}

func (m *migrator) plan(ctx context.Context) ([]migration, int, error) {
	configDirectory, err := resolvePVEQEMUConfigDirectory(m.configDirectory)
	if err != nil {
		return nil, 0, fmt.Errorf("resolve PVE QEMU config directory: %w", err)
	}
	entries, err := os.ReadDir(configDirectory)
	if err != nil {
		return nil, 0, fmt.Errorf("read PVE QEMU config directory: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	plans := make([]migration, 0)
	scanned := 0
	for _, entry := range entries {
		if entry.IsDir() || !vmConfigName.MatchString(entry.Name()) {
			continue
		}
		configPath := filepath.Join(configDirectory, entry.Name())
		raw, err := readLimitedRegular(configPath, maximumPVEConfigBytes)
		if err != nil {
			return nil, 0, fmt.Errorf("read QEMU config %s: %w", entry.Name(), err)
		}
		if value, err := configValue(raw, "template"); err != nil {
			return nil, 0, fmt.Errorf("VMID %s: %w", strings.TrimSuffix(entry.Name(), ".conf"), err)
		} else if value != "1" {
			continue
		}
		cicustom, err := configValue(raw, "cicustom")
		if err != nil {
			return nil, 0, fmt.Errorf("VMID %s: %w", strings.TrimSuffix(entry.Name(), ".conf"), err)
		}
		if cicustom == "" {
			continue
		}
		vendorValues := make([]string, 0, 1)
		managedValues := make([]string, 0, 1)
		for _, component := range strings.Split(cicustom, ",") {
			if strings.HasPrefix(component, "vendor=") {
				value := strings.TrimPrefix(component, "vendor=")
				vendorValues = append(vendorValues, value)
				if managedVendorVolume.MatchString(value) {
					managedValues = append(managedValues, value)
				}
			}
		}
		if len(managedValues) == 0 {
			continue
		}
		vmidText := strings.TrimSuffix(entry.Name(), ".conf")
		if len(vendorValues) != 1 || len(managedValues) != 1 {
			return nil, 0, fmt.Errorf("managed cicustom is ambiguous for VMID %s", vmidText)
		}
		match := managedVendorVolume.FindStringSubmatch(managedValues[0])
		scanned++
		resolved, err := m.run(ctx, "/usr/bin/pvesm", "path", managedValues[0])
		if err != nil {
			return nil, 0, err
		}
		resolved = strings.TrimSpace(resolved)
		if !filepath.IsAbs(resolved) || strings.ContainsAny(resolved, "\r\n") || filepath.Base(resolved) != match[2]+match[3]+".yaml" {
			return nil, 0, fmt.Errorf("PVE returned an invalid managed snippet path for VMID %s", vmidText)
		}
		content, err := readLimitedRegular(resolved, maximumSnippetBytes)
		if err != nil {
			return nil, 0, fmt.Errorf("read managed vendor-data for VMID %s: %w", vmidText, err)
		}
		sum := sha256.Sum256(content)
		if hex.EncodeToString(sum[:]) != match[3] {
			return nil, 0, fmt.Errorf("managed vendor-data hash mismatch for VMID %s", vmidText)
		}
		sanitized, changed, err := removeTopLevelTimezone(content)
		if err != nil {
			return nil, 0, fmt.Errorf("VMID %s: %w", vmidText, err)
		}
		if !changed {
			continue
		}
		newSum := sha256.Sum256(sanitized)
		newDigest := hex.EncodeToString(newSum[:])
		newName := match[2] + newDigest + ".yaml"
		newVolume := match[1] + ":snippets/" + newName
		newCICustom, err := replaceVendor(cicustom, managedValues[0], newVolume)
		if err != nil {
			return nil, 0, fmt.Errorf("VMID %s: %w", vmidText, err)
		}
		vmid, _ := strconv.Atoi(vmidText)
		plans = append(plans, migration{vmid: vmid, oldCICustom: cicustom, newCICustom: newCICustom, newVolume: newVolume, newPath: filepath.Join(filepath.Dir(resolved), newName), newContent: sanitized})
	}
	return plans, scanned, nil
}

// PVE exposes /etc/pve/qemu-server as the relative compatibility symlink
// nodes/<node>/qemu-server. The no-follow reader intentionally rejects that
// symlink, so resolve only this exact pmxcfs shape before opening config files.
// Absolute targets, traversal, nested links, and non-directories remain
// rejected.
func resolvePVEQEMUConfigDirectory(directory string) (string, error) {
	info, err := os.Lstat(directory)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		if !info.IsDir() {
			return "", errors.New("QEMU config path is not a directory")
		}
		return directory, nil
	}
	target, err := os.Readlink(directory)
	if err != nil {
		return "", err
	}
	if filepath.IsAbs(target) || filepath.Clean(target) != target {
		return "", errors.New("QEMU config symlink target is not a clean relative path")
	}
	parts := strings.Split(filepath.ToSlash(target), "/")
	if len(parts) != 3 || parts[0] != "nodes" || !pveNodeName.MatchString(parts[1]) || parts[2] != "qemu-server" {
		return "", errors.New("QEMU config symlink does not match the PVE pmxcfs layout")
	}
	root := filepath.Dir(directory)
	resolved := root
	for _, component := range parts {
		resolved = filepath.Join(resolved, component)
		resolvedInfo, err := os.Lstat(resolved)
		if err != nil {
			return "", err
		}
		if resolvedInfo.Mode()&os.ModeSymlink != 0 || !resolvedInfo.IsDir() {
			return "", fmt.Errorf("resolved PVE QEMU config component %q is not a direct directory", component)
		}
	}
	return resolved, nil
}

func (m *migrator) verify(ctx context.Context, vmid int, expected string) error {
	raw, err := m.run(ctx, "/usr/sbin/qm", "config", strconv.Itoa(vmid))
	if err != nil {
		return err
	}
	template, templateErr := configValue([]byte(raw), "template")
	cicustom, cicustomErr := configValue([]byte(raw), "cicustom")
	if templateErr != nil || cicustomErr != nil || template != "1" || cicustom != expected {
		return fmt.Errorf("VMID %d did not retain the expected template cicustom", vmid)
	}
	return nil
}

func (m *migrator) rollback(_ context.Context, applied []migration, cause error) error {
	rollbackContext, rollbackCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer rollbackCancel()
	rollbackErrors := make([]string, 0)
	for index := len(applied) - 1; index >= 0; index-- {
		plan := applied[index]
		if _, err := m.run(rollbackContext, "/usr/sbin/qm", "set", strconv.Itoa(plan.vmid), "--cicustom", plan.oldCICustom); err != nil {
			rollbackErrors = append(rollbackErrors, err.Error())
			continue
		}
		if err := m.verify(rollbackContext, plan.vmid, plan.oldCICustom); err != nil {
			rollbackErrors = append(rollbackErrors, err.Error())
		}
	}
	if len(rollbackErrors) > 0 {
		return fmt.Errorf("template migration failed (%v); rollback failed (%s)", cause, strings.Join(rollbackErrors, "; "))
	}
	return fmt.Errorf("template migration failed (%v); prior template switches rolled back", cause)
}

func configValue(raw []byte, key string) (string, error) {
	prefix := key + ": "
	value := ""
	found := false
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		if found {
			return "", fmt.Errorf("duplicate %s property", key)
		}
		value, found = strings.TrimSpace(strings.TrimPrefix(line, prefix)), true
	}
	return value, nil
}

func removeTopLevelTimezone(content []byte) ([]byte, bool, error) {
	if !utf8.Valid(content) {
		return nil, false, errors.New("managed vendor-data is not UTF-8")
	}
	lines := bytes.SplitAfter(content, []byte("\n"))
	matches := make([]int, 0, 1)
	for index, line := range lines {
		if topLevelTimezone.Match(line) {
			matches = append(matches, index)
		}
	}
	if len(matches) == 0 {
		return content, false, nil
	}
	if len(matches) != 1 {
		return nil, false, errors.New("managed vendor-data has multiple top-level timezone properties")
	}
	lines = append(lines[:matches[0]], lines[matches[0]+1:]...)
	result := bytes.Join(lines, nil)
	if !bytes.HasPrefix(result, []byte("#cloud-config")) {
		return nil, false, errors.New("managed vendor-data has no cloud-config header")
	}
	return result, true, nil
}

func replaceVendor(cicustom, oldVolume, newVolume string) (string, error) {
	parts := strings.Split(cicustom, ",")
	matches := 0
	for index, part := range parts {
		if part == "vendor="+oldVolume {
			parts[index] = "vendor=" + newVolume
			matches++
		}
	}
	if matches != 1 {
		return "", errors.New("managed cicustom has an ambiguous vendor component")
	}
	return strings.Join(parts, ","), nil
}

func readLimitedRegular(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > limit {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("path is not a safe bounded regular file")
	}
	file, err := fsutil.OpenRegularInDirectoryNoFollow(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != info.Size() || int64(len(data)) > limit {
		return nil, errors.New("file changed while reading")
	}
	return data, nil
}

func installSnippet(path string, content []byte) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("sanitized vendor-data path is unsafe: %s", path)
		}
		existing, err := readLimitedRegular(path, maximumSnippetBytes)
		if err != nil || !bytes.Equal(existing, content) {
			return fmt.Errorf("sanitized vendor-data path has different content: %s", path)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := fsutil.AtomicWriteFile(path, content, 0o644, false); err != nil {
		return fmt.Errorf("install sanitized vendor-data: %w", err)
	}
	return nil
}
