//go:build !windows

package hostfirewall

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
	"time"
)

func ownedByRoot(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0
}

func effectiveUID() int {
	return os.Geteuid()
}

func syncDirectory(directory *os.File) error { return directory.Sync() }

func inspectFirewallSelectorPath(path string) (bool, error) {
	if path != "/run/proxmox-nftables-firewall-force-disable" && path != "/usr/libexec/proxmox/proxmox-firewall" {
		return false, errors.New("unsupported firewall selector path")
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, errors.New("cannot inspect firewall selector path")
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !ownedByRoot(info) || info.Mode().Perm()&0o022 != 0 {
		return false, errors.New("firewall selector path metadata is unsafe")
	}
	if path == "/usr/libexec/proxmox/proxmox-firewall" && info.Mode().Perm()&0o111 == 0 {
		return false, nil
	}
	return true, nil
}

// inspectUFWDisablePreconditions validates the package-controlled inputs used
// by the safe removal path. We never invoke `ufw disable`/force-stop. The
// MANAGE_BUILTINS value is accepted for inventory only because ordinary stop
// and dpkg prerm are made inert first by atomically setting ENABLED=no.
func inspectUFWDisablePreconditions(libraryPrefix string) error {
	if libraryPrefix != "/lib" && libraryPrefix != "/usr/lib" {
		return errors.New("unsupported UFW package library layout")
	}
	for _, path := range []string{
		"/usr/sbin/ufw", libraryPrefix + "/ufw/ufw-init", libraryPrefix + "/ufw/ufw-init-functions",
		libraryPrefix + "/systemd/system/ufw.service", "/etc/default/ufw", "/etc/ufw/ufw.conf",
	} {
		info, err := os.Lstat(path)
		if err != nil {
			return errors.New("cannot inspect packaged UFW disable precondition")
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !ownedByRoot(info) || info.Mode().Perm()&0o022 != 0 {
			return errors.New("packaged UFW disable precondition has unsafe metadata")
		}
	}
	binary, err := os.Lstat("/usr/sbin/ufw")
	if err != nil || binary.Mode().Perm()&0o111 == 0 {
		return errors.New("packaged UFW executable is missing or not executable")
	}
	if err := verifyPackagedUFWRuntimeHashes(libraryPrefix); err != nil {
		return err
	}
	raw, err := os.ReadFile("/etc/default/ufw")
	if err != nil || len(raw) == 0 || len(raw) > 64<<10 {
		return errors.New("cannot safely read /etc/default/ufw")
	}
	if _, err := parseSafeUFWDefaults(raw); err != nil {
		return err
	}
	conf, err := os.ReadFile("/etc/ufw/ufw.conf")
	if err != nil || len(conf) == 0 || len(conf) > 64<<10 {
		return errors.New("cannot safely read /etc/ufw/ufw.conf")
	}
	if _, _, err := rewriteUFWEnabled(conf); err != nil {
		return err
	}
	return nil
}

func verifyPackagedUFWRuntimeHashes(libraryPrefix string) error {
	manifestPath := "/var/lib/dpkg/info/ufw.md5sums"
	info, err := os.Lstat(manifestPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		!ownedByRoot(info) || info.Mode().Perm()&0o022 != 0 {
		return errors.New("UFW package checksum manifest metadata is unsafe")
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil || len(raw) == 0 || len(raw) > 2<<20 {
		return errors.New("cannot safely read UFW package checksum manifest")
	}
	wanted := map[string]string{}
	for _, path := range []string{
		"/usr/sbin/ufw", libraryPrefix + "/ufw/ufw-init", libraryPrefix + "/ufw/ufw-init-functions",
		libraryPrefix + "/systemd/system/ufw.service",
	} {
		wanted[strings.TrimPrefix(path, "/")] = ""
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return errors.New("UFW package checksum manifest is invalid")
		}
		if _, tracked := wanted[fields[1]]; !tracked {
			continue
		}
		if wanted[fields[1]] != "" || len(fields[0]) != md5.Size*2 {
			return errors.New("UFW package checksum manifest is ambiguous")
		}
		if _, err := hex.DecodeString(fields[0]); err != nil {
			return errors.New("UFW package checksum manifest contains an invalid digest")
		}
		wanted[fields[1]] = strings.ToLower(fields[0])
	}
	for relativePath, expected := range wanted {
		if expected == "" {
			return errors.New("UFW package checksum manifest is incomplete")
		}
		file, err := os.Open("/" + relativePath)
		if err != nil {
			return errors.New("cannot open packaged UFW runtime for verification")
		}
		openedInfo, statErr := file.Stat()
		if statErr != nil || !openedInfo.Mode().IsRegular() || !ownedByRoot(openedInfo) ||
			openedInfo.Mode().Perm()&0o022 != 0 || openedInfo.Size() < 1 || openedInfo.Size() > 4<<20 {
			_ = file.Close()
			return errors.New("opened packaged UFW runtime metadata is unsafe")
		}
		hash := md5.New() // dpkg's package manifest format is MD5 by definition.
		_, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || hex.EncodeToString(hash.Sum(nil)) != expected {
			return errors.New("packaged UFW runtime checksum verification failed")
		}
	}
	return nil
}

func disableUFWAtBoot() error {
	directoryInfo, err := os.Lstat("/etc/ufw")
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 ||
		!ownedByRoot(directoryInfo) || directoryInfo.Mode().Perm()&0o022 != 0 {
		return errors.New("UFW configuration directory metadata is unsafe")
	}
	info, err := os.Lstat("/etc/ufw/ufw.conf")
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		!ownedByRoot(info) || info.Mode().Perm()&0o022 != 0 {
		return errors.New("UFW boot configuration metadata is unsafe")
	}
	raw, err := os.ReadFile("/etc/ufw/ufw.conf")
	if err != nil || len(raw) == 0 || len(raw) > 64<<10 {
		return errors.New("cannot safely read UFW boot configuration")
	}
	replacement, changed, err := rewriteUFWEnabled(raw)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	temporary, err := os.CreateTemp("/etc/ufw", ".ppflight-ufw.conf.*")
	if err != nil {
		return errors.New("cannot create UFW boot configuration replacement")
	}
	temporaryPath := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}
	if err := temporary.Chmod(info.Mode().Perm()); err != nil {
		cleanup()
		return errors.New("cannot set UFW boot configuration replacement mode")
	}
	if _, err := temporary.Write(replacement); err != nil {
		cleanup()
		return errors.New("cannot write UFW boot configuration replacement")
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return errors.New("cannot sync UFW boot configuration replacement")
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return errors.New("cannot close UFW boot configuration replacement")
	}
	if err := os.Rename(temporaryPath, "/etc/ufw/ufw.conf"); err != nil {
		_ = os.Remove(temporaryPath)
		return errors.New("cannot atomically disable UFW boot configuration")
	}
	directory, err := os.Open("/etc/ufw")
	if err != nil {
		return errors.New("cannot open UFW configuration directory")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return errors.New("cannot sync UFW configuration directory")
	}
	verify, err := os.ReadFile("/etc/ufw/ufw.conf")
	if err != nil {
		return errors.New("cannot read back UFW boot configuration")
	}
	_, verifyChanged, err := rewriteUFWEnabled(verify)
	if err != nil || verifyChanged {
		return errors.New("UFW boot configuration disable readback failed")
	}
	return nil
}

func acquireFirewallProcessLock(ctx context.Context) (func(), error) {
	if firewallNetfilterLockHeld(ctx) {
		return func() {}, nil
	}
	return acquireRootFirewallLock(ctx, "/run/ppflight-agent-host-firewall.lock")
}

func acquireFirewallEnforcementLock(ctx context.Context) (context.Context, func(), error) {
	unlock, err := acquireRootFirewallLock(ctx, "/run/ppflight-agent-host-firewall.lock")
	if err != nil {
		return nil, nil, err
	}
	return context.WithValue(ctx, firewallNetfilterLockContextKey{}, true), unlock, nil
}

func acquireFirewallTransactionLock(ctx context.Context) (func(), error) {
	return acquireRootFirewallLock(ctx, "/run/ppflight-agent-host-firewall-transaction.lock")
}

func acquireRootFirewallLock(ctx context.Context, lockPath string) (func(), error) {
	if lockPath != "/run/ppflight-agent-host-firewall.lock" && lockPath != "/run/ppflight-agent-host-firewall-transaction.lock" {
		return nil, errors.New("unsupported host firewall process lock")
	}
	if os.Geteuid() != 0 {
		return nil, errors.New("host firewall process lock requires root")
	}
	fd, err := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, errors.New("cannot open host firewall process lock")
	}
	file := os.NewFile(uintptr(fd), lockPath)
	closeOnError := func() { _ = file.Close() }
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil || stat.Uid != 0 || stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Mode&0o777 != 0o600 {
		closeOnError()
		return nil, errors.New("host firewall process lock metadata is unsafe")
	}
	if err := flockWithContext(ctx, fd); err != nil {
		closeOnError()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}

func flockWithContext(ctx context.Context, fd int) error {
	for {
		err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			return errors.New("cannot acquire host firewall process lock")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}
