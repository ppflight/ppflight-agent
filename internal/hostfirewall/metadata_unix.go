//go:build !windows

package hostfirewall

import (
	"context"
	"errors"
	"os"
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
