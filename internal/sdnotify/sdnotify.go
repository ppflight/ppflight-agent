// Package sdnotify implements the small, explicit subset of systemd's notify
// protocol used by the Agent lifecycle. It does not daemonize, install itself,
// or interfere with an administrator stopping or disabling the service.
package sdnotify

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// MinWatchdogTimeout prevents an untrusted environment from creating a
	// busy heartbeat loop. systemd passes the configured WatchdogSec as
	// WATCHDOG_USEC; the Agent sends at half this timeout.
	MinWatchdogTimeout = time.Second
	// MaxWatchdogTimeout bounds duration arithmetic and catches a corrupted
	// service environment instead of silently disabling supervision.
	MaxWatchdogTimeout = 24 * time.Hour

	maxNotifySocketBytes = 107
)

type environmentLookup func(string) (string, bool)

type configuration struct {
	socket          string
	watchdogTimeout time.Duration
}

// Notifier is immutable and safe for concurrent lifecycle/watchdog calls.
// A disabled notifier is a no-op, which is the normal state outside systemd.
type Notifier struct {
	socket          string
	watchdogTimeout time.Duration
}

// New reads the systemd-provided notification environment. On non-Linux
// systems it always returns a disabled no-op notifier.
func New() (*Notifier, error) {
	return newNotifier(os.LookupEnv, os.Getpid())
}

// Enabled reports whether READY/STOPPING notifications have a target.
func (n *Notifier) Enabled() bool {
	return n != nil && n.socket != ""
}

// WatchdogTimeout returns systemd's configured watchdog timeout, or zero when
// WATCHDOG_USEC is absent or WATCHDOG_PID addresses another process.
func (n *Notifier) WatchdogTimeout() time.Duration {
	if n == nil {
		return 0
	}
	return n.watchdogTimeout
}

// WatchdogInterval is the recommended heartbeat interval. It is deliberately
// half the systemd timeout so one delayed tick does not immediately expire it.
// Zero means watchdog heartbeats are disabled.
func (n *Notifier) WatchdogInterval() time.Duration {
	return n.WatchdogTimeout() / 2
}

// Ready tells systemd that initialization completed successfully.
func (n *Notifier) Ready() error {
	return n.send("READY=1", false)
}

// Watchdog sends one liveness heartbeat when WATCHDOG_USEC applies to this
// process. Calling it when watchdog supervision is disabled is a no-op.
func (n *Notifier) Watchdog() error {
	return n.send("WATCHDOG=1", true)
}

// Stopping tells systemd that an administrator-requested or graceful shutdown
// has begun. Restart policy remains entirely under systemd's control.
func (n *Notifier) Stopping() error {
	return n.send("STOPPING=1", false)
}

func (n *Notifier) send(message string, watchdogOnly bool) error {
	if n == nil || n.socket == "" || watchdogOnly && n.watchdogTimeout == 0 {
		return nil
	}
	return sendNotification(n.socket, message)
}

func parseConfiguration(lookup environmentLookup, currentPID int) (configuration, error) {
	if lookup == nil {
		return configuration{}, nil
	}
	socket, present := lookup("NOTIFY_SOCKET")
	if !present || socket == "" {
		return configuration{}, nil
	}
	if len(socket) < 2 || len(socket) > maxNotifySocketBytes || strings.ContainsAny(socket, "\x00\r\n") || socket[0] != '/' && socket[0] != '@' {
		return configuration{}, errors.New("systemd NOTIFY_SOCKET is invalid")
	}
	result := configuration{socket: socket}

	microseconds, watchdogPresent := lookup("WATCHDOG_USEC")
	if !watchdogPresent {
		return result, nil
	}
	if currentPID <= 0 {
		return configuration{}, errors.New("current process ID is invalid")
	}
	if watchdogPID, pidPresent := lookup("WATCHDOG_PID"); pidPresent {
		parsedPID, err := strconv.ParseInt(watchdogPID, 10, 64)
		if err != nil || parsedPID <= 0 {
			return configuration{}, errors.New("systemd WATCHDOG_PID is invalid")
		}
		if parsedPID != int64(currentPID) {
			return result, nil
		}
	}
	value, err := strconv.ParseUint(microseconds, 10, 64)
	minimum := uint64(MinWatchdogTimeout / time.Microsecond)
	maximum := uint64(MaxWatchdogTimeout / time.Microsecond)
	if err != nil || value < minimum || value > maximum {
		return configuration{}, errors.New("systemd WATCHDOG_USEC is outside the safe range")
	}
	result.watchdogTimeout = time.Duration(value) * time.Microsecond
	return result, nil
}
