//go:build !linux

package sdnotify

import "testing"

func TestNewIsNoOpOutsideLinux(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "not-even-an-absolute-socket")
	t.Setenv("WATCHDOG_USEC", "not-a-number")
	notifier, err := New()
	if err != nil || notifier.Enabled() || notifier.WatchdogInterval() != 0 {
		t.Fatalf("notifier=%#v err=%v", notifier, err)
	}
	if err := notifier.Ready(); err != nil {
		t.Fatal(err)
	}
	if err := notifier.Watchdog(); err != nil {
		t.Fatal(err)
	}
	if err := notifier.Stopping(); err != nil {
		t.Fatal(err)
	}
}
