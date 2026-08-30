package sdnotify

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func lookupEnvironment(values map[string]string) environmentLookup {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

func TestParseConfigurationWatchdogAndPID(t *testing.T) {
	tests := []struct {
		name    string
		values  map[string]string
		pid     int
		want    configuration
		wantErr bool
	}{
		{name: "outside systemd", values: map[string]string{}, pid: 42},
		{name: "notify only", values: map[string]string{"NOTIFY_SOCKET": "/run/systemd/notify"}, pid: 42, want: configuration{socket: "/run/systemd/notify"}},
		{name: "filesystem watchdog", values: map[string]string{"NOTIFY_SOCKET": "/run/systemd/notify", "WATCHDOG_USEC": "60000000"}, pid: 42, want: configuration{socket: "/run/systemd/notify", watchdogTimeout: time.Minute}},
		{name: "abstract matching pid", values: map[string]string{"NOTIFY_SOCKET": "@systemd-notify", "WATCHDOG_USEC": "2000000", "WATCHDOG_PID": "42"}, pid: 42, want: configuration{socket: "@systemd-notify", watchdogTimeout: 2 * time.Second}},
		{name: "other pid disables watchdog", values: map[string]string{"NOTIFY_SOCKET": "/run/systemd/notify", "WATCHDOG_USEC": "60000000", "WATCHDOG_PID": "43"}, pid: 42, want: configuration{socket: "/run/systemd/notify"}},
		{name: "invalid pid", values: map[string]string{"NOTIFY_SOCKET": "/run/systemd/notify", "WATCHDOG_USEC": "60000000", "WATCHDOG_PID": "not-a-pid"}, pid: 42, wantErr: true},
		{name: "zero pid", values: map[string]string{"NOTIFY_SOCKET": "/run/systemd/notify", "WATCHDOG_USEC": "60000000", "WATCHDOG_PID": "0"}, pid: 42, wantErr: true},
		{name: "invalid usec", values: map[string]string{"NOTIFY_SOCKET": "/run/systemd/notify", "WATCHDOG_USEC": "1.5"}, pid: 42, wantErr: true},
		{name: "below minimum", values: map[string]string{"NOTIFY_SOCKET": "/run/systemd/notify", "WATCHDOG_USEC": "999999"}, pid: 42, wantErr: true},
		{name: "above maximum", values: map[string]string{"NOTIFY_SOCKET": "/run/systemd/notify", "WATCHDOG_USEC": fmt.Sprint(uint64(MaxWatchdogTimeout/time.Microsecond) + 1)}, pid: 42, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseConfiguration(lookupEnvironment(test.values), test.pid)
			if (err != nil) != test.wantErr || !test.wantErr && got != test.want {
				t.Fatalf("configuration=%#v err=%v want=%#v wantErr=%v", got, err, test.want, test.wantErr)
			}
		})
	}
}

func TestParseConfigurationRejectsUnsafeSocket(t *testing.T) {
	for name, socket := range map[string]string{
		"relative":       "run/systemd/notify",
		"empty abstract": "@",
		"newline":        "/run/systemd/notify\nother",
		"nul":            "/run/systemd/notify\x00other",
		"too long":       "/" + strings.Repeat("x", maxNotifySocketBytes),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseConfiguration(lookupEnvironment(map[string]string{"NOTIFY_SOCKET": socket}), 42); err == nil {
				t.Fatal("unsafe NOTIFY_SOCKET was accepted")
			}
		})
	}
}

func TestNotifierIntervalsAndDisabledCalls(t *testing.T) {
	disabled := &Notifier{}
	if disabled.Enabled() || disabled.WatchdogTimeout() != 0 || disabled.WatchdogInterval() != 0 {
		t.Fatal("zero notifier is not disabled")
	}
	if err := disabled.Ready(); err != nil {
		t.Fatal(err)
	}
	if err := disabled.Watchdog(); err != nil {
		t.Fatal(err)
	}
	if err := disabled.Stopping(); err != nil {
		t.Fatal(err)
	}
	enabled := &Notifier{socket: "/run/systemd/notify", watchdogTimeout: time.Minute}
	if !enabled.Enabled() || enabled.WatchdogTimeout() != time.Minute || enabled.WatchdogInterval() != 30*time.Second {
		t.Fatal("watchdog interval was not derived from its timeout")
	}
}
