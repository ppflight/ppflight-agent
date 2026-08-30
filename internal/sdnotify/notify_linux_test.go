//go:build linux

package sdnotify

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestLinuxNotifierSendsFilesystemDatagrams(t *testing.T) {
	directory, err := os.MkdirTemp("", "sdnotify-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	socket := filepath.Join(directory, "notify.sock")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	notifier, err := newNotifier(lookupEnvironment(map[string]string{
		"NOTIFY_SOCKET": socket,
		"WATCHDOG_USEC": "2000000",
		"WATCHDOG_PID":  strconv.Itoa(os.Getpid()),
	}), os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	assertNotification(t, listener, notifier.Ready, "READY=1")
	assertNotification(t, listener, notifier.Watchdog, "WATCHDOG=1")
	assertNotification(t, listener, notifier.Stopping, "STOPPING=1")
}

func TestLinuxNotifierSupportsAbstractSocket(t *testing.T) {
	name := "ppflight-sdnotify-" + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: "\x00" + name, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	notifier, err := newNotifier(lookupEnvironment(map[string]string{"NOTIFY_SOCKET": "@" + name}), os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	assertNotification(t, listener, notifier.Ready, "READY=1")
}

func assertNotification(t *testing.T, listener *net.UnixConn, send func() error, want string) {
	t.Helper()
	if err := listener.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := send(); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	count, _, err := listener.ReadFromUnix(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buffer[:count]); got != want {
		t.Fatalf("notification=%q want=%q", got, want)
	}
}
