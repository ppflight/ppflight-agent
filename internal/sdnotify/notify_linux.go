//go:build linux

package sdnotify

import (
	"fmt"
	"net"
)

func newNotifier(lookup environmentLookup, pid int) (*Notifier, error) {
	config, err := parseConfiguration(lookup, pid)
	if err != nil {
		return nil, err
	}
	return &Notifier{socket: config.socket, watchdogTimeout: config.watchdogTimeout}, nil
}

func sendNotification(socket, message string) error {
	name := socket
	if name[0] == '@' {
		// systemd documents '@name' in NOTIFY_SOCKET as Linux's abstract Unix
		// namespace. net.UnixAddr represents that leading NUL literally.
		name = "\x00" + name[1:]
	}
	connection, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: name, Net: "unixgram"})
	if err != nil {
		return fmt.Errorf("connect systemd notify socket: %w", err)
	}
	defer connection.Close()
	if _, err := connection.Write([]byte(message)); err != nil {
		return fmt.Errorf("send systemd notification: %w", err)
	}
	return nil
}
