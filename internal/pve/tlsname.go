package pve

import (
	"errors"
	"net"
	"strings"
)

// ValidateTLSServerName accepts an ASCII DNS hostname used exclusively for
// TLS SNI and certificate hostname verification. The TCP destination remains
// the IPv4 endpoint in Config.Endpoint. IP literals and wildcards are rejected
// because they would reintroduce the common PVE 127.0.0.1 SAN mismatch or
// broaden certificate identity unexpectedly.
func ValidateTLSServerName(value string) error {
	if value == "" || len(value) > 253 || strings.TrimSpace(value) != value || strings.Contains(value, "*") || net.ParseIP(value) != nil {
		return errors.New("TLS server name must be a strict DNS hostname, not an IP address or wildcard")
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("TLS server name contains an invalid DNS label")
		}
		for _, character := range label {
			if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return errors.New("TLS server name contains a non-DNS character")
		}
	}
	return nil
}
