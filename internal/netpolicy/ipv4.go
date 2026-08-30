// Package netpolicy contains the network invariants shared by every outbound
// PPFlight Agent HTTP client.  The production deployment deliberately uses
// IPv4 only: DNS names may have both A and AAAA records, but the agent never
// falls back to an IPv6 peer.
package netpolicy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"
)

// NetworkPolicy is independently issued by each binding authority.  The
// observed address is service metadata: it is never learned from the local
// network nor used by the agent as a destination.
type NetworkPolicy struct {
	AgentObservedIPv4 string `json:"agentObservedIPv4"`
	// ServerIPv4Allowlist is a deprecated in-memory no-op retained only so RC
	// callers still compile. json:"-" keeps it out of the exact wire/store shape.
	ServerIPv4Allowlist []string `json:"-"`
}

// ValidateNetworkPolicy rejects non-canonical source-address metadata.
func ValidateNetworkPolicy(policy NetworkPolicy) error {
	if !canonicalIPv4(policy.AgentObservedIPv4) {
		return errors.New("invalid IPv4 network policy")
	}
	return nil
}

func canonicalIPv4(value string) bool {
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil || ip.String() != value || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	return value != "255.255.255.255"
}

// DialContextIPv4 is suitable for http.Transport.DialContext.  Using tcp4 is
// important here: resolving a dual-stack hostname and merely checking the URL
// does not prevent net.Dialer from selecting an IPv6 address.
func DialContextIPv4(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	return dialer.DialContext(ctx, "tcp4", address)
}

// ApplyIPv4Only mutates a private transport clone. Callers must never pass a
// transport that is concurrently used elsewhere.
func ApplyIPv4Only(transport *http.Transport) *http.Transport {
	if transport == nil {
		transport = http.DefaultTransport.(*http.Transport).Clone()
	}
	transport.DialContext = DialContextIPv4
	transport.Proxy = nil
	return transport
}

// ValidateIPv4URL rejects a literal IPv6 destination up front. Hostnames are
// allowed and are constrained to A records at dial time by DialContextIPv4.
func ValidateIPv4URL(parsed *url.URL) error {
	if parsed == nil || parsed.Hostname() == "" {
		return errors.New("URL host is required")
	}
	if ip := net.ParseIP(parsed.Hostname()); ip != nil && ip.To4() == nil {
		return errors.New("IPv6 destinations are not allowed")
	}
	return nil
}
