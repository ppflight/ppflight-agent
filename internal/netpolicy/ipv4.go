// Package netpolicy contains the network invariants shared by every outbound
// PPFlight Agent HTTP client.  The production deployment deliberately uses
// IPv4 only: DNS names may have both A and AAAA records, but the agent never
// falls back to an IPv6 peer.
package netpolicy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"time"
)

const (
	MinServerIPv4Allowlist = 1
	MaxServerIPv4Allowlist = 16
)

// NetworkPolicy is independently issued by each binding authority.  The
// observed address is service metadata: it is never learned from the local
// network nor used by the agent as a destination.  ServerIPv4Allowlist is the
// complete, canonical destination set the agent may use for that authority.
type NetworkPolicy struct {
	AgentObservedIPv4   string   `json:"agentObservedIPv4"`
	ServerIPv4Allowlist []string `json:"serverIPv4Allowlist"`
}

// ValidateNetworkPolicy rejects non-canonical spellings as well as duplicate
// addresses.  Keeping this wire value canonical avoids two implementations
// accepting different textual forms for the same address.
func ValidateNetworkPolicy(policy NetworkPolicy) error {
	if !canonicalIPv4(policy.AgentObservedIPv4) || len(policy.ServerIPv4Allowlist) < MinServerIPv4Allowlist || len(policy.ServerIPv4Allowlist) > MaxServerIPv4Allowlist {
		return errors.New("invalid IPv4 network policy")
	}
	seen := make(map[string]struct{}, len(policy.ServerIPv4Allowlist))
	for _, value := range policy.ServerIPv4Allowlist {
		if !canonicalIPv4(value) {
			return errors.New("invalid IPv4 network policy")
		}
		if _, duplicate := seen[value]; duplicate {
			return errors.New("invalid IPv4 network policy")
		}
		seen[value] = struct{}{}
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

// Resolver is intentionally narrow so resolution behavior can be tested
// without a host DNS dependency. Production callers use net.DefaultResolver.
type Resolver interface {
	LookupIP(context.Context, string, string) ([]net.IP, error)
}

// PinnedDialContext resolves hostnames exclusively through A records and
// dials only their intersection with allowlist. It dials the selected address
// directly, leaving the HTTP URL hostname intact for Host and TLS SNI checks.
// Thus proxying, AAAA fallback, and DNS rebinding cannot bypass the policy.
func PinnedDialContext(allowlist []string, resolver Resolver) (func(context.Context, string, string) (net.Conn, error), error) {
	policy := NetworkPolicy{AgentObservedIPv4: "127.0.0.1", ServerIPv4Allowlist: append([]string(nil), allowlist...)}
	if err := ValidateNetworkPolicy(policy); err != nil {
		return nil, err
	}
	allowed := make(map[string]struct{}, len(allowlist))
	for _, value := range allowlist {
		allowed[value] = struct{}{}
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || port == "" {
			return nil, errors.New("invalid destination address")
		}
		var candidates []string
		if parsed := net.ParseIP(host); parsed != nil {
			if parsed.To4() == nil {
				return nil, errors.New("IPv6 destinations are not allowed")
			}
			canonical := parsed.String()
			if _, ok := allowed[canonical]; !ok {
				return nil, errors.New("destination IPv4 is not allowlisted")
			}
			candidates = []string{canonical}
		} else {
			ips, lookupErr := resolver.LookupIP(ctx, "ip4", host)
			if lookupErr != nil {
				return nil, fmt.Errorf("resolve destination A records: %w", lookupErr)
			}
			candidateSet := make(map[string]struct{}, len(ips))
			for _, ip := range ips {
				if ip.To4() == nil {
					continue
				}
				canonical := ip.String()
				if _, ok := allowed[canonical]; ok {
					if _, duplicate := candidateSet[canonical]; duplicate {
						continue
					}
					candidateSet[canonical] = struct{}{}
					candidates = append(candidates, canonical)
				}
			}
		}
		if len(candidates) == 0 {
			return nil, errors.New("no resolved A record is allowlisted")
		}
		sort.Strings(candidates)
		dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
		var last error
		for _, ip := range candidates {
			conn, dialErr := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(ip, port))
			if dialErr == nil {
				return conn, nil
			}
			last = dialErr
		}
		return nil, fmt.Errorf("dial allowlisted IPv4: %w", last)
	}, nil
}

// ApplyIPv4Allowlist applies PinnedDialContext to a private transport clone.
// It also disables ambient proxy use; callers still configure redirect refusal
// on their client because redirect handling is client-level state.
func ApplyIPv4Allowlist(transport *http.Transport, allowlist []string) (*http.Transport, error) {
	if transport == nil {
		transport = http.DefaultTransport.(*http.Transport).Clone()
	}
	dial, err := PinnedDialContext(allowlist, nil)
	if err != nil {
		return nil, err
	}
	transport.DialContext = dial
	transport.Proxy = nil
	return transport, nil
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
