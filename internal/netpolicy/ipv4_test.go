package netpolicy

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"testing"
)

type staticResolver struct {
	ips []net.IP
	err error
}

func (r staticResolver) LookupIP(context.Context, string, string) ([]net.IP, error) {
	return r.ips, r.err
}

func TestValidateIPv4URL(t *testing.T) {
	for _, value := range []string{"https://127.0.0.1:8006", "https://example.test/path"} {
		parsed, _ := url.Parse(value)
		if err := ValidateIPv4URL(parsed); err != nil {
			t.Fatalf("%s: %v", value, err)
		}
	}
	parsed, _ := url.Parse("https://[2001:db8::1]/path")
	if err := ValidateIPv4URL(parsed); err == nil {
		t.Fatal("expected IPv6 literal rejection")
	}
}

func TestApplyIPv4Only(t *testing.T) {
	transport := ApplyIPv4Only((&http.Transport{}).Clone())
	if transport.DialContext == nil {
		t.Fatal("IPv4 dialer was not installed")
	}
}

func TestNetworkPolicyRejectsNonCanonicalAndDuplicateAddresses(t *testing.T) {
	valid := NetworkPolicy{AgentObservedIPv4: "127.0.0.1", ServerIPv4Allowlist: []string{"192.0.2.10"}}
	if err := ValidateNetworkPolicy(valid); err != nil {
		t.Fatal(err)
	}
	for _, policy := range []NetworkPolicy{
		{AgentObservedIPv4: "0.0.0.0", ServerIPv4Allowlist: []string{"192.0.2.10"}},
		{AgentObservedIPv4: "127.0.0.1", ServerIPv4Allowlist: []string{"192.0.2.010"}},
		{AgentObservedIPv4: "127.0.0.1", ServerIPv4Allowlist: []string{"192.0.2.10", "192.0.2.10"}},
		{AgentObservedIPv4: "127.0.0.1", ServerIPv4Allowlist: nil},
	} {
		if err := ValidateNetworkPolicy(policy); err == nil {
			t.Fatalf("accepted %#v", policy)
		}
	}
}

func TestPinnedDialRejectsDNSResultsOutsideAllowlist(t *testing.T) {
	dial, err := PinnedDialContext([]string{"127.0.0.1"}, staticResolver{ips: []net.IP{net.ParseIP("192.0.2.55"), net.ParseIP("192.0.2.55")}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dial(context.Background(), "tcp", "service.example:443"); err == nil {
		t.Fatal("accepted wholly unauthorized A records")
	}
}

func TestPinnedDialUsesAllowlistedARecordAmongMixedAnswers(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- struct{}{}
			_ = conn.Close()
		}
	}()
	dial, err := PinnedDialContext([]string{"127.0.0.1"}, staticResolver{ips: []net.IP{net.ParseIP("192.0.2.55"), net.ParseIP("127.0.0.1"), net.ParseIP("127.0.0.1")}})
	if err != nil {
		t.Fatal(err)
	}
	_, port, splitErr := net.SplitHostPort(listener.Addr().String())
	if splitErr != nil {
		t.Fatal(splitErr)
	}
	connection, err := dial(context.Background(), "tcp", net.JoinHostPort("service.example", port))
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	<-accepted
}
