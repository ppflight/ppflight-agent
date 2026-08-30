package netpolicy

import (
	"net/http"
	"net/url"
	"testing"
)

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
	transport := ApplyIPv4Only((&http.Transport{Proxy: http.ProxyFromEnvironment}).Clone())
	if transport.DialContext == nil || transport.Proxy != nil {
		t.Fatal("IPv4 direct dialer was not installed")
	}
}

func TestNetworkPolicyRequiresCanonicalObservedIPv4(t *testing.T) {
	valid := NetworkPolicy{AgentObservedIPv4: "127.0.0.1"}
	if err := ValidateNetworkPolicy(valid); err != nil {
		t.Fatal(err)
	}
	for _, policy := range []NetworkPolicy{
		{AgentObservedIPv4: ""},
		{AgentObservedIPv4: "0.0.0.0"},
		{AgentObservedIPv4: "192.0.2.010"},
		{AgentObservedIPv4: "2001:db8::1"},
	} {
		if err := ValidateNetworkPolicy(policy); err == nil {
			t.Fatalf("accepted %#v", policy)
		}
	}
}
