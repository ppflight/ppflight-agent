package pve

import "testing"

func TestValidateTLSServerNameRejectsLocalAndBroadIdentities(t *testing.T) {
	for _, value := range []string{"", "localhost", "LOCALHOST", "127.0.0.1", "::1", "*.example.com", "bad_name.example"} {
		if err := ValidateTLSServerName(value); err == nil {
			t.Fatalf("unsafe TLS server name %q was accepted", value)
		}
	}
	for _, value := range []string{"pve", "pve01.example.com"} {
		if err := ValidateTLSServerName(value); err != nil {
			t.Fatalf("safe TLS server name %q rejected: %v", value, err)
		}
	}
}
