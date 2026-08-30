package enrollment

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/netpolicy"
	"github.com/ppflight/ppflight-agent/internal/protocol"
)

func websiteStatusExpected() StatusExpected {
	return StatusExpected{
		BindingID: "550e8400-e29b-41d4-a716-446655440001", DeviceID: "device-01", AgentRef: "agent-01",
		CredentialEpoch: 7, AssignmentRevision: 19,
	}
}

func websiteStatusResponse(now time.Time) StatusResponse {
	expected := websiteStatusExpected()
	commandID := "command-01"
	lastVerified := now.Add(-time.Minute)
	lastAssignment := now.Add(-2 * time.Minute)
	lastCommand := now.Add(-30 * time.Second)
	lastReceipt := now.Add(-10 * time.Second)
	return StatusResponse{
		SchemaVersion: 1, BindingID: expected.BindingID, DeviceID: expected.DeviceID, AgentRef: expected.AgentRef,
		Status: "active", CredentialEpoch: 7, AssignmentRevision: 19,
		LastVerifiedAt: &lastVerified, LastAssignmentIssuedAt: &lastAssignment, LastCommandIssuedAt: &lastCommand,
		LastReceiptReceivedAt: &lastReceipt, LastReceiptCommandID: &commandID,
		CommandChannelStale: false, ServerTime: now,
	}
}

func websiteStatusCredential(secret []byte) HMACCredential {
	return HMACCredential{KeyID: "commands-key-01", Secret: Secret(base64.StdEncoding.EncodeToString(secret))}
}
func websiteStatusPolicy() netpolicy.NetworkPolicy {
	return netpolicy.NetworkPolicy{AgentObservedIPv4: "127.0.0.1", ServerIPv4Allowlist: []string{"127.0.0.1"}}
}

func TestWebsiteStatusClientSignsExactEmptyGETAndPinsLocalIdentity(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	secret := []byte("0123456789abcdef0123456789abcdef")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != StatusPath || r.URL.RawQuery != "" || r.ContentLength != 0 {
			t.Errorf("unexpected request method=%s target=%s length=%d", r.Method, r.URL.String(), r.ContentLength)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || len(body) != 0 {
			t.Errorf("status request body=%q err=%v", body, err)
		}
		if err := protocol.VerifyRequest(r, nil, func(keyID string) ([]byte, error) {
			if keyID != "commands-key-01" {
				return nil, errors.New("wrong key")
			}
			return secret, nil
		}, protocol.VerifyOptions{Now: now}); err != nil {
			t.Errorf("request signature: %v", err)
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(websiteStatusResponse(now))
	}))
	defer server.Close()
	client, err := NewStatusClient(StatusClientConfig{
		BindingEndpoint: server.URL + "/internal/v1/agents/bind", Credential: websiteStatusCredential(secret),
		NetworkPolicy: websiteStatusPolicy(),
		HTTPClient:    server.Client(), Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(context.Background(), websiteStatusExpected())
	if err != nil || response.Status != "active" || response.AssignmentRevision != 19 {
		t.Fatalf("response=%#v err=%v", response, err)
	}
}

func TestWebsiteStatusGoldenJSON(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	raw, err := json.Marshal(websiteStatusResponse(now))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schemaVersion":1,"bindingId":"550e8400-e29b-41d4-a716-446655440001","deviceId":"device-01","agentRef":"agent-01","status":"active","credentialEpoch":"7","assignmentRevision":"19","lastVerifiedAt":"2026-08-30T11:59:00Z","lastAssignmentIssuedAt":"2026-08-30T11:58:00Z","lastCommandIssuedAt":"2026-08-30T11:59:30Z","lastReceiptReceivedAt":"2026-08-30T11:59:50Z","lastReceiptCommandId":"command-01","commandChannelStale":false,"serverTime":"2026-08-30T12:00:00Z"}`
	if string(raw) != want {
		t.Fatalf("golden mismatch\n got: %s\nwant: %s", raw, want)
	}
}

func TestWebsiteStatusRejectsUnknownDuplicateNumericAndOversizedResponses(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	secret := []byte("0123456789abcdef0123456789abcdef")
	valid, err := json.Marshal(websiteStatusResponse(now))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"unknown":   append(append([]byte(nil), valid[:len(valid)-1]...), []byte(`,"unexpected":true}`)...),
		"duplicate": []byte(strings.Replace(string(valid), `"status":"active"`, `"status":"active","status":"stale"`, 1)),
		"numeric":   []byte(strings.Replace(string(valid), `"credentialEpoch":"7"`, `"credentialEpoch":7`, 1)),
		"oversized": []byte(`{"padding":"` + strings.Repeat("x", MaxResponseBytes) + `"}`),
	}
	for name, responseBody := range cases {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(responseBody)
			}))
			defer server.Close()
			client, err := NewStatusClient(StatusClientConfig{BindingEndpoint: server.URL, Credential: websiteStatusCredential(secret), NetworkPolicy: websiteStatusPolicy(), HTTPClient: server.Client(), Now: func() time.Time { return now }})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Get(context.Background(), websiteStatusExpected()); err == nil {
				t.Fatal("invalid status response was accepted")
			}
		})
	}
}

func TestWebsiteStatusRequiresNullableFieldsAndAcceptsExplicitNull(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	secret := []byte("0123456789abcdef0123456789abcdef")
	response := websiteStatusResponse(now)
	response.LastVerifiedAt = nil
	response.LastAssignmentIssuedAt = nil
	response.LastCommandIssuedAt = nil
	response.LastReceiptReceivedAt = nil
	response.LastReceiptCommandID = nil
	valid, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	responseBody := valid
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(responseBody)
	}))
	defer server.Close()
	client, err := NewStatusClient(StatusClientConfig{
		BindingEndpoint: server.URL,
		Credential:      websiteStatusCredential(secret),
		NetworkPolicy:   websiteStatusPolicy(),
		HTTPClient:      server.Client(),
		Now:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(context.Background(), websiteStatusExpected()); err != nil {
		t.Fatalf("explicit null status fields were rejected: %v\n%s", err, valid)
	}

	nullable := []string{
		"lastVerifiedAt",
		"lastAssignmentIssuedAt",
		"lastCommandIssuedAt",
		"lastReceiptReceivedAt",
		"lastReceiptCommandId",
	}
	for _, missing := range nullable {
		t.Run(missing, func(t *testing.T) {
			var object map[string]json.RawMessage
			if err := json.Unmarshal(valid, &object); err != nil {
				t.Fatal(err)
			}
			delete(object, missing)
			responseBody, err = json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Get(context.Background(), websiteStatusExpected()); err == nil {
				t.Fatalf("status response missing %q was accepted", missing)
			}
		})
	}
}

func TestWebsiteStatusRejectsRedirectAndUnsafeEndpoint(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	followed := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/target" {
			followed = true
			return
		}
		http.Redirect(w, r, "/target", http.StatusFound)
	}))
	defer server.Close()
	client, err := NewStatusClient(StatusClientConfig{BindingEndpoint: server.URL, Credential: websiteStatusCredential(secret), NetworkPolicy: websiteStatusPolicy(), HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(context.Background(), websiteStatusExpected()); err == nil || followed {
		t.Fatalf("redirect err=%v followed=%v", err, followed)
	}
	if _, err := NewStatusClient(StatusClientConfig{BindingEndpoint: "https://[::1]/bind", Credential: websiteStatusCredential(secret), NetworkPolicy: websiteStatusPolicy()}); err == nil {
		t.Fatal("IPv6 status endpoint was accepted")
	}
}

func TestWebsiteStatusClientHardensProvidedTransport(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	provided := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS10},
	}}
	client, err := NewStatusClient(StatusClientConfig{
		BindingEndpoint: "https://website.example/internal/v1/agents/bind",
		Credential:      websiteStatusCredential(secret),
		NetworkPolicy:   netpolicy.NetworkPolicy{AgentObservedIPv4: "127.0.0.1", ServerIPv4Allowlist: []string{"192.0.2.1"}},
		HTTPClient:      provided,
	})
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.http.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.DialContext == nil || transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatal("website status client did not enforce IPv4/no-proxy/TLS 1.2 transport policy")
	}
	if original := provided.Transport.(*http.Transport); original.Proxy == nil || original.TLSClientConfig.MinVersion != tls.VersionTLS10 {
		t.Fatal("website status client mutated the caller's shared transport")
	}
}

func TestWebsiteStatusValidationRejectsWhitelistAndClockMismatch(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	tests := []func(*StatusResponse){
		func(r *StatusResponse) { r.BindingID = "550e8400-e29b-41d4-a716-446655440099" },
		func(r *StatusResponse) { r.DeviceID = "device-02" },
		func(r *StatusResponse) { r.AgentRef = "agent-02" },
		func(r *StatusResponse) { r.CredentialEpoch-- },
		func(r *StatusResponse) { r.AssignmentRevision-- },
		func(r *StatusResponse) { r.Status = "unknown" },
		func(r *StatusResponse) { r.ServerTime = now.Add(5*time.Minute + time.Second) },
	}
	for _, edit := range tests {
		response := websiteStatusResponse(now)
		edit(&response)
		if err := response.Validate(websiteStatusExpected(), now); err == nil {
			t.Fatalf("invalid response accepted: %#v", response)
		}
	}
}
