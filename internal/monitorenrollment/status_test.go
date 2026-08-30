package monitorenrollment

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/enrollment"
	"github.com/ppflight/ppflight-agent/internal/netpolicy"
	"github.com/ppflight/ppflight-agent/internal/protocol"
)

func TestStatusClientSignsAndPinsLocalWhitelist(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	secret := []byte("0123456789abcdef0123456789abcdef")
	expected := StatusExpected{BindingID: "550e8400-e29b-41d4-a716-446655440001", DeviceID: "device-01", MonitoringAgentRef: "monitor-agent-01", CredentialEpoch: 7}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != StatusPath || r.URL.RawQuery != "" {
			t.Errorf("unexpected target %s", r.URL.String())
		}
		if err := protocol.VerifyRequest(r, nil, func(key string) ([]byte, error) { return secret, nil }, protocol.VerifyOptions{Now: now}); err != nil {
			t.Errorf("request was not signed: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(StatusResponse{SchemaVersion: 1, BindingID: expected.BindingID, DeviceID: expected.DeviceID, MonitoringAgentRef: expected.MonitoringAgentRef, Status: "active", CredentialEpoch: 7, ServerTime: now})
	}))
	defer server.Close()
	client, err := NewStatusClient(StatusClientConfig{BindingEndpoint: server.URL + "/internal/v1/monitoring/agents/bind", HTTPClient: server.Client(), Now: func() time.Time { return now }, NetworkPolicy: netpolicy.NetworkPolicy{AgentObservedIPv4: "127.0.0.1", ServerIPv4Allowlist: []string{"127.0.0.1"}}, Credential: HMACCredential{Algorithm: "hmac-sha256", KeyID: "monitor-key-01", SecretEncoding: "base64", Secret: enrollment.Secret(base64.StdEncoding.EncodeToString(secret))}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Get(context.Background(), expected)
	if err != nil || result.Status != "active" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestStatusResponseRejectsDifferentBinding(t *testing.T) {
	now := time.Now().UTC()
	response := StatusResponse{SchemaVersion: 1, BindingID: "550e8400-e29b-41d4-a716-446655440001", DeviceID: "device-01", MonitoringAgentRef: "monitor-agent-01", Status: "active", CredentialEpoch: 1, ServerTime: now}
	if err := response.Validate(StatusExpected{BindingID: "550e8400-e29b-41d4-a716-446655440099", DeviceID: "device-01", MonitoringAgentRef: "monitor-agent-01", CredentialEpoch: 1}, now); err == nil {
		t.Fatal("cross-binding status was accepted")
	}
}

func TestMonitoringStatusRequiresExactFieldsAndAcceptsExplicitNull(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	secret := []byte("0123456789abcdef0123456789abcdef")
	expected := StatusExpected{BindingID: "550e8400-e29b-41d4-a716-446655440001", DeviceID: "device-01", MonitoringAgentRef: "monitor-agent-01", CredentialEpoch: 7}
	valid, err := json.Marshal(StatusResponse{
		SchemaVersion: 1, BindingID: expected.BindingID, DeviceID: expected.DeviceID,
		MonitoringAgentRef: expected.MonitoringAgentRef, Status: "active",
		CredentialEpoch: 7, ServerTime: now,
	})
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
		HTTPClient:      server.Client(),
		Now:             func() time.Time { return now },
		NetworkPolicy:   netpolicy.NetworkPolicy{AgentObservedIPv4: "127.0.0.1", ServerIPv4Allowlist: []string{"127.0.0.1"}},
		Credential: HMACCredential{
			Algorithm: "hmac-sha256", KeyID: "monitor-key-01", SecretEncoding: "base64",
			Secret: enrollment.Secret(base64.StdEncoding.EncodeToString(secret)),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(context.Background(), expected); err != nil {
		t.Fatalf("explicit null status fields were rejected: %v\n%s", err, valid)
	}

	nullable := []string{
		"lastVerifiedAt",
		"lastTelemetryReceivedAt",
		"lastTelemetryBatchId",
		"lastAuditReceivedAt",
		"lastAuditBatchId",
	}
	for _, missing := range nullable {
		t.Run("missing_"+missing, func(t *testing.T) {
			var object map[string]json.RawMessage
			if err := json.Unmarshal(valid, &object); err != nil {
				t.Fatal(err)
			}
			delete(object, missing)
			responseBody, err = json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Get(context.Background(), expected); err == nil {
				t.Fatalf("status response missing %q was accepted", missing)
			}
		})
	}

	responseBody = append(append([]byte(nil), valid[:len(valid)-1]...), []byte(`,"unexpected":true}`)...)
	if _, err := client.Get(context.Background(), expected); err == nil {
		t.Fatal("monitoring status response with an unknown field was accepted")
	}
	responseBody = []byte(strings.Replace(string(valid), `"status":"active"`, `"status":"active","status":"stale"`, 1))
	if _, err := client.Get(context.Background(), expected); err == nil {
		t.Fatal("monitoring status response with a duplicate field was accepted")
	}
}
