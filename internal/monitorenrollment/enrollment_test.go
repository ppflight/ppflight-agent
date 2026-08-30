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
)

func request() Request {
	return Request{SchemaVersion: 1, RequestID: "123e4567-e89b-42d3-a456-426614174000", BindingCode: "MONITOR-123456", DeviceID: "device-01", AgentVersion: "1.0.0", Hostname: "pve01.example", NodeClaim: enrollment.NodeClaim{NodeRef: "pve01", PVEVersion: "9.0.8"}, Capabilities: []string{"telemetry-v1"}}
}

func TestRequestAcceptsDottedBindingCode(t *testing.T) {
	value := request()
	value.BindingCode = "PPF.MONITOR-123456"
	if err := value.Validate(); err != nil {
		t.Fatal(err)
	}
}

func response(origin string) Response {
	return Response{SchemaVersion: 1, BindingID: "123e4567-e89b-42d3-a456-426614174001", DeviceID: "device-01", MonitoringAgentRef: "monitor-agent-01", IngestEndpoint: origin + "/internal/v1/monitoring/telemetry/batches", HMACCredential: HMACCredential{Algorithm: "hmac-sha256", KeyID: "monitor-key-01", SecretEncoding: "base64", Secret: enrollment.Secret(base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")))}, Telemetry: TelemetryContract{PayloadFormat: "telemetry-v1", Compression: "gzip", MaxCompressedBytes: 8 << 20, MaxUncompressedBytes: 32 << 20}, NetworkPolicy: netpolicy.NetworkPolicy{AgentObservedIPv4: "127.0.0.1", ServerIPv4Allowlist: []string{"127.0.0.1"}}, CredentialEpoch: 1, IssuedAt: time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)}
}

func TestIndependentMonitoringBind(t *testing.T) {
	var received Request
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response(server.URL))
	}))
	defer server.Close()
	client, err := NewClient(Config{Endpoint: server.URL + "/internal/v1/monitoring/agents/bind", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.Bind(context.Background(), request())
	if err != nil {
		t.Fatal(err)
	}
	if got.MonitoringAgentRef != "monitor-agent-01" || received.RequestID == "" || received.BindingCode != "MONITOR-123456" {
		t.Fatalf("got=%#v received=%#v", got, received)
	}
}

func TestMonitoringResponseRequiresItsOwnCanonicalNetworkPolicy(t *testing.T) {
	endpoint, err := secureURL("https://monitor.example/internal/v1/monitoring/agents/bind")
	if err != nil {
		t.Fatal(err)
	}
	value := response("https://monitor.example")
	if err := value.Validate(endpoint); err != nil {
		t.Fatal(err)
	}
	value.NetworkPolicy.ServerIPv4Allowlist = []string{"192.0.2.10", "192.0.2.10"}
	if err := value.Validate(endpoint); err == nil {
		t.Fatal("accepted duplicate monitoring allowlist")
	}
}

func TestMonitoringBindRejectsDeviceMismatchDuplicateAndCrossOrigin(t *testing.T) {
	for name, body := range map[string]func(string) []byte{
		"device": func(origin string) []byte {
			v := response(origin)
			v.DeviceID = "other-device"
			raw, _ := json.Marshal(v)
			return raw
		},
		"origin": func(origin string) []byte {
			v := response(origin)
			v.IngestEndpoint = "https://other.example/ingest"
			raw, _ := json.Marshal(v)
			return raw
		},
		"duplicate": func(origin string) []byte {
			v := response(origin)
			raw, _ := json.Marshal(v)
			return append(raw[:len(raw)-1], []byte(`,"credentialEpoch":2}`)...)
		},
	} {
		t.Run(name, func(t *testing.T) {
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(body(server.URL))
			}))
			defer server.Close()
			client, err := NewClient(Config{Endpoint: server.URL, HTTPClient: server.Client()})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Bind(context.Background(), request()); err == nil {
				t.Fatal("accepted invalid response")
			}
		})
	}
}

func TestMonitoringResponseLimitsAndSecretRedaction(t *testing.T) {
	value := response("https://monitor.example")
	value.Telemetry.PayloadFormat = "legacy-ingest-v1"
	endpoint, _ := secureURL("https://monitor.example/bind")
	if err := value.Validate(endpoint); err == nil {
		t.Fatal("accepted legacy payload from automatic bind")
	}
	if text := value.HMACCredential.Secret.String(); strings.Contains(text, "012345") {
		t.Fatalf("secret leaked: %s", text)
	}
}
