package admincli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/bindingoverlay"
	"github.com/ppflight/ppflight-agent/internal/config"
	"github.com/ppflight/ppflight-agent/internal/enrollment"
	"github.com/ppflight/ppflight-agent/internal/monitorenrollment"
	"github.com/ppflight/ppflight-agent/internal/netpolicy"
)

func TestRealCLIDualBindResolvesRuntimeOverlay(t *testing.T) {
	filename := prepareBindConfig(t)
	assertIPv4 := func(r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || net.ParseIP(host).To4() == nil {
			t.Errorf("request did not arrive over IPv4: %q", r.RemoteAddr)
		}
	}

	var website *httptest.Server
	website = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertIPv4(r)
		switch r.URL.Path {
		case "/internal/v1/agents/bind":
			var request enrollment.Request
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode website bind: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			response := bindingResponse(website.URL)
			response.DeviceID = request.DeviceID
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(response)
		case "/assignments":
			w.WriteHeader(http.StatusNoContent)
		case "/commands":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"schemaVersion": 1, "cursor": "cursor-1", "commands": []any{}})
		case "/metering", "/telemetry", "/receipts":
			w.WriteHeader(http.StatusAccepted)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer website.Close()

	var monitoring *httptest.Server
	monitoring = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertIPv4(r)
		switch r.URL.Path {
		case "/internal/v1/monitoring/agents/bind":
			var request monitorenrollment.Request
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode monitoring bind: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			secret := enrollment.Secret(base64.StdEncoding.EncodeToString([]byte("monitoring-secret")))
			response := monitorenrollment.Response{
				SchemaVersion: 1, BindingID: "123e4567-e89b-42d3-a456-426614174003", DeviceID: request.DeviceID,
				MonitoringAgentRef: "monitor-agent-01", IngestEndpoint: monitoring.URL + monitorenrollment.TelemetryPath,
				HMACCredential:  monitorenrollment.HMACCredential{Algorithm: "hmac-sha256", KeyID: "monitor-key-01", SecretEncoding: "base64", Secret: secret},
				Telemetry:       monitorenrollment.TelemetryContract{PayloadFormat: "telemetry-v1", Compression: "gzip", MaxCompressedBytes: 8 << 20, MaxUncompressedBytes: 32 << 20},
				NetworkPolicy:   netpolicy.NetworkPolicy{AgentObservedIPv4: "127.0.0.1", ServerIPv4Allowlist: []string{"127.0.0.1"}},
				CredentialEpoch: 1, IssuedAt: time.Now().UTC(),
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(response)
		case monitorenrollment.TelemetryPath, monitorenrollment.AuditPath:
			w.WriteHeader(http.StatusAccepted)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer monitoring.Close()

	var stdout, stderr bytes.Buffer
	websiteCode := runWebsiteBindForTest([]string{"--config", filename, "bind", "--endpoint", website.URL + "/internal/v1/agents/bind", "--hostname", "pve-test"}, "integration", strings.NewReader("WEBSITE-123456\n"), &stdout, &stderr)
	if websiteCode != 0 {
		t.Fatalf("website bind code=%d stderr=%s", websiteCode, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	monitoringCode := runMonitoringBindForTest([]string{"--config", filename, "monitoring", "bind", "--endpoint", monitoring.URL + "/internal/v1/monitoring/agents/bind", "--hostname", "pve-test"}, "integration", strings.NewReader("MONITOR-123456\n"), &stdout, &stderr)
	if monitoringCode != 0 {
		t.Fatalf("monitoring bind code=%d stderr=%s", monitoringCode, stderr.String())
	}

	cfg, err := config.LoadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := bindingoverlay.Resolve(cfg, func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatalf("runtime binding overlay: %v", err)
	}
	if secrets.WebsiteBindingID == "" || secrets.WebsiteCredentialEpoch != 1 || secrets.MonitoringBindingID == "" || secrets.MonitoringAudit.CredentialEpoch != 1 {
		t.Fatalf("incomplete runtime identities: %#v", secrets)
	}
}
