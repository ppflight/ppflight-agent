package enrollment

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/netpolicy"
)

func validRequest() Request {
	return Request{SchemaVersion: SchemaVersion, RequestID: "123e4567-e89b-42d3-a456-426614174000", BindingCode: "BINDING-123456", DeviceID: "device-01", AgentVersion: "1.2.3", Hostname: "pve-node-1.example", NodeClaim: NodeClaim{NodeRef: "node-01", PVEVersion: "8.2.2"}, Capabilities: []string{"inventory", "telemetry"}}
}

func validResponse(serverURL string) Response {
	secret := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	credential := HMACCredential{KeyID: "key-01", Secret: Secret(secret)}
	return Response{
		SchemaVersion: SchemaVersion, BindingID: "123e4567-e89b-42d3-a456-426614174001", DeviceID: "device-01", AgentRef: "agent-01", CollectorRef: "collector-01", SourceRef: "source-01", ClusterRef: "cluster-01", NodeRef: "node-01", Site: "site-01",
		Endpoints:                Endpoints{Metering: serverURL + "/metering", Telemetry: serverURL + "/telemetry", Assignments: serverURL + "/assignments", Commands: serverURL + "/commands", Receipts: serverURL + "/receipts"},
		HMACCredentials:          HMACCredentials{Metering: credential, Telemetry: credential, Assignments: credential, Commands: credential, Receipts: credential},
		CommandSigningCredential: CommandSigningCredential{KeyID: "command-key-01", Algorithm: "ed25519", PublicKey: key},
		AllowedActions:           []string{"vm.start", "vm.shutdown"}, AssignmentDocument: json.RawMessage(`{"assignments":[]}`), CredentialEpoch: 1, IssuedAt: time.Date(2026, 8, 30, 1, 2, 3, 0, time.UTC),
		NetworkPolicy: netpolicy.NetworkPolicy{AgentObservedIPv4: "127.0.0.1", ServerIPv4Allowlist: []string{"127.0.0.1"}},
	}
}

func TestBindPostsStrictJSONAndReturnsValidatedResponse(t *testing.T) {
	var received Request
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content type = %q", r.Header.Get("Content-Type"))
		}
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&received); err != nil {
			t.Errorf("decode request: %v", err)
		}
		var extra any
		if decoder.Decode(&extra) == nil {
			t.Error("request contained a second JSON value")
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err := json.NewEncoder(w).Encode(validResponse(server.URL)); err != nil {
			t.Fatal(err)
		}
	}))
	defer server.Close()
	client, err := NewClient(Config{Endpoint: server.URL + "/v1/bind", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Bind(context.Background(), validRequest())
	if err != nil {
		t.Fatal(err)
	}
	if response.AgentRef != "agent-01" || received.BindingCode != "BINDING-123456" {
		t.Fatalf("wrong binding data: %#v / %#v", response.AgentRef, received)
	}
}

func TestBindRejectsUnknownResponseFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := validResponse(serverURL(r))
		encoded, _ := json.Marshal(response)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(append(encoded[:len(encoded)-1], []byte(`,"unexpected":true}`)...))
	}))
	defer server.Close()
	client, err := NewClient(Config{Endpoint: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Bind(context.Background(), validRequest()); err == nil || strings.Contains(err.Error(), "BINDING-123456") {
		t.Fatalf("error = %v", err)
	}
}

func TestBindRejectsRetiredServerIPv4Allowlist(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		encoded, _ := json.Marshal(validResponse(serverURL(r)))
		encoded = []byte(strings.Replace(string(encoded), `"networkPolicy":{"agentObservedIPv4":"127.0.0.1"}`, `"networkPolicy":{"agentObservedIPv4":"127.0.0.1","serverIPv4Allowlist":["192.0.2.1"]}`, 1))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(encoded)
	}))
	defer server.Close()
	client, err := NewClient(Config{Endpoint: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Bind(context.Background(), validRequest()); err == nil {
		t.Fatal("accepted retired serverIPv4Allowlist in strict bind response")
	}
}

func TestBindRejectsCrossOriginEndpointAndDoesNotLeakSecrets(t *testing.T) {
	secret := "SECRET-MUST-NOT-LEAK"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := validResponse(serverURL(r))
		response.Endpoints.Commands = "https://elsewhere.example/commands"
		response.HMACCredentials.Commands.Secret = Secret(secret)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
	client, err := NewClient(Config{Endpoint: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Bind(context.Background(), validRequest())
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe error: %v", err)
	}
}

func TestBindRejectsRedirectAndOversizedResponse(t *testing.T) {
	redirected := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/target" {
			redirected = true
			return
		}
		http.Redirect(w, r, "/target", http.StatusFound)
	}))
	defer server.Close()
	client, err := NewClient(Config{Endpoint: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Bind(context.Background(), validRequest()); err == nil || redirected {
		t.Fatalf("redirect err=%v followed=%t", err, redirected)
	}

	large := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{" + strings.Repeat("x", MaxResponseBytes+1) + "}"))
	}))
	defer large.Close()
	client, err = NewClient(Config{Endpoint: large.URL, HTTPClient: large.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Bind(context.Background(), validRequest()); err == nil {
		t.Fatal("accepted oversized response")
	}
}

func TestValidationAndSecureTransport(t *testing.T) {
	request := validRequest()
	request.BindingCode = "bad code"
	if err := request.Validate(); err == nil || strings.Contains(err.Error(), request.BindingCode) {
		t.Fatalf("binding code leaked: %v", err)
	}
	request = validRequest()
	request.BindingCode = "PPF.WEBSITE-123456"
	if err := request.Validate(); err != nil {
		t.Fatalf("dotted human-readable code rejected: %v", err)
	}
	if formatted := fmt.Sprint(HMACCredential{KeyID: "key-01", Secret: Secret("not-for-logs")}); strings.Contains(formatted, "not-for-logs") {
		t.Fatalf("credential formatting leaked secret: %q", formatted)
	}
	if _, err := NewClient(Config{Endpoint: "http://service.example/v1/bind"}); err == nil {
		t.Fatal("accepted non-loopback HTTP")
	}
	if _, err := NewClient(Config{Endpoint: "https://service.example/v1/bind?token=bad"}); err == nil {
		t.Fatal("accepted endpoint query")
	}
	base := &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS10}}}
	client, err := NewClient(Config{Endpoint: "https://service.example/v1/bind", HTTPClient: base})
	if err != nil {
		t.Fatal(err)
	}
	transport := client.http.Transport.(*http.Transport)
	if transport.Proxy != nil || transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatal("client did not disable proxy or require TLS 1.2")
	}
}

func TestResponseValidateAllRequiredContractGroups(t *testing.T) {
	baseURL := "https://service.example"
	for name, mutate := range map[string]func(*Response){
		"identity":   func(r *Response) { r.AgentRef = "" },
		"endpoint":   func(r *Response) { r.Endpoints.Telemetry = "http://service.example/telemetry" },
		"hmac":       func(r *Response) { r.HMACCredentials.Metering.Secret = "not-base64" },
		"signing":    func(r *Response) { r.CommandSigningCredential.Algorithm = "rsa" },
		"actions":    func(r *Response) { r.AllowedActions = []string{"bad action"} },
		"assignment": func(r *Response) { r.AssignmentDocument = json.RawMessage(`[]`) },
		"network":    func(r *Response) { r.NetworkPolicy.AgentObservedIPv4 = "0.0.0.0" },
		"epoch":      func(r *Response) { r.CredentialEpoch = 0 },
		"issued":     func(r *Response) { r.IssuedAt = time.Time{} },
	} {
		t.Run(name, func(t *testing.T) {
			response := validResponse(baseURL)
			mutate(&response)
			endpoint, err := parseSecureURL(baseURL + "/v1/bind")
			if err != nil {
				t.Fatal(err)
			}
			if err := response.Validate(endpoint); err == nil {
				t.Fatal("accepted invalid response")
			}
		})
	}
}

func TestResponseAllowsCompleteThirtyThreeActionRegistry(t *testing.T) {
	response := validResponse("https://service.example")
	response.AllowedActions = make([]string, 33)
	for index := range response.AllowedActions {
		response.AllowedActions[index] = fmt.Sprintf("vm.action-%d", index+1)
	}
	endpoint, err := parseSecureURL("https://service.example/v1/bind")
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Validate(endpoint); err != nil {
		t.Fatalf("33-action website grant was rejected: %v", err)
	}
}

func serverURL(r *http.Request) string { return "http://" + r.Host }
