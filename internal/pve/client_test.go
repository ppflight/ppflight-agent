package pve

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testClient(t *testing.T, h http.Handler) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewTLSServer(h)
	c, err := NewClient(testTLSConfig(t, server, "monitor@pve!agent", "secret"))
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return c, server
}

func testTLSConfig(t *testing.T, server *httptest.Server, tokenID, tokenSecret string) Config {
	t.Helper()
	certificate, err := x509.ParseCertificate(server.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "pve-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return Config{Endpoint: server.URL, TokenID: tokenID, TokenSecret: tokenSecret, CAFile: caFile, TLSServerName: "example.com"}
}
func TestClientAuthAndPath(t *testing.T) {
	c, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "PVEAPIToken=monitor@pve!agent=secret" {
			t.Errorf("bad auth header")
		}
		if r.URL.Path != "/api2/json/nodes/pve1/status" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		fmt.Fprint(w, `{"data":{"uptime":1}}`)
	}))
	defer server.Close()
	if _, err := c.NodeStatus(context.Background(), "pve1"); err != nil {
		t.Fatal(err)
	}
}

func TestClientReportsProgressAfterSuccessAndFailure(t *testing.T) {
	c, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "failure") {
			http.Error(w, "failed", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprint(w, `{"data":{}}`)
	}))
	defer server.Close()
	var progress atomic.Uint64
	c.SetProgressReporter(func() { progress.Add(1) })
	var result map[string]any
	if err := c.Do(context.Background(), http.MethodGet, "/success", nil, nil, &result); err != nil {
		t.Fatal(err)
	}
	if err := c.Do(context.Background(), http.MethodGet, "/failure", nil, nil, &result); err == nil {
		t.Fatal("expected failure")
	}
	if progress.Load() != 2 {
		t.Fatalf("progress=%d", progress.Load())
	}
}

func TestHTTPErrorExtractsOnlyBoundedTopLevelPVEMessage(t *testing.T) {
	c, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"data":null,"message":"Configuration file 'nodes/pve1/qemu-server/101.conf' does not exist","errors":{"message":"nested value"}}`)
	}))
	defer server.Close()
	var result map[string]any
	err := c.Do(context.Background(), http.MethodDelete, "/nodes/pve1/qemu/101", nil, nil, &result)
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("error=%v", err)
	}
	if httpErr.StatusCode != http.StatusInternalServerError || httpErr.Reason != "Configuration file 'nodes/pve1/qemu-server/101.conf' does not exist" {
		t.Fatalf("HTTP error=%#v", httpErr)
	}
	if !strings.Contains(httpErr.Body, `"nested value"`) {
		t.Fatalf("bounded diagnostic body=%q", httpErr.Body)
	}
}

func TestHTTPErrorDoesNotPromotePlainTextToStructuredReason(t *testing.T) {
	c, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Configuration file does not exist", http.StatusInternalServerError)
	}))
	defer server.Close()
	var result map[string]any
	err := c.Do(context.Background(), http.MethodDelete, "/nodes/pve1/qemu/101", nil, nil, &result)
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.Reason != "" {
		t.Fatalf("error=%#v", err)
	}
}
func TestClientWriteAndUPID(t *testing.T) {
	c, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil || r.Form.Get("name") != "new" {
				t.Error("write form not sent")
			}
			fmt.Fprint(w, `{"data":"UPID:node:1"}`)
			return
		}
		if !strings.Contains(r.URL.Path, "UPID:node:1") {
			t.Errorf("UPID path was corrupted: %s", r.URL.EscapedPath())
		}
		fmt.Fprint(w, `{"data":{"status":"OK"}}`)
	}))
	defer server.Close()
	var upid string
	if err := c.Do(context.Background(), http.MethodPost, "/nodes/pve1/qemu", nil, url.Values{"name": {"new"}}, &upid); err != nil {
		t.Fatal(err)
	}
	if upid != "UPID:node:1" {
		t.Fatalf("upid %q", upid)
	}
	if _, err := c.TaskStatus(context.Background(), "pve1", upid); err != nil {
		t.Fatal(err)
	}
}

func TestClientRejectsDeleteFormBodyBeforeRequest(t *testing.T) {
	requests := 0
	c, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		fmt.Fprint(w, `{"data":null}`)
	}))
	defer server.Close()
	var result json.RawMessage
	err := c.Do(context.Background(), http.MethodDelete, "/nodes/pve1/qemu/101", nil, url.Values{"purge": {"1"}}, &result)
	if err == nil || err.Error() != "pve DELETE parameters must be encoded in query" {
		t.Fatalf("error=%v", err)
	}
	if requests != 0 {
		t.Fatalf("requests=%d, want 0", requests)
	}
}
func TestProbeAbsentAgentIsUnavailable(t *testing.T) {
	c, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "agent not running", http.StatusInternalServerError)
	}))
	defer server.Close()
	result, err := c.ProbeGuestAgent(context.Background(), "pve1", 100)
	if err != nil {
		t.Fatal(err)
	}
	if result.Availability["os"] != Unavailable || result.OS != nil {
		t.Fatalf("got %#v", result)
	}
}

func TestProbeGuestAgentReportsProgressForEveryBoundedSubrequest(t *testing.T) {
	c, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/agent/info"):
			fmt.Fprint(w, `{"data":{"version":"9.0","supported_commands":[{"name":"guest-get-osinfo","enabled":true},{"name":"guest-get-fsinfo","enabled":true},{"name":"guest-network-get-interfaces","enabled":true}]}}`)
		case strings.HasSuffix(r.URL.Path, "/agent/get-osinfo"):
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
		case strings.HasSuffix(r.URL.Path, "/agent/get-fsinfo"):
			fmt.Fprint(w, `{"data":[]}`)
		case strings.HasSuffix(r.URL.Path, "/agent/network-get-interfaces"):
			fmt.Fprint(w, `{"data":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	var progress atomic.Uint64
	c.SetProgressReporter(func() { progress.Add(1) })
	result, err := c.ProbeGuestAgent(context.Background(), "pve1", 100)
	if err != nil {
		t.Fatal(err)
	}
	if progress.Load() != 4 {
		t.Fatalf("progress=%d want one signal for each QGA request", progress.Load())
	}
	if result.Availability["info"] != Available || result.Availability["os"] != Unavailable || result.Availability["filesystems"] != Available || result.Availability["interfaces"] != Available {
		t.Fatalf("availability=%#v", result.Availability)
	}
}

func TestClientRejectsRemotePlainHTTP(t *testing.T) {
	if _, err := NewClient(Config{Endpoint: "http://pve.example.test:8006", TokenID: "x", TokenSecret: "x"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestClientRejectsInsecureTLS(t *testing.T) {
	if _, err := NewClient(Config{Endpoint: "https://127.0.0.1:8006", TokenID: "x", TokenSecret: "x", InsecureSkipTLS: true}); err == nil {
		t.Fatal("insecure TLS was accepted")
	}
}

func TestClientRejectsRequestTimeoutLongerThanWatchdogProgressWindow(t *testing.T) {
	if _, err := NewClient(Config{Endpoint: "https://127.0.0.1:8006", TokenID: "x", TokenSecret: "x", Timeout: 31 * time.Second}); err == nil {
		t.Fatal("unbounded PVE request timeout was accepted")
	}
}
func TestTLSConfigHasMinimumVersion(t *testing.T) {
	c, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"data":[]}`) }))
	defer server.Close()
	transport := c.http.Transport.(*http.Transport)
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatal("TLS minimum was not set")
	}
	if transport.Proxy != nil {
		t.Fatal("PVE client must not use ambient proxy configuration")
	}
	if c.http.CheckRedirect == nil {
		t.Fatal("PVE client must reject redirects")
	}
}

func TestTLSNameVerificationIsSeparatedFromIPv4LoopbackDial(t *testing.T) {
	var remoteIP, sni string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			t.Errorf("remote address: %v", err)
		}
		remoteIP, sni = host, r.TLS.ServerName
		fmt.Fprint(w, `{"data":{"version":"9.0"}}`)
	}))
	server.StartTLS()
	defer server.Close()
	client, err := NewClient(testTLSConfig(t, server, "read@pve!collector", "secret-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Version(context.Background()); err != nil {
		t.Fatal(err)
	}
	if parsed := net.ParseIP(remoteIP); parsed == nil || parsed.To4() == nil || sni != "example.com" {
		t.Fatalf("remoteIP=%q sni=%q", remoteIP, sni)
	}
}

func TestTLSNameRejectsIPsWildcardsAndUnsafeLabels(t *testing.T) {
	for _, value := range []string{"", "127.0.0.1", "*.example.test", " name.example", "-node.example", "node_.example"} {
		if ValidateTLSServerName(value) == nil {
			t.Fatalf("unsafe TLS server name accepted: %q", value)
		}
	}
	for _, value := range []string{"pve", "pve-01.example.test"} {
		if err := ValidateTLSServerName(value); err != nil {
			t.Fatalf("valid TLS server name %q rejected: %v", value, err)
		}
	}
}

func TestClientRejectsRedirects(t *testing.T) {
	redirected := false
	c, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect-target" {
			redirected = true
			fmt.Fprint(w, `{"data":{}}`)
			return
		}
		http.Redirect(w, r, "/redirect-target", http.StatusFound)
	}))
	defer server.Close()
	var result map[string]any
	err := c.Do(context.Background(), http.MethodGet, "/nodes/pve1/status", nil, nil, &result)
	if err == nil {
		t.Fatal("redirect response was accepted")
	}
	if redirected {
		t.Fatal("PVE client followed a redirect")
	}
}

func TestNodeStatusAcceptsStringLoadAverage(t *testing.T) {
	c, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":{"loadavg":["0.10",0.20,"0.30"]}}`)
	}))
	defer server.Close()
	status, err := c.NodeStatus(context.Background(), "pve1")
	if err != nil || len(status.LoadAvg) != 3 || status.LoadAvg[1] != .2 {
		t.Fatalf("unexpected status: %#v, %v", status, err)
	}
}

func TestNodesIncludesIdleClusterMember(t *testing.T) {
	c, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api2/json/nodes" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		fmt.Fprint(w, `{"data":[{"node":"idle-node","status":"online"}]}`)
	}))
	defer server.Close()
	nodes, err := c.Nodes(context.Background())
	if err != nil || len(nodes) != 1 || nodes[0].Node != "idle-node" {
		t.Fatalf("unexpected nodes %#v: %v", nodes, err)
	}
}
