package pve

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func testClient(t *testing.T, h http.Handler) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewTLSServer(h)
	c, err := NewClient(Config{Endpoint: server.URL, TokenID: "monitor@pve!agent", TokenSecret: "secret", InsecureSkipTLS: true})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return c, server
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
func TestClientRejectsRemotePlainHTTP(t *testing.T) {
	if _, err := NewClient(Config{Endpoint: "http://pve.example.test:8006", TokenID: "x", TokenSecret: "x"}); err == nil {
		t.Fatal("expected error")
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
