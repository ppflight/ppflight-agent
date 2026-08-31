package discovery

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ppflight/ppflight-agent/internal/pve"
)

func testService(t *testing.T, handler http.Handler) (*Service, *httptest.Server) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	certificate, err := x509.ParseCertificate(server.Certificate().Raw)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "pve-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0o600); err != nil {
		server.Close()
		t.Fatal(err)
	}
	client, err := pve.NewClient(pve.Config{Endpoint: server.URL, TokenID: "discover@pve!agent", TokenSecret: "secret", CAFile: caFile, TLSServerName: "example.com"})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return New(client), server
}

func TestDiscoverTemplatesIsBoundedAndPageable(t *testing.T) {
	service, server := testService(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method %s", r.Method)
		}
		switch r.URL.Path {
		case "/api2/json/cluster/resources":
			if r.URL.Query().Get("type") != "vm" || r.URL.Query().Has("start") || r.URL.Query().Has("limit") {
				t.Errorf("query %s", r.URL.RawQuery)
			}
			fmt.Fprint(w, `{"data":[{"id":"qemu/101","type":"qemu","node":"pve1","vmid":101,"name":"golden","template":1},{"id":"lxc/102","type":"lxc","node":"pve1","vmid":102,"template":0},{"id":"qemu/103","type":"qemu","node":"pve1","vmid":103,"template":0}]}`)
		case "/api2/json/nodes/pve1/qemu/101/config":
			fmt.Fprint(w, `{"data":{"scsi2":"fast:cloudinit","net0":"virtio=aa"}}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	result := service.Discover(context.Background(), Request{OperationID: "op-1", Phase: PhaseTemplates, Limit: 2})
	if result.ErrorCode != "" || result.Complete || result.NextCursor != "2" {
		t.Fatalf("page result %#v", result)
	}
	if len(result.Data.Templates) != 1 || !result.Data.Templates[0].CloudInit || result.Data.Templates[0].NetworkCount != 1 {
		t.Fatalf("templates %#v", result.Data.Templates)
	}
}

func TestDiscoverFirewallCoversClusterNodeAndGuest(t *testing.T) {
	service, server := testService(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method %s", r.Method)
		}
		switch r.URL.Path {
		case "/api2/json/cluster/resources":
			fmt.Fprint(w, `{"data":[{"id":"qemu/101","type":"qemu","node":"pve1","vmid":101}]}`)
		case "/api2/json/cluster/firewall/options", "/api2/json/nodes/pve1/firewall/options", "/api2/json/nodes/pve1/qemu/101/firewall/options":
			fmt.Fprint(w, `{"data":{"enable":1}}`)
		case "/api2/json/cluster/firewall/rules", "/api2/json/nodes/pve1/firewall/rules", "/api2/json/nodes/pve1/qemu/101/firewall/rules":
			fmt.Fprint(w, `{"data":[{"pos":0,"type":"in","action":"ACCEPT"}]}`)
		case "/api2/json/cluster/firewall/ipset", "/api2/json/nodes/pve1/qemu/101/firewall/ipset":
			fmt.Fprint(w, `{"data":[{"name":"office"}]}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	result := service.Discover(context.Background(), Request{OperationID: "op-2", Phase: PhaseFirewall, NodeRef: "pve1", Limit: 2})
	if result.ErrorCode != "" || !result.Complete || len(result.Data.Firewall) != 3 {
		t.Fatalf("firewall result %#v", result)
	}
	for _, scope := range result.Data.Firewall {
		wantIPSets := 1
		if scope.Scope == "node" {
			wantIPSets = 0
		}
		if scope.Options == nil || len(scope.Rules) != 1 || len(scope.IPSets) != wantIPSets {
			t.Fatalf("incomplete scope %#v", scope)
		}
	}
}

func TestDiscoverPaginationValidationAndSafeErrors(t *testing.T) {
	service, server := testService(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method %s", r.Method)
		}
		if r.URL.Path != "/api2/json/access/permissions" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") == "" {
			t.Error("missing PVE token")
		}
		fmt.Fprint(w, `{"data":{"/vms/1":{"VM.Audit":1},"/":{"Sys.Audit":1}}}`)
	}))
	defer server.Close()
	invalid := service.Discover(context.Background(), Request{OperationID: "bad space", Phase: PhaseNodes})
	if invalid.ErrorCode != "INVALID_REQUEST" || !invalid.Complete {
		t.Fatalf("invalid %#v", invalid)
	}
	page := service.Discover(context.Background(), Request{OperationID: "op-3", Phase: PhasePermissions, Limit: 1})
	if page.ErrorCode != "" || page.Complete || page.NextCursor != "1" || len(page.Data.Permissions) != 1 || page.Data.Permissions[0].Path != "/" {
		t.Fatalf("permission page %#v", page)
	}
}

func TestDiscoverCapacityAndReadinessUseNodeScopedReads(t *testing.T) {
	service, server := testService(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method %s", r.Method)
		}
		switch r.URL.Path {
		case "/api2/json/nodes":
			fmt.Fprint(w, `{"data":[{"node":"pve1","status":"online"}]}`)
		case "/api2/json/nodes/pve1/status":
			fmt.Fprint(w, `{"data":{"pveversion":"8.4.1","uptime":0}}`)
		case "/api2/json/nodes/pve1/storage":
			fmt.Fprint(w, `{"data":[{"storage":"local","type":"dir"},{"storage":"fast","type":"zfspool"}]}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	capacity := service.Discover(context.Background(), Request{OperationID: "op-5", Phase: PhaseCapacity, NodeRef: "pve1", Limit: 1})
	if capacity.ErrorCode != "" || capacity.Complete || capacity.NextCursor != "1" || capacity.Data.Capacity == nil || len(capacity.Data.Capacity.Storage) != 1 {
		t.Fatalf("capacity %#v", capacity)
	}
	readiness := service.Discover(context.Background(), Request{OperationID: "op-6", Phase: PhaseReadiness, NodeRef: "pve1"})
	if readiness.ErrorCode != "" || !readiness.Data.Readiness.Ready || readiness.Data.Readiness.Nodes[0].Status != "online" {
		t.Fatalf("readiness %#v", readiness)
	}
}

func TestDiscoverClassifiesForbiddenWithoutLeakingPVEBody(t *testing.T) {
	service, server := testService(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "private PVE detail", http.StatusForbidden)
	}))
	defer server.Close()
	result := service.Discover(context.Background(), Request{OperationID: "op-4", Phase: PhaseVersion})
	if result.ErrorCode != "PVE_FORBIDDEN" || !result.Complete {
		t.Fatalf("result %#v", result)
	}
}
