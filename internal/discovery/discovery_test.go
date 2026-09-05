package discovery

import (
	"context"
	"crypto/x509"
	"encoding/json"
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
			fmt.Fprint(w, `{"data":{"cores":2,"sockets":1,"memory":1024,"scsi0":"fast:vm-101-disk-0,size=8G","ide2":"fast:cloudinit,media=cdrom","net0":"virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=0","agent":"enabled=1","tags":"ppflight-cloudinit;ppflight-qga-preinstalled"}}`)
		case "/api2/json/nodes/pve1/qemu/101/firewall/rules", "/api2/json/nodes/pve1/qemu/101/firewall/ipset":
			fmt.Fprint(w, `{"data":[]}`)
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
	if len(result.Data.Templates) != 1 || !result.Data.Templates[0].CloudInit || result.Data.Templates[0].NetworkCount != 1 || result.Data.Templates[0].ConfigSHA256 == "" || !result.Data.Templates[0].Baseline.QGAPackagePreinstalled || !result.Data.Templates[0].Baseline.GuestFirewallEmpty {
		t.Fatalf("templates %#v", result.Data.Templates)
	}
}

func TestDiscoverGuestsReturnsOnlyNonTemplateVMIDs(t *testing.T) {
	service, server := testService(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api2/json/cluster/resources" {
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `{"data":[{"id":"qemu/100","type":"qemu","node":"pve1","vmid":100,"template":1},{"id":"qemu/101","type":"qemu","node":"pve1","vmid":101,"template":0},{"id":"lxc/102","type":"lxc","node":"pve2","vmid":102,"template":0}]}`)
	}))
	defer server.Close()

	result := service.Discover(context.Background(), Request{OperationID: "guest-inventory", Phase: PhaseGuests, Limit: 50})
	if result.ErrorCode != "" || !result.Complete || len(result.Data.Guests) != 2 {
		t.Fatalf("guest inventory %#v", result)
	}
	if result.Data.Guests[0] != (Guest{Kind: "qemu", Node: "pve1", VMID: 101}) || result.Data.Guests[1] != (Guest{Kind: "lxc", Node: "pve2", VMID: 102}) {
		t.Fatalf("unexpected guests %#v", result.Data.Guests)
	}
}

func TestDiscoverTemplateBaselineFailureIsNotReportedAsConnectionOutage(t *testing.T) {
	service, server := testService(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api2/json/cluster/resources":
			fmt.Fprint(w, `{"data":[{"id":"qemu/9000","type":"qemu","node":"pve","vmid":9000,"name":"ubuntu-2204","template":1}]}`)
		case "/api2/json/nodes/pve/qemu/9000/config":
			fmt.Fprint(w, `{"data":{"cores":2,"sockets":1,"scsi0":"local-zfs:base-9000-disk-0,size=8G","ide2":"local-zfs:cloudinit,media=cdrom","net0":"virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=1","agent":"enabled=1"}}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	result := service.Discover(context.Background(), Request{OperationID: "template-baseline-check", Phase: PhaseTemplates, Limit: 50})
	if result.ErrorCode != "PVE_ERROR" || !result.Complete || len(result.Data.Templates) != 0 {
		t.Fatalf("template baseline failure %#v", result)
	}
}

func TestDiscoverTemplateUsesPVEDefaultSingleSocketWhenOmitted(t *testing.T) {
	service, server := testService(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api2/json/cluster/resources":
			fmt.Fprint(w, `{"data":[{"id":"qemu/9000","type":"qemu","node":"pve","vmid":9000,"name":"ubuntu-2204","template":1}]}`)
		case "/api2/json/nodes/pve/qemu/9000/config":
			fmt.Fprint(w, `{"data":{"cores":2,"memory":2048,"scsi0":"local-zfs:base-9000-disk-0,size=8G","ide2":"local-zfs:cloudinit,media=cdrom","net0":"virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=1","agent":"enabled=1","tags":"ppflight-cloudinit;ppflight-qga-preinstalled"}}`)
		case "/api2/json/nodes/pve/qemu/9000/firewall/rules", "/api2/json/nodes/pve/qemu/9000/firewall/ipset":
			fmt.Fprint(w, `{"data":[]}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	result := service.Discover(context.Background(), Request{OperationID: "template-default-socket", Phase: PhaseTemplates, Limit: 50})
	if result.ErrorCode != "" || !result.Complete || len(result.Data.Templates) != 1 || result.Data.Templates[0].Baseline == nil || result.Data.Templates[0].Baseline.Sockets != 1 {
		t.Fatalf("template default socket normalization %#v", result)
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

func TestDiscoverFirewallEmitsEffectiveScopeDefaults(t *testing.T) {
	service, server := testService(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api2/json/cluster/resources":
			fmt.Fprint(w, `{"data":[]}`)
		case "/api2/json/cluster/firewall/options", "/api2/json/nodes/pve1/firewall/options":
			fmt.Fprint(w, `{"data":{"digest":"omitted-default"}}`)
		case "/api2/json/cluster/firewall/rules", "/api2/json/nodes/pve1/firewall/rules":
			fmt.Fprint(w, `{"data":[]}`)
		case "/api2/json/cluster/firewall/ipset":
			fmt.Fprint(w, `{"data":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	result := service.Discover(context.Background(), Request{OperationID: "firewall-defaults", Phase: PhaseFirewall, NodeRef: "pve1", Limit: 50})
	if result.ErrorCode != "" || !result.Complete || len(result.Data.Firewall) != 2 {
		t.Fatalf("firewall result %#v", result)
	}
	if got := result.Data.Firewall[0].Options.Enable; got == nil || *got != 0 {
		t.Fatalf("cluster effective enable = %v, want 0", got)
	}
	if got := result.Data.Firewall[1].Options.Enable; got == nil || *got != 1 {
		t.Fatalf("node effective enable = %v, want 1", got)
	}
	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Data struct {
			Firewall []struct {
				Options map[string]any `json:"options"`
			} `json:"firewall"`
		} `json:"data"`
	}
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	for i, want := range []float64{0, 1} {
		if got, ok := decoded.Data.Firewall[i].Options["enable"]; !ok || got != want {
			t.Fatalf("wire firewall[%d].options.enable = %#v, present=%v; want %v", i, got, ok, want)
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
