package control

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/discovery"
	"github.com/ppflight/ppflight-agent/internal/pve"
)

func TestCloneRequiresFreshTemplateBaselineHash(t *testing.T) {
	baseline := pve.TemplateBaseline{
		Cores: 2, Sockets: 1, MemoryMiB: 1024,
		BootDisk:       pve.TemplateBootDisk{Interface: "scsi0", SizeGiB: 8},
		Networks:       []pve.TemplateNetwork{{Interface: "net0", Bridge: "vmbr0", Model: "virtio", Firewall: false}},
		CloudInitDrive: true, QGADeviceEnabled: true, QGAPackagePreinstalled: true, GuestFirewallEmpty: true,
	}
	canonical, _ := json.Marshal(baseline)
	digest := fmt.Sprintf("%x", sha256.Sum256(canonical))
	mutated := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api2/json/cluster/resources":
			_, _ = w.Write([]byte(`{"data":[{"type":"qemu","node":"pve1","vmid":100,"template":1}]}`))
		case "/api2/json/nodes/pve1/qemu/100/config":
			_, _ = w.Write([]byte(`{"data":{"cores":2,"sockets":1,"memory":1024,"scsi0":"local-lvm:vm-100-disk-0,size=8G","ide2":"local:cloudinit,media=cdrom","net0":"virtio=AA:BB:CC:DD:EE:01,bridge=vmbr0,firewall=0","agent":"enabled=1","tags":"ppflight-cloudinit;ppflight-qga-preinstalled"}}`))
		case "/api2/json/nodes/pve1/qemu/100/firewall/rules", "/api2/json/nodes/pve1/qemu/100/firewall/ipset":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case "/api2/json/nodes/pve1/qemu/100/clone":
			mutated = true
			_ = r.ParseForm()
			if r.Method != http.MethodPost || r.Form.Get("newid") != "101" || r.Form.Get("full") != "1" || r.Form.Get("target") != "pve1" || r.Form.Get("storage") != "local-lvm" {
				t.Fatalf("clone form: %v", r.Form)
			}
			_, _ = w.Write([]byte(`{"data":"UPID:pve1:clone"}`))
		default:
			t.Fatalf("unexpected request: %s", r.URL.Path)
		}
	}))
	defer server.Close()
	client := controlTestClient(t, server)
	valid := fmt.Sprintf(`{"sourceVmid":100,"templateRef":"ubuntu-24.04","name":"vm101","target":"pve1","storage":"local-lvm","full":true,"sourceConfigSha256":"%s"}`, digest)
	if _, _, err := executePVE(context.Background(), client, controlCommand("vm.clone", "qemu", valid)); err != nil || !mutated {
		t.Fatalf("valid clone failed: mutated=%t err=%v", mutated, err)
	}
	mutated = false
	invalid := `{"sourceVmid":100,"templateRef":"ubuntu-24.04","name":"vm101","target":"pve1","storage":"local-lvm","full":true,"sourceConfigSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	if _, _, err := executePVE(context.Background(), client, controlCommand("vm.clone", "qemu", invalid)); err == nil || mutated {
		t.Fatalf("stale template hash reached mutation: mutated=%t err=%v", mutated, err)
	}
}

func controlTestClient(t *testing.T, server *httptest.Server) *pve.Client {
	t.Helper()
	c, err := pve.NewClient(pve.Config{Endpoint: server.URL, TokenID: "root@pam!control", TokenSecret: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func controlCommand(action, guest string, parameters string) Command {
	command := Command{
		OperationID: "operation-1", Scope: ScopeVM, Action: action, Parameters: json.RawMessage(parameters),
		Identity: Identity{ServiceRef: "service-1", ClusterRef: "cluster-1", NodeRef: "pve1", VMID: 101, Generation: 1, InstanceUUID: "instance-1", GuestType: guest},
	}
	switch {
	case clusterAction(action):
		command.Scope = ScopeCluster
		command.Identity = Identity{ClusterRef: "cluster-1"}
	case nodeAction(action):
		command.Scope = ScopeNode
		command.Identity = Identity{ClusterRef: "cluster-1", NodeRef: "pve1"}
	}
	return command
}

func TestVMDeleteIsConvergentAndClassifiesPVEHTTPFailures(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		body      string
		wantState string
		wantCode  string
		wantErr   bool
	}{
		{name: "normal task submission", status: http.StatusOK, body: `{"data":"UPID:pve1:delete"}`, wantState: "submitted", wantCode: "PVE_TASK_SUBMITTED"},
		{name: "already absent", status: http.StatusNotFound, body: `{"errors":{"vmid":"not found"}}`, wantState: "succeeded", wantCode: "SUCCEEDED"},
		{name: "PVE missing config is already absent", status: http.StatusInternalServerError, body: `{"data":null,"message":"Configuration file 'nodes/pve1/qemu-server/101.conf' does not exist"}`, wantState: "succeeded", wantCode: "SUCCEEDED"},
		{name: "different missing config is not accepted", status: http.StatusInternalServerError, body: `{"data":null,"message":"Configuration file 'nodes/pve1/qemu-server/102.conf' does not exist"}`, wantState: "indeterminate", wantCode: "PVE_ACTION_INDETERMINATE", wantErr: true},
		{name: "unstructured missing text is not accepted", status: http.StatusInternalServerError, body: `Configuration file 'nodes/pve1/qemu-server/101.conf' does not exist`, wantState: "indeterminate", wantCode: "PVE_ACTION_INDETERMINATE", wantErr: true},
		{name: "forbidden", status: http.StatusForbidden, body: `{"errors":{"permission":"denied"}}`, wantState: "failed", wantCode: "PVE_ACTION_FORBIDDEN", wantErr: true},
		{name: "conflict", status: http.StatusConflict, body: `{"errors":{"lock":"busy"}}`, wantState: "failed", wantCode: "PVE_ACTION_CONFLICT", wantErr: true},
		{name: "server failure", status: http.StatusBadGateway, body: `{"errors":{"proxy":"unavailable"}}`, wantState: "indeterminate", wantCode: "PVE_ACTION_INDETERMINATE", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.Method != http.MethodDelete || r.URL.Path != "/api2/json/nodes/pve1/qemu/101" {
					t.Fatalf("request %s %s", r.Method, r.URL.Path)
				}
				body, err := io.ReadAll(r.Body)
				query := r.URL.Query()
				if err != nil || len(body) != 0 || r.ContentLength > 0 || r.Header.Get("Content-Type") != "" || query.Get("purge") != "1" || query.Get("destroy-unreferenced-disks") != "1" {
					t.Fatalf("query=%v body=%q contentLength=%d contentType=%q readErr=%v", query, body, r.ContentLength, r.Header.Get("Content-Type"), err)
				}
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			command := controlCommand("vm.delete", "qemu", `{"purge":true,"destroyUnreferencedDisks":true}`)
			receipt, err := (Executor{Client: controlTestClient(t, server), Mode: "production", ProductionExecution: true}).Execute(context.Background(), command, time.Now())
			if (err != nil) != tt.wantErr || receipt.State != tt.wantState || receipt.Code != tt.wantCode || requests != 1 {
				t.Fatalf("receipt=%#v err=%v requests=%d", receipt, err, requests)
			}
			if !tt.wantErr && tt.wantState == "succeeded" && string(receipt.Result) != `{"deleted":true,"alreadyAbsent":true}` {
				t.Fatalf("not-found result=%s", receipt.Result)
			}
		})
	}
}

func TestVMDeleteMissingConfigRequiresExactSignedGuestIdentity(t *testing.T) {
	qemu := controlCommand("vm.delete", "qemu", `{"purge":true,"destroyUnreferencedDisks":true}`)
	lxc := controlCommand("vm.delete", "lxc", `{"purge":true,"destroyUnreferencedDisks":true}`)
	tests := []struct {
		name    string
		command Command
		reason  string
		want    bool
	}{
		{name: "qemu", command: qemu, reason: "Configuration file 'nodes/pve1/qemu-server/101.conf' does not exist", want: true},
		{name: "lxc", command: lxc, reason: "Configuration file 'nodes/pve1/lxc/101.conf' does not exist", want: true},
		{name: "different node", command: qemu, reason: "Configuration file 'nodes/pve2/qemu-server/101.conf' does not exist"},
		{name: "different guest type", command: qemu, reason: "Configuration file 'nodes/pve1/lxc/101.conf' does not exist"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := vmDeleteTargetAlreadyAbsent(tt.command, &pve.HTTPError{StatusCode: http.StatusInternalServerError, Reason: tt.reason})
			if got != tt.want {
				t.Fatalf("already absent=%t want=%t", got, tt.want)
			}
		})
	}
}

func TestExecutorResourceAndNetworkUseConfigDigest(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch requests {
		case 1:
			if r.Method != http.MethodGet || r.URL.Path != "/api2/json/nodes/pve1/qemu/101/config" {
				t.Fatalf("config request: %s %s", r.Method, r.URL.Path)
			}
			_, _ = w.Write([]byte(`{"data":{"digest":"d1","cores":2,"sockets":1,"memory":1024}}`))
		case 2:
			if r.Method != http.MethodPut || r.URL.Path != "/api2/json/nodes/pve1/qemu/101/config" {
				t.Fatalf("resource request: %s %s", r.Method, r.URL.Path)
			}
			_ = r.ParseForm()
			if r.Form.Get("cores") != "4" || r.Form.Get("memory") != "2048" || r.Form.Get("digest") != "d1" || r.Form.Get("sockets") != "" {
				t.Fatalf("resource form: %v", r.Form)
			}
			_, _ = w.Write([]byte(`{"data":"UPID:node:1"}`))
		case 3:
			_, _ = w.Write([]byte(`{"data":{"digest":"d2","net0":"virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=1,foo=keep","ipconfig0":"ip=dhcp"}}`))
		case 4:
			_ = r.ParseForm()
			if r.Method != http.MethodPut || r.Form.Get("net0") != "virtio=AA:BB:CC:DD:EE:00,foo=keep,bridge=vmbr1,tag=200,mtu=9000,firewall=0" || r.Form.Get("ipconfig0") != "ip=10.0.0.5/24" || r.Form.Get("digest") != "d2" {
				t.Fatalf("network form: %s %v", r.URL.Path, r.Form)
			}
			_, _ = w.Write([]byte(`{"data":"UPID:node:2"}`))
		}
	}))
	defer server.Close()
	client := controlTestClient(t, server)
	if _, _, err := executePVE(context.Background(), client, controlCommand("vm.set-resources", "qemu", `{"cores":4,"memoryMiB":2048}`)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := executePVE(context.Background(), client, controlCommand("vm.set-network", "qemu", `{"interface":"net0","bridge":"vmbr1","mac":"AA:BB:CC:DD:EE:00","vlan":200,"mtu":9000,"firewall":false,"ipv4":"10.0.0.5/24"}`)); err != nil {
		t.Fatal(err)
	}
	if requests != 4 {
		t.Fatalf("requests=%d", requests)
	}
}

func TestSetNetworkRemovesEmptyQEMUIPConfigFields(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch requests {
		case 1:
			if r.Method != http.MethodGet || r.URL.Path != "/api2/json/nodes/pve1/qemu/101/config" {
				t.Fatalf("config request: %s %s", r.Method, r.URL.Path)
			}
			_, _ = w.Write([]byte(`{"data":{"digest":"d1","net0":"virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=0","ipconfig0":"ip=192.0.2.10/24,gw=192.0.2.1,ip6=manual,gw6=2001:db8::1"}}`))
		case 2:
			if r.Method != http.MethodPut || r.URL.Path != "/api2/json/nodes/pve1/qemu/101/config" {
				t.Fatalf("network request: %s %s", r.Method, r.URL.Path)
			}
			_ = r.ParseForm()
			if got := r.Form.Get("ipconfig0"); got != "ip=192.0.2.10/24,gw=192.0.2.1" {
				t.Fatalf("empty address-family fields reached PVE: %q", got)
			}
			if r.Form.Get("digest") != "d1" {
				t.Fatalf("network digest: %q", r.Form.Get("digest"))
			}
			_, _ = w.Write([]byte(`{"data":null}`))
		}
	}))
	defer server.Close()

	client := controlTestClient(t, server)
	command := controlCommand("vm.set-network", "qemu", `{"interface":"net0","firewall":true,"ipv4":"192.0.2.10/24","ipv6":"","gateway4":"192.0.2.1","gateway6":""}`)
	if _, _, err := executePVE(context.Background(), client, command); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("requests=%d", requests)
	}
}

func TestProvisioningActionsUseTypedFormsAndReadback(t *testing.T) {
	t.Run("absolute disk growth and IO policy", func(t *testing.T) {
		requests := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests++
			switch requests {
			case 1:
				_, _ = w.Write([]byte(`{"data":{"digest":"d1","scsi0":"local-lvm:vm-101-disk-0,size=8G,cache=none"}}`))
			case 2:
				_ = r.ParseForm()
				if r.URL.Path != "/api2/json/nodes/pve1/qemu/101/resize" || r.Form.Get("disk") != "scsi0" || r.Form.Get("size") != "20G" {
					t.Fatalf("resize request: %s %v", r.URL.Path, r.Form)
				}
				_, _ = w.Write([]byte(`{"data":"UPID:pve1:resize"}`))
			case 3:
				_, _ = w.Write([]byte(`{"data":{"digest":"d2","scsi0":"local-lvm:vm-101-disk-0,size=20G,cache=none,iops_rd=50"}}`))
			case 4:
				_ = r.ParseForm()
				want := "local-lvm:vm-101-disk-0,size=20G,cache=none,iops_rd=1000,iops_wr=900,iops_rd_max=1200,iops_rd_max_length=30"
				if r.URL.Path != "/api2/json/nodes/pve1/qemu/101/config" || r.Form.Get("scsi0") != want || r.Form.Get("digest") != "d2" {
					t.Fatalf("disk policy request: %s %v", r.URL.Path, r.Form)
				}
				_, _ = w.Write([]byte(`{"data":null}`))
			}
		}))
		defer server.Close()
		client := controlTestClient(t, server)
		if _, _, err := executePVE(context.Background(), client, controlCommand("vm.resize", "qemu", `{"disk":"scsi0","targetGiB":20}`)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := executePVE(context.Background(), client, controlCommand("vm.set-disk-io", "qemu", `{"disk":"scsi0","limits":{"iopsRead":1000,"iopsWrite":900,"iopsReadMax":1200,"iopsWriteMax":null,"iopsReadMaxLength":30,"iopsWriteMaxLength":null,"mbpsRead":null,"mbpsWrite":null,"mbpsReadMax":null,"mbpsWriteMax":null}}`)); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Cloud-Init secrets never enter result", func(t *testing.T) {
		requests := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests++
			if requests == 1 {
				_, _ = w.Write([]byte(`{"data":{"digest":"cloud-digest"}}`))
				return
			}
			_ = r.ParseForm()
			if r.Form.Get("ciuser") != "root" || r.Form.Get("cipassword") != "secret-value" || r.Form.Get("name") != "vm101" || r.Form.Get("agent") != "enabled=1" || r.Form.Get("digest") != "cloud-digest" {
				t.Fatalf("cloud-init form: %v", r.Form)
			}
			if !strings.Contains(r.Form.Get("sshkeys"), "+") || !strings.Contains(r.Form.Get("sshkeys"), "%3D") {
				t.Fatalf("sshkeys were not inner URL encoded: %q", r.Form.Get("sshkeys"))
			}
			_, _ = w.Write([]byte(`{"data":{"cipassword":"secret-value"}}`))
		}))
		defer server.Close()
		command := controlCommand("vm.set-cloud-init", "qemu", `{"hostname":"vm101","username":"root","password":"secret-value","passwordFormat":"plain","sshAuthorizedKeys":["ssh-ed25519 QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="],"qgaEnabled":true}`)
		receipt, err := (Executor{Client: controlTestClient(t, server), Mode: "production", ProductionExecution: true}).Execute(context.Background(), command, time.Now())
		if err != nil || receipt.State != "succeeded" || !strings.Contains(string(receipt.Result), `"configured":true`) {
			t.Fatalf("receipt=%#v err=%v", receipt, err)
		}
		if raw, _ := json.Marshal(receipt); strings.Contains(string(raw), "secret-value") {
			t.Fatalf("Cloud-Init secret leaked: %s", raw)
		}
	})

	t.Run("Cloud-Init omits an empty SSH key list", func(t *testing.T) {
		requests := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests++
			if requests == 1 {
				_, _ = w.Write([]byte(`{"data":{"digest":"cloud-digest"}}`))
				return
			}
			_ = r.ParseForm()
			if _, present := r.Form["sshkeys"]; present {
				t.Fatalf("empty sshkeys must be omitted: %v", r.Form)
			}
			_, _ = w.Write([]byte(`{"data":null}`))
		}))
		defer server.Close()
		command := controlCommand("vm.set-cloud-init", "qemu", `{"hostname":"vm101","username":"root","password":"secret-value","passwordFormat":"plain","sshAuthorizedKeys":[],"qgaEnabled":true}`)
		receipt, err := (Executor{Client: controlTestClient(t, server), Mode: "production", ProductionExecution: true}).Execute(context.Background(), command, time.Now())
		if err != nil || receipt.State != "succeeded" || requests != 2 {
			t.Fatalf("receipt=%#v err=%v requests=%d", receipt, err, requests)
		}
	})

	t.Run("timezone waits for QGA command completion", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, "/agent/info"):
				_, _ = w.Write([]byte(`{"data":{"result":{"version":"9.0","supported_commands":[{"name":"guest-exec","enabled":true}]}}}`))
			case strings.HasSuffix(r.URL.Path, "/agent/exec"):
				_ = r.ParseForm()
				if strings.Join(r.Form["command"], "|") != "/usr/bin/timedatectl|set-timezone|Asia/Shanghai" {
					t.Fatalf("timezone command: %v", r.Form)
				}
				_, _ = w.Write([]byte(`{"data":{"pid":7}}`))
			case strings.HasSuffix(r.URL.Path, "/agent/exec-status"):
				if r.URL.Query().Get("pid") != "7" {
					t.Fatalf("pid query: %v", r.URL.Query())
				}
				_, _ = w.Write([]byte(`{"data":{"exited":1,"exitcode":0}}`))
			case strings.HasSuffix(r.URL.Path, "/agent/get-timezone"):
				_, _ = w.Write([]byte(`{"data":{"result":{"zone":"Asia/Shanghai","offset":28800}}}`))
			default:
				t.Fatalf("unexpected request: %s", r.URL.Path)
			}
		}))
		defer server.Close()
		receipt, err := (Executor{Client: controlTestClient(t, server), Mode: "production", ProductionExecution: true}).Execute(context.Background(), controlCommand("vm.set-timezone", "qemu", `{"timezone":"Asia/Shanghai"}`), time.Now())
		if err != nil || receipt.State != "succeeded" || !strings.Contains(string(receipt.Result), `"verified":true`) {
			t.Fatalf("receipt=%#v err=%v", receipt, err)
		}
	})

	t.Run("timezone waits for QGA to become available after guest boot", func(t *testing.T) {
		infoReads := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, "/agent/info"):
				infoReads++
				if infoReads < 3 {
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(`{"data":null}`))
					return
				}
				_, _ = w.Write([]byte(`{"data":{"result":{"version":"9.0","supported_commands":[{"name":"guest-exec","enabled":true}]}}}`))
			case strings.HasSuffix(r.URL.Path, "/agent/exec"):
				_, _ = w.Write([]byte(`{"data":{"pid":7}}`))
			case strings.HasSuffix(r.URL.Path, "/agent/exec-status"):
				_, _ = w.Write([]byte(`{"data":{"exited":1,"exitcode":0}}`))
			case strings.HasSuffix(r.URL.Path, "/agent/get-timezone"):
				_, _ = w.Write([]byte(`{"data":{"result":{"zone":"UTC","offset":0}}}`))
			default:
				t.Fatalf("unexpected request: %s", r.URL.Path)
			}
		}))
		defer server.Close()
		executor := Executor{
			Client: controlTestClient(t, server), Mode: "production", ProductionExecution: true,
			QGABootWait: 100 * time.Millisecond, QGAPollInterval: time.Millisecond,
		}
		receipt, err := executor.Execute(context.Background(), controlCommand("vm.set-timezone", "qemu", `{"timezone":"UTC"}`), time.Now())
		if err != nil || receipt.State != "succeeded" || infoReads != 3 {
			t.Fatalf("receipt=%#v err=%v infoReads=%d", receipt, err, infoReads)
		}
	})

	t.Run("timezone rejects after its bounded QGA startup grace", func(t *testing.T) {
		infoReads := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			infoReads++
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"data":null}`))
		}))
		defer server.Close()
		executor := Executor{
			Client: controlTestClient(t, server), Mode: "production", ProductionExecution: true,
			QGABootWait: 5 * time.Millisecond, QGAPollInterval: time.Millisecond,
		}
		receipt, err := executor.Execute(context.Background(), controlCommand("vm.set-timezone", "qemu", `{"timezone":"UTC"}`), time.Now())
		if err == nil || receipt.State != "rejected" || receipt.Code != "QGA_UNAVAILABLE" || infoReads < 2 {
			t.Fatalf("receipt=%#v err=%v infoReads=%d", receipt, err, infoReads)
		}
	})
}

func TestDeliveryVerificationRequiresCompleteFreshReadback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/status/current"):
			_, _ = w.Write([]byte(`{"data":{"status":"running","uptime":30}}`))
		case strings.HasSuffix(r.URL.Path, "/config"):
			_, _ = w.Write([]byte(`{"data":{"cores":2,"sockets":1,"memory":1024,"scsi0":"local-lvm:vm-101-disk-0,size=20G,iops_rd=1000,mbps_rd=100","net0":"virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,mtu=1500,firewall=1,rate=100","ipconfig0":"ip=192.0.2.10/24,ip6=2001:db8::10/64"}}`))
		case strings.HasSuffix(r.URL.Path, "/agent/info"):
			_, _ = w.Write([]byte(`{"data":{"result":{"version":"9.0","supported_commands":[{"name":"guest-network-get-interfaces","enabled":true}]}}}`))
		case strings.HasSuffix(r.URL.Path, "/agent/network-get-interfaces"):
			_, _ = w.Write([]byte(`{"data":{"result":[{"name":"eth0","hardware-address":"aa:bb:cc:dd:ee:ff","ip-addresses":[{"ip-address":"192.0.2.10","prefix":24,"ip-address-type":"ipv4"},{"ip-address":"2001:db8::10","prefix":64,"ip-address-type":"ipv6"}]}]}}`))
		case strings.HasSuffix(r.URL.Path, "/agent/get-timezone"):
			_, _ = w.Write([]byte(`{"data":{"result":{"zone":"UTC","offset":0}}}`))
		case strings.HasSuffix(r.URL.Path, "/firewall/options"):
			if r.URL.Path == "/api2/json/cluster/firewall/options" {
				_, _ = w.Write([]byte(`{"data":{"enable":1}}`))
			} else {
				_, _ = w.Write([]byte(`{"data":{"enable":1,"policy_in":"ACCEPT","policy_out":"ACCEPT","macfilter":1}}`))
			}
		case strings.HasSuffix(r.URL.Path, "/firewall/ipset"):
			_, _ = w.Write([]byte(`{"data":[{"name":"ipfilter-net0"}]}`))
		case strings.HasSuffix(r.URL.Path, "/firewall/ipset/ipfilter-net0"):
			_, _ = w.Write([]byte(`{"data":[{"cidr":"192.0.2.10/32","nomatch":0},{"cidr":"2001:db8::10/128","nomatch":0}]}`))
		default:
			t.Fatalf("unexpected request: %s", r.URL.Path)
		}
	}))
	defer server.Close()
	command := controlCommand("vm.verify-delivery", "qemu", `{"notBefore":"2026-01-01T00:00:00Z","expected":{"cores":2,"sockets":1,"memoryMiB":1024,"disk":{"interface":"scsi0","minimumGiB":20,"limits":{"iopsRead":1000,"iopsWrite":null,"iopsReadMax":null,"iopsWriteMax":null,"iopsReadMaxLength":null,"iopsWriteMaxLength":null,"mbpsRead":100,"mbpsWrite":null,"mbpsReadMax":null,"mbpsWriteMax":null}},"networks":[{"interface":"net0","bridge":"vmbr0","mac":"AA:BB:CC:DD:EE:FF","vlan":null,"mtu":1500,"firewall":true,"rateMbps":"100","ipv4":"192.0.2.10/24","ipv6":"2001:db8::10/64","ipFilterCidrs":["192.0.2.10/32","2001:db8::10/128"]}],"timezone":"UTC"}}`)
	receipt, err := (Executor{ReadClient: controlTestClient(t, server), Mode: "test"}).Execute(context.Background(), command, time.Now())
	if err != nil || receipt.State != "succeeded" || receipt.DryRun {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	var result DeliveryVerificationResult
	if json.Unmarshal(receipt.Result, &result) != nil || !result.Ready || !result.ConfigMatched || !result.DiskIOMatched || !result.NetworkMatched || !result.FirewallMatched || !result.QGAFresh || !result.GuestAddressMatched || !result.TimezoneMatched || result.PowerState != "running" {
		t.Fatalf("result=%s", receipt.Result)
	}
	if !regexp.MustCompile(`"observedAt":"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"`).Match(receipt.Result) {
		t.Fatalf("delivery result timestamp is not the whole-second golden: %s", receipt.Result)
	}
}

func TestDeliveryVerificationAcceptsOnlyExactDisabledFirewallReadback(t *testing.T) {
	disabledGolden, err := os.ReadFile("testdata/agent-v1-vm-verify-delivery-disabled.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateParameters(controlCommand("vm.verify-delivery", "qemu", string(disabledGolden))); err != nil {
		t.Fatalf("disabled delivery golden is invalid: %v", err)
	}
	tests := []struct {
		name         string
		network      string
		guestOptions string
		wantError    bool
	}{
		{
			name:         "explicit disabled values",
			network:      "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,mtu=1500,firewall=0,rate=100",
			guestOptions: `{"enable":0}`,
		},
		{
			name:         "omitted PVE defaults",
			network:      "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,mtu=1500,rate=100",
			guestOptions: `{}`,
		},
		{
			name:         "guest firewall unexpectedly enabled",
			network:      "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,mtu=1500,firewall=0,rate=100",
			guestOptions: `{"enable":1}`,
			wantError:    true,
		},
		{
			name:         "network firewall unexpectedly enabled",
			network:      "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,mtu=1500,firewall=1,rate=100",
			guestOptions: `{"enable":0}`,
			wantError:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/status/current"):
					_, _ = w.Write([]byte(`{"data":{"status":"running","uptime":30}}`))
				case strings.HasSuffix(r.URL.Path, "/config"):
					_, _ = w.Write([]byte(`{"data":{"cores":2,"sockets":1,"memory":1024,"scsi0":"local-lvm:vm-101-disk-0,size=20G,iops_rd=1000,mbps_rd=100","net0":` + strconv.Quote(tt.network) + `,"ipconfig0":"ip=192.0.2.10/24,ip6=2001:db8::10/64"}}`))
				case strings.HasSuffix(r.URL.Path, "/agent/info"):
					_, _ = w.Write([]byte(`{"data":{"version":"9.0","supported_commands":[{"name":"guest-network-get-interfaces","enabled":true}]}}`))
				case strings.HasSuffix(r.URL.Path, "/agent/network-get-interfaces"):
					_, _ = w.Write([]byte(`{"data":[{"name":"eth0","hardware-address":"aa:bb:cc:dd:ee:ff","ip-addresses":[{"ip-address":"192.0.2.10","prefix":24,"ip-address-type":"ipv4"},{"ip-address":"2001:db8::10","prefix":64,"ip-address-type":"ipv6"}]}]}`))
				case strings.HasSuffix(r.URL.Path, "/agent/get-timezone"):
					_, _ = w.Write([]byte(`{"data":{"zone":"UTC","offset":0}}`))
				case strings.HasSuffix(r.URL.Path, "/firewall/options"):
					if r.URL.Path == "/api2/json/cluster/firewall/options" {
						t.Fatalf("disabled delivery must not claim or inspect cluster enforcement")
					}
					_, _ = w.Write([]byte(`{"data":` + tt.guestOptions + `}`))
				default:
					t.Fatalf("unexpected request: %s", r.URL.Path)
				}
			}))
			defer server.Close()

			command := controlCommand("vm.verify-delivery", "qemu", string(disabledGolden))
			receipt, err := (Executor{ReadClient: controlTestClient(t, server), Mode: "test"}).Execute(context.Background(), command, time.Now())
			if tt.wantError {
				if err == nil || receipt.State == "succeeded" {
					t.Fatalf("receipt=%#v err=%v, want fail-closed mismatch", receipt, err)
				}
				return
			}
			if err != nil || receipt.State != "succeeded" || receipt.DryRun {
				t.Fatalf("receipt=%#v err=%v", receipt, err)
			}
			var result DeliveryVerificationResult
			if json.Unmarshal(receipt.Result, &result) != nil || !result.Ready || !result.NetworkMatched || !result.FirewallMatched {
				t.Fatalf("result=%s", receipt.Result)
			}
		})
	}
}

func TestGuestIPFilterVerificationIsReadOnlyAndWorksWhileGuestIsStopped(t *testing.T) {
	parametersGolden, err := os.ReadFile("testdata/agent-v1-firewall-verify-ipfilter.json")
	if err != nil {
		t.Fatal(err)
	}
	expectedGolden, err := os.ReadFile("testdata/agent-v1-firewall-verify-ipfilter-result.json")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("verification attempted a write: %s %s", r.Method, r.URL.Path)
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/config"):
			_, _ = w.Write([]byte(`{"data":{"net0":"virtio=AA:BB:CC:DD:EE:01,bridge=vmbr0,firewall=1","net1":"virtio=AA:BB:CC:DD:EE:02,bridge=vmbr1,firewall=1"}}`))
		case strings.HasSuffix(r.URL.Path, "/firewall/options"):
			if r.URL.Path == "/api2/json/cluster/firewall/options" {
				_, _ = w.Write([]byte(`{"data":{"enable":1}}`))
			} else {
				_, _ = w.Write([]byte(`{"data":{"enable":1,"policy_in":"ACCEPT","policy_out":"ACCEPT","macfilter":1}}`))
			}
		case strings.HasSuffix(r.URL.Path, "/firewall/ipset"):
			_, _ = w.Write([]byte(`{"data":[{"name":"ipfilter-net0"},{"name":"ipfilter-net1"}]}`))
		case strings.HasSuffix(r.URL.Path, "/firewall/ipset/ipfilter-net0"):
			_, _ = w.Write([]byte(`{"data":[{"cidr":"192.0.2.10","nomatch":0}]}`))
		case strings.HasSuffix(r.URL.Path, "/firewall/ipset/ipfilter-net1"):
			_, _ = w.Write([]byte(`{"data":[{"cidr":"2001:0db8:0:0:0:0:0:10","nomatch":0}]}`))
		default:
			t.Fatalf("unexpected verification read: %s", r.URL.Path)
		}
	}))
	defer server.Close()
	command := controlCommand("firewall.guest.verify-ipfilter", "qemu", string(parametersGolden))
	receipt, err := (Executor{ReadClient: controlTestClient(t, server), Mode: "test"}).Execute(context.Background(), command, time.Now())
	if err != nil || receipt.State != "succeeded" || receipt.Code != "SUCCEEDED" || receipt.DryRun {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	var result IPFilterVerificationResult
	if json.Unmarshal(receipt.Result, &result) != nil || !result.Verified || !result.GuestFirewallEnabled || result.PolicyIn != "ACCEPT" || result.PolicyOut != "ACCEPT" || !result.MACFilterEnabled || len(result.Networks) != 2 || result.Networks[0].MACAddress == nil || *result.Networks[0].MACAddress != "AA:BB:CC:DD:EE:01" || result.Networks[1].MACAddress == nil || *result.Networks[1].MACAddress != "AA:BB:CC:DD:EE:02" || !result.Networks[0].FirewallEnabled || !result.Networks[0].IPFilterEnabled || result.Networks[0].IPSet != "ipfilter-net0" {
		t.Fatalf("result=%s", receipt.Result)
	}
	var expected IPFilterVerificationResult
	if err := json.Unmarshal(expectedGolden, &expected); err != nil {
		t.Fatal(err)
	}
	result.ObservedAt = expected.ObservedAt
	if !reflect.DeepEqual(result, expected) {
		t.Fatalf("result=%#v does not match golden=%#v", result, expected)
	}
	if !regexp.MustCompile(`"observedAt":"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"`).Match(receipt.Result) {
		t.Fatalf("IPFilter result timestamp is not the whole-second golden: %s", receipt.Result)
	}
}

func TestGuestIPFilterSetPreconfigurationVerificationIsReadOnlyAndMultiNIC(t *testing.T) {
	parametersGolden, err := os.ReadFile("testdata/agent-v1-firewall-verify-ipfilter-sets.json")
	if err != nil {
		t.Fatal(err)
	}
	expectedGolden, err := os.ReadFile("testdata/agent-v1-firewall-verify-ipfilter-sets-result.json")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("preconfiguration verification attempted a write: %s %s", r.Method, r.URL.Path)
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/firewall/options"):
			if r.URL.Path == "/api2/json/cluster/firewall/options" {
				t.Fatalf("preconfiguration verification must not depend on cluster enforcement")
			}
			_, _ = w.Write([]byte(`{"data":{"enable":0}}`))
		case strings.HasSuffix(r.URL.Path, "/config"):
			_, _ = w.Write([]byte(`{"data":{"net0":"virtio=AA:BB:CC:DD:EE:01,bridge=vmbr0,firewall=0","net1":"virtio=AA:BB:CC:DD:EE:02,bridge=vmbr1"}}`))
		case strings.HasSuffix(r.URL.Path, "/firewall/ipset"):
			_, _ = w.Write([]byte(`{"data":[{"name":"ipfilter-net0"},{"name":"ipfilter-net1"}]}`))
		case strings.HasSuffix(r.URL.Path, "/firewall/ipset/ipfilter-net0"):
			_, _ = w.Write([]byte(`{"data":[{"cidr":"192.0.2.10","nomatch":0}]}`))
		case strings.HasSuffix(r.URL.Path, "/firewall/ipset/ipfilter-net1"):
			_, _ = w.Write([]byte(`{"data":[{"cidr":"2001:0db8:0:0:0:0:0:10","nomatch":0}]}`))
		default:
			t.Fatalf("unexpected preconfiguration read: %s", r.URL.Path)
		}
	}))
	defer server.Close()
	command := controlCommand("firewall.guest.verify-ipfilter-sets", "qemu", string(parametersGolden))
	receipt, err := (Executor{ReadClient: controlTestClient(t, server), Mode: "test"}).Execute(context.Background(), command, time.Now())
	if err != nil || receipt.State != "succeeded" || receipt.Code != "SUCCEEDED" || receipt.DryRun {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	var result IPFilterSetVerificationResult
	if json.Unmarshal(receipt.Result, &result) != nil || !result.Verified || result.GuestFirewallEnabled || result.EnforcementState != "preconfigured-not-enforcing" || len(result.Networks) != 2 || result.Networks[0].FirewallEnabled || result.Networks[1].FirewallEnabled || result.Networks[0].IPSet != "ipfilter-net0" || result.Networks[1].IPSet != "ipfilter-net1" {
		t.Fatalf("result=%s", receipt.Result)
	}
	var expected IPFilterSetVerificationResult
	if err := json.Unmarshal(expectedGolden, &expected); err != nil {
		t.Fatal(err)
	}
	result.ObservedAt = expected.ObservedAt
	if !reflect.DeepEqual(result, expected) {
		t.Fatalf("result=%#v does not match golden=%#v", result, expected)
	}
	if !regexp.MustCompile(`"observedAt":"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"`).Match(receipt.Result) {
		t.Fatalf("IPFilter set result timestamp is not the whole-second golden: %s", receipt.Result)
	}
}

func TestGuestIPFilterSetPreconfigurationVerificationFailsClosed(t *testing.T) {
	tests := []struct {
		name, guestOptions, network, entries string
	}{
		{"guest enforcement enabled", `{"enable":1}`, "virtio=AA:BB:CC:DD:EE:01,bridge=vmbr0,firewall=0", `[{"cidr":"192.0.2.10/32","nomatch":0}]`},
		{"NIC enforcement enabled", `{"enable":0}`, "virtio=AA:BB:CC:DD:EE:01,bridge=vmbr0,firewall=1", `[{"cidr":"192.0.2.10/32","nomatch":0}]`},
		{"negative IPSet entry", `{"enable":0}`, "virtio=AA:BB:CC:DD:EE:01,bridge=vmbr0,firewall=0", `[{"cidr":"192.0.2.10/32","nomatch":1}]`},
		{"extra IPSet entry", `{"enable":0}`, "virtio=AA:BB:CC:DD:EE:01,bridge=vmbr0,firewall=0", `[{"cidr":"192.0.2.10/32","nomatch":0},{"cidr":"192.0.2.11/32","nomatch":0}]`},
		{"signed MAC mismatch", `{"enable":0}`, "virtio=AA:BB:CC:DD:EE:09,bridge=vmbr0,firewall=0", `[{"cidr":"192.0.2.10/32","nomatch":0}]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Fatalf("verification attempted a write: %s %s", r.Method, r.URL.Path)
				}
				switch {
				case strings.HasSuffix(r.URL.Path, "/firewall/options"):
					_, _ = w.Write([]byte(`{"data":` + tt.guestOptions + `}`))
				case strings.HasSuffix(r.URL.Path, "/config"):
					_, _ = w.Write([]byte(`{"data":{"net0":` + strconv.Quote(tt.network) + `}}`))
				case strings.HasSuffix(r.URL.Path, "/firewall/ipset"):
					_, _ = w.Write([]byte(`{"data":[{"name":"ipfilter-net0"}]}`))
				case strings.HasSuffix(r.URL.Path, "/firewall/ipset/ipfilter-net0"):
					_, _ = w.Write([]byte(`{"data":` + tt.entries + `}`))
				default:
					t.Fatalf("unexpected verification read: %s", r.URL.Path)
				}
			}))
			defer server.Close()
			command := controlCommand("firewall.guest.verify-ipfilter-sets", "qemu", `{"networks":[{"interface":"net0","macAddress":"AA:BB:CC:DD:EE:01","ipFilterCidrs":["192.0.2.10/32"]}]}`)
			receipt, err := (Executor{ReadClient: controlTestClient(t, server), Mode: "test"}).Execute(context.Background(), command, time.Now())
			if err == nil || receipt.State != "failed" || receipt.Code != "IPFILTER_SETS_NOT_READY" {
				t.Fatalf("receipt=%#v err=%v", receipt, err)
			}
		})
	}
}

func TestGuestIPFilterVerificationRejectsSignedMACDriftForQEMUAndLXC(t *testing.T) {
	tests := []struct {
		name, action, kind, guestOptions, network, wantCode string
	}{
		{"qemu dormant", "firewall.guest.verify-ipfilter-sets", "qemu", `{"enable":0}`, "virtio=AA:BB:CC:DD:EE:09,bridge=vmbr0,firewall=0", "IPFILTER_SETS_NOT_READY"},
		{"lxc dormant", "firewall.guest.verify-ipfilter-sets", "lxc", `{"enable":0}`, "name=eth0,hwaddr=AA:BB:CC:DD:EE:09,bridge=vmbr0,firewall=0", "IPFILTER_SETS_NOT_READY"},
		{"qemu enforcing", "firewall.guest.verify-ipfilter", "qemu", `{"enable":1,"policy_in":"ACCEPT","policy_out":"ACCEPT","macfilter":1}`, "virtio=AA:BB:CC:DD:EE:09,bridge=vmbr0,firewall=1", "IPFILTER_NOT_READY"},
		{"lxc enforcing", "firewall.guest.verify-ipfilter", "lxc", `{"enable":1,"policy_in":"ACCEPT","policy_out":"ACCEPT","macfilter":1}`, "name=eth0,hwaddr=AA:BB:CC:DD:EE:09,bridge=vmbr0,firewall=1", "IPFILTER_NOT_READY"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/api2/json/cluster/firewall/options":
					_, _ = w.Write([]byte(`{"data":{"enable":1}}`))
				case strings.HasSuffix(r.URL.Path, "/firewall/options"):
					_, _ = w.Write([]byte(`{"data":` + tt.guestOptions + `}`))
				case strings.HasSuffix(r.URL.Path, "/config"):
					_, _ = w.Write([]byte(`{"data":{"net0":` + strconv.Quote(tt.network) + `}}`))
				default:
					t.Fatalf("MAC mismatch must fail before IPSet reads: %s", r.URL.Path)
				}
			}))
			defer server.Close()
			command := controlCommand(tt.action, tt.kind, `{"networks":[{"interface":"net0","macAddress":"AA:BB:CC:DD:EE:01","ipFilterCidrs":["192.0.2.10/32"]}]}`)
			receipt, err := (Executor{ReadClient: controlTestClient(t, server), Mode: "test"}).Execute(context.Background(), command, time.Now())
			if err == nil || receipt.State != "failed" || receipt.Code != tt.wantCode {
				t.Fatalf("receipt=%#v err=%v", receipt, err)
			}
		})
	}
}

func TestGuestIPFilterVerificationRejectsBlockingPolicyOrDisabledMACFilter(t *testing.T) {
	for name, guestOptions := range map[string]string{
		"implicit input drop": `{"enable":1}`,
		"explicit input drop": `{"enable":1,"policy_in":"DROP","policy_out":"ACCEPT","macfilter":1}`,
		"output drop":         `{"enable":1,"policy_in":"ACCEPT","policy_out":"DROP","macfilter":1}`,
		"MAC filter disabled": `{"enable":1,"policy_in":"ACCEPT","policy_out":"ACCEPT","macfilter":0}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api2/json/cluster/firewall/options" {
					_, _ = w.Write([]byte(`{"data":{"enable":1}}`))
					return
				}
				if strings.HasSuffix(r.URL.Path, "/firewall/options") {
					_, _ = w.Write([]byte(`{"data":` + guestOptions + `}`))
					return
				}
				t.Fatalf("unexpected verification read: %s", r.URL.Path)
			}))
			defer server.Close()
			command := controlCommand("firewall.guest.verify-ipfilter", "qemu", `{"networks":[{"interface":"net0","ipFilterCidrs":["192.0.2.10/32"]}]}`)
			receipt, err := (Executor{ReadClient: controlTestClient(t, server), Mode: "test"}).Execute(context.Background(), command, time.Now())
			if err == nil || receipt.State != "failed" || receipt.Code != "IPFILTER_NOT_READY" {
				t.Fatalf("receipt=%#v err=%v", receipt, err)
			}
		})
	}
}

func TestGuestIPFilterVerificationRejectsDisabledNICFirewall(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api2/json/cluster/firewall/options":
			_, _ = w.Write([]byte(`{"data":{"enable":1}}`))
		case strings.HasSuffix(r.URL.Path, "/firewall/options"):
			_, _ = w.Write([]byte(`{"data":{"enable":1,"policy_in":"ACCEPT","policy_out":"ACCEPT","macfilter":1}}`))
		case strings.HasSuffix(r.URL.Path, "/config"):
			_, _ = w.Write([]byte(`{"data":{"net0":"virtio=AA:BB:CC:DD:EE:01,bridge=vmbr0,firewall=0"}}`))
		default:
			t.Fatalf("unexpected verification read after disabled NIC firewall: %s", r.URL.Path)
		}
	}))
	defer server.Close()
	command := controlCommand("firewall.guest.verify-ipfilter", "qemu", `{"networks":[{"interface":"net0","ipFilterCidrs":["192.0.2.10/32"]}]}`)
	receipt, err := (Executor{ReadClient: controlTestClient(t, server), Mode: "test"}).Execute(context.Background(), command, time.Now())
	if err == nil || receipt.State != "failed" || receipt.Code != "IPFILTER_NOT_READY" {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
}

func TestGuestIPFilterVerificationRejectsAmbiguousOrNonHostContracts(t *testing.T) {
	for _, parameters := range []string{
		`{"networks":[]}`,
		`{"networks":[{"interface":"net0","ipFilterCidrs":["192.0.2.0/24"]}]}`,
		`{"networks":[{"interface":"net0","ipFilterCidrs":["2001:DB8::10/128"]}]}`,
		`{"networks":[{"interface":"net0","ipFilterCidrs":["192.0.2.10/32"]},{"interface":"net0","ipFilterCidrs":["192.0.2.11/32"]}]}`,
		`{"networks":[{"interface":"net0","macAddress":"aa:bb:cc:dd:ee:01","ipFilterCidrs":["192.0.2.10/32"]}]}`,
		`{"networks":[{"interface":"net0","macAddress":"03:00:00:00:00:01","ipFilterCidrs":["192.0.2.10/32"]}]}`,
		`{"networks":[{"interface":"net0","macAddress":"00:00:00:00:00:00","ipFilterCidrs":["192.0.2.10/32"]}]}`,
		`{"networks":[{"interface":"net0","macAddress":"AA:BB:CC:DD:EE:01","ipFilterCidrs":["192.0.2.10/32"]},{"interface":"net1","macAddress":"AA:BB:CC:DD:EE:01","ipFilterCidrs":["192.0.2.11/32"]}]}`,
		`{"networks":[{"interface":"net0","ipFilterCidrs":["192.0.2.10/32"],"unknown":true}]}`,
	} {
		for _, action := range []string{"firewall.guest.verify-ipfilter", "firewall.guest.verify-ipfilter-sets"} {
			if err := validateParameters(controlCommand(action, "qemu", parameters)); err == nil {
				t.Fatalf("unsafe %s contract accepted: %s", action, parameters)
			}
		}
	}
}

func TestGuestIPFilterVerificationRejectsNegativeOrExtraEntries(t *testing.T) {
	for _, entries := range []string{
		`[{"cidr":"192.0.2.10/32","nomatch":1}]`,
		`[{"cidr":"192.0.2.10/32","nomatch":0},{"cidr":"192.0.2.11/32","nomatch":0}]`,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, "/config"):
				_, _ = w.Write([]byte(`{"data":{"net0":"virtio=AA:BB:CC:DD:EE:01,bridge=vmbr0,firewall=1"}}`))
			case strings.HasSuffix(r.URL.Path, "/firewall/options"):
				if r.URL.Path == "/api2/json/cluster/firewall/options" {
					_, _ = w.Write([]byte(`{"data":{"enable":1}}`))
				} else {
					_, _ = w.Write([]byte(`{"data":{"enable":1,"policy_in":"ACCEPT","policy_out":"ACCEPT","macfilter":1}}`))
				}
			case strings.HasSuffix(r.URL.Path, "/firewall/ipset"):
				_, _ = w.Write([]byte(`{"data":[{"name":"ipfilter-net0"}]}`))
			default:
				_, _ = w.Write([]byte(`{"data":` + entries + `}`))
			}
		}))
		command := controlCommand("firewall.guest.verify-ipfilter", "qemu", `{"networks":[{"interface":"net0","ipFilterCidrs":["192.0.2.10/32"]}]}`)
		receipt, err := (Executor{ReadClient: controlTestClient(t, server), Mode: "test"}).Execute(context.Background(), command, time.Now())
		server.Close()
		if err == nil || receipt.State != "failed" || receipt.Code != "IPFILTER_NOT_READY" {
			t.Fatalf("entries=%s receipt=%#v err=%v", entries, receipt, err)
		}
	}
}

func TestGuestIPFilterVerificationFailsClosedWhenClusterFirewallIsDisabled(t *testing.T) {
	reads := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reads++
		if r.Method != http.MethodGet || r.URL.Path != "/api2/json/cluster/firewall/options" {
			t.Fatalf("unexpected read after disabled cluster firewall: %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"data":{"enable":0}}`))
	}))
	defer server.Close()
	command := controlCommand("firewall.guest.verify-ipfilter", "qemu", `{"networks":[{"interface":"net0","ipFilterCidrs":["192.0.2.10/32"]}]}`)
	receipt, err := (Executor{ReadClient: controlTestClient(t, server), Mode: "test"}).Execute(context.Background(), command, time.Now())
	if err == nil || receipt.State != "failed" || receipt.Code != "IPFILTER_NOT_READY" || reads != 1 {
		t.Fatalf("reads=%d receipt=%#v err=%v", reads, receipt, err)
	}
}

func TestGuestIPFilterVerificationFailsClosedWhenClusterEbtablesIsDisabled(t *testing.T) {
	reads := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reads++
		if r.Method != http.MethodGet || r.URL.Path != "/api2/json/cluster/firewall/options" {
			t.Fatalf("unexpected read after disabled cluster ebtables: %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"data":{"enable":1,"ebtables":0}}`))
	}))
	defer server.Close()
	command := controlCommand("firewall.guest.verify-ipfilter", "qemu", `{"networks":[{"interface":"net0","macAddress":"AA:BB:CC:DD:EE:01","ipFilterCidrs":["192.0.2.10/32"]}]}`)
	receipt, err := (Executor{ReadClient: controlTestClient(t, server), Mode: "test"}).Execute(context.Background(), command, time.Now())
	if err == nil || receipt.State != "failed" || receipt.Code != "IPFILTER_NOT_READY" || reads != 1 {
		t.Fatalf("reads=%d receipt=%#v err=%v", reads, receipt, err)
	}
}

func TestGuestIPFilterVerificationFailsClosedWhenNodeFirewallIsDisabled(t *testing.T) {
	reads := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reads++
		switch r.URL.Path {
		case "/api2/json/cluster/firewall/options":
			_, _ = w.Write([]byte(`{"data":{"enable":1}}`))
		case "/api2/json/nodes/pve1/firewall/options":
			_, _ = w.Write([]byte(`{"data":{"enable":0}}`))
		default:
			t.Fatalf("unexpected read after disabled node firewall: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	command := controlCommand("firewall.guest.verify-ipfilter", "qemu", `{"networks":[{"interface":"net0","macAddress":"AA:BB:CC:DD:EE:01","ipFilterCidrs":["192.0.2.10/32"]}]}`)
	receipt, err := (Executor{ReadClient: controlTestClient(t, server), Mode: "test"}).Execute(context.Background(), command, time.Now())
	if err == nil || receipt.State != "failed" || receipt.Code != "IPFILTER_NOT_READY" || reads != 2 {
		t.Fatalf("reads=%d receipt=%#v err=%v", reads, receipt, err)
	}
}

func TestExecutorControlledEndpointForms(t *testing.T) {
	tests := []struct {
		name, action, guest, parameters, method, path string
		form                                          url.Values
	}{
		{"lxc create", "vm.create", "lxc", `{"name":"ct1","cores":2,"memoryMiB":512,"storage":"local-lvm","diskGiB":8,"template":"local:vztmpl/debian.tar.zst","start":false}`, http.MethodPost, "/api2/json/nodes/pve1/lxc", url.Values{"hostname": {"ct1"}, "ostemplate": {"local:vztmpl/debian.tar.zst"}, "rootfs": {"local-lvm:8"}}},
		{"delete explicit", "vm.delete", "qemu", `{"purge":true,"destroyUnreferencedDisks":false}`, http.MethodDelete, "/api2/json/nodes/pve1/qemu/101", url.Values{"purge": {"1"}, "destroy-unreferenced-disks": {"0"}}},
		{"snapshot", "snapshot.create", "lxc", `{"name":"before","description":"safe","includeRam":false}`, http.MethodPost, "/api2/json/nodes/pve1/lxc/101/snapshot", url.Values{"snapname": {"before"}, "vmstate": {"0"}}},
		{"backup", "backup.create", "qemu", `{"storage":"backup1","mode":"snapshot","compress":"zstd"}`, http.MethodPost, "/api2/json/nodes/pve1/vzdump", url.Values{"storage": {"backup1"}, "mode": {"snapshot"}, "compress": {"zstd"}}},
		{"firewall guest option legacy", "firewall.guest.set-options", "qemu", `{"enable":true}`, http.MethodPut, "/api2/json/nodes/pve1/qemu/101/firewall/options", url.Values{"enable": {"1"}}},
		{"firewall guest anti-spoof policy", "firewall.guest.set-options", "qemu", `{"enable":true,"policyIn":"ACCEPT","policyOut":"ACCEPT","macFilter":true}`, http.MethodPut, "/api2/json/nodes/pve1/qemu/101/firewall/options", url.Values{"enable": {"1"}, "policy_in": {"ACCEPT"}, "policy_out": {"ACCEPT"}, "macfilter": {"1"}}},
		{"firewall node option", "firewall.node.set-options", "lxc", `{"enable":false}`, http.MethodPut, "/api2/json/nodes/pve1/firewall/options", url.Values{"enable": {"0"}}},
		{"firewall cluster option", "firewall.cluster.set-options", "qemu", `{"enable":true}`, http.MethodPut, "/api2/json/cluster/firewall/options", url.Values{"enable": {"1"}}},
		{"firewall rule", "firewall.rule.create", "qemu", `{"direction":"in","action":"ACCEPT","protocol":"tcp","source":"+trusted","destinationPort":"443","enable":true}`, http.MethodPost, "/api2/json/nodes/pve1/qemu/101/firewall/rules", url.Values{"type": {"in"}, "action": {"ACCEPT"}, "proto": {"tcp"}, "source": {"+trusted"}, "dport": {"443"}, "enable": {"1"}}},
		{"firewall rule update", "firewall.rule.update", "qemu", `{"position":3,"direction":"out","action":"DROP","enable":true}`, http.MethodPut, "/api2/json/nodes/pve1/qemu/101/firewall/rules/3", url.Values{"type": {"out"}, "action": {"DROP"}, "enable": {"1"}}},
		{"ipset entry", "firewall.ipset.entry.create", "qemu", `{"name":"trusted","cidr":"10.0.0.0/24","noSubnet":false}`, http.MethodPost, "/api2/json/nodes/pve1/qemu/101/firewall/ipset/trusted", url.Values{"cidr": {"10.0.0.0/24"}, "nomatch": {"0"}}},
		{"ipset entry update", "firewall.ipset.entry.update", "qemu", `{"name":"trusted","cidr":"10.0.0.0/24","comment":"office","noSubnet":true}`, http.MethodPut, "/api2/json/nodes/pve1/qemu/101/firewall/ipset/trusted/10.0.0.0/24", url.Values{"comment": {"office"}, "nomatch": {"1"}}},
		{"ipset entry delete", "firewall.ipset.entry.delete", "qemu", `{"name":"trusted","cidr":"10.0.0.0/24"}`, http.MethodDelete, "/api2/json/nodes/pve1/qemu/101/firewall/ipset/trusted/10.0.0.0/24", nil},
		{"ipset update", "firewall.ipset.update", "qemu", `{"name":"trusted","comment":"office"}`, http.MethodPut, "/api2/json/nodes/pve1/qemu/101/firewall/ipset/trusted", url.Values{"comment": {"office"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != tt.method || r.URL.Path != tt.path {
					t.Fatalf("request=%s %s", r.Method, r.URL.Path)
				}
				_ = r.ParseForm()
				gotForm := r.Form
				if r.Method == http.MethodDelete {
					body, _ := io.ReadAll(r.Body)
					if len(body) != 0 || r.ContentLength > 0 || r.Header.Get("Content-Type") != "" {
						t.Fatalf("DELETE sent request content: length=%d contentLength=%d contentType=%q", len(body), r.ContentLength, r.Header.Get("Content-Type"))
					}
					gotForm = r.URL.Query()
				}
				for key, want := range tt.form {
					if got := gotForm[key]; strings.Join(got, ",") != strings.Join(want, ",") {
						t.Fatalf("%s=%v want %v", key, got, want)
					}
				}
				_, _ = w.Write([]byte(`{"data":"UPID:pve1:1"}`))
			}))
			defer server.Close()
			if _, _, err := executePVE(context.Background(), controlTestClient(t, server), controlCommand(tt.action, tt.guest, tt.parameters)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestExecutorRejectsUnknownAndUnsafeParameters(t *testing.T) {
	for _, c := range []Command{
		controlCommand("vm.set-resources", "qemu", `{"cores":4,"unexpected":true}`),
		controlCommand("vm.delete", "qemu", `{"purge":true}`),
		controlCommand("vm.set-network", "lxc", `{"interface":"net0","model":"virtio"}`),
		controlCommand("vm.set-network", "qemu", `{"interface":"net0","mac":"not-a-mac"}`),
		controlCommand("vm.set-network", "qemu", `{"interface":"net0","vlan":4095}`),
		controlCommand("vm.set-network", "qemu", `{"interface":"net0","bridge":"vmbr0\nrate=100"}`),
		controlCommand("vm.resize", "qemu", `{"disk":"scsi0","size":"+1G","targetGiB":20}`),
		controlCommand("vm.set-disk-io", "qemu", `{"disk":"scsi0","limits":{"iopsRead":1000,"iopsWrite":null,"iopsReadMax":500,"iopsWriteMax":null,"iopsReadMaxLength":null,"iopsWriteMaxLength":null,"mbpsRead":null,"mbpsWrite":null,"mbpsReadMax":null,"mbpsWriteMax":null}}`),
		controlCommand("vm.set-cloud-init", "qemu", `{"hostname":"vm101","username":"root","password":"secret-value","passwordFormat":"plain","sshAuthorizedKeys":["not-a-key"],"qgaEnabled":true}`),
		controlCommand("vm.set-cloud-init", "qemu", `{"hostname":"vm101","username":"root","password":"secret-value","passwordFormat":"plain","sshAuthorizedKeys":[],"qgaEnabled":false}`),
		controlCommand("vm.set-timezone", "qemu", `{"timezone":"../../etc/passwd"}`),
		controlCommand("vm.verify-delivery", "qemu", `{"interface":"net0","expectedMac":"AA:BB:CC:DD:EE:FF","expectedAddresses":["192.0.2.10"],"requireQGA":false}`),
		controlCommand("vm.reset-password", "qemu", `{"username":"root","password":"secret-value"}`),
		controlCommand("snapshot.create", "qemu", `{"name":"snap1"}`),
		controlCommand("firewall.rule.delete", "qemu", `{}`),
		controlCommand("firewall.node.set-options", "", `{}`),
		controlCommand("firewall.node.set-options", "", `{"enable":true,"policyIn":"ACCEPT"}`),
		controlCommand("firewall.guest.set-options", "qemu", `{"enable":true,"policyIn":"accept"}`),
		controlCommand("firewall.guest.set-options", "qemu", `{"enable":true,"policyIn":"ACCEPT","unexpected":true}`),
		controlCommand("firewall.rule.create", "qemu", `{"direction":"in","action":"ACCEPT","protocol":"tcp","destinationPort":"99999","enable":true}`),
		controlCommand("firewall.ipset.entry.create", "qemu", `{"name":"trusted","cidr":"10.0.0.0/24"}`),
		controlCommand("firewall.ipset.entry.update", "qemu", `{"name":"trusted","cidr":"10.0.0.0/24"}`),
		controlCommand("firewall.ipset.entry.delete", "qemu", `{"name":"trusted","cidr":""}`),
	} {
		if err := validateParameters(c); err == nil {
			t.Fatalf("expected rejection for %s: %s", c.Action, c.Parameters)
		}
	}
}

func TestProvisioningGoldenRejectsCrossLanguageDrift(t *testing.T) {
	fixtures := validActionParameterFixtures()
	var disk map[string]any
	if json.Unmarshal([]byte(fixtures["vm.set-disk-io"]), &disk) != nil {
		t.Fatal("invalid test fixture")
	}
	disk["limits"].(map[string]any)["iopsReadMax"] = float64(1200)
	diskRaw, _ := json.Marshal(disk)
	if err := validateParameters(controlCommand("vm.set-disk-io", "qemu", string(diskRaw))); err == nil {
		t.Fatal("accepted IOPS burst maximum without required burst length")
	}
	var disabledDelivery map[string]any
	if json.Unmarshal([]byte(fixtures["vm.verify-delivery"]), &disabledDelivery) != nil {
		t.Fatal("invalid delivery fixture")
	}
	disabledNetwork := disabledDelivery["expected"].(map[string]any)["networks"].([]any)[0].(map[string]any)
	disabledNetwork["firewall"] = false
	disabledNetwork["ipFilterCidrs"] = []any{}
	disabledRaw, _ := json.Marshal(disabledDelivery)
	if err := validateParameters(controlCommand("vm.verify-delivery", "qemu", string(disabledRaw))); err != nil {
		t.Fatalf("rejected exact customer-controlled disabled delivery: %v", err)
	}

	for name, mutate := range map[string]func(map[string]any){
		"missing nullable VLAN key": func(payload map[string]any) {
			delete(payload["expected"].(map[string]any)["networks"].([]any)[0].(map[string]any), "vlan")
		},
		"fractional notBefore": func(payload map[string]any) { payload["notBefore"] = "2026-01-01T00:00:00.123Z" },
		"noncanonical MAC": func(payload map[string]any) {
			payload["expected"].(map[string]any)["networks"].([]any)[0].(map[string]any)["mac"] = "aa:bb:cc:dd:ee:ff"
		},
		"firewall disabled with filter claims": func(payload map[string]any) {
			payload["expected"].(map[string]any)["networks"].([]any)[0].(map[string]any)["firewall"] = false
		},
		"firewall enabled without filter claims": func(payload map[string]any) {
			payload["expected"].(map[string]any)["networks"].([]any)[0].(map[string]any)["ipFilterCidrs"] = []any{}
		},
		"firewall enabled with subnet filter claim": func(payload map[string]any) {
			payload["expected"].(map[string]any)["networks"].([]any)[0].(map[string]any)["ipFilterCidrs"] = []any{"192.0.2.0/24"}
		},
		"firewall enabled with noncanonical IPv6 filter claim": func(payload map[string]any) {
			payload["expected"].(map[string]any)["networks"].([]any)[0].(map[string]any)["ipFilterCidrs"] = []any{"2001:DB8::10/128"}
		},
		"firewall enabled with wrong host filter claim": func(payload map[string]any) {
			payload["expected"].(map[string]any)["networks"].([]any)[0].(map[string]any)["ipFilterCidrs"] = []any{"192.0.2.11/32", "2001:db8::10/128"}
		},
		"firewall enabled with missing IPv6 host filter claim": func(payload map[string]any) {
			payload["expected"].(map[string]any)["networks"].([]any)[0].(map[string]any)["ipFilterCidrs"] = []any{"192.0.2.10/32"}
		},
		"firewall enabled with dynamic address": func(payload map[string]any) {
			network := payload["expected"].(map[string]any)["networks"].([]any)[0].(map[string]any)
			network["ipv4"] = "dhcp"
			network["ipFilterCidrs"] = []any{"2001:db8::10/128"}
		},
		"noncanonical expected IPv6": func(payload map[string]any) {
			payload["expected"].(map[string]any)["networks"].([]any)[0].(map[string]any)["ipv6"] = "2001:DB8::10/64"
		},
	} {
		t.Run(name, func(t *testing.T) {
			var payload map[string]any
			if json.Unmarshal([]byte(fixtures["vm.verify-delivery"]), &payload) != nil {
				t.Fatal("invalid test fixture")
			}
			mutate(payload)
			raw, _ := json.Marshal(payload)
			if err := validateParameters(controlCommand("vm.verify-delivery", "qemu", string(raw))); err == nil {
				t.Fatalf("accepted drift payload: %s", raw)
			}
		})
	}
}

func TestMultiNICDeliveryGoldenRequiresUniqueCanonicalMACs(t *testing.T) {
	raw, err := os.ReadFile("testdata/agent-v1-vm-verify-delivery-multi-nic.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateParameters(controlCommand("vm.verify-delivery", "qemu", string(raw))); err != nil {
		t.Fatalf("multi-NIC delivery golden is invalid: %v", err)
	}

	for name, mac := range map[string]string{
		"duplicate MAC": "AA:BB:CC:DD:EE:FF",
		"empty MAC":     "",
		"lowercase MAC": "aa:bb:cc:dd:ee:00",
	} {
		t.Run(name, func(t *testing.T) {
			var payload map[string]any
			if err := json.Unmarshal(raw, &payload); err != nil {
				t.Fatal(err)
			}
			payload["expected"].(map[string]any)["networks"].([]any)[1].(map[string]any)["mac"] = mac
			mutated, _ := json.Marshal(payload)
			if err := validateParameters(controlCommand("vm.verify-delivery", "qemu", string(mutated))); err == nil {
				t.Fatalf("accepted ambiguous multi-NIC MAC: %s", mutated)
			}
		})
	}
}

func TestMultiNICDeliveryGoldenRejectsPartialFirewallState(t *testing.T) {
	raw, err := os.ReadFile("testdata/agent-v1-vm-verify-delivery-multi-nic.json")
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	network := payload["expected"].(map[string]any)["networks"].([]any)[1].(map[string]any)
	network["firewall"] = false
	network["ipFilterCidrs"] = []any{}
	mutated, _ := json.Marshal(payload)
	if err := validateParameters(controlCommand("vm.verify-delivery", "qemu", string(mutated))); err == nil {
		t.Fatalf("accepted partially protected multi-NIC delivery: %s", mutated)
	}
}

func TestNetworkUpdateNeverChangesMACImplicitly(t *testing.T) {
	bridge := "vmbr1"
	parameters := networkP{Interface: "net0", Bridge: &bridge}
	updated, err := mergeNetwork("qemu", "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=1", parameters)
	if err != nil {
		t.Fatal(err)
	}
	if updated != "virtio=AA:BB:CC:DD:EE:FF,firewall=1,bridge=vmbr1" {
		t.Fatalf("network update changed identity: %q", updated)
	}
}

func TestExecutorPasswordReceiptDoesNotExposePassword(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/agent/info") {
			_, _ = w.Write([]byte(`{"data":{"result":{"version":"9.0","supported_commands":[{"name":"guest-set-user-password","enabled":true}]}}}`))
			return
		}
		_ = r.ParseForm()
		if r.Form.Get("password") != "secret-value" {
			t.Fatal("password did not reach PVE form")
		}
		// Even a surprising upstream echo must never reach a receipt or journal.
		_, _ = w.Write([]byte(`{"data":{"result":{"password":"secret-value"}}}`))
	}))
	defer server.Close()
	r, err := (Executor{Client: controlTestClient(t, server), Mode: "production", ProductionExecution: true}).Execute(context.Background(), controlCommand("vm.reset-password", "qemu", `{"username":"root","password":"secret-value","crypted":false}`), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), "secret-value") {
		t.Fatalf("password leaked in receipt: %s", raw)
	}
}

func TestExecutorRunsTypedReadOnlyActionsWhenWritesDisabled(t *testing.T) {
	t.Run("task status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || !strings.Contains(r.URL.Path, "/tasks/UPID:pve1:1:2:3:task:101:root@pam!api:/status") {
				t.Fatalf("unexpected task read: %s %s", r.Method, r.URL.Path)
			}
			_, _ = w.Write([]byte(`{"data":{"status":"stopped","exitstatus":"OK","user":"root@pam"}}`))
		}))
		defer server.Close()
		command := controlCommand("task.status", "", `{"upid":"UPID:pve1:1:2:3:task:101:root@pam!api:"}`)
		receipt, err := (Executor{Client: controlTestClient(t, server), Mode: "test"}).Execute(context.Background(), command, time.Now())
		if err != nil || receipt.State != "succeeded" || receipt.DryRun {
			t.Fatalf("receipt=%#v err=%v", receipt, err)
		}
		var result TaskStatusResult
		if err := json.Unmarshal(receipt.Result, &result); err != nil || result.Status != "stopped" || result.ExitStatus != "OK" || result.UPID == "" {
			t.Fatalf("result=%#v err=%v", result, err)
		}
		if strings.Contains(string(receipt.Result), "user") {
			t.Fatalf("task result was not typed: %s", receipt.Result)
		}
	})

	t.Run("discovery", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/api2/json/version" {
				t.Fatalf("unexpected discovery read: %s %s", r.Method, r.URL.Path)
			}
			_, _ = w.Write([]byte(`{"data":{"version":"9.0","release":"1"}}`))
		}))
		defer server.Close()
		client := controlTestClient(t, server)
		command := controlCommand("pve.discover", "", `{"operationId":"operation-1","phase":"version","limit":1}`)
		receipt, err := (Executor{Discovery: discovery.New(client), Mode: "test"}).Execute(context.Background(), command, time.Now())
		if err != nil || receipt.State != "succeeded" || receipt.DryRun {
			t.Fatalf("receipt=%#v err=%v", receipt, err)
		}
		var result discovery.Result
		if err := json.Unmarshal(receipt.Result, &result); err != nil || result.OperationID != "operation-1" || result.Phase != discovery.PhaseVersion || result.Data.Version == nil {
			t.Fatalf("result=%#v err=%v", result, err)
		}
	})
}

func TestExecutorFreezesPasswordResetWhenQGAUnavailableOrUnsupported(t *testing.T) {
	for _, tt := range []struct {
		name, info, code string
		status           int
	}{
		{name: "agent stopped", status: http.StatusInternalServerError, info: `{"data":null}`, code: "QGA_UNAVAILABLE"},
		{name: "command unsupported", status: http.StatusOK, info: `{"data":{"result":{"version":"9.0","supported_commands":[]}}}`, code: "QGA_COMMAND_UNSUPPORTED"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			reads, writes := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/agent/info") {
					reads++
					w.WriteHeader(tt.status)
					_, _ = w.Write([]byte(tt.info))
					return
				}
				writes++
				_, _ = w.Write([]byte(`{"data":null}`))
			}))
			defer server.Close()

			receipt, err := (Executor{Client: controlTestClient(t, server), Mode: "production", ProductionExecution: true}).Execute(
				context.Background(), controlCommand("vm.reset-password", "qemu", `{"username":"root","password":"secret-value","crypted":false}`), time.Now(),
			)
			if err == nil || receipt.State != "rejected" || receipt.Code != tt.code || reads != 1 || writes != 0 {
				t.Fatalf("receipt=%#v err=%v reads=%d writes=%d", receipt, err, reads, writes)
			}
		})
	}
}
