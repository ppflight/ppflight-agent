package control

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/discovery"
	"github.com/ppflight/ppflight-agent/internal/pve"
)

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
		if _, _, err := executePVE(context.Background(), client, controlCommand("vm.set-disk-limits", "qemu", `{"disk":"scsi0","iopsRead":1000,"iopsWrite":900,"iopsReadMax":1200,"iopsReadMaxLength":30}`)); err != nil {
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
		command := controlCommand("vm.set-cloud-init", "qemu", `{"username":"root","password":"secret-value","sshKeys":["ssh-ed25519 QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="],"hostname":"vm101","enableQGA":true}`)
		receipt, err := (Executor{Client: controlTestClient(t, server), Mode: "production", ProductionExecution: true}).Execute(context.Background(), command, time.Now())
		if err != nil || receipt.State != "succeeded" || len(receipt.Result) != 0 {
			t.Fatalf("receipt=%#v err=%v", receipt, err)
		}
		if raw, _ := json.Marshal(receipt); strings.Contains(string(raw), "secret-value") {
			t.Fatalf("Cloud-Init secret leaked: %s", raw)
		}
	})

	t.Run("timezone waits for QGA command completion", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, "/agent/info"):
				_, _ = w.Write([]byte(`{"data":{"version":"9.0","supported_commands":[{"name":"guest-exec","enabled":true}]}}`))
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
}

func TestDeliveryVerificationRequiresRunningGuestQGAIdentityAndAddress(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/status/current"):
			_, _ = w.Write([]byte(`{"data":{"status":"running","uptime":30}}`))
		case strings.HasSuffix(r.URL.Path, "/config"):
			_, _ = w.Write([]byte(`{"data":{"net0":"virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0"}}`))
		case strings.HasSuffix(r.URL.Path, "/agent/info"):
			_, _ = w.Write([]byte(`{"data":{"version":"9.0","supported_commands":[{"name":"guest-network-get-interfaces","enabled":true}]}}`))
		case strings.HasSuffix(r.URL.Path, "/agent/network-get-interfaces"):
			_, _ = w.Write([]byte(`{"data":[{"name":"eth0","hardware-address":"aa:bb:cc:dd:ee:ff","ip-addresses":[{"ip-address":"192.0.2.10","prefix":24,"ip-address-type":"ipv4"}]}]}`))
		default:
			t.Fatalf("unexpected request: %s", r.URL.Path)
		}
	}))
	defer server.Close()
	command := controlCommand("vm.verify-delivery", "qemu", `{"interface":"net0","expectedMac":"AA:BB:CC:DD:EE:FF","expectedAddresses":["192.0.2.10"],"requireQGA":true}`)
	receipt, err := (Executor{ReadClient: controlTestClient(t, server), Mode: "test"}).Execute(context.Background(), command, time.Now())
	if err != nil || receipt.State != "succeeded" || receipt.DryRun {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	var result DeliveryVerificationResult
	if json.Unmarshal(receipt.Result, &result) != nil || !result.NetworkVerified || !result.QGAAvailable || len(result.MatchedAddresses) != 1 {
		t.Fatalf("result=%s", receipt.Result)
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
		{"firewall guest option", "firewall.guest.set-options", "qemu", `{"enable":true}`, http.MethodPut, "/api2/json/nodes/pve1/qemu/101/firewall/options", url.Values{"enable": {"1"}}},
		{"firewall guest ipfilter", "firewall.guest.set-ipfilter", "qemu", `{"interface":"net0","enable":true}`, http.MethodPut, "/api2/json/nodes/pve1/qemu/101/firewall/options", url.Values{"ipfilter-net0": {"1"}}},
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
					gotForm, _ = url.ParseQuery(string(body))
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
		controlCommand("vm.set-disk-limits", "qemu", `{"disk":"scsi0","iopsRead":1000,"iopsReadMax":500}`),
		controlCommand("vm.set-cloud-init", "qemu", `{"username":"root","password":"secret-value","sshKeys":["not-a-key"],"hostname":"vm101","enableQGA":true}`),
		controlCommand("vm.set-cloud-init", "qemu", `{"username":"root","password":"secret-value","sshKeys":[],"hostname":"vm101","enableQGA":false}`),
		controlCommand("vm.set-timezone", "qemu", `{"timezone":"../../etc/passwd"}`),
		controlCommand("vm.verify-delivery", "qemu", `{"interface":"net0","expectedMac":"AA:BB:CC:DD:EE:FF","expectedAddresses":["192.0.2.10"],"requireQGA":false}`),
		controlCommand("vm.reset-password", "qemu", `{"username":"root","password":"secret-value"}`),
		controlCommand("snapshot.create", "qemu", `{"name":"snap1"}`),
		controlCommand("firewall.rule.delete", "qemu", `{}`),
		controlCommand("firewall.node.set-options", "", `{}`),
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
			_, _ = w.Write([]byte(`{"data":{"version":"9.0","supported_commands":[{"name":"guest-set-user-password","enabled":true}]}}`))
			return
		}
		_ = r.ParseForm()
		if r.Form.Get("password") != "secret-value" {
			t.Fatal("password did not reach PVE form")
		}
		// Even a surprising upstream echo must never reach a receipt or journal.
		_, _ = w.Write([]byte(`{"data":{"password":"secret-value"}}`))
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
		{name: "command unsupported", status: http.StatusOK, info: `{"data":{"version":"9.0","supported_commands":[]}}`, code: "QGA_COMMAND_UNSUPPORTED"},
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
