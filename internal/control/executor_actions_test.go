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
	"regexp"
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
		CloudInitDrive: true, QGADeviceEnabled: true, GuestFirewallEmpty: true,
	}
	canonical, _ := json.Marshal(baseline)
	digest := fmt.Sprintf("%x", sha256.Sum256(canonical))
	mutated := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api2/json/cluster/resources":
			_, _ = w.Write([]byte(`{"data":[{"type":"qemu","node":"pve1","vmid":100,"template":1}]}`))
		case "/api2/json/nodes/pve1/qemu/100/config":
			_, _ = w.Write([]byte(`{"data":{"cores":2,"sockets":1,"memory":1024,"scsi0":"local-lvm:vm-100-disk-0,size=8G","ide2":"local:cloudinit,media=cdrom","net0":"virtio=AA:BB:CC:DD:EE:01,bridge=vmbr0,firewall=0","agent":"enabled=1"}}`))
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
	valid := fmt.Sprintf(`{"sourceVmid":100,"name":"vm101","target":"pve1","storage":"local-lvm","full":true,"sourceConfigSha256":"%s"}`, digest)
	if _, _, err := executePVE(context.Background(), client, controlCommand("vm.clone", "qemu", valid)); err != nil || !mutated {
		t.Fatalf("valid clone failed: mutated=%t err=%v", mutated, err)
	}
	mutated = false
	invalid := `{"sourceVmid":100,"name":"vm101","target":"pve1","storage":"local-lvm","full":true,"sourceConfigSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
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
			case strings.HasSuffix(r.URL.Path, "/agent/get-timezone"):
				_, _ = w.Write([]byte(`{"data":{"zone":"Asia/Shanghai","offset":28800}}`))
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

func TestDeliveryVerificationRequiresCompleteFreshReadback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/status/current"):
			_, _ = w.Write([]byte(`{"data":{"status":"running","uptime":30}}`))
		case strings.HasSuffix(r.URL.Path, "/config"):
			_, _ = w.Write([]byte(`{"data":{"cores":2,"sockets":1,"memory":1024,"scsi0":"local-lvm:vm-101-disk-0,size=20G,iops_rd=1000,mbps_rd=100","net0":"virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,mtu=1500,firewall=1,rate=100","ipconfig0":"ip=192.0.2.10/24,ip6=2001:db8::10/64"}}`))
		case strings.HasSuffix(r.URL.Path, "/agent/info"):
			_, _ = w.Write([]byte(`{"data":{"version":"9.0","supported_commands":[{"name":"guest-network-get-interfaces","enabled":true}]}}`))
		case strings.HasSuffix(r.URL.Path, "/agent/network-get-interfaces"):
			_, _ = w.Write([]byte(`{"data":[{"name":"eth0","hardware-address":"aa:bb:cc:dd:ee:ff","ip-addresses":[{"ip-address":"192.0.2.10","prefix":24,"ip-address-type":"ipv4"},{"ip-address":"2001:db8::10","prefix":64,"ip-address-type":"ipv6"}]}]}`))
		case strings.HasSuffix(r.URL.Path, "/agent/get-timezone"):
			_, _ = w.Write([]byte(`{"data":{"zone":"UTC","offset":0}}`))
		case strings.HasSuffix(r.URL.Path, "/firewall/options"):
			_, _ = w.Write([]byte(`{"data":{"enable":1}}`))
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
		controlCommand("vm.set-disk-io", "qemu", `{"disk":"scsi0","limits":{"iopsRead":1000,"iopsWrite":null,"iopsReadMax":500,"iopsWriteMax":null,"iopsReadMaxLength":null,"iopsWriteMaxLength":null,"mbpsRead":null,"mbpsWrite":null,"mbpsReadMax":null,"mbpsWriteMax":null}}`),
		controlCommand("vm.set-cloud-init", "qemu", `{"hostname":"vm101","username":"root","password":"secret-value","passwordFormat":"plain","sshAuthorizedKeys":["not-a-key"],"qgaEnabled":true}`),
		controlCommand("vm.set-cloud-init", "qemu", `{"hostname":"vm101","username":"root","password":"secret-value","passwordFormat":"plain","sshAuthorizedKeys":[],"qgaEnabled":false}`),
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

	for name, mutate := range map[string]func(map[string]any){
		"missing nullable VLAN key": func(payload map[string]any) {
			delete(payload["expected"].(map[string]any)["networks"].([]any)[0].(map[string]any), "vlan")
		},
		"fractional notBefore": func(payload map[string]any) { payload["notBefore"] = "2026-01-01T00:00:00.123Z" },
		"noncanonical MAC": func(payload map[string]any) {
			payload["expected"].(map[string]any)["networks"].([]any)[0].(map[string]any)["mac"] = "aa:bb:cc:dd:ee:ff"
		},
		"firewall disabled": func(payload map[string]any) {
			payload["expected"].(map[string]any)["networks"].([]any)[0].(map[string]any)["firewall"] = false
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
