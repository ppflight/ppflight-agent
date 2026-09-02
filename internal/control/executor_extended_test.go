package control

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/pve"
)

type initialAuthorizerFunc func(Command, string, string) error

func (f initialAuthorizerFunc) AuthorizeInitialResources(c Command, operation, digest string) error {
	return f(c, operation, digest)
}

type memoryConsoleSink struct {
	secret  ConsoleSessionSecret
	revoked ConsoleSessionRevoke
}

func (s *memoryConsoleSink) Publish(_ context.Context, secret ConsoleSessionSecret) (ConsoleSessionPublication, error) {
	s.secret = secret
	return ConsoleSessionPublication{SessionRef: secret.SessionRef, Path: "/console/session/" + secret.SessionRef, ExpiresAt: secret.ExpiresAt, OneTime: true}, nil
}
func (s *memoryConsoleSink) Revoke(_ context.Context, revoke ConsoleSessionRevoke) error {
	s.revoked = revoke
	return nil
}

func TestInitialResourcesAllowsReviewedCloneDecreaseAndReadsBack(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch requests {
		case 1:
			_, _ = w.Write([]byte(`{"data":[{"type":"qemu","node":"pve1","vmid":101,"template":0,"status":"stopped"}]}`))
		case 2:
			_, _ = w.Write([]byte(`{"data":{"digest":"before","cores":2,"sockets":1,"memory":2048}}`))
		case 3:
			_ = r.ParseForm()
			if r.Method != http.MethodPut || r.Form.Get("cores") != "1" || r.Form.Get("sockets") != "1" || r.Form.Get("memory") != "1024" || r.Form.Get("digest") != "before" {
				t.Fatalf("initial resource form=%v", r.Form)
			}
			_, _ = w.Write([]byte(`{"data":null}`))
		case 4:
			_, _ = w.Write([]byte(`{"data":{"digest":"after","cores":1,"sockets":1,"memory":1024}}`))
		default:
			t.Fatalf("unexpected request %d: %s", requests, r.URL.Path)
		}
	}))
	defer server.Close()
	command := controlCommand("vm.set-initial-resources", "qemu", `{"cores":1,"sockets":1,"memoryMiB":1024,"cloneOperationId":"operation-1","vmGeneration":1,"templateConfigSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	authorized := false
	receipt, err := (Executor{Client: controlTestClient(t, server), Mode: "production", ProductionExecution: true, InitialResources: initialAuthorizerFunc(func(_ Command, operation, digest string) error {
		authorized = operation == "operation-1" && strings.HasPrefix(digest, "aaaa")
		return nil
	})}).Execute(context.Background(), command, time.Now())
	if err != nil || receipt.State != "succeeded" || !authorized || requests != 4 {
		t.Fatalf("receipt=%#v authorized=%t requests=%d err=%v", receipt, authorized, requests, err)
	}
}

func TestInitialResourceJournalRequiresCompletedMatchingCloneAndRejectsDelivery(t *testing.T) {
	now := time.Now().UTC()
	journal, err := OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	clone := controlCommand("vm.clone", "qemu", `{"sourceVmid":9001,"name":"vm101","target":"pve1","storage":"local-lvm","full":true,"sourceConfigSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	clone.CommandID = "clone-command"
	if _, duplicate, err := journal.Claim(clone, now); err != nil || duplicate {
		t.Fatalf("claim clone duplicate=%t err=%v", duplicate, err)
	}
	initial := controlCommand("vm.set-initial-resources", "qemu", `{"cores":1,"sockets":1,"memoryMiB":1024,"cloneOperationId":"operation-1","vmGeneration":1,"templateConfigSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	if err := journal.AuthorizeInitialResources(initial, "operation-1", strings.Repeat("a", 64)); err == nil {
		t.Fatal("unfinished clone authorized initial resources")
	}
	cloneReceipt := Receipt{SchemaVersion: 1, ReceiptID: "clone-receipt", CommandID: clone.CommandID, OperationID: clone.OperationID, AgentRef: "agent-1", State: "succeeded", Code: "SUCCEEDED", ExecutionMode: "production", StartedAt: now, FinishedAt: now}
	if err := journal.Complete(clone, cloneReceipt); err != nil {
		t.Fatal(err)
	}
	if err := journal.AuthorizeInitialResources(initial, "operation-1", strings.Repeat("a", 64)); err != nil {
		t.Fatalf("completed matching clone not authorized: %v", err)
	}
	initial.CommandID = "initial-command"
	if _, _, err := journal.Claim(initial, now); err != nil {
		t.Fatal(err)
	}
	initialReceipt := cloneReceipt
	initialReceipt.CommandID, initialReceipt.ReceiptID = initial.CommandID, "initial-receipt"
	if err := journal.Complete(initial, initialReceipt); err != nil {
		t.Fatal(err)
	}
	secondInitial := initial
	secondInitial.CommandID = "second-initial-command"
	if err := journal.AuthorizeInitialResources(secondInitial, "operation-1", strings.Repeat("a", 64)); err == nil {
		t.Fatal("second initial resource command was authorized")
	}
	delivery := controlCommand("vm.verify-delivery", "qemu", `{"notBefore":"2026-01-01T00:00:00Z","expected":{"cores":2,"sockets":1,"memoryMiB":1024,"disk":{"interface":"scsi0","minimumGiB":20,"limits":{"iopsRead":1000,"iopsWrite":null,"iopsReadMax":null,"iopsWriteMax":null,"iopsReadMaxLength":null,"iopsWriteMaxLength":null,"mbpsRead":100,"mbpsWrite":null,"mbpsReadMax":null,"mbpsWriteMax":null}},"networks":[{"interface":"net0","bridge":"vmbr0","mac":"AA:BB:CC:DD:EE:FF","vlan":null,"mtu":1500,"firewall":true,"rateMbps":"100","ipv4":"192.0.2.10/24","ipv6":"","ipFilterCidrs":["192.0.2.10/32"]}],"timezone":"UTC"}}`)
	delivery.CommandID = "delivery-command"
	if _, _, err := journal.Claim(delivery, now); err != nil {
		t.Fatal(err)
	}
	deliveryReceipt := cloneReceipt
	deliveryReceipt.CommandID, deliveryReceipt.ReceiptID = delivery.CommandID, "delivery-receipt"
	if err := journal.Complete(delivery, deliveryReceipt); err != nil {
		t.Fatal(err)
	}
	if err := journal.AuthorizeInitialResources(initial, "operation-1", strings.Repeat("a", 64)); err == nil {
		t.Fatal("delivered generation authorized initial resource override")
	}
}

func TestSnapshotAndBackupInventoryAreTypedAndBounded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api2/json/nodes/pve1/qemu/101/snapshot":
			_, _ = w.Write([]byte(`{"data":[{"name":"current"},{"name":"before","snaptime":1788300000,"vmstate":0},{"name":"after","parent":"before","snaptime":1788300100,"vmstate":1}]}`))
		case "/api2/json/nodes/pve1/storage/backup1/content":
			if r.URL.Query().Get("content") != "backup" || r.URL.Query().Get("vmid") != "101" {
				t.Fatalf("backup query=%v", r.URL.Query())
			}
			_, _ = w.Write([]byte(`{"data":[{"volid":"backup1:backup/vzdump-qemu-101.vma.zst","content":"backup","format":"zst","vmid":101,"size":9007199254740993,"ctime":1788300000},{"volid":"other:iso/unsafe.iso","content":"iso","vmid":101,"size":1,"ctime":1}]}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	executor := Executor{ReadClient: controlTestClient(t, server), Mode: "test"}
	snapshots, err := executor.Execute(context.Background(), controlCommand("snapshot.list", "qemu", `{"limit":10}`), time.Now())
	if err != nil || strings.Contains(string(snapshots.Result), "current") || !strings.Contains(string(snapshots.Result), `"parentId":"before"`) {
		t.Fatalf("snapshots=%s err=%v", snapshots.Result, err)
	}
	backups, err := executor.Execute(context.Background(), controlCommand("backup.get", "qemu", `{"storage":"backup1","volume":"backup1:backup/vzdump-qemu-101.vma.zst"}`), time.Now())
	if err != nil || !strings.Contains(string(backups.Result), `"sizeBytes":"9007199254740993"`) || strings.Contains(string(backups.Result), "unsafe.iso") {
		t.Fatalf("backups=%s err=%v", backups.Result, err)
	}
}

func TestConsoleTicketNeverEntersReceipt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"user":"root@pam","ticket":"PVE:super-secret-ticket","cert":"-----BEGIN CERTIFICATE-----safe-----END CERTIFICATE-----","port":5901}}`))
	}))
	defer server.Close()
	sink := &memoryConsoleSink{}
	command := controlCommand("vm.console.create-session", "qemu", `{"ttlSeconds":60,"webSocket":true}`)
	command.CommandID, command.BindingID, command.DeviceID, command.AssignmentRevision = "console-command", "11111111-1111-4111-8111-111111111111", "device-1", 1
	receipt, err := (Executor{Client: controlTestClient(t, server), ConsoleSessions: sink, Mode: "production", ProductionExecution: true}).Execute(context.Background(), command, time.Now())
	if err != nil || sink.secret.PVETicket == "" || receipt.State != "succeeded" {
		t.Fatalf("receipt=%#v secret=%#v err=%v", receipt, sink.secret, err)
	}
	raw, _ := json.Marshal(receipt)
	if strings.Contains(string(raw), "super-secret-ticket") || strings.Contains(string(raw), "BEGIN CERTIFICATE") || strings.Contains(string(raw), "root@pam") {
		t.Fatalf("console secret leaked in receipt: %s", raw)
	}
}

func TestLXCPasswordResetUsesOnlyTypedConfigFieldAndNoResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Method != http.MethodPut || r.URL.Path != "/api2/json/nodes/pve1/lxc/101/config" || r.Form.Get("password") != "secret-value" || len(r.Form) != 1 {
			t.Fatalf("request=%s %s form=%v", r.Method, r.URL.Path, r.Form)
		}
		_, _ = w.Write([]byte(`{"data":null}`))
	}))
	defer server.Close()
	receipt, err := (Executor{Client: controlTestClient(t, server), Mode: "production", ProductionExecution: true}).Execute(context.Background(), controlCommand("vm.reset-password", "lxc", `{"username":"root","password":"secret-value","crypted":false,"osFamily":"linux"}`), time.Now())
	if err != nil || receipt.State != "succeeded" || len(receipt.Result) != 0 {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
}

func TestLXCPasswordResetRejectsNonRootWindowsAndCrypted(t *testing.T) {
	for _, parameters := range []string{
		`{"username":"admin","password":"secret","crypted":false,"osFamily":"linux"}`,
		`{"username":"root","password":"secret","crypted":false,"osFamily":"windows"}`,
		`{"username":"root","password":"secret","crypted":true,"osFamily":"linux"}`,
	} {
		if err := validateParameters(controlCommand("vm.reset-password", "lxc", parameters)); err == nil {
			t.Fatalf("unsafe LXC password parameters accepted: %s", parameters)
		}
	}
}

func TestReinstallFirewallBuildsIPFiltersBeforeEnforcement(t *testing.T) {
	type mutation struct {
		path string
		form url.Values
	}
	var mutations []mutation
	enabled := true
	command := controlCommand("vm.reinstall", "qemu", reinstallFixture())
	err := restoreReinstallFirewall(context.Background(), nil, command, []deliveryNetwork{{
		Interface: "net0", Firewall: &enabled, IPFilterCIDRs: []string{"192.0.2.10/32", "2001:db8::10/128"},
	}}, func(_ string, path string, form url.Values, _ string) error {
		mutations = append(mutations, mutation{path: path, form: form})
		return nil
	})
	if err != nil || len(mutations) != 5 {
		t.Fatalf("mutations=%#v err=%v", mutations, err)
	}
	if mutations[0].path != "/nodes/pve1/qemu/101/firewall/options" || mutations[0].form.Get("enable") != "0" || mutations[1].form.Get("name") != "ipfilter-net0" || mutations[2].form.Get("cidr") != "192.0.2.10/32" || mutations[3].form.Get("cidr") != "2001:db8::10/128" || mutations[4].form.Get("enable") != "1" {
		t.Fatalf("unsafe firewall restoration order: %#v", mutations)
	}
}

func TestReinstallUsesFixedTemplateCompensationAndFinalReadback(t *testing.T) {
	baseline := pve.TemplateBaseline{
		Cores: 2, Sockets: 1, MemoryMiB: 1024,
		BootDisk:       pve.TemplateBootDisk{Interface: "scsi0", SizeGiB: 8},
		Networks:       []pve.TemplateNetwork{{Interface: "net0", Bridge: "vmbr0", Model: "virtio"}},
		CloudInitDrive: true, QGADeviceEnabled: true, GuestFirewallEmpty: true,
	}
	canonical, _ := json.Marshal(baseline)
	templateHash := fmt.Sprintf("%x", sha256.Sum256(canonical))
	mutations := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			mutations = append(mutations, r.Method+" "+r.URL.Path)
			if strings.HasSuffix(r.URL.Path, "/agent/exec") {
				_, _ = w.Write([]byte(`{"data":17}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":null}`))
			return
		}
		switch r.URL.Path {
		case "/api2/json/cluster/resources":
			_, _ = w.Write([]byte(`{"data":[{"type":"qemu","node":"pve1","vmid":101,"template":0,"status":"stopped"},{"type":"qemu","node":"pve1","vmid":9001,"template":1,"status":"stopped"}]}`))
		case "/api2/json/nodes/pve1/qemu/9001/config":
			_, _ = w.Write([]byte(`{"data":{"cores":2,"sockets":1,"memory":1024,"scsi0":"local-zfs:vm-9001-disk-0,size=8G","ide2":"local-zfs:cloudinit,media=cdrom","net0":"virtio=02:00:00:00:00:01,bridge=vmbr0,firewall=0","agent":"enabled=1"}}`))
		case "/api2/json/nodes/pve1/qemu/9001/firewall/rules", "/api2/json/nodes/pve1/qemu/9001/firewall/ipset":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case "/api2/json/nodes/pve1/qemu/101/config":
			_, _ = w.Write([]byte(`{"data":{"digest":"digest-1","cores":2,"sockets":1,"memory":1024,"scsi0":"local-zfs:vm-101-disk-0,size=20G,iops_rd=1000,mbps_rd=100","net0":"virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,mtu=1500,firewall=1,rate=100","ipconfig0":"ip=192.0.2.10/24,ip6=2001:db8::10/64"}}`))
		case "/api2/json/nodes/pve1/qemu/101/status/current":
			_, _ = w.Write([]byte(`{"data":{"status":"running","qmpstatus":"running"}}`))
		case "/api2/json/nodes/pve1/qemu/101/agent/info":
			_, _ = w.Write([]byte(`{"data":{"version":"9.0","supported_commands":[{"name":"guest-get-osinfo","enabled":true},{"name":"guest-network-get-interfaces","enabled":true}]}}`))
		case "/api2/json/nodes/pve1/qemu/101/agent/get-osinfo":
			_, _ = w.Write([]byte(`{"data":{"name":"ubuntu","pretty-name":"Ubuntu 24.04 LTS","version-id":"24.04"}}`))
		case "/api2/json/nodes/pve1/qemu/101/agent/network-get-interfaces":
			_, _ = w.Write([]byte(`{"data":[{"name":"ens18","hardware-address":"AA:BB:CC:DD:EE:FF","ip-addresses":[{"ip-address":"192.0.2.10","prefix":24,"ip-address-type":"ipv4"},{"ip-address":"2001:db8::10","prefix":64,"ip-address-type":"ipv6"}]}]}`))
		case "/api2/json/nodes/pve1/qemu/101/agent/get-timezone":
			_, _ = w.Write([]byte(`{"data":{"zone":"UTC","offset":0}}`))
		case "/api2/json/nodes/pve1/qemu/101/agent/exec-status":
			_, _ = w.Write([]byte(`{"data":{"exited":1,"exitcode":0}}`))
		case "/api2/json/cluster/firewall/options":
			_, _ = w.Write([]byte(`{"data":{"enable":1,"ebtables":1}}`))
		case "/api2/json/nodes/pve1/firewall/options":
			_, _ = w.Write([]byte(`{"data":{"enable":1}}`))
		case "/api2/json/nodes/pve1/qemu/101/firewall/options":
			_, _ = w.Write([]byte(`{"data":{"enable":1,"policy_in":"ACCEPT","policy_out":"ACCEPT","macfilter":1}}`))
		case "/api2/json/nodes/pve1/qemu/101/firewall/ipset":
			_, _ = w.Write([]byte(`{"data":[{"name":"ipfilter-net0"}]}`))
		case "/api2/json/nodes/pve1/qemu/101/firewall/ipset/ipfilter-net0":
			_, _ = w.Write([]byte(`{"data":[{"cidr":"192.0.2.10/32","nomatch":0},{"cidr":"2001:db8::10/128","nomatch":0}]}`))
		default:
			t.Fatalf("unexpected GET %s", r.URL.Path)
		}
	}))
	defer server.Close()
	enabled := true
	qga := true
	start := true
	mtu := 1500
	bridge, mac, rate, ipv4, ipv6, gateway4, gateway6 := "vmbr0", "AA:BB:CC:DD:EE:FF", "100", "192.0.2.10/24", "2001:db8::10/64", "192.0.2.1", "2001:db8::1"
	iops, mbps := int64(1000), int64(100)
	parameters := reinstallP{
		TemplateRef: "ubuntu-24.04", TemplateVersion: "24.04", TemplateNode: "pve1", TemplateGuestType: "qemu", TemplateVMID: 9001, TemplateConfigSHA256: templateHash,
		VMGeneration: 1, TemporaryVMID: 800101, Storage: "local-zfs", NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Start: &start,
		Expected:   deliveryExpected{Cores: 2, Sockets: 1, MemoryMiB: 1024, Disk: deliveryDisk{Interface: "scsi0", MinimumGiB: 20, Limits: diskIOLimits{IOPSRead: &iops, MBPSRead: &mbps}}, Networks: []deliveryNetwork{{Interface: "net0", Bridge: bridge, MAC: mac, MTU: mtu, Firewall: &enabled, RateMbps: rate, IPv4: ipv4, IPv6: ipv6, IPFilterCIDRs: []string{"192.0.2.10/32", "2001:db8::10/128"}}}, Timezone: "UTC"},
		ExpectedOS: reinstallOS{Family: "linux", Name: "ubuntu", VersionID: "24.04"},
		Networks:   []networkP{{Interface: "net0", Bridge: &bridge, MAC: &mac, MTU: &mtu, Firewall: &enabled, RateMbps: &rate, IPv4: &ipv4, IPv6: &ipv6, Gateway4: &gateway4, Gateway6: &gateway6}},
		CloudInit:  cloudInitP{Hostname: "vm101", Username: "root", Password: "fixture-secret", PasswordFormat: "plain", SSHAuthorizedKeys: []string{}, QGAEnabled: &qga},
	}
	raw, _ := json.Marshal(parameters)
	// The wire contract requires every nullable key to be signed explicitly;
	// Go's reusable action structs omit nil optional values when marshaled.
	var exact map[string]any
	_ = json.Unmarshal(raw, &exact)
	limits := exact["expected"].(map[string]any)["disk"].(map[string]any)["limits"].(map[string]any)
	for _, key := range []string{"iopsRead", "iopsWrite", "iopsReadMax", "iopsWriteMax", "iopsReadMaxLength", "iopsWriteMaxLength", "mbpsRead", "mbpsWrite", "mbpsReadMax", "mbpsWriteMax"} {
		if _, ok := limits[key]; !ok {
			limits[key] = nil
		}
	}
	exact["expected"].(map[string]any)["networks"].([]any)[0].(map[string]any)["vlan"] = nil
	exact["networks"].([]any)[0].(map[string]any)["vlan"] = nil
	raw, _ = json.Marshal(exact)
	command := controlCommand("vm.reinstall", "qemu", string(raw))
	receipt, err := (Executor{Client: controlTestClient(t, server), Mode: "production", ProductionExecution: true}).Execute(context.Background(), command, time.Now())
	if err != nil || receipt.State != "succeeded" || !strings.Contains(string(receipt.Result), `"reinstalled":true`) || strings.Contains(string(receipt.Result), "fixture-secret") {
		t.Fatalf("receipt=%#v mutations=%v err=%v", receipt, mutations, err)
	}
	wanted := []string{"POST /api2/json/nodes/pve1/qemu/101/clone", "DELETE /api2/json/nodes/pve1/qemu/101", "POST /api2/json/nodes/pve1/qemu/9001/clone", "DELETE /api2/json/nodes/pve1/qemu/800101"}
	for _, expected := range wanted {
		if !containsString(mutations, expected) {
			t.Fatalf("missing %s in %v", expected, mutations)
		}
	}
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func TestSuspendResumeUseFixedStatusEndpoints(t *testing.T) {
	for _, action := range []string{"vm.suspend", "vm.resume"} {
		t.Run(action, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					if r.URL.Path != "/api2/json/nodes/pve1/qemu/101/status/"+strings.TrimPrefix(action, "vm.") {
						t.Fatalf("request=%s %s", r.Method, r.URL.Path)
					}
					_, _ = w.Write([]byte(`{"data":null}`))
					return
				}
				status := `{"status":"running","qmpstatus":"running"}`
				if action == "vm.suspend" {
					status = `{"status":"running","qmpstatus":"paused"}`
				}
				_, _ = w.Write([]byte(`{"data":` + status + `}`))
			}))
			defer server.Close()
			upid, result, err := executePVE(context.Background(), controlTestClient(t, server), controlCommand(action, "qemu", `{}`))
			if err != nil || upid != "" || !strings.Contains(string(result), `"verified":true`) {
				t.Fatalf("upid=%q result=%s err=%v", upid, result, err)
			}
		})
	}
}

func TestNewActionsRejectUnknownFieldsAndArbitrarySources(t *testing.T) {
	cases := []Command{
		controlCommand("vm.set-initial-resources", "qemu", `{"cores":1,"sockets":1,"memoryMiB":1024,"cloneOperationId":"operation-1","vmGeneration":1,"templateConfigSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","delivered":false}`),
		controlCommand("vm.reinstall", "qemu", strings.TrimSuffix(reinstallFixture(), "}")+`,"url":"https://evil.invalid/image.qcow2"}`),
		controlCommand("vm.console.create-session", "qemu", `{"ttlSeconds":60,"webSocket":true,"endpoint":"/arbitrary"}`),
		controlCommand("snapshot.list", "qemu", `{"limit":10,"path":"/etc"}`),
		controlCommand("backup.get", "qemu", `{"storage":"backup1","volume":"../../etc/shadow"}`),
	}
	for _, command := range cases {
		if err := validateParameters(command); err == nil {
			t.Errorf("unsafe %s parameters accepted", command.Action)
		}
	}
}

func TestReinstallRequiresEveryExactNestedKey(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "agent-v1-vm-reinstall.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	expected := document["expected"].(map[string]any)
	disk := expected["disk"].(map[string]any)
	limits := disk["limits"].(map[string]any)
	delete(limits, "mbpsWriteMax")
	missingLimit, _ := json.Marshal(document)
	if err := validateParameters(controlCommand("vm.reinstall", "qemu", string(missingLimit))); err == nil {
		t.Fatal("reinstall accepted a missing nullable disk-limit key")
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	networks := document["networks"].([]any)
	delete(networks[0].(map[string]any), "gateway6")
	missingNetworkKey, _ := json.Marshal(document)
	if err := validateParameters(controlCommand("vm.reinstall", "qemu", string(missingNetworkKey))); err == nil {
		t.Fatal("reinstall accepted a missing network key")
	}
}

func TestReinstallRejectsWindowsUntilAWindowsRecoveryContractExists(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "agent-v1-vm-reinstall.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	document["expectedOs"].(map[string]any)["family"] = "windows"
	document["expectedOs"].(map[string]any)["name"] = "windows"
	document["expectedOs"].(map[string]any)["versionId"] = "2025"
	unsafe, _ := json.Marshal(document)
	if err := validateParameters(controlCommand("vm.reinstall", "qemu", string(unsafe))); err == nil {
		t.Fatal("Linux Cloud-Init reinstall contract accepted a Windows guest")
	}
}

func TestProvisioningActionGoldensValidateAndContainNoConsoleSecret(t *testing.T) {
	initial, err := os.ReadFile("testdata/agent-v1-vm-set-initial-resources.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateParameters(controlCommand("vm.set-initial-resources", "qemu", string(initial))); err != nil {
		t.Fatalf("initial resources golden: %v", err)
	}
	reinstall, err := os.ReadFile("testdata/agent-v1-vm-reinstall.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateParameters(controlCommand("vm.reinstall", "qemu", string(reinstall))); err != nil {
		t.Fatalf("reinstall golden: %v", err)
	}
	console, err := os.ReadFile("testdata/agent-v1-console-session-result.json")
	if err != nil {
		t.Fatal(err)
	}
	var publication ConsoleSessionPublication
	if json.Unmarshal(console, &publication) != nil || publication.SessionRef == "" || !publication.OneTime || strings.Contains(strings.ToLower(string(console)), "ticket") || strings.Contains(strings.ToLower(string(console)), "certificate") {
		t.Fatalf("unsafe console result golden: %s", console)
	}
}
