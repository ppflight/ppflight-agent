package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
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

func (f initialAuthorizerFunc) AuthorizeInitialResources(c Command, operation, _ string, _ int, digest string) error {
	return f(c, operation, digest)
}

type memoryConsoleSink struct {
	registration ConsoleTunnelRegistration
	local        ConsoleLocalEndpoint
	revoked      ConsoleSessionRevoke
	invalidated  bool
}

func (s *memoryConsoleSink) Publish(_ context.Context, registration ConsoleTunnelRegistration, local ConsoleLocalEndpoint) (ConsoleSessionPublication, error) {
	s.registration = registration
	s.local = local
	return ConsoleSessionPublication{SessionRef: registration.SessionRef, State: "ready", BrowserPath: "/console/session/" + registration.SessionRef, ExpiresAt: registration.ExpiresAt}, nil
}
func (s *memoryConsoleSink) Revoke(_ context.Context, revoke ConsoleSessionRevoke) error {
	s.revoked = revoke
	return nil
}
func (s *memoryConsoleSink) Invalidate() { s.invalidated = true }

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
	command := controlCommand("vm.set-initial-resources", "qemu", `{"cores":1,"sockets":1,"memoryMiB":1024,"cloneOperationId":"operation-clone","templateRef":"ubuntu-24.04","sourceVmid":9001,"vmGeneration":"1","templateConfigSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	command.OperationID = "operation-initial"
	authorized := false
	receipt, err := (Executor{Client: controlTestClient(t, server), Mode: "production", ProductionExecution: true, InitialResources: initialAuthorizerFunc(func(_ Command, operation, digest string) error {
		authorized = operation == "operation-clone" && strings.HasPrefix(digest, "aaaa")
		return nil
	})}).Execute(context.Background(), command, time.Now())
	if err != nil || receipt.State != "succeeded" || !authorized || requests != 4 {
		t.Fatalf("receipt=%#v authorized=%t requests=%d err=%v", receipt, authorized, requests, err)
	}
}

const initialResourcesFixture = `{"cores":1,"sockets":1,"memoryMiB":1024,"cloneOperationId":"operation-clone","templateRef":"ubuntu-24.04","sourceVmid":9001,"vmGeneration":"1","templateConfigSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`

func lineageCommand(action, parameters, commandID, operationID string) Command {
	command := controlCommand(action, "qemu", parameters)
	command.CommandID = commandID
	command.OperationID = operationID
	command.IdempotencyKey = commandID + "-idempotency"
	command.AgentRef = "agent-1"
	command.BindingID = "11111111-1111-4111-8111-111111111111"
	command.DeviceID = "device-1"
	command.CredentialEpoch = 1
	command.AssignmentRevision = 7
	return command
}

func completeLineageRecord(t *testing.T, journal *Journal, command Command, state string, at time.Time) Receipt {
	t.Helper()
	code := strings.ToUpper(state)
	if state == "succeeded" {
		code = "SUCCEEDED"
	}
	receipt := Receipt{SchemaVersion: 1, ReceiptID: command.CommandID + "-receipt", CommandID: command.CommandID, OperationID: command.OperationID, AgentRef: command.AgentRef, State: state, Code: code, ExecutionMode: "production", StartedAt: at, FinishedAt: at}
	if command.Action == "vm.set-initial-resources" && state == "succeeded" {
		receipt.Result, _ = json.Marshal(initialResourcesResult{Configured: true, Verified: true, Cores: 1, Sockets: 1, MemoryMiB: 1024, VMGeneration: 1, TemplateRef: "ubuntu-24.04", SourceVMID: 9001, TemplateConfigSHA256: strings.Repeat("a", 64)})
	}
	if err := journal.Complete(command, receipt); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func successfulCloneJournal(t *testing.T) (*Journal, Command, Command, time.Time) {
	t.Helper()
	now := time.Now().UTC()
	journal, err := OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	clone := lineageCommand("vm.clone", `{"sourceVmid":9001,"templateRef":"ubuntu-24.04","name":"vm101","target":"pve1","storage":"local-lvm","full":true,"sourceConfigSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`, "clone-command", "operation-clone")
	if _, duplicate, err := journal.Claim(clone, now); err != nil || duplicate {
		t.Fatalf("claim clone duplicate=%t err=%v", duplicate, err)
	}
	completeLineageRecord(t, journal, clone, "succeeded", now)
	initial := lineageCommand("vm.set-initial-resources", initialResourcesFixture, "initial-command", "operation-initial")
	return journal, clone, initial, now
}

func TestInitialResourceJournalAuthorizesDistinctSuccessfulCloneAndIsIdempotent(t *testing.T) {
	journal, clone, initial, now := successfulCloneJournal(t)
	if clone.OperationID == initial.OperationID {
		t.Fatal("clone and initial resource operation IDs must be distinct")
	}
	if _, duplicate, err := journal.Claim(initial, now.Add(time.Second)); err != nil || duplicate {
		t.Fatalf("claim initial duplicate=%t err=%v", duplicate, err)
	}
	if err := journal.AuthorizeInitialResources(initial, clone.OperationID, "ubuntu-24.04", 9001, strings.Repeat("a", 64)); err != nil {
		t.Fatalf("completed matching clone not authorized: %v", err)
	}
	want := completeLineageRecord(t, journal, initial, "succeeded", now.Add(2*time.Second))
	got, duplicate, err := journal.Claim(initial, now.Add(3*time.Second))
	if err != nil || !duplicate || got.ReceiptID != want.ReceiptID || got.State != "succeeded" || !bytes.Equal(got.Result, want.Result) {
		t.Fatalf("idempotent replay got=%#v duplicate=%t err=%v", got, duplicate, err)
	}
	second := initial
	second.CommandID = "initial-command-2"
	second.OperationID = "operation-initial-2"
	second.IdempotencyKey = initial.IdempotencyKey
	if err := journal.AuthorizeInitialResources(second, clone.OperationID, "ubuntu-24.04", 9001, strings.Repeat("a", 64)); err == nil {
		t.Fatal("different command replay consumed initial resource authorization twice")
	}
	if _, _, err := journal.Claim(second, now.Add(4*time.Second)); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("idempotency key reuse err=%v", err)
	}
}

func TestInitialResourceJournalSurvivesRestart(t *testing.T) {
	directory := t.TempDir()
	now := time.Now().UTC()
	journal, err := OpenJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	clone := lineageCommand("vm.clone", `{"sourceVmid":9001,"templateRef":"ubuntu-24.04","name":"vm101","target":"pve1","storage":"local-lvm","full":true,"sourceConfigSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`, "clone-command", "operation-clone")
	if _, _, err := journal.Claim(clone, now); err != nil {
		t.Fatal(err)
	}
	completeLineageRecord(t, journal, clone, "succeeded", now)
	reopened, err := OpenJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	initial := lineageCommand("vm.set-initial-resources", initialResourcesFixture, "initial-command", "operation-initial")
	if err := reopened.AuthorizeInitialResources(initial, clone.OperationID, "ubuntu-24.04", 9001, strings.Repeat("a", 64)); err != nil {
		t.Fatalf("durable lineage did not survive restart: %v", err)
	}
}

func TestInitialResourceJournalRejectsMissingOrNonSuccessfulClone(t *testing.T) {
	for _, state := range []string{"missing", "submitted", "waiting", "failed", "rolled_back"} {
		t.Run(state, func(t *testing.T) {
			now := time.Now().UTC()
			journal, err := OpenJournal(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			clone := lineageCommand("vm.clone", `{"sourceVmid":9001,"templateRef":"ubuntu-24.04","name":"vm101","target":"pve1","storage":"local-lvm","full":true,"sourceConfigSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`, "clone-command", "operation-clone")
			if state != "missing" {
				if _, _, err := journal.Claim(clone, now); err != nil {
					t.Fatal(err)
				}
				completeLineageRecord(t, journal, clone, state, now)
			}
			initial := lineageCommand("vm.set-initial-resources", initialResourcesFixture, "initial-command", "operation-initial")
			if err := journal.AuthorizeInitialResources(initial, clone.OperationID, "ubuntu-24.04", 9001, strings.Repeat("a", 64)); err == nil {
				t.Fatalf("%s clone authorized initial resources", state)
			}
		})
	}
}

func TestInitialResourceJournalRejectsEveryAuthorityOrIdentityMismatch(t *testing.T) {
	mutations := map[string]func(*Command, *string){
		"binding":   func(c *Command, _ *string) { c.BindingID = "22222222-2222-4222-8222-222222222222" },
		"device":    func(c *Command, _ *string) { c.DeviceID = "device-2" },
		"agent":     func(c *Command, _ *string) { c.AgentRef = "agent-2" },
		"cluster":   func(c *Command, _ *string) { c.Identity.ClusterRef = "cluster-2" },
		"node":      func(c *Command, _ *string) { c.Identity.NodeRef = "pve2" },
		"service":   func(c *Command, _ *string) { c.Identity.ServiceRef = "service-2" },
		"instance":  func(c *Command, _ *string) { c.Identity.InstanceUUID = "instance-2" },
		"guestType": func(c *Command, _ *string) { c.Identity.GuestType = "lxc" },
		"vmid":      func(c *Command, _ *string) { c.Identity.VMID = 102 },
		"generation": func(c *Command, _ *string) {
			c.Identity.Generation = 2
		},
		"revision": func(c *Command, _ *string) { c.AssignmentRevision = 8 },
		"epoch":    func(c *Command, _ *string) { c.CredentialEpoch = 2 },
		"templateHash": func(_ *Command, digest *string) {
			*digest = strings.Repeat("b", 64)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			journal, clone, initial, _ := successfulCloneJournal(t)
			digest := strings.Repeat("a", 64)
			mutate(&initial, &digest)
			if err := journal.AuthorizeInitialResources(initial, clone.OperationID, "ubuntu-24.04", 9001, digest); err == nil {
				t.Fatal("mismatched clone lineage was authorized")
			}
		})
	}
	journal, clone, initial, _ := successfulCloneJournal(t)
	if err := journal.AuthorizeInitialResources(initial, clone.OperationID, "debian-13", 9001, strings.Repeat("a", 64)); err == nil {
		t.Fatal("cross-templateRef clone lineage was authorized")
	}
	if err := journal.AuthorizeInitialResources(initial, clone.OperationID, "ubuntu-24.04", 9002, strings.Repeat("a", 64)); err == nil {
		t.Fatal("cross-sourceVmid clone lineage was authorized")
	}
}

func TestJournalRejectsOperationIDReuseAcrossCommands(t *testing.T) {
	journal, _, initial, now := successfulCloneJournal(t)
	initial.OperationID = "operation-clone"
	if _, _, err := journal.Claim(initial, now.Add(time.Second)); !errors.Is(err, ErrOperationConflict) {
		t.Fatalf("operation reuse err=%v", err)
	}
}

func TestInitialResourceJournalRejectsFinalizationAndGenerationAdvance(t *testing.T) {
	for _, action := range []string{"vm.start", "vm.verify-delivery", "vm.reinstall", "generation-advance"} {
		t.Run(action, func(t *testing.T) {
			journal, clone, initial, now := successfulCloneJournal(t)
			barrierAction := action
			if action == "generation-advance" {
				barrierAction = "vm.reinstall"
			}
			barrier := lineageCommand(barrierAction, `{}`, "barrier-command", "operation-barrier")
			if action == "generation-advance" {
				barrier.Identity.Generation = 2
			}
			if _, _, err := journal.Claim(barrier, now.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			completeLineageRecord(t, journal, barrier, "succeeded", now.Add(2*time.Second))
			if err := journal.AuthorizeInitialResources(initial, clone.OperationID, "ubuntu-24.04", 9001, strings.Repeat("a", 64)); err == nil {
				t.Fatalf("%s did not close initial resource authorization", action)
			}
		})
	}
}

func TestOrdinaryResourceDowngradeAndDiskShrinkRemainRejected(t *testing.T) {
	t.Run("CPU and memory downgrade", func(t *testing.T) {
		requests := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests++
			if r.Method != http.MethodGet || r.URL.Path != "/api2/json/nodes/pve1/qemu/101/config" {
				t.Fatalf("unexpected mutation request: %s %s", r.Method, r.URL.Path)
			}
			_, _ = w.Write([]byte(`{"data":{"digest":"current","cores":4,"sockets":1,"memory":4096}}`))
		}))
		defer server.Close()
		_, _, err := executePVE(context.Background(), controlTestClient(t, server), controlCommand("vm.set-resources", "qemu", `{"cores":2,"memoryMiB":2048}`))
		if err == nil || !strings.Contains(err.Error(), "may only increase") || requests != 1 {
			t.Fatalf("downgrade err=%v requests=%d", err, requests)
		}
	})
	t.Run("disk shrink", func(t *testing.T) {
		requests := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests++
			if r.Method != http.MethodGet || r.URL.Path != "/api2/json/nodes/pve1/qemu/101/config" {
				t.Fatalf("unexpected mutation request: %s %s", r.Method, r.URL.Path)
			}
			_, _ = w.Write([]byte(`{"data":{"digest":"current","scsi0":"local-zfs:vm-101-disk-0,size=40G"}}`))
		}))
		defer server.Close()
		_, _, err := executePVE(context.Background(), controlTestClient(t, server), controlCommand("vm.resize", "qemu", `{"disk":"scsi0","targetGiB":20}`))
		if err == nil || !strings.Contains(err.Error(), "may only increase") || requests != 1 {
			t.Fatalf("shrink err=%v requests=%d", err, requests)
		}
	})
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
		_ = r.ParseForm()
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/vncproxy") || r.Form.Get("websocket") != "1" {
			t.Fatalf("unexpected vncproxy request: %s %s %v", r.Method, r.URL.Path, r.Form)
		}
		_, _ = w.Write([]byte(`{"data":{"user":"root@pam","ticket":"PVE:super-secret-ticket","cert":"-----BEGIN CERTIFICATE-----safe-----END CERTIFICATE-----","port":5901}}`))
	}))
	defer server.Close()
	sink := &memoryConsoleSink{}
	command := controlCommand("vm.console.create-session", "qemu", `{"ttlSeconds":60,"webSocket":true}`)
	command.CommandID, command.AgentRef, command.BindingID, command.DeviceID, command.CredentialEpoch, command.AssignmentRevision = "console-command", "agent-1", "11111111-1111-4111-8111-111111111111", "device-1", 1, 1
	receipt, err := (Executor{Client: controlTestClient(t, server), ConsoleSessions: sink, Mode: "production", ProductionExecution: true}).Execute(context.Background(), command, time.Now())
	if err != nil || len(sink.local.Ticket) == 0 || sink.registration.Transport != "agent-reverse-wss-v1" || receipt.State != "succeeded" {
		t.Fatalf("receipt=%#v registration=%#v err=%v", receipt, sink.registration, err)
	}
	raw, _ := json.Marshal(receipt)
	if strings.Contains(string(raw), "super-secret-ticket") || strings.Contains(string(raw), "BEGIN CERTIFICATE") || strings.Contains(string(raw), "root@pam") {
		t.Fatalf("console secret leaked in receipt: %s", raw)
	}
}

func TestConsolePublicationDoesNotSurviveJournalReplayAfterAgentRestart(t *testing.T) {
	directory := t.TempDir()
	now := time.Now().UTC()
	journal, err := OpenJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	command := lineageCommand("vm.console.create-session", `{"ttlSeconds":60,"webSocket":true}`, "console-command", "console-operation")
	if _, duplicate, err := journal.Claim(command, now); err != nil || duplicate {
		t.Fatalf("claim console duplicate=%t err=%v", duplicate, err)
	}
	publication, _ := json.Marshal(ConsoleSessionPublication{SessionRef: "session-1", State: "ready", ExpiresAt: now.Add(time.Minute), BrowserPath: "/api/console/opaque-1"})
	receipt := Receipt{SchemaVersion: 1, ReceiptID: "console-receipt", CommandID: command.CommandID, OperationID: command.OperationID, AgentRef: command.AgentRef, State: "succeeded", Code: "SUCCEEDED", ExecutionMode: "production", StartedAt: now, FinishedAt: now, Result: publication}
	if err := journal.Complete(command, receipt); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	replayed, duplicate, err := reopened.Claim(command, now.Add(time.Minute))
	if err != nil || !duplicate || replayed.State != "succeeded" || len(replayed.Result) != 0 {
		t.Fatalf("restart replay retained stale console session: receipt=%#v duplicate=%t err=%v", replayed, duplicate, err)
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
		CloudInitDrive: true, QGADeviceEnabled: true, QGAPackagePreinstalled: true, GuestFirewallEmpty: true,
	}
	canonical, _ := json.Marshal(baseline)
	templateHash := fmt.Sprintf("%x", sha256.Sum256(canonical))
	mutations := []string{}
	targetStatus := "running"
	timezoneAttempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			mutations = append(mutations, r.Method+" "+r.URL.Path)
			if strings.HasSuffix(r.URL.Path, "/101/status/shutdown") {
				targetStatus = "stopped"
			}
			if strings.HasSuffix(r.URL.Path, "/101/status/start") {
				targetStatus = "running"
			}
			if strings.HasSuffix(r.URL.Path, "/agent/exec") {
				timezoneAttempts++
				if timezoneAttempts < 3 {
					http.Error(w, "QGA is not running yet", http.StatusInternalServerError)
					return
				}
				_, _ = w.Write([]byte(`{"data":17}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":null}`))
			return
		}
		switch r.URL.Path {
		case "/api2/json/cluster/resources":
			_, _ = fmt.Fprintf(w, `{"data":[{"type":"qemu","node":"pve1","vmid":101,"template":0,"status":%q},{"type":"qemu","node":"pve1","vmid":9001,"template":1,"status":"stopped"}]}`, targetStatus)
		case "/api2/json/nodes/pve1/qemu/9001/config":
			_, _ = w.Write([]byte(`{"data":{"cores":2,"sockets":1,"memory":1024,"scsi0":"local-zfs:vm-9001-disk-0,size=8G","ide2":"local-zfs:cloudinit,media=cdrom","net0":"virtio=02:00:00:00:00:01,bridge=vmbr0,firewall=0","agent":"enabled=1","tags":"ppflight-cloudinit;ppflight-qga-preinstalled"}}`))
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
	receipt, err := (Executor{Client: controlTestClient(t, server), Mode: "production", ProductionExecution: true, ReinstallReadyWait: 100 * time.Millisecond, ReinstallPollInterval: time.Millisecond}).Execute(context.Background(), command, time.Now())
	if err != nil || receipt.State != "succeeded" || !strings.Contains(string(receipt.Result), `"reinstalled":true`) || strings.Contains(string(receipt.Result), "fixture-secret") {
		t.Fatalf("receipt=%#v mutations=%v err=%v", receipt, mutations, err)
	}
	if timezoneAttempts != 3 {
		t.Fatalf("post-boot QGA was not retried: attempts=%d", timezoneAttempts)
	}
	wanted := []string{"POST /api2/json/nodes/pve1/qemu/101/status/shutdown", "POST /api2/json/nodes/pve1/qemu/101/clone", "DELETE /api2/json/nodes/pve1/qemu/101", "POST /api2/json/nodes/pve1/qemu/9001/clone", "DELETE /api2/json/nodes/pve1/qemu/800101"}
	for _, expected := range wanted {
		if !containsString(mutations, expected) {
			t.Fatalf("missing %s in %v", expected, mutations)
		}
	}
	if mutationIndex(mutations, wanted[0]) > mutationIndex(mutations, wanted[1]) {
		t.Fatalf("running VM was cloned before shutdown: %v", mutations)
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

func mutationIndex(values []string, wanted string) int {
	for index, value := range values {
		if value == wanted {
			return index
		}
	}
	return -1
}

func TestReinstallMissingTargetIsDeterministicPreflightFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api2/json/cluster/resources" {
			t.Fatalf("preflight reached unexpected request: %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer server.Close()
	receipt, err := (Executor{Client: controlTestClient(t, server), Mode: "production", ProductionExecution: true}).Execute(context.Background(), controlCommand("vm.reinstall", "qemu", reinstallFixture()), time.Now())
	if err == nil || !errors.Is(err, ErrReinstallPreflight) || receipt.State != "failed" || receipt.Code != "REINSTALL_PREFLIGHT_REJECTED" || receipt.Accepted || receipt.MutationMayHaveSucceeded {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
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
		controlCommand("vm.set-initial-resources", "qemu", `{"cores":1,"sockets":1,"memoryMiB":1024,"cloneOperationId":"operation-clone","templateRef":"ubuntu-24.04","sourceVmid":9001,"vmGeneration":"1","templateConfigSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","delivered":false}`),
		controlCommand("vm.reinstall", "qemu", strings.TrimSuffix(reinstallFixture(), "}")+`,"url":"https://evil.invalid/image.qcow2"}`),
		controlCommand("vm.console.create-session", "qemu", `{"ttlSeconds":60,"webSocket":true,"endpoint":"/arbitrary"}`),
		controlCommand("snapshot.list", "qemu", `{"limit":10,"path":"/etc"}`),
		controlCommand("backup.get", "qemu", `{"storage":"backup1","volume":"../../etc/shadow"}`),
		controlCommand("vm.console.create-session", "qemu", `{"ttlSeconds":29,"webSocket":true}`),
		controlCommand("vm.console.create-session", "qemu", `{"ttlSeconds":301,"webSocket":true}`),
		controlCommand("vm.console.create-session", "lxc", `{"ttlSeconds":60,"webSocket":true}`),
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
	if json.Unmarshal(console, &publication) != nil || publication.SessionRef == "" || publication.State != "ready" || publication.BrowserPath == "" || strings.Contains(strings.ToLower(string(console)), "ticket") || strings.Contains(strings.ToLower(string(console)), "certificate") {
		t.Fatalf("unsafe console result golden: %s", console)
	}
	registrationRaw, err := os.ReadFile("testdata/agent-v1-console-reverse-tunnel-request.json")
	if err != nil {
		t.Fatal(err)
	}
	var registration ConsoleTunnelRegistration
	if json.Unmarshal(registrationRaw, &registration) != nil || !validConsoleRegistration(registration, time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)) || strings.Contains(strings.ToLower(string(registrationRaw)), "pveticket") || strings.Contains(strings.ToLower(string(registrationRaw)), "pveport") {
		t.Fatalf("unsafe console tunnel request golden: %s", registrationRaw)
	}
}
