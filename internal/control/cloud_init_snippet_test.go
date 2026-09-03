package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/inventory"
	"github.com/ppflight/ppflight-agent/internal/pve"
)

func snippetCommand(parameters string) Command {
	command := controlCommand("vm.cloud-init-snippet.delete", "qemu", parameters)
	command.CommandID = "command-snippet-delete"
	command.OperationID = "operation-snippet-delete"
	command.IdempotencyKey = "idempotency-snippet-delete"
	command.AgentRef = "agent-1"
	return command
}

type snippetPVEFixture struct {
	mu             sync.Mutex
	attached       bool
	present        bool
	otherCICustom  string
	sharedType     string
	digestConflict bool
	deleteUPID     string
	osType         string
	scanStatus     int
	putCount       int
	deleteCount    int
}

func (f *snippetPVEFixture) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api2/json/access/permissions":
			_, _ = w.Write([]byte(`{"data":{"/":{"VM.Audit":1,"Datastore.Audit":1}}}`))
		case "/api2/json/cluster/resources":
			if f.scanStatus != 0 {
				w.WriteHeader(f.scanStatus)
				_, _ = w.Write([]byte(`{"errors":{}}`))
				return
			}
			rows := `[{"type":"qemu","node":"pve1","vmid":101}]`
			if f.sharedType != "" {
				rows = `[{"type":"qemu","node":"pve1","vmid":101},{"type":"` + f.sharedType + `","node":"pve1","vmid":102}]`
			}
			_, _ = w.Write([]byte(`{"data":` + rows + `}`))
		case "/api2/json/nodes/pve1/qemu/101/config":
			if r.Method == http.MethodPut {
				f.putCount++
				_ = r.ParseForm()
				if r.Form.Get("digest") != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
					t.Fatalf("detach omitted config digest: %v", r.Form)
				}
				if f.digestConflict {
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write([]byte(`{"errors":{}}`))
					return
				}
				if f.otherCICustom == "" {
					if r.Form.Get("delete") != "cicustom" || r.Form.Get("cicustom") != "" {
						t.Fatalf("sole network detach form: %v", r.Form)
					}
				} else if got := r.Form.Get("cicustom"); got != f.otherCICustom {
					t.Fatalf("remaining cicustom=%q want %q", got, f.otherCICustom)
				}
				f.attached = false
				_, _ = w.Write([]byte(`{"data":null}`))
				return
			}
			custom := f.otherCICustom
			if f.attached {
				if custom != "" {
					custom += ","
				}
				custom += "network=local:snippets/example.yaml"
			}
			osType := f.osType
			if osType == "" {
				osType = "l26"
			}
			_, _ = w.Write([]byte(`{"data":{"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ostype":` + mustJSONString(t, osType) + `,"cicustom":` + mustJSONString(t, custom) + `}}`))
		case "/api2/json/nodes/pve1/qemu/102/config", "/api2/json/nodes/pve1/lxc/102/config":
			_, _ = w.Write([]byte(`{"data":{"cicustom":"network=local:snippets/example.yaml"}}`))
		case "/api2/json/nodes/pve1/storage/local/content":
			if f.present {
				_, _ = w.Write([]byte(`{"data":[{"volid":"local:snippets/example.yaml","content":"snippets"}]}`))
			} else {
				_, _ = w.Write([]byte(`{"data":[]}`))
			}
		default:
			if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api2/json/nodes/pve1/storage/local/content/") {
				f.deleteCount++
				if got := r.URL.EscapedPath(); !strings.HasSuffix(got, "/local%3Asnippets%2Fexample.yaml") {
					t.Fatalf("snippet volume was not one encoded segment: %s", got)
				}
				f.present = false
				if f.deleteUPID != "" {
					_, _ = w.Write([]byte(`{"data":` + mustJSONString(t, f.deleteUPID) + `}`))
				} else {
					_, _ = w.Write([]byte(`{"data":null}`))
				}
				return
			}
			t.Fatalf("unexpected PVE request %s %s", r.Method, r.URL.String())
		}
	})
}

func mustJSONString(t *testing.T, value string) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func executeSnippetFixture(t *testing.T, fixture *snippetPVEFixture, command Command) (Receipt, *Journal) {
	t.Helper()
	server := httptest.NewServer(fixture.handler(t))
	t.Cleanup(server.Close)
	journal, err := OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, duplicate, err := journal.Claim(command, time.Now()); err != nil || duplicate {
		t.Fatalf("claim duplicate=%t err=%v", duplicate, err)
	}
	executor := Executor{Client: controlTestClient(t, server), CloudInitSnippets: journal, Mode: "production", ProductionExecution: true}
	receipt, _ := executor.Execute(context.Background(), command, time.Now())
	if err := journal.Complete(command, receipt); err != nil {
		t.Fatal(err)
	}
	return receipt, journal
}

func snippetRecoveryService(journal *Journal, client *pve.Client, task SubmittedTask) *Service {
	assignments := inventory.NewStore(inventory.Document{Assignments: []inventory.Assignment{{
		ServiceRef: task.ServiceRef, ClusterRef: task.ClusterRef, NodeRef: task.NodeRef, VMID: task.VMID,
		Generation: uint64(task.Generation), InstanceUUID: task.InstanceUUID, GuestType: task.GuestType, BillingState: "disabled",
	}}})
	return &Service{
		journal: journal, executor: Executor{Client: client}, assignments: assignments,
		bindingID: task.BindingID, deviceID: task.DeviceID, credentialEpoch: uint64(task.CredentialEpoch),
		assignmentRevision: uint64(task.AssignmentRevision), agentRef: task.AgentRef, clusterRef: task.ClusterRef,
	}
}

func TestCloudInitSnippetDeleteSyncAndPreservesOtherComponents(t *testing.T) {
	for _, other := range []string{"", "user=local:snippets/user.yaml,vendor=local:snippets/vendor.yaml,meta=local:snippets/meta.yaml"} {
		t.Run(other, func(t *testing.T) {
			fixture := &snippetPVEFixture{attached: true, present: true, otherCICustom: other}
			receipt, _ := executeSnippetFixture(t, fixture, snippetCommand(`{"volume":"local:snippets/example.yaml","attachment":"network","deleteUnreferenced":true}`))
			if receipt.State != "succeeded" || receipt.Code != "SUCCEEDED" || string(receipt.Result) != `{"detached":true,"deleted":true,"alreadyAbsent":false}` {
				t.Fatalf("unexpected receipt: %+v result=%s", receipt, receipt.Result)
			}
			if fixture.putCount != 1 || fixture.deleteCount != 1 || fixture.attached || fixture.present {
				t.Fatalf("mutation counts/state: %+v", fixture)
			}
		})
	}
}

func TestCloudInitSnippetDeleteRejectsSharedQEMUAndLXCWithoutMutation(t *testing.T) {
	for _, guestType := range []string{"qemu", "lxc"} {
		t.Run(guestType, func(t *testing.T) {
			fixture := &snippetPVEFixture{attached: true, present: true, sharedType: guestType}
			receipt, _ := executeSnippetFixture(t, fixture, snippetCommand(`{"volume":"local:snippets/example.yaml","attachment":"network","deleteUnreferenced":true}`))
			if receipt.Code != "CLOUD_INIT_SNIPPET_SHARED" || fixture.putCount != 0 || fixture.deleteCount != 0 {
				t.Fatalf("shared reference did not fail closed: receipt=%+v fixture=%+v", receipt, fixture)
			}
		})
	}
}

func TestCloudInitSnippetDeleteRejectsReferenceMismatchAndDigestConflict(t *testing.T) {
	missing := &snippetPVEFixture{present: true}
	receipt, _ := executeSnippetFixture(t, missing, snippetCommand(`{"volume":"local:snippets/example.yaml","attachment":"network","deleteUnreferenced":true}`))
	if receipt.Code != "CLOUD_INIT_SNIPPET_REFERENCE_MISMATCH" || missing.putCount != 0 || missing.deleteCount != 0 {
		t.Fatalf("reference mismatch mutated: %+v %+v", receipt, missing)
	}

	conflict := &snippetPVEFixture{attached: true, present: true, digestConflict: true}
	receipt, _ = executeSnippetFixture(t, conflict, snippetCommand(`{"volume":"local:snippets/example.yaml","attachment":"network","deleteUnreferenced":true}`))
	if receipt.Code != "CLOUD_INIT_SNIPPET_CONFIG_CONFLICT" || conflict.deleteCount != 0 {
		t.Fatalf("digest conflict was not isolated: %+v %+v", receipt, conflict)
	}
}

func TestCloudInitSnippetDeleteStrictParameters(t *testing.T) {
	invalid := []string{
		`{"volume":"local:iso/example.iso","attachment":"network","deleteUnreferenced":true}`,
		`{"volume":"local:backup/example","attachment":"network","deleteUnreferenced":true}`,
		`{"volume":"local:snippets/../x","attachment":"network","deleteUnreferenced":true}`,
		`{"volume":"local:snippets/%2e%2e","attachment":"network","deleteUnreferenced":true}`,
		`{"volume":"local:snippets//x","attachment":"network","deleteUnreferenced":true}`,
		`{"volume":"local:snippets/example.yaml","attachment":"user","deleteUnreferenced":true}`,
		`{"volume":"local:snippets/example.yaml","attachment":"network","deleteUnreferenced":false}`,
		`{"volume":"local:snippets/example.yaml","attachment":"network"}`,
		`{"volume":"local:snippets/example.yaml","attachment":"network","deleteUnreferenced":true,"node":"pve2"}`,
		`{"volume":"local:snippets/example.yaml","volume":"local:snippets/other.yaml","attachment":"network","deleteUnreferenced":true}`,
	}
	for _, raw := range invalid {
		if err := validateParameters(snippetCommand(raw)); err == nil {
			t.Errorf("accepted unsafe parameters: %s", raw)
		}
	}
	lxc := snippetCommand(`{"volume":"local:snippets/example.yaml","attachment":"network","deleteUnreferenced":true}`)
	lxc.Identity.GuestType = "lxc"
	if err := validateParameters(lxc); err == nil {
		t.Error("accepted LXC target")
	}
}

func TestCloudInitSnippetDeleteAsyncJournalAndRecovery(t *testing.T) {
	fixture := &snippetPVEFixture{attached: true, present: true, deleteUPID: "UPID:pve1:1:2:3:delete:101:root@pam!api:"}
	command := snippetCommand(`{"volume":"local:snippets/example.yaml","attachment":"network","deleteUnreferenced":true}`)
	receipt, journal := executeSnippetFixture(t, fixture, command)
	if receipt.State != "submitted" || receipt.PVETaskUPID != "" {
		t.Fatalf("expected submitted receipt: %+v", receipt)
	}
	if receipt.Asynchronous != true {
		t.Fatalf("submitted receipt did not retain asynchronous state: %+v", receipt)
	}
	tasks, err := journal.SubmittedWaiting()
	if err != nil || len(tasks) != 1 || tasks[0].SnippetDeletePhase != snippetPhaseDeleteSubmitted {
		t.Fatalf("durable submitted task=%+v err=%v", tasks, err)
	}
	recoveryServer := httptest.NewServer(fixture.handler(t))
	defer recoveryServer.Close()
	service := snippetRecoveryService(journal, controlTestClient(t, recoveryServer), tasks[0])
	final, err := service.reconciledSnippetDeleteReceipt(context.Background(), tasks[0], TaskResolution{Status: "stopped", ExitStatus: "OK"}, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.CompleteSubmitted(tasks[0], final); err != nil {
		t.Fatal(err)
	}
	if final.State != "succeeded" || string(final.Result) != `{"detached":true,"deleted":true,"alreadyAbsent":false}` {
		t.Fatalf("unexpected reconciled receipt: %+v", final)
	}
	replayed, duplicate, err := journal.Claim(command, time.Now())
	if err != nil || !duplicate || string(replayed.Result) != string(final.Result) {
		t.Fatalf("replay duplicate=%t err=%v receipt=%+v", duplicate, err, replayed)
	}
}

func TestCloudInitSnippetDeleteCrashRecoveryAfterDetachAndDelete(t *testing.T) {
	for _, storagePresent := range []bool{true, false} {
		t.Run(map[bool]string{true: "after-detach", false: "after-delete"}[storagePresent], func(t *testing.T) {
			fixture := &snippetPVEFixture{attached: false, present: storagePresent}
			command := snippetCommand(`{"volume":"local:snippets/example.yaml","attachment":"network","deleteUnreferenced":true}`)
			server := httptest.NewServer(fixture.handler(t))
			defer server.Close()
			journal, err := OpenJournal(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = journal.Claim(command, time.Now()); err != nil {
				t.Fatal(err)
			}
			storage, digest, _ := snippetVolumeIdentity("local:snippets/example.yaml")
			if _, err = journal.BeginCloudInitSnippetDelete(command, storage, digest, time.Now()); err != nil {
				t.Fatal(err)
			}
			if err = journal.AdvanceCloudInitSnippetDelete(command, snippetPhaseReferenceProven, time.Now()); err != nil {
				t.Fatal(err)
			}
			journal, err = OpenJournal(journal.directory)
			if err != nil {
				t.Fatal(err)
			}
			executor := Executor{Client: controlTestClient(t, server), CloudInitSnippets: journal, Mode: "production", ProductionExecution: true}
			receipt, _ := executor.Execute(context.Background(), command, time.Now())
			wantAbsent := !storagePresent
			var result CloudInitSnippetDeleteResult
			_ = json.Unmarshal(receipt.Result, &result)
			if receipt.State != "succeeded" || result.AlreadyAbsent != wantAbsent || fixture.putCount != 0 {
				t.Fatalf("crash recovery failed: receipt=%+v fixture=%+v", receipt, fixture)
			}
			if storagePresent && fixture.deleteCount != 1 || !storagePresent && fixture.deleteCount != 0 {
				t.Fatalf("unsafe delete replay count=%d", fixture.deleteCount)
			}
		})
	}
}

func TestCloudInitSnippetDeleteJournalContainsNoRawVolumeOrConfig(t *testing.T) {
	fixture := &snippetPVEFixture{attached: true, present: true, otherCICustom: "user=local:snippets/private-user.yaml"}
	command := snippetCommand(`{"volume":"local:snippets/example.yaml","attachment":"network","deleteUnreferenced":true}`)
	_, journal := executeSnippetFixture(t, fixture, command)
	entries, err := os.ReadDir(journal.directory)
	if err != nil || len(entries) != 1 {
		t.Fatalf("journal entries=%d err=%v", len(entries), err)
	}
	raw, err := os.ReadFile(filepath.Join(journal.directory, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"example.yaml", "private-user.yaml", "cicustom", "local:snippets"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("journal leaked %q: %s", forbidden, raw)
		}
	}
}

func TestCloudInitSnippetDeleteCommandConflictAndNonOKTask(t *testing.T) {
	fixture := &snippetPVEFixture{attached: true, present: true, deleteUPID: "UPID:pve1:1:2:3:delete:101:root@pam!api:"}
	command := snippetCommand(`{"volume":"local:snippets/example.yaml","attachment":"network","deleteUnreferenced":true}`)
	_, journal := executeSnippetFixture(t, fixture, command)
	tasks, _ := journal.SubmittedWaiting()
	service := snippetRecoveryService(journal, nil, tasks[0])
	failed, err := service.reconciledSnippetDeleteReceipt(context.Background(), tasks[0], TaskResolution{Status: "stopped", ExitStatus: "ERROR"}, nil, time.Now())
	if err != nil || failed.State != "failed" || failed.Code != "CLOUD_INIT_SNIPPET_DELETE_FAILED" {
		t.Fatalf("non-OK task was accepted: %+v err=%v", failed, err)
	}
	conflict := command
	conflict.Parameters = json.RawMessage(`{"volume":"local:snippets/other.yaml","attachment":"network","deleteUnreferenced":true}`)
	if _, _, err := journal.Claim(conflict, time.Now()); !errors.Is(err, ErrCommandConflict) {
		t.Fatalf("different digest did not conflict: %v", err)
	}
}

func TestCloudInitSnippetDeleteGoldensAreExact(t *testing.T) {
	parameters, err := os.ReadFile("testdata/agent-v1-vm-cloud-init-snippet-delete.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateParameters(controlCommand("vm.cloud-init-snippet.delete", "qemu", string(parameters))); err != nil {
		t.Fatalf("parameters golden rejected: %v", err)
	}
	resultRaw, err := os.ReadFile("testdata/agent-v1-vm-cloud-init-snippet-delete-result.json")
	if err != nil {
		t.Fatal(err)
	}
	var result CloudInitSnippetDeleteResult
	if strictParameters(resultRaw, &result) != nil || !result.Detached || !result.Deleted || result.AlreadyAbsent {
		t.Fatalf("result golden rejected: %s", resultRaw)
	}
	canonical, _ := json.Marshal(result)
	if string(canonical) != `{"detached":true,"deleted":true,"alreadyAbsent":false}` {
		t.Fatalf("result field order/shape drifted: %s", canonical)
	}
}

func TestCloudInitSnippetDeleteFailsClosedOnWindowsOrIncompleteScan(t *testing.T) {
	for name, fixture := range map[string]*snippetPVEFixture{
		"windows":          {attached: true, present: true, osType: "win11"},
		"scan-forbidden":   {attached: true, present: true, scanStatus: http.StatusForbidden},
		"scan-unavailable": {attached: true, present: true, scanStatus: http.StatusServiceUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			receipt, _ := executeSnippetFixture(t, fixture, snippetCommand(`{"volume":"local:snippets/example.yaml","attachment":"network","deleteUnreferenced":true}`))
			if receipt.State == "succeeded" || fixture.putCount != 0 || fixture.deleteCount != 0 {
				t.Fatalf("unsafe target/scan mutated: receipt=%+v fixture=%+v", receipt, fixture)
			}
		})
	}
}

func TestCloudInitSnippetDeleteWaitingAndIndeterminateDoNotResubmit(t *testing.T) {
	fixture := &snippetPVEFixture{attached: true, present: true, deleteUPID: "UPID:pve1:1:2:3:delete:101:root@pam!api:"}
	command := snippetCommand(`{"volume":"local:snippets/example.yaml","attachment":"network","deleteUnreferenced":true}`)
	_, journal := executeSnippetFixture(t, fixture, command)
	tasks, _ := journal.SubmittedWaiting()
	service := snippetRecoveryService(journal, nil, tasks[0])
	for name, test := range map[string]struct {
		resolution TaskResolution
		err        error
		code       string
	}{
		"running":        {resolution: TaskResolution{Status: "running"}, code: "PVE_TASK_WAITING"},
		"status-unknown": {err: context.DeadlineExceeded, code: "CLOUD_INIT_SNIPPET_DELETE_INDETERMINATE"},
	} {
		t.Run(name, func(t *testing.T) {
			receipt, err := service.reconciledSnippetDeleteReceipt(context.Background(), tasks[0], test.resolution, test.err, time.Now())
			if err != nil || receipt.State != "waiting" || receipt.Code != test.code || receipt.PVETaskUPID != "" || fixture.deleteCount != 1 {
				t.Fatalf("unsafe reconcile: receipt=%+v err=%v deletes=%d", receipt, err, fixture.deleteCount)
			}
		})
	}
	service.bindingID = "changed-binding"
	receipt, err := service.reconciledSnippetDeleteReceipt(context.Background(), tasks[0], TaskResolution{Status: "stopped", ExitStatus: "OK"}, nil, time.Now())
	if err != nil || receipt.State != "indeterminate" || receipt.Code != "CLOUD_INIT_SNIPPET_DELETE_INDETERMINATE" || fixture.deleteCount != 1 {
		t.Fatalf("changed authority was not quarantined: receipt=%+v err=%v", receipt, err)
	}
}

func TestCloudInitSnippetDeletePhasesAndAuthorityAreBound(t *testing.T) {
	want := []string{"validated", "reference_proven", "detached", "delete_submitted", "deleted", "verified", "succeeded"}
	if got := sortedSnippetPhases(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("phase order=%v want=%v", got, want)
	}
	journal, err := OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	command := snippetCommand(`{"volume":"local:snippets/example.yaml","attachment":"network","deleteUnreferenced":true}`)
	if _, _, err = journal.Claim(command, time.Now()); err != nil {
		t.Fatal(err)
	}
	storage, digest, _ := snippetVolumeIdentity("local:snippets/example.yaml")
	if _, err = journal.BeginCloudInitSnippetDelete(command, storage, digest, time.Now()); err != nil {
		t.Fatal(err)
	}
	changed := command
	changed.Identity.Generation++
	if err = journal.AdvanceCloudInitSnippetDelete(changed, snippetPhaseReferenceProven, time.Now()); !errors.Is(err, ErrCommandConflict) {
		t.Fatalf("changed generation advanced durable phase: %v", err)
	}
}
