package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/auditlog"
	"github.com/ppflight/ppflight-agent/internal/inventory"
	"github.com/ppflight/ppflight-agent/internal/protocol"
	"github.com/ppflight/ppflight-agent/internal/store"
	"github.com/ppflight/ppflight-agent/internal/uploader"
)

func TestClientSignsExactPollQuery(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("agentRef") != "agent-1" || r.URL.Query().Get("after") != "cursor-1" || r.URL.Query().Get("limit") != "1" || r.URL.Query().Get("wait") != "25" {
			t.Fatalf("unexpected query: %s", r.URL.RawQuery)
		}
		if err := protocol.VerifyRequest(r, nil, func(keyID string) ([]byte, error) {
			if keyID != "key-1" {
				t.Fatalf("key id=%q", keyID)
			}
			return []byte("secret"), nil
		}, protocol.VerifyOptions{Now: now}); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(PollResponse{SchemaVersion: 1, Cursor: "cursor-2", Commands: []Command{}})
	}))
	defer server.Close()
	client, err := NewClient(ClientConfig{Endpoint: server.URL, AgentRef: "agent-1", Limit: 1, AuthMode: uploader.AuthHMACSHA256, KeyID: "key-1", Secret: []byte("secret"), Now: func() time.Time { return now }, HTTPClient: server.Client(), ServerIPv4Allowlist: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Poll(context.Background(), "cursor-1")
	if err != nil || result.Cursor != "cursor-2" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestClientRejectsBatchClaimsAndTimeoutsThatCannotCarryTheWait(t *testing.T) {
	if _, err := NewClient(ClientConfig{Endpoint: "https://127.0.0.1:8443/commands", AgentRef: "agent-1", Limit: 2, AuthMode: uploader.AuthNone}); err == nil {
		t.Fatal("batch claim limit was accepted")
	}
	if _, err := NewClient(ClientConfig{Endpoint: "https://127.0.0.1:8443/commands", AgentRef: "agent-1", Limit: 1, Wait: 25 * time.Second, Timeout: 25 * time.Second, AuthMode: uploader.AuthNone}); err == nil {
		t.Fatal("timeout without long-poll headroom was accepted")
	}
}

type fixedPoller struct{ response PollResponse }

func (p fixedPoller) Poll(context.Context, string) (PollResponse, error) { return p.response, nil }

type memoryReceiptQueue struct{ payloads [][]byte }

func (q *memoryReceiptQueue) Enqueue(_ string, payload []byte) (store.Item, bool, error) {
	q.payloads = append(q.payloads, append([]byte(nil), payload...))
	return store.Item{}, true, nil
}

type memoryAuditSink struct{ events []auditlog.Event }

func (s *memoryAuditSink) Enqueue(event auditlog.Event) error {
	s.events = append(s.events, event)
	return nil
}

func TestServiceDryRunJournalsAndQueuesReceipt(t *testing.T) {
	now := time.Now().UTC()
	command, assignments := signedCommand(t, now)
	queue := &memoryReceiptQueue{}
	audit := &memoryAuditSink{}
	directory := t.TempDir()
	journal, err := OpenJournal(directory + "/journal")
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(ServiceConfig{
		AgentRef: "agent-1", ClusterRef: "cluster-1", Mode: "test", CommandSecret: []byte("secret"),
		AllowedActions: []string{"vm.start"}, Assignments: assignments,
		Poller:  fixedPoller{PollResponse{SchemaVersion: 1, Cursor: "cursor-1", Commands: []Command{command}}},
		Journal: journal, Executor: Executor{Mode: "test"}, ReceiptQueue: queue, AuditSink: audit, AgentVersion: "test-version",
		CursorFile: directory + "/cursor.json", Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	processed, err := service.PollOnce(context.Background())
	if err != nil || processed != 1 || len(queue.payloads) != 1 || len(audit.events) != 1 {
		t.Fatalf("processed=%d payloads=%d err=%v", processed, len(queue.payloads), err)
	}
	var receipt Receipt
	if err := json.Unmarshal(queue.payloads[0], &receipt); err != nil || receipt.Code != "DRY_RUN" || !receipt.DryRun {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
}

func TestServiceLegacyAuthorityReadsRefreshedRevisionUntilDynamicSwitch(t *testing.T) {
	now := time.Now().UTC()
	command, assignments := signedCommand(t, now)
	command.AssignmentRevision = 8
	command.Signature = SignCommand(command, []byte("secret"))
	revision := uint64(7)
	queue := &memoryReceiptQueue{}
	directory := t.TempDir()
	journal, err := OpenJournal(directory + "/journal")
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(ServiceConfig{
		AgentRef: "agent-1", ClusterRef: "cluster-1", Mode: "test", CommandSecret: []byte("secret"),
		BindingID: command.BindingID, DeviceID: command.DeviceID, CredentialEpoch: uint64(command.CredentialEpoch),
		AssignmentRevision: func() uint64 { return revision },
		AllowedActions:     []string{"vm.start"}, Assignments: assignments,
		Poller:  fixedPoller{PollResponse{SchemaVersion: 1, Cursor: "cursor-1", Commands: []Command{command}}},
		Journal: journal, Executor: Executor{Mode: "test"}, ReceiptQueue: queue, AuditSink: &memoryAuditSink{}, AgentVersion: "test-version",
		CursorFile: directory + "/cursor.json", Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	revision = 8
	processed, err := service.PollOnce(context.Background())
	if err != nil || processed != 1 || len(queue.payloads) != 1 {
		t.Fatalf("processed=%d payloads=%d err=%v", processed, len(queue.payloads), err)
	}
	var receipt Receipt
	if err := json.Unmarshal(queue.payloads[0], &receipt); err != nil || receipt.Code != "DRY_RUN" {
		t.Fatalf("legacy refreshed revision was not used: receipt=%#v err=%v", receipt, err)
	}
}

func TestServiceSetNetworkPolicyRejectionCodesAreStableAndDoNotLeakAuthority(t *testing.T) {
	now := time.Now().UTC()
	newCommand := func(parameters string, revision uint64) (Command, *inventory.Store) {
		command, assignments := signedCommand(t, now)
		command.Action = "vm.set-network"
		command.AssignmentRevision = protocol.Counter(revision)
		command.Parameters = json.RawMessage(parameters)
		command.ApprovalRef = "approval-network-1"
		command.BodySHA256 = protocolHash(command.Parameters)
		command.Signature = SignCommand(command, []byte("secret"))
		return command, assignments
	}
	newService := func(t *testing.T, command Command, assignments *inventory.Store, allowed []string, revision uint64) (*memoryReceiptQueue, error) {
		t.Helper()
		directory := t.TempDir()
		journal, err := OpenJournal(directory + "/journal")
		if err != nil {
			return nil, err
		}
		queue := &memoryReceiptQueue{}
		service, err := NewService(ServiceConfig{
			AgentRef: "agent-1", ClusterRef: "cluster-1", Mode: "test", CommandSecret: []byte("secret"),
			BindingID: command.BindingID, DeviceID: command.DeviceID, CredentialEpoch: uint64(command.CredentialEpoch),
			AssignmentRevision: func() uint64 { return revision }, AllowedActions: allowed, Assignments: assignments,
			Poller:  fixedPoller{PollResponse{SchemaVersion: 1, Cursor: "cursor-1", Commands: []Command{command}}},
			Journal: journal, Executor: Executor{Mode: "test"}, ReceiptQueue: queue, AuditSink: &memoryAuditSink{}, AgentVersion: "test-version",
			CursorFile: directory + "/cursor.json", Now: func() time.Time { return now },
		})
		if err != nil {
			return nil, err
		}
		if processed, err := service.PollOnce(context.Background()); err != nil || processed != 1 {
			return nil, fmt.Errorf("processed=%d: %w", processed, err)
		}
		return queue, nil
	}
	readCode := func(t *testing.T, queue *memoryReceiptQueue) string {
		t.Helper()
		if len(queue.payloads) != 1 {
			t.Fatalf("receipt count=%d", len(queue.payloads))
		}
		var receipt Receipt
		if err := json.Unmarshal(queue.payloads[0], &receipt); err != nil {
			t.Fatal(err)
		}
		return receipt.Code
	}

	t.Run("legal signed command uses the runtime authority", func(t *testing.T) {
		command, assignments := newCommand(`{"interface":"net0","bridge":"vmbr1"}`, 7)
		queue, err := newService(t, command, assignments, []string{"vm.set-network"}, 7)
		if err != nil {
			t.Fatal(err)
		}
		if code := readCode(t, queue); code != "DRY_RUN" {
			t.Fatalf("legal vm.set-network receipt code=%q", code)
		}
	})

	t.Run("runtime action authority is reported without its contents", func(t *testing.T) {
		command, assignments := newCommand(`{"interface":"net0","bridge":"vmbr1"}`, 7)
		queue, err := newService(t, command, assignments, []string{"vm.start"}, 7)
		if err != nil {
			t.Fatal(err)
		}
		if code := readCode(t, queue); code != "COMMAND_ACTION_NOT_ALLOWED" {
			t.Fatalf("action authority receipt code=%q", code)
		}
	})

	t.Run("illegal parameters do not collapse to COMMAND_REJECTED", func(t *testing.T) {
		command, assignments := newCommand(`{"interface":"net0","macAddress":"AA:BB:CC:DD:EE:00"}`, 7)
		queue, err := newService(t, command, assignments, []string{"vm.set-network"}, 7)
		if err != nil {
			t.Fatal(err)
		}
		if code := readCode(t, queue); code != "INVALID_PARAMETERS" {
			t.Fatalf("illegal vm.set-network receipt code=%q", code)
		}
	})
}

func TestProductionServiceReportsBoundedPreAuthenticationRejectionCodes(t *testing.T) {
	now := time.Now().UTC()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	otherPrivateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))

	tests := []struct {
		name string
		want string
		edit func(*Command)
	}{
		{name: "body hash", want: "COMMAND_BODY_HASH_INVALID", edit: func(command *Command) {
			command.BodySHA256 = strings.Repeat("0", 64)
			command.Signature, _ = SignCommandEd25519(*command, privateKey)
		}},
		{name: "signing key", want: "COMMAND_SIGNING_KEY_MISMATCH", edit: func(command *Command) {
			command.SigningKeyID = "website-key-2"
			command.Signature, _ = SignCommandEd25519(*command, privateKey)
		}},
		{name: "signature", want: "COMMAND_SIGNATURE_INVALID", edit: func(command *Command) {
			command.Signature, _ = SignCommandEd25519(*command, otherPrivateKey)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			command, assignments := signedCommand(t, now)
			command.SigningKeyID = "website-key-1"
			command.Signature, _ = SignCommandEd25519(command, privateKey)
			tt.edit(&command)
			queue := &memoryReceiptQueue{}
			audit := &memoryAuditSink{}
			directory := t.TempDir()
			journal, err := OpenJournal(directory + "/journal")
			if err != nil {
				t.Fatal(err)
			}
			service, err := NewService(ServiceConfig{
				AgentRef: "agent-1", ClusterRef: "cluster-1", Mode: "production",
				BindingID: command.BindingID, DeviceID: command.DeviceID, CredentialEpoch: uint64(command.CredentialEpoch),
				AssignmentRevision:  func() uint64 { return uint64(command.AssignmentRevision) },
				CommandSigningKeyID: "website-key-1", CommandPublicKey: publicKey,
				AllowedActions: []string{command.Action}, Assignments: assignments,
				Poller:  fixedPoller{PollResponse{SchemaVersion: 1, Cursor: "cursor-1", Commands: []Command{command}}},
				Journal: journal, Executor: Executor{Mode: "production"}, ReceiptQueue: queue, AuditSink: audit,
				AgentVersion: "0.1.1-rc.4", CursorFile: directory + "/cursor.json", Now: func() time.Time { return now },
			})
			if err != nil {
				t.Fatal(err)
			}
			if processed, err := service.PollOnce(context.Background()); err != nil || processed != 1 {
				t.Fatalf("processed=%d err=%v", processed, err)
			}
			if len(queue.payloads) != 1 {
				t.Fatalf("receipt count=%d", len(queue.payloads))
			}
			if len(audit.events) != 0 {
				t.Fatalf("unauthenticated rejection produced %d audit events", len(audit.events))
			}
			var receipt Receipt
			if err := json.Unmarshal(queue.payloads[0], &receipt); err != nil || receipt.Code != tt.want {
				t.Fatalf("receipt=%#v err=%v", receipt, err)
			}
		})
	}
}

func TestProductionServiceQueuesRunningReceiptBeforeMutationResult(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	command, assignments := signedCommand(t, now)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	command.SigningKeyID = "website-key-1"
	command.Signature, _ = SignCommandEd25519(command, privateKey)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api2/json/nodes/pve-1/qemu/101/status/start" {
			t.Fatalf("unexpected mutation %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"data":"UPID:pve-1:1:2:3:qmstart:101:root@pam:"}`))
	}))
	defer server.Close()
	directory := t.TempDir()
	journal, err := OpenJournal(directory + "/journal")
	if err != nil {
		t.Fatal(err)
	}
	queue := &memoryReceiptQueue{}
	service, err := NewService(ServiceConfig{
		AgentRef: "agent-1", ClusterRef: "cluster-1", Mode: "production",
		BindingID: command.BindingID, DeviceID: command.DeviceID, CredentialEpoch: uint64(command.CredentialEpoch),
		AssignmentRevision:  func() uint64 { return uint64(command.AssignmentRevision) },
		CommandSigningKeyID: "website-key-1", CommandPublicKey: publicKey,
		AllowedActions: []string{command.Action}, Assignments: assignments,
		Poller:  fixedPoller{PollResponse{SchemaVersion: 1, Cursor: "cursor-1", Commands: []Command{command}}},
		Journal: journal, Executor: Executor{Client: controlTestClient(t, server), Mode: "production", ProductionExecution: true},
		ReceiptQueue: queue, AuditSink: &memoryAuditSink{}, AgentVersion: "test-version",
		CursorFile: directory + "/cursor.json", Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if processed, pollErr := service.PollOnce(context.Background()); pollErr != nil || processed != 1 {
		t.Fatalf("processed=%d err=%v", processed, pollErr)
	}
	if len(queue.payloads) != 2 {
		t.Fatalf("receipt count=%d", len(queue.payloads))
	}
	var running, terminal Receipt
	if err := json.Unmarshal(queue.payloads[0], &running); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(queue.payloads[1], &terminal); err != nil {
		t.Fatal(err)
	}
	if running.State != "running" || running.Code != "COMMAND_STARTED" || !running.Accepted || !running.Asynchronous || terminal.State != "submitted" || terminal.Code != "PVE_TASK_SUBMITTED" {
		t.Fatalf("running=%#v terminal=%#v", running, terminal)
	}
}

func TestProductionServiceStartsAtRevisionZeroForFirstSignedRefresh(t *testing.T) {
	_, assignments := signedCommand(t, time.Now().UTC())
	directory := t.TempDir()
	journal, err := OpenJournal(directory + "/journal")
	if err != nil {
		t.Fatal(err)
	}
	publicKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	service, err := NewService(ServiceConfig{
		AgentRef: "agent-1", ClusterRef: "cluster-1", Mode: "production",
		BindingID: "11111111-1111-4111-8111-111111111111", DeviceID: "device-1", CredentialEpoch: 3,
		AssignmentRevision:  func() uint64 { return 0 },
		CommandSigningKeyID: "key-1", CommandPublicKey: publicKey,
		AllowedActions: []string{"vm.start"}, Assignments: assignments,
		Poller: fixedPoller{PollResponse{SchemaVersion: 1, Cursor: "cursor-1"}}, Journal: journal,
		Executor: Executor{Mode: "production"}, ReceiptQueue: &memoryReceiptQueue{}, CursorFile: directory + "/cursor.json",
	})
	if err != nil || service == nil {
		t.Fatalf("revision-zero startup must allow the first signed refresh: service=%#v err=%v", service, err)
	}
}

func TestReplaceRatePreservesNetworkConfiguration(t *testing.T) {
	value, err := replaceRate("virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=1,rate=180", "5")
	if err != nil || value != "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=1,rate=5" {
		t.Fatalf("value=%q err=%v", value, err)
	}
	value, err = replaceRate(value, "0")
	if err != nil || value != "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=1" {
		t.Fatalf("value=%q err=%v", value, err)
	}
}
