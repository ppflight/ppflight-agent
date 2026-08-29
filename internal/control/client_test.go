package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/protocol"
	"github.com/ppflight/ppflight-agent/internal/store"
	"github.com/ppflight/ppflight-agent/internal/uploader"
)

func TestClientSignsExactPollQuery(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("agentRef") != "agent-1" || r.URL.Query().Get("after") != "cursor-1" || r.URL.Query().Get("limit") != "7" {
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
	client, err := NewClient(ClientConfig{Endpoint: server.URL, AgentRef: "agent-1", Limit: 7, AuthMode: uploader.AuthHMACSHA256, KeyID: "key-1", Secret: []byte("secret"), Now: func() time.Time { return now }, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Poll(context.Background(), "cursor-1")
	if err != nil || result.Cursor != "cursor-2" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

type fixedPoller struct{ response PollResponse }

func (p fixedPoller) Poll(context.Context, string) (PollResponse, error) { return p.response, nil }

type memoryReceiptQueue struct{ payloads [][]byte }

func (q *memoryReceiptQueue) Enqueue(_ string, payload []byte) (store.Item, bool, error) {
	q.payloads = append(q.payloads, append([]byte(nil), payload...))
	return store.Item{}, true, nil
}

func TestServiceDryRunJournalsAndQueuesReceipt(t *testing.T) {
	now := time.Now().UTC()
	command, assignments := signedCommand(t, now)
	queue := &memoryReceiptQueue{}
	directory := t.TempDir()
	journal, err := OpenJournal(directory + "/journal")
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(ServiceConfig{
		AgentRef: "agent-1", ClusterRef: "cluster-1", Mode: "test", CommandSecret: []byte("secret"),
		AllowedActions: []string{"vm.start"}, Assignments: assignments,
		Poller:  fixedPoller{PollResponse{SchemaVersion: 1, Cursor: "cursor-1", Commands: []Command{command}}},
		Journal: journal, Executor: Executor{Mode: "test"}, ReceiptQueue: queue, CursorFile: directory + "/cursor.json", Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	processed, err := service.PollOnce(context.Background())
	if err != nil || processed != 1 || len(queue.payloads) != 1 {
		t.Fatalf("processed=%d payloads=%d err=%v", processed, len(queue.payloads), err)
	}
	var receipt Receipt
	if err := json.Unmarshal(queue.payloads[0], &receipt); err != nil || receipt.Code != "DRY_RUN" || !receipt.DryRun {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
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
