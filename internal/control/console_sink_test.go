package control

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/protocol"
)

func TestConsoleSinkUsesFixedSignedEndpointAndStrictResponse(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	now := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.URL.Path != "/api/control/console-sessions" || r.Header.Get("Idempotency-Key") != "command-1" {
			t.Fatalf("request=%s %s headers=%v", r.Method, r.URL.Path, r.Header)
		}
		if err := protocol.VerifyRequest(r, body, func(keyID string) ([]byte, error) {
			if keyID != "key-1" {
				t.Fatalf("keyId=%s", keyID)
			}
			return key, nil
		}, protocol.VerifyOptions{Now: now}); err != nil {
			t.Fatalf("signature: %v", err)
		}
		var secret ConsoleSessionSecret
		if json.Unmarshal(body, &secret) != nil || secret.PVETicket != "one-use-ticket" {
			t.Fatal("missing typed console secret")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sessionRef":"session-1","path":"/console/session/session-1","expiresAt":"2026-09-02T00:01:00Z","oneTime":true}`))
	}))
	defer server.Close()
	endpoint, _ := url.Parse(server.URL + "/api/control/console-sessions")
	sink := &HTTPSConsoleSessionSink{endpoint: endpoint, client: server.Client(), keyID: "key-1", secret: key, now: func() time.Time { return now }}
	result, err := sink.Publish(context.Background(), ConsoleSessionSecret{SessionRef: "session-1", CommandID: "command-1", IdempotencyKey: "command-1", PVETicket: "one-use-ticket"})
	if err != nil || result.SessionRef != "session-1" || !result.OneTime {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestConsoleSinkConstructorDerivesSiblingEndpointAndRejectsRedirects(t *testing.T) {
	sink, err := NewHTTPSConsoleSessionSink("https://www.example/api/control/receipts", "key-1", []byte("0123456789abcdef"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if sink.endpoint.String() != "https://www.example/api/control/console-sessions" || sink.client.CheckRedirect == nil {
		t.Fatalf("sink=%#v", sink)
	}
	request, _ := http.NewRequest(http.MethodGet, "https://other.example", nil)
	if sink.client.CheckRedirect(request, nil) == nil {
		t.Fatal("console redirect was accepted")
	}
}
