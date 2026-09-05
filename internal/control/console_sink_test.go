package control

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/ppflight/ppflight-agent/internal/protocol"
)

func consoleRegistration(now time.Time) ConsoleTunnelRegistration {
	return ConsoleTunnelRegistration{
		SchemaVersion: 1, Transport: "agent-reverse-wss-v1", SessionRef: "session-1",
		CommandID: "command-1", IdempotencyKey: "command-1-idempotency", OperationID: "operation-1",
		BindingID: "11111111-1111-4111-8111-111111111111", DeviceID: "device-1", CredentialEpoch: 2,
		AssignmentRevision: 7, AgentRef: "agent-1", ClusterRef: "cluster-1", NodeRef: "pve1",
		ServiceRef: "service-1", InstanceUUID: "instance-1", Generation: 3, GuestType: "qemu", VMID: 101,
		ExpiresAt: now.Add(60 * time.Second), OneTime: true,
	}
}

func startFakeVNC(t *testing.T, ticket []byte, payload []byte) (int, <-chan error, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer connection.Close()
		if _, err = connection.Write([]byte("RFB 003.008\n")); err != nil {
			done <- err
			return
		}
		version := make([]byte, 12)
		if _, err = io.ReadFull(connection, version); err != nil || string(version) != "RFB 003.008\n" {
			done <- err
			return
		}
		if _, err = connection.Write([]byte{1, 2}); err != nil {
			done <- err
			return
		}
		choice := make([]byte, 1)
		if _, err = io.ReadFull(connection, choice); err != nil || choice[0] != 2 {
			done <- err
			return
		}
		challenge := []byte("0123456789abcdef")
		if _, err = connection.Write(challenge); err != nil {
			done <- err
			return
		}
		response := make([]byte, 16)
		if _, err = io.ReadFull(connection, response); err != nil || bytes.Equal(response, challenge) || len(ticket) == 0 {
			done <- err
			return
		}
		if err = binary.Write(connection, binary.BigEndian, uint32(0)); err != nil {
			done <- err
			return
		}
		shared := make([]byte, 1)
		if _, err = io.ReadFull(connection, shared); err != nil {
			done <- err
			return
		}
		if _, err = connection.Write(payload); err != nil {
			done <- err
			return
		}
		reply := make([]byte, 6)
		_, err = io.ReadFull(connection, reply)
		if err == nil && string(reply) != "CLIENT" {
			err = io.ErrUnexpectedEOF
		}
		done <- err
	}()
	return listener.Addr().(*net.TCPAddr).Port, done, func() { _ = listener.Close() }
}

func TestConsoleReverseTunnelAuthenticatesLocallyAndForwardsBytes(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	now := time.Now().UTC().Truncate(time.Second)
	registration := consoleRegistration(now)
	ticket := []byte("ephemeral-pve-ticket")
	port, pveDone, closePVE := startFakeVNC(t, ticket, []byte("SERVER"))
	defer closePVE()
	browserDone := make(chan error, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/control/console-sessions":
			body, _ := io.ReadAll(r.Body)
			if err := protocol.VerifyRequest(r, body, func(keyID string) ([]byte, error) { return key, nil }, protocol.VerifyOptions{Now: now}); err != nil {
				t.Errorf("registration signature: %v", err)
			}
			if bytes.Contains(body, ticket) || bytes.Contains(body, []byte("pvePort")) || bytes.Contains(body, []byte("pveTicket")) {
				t.Errorf("PVE secret or localhost detail leaked to broker: %s", body)
			}
			var got ConsoleTunnelRegistration
			if err := json.Unmarshal(body, &got); err != nil || got != registration {
				t.Errorf("registration=%#v err=%v", got, err)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(ConsoleSessionPublication{SessionRef: registration.SessionRef, State: "ready", ExpiresAt: registration.ExpiresAt, BrowserPath: "/api/console/opaque-1"})
		case r.Method == http.MethodGet && r.URL.Path == "/api/control/console-sessions/session-1/agent-tunnel":
			if err := protocol.VerifyRequest(r, nil, func(keyID string) ([]byte, error) { return key, nil }, protocol.VerifyOptions{Now: now}); err != nil {
				t.Errorf("tunnel signature: %v", err)
			}
			connection, err := websocket.Accept(w, r, nil)
			if err != nil {
				browserDone <- err
				return
			}
			stream := websocket.NetConn(context.Background(), connection, websocket.MessageBinary)
			defer stream.Close()
			version := make([]byte, 12)
			if _, err = io.ReadFull(stream, version); err == nil {
				_, err = stream.Write([]byte("RFB 003.008\n"))
			}
			security := make([]byte, 2)
			if err == nil {
				_, err = io.ReadFull(stream, security)
			}
			if err == nil && !bytes.Equal(security, []byte{1, 1}) {
				err = io.ErrUnexpectedEOF
			}
			if err == nil {
				_, err = stream.Write([]byte{1})
			}
			var status uint32
			if err == nil {
				err = binary.Read(stream, binary.BigEndian, &status)
			}
			if err == nil {
				_, err = stream.Write([]byte{1})
			}
			payload := make([]byte, 6)
			if err == nil {
				_, err = io.ReadFull(stream, payload)
			}
			if err == nil && string(payload) != "SERVER" {
				err = io.ErrUnexpectedEOF
			}
			if err == nil {
				_, err = stream.Write([]byte("CLIENT"))
			}
			browserDone <- err
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	endpoint, _ := url.Parse(server.URL + "/api/control/console-sessions")
	sink := &HTTPSConsoleSessionSink{endpoint: endpoint, client: server.Client(), tunnelClient: server.Client(), keyID: "key-1", secret: key, now: func() time.Time { return now }, active: make(map[string]*activeConsoleSession)}
	publication, err := sink.Publish(context.Background(), registration, ConsoleLocalEndpoint{Port: port, Ticket: ticket})
	if err != nil || publication.State != "ready" || publication.BrowserPath != "/api/console/opaque-1" {
		t.Fatalf("publication=%#v err=%v", publication, err)
	}
	select {
	case err := <-browserDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("browser tunnel did not finish")
	}
	select {
	case err := <-pveDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("local PVE socket was not completed")
	}
	if bytes.Contains(ticket, []byte("ticket")) {
		t.Fatal("ephemeral ticket was not zeroed")
	}
}

func TestConsoleSinkConstructorDerivesSameOriginWSSAndForbidsProxyRedirect(t *testing.T) {
	sink, err := NewHTTPSConsoleSessionSink("https://www.example/api/control/receipts", "key-1", []byte("0123456789abcdef"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if sink.endpoint.String() != "https://www.example/api/control/console-sessions" || sink.client.CheckRedirect == nil || sink.tunnelClient.CheckRedirect == nil {
		t.Fatalf("sink=%#v", sink)
	}
	transport, ok := sink.tunnelClient.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.DialContext == nil || transport.TLSClientConfig == nil || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("unsafe tunnel transport=%#v", sink.tunnelClient.Transport)
	}
	request, _ := http.NewRequest(http.MethodGet, "https://other.example", nil)
	if sink.client.CheckRedirect(request, nil) == nil {
		t.Fatal("console redirect was accepted")
	}
	if _, err := NewHTTPSConsoleSessionSink("https://[2001:db8::1]/api/control/receipts", "key-1", []byte("0123456789abcdef"), time.Second); err == nil {
		t.Fatal("literal IPv6 console broker was accepted")
	}
}

func TestConsoleSinkReservesConfiguredCapacityBeforeOpeningPVEConnections(t *testing.T) {
	sink, err := NewHTTPSConsoleSessionSinkWithLimit("https://www.example/api/control/receipts", "key-1", []byte("0123456789abcdef"), time.Second, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Reserve("session-1"); err != nil {
		t.Fatal(err)
	}
	if err := sink.Reserve("session-2"); err == nil || err.Error() != "active console session limit reached" {
		t.Fatalf("second reservation error=%v", err)
	}
	sink.Release("session-1")
	if err := sink.Reserve("session-2"); err != nil {
		t.Fatalf("released console slot was not reusable: %v", err)
	}
	if _, err := NewHTTPSConsoleSessionSinkWithLimit("https://www.example/api/control/receipts", "key-1", []byte("0123456789abcdef"), time.Second, 65); err == nil {
		t.Fatal("unsafe console capacity was accepted")
	}
}

func TestConsoleSinkNotifiesWebsiteWhenTunnelCloses(t *testing.T) {
	now := time.Now().UTC()
	registration := consoleRegistration(now)
	notified := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/control/console-sessions/"+registration.SessionRef+"/revoke" {
			t.Errorf("close notification=%s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		notified <- struct{}{}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	endpoint, _ := url.Parse(server.URL + "/api/control/console-sessions")
	sink := &HTTPSConsoleSessionSink{endpoint: endpoint, client: server.Client(), keyID: "key-1", secret: []byte("0123456789abcdef"), now: func() time.Time { return now }, active: make(map[string]*activeConsoleSession), reserved: make(map[string]struct{}), maxActive: 1}
	sink.notifyClosed(registration)
	select {
	case <-notified:
	case <-time.After(time.Second):
		t.Fatal("closed tunnel did not notify website")
	}
}

func TestConsolePublishRejectsDuplicateSessionBeforeOpeningAnotherSocket(t *testing.T) {
	now := time.Now().UTC()
	registration := consoleRegistration(now)
	sink := &HTTPSConsoleSessionSink{
		endpoint: &url.URL{Scheme: "https", Host: "example.test", Path: "/console-sessions"},
		client:   &http.Client{}, now: func() time.Time { return now },
		active: map[string]*activeConsoleSession{registration.SessionRef: {}},
	}
	ticket := []byte("must-be-zeroed")
	if _, err := sink.Publish(context.Background(), registration, ConsoleLocalEndpoint{Port: 5901, Ticket: ticket}); err == nil {
		t.Fatal("duplicate console session was accepted")
	}
	if bytes.Contains(ticket, []byte("zeroed")) || len(sink.active) != 1 {
		t.Fatal("duplicate rejection retained ticket or changed active session")
	}
}

func TestConsoleWebsiteFailureClosesAuthenticatedLocalSocket(t *testing.T) {
	now := time.Now().UTC()
	registration := consoleRegistration(now)
	ticket := []byte("ephemeral-pve-ticket")
	port, pveDone, closePVE := startFakeVNC(t, ticket, nil)
	defer closePVE()
	endpoint, _ := url.Parse("https://127.0.0.1:1/api/control/console-sessions")
	sink := &HTTPSConsoleSessionSink{endpoint: endpoint, client: &http.Client{Timeout: 100 * time.Millisecond}, keyID: "key-1", secret: []byte("0123456789abcdef"), now: func() time.Time { return now }, active: make(map[string]*activeConsoleSession)}
	if _, err := sink.Publish(context.Background(), registration, ConsoleLocalEndpoint{Port: port, Ticket: ticket}); err == nil {
		t.Fatal("unreachable website accepted console session")
	}
	select {
	case err := <-pveDone:
		if err == nil {
			t.Fatal("local PVE session completed instead of being closed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("website failure leaked local PVE socket")
	}
}

func TestConsoleBrokerRejectionReturnsOnlyBoundedHTTPAndErrorCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"error":{"code":"invalid_request","message":"secret provider detail"}}`))
	}))
	defer server.Close()
	sink := &HTTPSConsoleSessionSink{client: server.Client(), keyID: "key-1", secret: []byte("0123456789abcdef"), now: func() time.Time { return time.Now().UTC() }}
	err := sink.do(context.Background(), http.MethodPost, server.URL, "idempotency-1", map[string]any{"schemaVersion": 1}, nil)
	if err == nil || err.Error() != "console broker rejected request: HTTP 422 (invalid_request)" {
		t.Fatalf("unexpected broker rejection: %v", err)
	}
	if strings.Contains(err.Error(), "secret provider detail") {
		t.Fatal("broker rejection reflected a free-form response message")
	}
}

func TestConsoleBrokerRejectionDropsUnsafeErrorCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":{"code":"unsafe code: credential=secret"}}`))
	}))
	defer server.Close()
	sink := &HTTPSConsoleSessionSink{client: server.Client(), keyID: "key-1", secret: []byte("0123456789abcdef"), now: func() time.Time { return time.Now().UTC() }}
	err := sink.do(context.Background(), http.MethodPost, server.URL, "idempotency-1", map[string]any{"schemaVersion": 1}, nil)
	if err == nil || err.Error() != "console broker rejected request: HTTP 409" {
		t.Fatalf("unsafe broker error code was retained: %v", err)
	}
}

func TestConsoleSessionExpiryClosesLocalPVEAndWSS(t *testing.T) {
	now := time.Now().UTC()
	registration := consoleRegistration(now)
	registration.ExpiresAt = now.Add(300 * time.Millisecond)
	ticket := []byte("ephemeral-pve-ticket")
	port, pveDone, closePVE := startFakeVNC(t, ticket, nil)
	defer closePVE()
	wssClosed := make(chan struct{}, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(ConsoleSessionPublication{SessionRef: registration.SessionRef, State: "ready", ExpiresAt: registration.ExpiresAt, BrowserPath: "/api/console/opaque-expiring"})
		case r.Method == http.MethodGet:
			connection, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			stream := websocket.NetConn(context.Background(), connection, websocket.MessageBinary)
			defer func() {
				_ = stream.Close()
				wssClosed <- struct{}{}
			}()
			_, _ = io.Copy(io.Discard, stream)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	endpoint, _ := url.Parse(server.URL + "/console-sessions")
	sink := &HTTPSConsoleSessionSink{endpoint: endpoint, client: server.Client(), tunnelClient: server.Client(), keyID: "key-1", secret: []byte("0123456789abcdef"), now: func() time.Time { return now }, active: make(map[string]*activeConsoleSession)}
	if _, err := sink.Publish(context.Background(), registration, ConsoleLocalEndpoint{Port: port, Ticket: ticket}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-pveDone:
		if err == nil {
			t.Fatal("expired console completed instead of closing the local PVE socket")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expired console retained the local PVE socket")
	}
	select {
	case <-wssClosed:
	case <-time.After(2 * time.Second):
		t.Fatal("expired console retained the website WSS")
	}
}

func TestLocalPVEWebsocketModeWithoutVNCChallengeIsSupported(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		_, err := server.Write([]byte("RFB 003.008\n"))
		version := make([]byte, 12)
		if err == nil {
			_, err = io.ReadFull(server, version)
		}
		if err == nil {
			_, err = server.Write([]byte{1, 1})
		}
		choice := make([]byte, 1)
		if err == nil {
			_, err = io.ReadFull(server, choice)
		}
		if err == nil && choice[0] != 1 {
			err = io.ErrUnexpectedEOF
		}
		if err == nil {
			err = binary.Write(server, binary.BigEndian, uint32(0))
		}
		done <- err
	}()
	if err := authenticatePVEVNC(client, []byte("unused-local-ticket")); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestConsoleRevokeRejectsCrossAuthorityAndClosesBothSockets(t *testing.T) {
	now := time.Now().UTC()
	registration := consoleRegistration(now)
	revokeCalled := false
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/console-sessions/session-1/revoke" {
			t.Errorf("unexpected revoke request: %s %s", r.Method, r.URL.Path)
		}
		revokeCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer broker.Close()
	endpoint, _ := url.Parse(broker.URL + "/console-sessions")
	localClient, localServer := net.Pipe()
	tunnelClient, tunnelServer := net.Pipe()
	defer localServer.Close()
	defer tunnelServer.Close()
	_, cancel := context.WithCancel(context.Background())
	sink := &HTTPSConsoleSessionSink{endpoint: endpoint, client: broker.Client(), keyID: "key-1", secret: []byte("0123456789abcdef"), now: func() time.Time { return now }, active: map[string]*activeConsoleSession{registration.SessionRef: {registration: registration, cancel: cancel, local: localClient, tunnel: tunnelClient}}}
	revoke := ConsoleSessionRevoke{SchemaVersion: 1, SessionRef: registration.SessionRef, CommandID: "revoke-command", IdempotencyKey: "revoke-idempotency", OperationID: "revoke-operation", BindingID: registration.BindingID, DeviceID: registration.DeviceID, CredentialEpoch: registration.CredentialEpoch, AssignmentRevision: registration.AssignmentRevision, AgentRef: registration.AgentRef, ClusterRef: registration.ClusterRef, ServiceRef: registration.ServiceRef, InstanceUUID: registration.InstanceUUID, Generation: registration.Generation, NodeRef: registration.NodeRef, GuestType: registration.GuestType, VMID: registration.VMID}
	for name, mutate := range map[string]func(*ConsoleSessionRevoke){
		"binding":    func(v *ConsoleSessionRevoke) { v.BindingID = "22222222-2222-4222-8222-222222222222" },
		"device":     func(v *ConsoleSessionRevoke) { v.DeviceID = "device-2" },
		"generation": func(v *ConsoleSessionRevoke) { v.Generation = 4 },
	} {
		t.Run(name, func(t *testing.T) {
			cross := revoke
			mutate(&cross)
			if err := sink.Revoke(context.Background(), cross); err == nil {
				t.Fatal("cross-authority revoke was accepted")
			}
			if len(sink.active) != 1 {
				t.Fatal("cross-authority revoke closed the valid session")
			}
		})
	}
	if err := sink.Revoke(context.Background(), revoke); err != nil {
		t.Fatal(err)
	}
	if !revokeCalled {
		t.Fatal("broker revoke endpoint was not notified")
	}
	if len(sink.active) != 0 {
		t.Fatal("authority invalidation retained active session")
	}
	_ = localServer.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := localServer.Write([]byte{1}); err == nil {
		t.Fatal("authority invalidation did not close local PVE socket")
	}
}

func TestConsoleRegistrationAndPublicationAreStrictAndSecretFree(t *testing.T) {
	now := time.Now().UTC()
	registration := consoleRegistration(now)
	if !validConsoleRegistration(registration, now) {
		t.Fatal("valid registration rejected")
	}
	for name, mutate := range map[string]func(*ConsoleTunnelRegistration){
		"binding":    func(v *ConsoleTunnelRegistration) { v.BindingID = "bad" },
		"device":     func(v *ConsoleTunnelRegistration) { v.DeviceID = "" },
		"epoch":      func(v *ConsoleTunnelRegistration) { v.CredentialEpoch = 0 },
		"assignment": func(v *ConsoleTunnelRegistration) { v.AssignmentRevision = 0 },
		"generation": func(v *ConsoleTunnelRegistration) { v.Generation = 0 },
		"expired":    func(v *ConsoleTunnelRegistration) { v.ExpiresAt = now.Add(-time.Second) },
		"tooLong":    func(v *ConsoleTunnelRegistration) { v.ExpiresAt = now.Add(301 * time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			value := registration
			mutate(&value)
			if validConsoleRegistration(value, now) {
				t.Fatal("invalid registration accepted")
			}
		})
	}
	raw, _ := json.Marshal(registration)
	for _, forbidden := range []string{"pveTicket", "pveUser", "pvePort", "certificate", "token", "password"} {
		if strings.Contains(strings.ToLower(string(raw)), strings.ToLower(forbidden)) {
			t.Fatalf("registration leaked %s: %s", forbidden, raw)
		}
	}
}
