package control

import (
	"bytes"
	"context"
	"crypto/des"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/ppflight/ppflight-agent/internal/netpolicy"
	"github.com/ppflight/ppflight-agent/internal/protocol"
)

const maxConsoleBrokerResponseBytes = 64 << 10

// HTTPSConsoleSessionSink registers only secret-free identity metadata, then
// opens an Agent-originated WSS tunnel to the same website origin. The PVE
// ticket is consumed locally during the RFB authentication handshake and is
// never sent to the broker or browser.
type HTTPSConsoleSessionSink struct {
	endpoint     *url.URL
	client       *http.Client
	tunnelClient *http.Client
	keyID        string
	secret       []byte
	now          func() time.Time
	mu           sync.Mutex
	active       map[string]*activeConsoleSession
}

type activeConsoleSession struct {
	registration ConsoleTunnelRegistration
	cancel       context.CancelFunc
	local        net.Conn
	tunnel       net.Conn
}

func NewHTTPSConsoleSessionSink(receiptURL, keyID string, secret []byte, timeout time.Duration) (*HTTPSConsoleSessionSink, error) {
	parsed, err := url.Parse(receiptURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" || netpolicy.ValidateIPv4URL(parsed) != nil || keyID == "" || len(secret) < 16 {
		return nil, errors.New("console broker configuration is invalid")
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	parsed.Path = path.Join(path.Dir(parsed.Path), "console-sessions")
	transport := netpolicy.ApplyIPv4Only(http.DefaultTransport.(*http.Transport).Clone())
	transport.Proxy = nil
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	}
	redirect := func(*http.Request, []*http.Request) error {
		return errors.New("console broker redirects are not allowed")
	}
	return &HTTPSConsoleSessionSink{
		endpoint: parsed,
		client: &http.Client{
			Transport: transport, Timeout: timeout, CheckRedirect: redirect,
		},
		tunnelClient: &http.Client{Transport: transport, CheckRedirect: redirect},
		keyID:        keyID, secret: append([]byte(nil), secret...), now: time.Now,
		active: make(map[string]*activeConsoleSession),
	}, nil
}

func (s *HTTPSConsoleSessionSink) Publish(ctx context.Context, registration ConsoleTunnelRegistration, local ConsoleLocalEndpoint) (ConsoleSessionPublication, error) {
	if s == nil || s.endpoint == nil || s.client == nil || !validConsoleRegistration(registration, s.now().UTC()) || local.Port < 1 || local.Port > 65535 || len(local.Ticket) == 0 || len(local.Ticket) > 8192 {
		zeroBytes(local.Ticket)
		return ConsoleSessionPublication{}, errors.New("console broker is unavailable")
	}
	s.mu.Lock()
	_, alreadyActive := s.active[registration.SessionRef]
	s.mu.Unlock()
	if alreadyActive {
		zeroBytes(local.Ticket)
		return ConsoleSessionPublication{}, errors.New("console session is already active")
	}
	localConn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", fmt.Sprint(local.Port)))
	if err != nil {
		zeroBytes(local.Ticket)
		return ConsoleSessionPublication{}, errors.New("connect local PVE console")
	}
	cleanupLocal := true
	defer func() {
		zeroBytes(local.Ticket)
		if cleanupLocal {
			_ = localConn.Close()
		}
	}()
	_ = localConn.SetDeadline(registration.ExpiresAt)
	if err := authenticatePVEVNC(localConn, local.Ticket); err != nil {
		return ConsoleSessionPublication{}, errors.New("authenticate local PVE console")
	}
	zeroBytes(local.Ticket)

	var publication ConsoleSessionPublication
	if err := s.do(ctx, http.MethodPost, s.endpoint.String(), registration.IdempotencyKey, registration, &publication); err != nil {
		return ConsoleSessionPublication{}, err
	}
	if !validConsolePublication(publication, registration) {
		return ConsoleSessionPublication{}, errors.New("console broker response contract is invalid")
	}

	ws, err := s.dialTunnel(ctx, registration)
	if err != nil {
		return ConsoleSessionPublication{}, err
	}
	lifetime, cancel := context.WithDeadline(context.Background(), registration.ExpiresAt)
	tunnelConn := websocket.NetConn(lifetime, ws, websocket.MessageBinary)
	_ = tunnelConn.SetDeadline(registration.ExpiresAt)
	session := &activeConsoleSession{registration: registration, cancel: cancel, local: localConn, tunnel: tunnelConn}
	s.mu.Lock()
	if s.active == nil {
		s.active = make(map[string]*activeConsoleSession)
	}
	if _, exists := s.active[registration.SessionRef]; exists {
		s.mu.Unlock()
		cancel()
		_ = tunnelConn.Close()
		return ConsoleSessionPublication{}, errors.New("console session is already active")
	}
	s.active[registration.SessionRef] = session
	s.mu.Unlock()
	cleanupLocal = false
	go s.serve(session)
	return publication, nil
}

func (s *HTTPSConsoleSessionSink) dialTunnel(ctx context.Context, registration ConsoleTunnelRegistration) (*websocket.Conn, error) {
	target := *s.endpoint
	target.Scheme = "wss"
	target.Path = path.Join(target.Path, url.PathEscape(registration.SessionRef), "agent-tunnel")
	tunnelClient := s.tunnelClient
	if tunnelClient == nil {
		tunnelClient = &http.Client{Transport: s.client.Transport, CheckRedirect: s.client.CheckRedirect}
	}
	signed, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, errors.New("create console tunnel request")
	}
	signed.Header.Set("X-PPFlight-Console-Session", registration.SessionRef)
	if err := protocol.SignRequest(signed, nil, s.keyID, s.secret, s.now().UTC(), ""); err != nil {
		return nil, errors.New("sign console tunnel request")
	}
	connection, response, err := websocket.Dial(ctx, target.String(), &websocket.DialOptions{HTTPClient: tunnelClient, HTTPHeader: signed.Header})
	if err != nil {
		if response != nil && response.StatusCode >= 300 && response.StatusCode < 400 {
			return nil, errors.New("console broker redirect is not allowed")
		}
		return nil, errors.New("console broker tunnel failed")
	}
	return connection, nil
}

func (s *HTTPSConsoleSessionSink) serve(session *activeConsoleSession) {
	defer func() {
		session.cancel()
		_ = session.local.Close()
		_ = session.tunnel.Close()
		s.mu.Lock()
		if s.active[session.registration.SessionRef] == session {
			delete(s.active, session.registration.SessionRef)
		}
		s.mu.Unlock()
	}()
	if establishBrowserRFB(session.tunnel, session.local) != nil {
		return
	}
	done := make(chan struct{}, 2)
	copyStream := func(destination io.Writer, source io.Reader) {
		_, _ = io.Copy(destination, source)
		done <- struct{}{}
	}
	go copyStream(session.local, session.tunnel)
	go copyStream(session.tunnel, session.local)
	<-done
}

func (s *HTTPSConsoleSessionSink) Revoke(ctx context.Context, revoke ConsoleSessionRevoke) error {
	if s == nil || s.endpoint == nil || s.client == nil || !validConsoleRevoke(revoke) {
		return errors.New("console broker is unavailable")
	}
	s.mu.Lock()
	session := s.active[revoke.SessionRef]
	if session != nil && !sameConsoleAuthority(session.registration, revoke) {
		s.mu.Unlock()
		return errors.New("console session authority does not match")
	}
	if session != nil {
		delete(s.active, revoke.SessionRef)
	}
	s.mu.Unlock()
	if session != nil {
		session.cancel()
		_ = session.local.Close()
		_ = session.tunnel.Close()
	}
	target := *s.endpoint
	target.Path = path.Join(target.Path, url.PathEscape(revoke.SessionRef), "revoke")
	return s.do(ctx, http.MethodPost, target.String(), revoke.IdempotencyKey, revoke, nil)
}

// Invalidate immediately drops every active console whenever signed assignment
// authority changes. Binding/credential changes rebuild or stop the Agent and
// therefore close these process-local sockets as well.
func (s *HTTPSConsoleSessionSink) Invalidate() {
	if s == nil {
		return
	}
	s.mu.Lock()
	sessions := make([]*activeConsoleSession, 0, len(s.active))
	for ref, session := range s.active {
		sessions = append(sessions, session)
		delete(s.active, ref)
	}
	s.mu.Unlock()
	for _, session := range sessions {
		session.cancel()
		_ = session.local.Close()
		_ = session.tunnel.Close()
	}
}

func validConsoleRegistration(value ConsoleTunnelRegistration, now time.Time) bool {
	return value.SchemaVersion == 1 && value.Transport == "agent-reverse-wss-v1" && commandIDRE.MatchString(value.SessionRef) &&
		commandIDRE.MatchString(value.CommandID) && commandIDRE.MatchString(value.IdempotencyKey) && commandIDRE.MatchString(value.OperationID) &&
		uuidRE.MatchString(value.BindingID) && commandIDRE.MatchString(value.DeviceID) && value.CredentialEpoch > 0 && value.AssignmentRevision > 0 &&
		commandIDRE.MatchString(value.AgentRef) && commandIDRE.MatchString(value.ClusterRef) && commandIDRE.MatchString(value.ServiceRef) &&
		commandIDRE.MatchString(value.InstanceUUID) && value.Generation > 0 && journalNodeRef.MatchString(value.NodeRef) &&
		value.GuestType == "qemu" && value.VMID > 0 && value.OneTime && value.ExpiresAt.After(now) &&
		!value.ExpiresAt.After(now.Add(300*time.Second))
}

func validConsolePublication(value ConsoleSessionPublication, registration ConsoleTunnelRegistration) bool {
	return value.SessionRef == registration.SessionRef && value.State == "ready" && value.ExpiresAt.Equal(registration.ExpiresAt) &&
		value.BrowserPath != "" && len(value.BrowserPath) <= 512 && strings.HasPrefix(value.BrowserPath, "/") &&
		!strings.ContainsAny(value.BrowserPath, "\x00\r\n?#")
}

func validConsoleRevoke(value ConsoleSessionRevoke) bool {
	return value.SchemaVersion == 1 && commandIDRE.MatchString(value.SessionRef) && commandIDRE.MatchString(value.CommandID) &&
		commandIDRE.MatchString(value.IdempotencyKey) && commandIDRE.MatchString(value.OperationID) && uuidRE.MatchString(value.BindingID) &&
		commandIDRE.MatchString(value.DeviceID) && value.CredentialEpoch > 0 && value.AssignmentRevision > 0 &&
		commandIDRE.MatchString(value.AgentRef) && commandIDRE.MatchString(value.ClusterRef) && commandIDRE.MatchString(value.ServiceRef) &&
		commandIDRE.MatchString(value.InstanceUUID) && value.Generation > 0 && journalNodeRef.MatchString(value.NodeRef) &&
		value.GuestType == "qemu" && value.VMID > 0
}

func sameConsoleAuthority(registration ConsoleTunnelRegistration, revoke ConsoleSessionRevoke) bool {
	return registration.BindingID == revoke.BindingID && registration.DeviceID == revoke.DeviceID && registration.CredentialEpoch == revoke.CredentialEpoch &&
		registration.AssignmentRevision == revoke.AssignmentRevision && registration.AgentRef == revoke.AgentRef && registration.ClusterRef == revoke.ClusterRef &&
		registration.NodeRef == revoke.NodeRef && registration.ServiceRef == revoke.ServiceRef && registration.InstanceUUID == revoke.InstanceUUID &&
		registration.Generation == revoke.Generation && registration.GuestType == revoke.GuestType && registration.VMID == revoke.VMID
}

func authenticatePVEVNC(connection net.Conn, ticket []byte) error {
	version := make([]byte, 12)
	if _, err := io.ReadFull(connection, version); err != nil || !validRFBVersion(version) {
		return errors.New("invalid RFB protocol version")
	}
	if _, err := connection.Write(version); err != nil {
		return err
	}
	securityType := byte(0)
	if string(version) == "RFB 003.003\n" {
		var security uint32
		if err := binary.Read(connection, binary.BigEndian, &security); err != nil || (security != 1 && security != 2) {
			return errors.New("PVE VNC authentication is unavailable")
		}
		securityType = byte(security)
	} else {
		count := make([]byte, 1)
		if _, err := io.ReadFull(connection, count); err != nil || count[0] == 0 || count[0] > 32 {
			return errors.New("PVE VNC security types are invalid")
		}
		types := make([]byte, int(count[0]))
		if _, err := io.ReadFull(connection, types); err != nil {
			return errors.New("PVE VNC security types are invalid")
		}
		switch {
		case bytes.Contains(types, []byte{2}):
			securityType = 2
		case bytes.Contains(types, []byte{1}):
			// PVE websocket-mode proxies may rely entirely on the authenticated
			// localhost port and advertise RFB None. That remains safe because this
			// socket is obtained from the authenticated typed vncproxy action and
			// is reachable only through tcp4 127.0.0.1.
			securityType = 1
		default:
			return errors.New("PVE VNC ticket authentication is unavailable")
		}
		if _, err := connection.Write([]byte{securityType}); err != nil {
			return err
		}
	}
	if securityType == 1 {
		if string(version) == "RFB 003.008\n" {
			var status uint32
			if err := binary.Read(connection, binary.BigEndian, &status); err != nil || status != 0 {
				return errors.New("PVE rejected local VNC connection")
			}
		}
		return nil
	}
	challenge := make([]byte, 16)
	if _, err := io.ReadFull(connection, challenge); err != nil {
		return err
	}
	key := make([]byte, 8)
	copy(key, ticket)
	for index := range key {
		key[index] = reverseBits(key[index])
	}
	cipher, err := des.NewCipher(key)
	zeroBytes(key)
	if err != nil {
		return err
	}
	response := make([]byte, 16)
	cipher.Encrypt(response[:8], challenge[:8])
	cipher.Encrypt(response[8:], challenge[8:])
	zeroBytes(challenge)
	if _, err := connection.Write(response); err != nil {
		zeroBytes(response)
		return err
	}
	zeroBytes(response)
	var status uint32
	if err := binary.Read(connection, binary.BigEndian, &status); err != nil || status != 0 {
		return errors.New("PVE rejected VNC ticket")
	}
	return nil
}

func establishBrowserRFB(browser net.Conn, pve net.Conn) error {
	if _, err := browser.Write([]byte("RFB 003.008\n")); err != nil {
		return err
	}
	version := make([]byte, 12)
	if _, err := io.ReadFull(browser, version); err != nil || !validRFBVersion(version) {
		return errors.New("invalid browser RFB version")
	}
	if string(version) == "RFB 003.003\n" {
		if err := binary.Write(browser, binary.BigEndian, uint32(1)); err != nil {
			return err
		}
	} else {
		if _, err := browser.Write([]byte{1, 1}); err != nil {
			return err
		}
		choice := make([]byte, 1)
		if _, err := io.ReadFull(browser, choice); err != nil || choice[0] != 1 {
			return errors.New("browser rejected one-time console authentication")
		}
		if err := binary.Write(browser, binary.BigEndian, uint32(0)); err != nil {
			return err
		}
	}
	clientInit := make([]byte, 1)
	if _, err := io.ReadFull(browser, clientInit); err != nil {
		return err
	}
	_, err := pve.Write(clientInit)
	return err
}

func validRFBVersion(value []byte) bool {
	text := string(value)
	return text == "RFB 003.003\n" || text == "RFB 003.007\n" || text == "RFB 003.008\n"
}

func reverseBits(value byte) byte {
	value = (value&0xf0)>>4 | (value&0x0f)<<4
	value = (value&0xcc)>>2 | (value&0x33)<<2
	return (value&0xaa)>>1 | (value&0x55)<<1
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func (s *HTTPSConsoleSessionSink) do(ctx context.Context, method, endpoint, idempotencyKey string, body any, output any) error {
	raw, err := json.Marshal(body)
	if err != nil || len(raw) > maxConsoleBrokerResponseBytes {
		return errors.New("console broker request is invalid")
	}
	defer zeroBytes(raw)
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(raw))
	if err != nil {
		return errors.New("create console broker request")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Idempotency-Key", idempotencyKey)
	if err := protocol.SignRequest(request, raw, s.keyID, s.secret, s.now().UTC(), ""); err != nil {
		return errors.New("sign console broker request")
	}
	response, err := s.client.Do(request)
	if err != nil {
		return errors.New("console broker request failed")
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxConsoleBrokerResponseBytes+1))
	if err != nil || len(responseBody) > maxConsoleBrokerResponseBytes {
		return errors.New("console broker response is invalid")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		code := safeConsoleBrokerErrorCode(responseBody)
		if code == "" {
			return fmt.Errorf("console broker rejected request: HTTP %d", response.StatusCode)
		}
		return fmt.Errorf("console broker rejected request: HTTP %d (%s)", response.StatusCode, code)
	}
	if output == nil {
		return nil
	}
	if !strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "application/json") {
		return errors.New("console broker response is not JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return errors.New("console broker response contract is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("console broker response contract is invalid")
	}
	return nil
}

// safeConsoleBrokerErrorCode returns only the bounded protocol identifier from
// an error envelope. It deliberately excludes the free-form message and raw
// response so a broker cannot reflect secrets or arbitrary text into receipts,
// audit events, telemetry, or logs.
func safeConsoleBrokerErrorCode(body []byte) string {
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &envelope) != nil || envelope.Error.Code == "" || len(envelope.Error.Code) > 64 {
		return ""
	}
	for _, character := range envelope.Error.Code {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '_' || character == '.' || character == '-') {
			return ""
		}
	}
	return envelope.Error.Code
}
