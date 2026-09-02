package control

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/ppflight/ppflight-agent/internal/netpolicy"
	"github.com/ppflight/ppflight-agent/internal/protocol"
)

const maxConsoleBrokerResponseBytes = 64 << 10

// HTTPSConsoleSessionSink transfers console material directly from memory to
// a fixed, HMAC-authenticated website endpoint. It owns no queue and
// never retries: an uncertain response fails the command and the short-lived
// PVE ticket expires naturally.
type HTTPSConsoleSessionSink struct {
	endpoint *url.URL
	client   *http.Client
	keyID    string
	secret   []byte
	now      func() time.Time
}

func NewHTTPSConsoleSessionSink(receiptURL, keyID string, secret []byte, timeout time.Duration) (*HTTPSConsoleSessionSink, error) {
	parsed, err := url.Parse(receiptURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" || keyID == "" || len(secret) < 16 {
		return nil, errors.New("console broker configuration is invalid")
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	parsed.Path = path.Join(path.Dir(parsed.Path), "console-sessions")
	transport := netpolicy.ApplyIPv4Only(http.DefaultTransport.(*http.Transport).Clone())
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	}
	return &HTTPSConsoleSessionSink{endpoint: parsed, client: &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("console broker redirects are not allowed")
		},
	}, keyID: keyID, secret: append([]byte(nil), secret...), now: time.Now}, nil
}

func (s *HTTPSConsoleSessionSink) Publish(ctx context.Context, secret ConsoleSessionSecret) (ConsoleSessionPublication, error) {
	if s == nil || s.endpoint == nil || s.client == nil || !commandIDRE.MatchString(secret.SessionRef) || !commandIDRE.MatchString(secret.IdempotencyKey) || secret.PVETicket == "" {
		return ConsoleSessionPublication{}, errors.New("console broker is unavailable")
	}
	var result ConsoleSessionPublication
	if err := s.do(ctx, http.MethodPost, s.endpoint.String(), secret.IdempotencyKey, secret, &result); err != nil {
		return ConsoleSessionPublication{}, err
	}
	return result, nil
}

func (s *HTTPSConsoleSessionSink) Revoke(ctx context.Context, revoke ConsoleSessionRevoke) error {
	if s == nil || s.endpoint == nil || s.client == nil || !commandIDRE.MatchString(revoke.SessionRef) || !commandIDRE.MatchString(revoke.IdempotencyKey) {
		return errors.New("console broker is unavailable")
	}
	target := *s.endpoint
	target.Path = path.Join(target.Path, url.PathEscape(revoke.SessionRef), "revoke")
	return s.do(ctx, http.MethodPost, target.String(), revoke.IdempotencyKey, revoke, nil)
}

func (s *HTTPSConsoleSessionSink) do(ctx context.Context, method, endpoint, idempotencyKey string, body any, output any) error {
	raw, err := json.Marshal(body)
	if err != nil || len(raw) > maxConsoleBrokerResponseBytes {
		return errors.New("console broker request is invalid")
	}
	defer func() {
		for index := range raw {
			raw[index] = 0
		}
	}()
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
		return errors.New("console broker rejected request")
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
