package control

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/ppflight/ppflight-agent/internal/protocol"
	"github.com/ppflight/ppflight-agent/internal/uploader"
)

const maxPollResponseBytes = 1 << 20

type PollResponse struct {
	SchemaVersion int       `json:"schemaVersion"`
	Cursor        string    `json:"cursor"`
	Commands      []Command `json:"commands"`
}

type Poller interface {
	Poll(context.Context, string) (PollResponse, error)
}

type ClientConfig struct {
	Endpoint    string
	AgentRef    string
	Limit       int
	AuthMode    uploader.AuthMode
	KeyID       string
	Secret      []byte
	BearerToken string
	Timeout     time.Duration
	HTTPClient  *http.Client
	Now         func() time.Time
}

type Client struct {
	endpoint    string
	agentRef    string
	limit       int
	authMode    uploader.AuthMode
	keyID       string
	secret      []byte
	bearerToken string
	http        *http.Client
	now         func() time.Time
}

func NewClient(cfg ClientConfig) (*Client, error) {
	parsed, err := url.Parse(cfg.Endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || cfg.AgentRef == "" {
		return nil, errors.New("control poll endpoint and agent ref are required")
	}
	if cfg.Limit < 1 || cfg.Limit > 100 {
		return nil, errors.New("control poll limit must be 1-100")
	}
	switch cfg.AuthMode {
	case uploader.AuthHMACSHA256:
		if cfg.KeyID == "" || len(cfg.Secret) == 0 {
			return nil, errors.New("control HMAC credentials are required")
		}
	case uploader.AuthBearer:
		if cfg.BearerToken == "" {
			return nil, errors.New("control bearer token is required")
		}
	case uploader.AuthNone:
	default:
		return nil, errors.New("unsupported control authentication mode")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.HTTPClient == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		} else {
			transport.TLSClientConfig = transport.TLSClientConfig.Clone()
			transport.TLSClientConfig.MinVersion = tls.VersionTLS12
		}
		cfg.HTTPClient = &http.Client{
			Timeout:       cfg.Timeout,
			Transport:     transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Client{
		endpoint: cfg.Endpoint, agentRef: cfg.AgentRef, limit: cfg.Limit,
		authMode: cfg.AuthMode, keyID: cfg.KeyID, secret: append([]byte(nil), cfg.Secret...),
		bearerToken: cfg.BearerToken, http: cfg.HTTPClient, now: cfg.Now,
	}, nil
}

func (c *Client) Poll(ctx context.Context, after string) (PollResponse, error) {
	endpoint, err := url.Parse(c.endpoint)
	if err != nil {
		return PollResponse{}, err
	}
	query := endpoint.Query()
	query.Set("agentRef", c.agentRef)
	query.Set("limit", strconv.Itoa(c.limit))
	if after != "" {
		query.Set("after", after)
	}
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return PollResponse{}, err
	}
	req.Header.Set("Accept", "application/json")
	switch c.authMode {
	case uploader.AuthHMACSHA256:
		if err := protocol.SignRequest(req, nil, c.keyID, c.secret, c.now(), ""); err != nil {
			return PollResponse{}, err
		}
	case uploader.AuthBearer:
		req.Header.Set("Authorization", "Bearer "+c.bearerToken)
	}
	response, err := c.http.Do(req)
	if err != nil {
		return PollResponse{}, fmt.Errorf("poll control API: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxPollResponseBytes+1))
	if err != nil {
		return PollResponse{}, fmt.Errorf("read control response: %w", err)
	}
	if len(body) > maxPollResponseBytes {
		return PollResponse{}, errors.New("control response exceeds 1 MiB")
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return PollResponse{}, fmt.Errorf("control API returned HTTP %d%s", response.StatusCode, safeAPIErrorCode(body))
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var result PollResponse
	if err := decoder.Decode(&result); err != nil {
		return PollResponse{}, fmt.Errorf("decode control response: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return PollResponse{}, errors.New("control response must contain one JSON object")
	}
	if result.SchemaVersion != SchemaVersion || result.Cursor == "" || len(result.Commands) > c.limit {
		return PollResponse{}, errors.New("invalid control response envelope")
	}
	for _, command := range result.Commands {
		if command.CommandID == "" {
			return PollResponse{}, errors.New("control response contains an unidentifiable command")
		}
	}
	return result, nil
}

func safeAPIErrorCode(body []byte) string {
	var envelope struct {
		Code  string `json:"code"`
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		return ""
	}
	code := envelope.Code
	if code == "" {
		code = envelope.Error.Code
	}
	for _, r := range code {
		if !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_') {
			return ""
		}
	}
	if code == "" || len(code) > 64 {
		return ""
	}
	return " (" + code + ")"
}
