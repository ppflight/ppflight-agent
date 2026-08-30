// Package monitorenrollment binds the agent to the monitoring service as an
// independent trust domain. It can only issue telemetry-ingest authority.
package monitorenrollment

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ppflight/ppflight-agent/internal/enrollment"
	"github.com/ppflight/ppflight-agent/internal/netpolicy"
)

const (
	SchemaVersion             = 1
	MaxRequestBytes           = 64 << 10
	MaxResponseBytes          = 1 << 20
	TelemetryPath             = "/internal/v1/monitoring/telemetry/batches"
	AuditPath                 = "/internal/v1/monitoring/audit-events/batches"
	AuditMaxCompressedBytes   = int64(4 << 20)
	AuditMaxUncompressedBytes = int64(16 << 20)
)

var (
	safeID      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$`)
	bindingCode = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$`)
	uuidValue   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
	version     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}$`)
)

type Request struct {
	SchemaVersion int                  `json:"schemaVersion"`
	RequestID     string               `json:"requestId"`
	BindingCode   string               `json:"bindingCode"`
	DeviceID      string               `json:"deviceId"`
	AgentVersion  string               `json:"agentVersion"`
	Hostname      string               `json:"hostname"`
	NodeClaim     enrollment.NodeClaim `json:"nodeClaim"`
	Capabilities  []string             `json:"capabilities"`
}

// AuditEndpoint derives the second monitoring write route without expanding
// the strict v1 bind response. Both routes remain on the exact enrolled
// origin and use the monitoring-domain HMAC credential with server-side
// telemetry.write/audit.write scopes.
func AuditEndpoint(telemetryEndpoint string) (string, error) {
	parsed, err := secureURL(telemetryEndpoint)
	if err != nil || parsed.Path != TelemetryPath || parsed.RawPath != "" {
		return "", errors.New("monitoring telemetry endpoint has an unsupported path")
	}
	copyURL := *parsed
	copyURL.Path = AuditPath
	return copyURL.String(), nil
}

type HMACCredential struct {
	Algorithm      string            `json:"algorithm"`
	KeyID          string            `json:"keyId"`
	SecretEncoding string            `json:"secretEncoding"`
	Secret         enrollment.Secret `json:"secret"`
}

type TelemetryContract struct {
	PayloadFormat        string `json:"payloadFormat"`
	Compression          string `json:"compression"`
	MaxCompressedBytes   int64  `json:"maxCompressedBytes"`
	MaxUncompressedBytes int64  `json:"maxUncompressedBytes"`
}

type Response struct {
	SchemaVersion      int                     `json:"schemaVersion"`
	BindingID          string                  `json:"bindingId"`
	DeviceID           string                  `json:"deviceId"`
	MonitoringAgentRef string                  `json:"monitoringAgentRef"`
	IngestEndpoint     string                  `json:"ingestEndpoint"`
	HMACCredential     HMACCredential          `json:"hmacCredential"`
	Telemetry          TelemetryContract       `json:"telemetry"`
	NetworkPolicy      netpolicy.NetworkPolicy `json:"networkPolicy"`
	CredentialEpoch    uint64                  `json:"credentialEpoch"`
	IssuedAt           time.Time               `json:"issuedAt"`
}

type Config struct {
	Endpoint   string
	HTTPClient *http.Client
	Timeout    time.Duration
}

type Client struct {
	endpoint *url.URL
	http     *http.Client
}

func NewClient(cfg Config) (*Client, error) {
	endpoint, err := secureURL(cfg.Endpoint)
	if err != nil {
		return nil, errors.New("monitoring binding endpoint must be a secure URL")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	client, err := secureClient(cfg.HTTPClient, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	return &Client{endpoint: endpoint, http: client}, nil
}

func (c *Client) Bind(ctx context.Context, request Request) (Response, error) {
	if c == nil || c.endpoint == nil || c.http == nil || request.Validate() != nil {
		return Response{}, errors.New("invalid monitoring binding request")
	}
	body, err := json.Marshal(request)
	if err != nil || len(body) > MaxRequestBytes {
		return Response{}, errors.New("invalid monitoring binding request")
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return Response{}, errors.New("create monitoring binding request")
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	httpResponse, err := c.http.Do(httpRequest)
	if err != nil {
		return Response{}, errors.New("monitoring binding request failed")
	}
	defer httpResponse.Body.Close()
	body, err = io.ReadAll(io.LimitReader(httpResponse.Body, MaxResponseBytes+1))
	if err != nil || len(body) > MaxResponseBytes {
		return Response{}, errors.New("invalid monitoring binding response")
	}
	if httpResponse.StatusCode < 200 || httpResponse.StatusCode >= 300 {
		return Response{}, fmt.Errorf("monitoring binding service returned HTTP %d", httpResponse.StatusCode)
	}
	if media := strings.ToLower(strings.TrimSpace(strings.Split(httpResponse.Header.Get("Content-Type"), ";")[0])); media != "application/json" {
		return Response{}, errors.New("monitoring binding response must be application/json")
	}
	if err := rejectDuplicateKeys(body); err != nil {
		return Response{}, errors.New("invalid monitoring binding response")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var response Response
	if err := decoder.Decode(&response); err != nil {
		return Response{}, errors.New("invalid monitoring binding response")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Response{}, errors.New("invalid monitoring binding response")
	}
	if err := response.Validate(c.endpoint); err != nil || response.DeviceID != request.DeviceID {
		return Response{}, errors.New("invalid monitoring binding response")
	}
	return response, nil
}

func (r Request) Validate() error {
	if r.SchemaVersion != SchemaVersion || !uuidValue.MatchString(r.RequestID) || !bindingCode.MatchString(r.BindingCode) || !safeID.MatchString(r.DeviceID) || !version.MatchString(r.AgentVersion) || !hostname(r.Hostname) || !safeID.MatchString(r.NodeClaim.NodeRef) || !version.MatchString(r.NodeClaim.PVEVersion) || len(r.Capabilities) == 0 || len(r.Capabilities) > 32 {
		return errors.New("invalid monitoring binding request")
	}
	seen := map[string]bool{}
	for _, capability := range r.Capabilities {
		if !version.MatchString(capability) || seen[capability] {
			return errors.New("invalid monitoring binding request")
		}
		seen[capability] = true
	}
	return nil
}

func (r Response) Validate(bindingEndpoint *url.URL) error {
	if bindingEndpoint == nil || r.SchemaVersion != SchemaVersion || !uuidValue.MatchString(r.BindingID) || !safeID.MatchString(r.DeviceID) || !safeID.MatchString(r.MonitoringAgentRef) || r.CredentialEpoch == 0 || r.IssuedAt.IsZero() || netpolicy.ValidateNetworkPolicy(r.NetworkPolicy) != nil {
		return errors.New("invalid monitoring binding response")
	}
	ingest, err := secureURL(r.IngestEndpoint)
	if err != nil || !sameOrigin(bindingEndpoint, ingest) {
		return errors.New("invalid monitoring binding response")
	}
	if _, err := AuditEndpoint(r.IngestEndpoint); err != nil {
		return errors.New("invalid monitoring binding response")
	}
	decoded, err := base64.StdEncoding.DecodeString(string(r.HMACCredential.Secret))
	if r.HMACCredential.Algorithm != "hmac-sha256" || r.HMACCredential.SecretEncoding != "base64" || !safeID.MatchString(r.HMACCredential.KeyID) || err != nil || len(decoded) < 16 || len(decoded) > 4096 {
		return errors.New("invalid monitoring binding response")
	}
	if r.Telemetry.PayloadFormat != "telemetry-v1" || (r.Telemetry.Compression != "none" && r.Telemetry.Compression != "gzip") || r.Telemetry.MaxCompressedBytes < 1<<20 || r.Telemetry.MaxCompressedBytes > 64<<20 || r.Telemetry.MaxUncompressedBytes < r.Telemetry.MaxCompressedBytes || r.Telemetry.MaxUncompressedBytes > 256<<20 {
		return errors.New("invalid monitoring binding response")
	}
	return nil
}

func secureURL(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" || netpolicy.ValidateIPv4URL(parsed) != nil {
		return nil, errors.New("invalid secure URL")
	}
	if parsed.Scheme == "https" || parsed.Scheme == "http" && loopback(parsed.Hostname()) {
		return parsed, nil
	}
	return nil, errors.New("URL must use HTTPS")
}

func secureClient(provided *http.Client, timeout time.Duration) (*http.Client, error) {
	return secureClientWithAllowlist(provided, timeout, nil)
}

func secureClientWithAllowlist(provided *http.Client, timeout time.Duration, allowlist []string) (*http.Client, error) {
	if provided == nil {
		provided = &http.Client{}
	}
	result := *provided
	result.Timeout = timeout
	result.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if transport, ok := provided.Transport.(*http.Transport); ok {
		clone := netpolicy.ApplyIPv4Only(transport.Clone())
		if len(allowlist) != 0 {
			var policyErr error
			clone, policyErr = netpolicy.ApplyIPv4Allowlist(clone, allowlist)
			if policyErr != nil {
				return nil, errors.New("invalid IPv4 allowlist")
			}
		}
		clone.Proxy = nil
		if clone.TLSClientConfig == nil {
			clone.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		} else {
			clone.TLSClientConfig = clone.TLSClientConfig.Clone()
			if clone.TLSClientConfig.MinVersion < tls.VersionTLS12 {
				clone.TLSClientConfig.MinVersion = tls.VersionTLS12
			}
		}
		result.Transport = clone
	} else if provided.Transport == nil {
		transport := netpolicy.ApplyIPv4Only(http.DefaultTransport.(*http.Transport).Clone())
		if len(allowlist) != 0 {
			var policyErr error
			transport, policyErr = netpolicy.ApplyIPv4Allowlist(transport, allowlist)
			if policyErr != nil {
				return nil, errors.New("invalid IPv4 allowlist")
			}
		}
		transport.Proxy = nil
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		result.Transport = transport
	} else {
		return nil, errors.New("monitoring binding HTTP transport must be *http.Transport")
	}
	return &result, nil
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Hostname(), b.Hostname()) && port(a) == port(b)
}
func port(value *url.URL) string {
	if value.Port() != "" {
		return value.Port()
	}
	if value.Scheme == "https" {
		return "443"
	}
	return "80"
}
func loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() != nil && ip.IsLoopback()
}
func hostname(value string) bool {
	if len(value) == 0 || len(value) > 253 || strings.ContainsAny(value, " \t\r\n/\\") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
				return false
			}
		}
	}
	return true
}

func rejectDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, isDelim := token.(json.Delim)
		if !isDelim {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return errors.New("duplicate JSON key")
				}
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("invalid JSON")
		}
	}
	if err := walk(); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
