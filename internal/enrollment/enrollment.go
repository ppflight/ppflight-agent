// Package enrollment binds an agent to PPFlight's public service.  The agent
// always initiates this connection; the service never needs access to PVE.
package enrollment

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ppflight/ppflight-agent/internal/netpolicy"
)

const (
	SchemaVersion    = 1
	MaxRequestBytes  = 64 << 10
	MaxResponseBytes = 1 << 20
)

var (
	safeID       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$`)
	bindingCode  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$`)
	versionValue = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}$`)
	actionValue  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}(?:\.[a-z][a-z0-9-]{0,31}){1,3}$`)
	uuidValue    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
)

// Request is deliberately separate from the normal agent configuration: its
// BindingCode is short-lived and must never be persisted or logged.
type Request struct {
	SchemaVersion int       `json:"schemaVersion"`
	RequestID     string    `json:"requestId"`
	BindingCode   string    `json:"bindingCode"`
	DeviceID      string    `json:"deviceId"`
	AgentVersion  string    `json:"agentVersion"`
	Hostname      string    `json:"hostname"`
	NodeClaim     NodeClaim `json:"nodeClaim"`
	Capabilities  []string  `json:"capabilities"`
}

// ValidateBindingCode checks only the local syntax of a website enrollment
// code.  It never contacts the service and its error intentionally omits the
// supplied value, so callers can reject malformed terminal/file input before
// creating a durable request, stopping the Agent, or sending HTTP.
func ValidateBindingCode(value string) error {
	if !bindingCode.MatchString(value) {
		return errors.New("invalid binding code")
	}
	return nil
}

type NodeClaim struct {
	NodeRef    string `json:"nodeRef"`
	PVEVersion string `json:"pveVersion"`
}

type Endpoints struct {
	Metering    string `json:"metering"`
	Telemetry   string `json:"telemetry"`
	Assignments string `json:"assignments"`
	Commands    string `json:"commands"`
	Receipts    string `json:"receipts"`
}

// HMACCredential holds one endpoint-specific signing secret. It has no
// String method, and package errors intentionally never interpolate it.
type HMACCredential struct {
	KeyID  string `json:"keyId"`
	Secret Secret `json:"secret"`
}

// Secret preserves its JSON representation but redacts itself when formatted.
// This prevents accidental disclosure in loggers that use fmt.Stringer.
type Secret string

func (Secret) String() string { return "[REDACTED]" }

type HMACCredentials struct {
	Metering    HMACCredential `json:"metering"`
	Telemetry   HMACCredential `json:"telemetry"`
	Assignments HMACCredential `json:"assignments"`
	Commands    HMACCredential `json:"commands"`
	Receipts    HMACCredential `json:"receipts"`
}

// CommandSigningCredential is a public Ed25519 verification key. The service
// signs commands; the agent must never receive a command-signing private key.
type CommandSigningCredential struct {
	KeyID     string `json:"keyId"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"publicKey"`
}

type Response struct {
	SchemaVersion            int                      `json:"schemaVersion"`
	BindingID                string                   `json:"bindingId"`
	DeviceID                 string                   `json:"deviceId"`
	AgentRef                 string                   `json:"agentRef"`
	CollectorRef             string                   `json:"collectorRef"`
	SourceRef                string                   `json:"sourceRef"`
	ClusterRef               string                   `json:"clusterRef"`
	NodeRef                  string                   `json:"nodeRef"`
	Site                     string                   `json:"site"`
	Endpoints                Endpoints                `json:"endpoints"`
	HMACCredentials          HMACCredentials          `json:"hmacCredentials"`
	CommandSigningCredential CommandSigningCredential `json:"commandSigningCredential"`
	AllowedActions           []string                 `json:"allowedActions"`
	AssignmentDocument       json.RawMessage          `json:"assignmentDocument"`
	NetworkPolicy            netpolicy.NetworkPolicy  `json:"networkPolicy"`
	CredentialEpoch          uint64                   `json:"credentialEpoch"`
	IssuedAt                 time.Time                `json:"issuedAt"`
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

// RejectionError is returned only for an exact, allowlisted enrollment
// rejection from the HTTPS enrollment endpoint. The response message is
// deliberately not retained: it is operator-controlled remote text and may
// contain details that must not reach local logs.
type RejectionError struct {
	Code       string
	StatusCode int
}

func (e *RejectionError) Error() string {
	if e == nil {
		return "binding request rejected"
	}
	return "binding request rejected: " + e.Code
}

type rejectionEnvelope struct {
	Error rejectionBody `json:"error"`
}

type rejectionBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func NewClient(cfg Config) (*Client, error) {
	endpoint, err := parseSecureURL(cfg.Endpoint)
	if err != nil || endpoint.RawQuery != "" {
		return nil, errors.New("binding endpoint must be a secure URL without a query")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	client, err := securedClient(cfg.HTTPClient, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	return &Client{endpoint: endpoint, http: client}, nil
}

// Bind sends exactly one JSON object and accepts exactly one JSON object. It
// deliberately returns generic failures, so a binding code or returned secret
// cannot be disclosed through error text.
func (c *Client) Bind(ctx context.Context, request Request) (Response, error) {
	if c == nil || c.endpoint == nil || c.http == nil {
		return Response{}, errors.New("binding client is not initialized")
	}
	if err := request.Validate(); err != nil {
		return Response{}, err
	}
	body, err := json.Marshal(request)
	if err != nil || len(body) > MaxRequestBytes {
		return Response{}, errors.New("binding request is invalid or too large")
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return Response{}, errors.New("create binding request")
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	response, err := c.http.Do(httpRequest)
	if err != nil {
		return Response{}, errors.New("binding request failed")
	}
	defer response.Body.Close()
	body, err = io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
	if err != nil {
		return Response{}, errors.New("read binding response")
	}
	if len(body) > MaxResponseBytes {
		return Response{}, errors.New("binding response exceeds maximum size")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		// Most non-2xx responses remain ambiguous: a gateway can replace a
		// successful enrollment response after the service commits it. Only an
		// exact allowlisted service rejection is proof that this request did not
		// issue credentials and may safely release its local pending marker.
		if rejection := parseDefinitiveRejection(response.StatusCode, response.Header.Get("Content-Type"), body); rejection != nil {
			return Response{}, rejection
		}
		return Response{}, errors.New("binding response outcome is unknown")
	}
	if !isJSON(response.Header.Get("Content-Type")) {
		return Response{}, errors.New("binding response must be application/json")
	}
	if err := rejectDuplicateKeys(body); err != nil {
		return Response{}, errors.New("binding response is not a valid JSON object")
	}
	var result Response
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return Response{}, errors.New("binding response is not a valid JSON object")
	}
	if err := onlyOneJSONValue(decoder); err != nil {
		return Response{}, err
	}
	if err := result.Validate(c.endpoint); err != nil {
		return Response{}, err
	}
	if result.DeviceID != request.DeviceID {
		return Response{}, errors.New("binding response device does not match request")
	}
	return result, nil
}

func parseDefinitiveRejection(statusCode int, contentType string, body []byte) *RejectionError {
	// The website contract guarantees that this conflict is raised before the
	// one-time code is consumed or any binding credential is issued. Keep this
	// allowlist intentionally narrow; new codes require a matching server
	// transaction guarantee and a regression test before they are added.
	if statusCode != http.StatusConflict || !isJSON(contentType) || len(body) == 0 || len(body) > MaxResponseBytes {
		return nil
	}
	if err := rejectDuplicateKeys(body); err != nil {
		return nil
	}
	var envelope rejectionEnvelope
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil || onlyOneJSONValue(decoder) != nil {
		return nil
	}
	if envelope.Error.Code != "binding_already_active" || strings.TrimSpace(envelope.Error.Message) == "" || len(envelope.Error.Message) > 1024 {
		return nil
	}
	return &RejectionError{Code: envelope.Error.Code, StatusCode: statusCode}
}

func (r Request) Validate() error {
	if r.SchemaVersion != SchemaVersion || !uuidValue.MatchString(r.RequestID) || ValidateBindingCode(r.BindingCode) != nil || !safeID.MatchString(r.DeviceID) ||
		!versionValue.MatchString(r.AgentVersion) || !validHostname(r.Hostname) || !safeID.MatchString(r.NodeClaim.NodeRef) ||
		!versionValue.MatchString(r.NodeClaim.PVEVersion) || len(r.Capabilities) == 0 || len(r.Capabilities) > 64 {
		return errors.New("invalid binding request")
	}
	return validateUniqueValues(r.Capabilities, versionValue, "invalid binding request")
}

func (r Response) Validate(bindingEndpoint *url.URL) error {
	if bindingEndpoint == nil || r.SchemaVersion != SchemaVersion || !uuidValue.MatchString(r.BindingID) || !safeID.MatchString(r.DeviceID) || !safeID.MatchString(r.AgentRef) || !safeID.MatchString(r.CollectorRef) ||
		!safeID.MatchString(r.SourceRef) || !safeID.MatchString(r.ClusterRef) || !safeID.MatchString(r.NodeRef) || !safeID.MatchString(r.Site) ||
		r.CredentialEpoch == 0 || r.IssuedAt.IsZero() || len(r.AssignmentDocument) == 0 || !json.Valid(r.AssignmentDocument) || netpolicy.ValidateNetworkPolicy(r.NetworkPolicy) != nil {
		return errors.New("invalid binding response")
	}
	var assignment any
	if json.Unmarshal(r.AssignmentDocument, &assignment) != nil {
		return errors.New("invalid binding response")
	}
	if _, ok := assignment.(map[string]any); !ok {
		return errors.New("assignment document must be a JSON object")
	}
	for _, endpoint := range []string{r.Endpoints.Metering, r.Endpoints.Telemetry, r.Endpoints.Assignments, r.Endpoints.Commands, r.Endpoints.Receipts} {
		parsed, err := parseSecureURL(endpoint)
		if err != nil || !sameOrigin(bindingEndpoint, parsed) {
			return errors.New("binding response contains an unsafe endpoint")
		}
	}
	for _, credential := range []HMACCredential{r.HMACCredentials.Metering, r.HMACCredentials.Telemetry, r.HMACCredentials.Assignments, r.HMACCredentials.Commands, r.HMACCredentials.Receipts} {
		if !safeID.MatchString(credential.KeyID) || !validSecret(string(credential.Secret)) {
			return errors.New("binding response contains invalid credentials")
		}
	}
	if !safeID.MatchString(r.CommandSigningCredential.KeyID) || r.CommandSigningCredential.Algorithm != "ed25519" || !validEd25519Key(r.CommandSigningCredential.PublicKey) {
		return errors.New("binding response contains invalid command signing credential")
	}
	if len(r.AllowedActions) == 0 || len(r.AllowedActions) > 64 {
		return errors.New("binding response contains invalid allowed actions")
	}
	return validateUniqueValues(r.AllowedActions, actionValue, "binding response contains invalid allowed actions")
}

func securedClient(provided *http.Client, timeout time.Duration) (*http.Client, error) {
	if provided == nil {
		provided = &http.Client{}
	}
	result := *provided
	result.Timeout = timeout
	result.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if transport, ok := provided.Transport.(*http.Transport); ok {
		cloned := netpolicy.ApplyIPv4Only(transport.Clone())
		if cloned.TLSClientConfig == nil {
			cloned.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		} else {
			cloned.TLSClientConfig = cloned.TLSClientConfig.Clone()
			if cloned.TLSClientConfig.MinVersion < tls.VersionTLS12 {
				cloned.TLSClientConfig.MinVersion = tls.VersionTLS12
			}
		}
		result.Transport = cloned
	} else if provided.Transport == nil {
		transport := netpolicy.ApplyIPv4Only(http.DefaultTransport.(*http.Transport).Clone())
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		result.Transport = transport
	} else {
		return nil, errors.New("binding HTTP transport must be *http.Transport")
	}
	return &result, nil
}

func parseSecureURL(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" || netpolicy.ValidateIPv4URL(parsed) != nil {
		return nil, errors.New("invalid secure URL")
	}
	if parsed.Scheme == "https" {
		return parsed, nil
	}
	if parsed.Scheme == "http" && isLoopback(parsed.Hostname()) {
		return parsed, nil
	}
	return nil, errors.New("URL must use HTTPS")
}

func sameOrigin(first, second *url.URL) bool {
	return strings.EqualFold(first.Scheme, second.Scheme) && strings.EqualFold(first.Hostname(), second.Hostname()) && normalizedPort(first) == normalizedPort(second)
}

func normalizedPort(value *url.URL) string {
	if port := value.Port(); port != "" {
		return port
	}
	if value.Scheme == "https" {
		return "443"
	}
	return "80"
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() != nil && ip.IsLoopback()
}

func validHostname(value string) bool {
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

func validSecret(value string) bool {
	decoded, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(decoded) >= 16 && len(decoded) <= 4096
}

func validEd25519Key(value string) bool {
	decoded, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func validateUniqueValues(values []string, format *regexp.Regexp, message string) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !format.MatchString(value) {
			return errors.New(message)
		}
		if _, exists := seen[value]; exists {
			return errors.New(message)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func isJSON(contentType string) bool {
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	return mediaType == "application/json"
}

func onlyOneJSONValue(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("binding response must contain one JSON object")
	}
	return nil
}

// rejectDuplicateKeys is required before typed decoding because encoding/json
// otherwise silently keeps the final duplicate value.
func rejectDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("invalid JSON key")
				}
				if _, duplicate := seen[key]; duplicate {
					return errors.New("duplicate JSON key")
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err := decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err := decoder.Token()
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
