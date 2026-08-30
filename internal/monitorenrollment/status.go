package monitorenrollment

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ppflight/ppflight-agent/internal/netpolicy"
	"github.com/ppflight/ppflight-agent/internal/protocol"
)

const StatusPath = "/internal/v1/monitoring/agents/status"

type StatusResponse struct {
	SchemaVersion           int              `json:"schemaVersion"`
	BindingID               string           `json:"bindingId"`
	DeviceID                string           `json:"deviceId"`
	MonitoringAgentRef      string           `json:"monitoringAgentRef"`
	Status                  string           `json:"status"`
	CredentialEpoch         protocol.Counter `json:"credentialEpoch"`
	LastVerifiedAt          *time.Time       `json:"lastVerifiedAt"`
	LastTelemetryReceivedAt *time.Time       `json:"lastTelemetryReceivedAt"`
	LastTelemetryBatchID    *string          `json:"lastTelemetryBatchId"`
	TelemetryStale          bool             `json:"telemetryStale"`
	LastAuditReceivedAt     *time.Time       `json:"lastAuditReceivedAt"`
	LastAuditBatchID        *string          `json:"lastAuditBatchId"`
	AuditStale              bool             `json:"auditStale"`
	ServerTime              time.Time        `json:"serverTime"`
}

type StatusExpected struct {
	BindingID          string
	DeviceID           string
	MonitoringAgentRef string
	CredentialEpoch    uint64
}

type StatusClientConfig struct {
	BindingEndpoint string
	Credential      HMACCredential
	NetworkPolicy   netpolicy.NetworkPolicy
	HTTPClient      *http.Client
	Timeout         time.Duration
	Now             func() time.Time
}

type StatusClient struct {
	endpoint *url.URL
	keyID    string
	secret   []byte
	http     *http.Client
	now      func() time.Time
}

func NewStatusClient(cfg StatusClientConfig) (*StatusClient, error) {
	binding, err := secureURL(cfg.BindingEndpoint)
	if err != nil {
		return nil, errors.New("monitoring status binding origin is invalid")
	}
	endpoint := *binding
	endpoint.Path, endpoint.RawPath, endpoint.RawQuery, endpoint.Fragment = StatusPath, "", "", ""
	secret, err := base64.StdEncoding.Strict().DecodeString(string(cfg.Credential.Secret))
	if cfg.Credential.Algorithm != "hmac-sha256" || cfg.Credential.SecretEncoding != "base64" || !safeID.MatchString(cfg.Credential.KeyID) || err != nil || len(secret) < 16 || len(secret) > 4096 {
		return nil, errors.New("monitoring status credential is invalid")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if err := netpolicy.ValidateNetworkPolicy(cfg.NetworkPolicy); err != nil {
		return nil, errors.New("monitoring status network policy is invalid")
	}
	client, err := secureClientWithAllowlist(cfg.HTTPClient, cfg.Timeout, cfg.NetworkPolicy.ServerIPv4Allowlist)
	if err != nil {
		return nil, err
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &StatusClient{endpoint: &endpoint, keyID: cfg.Credential.KeyID, secret: secret, http: client, now: cfg.Now}, nil
}

func (c *StatusClient) Get(ctx context.Context, expected StatusExpected) (StatusResponse, error) {
	if c == nil || c.endpoint == nil || c.http == nil {
		return StatusResponse{}, errors.New("monitoring status client is not initialized")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint.String(), nil)
	if err != nil {
		return StatusResponse{}, errors.New("create monitoring status request")
	}
	request.Header.Set("Accept", "application/json")
	if err := protocol.SignRequest(request, nil, c.keyID, c.secret, c.now().UTC(), ""); err != nil {
		return StatusResponse{}, errors.New("sign monitoring status request")
	}
	response, err := c.http.Do(request)
	if err != nil {
		return StatusResponse{}, errors.New("monitoring status request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
	if err != nil || len(body) > MaxResponseBytes {
		return StatusResponse{}, errors.New("monitoring status response is invalid")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return StatusResponse{}, fmt.Errorf("monitoring status service returned HTTP %d", response.StatusCode)
	}
	if !isJSON(response.Header.Get("Content-Type")) || rejectDuplicateKeys(body) != nil || requireMonitoringStatusFields(body) != nil {
		return StatusResponse{}, errors.New("monitoring status response is not strict JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var result StatusResponse
	if err := decoder.Decode(&result); err != nil {
		return StatusResponse{}, errors.New("monitoring status response is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return StatusResponse{}, errors.New("monitoring status response must contain one object")
	}
	if err := result.Validate(expected, c.now().UTC()); err != nil {
		return StatusResponse{}, err
	}
	return result, nil
}

// requireMonitoringStatusFields keeps nullable fields mandatory in the wire
// shape. Unavailable observations are represented by JSON null; omission,
// substitution, and extension all fail closed.
func requireMonitoringStatusFields(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var object map[string]json.RawMessage
	if err := decoder.Decode(&object); err != nil || object == nil {
		return errors.New("monitoring status response must be an object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("monitoring status response must contain one object")
	}
	required := [...]string{
		"schemaVersion", "bindingId", "deviceId", "monitoringAgentRef", "status",
		"credentialEpoch", "lastVerifiedAt", "lastTelemetryReceivedAt",
		"lastTelemetryBatchId", "telemetryStale", "lastAuditReceivedAt",
		"lastAuditBatchId", "auditStale", "serverTime",
	}
	if len(object) != len(required) {
		return errors.New("monitoring status response has the wrong field set")
	}
	for _, key := range required {
		if _, present := object[key]; !present {
			return errors.New("monitoring status response is missing a required field")
		}
	}
	return nil
}

func (r StatusResponse) Validate(expected StatusExpected, now time.Time) error {
	if r.SchemaVersion != SchemaVersion || !uuidValue.MatchString(r.BindingID) || !safeID.MatchString(r.DeviceID) || !safeID.MatchString(r.MonitoringAgentRef) || r.ServerTime.IsZero() || uint64(r.CredentialEpoch) == 0 {
		return errors.New("monitoring status response identity is invalid")
	}
	switch r.Status {
	case "active", "stale", "revoked", "degraded":
	default:
		return errors.New("monitoring status response state is invalid")
	}
	if r.BindingID != expected.BindingID || r.DeviceID != expected.DeviceID || r.MonitoringAgentRef != expected.MonitoringAgentRef || uint64(r.CredentialEpoch) != expected.CredentialEpoch {
		return errors.New("monitoring status response does not match the local whitelist")
	}
	if delta := now.Sub(r.ServerTime); delta > 5*time.Minute || delta < -5*time.Minute {
		return errors.New("monitoring status server time is outside allowed skew")
	}
	for _, value := range []*string{r.LastTelemetryBatchID, r.LastAuditBatchID} {
		if value != nil && !uuidValue.MatchString(*value) {
			return errors.New("monitoring status response batch identity is invalid")
		}
	}
	for _, value := range []*time.Time{r.LastVerifiedAt, r.LastTelemetryReceivedAt, r.LastAuditReceivedAt} {
		if value != nil && value.IsZero() {
			return errors.New("monitoring status response contains a zero timestamp")
		}
	}
	return nil
}

func isJSON(value string) bool {
	mediaType := strings.TrimSpace(value)
	if index := strings.IndexByte(mediaType, ';'); index >= 0 {
		mediaType = mediaType[:index]
	}
	return strings.EqualFold(strings.TrimSpace(mediaType), "application/json")
}
