package enrollment

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
	"time"

	"github.com/ppflight/ppflight-agent/internal/netpolicy"
	"github.com/ppflight/ppflight-agent/internal/protocol"
)

const StatusPath = "/internal/v1/agents/status"

// StatusResponse is the exact website binding/channel status contract. It is
// read-only and contains no credential or command payload material.
type StatusResponse struct {
	SchemaVersion          int              `json:"schemaVersion"`
	BindingID              string           `json:"bindingId"`
	DeviceID               string           `json:"deviceId"`
	AgentRef               string           `json:"agentRef"`
	Status                 string           `json:"status"`
	CredentialEpoch        protocol.Counter `json:"credentialEpoch"`
	AssignmentRevision     protocol.Counter `json:"assignmentRevision"`
	LastVerifiedAt         *time.Time       `json:"lastVerifiedAt"`
	LastAssignmentIssuedAt *time.Time       `json:"lastAssignmentIssuedAt"`
	LastCommandIssuedAt    *time.Time       `json:"lastCommandIssuedAt"`
	LastReceiptReceivedAt  *time.Time       `json:"lastReceiptReceivedAt"`
	LastReceiptCommandID   *string          `json:"lastReceiptCommandId"`
	CommandChannelStale    bool             `json:"commandChannelStale"`
	ServerTime             time.Time        `json:"serverTime"`
}

type StatusExpected struct {
	BindingID          string
	DeviceID           string
	AgentRef           string
	CredentialEpoch    uint64
	AssignmentRevision uint64
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
	binding, err := parseSecureURL(cfg.BindingEndpoint)
	if err != nil {
		return nil, errors.New("website status binding origin is invalid")
	}
	endpoint := *binding
	endpoint.Path, endpoint.RawPath, endpoint.RawQuery, endpoint.Fragment, endpoint.ForceQuery = StatusPath, "", "", "", false
	secret, err := base64.StdEncoding.Strict().DecodeString(string(cfg.Credential.Secret))
	if !safeID.MatchString(cfg.Credential.KeyID) || err != nil || len(secret) < 16 || len(secret) > 4096 {
		return nil, errors.New("website status credential is invalid")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if err := netpolicy.ValidateNetworkPolicy(cfg.NetworkPolicy); err != nil {
		return nil, errors.New("website status network policy is invalid")
	}
	client, err := securedClient(cfg.HTTPClient, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &StatusClient{endpoint: &endpoint, keyID: cfg.Credential.KeyID, secret: secret, http: client, now: cfg.Now}, nil
}

// Get sends a signed GET with no query and no body. The Commands credential is
// supplied by the caller; this package never falls back to another endpoint's
// credential.
func (c *StatusClient) Get(ctx context.Context, expected StatusExpected) (StatusResponse, error) {
	if c == nil || c.endpoint == nil || c.http == nil {
		return StatusResponse{}, errors.New("website status client is not initialized")
	}
	now := c.now().UTC()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint.String(), nil)
	if err != nil {
		return StatusResponse{}, errors.New("create website status request")
	}
	request.Header.Set("Accept", "application/json")
	if err := protocol.SignRequest(request, nil, c.keyID, c.secret, now, ""); err != nil {
		return StatusResponse{}, errors.New("sign website status request")
	}
	response, err := c.http.Do(request)
	if err != nil {
		return StatusResponse{}, errors.New("website status request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
	if err != nil || len(body) > MaxResponseBytes {
		return StatusResponse{}, errors.New("website status response is invalid")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return StatusResponse{}, fmt.Errorf("website status service returned HTTP %d", response.StatusCode)
	}
	if !isJSON(response.Header.Get("Content-Type")) || rejectStatusDuplicateKeys(body) != nil || requireWebsiteStatusFields(body) != nil {
		return StatusResponse{}, errors.New("website status response is not strict JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var result StatusResponse
	if err := decoder.Decode(&result); err != nil {
		return StatusResponse{}, errors.New("website status response is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return StatusResponse{}, errors.New("website status response must contain one object")
	}
	if err := result.Validate(expected, now); err != nil {
		return StatusResponse{}, err
	}
	return result, nil
}

// requireWebsiteStatusFields makes nullable fields structurally required. A
// server must encode an unavailable value as JSON null rather than silently
// dropping the field, so every implementation authenticates the same frozen
// response shape.
func requireWebsiteStatusFields(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var object map[string]json.RawMessage
	if err := decoder.Decode(&object); err != nil || object == nil {
		return errors.New("website status response must be an object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("website status response must contain one object")
	}
	required := [...]string{
		"schemaVersion", "bindingId", "deviceId", "agentRef", "status",
		"credentialEpoch", "assignmentRevision", "lastVerifiedAt",
		"lastAssignmentIssuedAt", "lastCommandIssuedAt", "lastReceiptReceivedAt",
		"lastReceiptCommandId", "commandChannelStale", "serverTime",
	}
	if len(object) != len(required) {
		return errors.New("website status response has the wrong field set")
	}
	for _, key := range required {
		if _, present := object[key]; !present {
			return errors.New("website status response is missing a required field")
		}
	}
	return nil
}

func (r StatusResponse) Validate(expected StatusExpected, now time.Time) error {
	if !uuidValue.MatchString(expected.BindingID) || !safeID.MatchString(expected.DeviceID) || !safeID.MatchString(expected.AgentRef) || expected.CredentialEpoch == 0 || expected.AssignmentRevision == 0 {
		return errors.New("website status local identity is invalid")
	}
	if r.SchemaVersion != SchemaVersion || !uuidValue.MatchString(r.BindingID) || !safeID.MatchString(r.DeviceID) || !safeID.MatchString(r.AgentRef) || uint64(r.CredentialEpoch) == 0 || uint64(r.AssignmentRevision) == 0 || !validStatusTime(r.ServerTime) {
		return errors.New("website status response identity is invalid")
	}
	switch r.Status {
	case "active", "stale", "revoked", "degraded":
	default:
		return errors.New("website status response state is invalid")
	}
	if r.BindingID != expected.BindingID || r.DeviceID != expected.DeviceID || r.AgentRef != expected.AgentRef || uint64(r.CredentialEpoch) != expected.CredentialEpoch || uint64(r.AssignmentRevision) != expected.AssignmentRevision {
		return errors.New("website status response does not match the local whitelist")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if delta := now.Sub(r.ServerTime); delta > 5*time.Minute || delta < -5*time.Minute {
		return errors.New("website status server time is outside allowed skew")
	}
	for _, value := range []*time.Time{r.LastVerifiedAt, r.LastAssignmentIssuedAt, r.LastCommandIssuedAt, r.LastReceiptReceivedAt} {
		if value != nil && !validStatusTime(*value) {
			return errors.New("website status response contains an invalid timestamp")
		}
	}
	if r.LastReceiptCommandID != nil && !safeID.MatchString(*r.LastReceiptCommandID) {
		return errors.New("website status response receipt command identity is invalid")
	}
	return nil
}

func validStatusTime(value time.Time) bool {
	if value.IsZero() {
		return false
	}
	_, offset := value.Zone()
	return offset == 0
}

// encoding/json accepts the last duplicate key. Reject duplicates at every
// nesting level before typed decoding so different implementations cannot
// interpret an authenticated status response differently.
func rejectStatusDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 16 {
			return errors.New("website status JSON nesting is too deep")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("website status JSON key is invalid")
				}
				if _, duplicate := seen[key]; duplicate {
					return errors.New("website status JSON contains a duplicate key")
				}
				seen[key] = struct{}{}
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("website status JSON is invalid")
		}
	}
	if err := walk(1); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("website status JSON contains trailing data")
	}
	return nil
}
