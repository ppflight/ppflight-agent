// Package assignment securely refreshes website-issued assignment documents.
// It intentionally returns a verified result only; the caller owns durable,
// atomic persistence of the document and the refresh state.
package assignment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ppflight/ppflight-agent/internal/enrollment"
	"github.com/ppflight/ppflight-agent/internal/inventory"
	"github.com/ppflight/ppflight-agent/internal/netpolicy"
	"github.com/ppflight/ppflight-agent/internal/protocol"
)

const (
	SchemaVersion    = 1
	MaxResponseBytes = 4 << 20
	MaxWait          = 25 * time.Second
	MaxValidity      = 24 * time.Hour
)

var ErrNoChange = errors.New("assignment long poll returned no change")

var safeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{1,191}$`)

// State is the durable state supplied by, and later atomically persisted by,
// the caller. Cursor is opaque: its order is represented by Revision.
type State struct {
	Revision uint64
	Cursor   string
}

// Config holds the endpoint-specific assignment credential returned during
// enrollment and an injected assignment-signing public key. The public key is
// deliberately separate from the command-signing credential: deployments may
// rotate these keys independently.
type Config struct {
	Endpoint         string
	AgentRef         string
	DeviceID         string
	ClusterRef       string
	Credential       enrollment.HMACCredential
	SigningKeyID     string
	SigningPublicKey ed25519.PublicKey
	Wait             time.Duration
	Timeout          time.Duration
	MaxClockSkew     time.Duration
	HTTPClient       *http.Client
	// ServerIPv4Allowlist is a deprecated no-op kept only for source
	// compatibility with local RC callers. It is never stored or dialed.
	ServerIPv4Allowlist []string
	Now                 func() time.Time
	// AllowLoopbackHTTP exists only for hermetic test-mode Agent runs. Public
	// endpoints remain HTTPS-only and production never enables this option.
	AllowLoopbackHTTP bool
}

// Client is safe for concurrent use. Its credential is copied at construction
// and is never included in errors or results.
type Client struct {
	endpoint     *url.URL
	agentRef     string
	deviceID     string
	clusterRef   string
	keyID        string
	secret       []byte
	signingKeyID string
	publicKey    ed25519.PublicKey
	wait         time.Duration
	maxSkew      time.Duration
	http         *http.Client
	now          func() time.Time
}

// Result is ready for the upper layer to atomically persist. DocumentRaw is
// retained so persistence can preserve exactly the bytes that were hashed and
// signed by the website.
type Result struct {
	Document    inventory.Document
	DocumentRaw json.RawMessage
	State       State
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

// Bundle is the strict wire envelope returned by the assignments endpoint.
// Signature is base64 Ed25519 over CanonicalPayload. ContentSHA256 is the
// lowercase SHA-256 hex digest of the exact assignmentDocument JSON bytes.
type Bundle struct {
	SchemaVersion      int             `json:"schemaVersion"`
	AgentRef           string          `json:"agentRef"`
	DeviceID           string          `json:"deviceId"`
	ClusterRef         string          `json:"clusterRef"`
	Cursor             string          `json:"cursor"`
	Revision           uint64          `json:"revision"`
	IssuedAt           time.Time       `json:"issuedAt"`
	ExpiresAt          time.Time       `json:"expiresAt"`
	Nonce              string          `json:"nonce"`
	ContentSHA256      string          `json:"contentSha256"`
	SigningKeyID       string          `json:"signingKeyId"`
	AssignmentDocument json.RawMessage `json:"assignmentDocument"`
	Signature          string          `json:"signature"`
}

// CanonicalPayload is the stable byte sequence that the website signs. Every
// line is a validated scalar or digest, avoiding ambiguous JSON reformatting.
func (b Bundle) CanonicalPayload() ([]byte, error) {
	if !safeID.MatchString(b.AgentRef) || !safeID.MatchString(b.DeviceID) || !safeID.MatchString(b.ClusterRef) ||
		!safeID.MatchString(b.Cursor) || !validNonce(b.Nonce) || !safeID.MatchString(b.SigningKeyID) ||
		len(b.ContentSHA256) != sha256.Size*2 || !isLowerHex(b.ContentSHA256) || b.Revision == 0 || b.IssuedAt.IsZero() || b.ExpiresAt.IsZero() {
		return nil, errors.New("invalid assignment signature payload")
	}
	return []byte(strings.Join([]string{
		"ppflight-assignment-bundle-v1", strconv.Itoa(b.SchemaVersion), b.AgentRef, b.DeviceID, b.ClusterRef,
		b.Cursor, strconv.FormatUint(b.Revision, 10), b.IssuedAt.UTC().Format(time.RFC3339Nano),
		b.ExpiresAt.UTC().Format(time.RFC3339Nano), b.Nonce, b.ContentSHA256, b.SigningKeyID,
	}, "\n")), nil
}

func NewClient(cfg Config) (*Client, error) {
	endpoint, err := url.Parse(cfg.Endpoint)
	secureScheme := err == nil && endpoint.Scheme == "https"
	testLoopback := err == nil && cfg.AllowLoopbackHTTP && endpoint.Scheme == "http" && isIPv4Loopback(endpoint.Hostname())
	if err != nil || (!secureScheme && !testLoopback) || endpoint.Host == "" || endpoint.User != nil || endpoint.Fragment != "" || endpoint.RawQuery != "" || netpolicy.ValidateIPv4URL(endpoint) != nil {
		return nil, errors.New("assignment endpoint must be an HTTPS URL without credentials, fragment, or query")
	}
	if !safeID.MatchString(cfg.AgentRef) || !safeID.MatchString(cfg.DeviceID) || !safeID.MatchString(cfg.ClusterRef) ||
		!safeID.MatchString(cfg.Credential.KeyID) || !safeID.MatchString(cfg.SigningKeyID) || len(cfg.SigningPublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("invalid assignment client identity or credential")
	}
	secret, err := base64.StdEncoding.DecodeString(string(cfg.Credential.Secret))
	if err != nil || len(secret) < 16 || len(secret) > 4096 {
		return nil, errors.New("invalid assignment HMAC credential")
	}
	if cfg.Wait < 0 || cfg.Wait > MaxWait {
		return nil, fmt.Errorf("assignment wait must be between 0 and %s", MaxWait)
	}
	if cfg.Wait == 0 {
		cfg.Wait = MaxWait
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = cfg.Wait + 5*time.Second
	}
	if cfg.Timeout <= cfg.Wait || cfg.Timeout > MaxWait+30*time.Second {
		return nil, errors.New("assignment timeout must exceed wait and remain bounded")
	}
	if cfg.MaxClockSkew <= 0 {
		cfg.MaxClockSkew = 5 * time.Minute
	}
	if cfg.MaxClockSkew > time.Hour {
		return nil, errors.New("assignment clock skew is too large")
	}
	client, err := hardenedHTTPClient(cfg.HTTPClient, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Client{endpoint: endpoint, agentRef: cfg.AgentRef, deviceID: cfg.DeviceID, clusterRef: cfg.ClusterRef,
		keyID: cfg.Credential.KeyID, secret: append([]byte(nil), secret...), signingKeyID: cfg.SigningKeyID,
		publicKey: append(ed25519.PublicKey(nil), cfg.SigningPublicKey...), wait: cfg.Wait, maxSkew: cfg.MaxClockSkew,
		http: client, now: cfg.Now}, nil
}

func isIPv4Loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() != nil && ip.IsLoopback()
}

// Refresh uses the documented GET assignments contract. It sends the complete
// identity and both opaque cursor and monotonic revision; the request is HMAC
// signed using only the enrollment assignment credential.
func (c *Client) Refresh(ctx context.Context, previous State) (Result, error) {
	if c == nil || c.endpoint == nil || c.http == nil {
		return Result{}, errors.New("assignment client is not initialized")
	}
	if previous.Cursor != "" && !safeID.MatchString(previous.Cursor) {
		return Result{}, errors.New("invalid previous assignment cursor")
	}
	endpoint := *c.endpoint
	query := endpoint.Query()
	query.Set("agentRef", c.agentRef)
	query.Set("deviceId", c.deviceID)
	query.Set("clusterRef", c.clusterRef)
	query.Set("cursor", previous.Cursor)
	query.Set("version", strconv.FormatUint(previous.Revision, 10))
	query.Set("afterRevision", strconv.FormatUint(previous.Revision, 10))
	query.Set("wait", strconv.Itoa(int(c.wait.Seconds())))
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return Result{}, errors.New("create assignment request")
	}
	req.Header.Set("Accept", "application/json")
	if err := protocol.SignRequest(req, nil, c.keyID, c.secret, c.now(), ""); err != nil {
		return Result{}, errors.New("sign assignment request")
	}
	response, err := c.http.Do(req)
	if err != nil {
		return Result{}, errors.New("assignment request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
	if err != nil {
		return Result{}, errors.New("read assignment response")
	}
	if len(body) > MaxResponseBytes {
		return Result{}, errors.New("assignment response exceeds maximum size")
	}
	if response.StatusCode == http.StatusNoContent || response.StatusCode == http.StatusNotModified {
		return Result{}, ErrNoChange
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return Result{}, fmt.Errorf("assignment service returned HTTP %d", response.StatusCode)
	}
	if !isJSON(response.Header.Get("Content-Type")) {
		return Result{}, errors.New("assignment response must be application/json")
	}
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return Result{}, errors.New("assignment response is not strict JSON")
	}
	var bundle Bundle
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bundle); err != nil {
		return Result{}, errors.New("assignment response is not a valid JSON object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Result{}, errors.New("assignment response must contain one JSON object")
	}
	return c.verify(bundle, previous)
}

func (c *Client) verify(bundle Bundle, previous State) (Result, error) {
	now := c.now().UTC()
	if bundle.SchemaVersion != SchemaVersion || bundle.AgentRef != c.agentRef || bundle.DeviceID != c.deviceID || bundle.ClusterRef != c.clusterRef ||
		bundle.SigningKeyID != c.signingKeyID || !safeID.MatchString(bundle.Cursor) || !validNonce(bundle.Nonce) ||
		bundle.Revision <= previous.Revision || (previous.Cursor != "" && bundle.Cursor == previous.Cursor) ||
		bundle.IssuedAt.After(now.Add(c.maxSkew)) || !bundle.ExpiresAt.After(bundle.IssuedAt) || !bundle.ExpiresAt.After(now) ||
		bundle.ExpiresAt.Sub(bundle.IssuedAt) > MaxValidity || len(bundle.AssignmentDocument) == 0 || !json.Valid(bundle.AssignmentDocument) {
		return Result{}, errors.New("invalid or stale assignment bundle")
	}
	hash := sha256.Sum256(bundle.AssignmentDocument)
	if !strings.EqualFold(bundle.ContentSHA256, hex.EncodeToString(hash[:])) {
		return Result{}, errors.New("assignment content hash mismatch")
	}
	payload, err := bundle.CanonicalPayload()
	if err != nil {
		return Result{}, err
	}
	signature, err := base64.StdEncoding.DecodeString(bundle.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(c.publicKey, payload, signature) {
		return Result{}, errors.New("assignment signature verification failed")
	}
	document, err := inventory.Parse(bundle.AssignmentDocument, c.clusterRef)
	if err != nil {
		return Result{}, errors.New("assignment document is invalid")
	}
	if !document.IssuedAt.Equal(bundle.IssuedAt) {
		return Result{}, errors.New("assignment document does not match signed bundle")
	}
	return Result{Document: document, DocumentRaw: append(json.RawMessage(nil), bundle.AssignmentDocument...), State: State{Revision: bundle.Revision, Cursor: bundle.Cursor}, IssuedAt: bundle.IssuedAt, ExpiresAt: bundle.ExpiresAt}, nil
}

func hardenedHTTPClient(provided *http.Client, timeout time.Duration) (*http.Client, error) {
	if provided == nil {
		provided = &http.Client{}
	}
	result := *provided
	result.Timeout = timeout
	result.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	var transport *http.Transport
	if provided.Transport == nil {
		transport = netpolicy.ApplyIPv4Only(http.DefaultTransport.(*http.Transport).Clone())
	} else {
		var ok bool
		transport, ok = provided.Transport.(*http.Transport)
		if !ok {
			return nil, errors.New("assignment HTTP transport must be *http.Transport")
		}
		transport = netpolicy.ApplyIPv4Only(transport.Clone())
	}
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
			transport.TLSClientConfig.MinVersion = tls.VersionTLS12
		}
	}
	result.Transport = transport
	return &result, nil
}

func isJSON(contentType string) bool {
	return strings.EqualFold(strings.TrimSpace(strings.Split(contentType, ";")[0]), "application/json")
}

func isLowerHex(value string) bool {
	for _, char := range value {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}

func validNonce(value string) bool {
	return len(value) >= 16 && len(value) <= 191 && safeID.MatchString(value)
}

// rejectDuplicateJSONKeys closes the gap in encoding/json, whose normal
// decoder accepts duplicate object keys and silently retains the last one.
func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := consumeJSONValue(decoder); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("trailing JSON value")
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch token := token.(type) {
	case json.Delim:
		switch token {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok {
					return errors.New("object key is not a string")
				}
				if _, exists := seen[name]; exists {
					return errors.New("duplicate JSON key")
				}
				seen[name] = struct{}{}
				if err := consumeJSONValue(decoder); err != nil {
					return err
				}
			}
			_, err := decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := consumeJSONValue(decoder); err != nil {
					return err
				}
			}
			_, err := decoder.Token()
			return err
		}
	}
	return nil
}
