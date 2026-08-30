// Package uploader delivers signed batches while leaving durable retry state in store.
package uploader

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ppflight/ppflight-agent/internal/netpolicy"
	"github.com/ppflight/ppflight-agent/internal/protocol"
	"github.com/ppflight/ppflight-agent/internal/store"
)

type AuthMode string

const (
	AuthHMACSHA256 AuthMode = "hmac-sha256"
	AuthBearer     AuthMode = "bearer"
	// AuthNone is for local/httptest endpoints only. Production validation is
	// performed by the top-level configuration package.
	AuthNone AuthMode = "none"
)

type Destination struct {
	ID          string
	Endpoint    string
	AuthMode    AuthMode
	KeyID       string
	Secret      []byte
	BearerToken string
	// CredentialEpoch is issued by the binding authority. Increasing it is the
	// only in-process way to clear an authentication circuit breaker.
	CredentialEpoch uint64
	Compression     string
	// ServerIPv4Allowlist is deprecated and ignored. It is not a wire field.
	ServerIPv4Allowlist []string
}

type Queue interface {
	Next(time.Time) (store.Item, bool)
	Ack(batchID string) error
	Nack(batchID string, next time.Time, reason string) error
	Quarantine(batchID, reason string) error
}

type Config struct {
	Destination    Destination
	Queue          Queue
	HTTPClient     *http.Client
	RequestTimeout time.Duration
	// MaxResponseBytes bounds API response bodies that must be inspected for
	// machine-readable errors. Zero (or a negative value) uses the 2 MiB
	// default; values above the 8 MiB hard limit are rejected by New.
	MaxResponseBytes     int64
	MaxCompressedBytes   int64
	MaxUncompressedBytes int64
	Now                  func() time.Time
	BaseDelay            time.Duration
	MaxDelay             time.Duration
	TLSDelay             time.Duration
	// Jitter returns a delay in [0, maximum]. Inject a deterministic function
	// in tests; nil uses full jitter to avoid synchronized retry storms.
	Jitter func(maximum time.Duration) time.Duration
}

type Uploader struct {
	mu                   sync.RWMutex
	destination          Destination
	authBlocked          bool
	queue                Queue
	client               *http.Client
	maxResponseBytes     int64
	maxCompressedBytes   int64
	maxUncompressedBytes int64
	now                  func() time.Time
	baseDelay            time.Duration
	maxDelay             time.Duration
	tlsDelay             time.Duration
	jitter               func(maximum time.Duration) time.Duration
}

var ErrAuthBlocked = errors.New("destination authentication is blocked pending credential rotation")

func New(config Config) (*Uploader, error) {
	if config.Destination.ID == "" || config.Destination.Endpoint == "" || config.Queue == nil {
		return nil, errors.New("destination ID, endpoint and queue are required")
	}
	parsedEndpoint, err := url.Parse(config.Destination.Endpoint)
	if err != nil || netpolicy.ValidateIPv4URL(parsedEndpoint) != nil {
		return nil, errors.New("destination endpoint must have an IPv4-capable host")
	}
	switch config.Destination.AuthMode {
	case AuthHMACSHA256:
		if config.Destination.KeyID == "" || len(config.Destination.Secret) == 0 {
			return nil, errors.New("HMAC key ID and secret are required")
		}
	case AuthBearer:
		if config.Destination.BearerToken == "" {
			return nil, errors.New("bearer token is required")
		}
	case AuthNone:
	default:
		return nil, fmt.Errorf("unknown authentication mode %q", config.Destination.AuthMode)
	}
	if config.Destination.Compression == "" {
		config.Destination.Compression = "none"
	}
	if config.Destination.Compression != "none" && config.Destination.Compression != "gzip" {
		return nil, fmt.Errorf("unknown compression %q", config.Destination.Compression)
	}
	if config.HTTPClient == nil {
		config.HTTPClient, err = secureHTTPClient(config.RequestTimeout)
		if err != nil {
			return nil, errors.New("destination HTTP client is invalid")
		}
	} else if transport, ok := config.HTTPClient.Transport.(*http.Transport); ok {
		clone := netpolicy.ApplyIPv4Only(transport.Clone())
		config.HTTPClient = cloneHTTPClient(config.HTTPClient, clone, config.RequestTimeout)
	} else if config.HTTPClient.Transport == nil {
		clone := netpolicy.ApplyIPv4Only(http.DefaultTransport.(*http.Transport).Clone())
		config.HTTPClient = cloneHTTPClient(config.HTTPClient, clone, config.RequestTimeout)
	} else {
		return nil, errors.New("uploader HTTP transport must be *http.Transport")
	}
	if config.MaxResponseBytes <= 0 {
		config.MaxResponseBytes = defaultMaxResponseBytes
	}
	if config.MaxResponseBytes > maxResponseBytesLimit {
		return nil, fmt.Errorf("uploader max response size exceeds %d bytes", maxResponseBytesLimit)
	}
	if config.MaxCompressedBytes <= 0 {
		config.MaxCompressedBytes = 64 << 20
	}
	if config.MaxUncompressedBytes <= 0 {
		config.MaxUncompressedBytes = 256 << 20
	}
	if config.MaxCompressedBytes > 64<<20 || config.MaxUncompressedBytes > 256<<20 || config.MaxUncompressedBytes < config.MaxCompressedBytes {
		return nil, errors.New("uploader request size limits are invalid")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.BaseDelay <= 0 {
		config.BaseDelay = time.Second
	}
	if config.MaxDelay <= 0 {
		config.MaxDelay = 5 * time.Minute
	}
	if config.TLSDelay <= 0 {
		config.TLSDelay = time.Hour
	}
	if config.Jitter == nil {
		config.Jitter = func(maximum time.Duration) time.Duration {
			if maximum <= 0 {
				return 0
			}
			return time.Duration(rand.Int64N(int64(maximum) + 1))
		}
	}
	config.Destination.Secret = append([]byte(nil), config.Destination.Secret...)
	return &Uploader{destination: config.Destination, queue: config.Queue, client: config.HTTPClient, maxResponseBytes: config.MaxResponseBytes, maxCompressedBytes: config.MaxCompressedBytes, maxUncompressedBytes: config.MaxUncompressedBytes, now: config.Now, baseDelay: config.BaseDelay, maxDelay: config.MaxDelay, tlsDelay: config.TLSDelay, jitter: config.Jitter}, nil
}

type Result struct {
	Delivered   bool
	Pending     bool
	BatchID     string
	StatusCode  int
	RetryAt     time.Time
	AuthBlocked bool
	Err         error
}

// DeliverOne makes at most one request. Each destination owns an independent
// Queue, so one endpoint can never acknowledge another endpoint's delivery.
func (u *Uploader) DeliverOne(ctx context.Context) Result {
	item, ok := u.queue.Next(u.now())
	if !ok {
		return Result{}
	}
	result := Result{Pending: true, BatchID: item.BatchID}
	destination, blocked := u.destinationState()
	if blocked {
		result.AuthBlocked, result.Err = true, ErrAuthBlocked
		return result
	}
	if int64(len(item.Payload)) > u.maxUncompressedBytes {
		return u.quarantine(item, result, "PAYLOAD_UNCOMPRESSED_TOO_LARGE")
	}
	payload, err := encodePayload(item.Payload, destination.Compression)
	if err != nil {
		return u.retry(item, result, 0, err, time.Time{}, false)
	}
	if int64(len(payload)) > u.maxCompressedBytes {
		return u.quarantine(item, result, "PAYLOAD_COMPRESSED_TOO_LARGE")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, destination.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return u.retry(item, result, 0, err, time.Time{}, false)
	}
	req.Header.Set("Content-Type", "application/json")
	if destination.Compression == "gzip" {
		req.Header.Set("Content-Encoding", "gzip")
	}
	req.Header.Set("Idempotency-Key", item.BatchID)
	switch destination.AuthMode {
	case AuthHMACSHA256:
		if err := protocol.SignRequest(req, payload, destination.KeyID, destination.Secret, u.now(), ""); err != nil {
			return u.retry(item, result, 0, err, time.Time{}, false)
		}
	case AuthBearer:
		req.Header.Set("Authorization", "Bearer "+destination.BearerToken)
	}
	response, err := u.client.Do(req)
	if err != nil {
		return u.retry(item, result, 0, err, time.Time{}, isTLSError(err))
	}
	defer response.Body.Close()
	result.StatusCode = response.StatusCode
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		u.blockAuthentication()
		result.AuthBlocked, result.Err = true, ErrAuthBlocked
		// Do not Nack or Quarantine. The queue head and every following batch stay
		// untouched until a newer credential epoch is installed.
		return result
	}
	// Success is determined by HTTP status. Response bodies on successful
	// uploads are advisory and cannot turn an accepted batch back into a retry.
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		if err := u.queue.Ack(item.BatchID); err != nil {
			result.Err = err
			return result
		}
		result.Delivered, result.Pending = true, false
		return result
	}
	apiResponse, bodyErr := parseAPIResponse(response.Body, u.maxResponseBytes)
	if bodyErr != nil {
		if retryableStatus(response.StatusCode) {
			return u.retry(item, result, response.StatusCode, bodyErr, retryAfterAt(response.Header.Get("Retry-After"), u.now()), false)
		}
		return u.quarantine(item, result, bodyErr.Error())
	}
	duplicate := response.StatusCode == http.StatusConflict && strings.EqualFold(apiResponse.machineCode(), "DUPLICATE")
	if duplicate {
		if err := u.queue.Ack(item.BatchID); err != nil {
			result.Err = err
			return result
		}
		result.Delivered, result.Pending = true, false
		return result
	}
	message := apiResponse.message(response.StatusCode)
	if retryableStatus(response.StatusCode) {
		return u.retry(item, result, response.StatusCode, errors.New(message), retryAfterAt(response.Header.Get("Retry-After"), u.now()), false)
	}
	return u.quarantine(item, result, message)
}

func (u *Uploader) destinationState() (Destination, bool) {
	u.mu.RLock()
	defer u.mu.RUnlock()
	value := u.destination
	value.Secret = append([]byte(nil), value.Secret...)
	return value, u.authBlocked
}

func (u *Uploader) blockAuthentication() {
	u.mu.Lock()
	u.authBlocked = true
	u.mu.Unlock()
}

// RotateCredentials installs credentials issued by the same destination's
// binding authority. A strictly newer epoch is required, preventing old
// credential material or a local rollback from reopening a blocked channel.
func (u *Uploader) RotateCredentials(epoch uint64, keyID string, secret []byte, bearer string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if epoch == 0 || epoch <= u.destination.CredentialEpoch {
		return errors.New("credential epoch did not advance")
	}
	switch u.destination.AuthMode {
	case AuthHMACSHA256:
		if strings.TrimSpace(keyID) == "" || len(secret) == 0 || bearer != "" {
			return errors.New("invalid HMAC credential rotation")
		}
		u.destination.KeyID = keyID
		u.destination.Secret = append(u.destination.Secret[:0], secret...)
	case AuthBearer:
		if strings.TrimSpace(bearer) == "" || keyID != "" || len(secret) != 0 {
			return errors.New("invalid bearer credential rotation")
		}
		u.destination.BearerToken = bearer
	case AuthNone:
		return errors.New("unauthenticated destination has no rotatable credential")
	}
	u.destination.CredentialEpoch = epoch
	u.authBlocked = false
	return nil
}

func (u *Uploader) AuthenticationBlocked() bool {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.authBlocked
}

func encodePayload(payload []byte, compression string) ([]byte, error) {
	if compression != "gzip" {
		return payload, nil
	}
	var output bytes.Buffer
	writer, err := gzip.NewWriterLevel(&output, gzip.BestSpeed)
	if err != nil {
		return nil, err
	}
	// A zero timestamp makes retries byte-for-byte deterministic, which keeps
	// the request signature stable for a fixed timestamp/nonce in tests.
	writer.Header.ModTime = time.Time{}
	writer.Header.OS = 255
	if _, err := writer.Write(payload); err != nil {
		_ = writer.Close()
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func (u *Uploader) quarantine(item store.Item, result Result, reason string) Result {
	if err := u.queue.Quarantine(item.BatchID, reason); err != nil {
		result.Err = fmt.Errorf("delivery rejected (%s), and dead-letter persistence failed: %w", reason, err)
		return result
	}
	result.Pending = false
	result.Err = errors.New(reason)
	return result
}

func (u *Uploader) retry(item store.Item, result Result, status int, cause error, retryAfter time.Time, tlsFailure bool) Result {
	delay := u.jitter(backoff(item.Attempts+1, u.baseDelay, u.maxDelay))
	if delay < 0 {
		delay = 0
	}
	if tlsFailure && delay < u.tlsDelay {
		delay = u.tlsDelay
	}
	next := u.now().Add(delay)
	if retryAfter.After(next) {
		next = retryAfter
	}
	if err := u.queue.Nack(item.BatchID, next, cause.Error()); err != nil {
		result.Err = fmt.Errorf("delivery failed (%v), and retry state failed: %w", cause, err)
		return result
	}
	result.StatusCode, result.RetryAt, result.Err = status, next, cause
	return result
}

func retryableStatus(status int) bool {
	return status == http.StatusRequestTimeout || status == http.StatusTooEarly || status == http.StatusTooManyRequests || status >= 500
}

func backoff(attempt int, base, maximum time.Duration) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	delay := base
	for i := 1; i < attempt && delay < maximum; i++ {
		if delay > maximum/2 {
			return maximum
		}
		delay *= 2
	}
	if delay > maximum {
		return maximum
	}
	return delay
}

func retryAfterAt(raw string, now time.Time) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	if seconds, err := strconv.Atoi(raw); err == nil && seconds >= 0 {
		return now.Add(time.Duration(seconds) * time.Second)
	}
	if timestamp, err := http.ParseTime(raw); err == nil {
		return timestamp
	}
	return time.Time{}
}

const (
	defaultMaxResponseBytes = int64(2 << 20)
	maxResponseBytesLimit   = int64(8 << 20)
)

type apiResponse struct {
	Code    string   `json:"code"`
	Error   apiError `json:"error"`
	Message string   `json:"message"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *apiError) UnmarshalJSON(raw []byte) error {
	trimmed := bytes.TrimSpace(raw)
	if bytes.Equal(trimmed, []byte("null")) {
		*e = apiError{}
		return nil
	}
	if len(trimmed) > 0 && trimmed[0] == '"' {
		var message string
		if err := json.Unmarshal(trimmed, &message); err != nil {
			return err
		}
		*e = apiError{Message: message}
		return nil
	}
	type plainAPIError apiError
	var nested plainAPIError
	if err := json.Unmarshal(trimmed, &nested); err != nil {
		return errors.New("API error must be an object or string")
	}
	*e = apiError(nested)
	return nil
}

// machineCode returns an unambiguous machine-readable error code. Conflicting
// flat and nested codes are deliberately treated as unknown so a contradictory
// 409 response can never acknowledge data as a duplicate.
func (r apiResponse) machineCode() string {
	flat := strings.TrimSpace(r.Code)
	nested := strings.TrimSpace(r.Error.Code)
	if flat != "" && nested != "" && !strings.EqualFold(flat, nested) {
		return ""
	}
	if nested != "" {
		return nested
	}
	return flat
}

func (r apiResponse) message(status int) string {
	code := strings.TrimSpace(r.Error.Code)
	if code == "" {
		code = strings.TrimSpace(r.Code)
	}
	detail := strings.TrimSpace(r.Error.Message)
	if detail == "" {
		detail = strings.TrimSpace(r.Message)
	}
	if code != "" && detail != "" {
		return fmt.Sprintf("HTTP %d: %s: %s", status, code, detail)
	}
	if detail != "" {
		return fmt.Sprintf("HTTP %d: %s", status, detail)
	}
	if code != "" {
		return fmt.Sprintf("HTTP %d: %s", status, code)
	}
	return fmt.Sprintf("HTTP %d", status)
}
func parseAPIResponse(body io.Reader, maxBytes int64) (apiResponse, error) {
	raw, err := io.ReadAll(io.LimitReader(body, maxBytes+1))
	if err != nil {
		return apiResponse{}, fmt.Errorf("read API response: %w", err)
	}
	if int64(len(raw)) > maxBytes {
		return apiResponse{}, fmt.Errorf("API response exceeds %d bytes", maxBytes)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return apiResponse{}, nil
	}
	var response apiResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		return apiResponse{}, fmt.Errorf("invalid JSON API response: %w", err)
	}
	return response, nil
}

func secureHTTPClient(timeout time.Duration) (*http.Client, error) {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	transport := netpolicy.ApplyIPv4Only(http.DefaultTransport.(*http.Transport).Clone())
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	}
	transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	return &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func cloneHTTPClient(source *http.Client, transport *http.Transport, timeout time.Duration) *http.Client {
	clone := *source
	if timeout > 0 {
		clone.Timeout = timeout
	}
	clone.Transport = transport
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &clone
}

func isTLSError(err error) bool {
	var unknownAuthority x509.UnknownAuthorityError
	message := strings.ToLower(err.Error())
	return errors.As(err, &unknownAuthority) || strings.Contains(message, "tls") || strings.Contains(message, "x509")
}

func IsNetworkError(err error) bool { var netErr net.Error; return errors.As(err, &netErr) }
