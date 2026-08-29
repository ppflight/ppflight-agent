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
	"strconv"
	"strings"
	"time"

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
	Compression string
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
	Now            func() time.Time
	BaseDelay      time.Duration
	MaxDelay       time.Duration
	TLSDelay       time.Duration
	// Jitter returns a delay in [0, maximum]. Inject a deterministic function
	// in tests; nil uses full jitter to avoid synchronized retry storms.
	Jitter func(maximum time.Duration) time.Duration
}

type Uploader struct {
	destination Destination
	queue       Queue
	client      *http.Client
	now         func() time.Time
	baseDelay   time.Duration
	maxDelay    time.Duration
	tlsDelay    time.Duration
	jitter      func(maximum time.Duration) time.Duration
}

func New(config Config) (*Uploader, error) {
	if config.Destination.ID == "" || config.Destination.Endpoint == "" || config.Queue == nil {
		return nil, errors.New("destination ID, endpoint and queue are required")
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
		config.HTTPClient = secureHTTPClient(config.RequestTimeout)
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
	return &Uploader{destination: config.Destination, queue: config.Queue, client: config.HTTPClient, now: config.Now, baseDelay: config.BaseDelay, maxDelay: config.MaxDelay, tlsDelay: config.TLSDelay, jitter: config.Jitter}, nil
}

type Result struct {
	Delivered  bool
	Pending    bool
	BatchID    string
	StatusCode int
	RetryAt    time.Time
	Err        error
}

// DeliverOne makes at most one request. Each destination owns an independent
// Queue, so one endpoint can never acknowledge another endpoint's delivery.
func (u *Uploader) DeliverOne(ctx context.Context) Result {
	item, ok := u.queue.Next(u.now())
	if !ok {
		return Result{}
	}
	result := Result{Pending: true, BatchID: item.BatchID}
	payload, err := encodePayload(item.Payload, u.destination.Compression)
	if err != nil {
		return u.retry(item, result, 0, err, time.Time{}, false)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.destination.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return u.retry(item, result, 0, err, time.Time{}, false)
	}
	req.Header.Set("Content-Type", "application/json")
	if u.destination.Compression == "gzip" {
		req.Header.Set("Content-Encoding", "gzip")
	}
	req.Header.Set("Idempotency-Key", item.BatchID)
	switch u.destination.AuthMode {
	case AuthHMACSHA256:
		if err := protocol.SignRequest(req, payload, u.destination.KeyID, u.destination.Secret, u.now(), ""); err != nil {
			return u.retry(item, result, 0, err, time.Time{}, false)
		}
	case AuthBearer:
		req.Header.Set("Authorization", "Bearer "+u.destination.BearerToken)
	}
	response, err := u.client.Do(req)
	if err != nil {
		return u.retry(item, result, 0, err, time.Time{}, isTLSError(err))
	}
	defer response.Body.Close()
	apiResponse, bodyErr := parseAPIResponse(response.Body)
	result.StatusCode = response.StatusCode
	if bodyErr != nil {
		if response.StatusCode >= 200 && response.StatusCode < 300 || retryableStatus(response.StatusCode) {
			return u.retry(item, result, response.StatusCode, bodyErr, retryAfterAt(response.Header.Get("Retry-After"), u.now()), false)
		}
		return u.quarantine(item, result, bodyErr.Error())
	}
	duplicate := response.StatusCode == http.StatusConflict && strings.EqualFold(apiResponse.Code, "DUPLICATE")
	if (response.StatusCode >= 200 && response.StatusCode < 300) || duplicate {
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

const maxResponseBytes = 64 << 10

type apiResponse struct {
	Code    string `json:"code"`
	Error   string `json:"error"`
	Message string `json:"message"`
}

func (r apiResponse) message(status int) string {
	for _, text := range []string{r.Message, r.Error, r.Code} {
		if strings.TrimSpace(text) != "" {
			return fmt.Sprintf("HTTP %d: %s", status, text)
		}
	}
	return fmt.Sprintf("HTTP %d", status)
}
func parseAPIResponse(body io.Reader) (apiResponse, error) {
	raw, err := io.ReadAll(io.LimitReader(body, maxResponseBytes+1))
	if err != nil {
		return apiResponse{}, fmt.Errorf("read API response: %w", err)
	}
	if len(raw) > maxResponseBytes {
		return apiResponse{}, errors.New("API response exceeds 64 KiB")
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

func secureHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	}
	transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	return &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func isTLSError(err error) bool {
	var unknownAuthority x509.UnknownAuthorityError
	message := strings.ToLower(err.Error())
	return errors.As(err, &unknownAuthority) || strings.Contains(message, "tls") || strings.Contains(message, "x509")
}

func IsNetworkError(err error) bool { var netErr net.Error; return errors.As(err, &netErr) }
