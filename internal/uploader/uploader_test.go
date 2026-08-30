package uploader

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/protocol"
	"github.com/ppflight/ppflight-agent/internal/store"
)

func TestAuthenticationFailureOpensCircuitWithoutLosingQueue(t *testing.T) {
	now := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)
	queue, err := store.Open(store.Config{Root: t.TempDir(), Destination: "monitor-auth", Kind: store.Telemetry, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"batch-auth-1", "batch-auth-2"} {
		if _, _, err := queue.Enqueue(id, []byte(`{"schemaVersion":1}`)); err != nil {
			t.Fatal(err)
		}
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get(protocol.HeaderKeyID) != "new" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":"CREDENTIAL_REVOKED"}`))
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read rotated request: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if err := protocol.VerifyRequest(r, body, func(string) ([]byte, error) { return []byte("new-secret"), nil }, protocol.VerifyOptions{Now: now}); err != nil {
			t.Errorf("verify rotated request: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	u, err := New(Config{Destination: Destination{ID: "monitor-auth", Endpoint: server.URL, AuthMode: AuthHMACSHA256, KeyID: "old", Secret: []byte("old-secret"), CredentialEpoch: 1, ServerIPv4Allowlist: []string{"127.0.0.1"}}, Queue: queue, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	first := u.DeliverOne(context.Background())
	if !first.AuthBlocked || !errors.Is(first.Err, ErrAuthBlocked) || queue.Len() != 2 || queue.Stats().DeadLetterItems != 0 || queue.Snapshot()[0].Attempts != 0 {
		t.Fatalf("first=%#v len=%d stats=%#v", first, queue.Len(), queue.Stats())
	}
	second := u.DeliverOne(context.Background())
	if !second.AuthBlocked || requests != 1 || queue.Len() != 2 {
		t.Fatalf("blocked retry made a request: result=%#v requests=%d len=%d", second, requests, queue.Len())
	}
	if err := u.RotateCredentials(1, "same", []byte("same-secret"), ""); err == nil {
		t.Fatal("accepted non-advancing credential epoch")
	}
	if err := u.RotateCredentials(2, "new", []byte("new-secret"), ""); err != nil {
		t.Fatal(err)
	}
	resumed := u.DeliverOne(context.Background())
	if !resumed.Delivered || resumed.AuthBlocked || resumed.Err != nil || queue.Len() != 1 || requests != 2 {
		t.Fatalf("resumed=%#v requests=%d len=%d", resumed, requests, queue.Len())
	}
}

func TestForbiddenAlsoOpensAuthenticationCircuit(t *testing.T) {
	now := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)
	queue, err := store.Open(store.Config{Root: t.TempDir(), Destination: "forbidden", Kind: store.Telemetry, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"batch-forbidden-1", "batch-forbidden-2"} {
		if _, _, err := queue.Enqueue(id, []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("Authorization") != "Bearer replacement" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	u, err := New(Config{Destination: Destination{ID: "forbidden", Endpoint: server.URL, AuthMode: AuthBearer, BearerToken: "revoked", CredentialEpoch: 4, ServerIPv4Allowlist: []string{"127.0.0.1"}}, Queue: queue, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	result := u.DeliverOne(context.Background())
	if !result.AuthBlocked || !errors.Is(result.Err, ErrAuthBlocked) || !u.AuthenticationBlocked() || queue.Len() != 2 || queue.Stats().DeadLetterItems != 0 || queue.Snapshot()[0].Attempts != 0 {
		t.Fatalf("result=%#v stats=%#v", result, queue.Stats())
	}
	blocked := u.DeliverOne(context.Background())
	if !blocked.AuthBlocked || requests != 1 || queue.Len() != 2 {
		t.Fatalf("blocked=%#v requests=%d len=%d", blocked, requests, queue.Len())
	}
	for _, epoch := range []uint64{3, 4} {
		if err := u.RotateCredentials(epoch, "", nil, "replacement"); err == nil {
			t.Fatalf("accepted non-advancing credential epoch %d", epoch)
		}
	}
	if err := u.RotateCredentials(5, "", nil, "replacement"); err != nil {
		t.Fatal(err)
	}
	resumed := u.DeliverOne(context.Background())
	if !resumed.Delivered || resumed.AuthBlocked || resumed.Err != nil || u.AuthenticationBlocked() || queue.Len() != 1 || requests != 2 {
		t.Fatalf("resumed=%#v requests=%d len=%d", resumed, requests, queue.Len())
	}
}

func TestResponseBodyLimitsHaveSafeDefaultAndHardMaximum(t *testing.T) {
	queue, err := store.Open(store.Config{Root: t.TempDir(), Destination: "limits", Kind: store.Telemetry})
	if err != nil {
		t.Fatal(err)
	}
	base := Config{Destination: Destination{ID: "limits", Endpoint: "https://example.invalid", AuthMode: AuthNone, ServerIPv4Allowlist: []string{"192.0.2.1"}}, Queue: queue}
	u, err := New(base)
	if err != nil {
		t.Fatal(err)
	}
	if u.maxResponseBytes != defaultMaxResponseBytes {
		t.Fatalf("default max response bytes = %d, want %d", u.maxResponseBytes, defaultMaxResponseBytes)
	}
	base.MaxResponseBytes = maxResponseBytesLimit
	u, err = New(base)
	if err != nil {
		t.Fatalf("hard maximum was rejected: %v", err)
	}
	if u.maxResponseBytes != maxResponseBytesLimit {
		t.Fatalf("configured max response bytes = %d", u.maxResponseBytes)
	}
	base.MaxResponseBytes++
	if _, err := New(base); err == nil {
		t.Fatal("accepted response limit above hard maximum")
	}
}

func TestRequestSizeLimitsQuarantineBeforeNetworkDelivery(t *testing.T) {
	tests := []struct {
		name                 string
		payload              string
		maxCompressedBytes   int64
		maxUncompressedBytes int64
		wantCode             string
	}{
		{name: "uncompressed", payload: `12345`, maxCompressedBytes: 4, maxUncompressedBytes: 4, wantCode: "PAYLOAD_UNCOMPRESSED_TOO_LARGE"},
		{name: "compressed", payload: `12345`, maxCompressedBytes: 4, maxUncompressedBytes: 10, wantCode: "PAYLOAD_COMPRESSED_TOO_LARGE"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)
			queue, err := store.Open(store.Config{Root: t.TempDir(), Destination: "request-limit-" + test.name, Kind: store.Telemetry, Now: func() time.Time { return now }})
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := queue.Enqueue("batch-"+test.name, []byte(test.payload)); err != nil {
				t.Fatal(err)
			}
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests++
				w.WriteHeader(http.StatusAccepted)
			}))
			defer server.Close()
			u, err := New(Config{
				Destination: Destination{ID: "request-limit-" + test.name, Endpoint: server.URL, AuthMode: AuthNone, ServerIPv4Allowlist: []string{"127.0.0.1"}},
				Queue:       queue, Now: func() time.Time { return now },
				MaxCompressedBytes: test.maxCompressedBytes, MaxUncompressedBytes: test.maxUncompressedBytes,
			})
			if err != nil {
				t.Fatal(err)
			}
			result := u.DeliverOne(context.Background())
			if result.Delivered || result.Pending || result.Err == nil || !strings.Contains(result.Err.Error(), test.wantCode) {
				t.Fatalf("result=%#v", result)
			}
			if requests != 0 || queue.Len() != 0 || queue.Stats().DeadLetterItems != 1 {
				t.Fatalf("requests=%d len=%d stats=%#v", requests, queue.Len(), queue.Stats())
			}
		})
	}
}

func TestOversizedConflictResponseIsBoundedAndQuarantined(t *testing.T) {
	now := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)
	queue, err := store.Open(store.Config{Root: t.TempDir(), Destination: "oversized", Kind: store.Telemetry, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := queue.Enqueue("batch-oversized", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":{"code":"DUPLICATE","message":"` + strings.Repeat("x", 128) + `"}}`))
	}))
	defer server.Close()
	u, err := New(Config{Destination: Destination{ID: "oversized", Endpoint: server.URL, AuthMode: AuthNone, ServerIPv4Allowlist: []string{"127.0.0.1"}}, Queue: queue, Now: func() time.Time { return now }, MaxResponseBytes: 32})
	if err != nil {
		t.Fatal(err)
	}
	result := u.DeliverOne(context.Background())
	if result.Delivered || result.Pending || result.Err == nil || !strings.Contains(result.Err.Error(), "exceeds 32 bytes") || queue.Len() != 0 || queue.Stats().DeadLetterItems != 1 {
		t.Fatalf("result=%#v stats=%#v", result, queue.Stats())
	}
}

func TestSuccessfulHTTPStatusAcknowledgesWithoutParsingBody(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusPartialContent, 299} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			now := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)
			queue, err := store.Open(store.Config{Root: t.TempDir(), Destination: "success", Kind: store.Telemetry, Now: func() time.Time { return now }})
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := queue.Enqueue("batch-success", []byte(`{}`)); err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(strings.Repeat("not-json", 32)))
			}))
			defer server.Close()
			u, err := New(Config{Destination: Destination{ID: "success", Endpoint: server.URL, AuthMode: AuthNone, ServerIPv4Allowlist: []string{"127.0.0.1"}}, Queue: queue, Now: func() time.Time { return now }, MaxResponseBytes: 8})
			if err != nil {
				t.Fatal(err)
			}
			result := u.DeliverOne(context.Background())
			if !result.Delivered || result.Pending || result.Err != nil || result.StatusCode != status || queue.Len() != 0 {
				t.Fatalf("result=%#v len=%d", result, queue.Len())
			}
		})
	}
}

func TestDeliverSignsAndAcknowledges(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	queue, err := store.Open(store.Config{Root: t.TempDir(), Destination: "control", Kind: store.Metering, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := queue.Enqueue("batch-1", []byte(`{"batchId":"batch-1"}`)); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := []byte(`{"batchId":"batch-1"}`)
		if err := protocol.VerifyRequest(r, body, func(string) ([]byte, error) { return []byte("top-secret"), nil }, protocol.VerifyOptions{Now: now}); err != nil {
			t.Errorf("signature verification: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Idempotency-Key") != "batch-1" {
			t.Errorf("missing idempotency key")
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	u, err := New(Config{Destination: Destination{ID: "control", Endpoint: server.URL, AuthMode: AuthHMACSHA256, KeyID: "agent-key", Secret: []byte("top-secret"), ServerIPv4Allowlist: []string{"127.0.0.1"}}, Queue: queue, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	result := u.DeliverOne(context.Background())
	if !result.Delivered || result.Err != nil || queue.Len() != 0 {
		t.Fatalf("result=%#v len=%d", result, queue.Len())
	}
}

func TestTransientFailurePersistsBackoff(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	queue, err := store.Open(store.Config{Root: t.TempDir(), Destination: "monitor", Kind: store.Telemetry, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := queue.Enqueue("batch-2", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer server.Close()
	u, err := New(Config{Destination: Destination{ID: "monitor", Endpoint: server.URL, AuthMode: AuthHMACSHA256, KeyID: "k", Secret: []byte("s"), ServerIPv4Allowlist: []string{"127.0.0.1"}}, Queue: queue, Now: func() time.Time { return now }, BaseDelay: time.Second, Jitter: func(delay time.Duration) time.Duration { return delay }})
	if err != nil {
		t.Fatal(err)
	}
	result := u.DeliverOne(context.Background())
	if result.Err == nil || !result.RetryAt.Equal(now.Add(time.Second)) {
		t.Fatalf("result = %#v", result)
	}
	item := queue.Snapshot()[0]
	if item.Attempts != 1 || !item.NextAttempt.Equal(result.RetryAt) {
		t.Fatalf("item = %#v", item)
	}
}

func TestBearerAndConflictWithoutDuplicateAreQuarantined(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	queue, err := store.Open(store.Config{Root: t.TempDir(), Destination: "monitor", Kind: store.Telemetry, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := queue.Enqueue("batch-3", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer token-value" {
			t.Errorf("authorization = %q", got)
		}
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":{"code":"IDEMPOTENCY_CONFLICT","message":"different payload"}}`))
	}))
	defer server.Close()
	u, err := New(Config{Destination: Destination{ID: "monitor", Endpoint: server.URL, AuthMode: AuthBearer, BearerToken: "token-value", ServerIPv4Allowlist: []string{"127.0.0.1"}}, Queue: queue, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	result := u.DeliverOne(context.Background())
	if result.Delivered || result.Pending || result.Err == nil || !strings.Contains(result.Err.Error(), "IDEMPOTENCY_CONFLICT") || !strings.Contains(result.Err.Error(), "different payload") || queue.Len() != 0 {
		t.Fatalf("result=%#v len=%d", result, queue.Len())
	}
	stats := queue.Stats()
	if stats.DeadLetterItems != 1 {
		t.Fatalf("stats=%#v", stats)
	}
}

func TestExplicitDuplicateAcknowledges(t *testing.T) {
	for name, body := range map[string]string{
		"flat":   `{"code":"DUPLICATE","message":"already accepted"}`,
		"nested": `{"error":{"code":"DUPLICATE","message":"already accepted"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			queue, err := store.Open(store.Config{Root: t.TempDir(), Destination: "control", Kind: store.Metering, Now: func() time.Time { return now }})
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := queue.Enqueue("batch-4", []byte(`{}`)); err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()
			u, err := New(Config{Destination: Destination{ID: "control", Endpoint: server.URL, AuthMode: AuthNone, ServerIPv4Allowlist: []string{"127.0.0.1"}}, Queue: queue, Now: func() time.Time { return now }})
			if err != nil {
				t.Fatal(err)
			}
			result := u.DeliverOne(context.Background())
			if !result.Delivered || result.Err != nil || queue.Len() != 0 || queue.Stats().DeadLetterItems != 0 {
				t.Fatalf("result=%#v stats=%#v", result, queue.Stats())
			}
		})
	}
}

func TestContradictoryDuplicateCodeDoesNotAcknowledge(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	queue, err := store.Open(store.Config{Root: t.TempDir(), Destination: "conflicting-codes", Kind: store.Metering, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := queue.Enqueue("batch-conflicting-codes", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"code":"DUPLICATE","error":{"code":"IDEMPOTENCY_CONFLICT","message":"payload digest differs"}}`))
	}))
	defer server.Close()
	u, err := New(Config{Destination: Destination{ID: "conflicting-codes", Endpoint: server.URL, AuthMode: AuthNone, ServerIPv4Allowlist: []string{"127.0.0.1"}}, Queue: queue, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	result := u.DeliverOne(context.Background())
	if result.Delivered || result.Pending || result.Err == nil || queue.Len() != 0 || queue.Stats().DeadLetterItems != 1 {
		t.Fatalf("result=%#v stats=%#v", result, queue.Stats())
	}
}

func TestDuplicateCodeOnServerErrorDoesNotAcknowledge(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	queue, err := store.Open(store.Config{Root: t.TempDir(), Destination: "control", Kind: store.Metering, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := queue.Enqueue("batch-500", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"code":"DUPLICATE"}`))
	}))
	defer server.Close()
	u, err := New(Config{Destination: Destination{ID: "control", Endpoint: server.URL, AuthMode: AuthNone, ServerIPv4Allowlist: []string{"127.0.0.1"}}, Queue: queue, Now: func() time.Time { return now }, Jitter: func(time.Duration) time.Duration { return time.Second }})
	if err != nil {
		t.Fatal(err)
	}
	result := u.DeliverOne(context.Background())
	if result.Delivered || queue.Len() != 1 || result.Err == nil {
		t.Fatalf("result=%#v len=%d", result, queue.Len())
	}
}

func TestGzipPayloadIsSignedAfterCompression(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	queue, err := store.Open(store.Config{Root: t.TempDir(), Destination: "gzip", Kind: store.Telemetry, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"batchId":"gzip"}`)
	if _, _, err := queue.Enqueue("gzip", payload); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		compressed, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if r.Header.Get("Content-Encoding") != "gzip" {
			t.Fatalf("content encoding=%q", r.Header.Get("Content-Encoding"))
		}
		if err := protocol.VerifyRequest(r, compressed, func(string) ([]byte, error) { return []byte("secret"), nil }, protocol.VerifyOptions{Now: now}); err != nil {
			t.Fatal(err)
		}
		reader, err := gzip.NewReader(bytes.NewReader(compressed))
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		_ = reader.Close()
		if string(decoded) != string(payload) {
			t.Fatalf("decoded=%s", decoded)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	u, err := New(Config{Destination: Destination{ID: "gzip", Endpoint: server.URL, AuthMode: AuthHMACSHA256, KeyID: "key", Secret: []byte("secret"), Compression: "gzip", ServerIPv4Allowlist: []string{"127.0.0.1"}}, Queue: queue, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	result := u.DeliverOne(context.Background())
	if !result.Delivered || result.Err != nil {
		t.Fatalf("result=%#v", result)
	}
}

func TestDefaultClientDisablesProxyAndRedirects(t *testing.T) {
	queue, err := store.Open(store.Config{Root: t.TempDir(), Destination: "test", Kind: store.Telemetry})
	if err != nil {
		t.Fatal(err)
	}
	u, err := New(Config{Destination: Destination{ID: "test", Endpoint: "https://example.invalid", AuthMode: AuthNone, ServerIPv4Allowlist: []string{"192.0.2.1"}}, Queue: queue})
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := u.client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.TLSClientConfig.MinVersion < tls.VersionTLS12 || u.client.CheckRedirect == nil {
		t.Fatalf("unsafe default client: %#v", u.client)
	}
}
