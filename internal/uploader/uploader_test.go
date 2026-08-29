package uploader

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/protocol"
	"github.com/ppflight/ppflight-agent/internal/store"
)

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
	u, err := New(Config{Destination: Destination{ID: "control", Endpoint: server.URL, AuthMode: AuthHMACSHA256, KeyID: "agent-key", Secret: []byte("top-secret")}, Queue: queue, Now: func() time.Time { return now }})
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
	u, err := New(Config{Destination: Destination{ID: "monitor", Endpoint: server.URL, AuthMode: AuthHMACSHA256, KeyID: "k", Secret: []byte("s")}, Queue: queue, Now: func() time.Time { return now }, BaseDelay: time.Second, Jitter: func(delay time.Duration) time.Duration { return delay }})
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
		_, _ = w.Write([]byte(`{"code":"CONFLICT","message":"different payload"}`))
	}))
	defer server.Close()
	u, err := New(Config{Destination: Destination{ID: "monitor", Endpoint: server.URL, AuthMode: AuthBearer, BearerToken: "token-value"}, Queue: queue, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	result := u.DeliverOne(context.Background())
	if result.Delivered || result.Pending || result.Err == nil || queue.Len() != 0 {
		t.Fatalf("result=%#v len=%d", result, queue.Len())
	}
	stats := queue.Stats()
	if stats.DeadLetterItems != 1 {
		t.Fatalf("stats=%#v", stats)
	}
}

func TestExplicitDuplicateAcknowledges(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	queue, err := store.Open(store.Config{Root: t.TempDir(), Destination: "control", Kind: store.Metering, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := queue.Enqueue("batch-4", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"code":"DUPLICATE"}`))
	}))
	defer server.Close()
	u, err := New(Config{Destination: Destination{ID: "control", Endpoint: server.URL, AuthMode: AuthNone}, Queue: queue, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	result := u.DeliverOne(context.Background())
	if !result.Delivered || result.Err != nil || queue.Len() != 0 {
		t.Fatalf("result=%#v", result)
	}
}

func TestDuplicateCodeOnServerErrorDoesNotAcknowledge(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	queue, err := store.Open(store.Config{Root: t.TempDir(), Destination: "control", Kind: store.Metering, Now: func() time.Time { return now }})
	if err != nil { t.Fatal(err) }
	if _, _, err := queue.Enqueue("batch-500", []byte(`{}`)); err != nil { t.Fatal(err) }
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError); _, _ = w.Write([]byte(`{"code":"DUPLICATE"}`)) }))
	defer server.Close()
	u, err := New(Config{Destination: Destination{ID: "control", Endpoint: server.URL, AuthMode: AuthNone}, Queue: queue, Now: func() time.Time { return now }, Jitter: func(time.Duration) time.Duration { return time.Second }})
	if err != nil { t.Fatal(err) }
	result := u.DeliverOne(context.Background())
	if result.Delivered || queue.Len() != 1 || result.Err == nil { t.Fatalf("result=%#v len=%d", result, queue.Len()) }
}

func TestGzipPayloadIsSignedAfterCompression(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	queue, err := store.Open(store.Config{Root: t.TempDir(), Destination: "gzip", Kind: store.Telemetry, Now: func() time.Time { return now }})
	if err != nil { t.Fatal(err) }
	payload := []byte(`{"batchId":"gzip"}`)
	if _, _, err := queue.Enqueue("gzip", payload); err != nil { t.Fatal(err) }
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		compressed, err := io.ReadAll(r.Body); if err != nil { t.Fatal(err) }
		if r.Header.Get("Content-Encoding") != "gzip" { t.Fatalf("content encoding=%q", r.Header.Get("Content-Encoding")) }
		if err := protocol.VerifyRequest(r, compressed, func(string) ([]byte, error) { return []byte("secret"), nil }, protocol.VerifyOptions{Now: now}); err != nil { t.Fatal(err) }
		reader, err := gzip.NewReader(bytes.NewReader(compressed)); if err != nil { t.Fatal(err) }; decoded, err := io.ReadAll(reader); if err != nil { t.Fatal(err) }; _ = reader.Close()
		if string(decoded) != string(payload) { t.Fatalf("decoded=%s", decoded) }
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	u, err := New(Config{Destination: Destination{ID: "gzip", Endpoint: server.URL, AuthMode: AuthHMACSHA256, KeyID: "key", Secret: []byte("secret"), Compression: "gzip"}, Queue: queue, Now: func() time.Time { return now }})
	if err != nil { t.Fatal(err) }
	result := u.DeliverOne(context.Background()); if !result.Delivered || result.Err != nil { t.Fatalf("result=%#v", result) }
}

func TestDefaultClientDisablesProxyAndRedirects(t *testing.T) {
	queue, err := store.Open(store.Config{Root: t.TempDir(), Destination: "test", Kind: store.Telemetry})
	if err != nil {
		t.Fatal(err)
	}
	u, err := New(Config{Destination: Destination{ID: "test", Endpoint: "https://example.invalid", AuthMode: AuthNone}, Queue: queue})
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := u.client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.TLSClientConfig.MinVersion < tls.VersionTLS12 || u.client.CheckRedirect == nil {
		t.Fatalf("unsafe default client: %#v", u.client)
	}
}
