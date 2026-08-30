package health

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestReadinessAndMetrics(t *testing.T) {
	registry := New("0.1.0", "test", "agent-1", "cluster-1", "pve-1", true, false, false, time.Now())
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()
	registry.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("code=%d", response.Code)
	}
	registry.Collection(time.Now(), nil)
	request = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	response = httptest.NewRecorder()
	registry.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "ppflight_agent_ready 1") {
		t.Fatalf("body=%s", response.Body.String())
	}
}

func TestAuthenticationBlockedIsVisibleAndClearsOnSuccess(t *testing.T) {
	registry := New("0.1.0", "production", "agent-1", "cluster-1", "pve-1", true, true, false, time.Now())
	now := time.Now().UTC()
	registry.DeliveryState("monitoring", now, false, true, fmt.Errorf("destination authentication is blocked"))
	status := registry.Snapshot()
	if !status.Deliveries["monitoring"].AuthBlocked || status.Deliveries["monitoring"].AuthBlockedSince == nil || !status.Deliveries["monitoring"].AuthBlockedSince.Equal(now) {
		t.Fatalf("status=%#v", status.Deliveries["monitoring"])
	}
	registry.DeliveryState("monitoring", now.Add(500*time.Millisecond), false, true, fmt.Errorf("destination authentication is blocked"))
	if since := registry.Snapshot().Deliveries["monitoring"].AuthBlockedSince; since == nil || !since.Equal(now) {
		t.Fatalf("authentication block start moved: %v", since)
	}
	if metrics := registry.metrics(); !strings.Contains(metrics, `ppflight_agent_delivery_auth_blocked{destination="monitoring"} 1`) {
		t.Fatalf("metrics=%s", metrics)
	}
	registry.DeliveryState("monitoring", now.Add(time.Second), true, false, nil)
	cleared := registry.Snapshot().Deliveries["monitoring"]
	if cleared.AuthBlocked || cleared.AuthBlockedSince != nil {
		t.Fatal("successful delivery did not clear auth block")
	}
}

func TestBindingAuthorityIsNonSecretAndUsesDecimalEpochs(t *testing.T) {
	registry := New("0.1.0", "production", "agent-1", "cluster-1", "pve-1", true, true, false, time.Now())
	registry.Bindings("website-binding", 9007199254740993, "monitoring-binding", 18446744073709551615)
	status := registry.Snapshot()
	if status.Bindings.Website.BindingID != "website-binding" || status.Bindings.Website.CredentialEpoch != "9007199254740993" {
		t.Fatalf("website binding status=%#v", status.Bindings.Website)
	}
	if status.Bindings.Monitoring.BindingID != "monitoring-binding" || status.Bindings.Monitoring.CredentialEpoch != "18446744073709551615" {
		t.Fatalf("monitoring binding status=%#v", status.Bindings.Monitoring)
	}
}
