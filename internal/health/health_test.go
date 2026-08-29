package health

import (
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
