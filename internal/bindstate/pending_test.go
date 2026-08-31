package bindstate

import (
	"errors"
	"os"
	"runtime"
	"testing"

	"github.com/ppflight/ppflight-agent/internal/enrollment"
)

func testPendingTemplate(t *testing.T, domain string) BindingRequestTemplate {
	t.Helper()
	capabilities := []string{"pve.discovery.v1", "pve.telemetry.v1"}
	if domain == "monitoring" {
		capabilities = []string{"telemetry-v1"}
	}
	template, err := NewBindingRequestTemplate(domain, "https://enroll.example.test/internal/v1/agents/bind", "device-01", "1.2.3", "pve-test", enrollment.NodeClaim{NodeRef: "node-01", PVEVersion: "9.0.8"}, capabilities)
	if err != nil {
		t.Fatal(err)
	}
	return template
}

func TestPendingBindingRequestReusesIDForSameFingerprint(t *testing.T) {
	directory := t.TempDir()
	fingerprint, err := RequestFingerprint(map[string]any{"bindingCode": "high-entropy-code", "deviceId": "device-1"})
	if err != nil {
		t.Fatal(err)
	}
	first, _, lock, err := PreparePending(directory, "website", fingerprint, testPendingTemplate(t, "website"))
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	second, _, lock, err := PreparePending(directory, "website", fingerprint, testPendingTemplate(t, "website"))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if first != second {
		t.Fatalf("request ID changed across retry: %q != %q", first, second)
	}
	raw, err := os.ReadFile(PendingPath(directory, "website"))
	if err != nil {
		t.Fatal(err)
	}
	if stringContains(string(raw), "high-entropy-code") {
		t.Fatal("pending state persisted the binding code")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(PendingPath(directory, "website"))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o640 {
			t.Fatalf("pending state mode = %o", info.Mode().Perm())
		}
	}
}

func TestPendingBindingChangedRequestIsRejectedUntilCleared(t *testing.T) {
	directory := t.TempDir()
	firstHash, _ := RequestFingerprint(map[string]string{"bindingCode": "first-high-entropy-code"})
	secondHash, _ := RequestFingerprint(map[string]string{"bindingCode": "second-high-entropy-code"})
	first, _, lock, err := PreparePending(directory, "monitoring", firstHash, testPendingTemplate(t, "monitoring"))
	if err != nil {
		t.Fatal(err)
	}
	_ = lock.Close()
	if second, _, secondLock, err := PreparePending(directory, "monitoring", secondHash, testPendingTemplate(t, "monitoring")); err == nil {
		_ = secondLock.Close()
		t.Fatalf("changed unresolved request was accepted with id %q after %q", second, first)
	} else if !errors.Is(err, ErrPendingRequestConflict) {
		t.Fatalf("changed unresolved request error = %v", err)
	}
	if pending, err := PendingRequestExists(directory, "monitoring"); err != nil || !pending {
		t.Fatalf("original pending request was not preserved: pending=%v err=%v", pending, err)
	}
	if err := ClearPending(directory, "monitoring"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(PendingPath(directory, "monitoring")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending state still exists: %v", err)
	}
}

func TestBindingRequestFingerprintBindsDomainAndCanonicalEndpoint(t *testing.T) {
	request := map[string]string{"bindingCode": "high-entropy-code", "deviceId": "device-1"}
	first, err := BindingRequestFingerprint("website", "HTTPS://Enroll.Example.test/internal/v1/agents/bind", request)
	if err != nil {
		t.Fatal(err)
	}
	equivalent, err := BindingRequestFingerprint("website", "https://enroll.example.test:443/internal/v1/agents/bind", request)
	if err != nil || equivalent != first {
		t.Fatalf("canonical website endpoint changed fingerprint: first=%s equivalent=%s err=%v", first, equivalent, err)
	}
	for _, changed := range []struct {
		domain   string
		endpoint string
	}{
		{domain: "monitoring", endpoint: "https://enroll.example.test:443/internal/v1/agents/bind"},
		{domain: "website", endpoint: "https://enroll.example.test:443/internal/v1/agents/bind-other"},
		{domain: "website", endpoint: "https://enroll.example.test:8443/internal/v1/agents/bind"},
	} {
		fingerprint, fingerprintErr := BindingRequestFingerprint(changed.domain, changed.endpoint, request)
		if fingerprintErr != nil || fingerprint == first {
			t.Fatalf("changed request identity did not alter fingerprint: %+v fingerprint=%s err=%v", changed, fingerprint, fingerprintErr)
		}
	}
	if _, err := BindingRequestFingerprint("website", "https://enroll.example.test/internal/v1/agents/bind?switch=1", request); err == nil {
		t.Fatal("query-bearing binding endpoint was accepted")
	}
}

func TestPreparePendingLockedUsesOuterTransactionWithoutSelfLock(t *testing.T) {
	directory := t.TempDir()
	fingerprint, err := RequestFingerprint(map[string]string{"bindingCode": "PENDING-123456", "deviceId": "device-01"})
	if err != nil {
		t.Fatal(err)
	}
	outer, err := AcquireTransaction(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer outer.Close()
	requestID, stored, err := PreparePendingLocked(directory, "website", fingerprint, testPendingTemplate(t, "website"))
	if err != nil || requestID == "" || stored.Endpoint == "" {
		t.Fatalf("locked pending preparation failed: id=%q template=%#v err=%v", requestID, stored, err)
	}
	// A normal caller cannot acquire the same process-wide nonblocking lock a
	// second time. This makes the regression meaningful on Linux flock and
	// proves bind must use the Locked form while it owns outer.
	if _, _, competing, err := PreparePending(directory, "website", fingerprint, testPendingTemplate(t, "website")); err == nil {
		_ = competing.Close()
		t.Fatal("independent pending preparation acquired an already-held transaction lock")
	}
}

func TestPendingTemplateNeverPersistsCodeAndRejectsLegacySchema(t *testing.T) {
	directory := t.TempDir()
	template := testPendingTemplate(t, "monitoring")
	request := map[string]string{"bindingCode": "MONITOR-SECRET-123456", "deviceId": template.DeviceID}
	fingerprint, err := BindingRequestFingerprint("monitoring", template.Endpoint, request)
	if err != nil {
		t.Fatal(err)
	}
	_, _, lock, err := PreparePending(directory, "monitoring", fingerprint, template)
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(PendingPath(directory, "monitoring"))
	if err != nil {
		t.Fatal(err)
	}
	if stringContains(string(raw), "MONITOR-SECRET-123456") || stringContains(string(raw), "bindingCode") {
		t.Fatal("pending template persisted a binding code")
	}
	if err := os.WriteFile(PendingPath(directory, "monitoring"), []byte(`{"schemaVersion":1,"kind":"monitoring","requestId":"123e4567-e89b-42d3-a456-426614174000","fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","createdAt":"2026-08-31T00:00:00Z"}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadPendingTemplate(directory, "monitoring"); err == nil {
		t.Fatal("old pending schema was guessed instead of rejected")
	}
}

func stringContains(value, wanted string) bool {
	for i := 0; i+len(wanted) <= len(value); i++ {
		if value[i:i+len(wanted)] == wanted {
			return true
		}
	}
	return false
}
