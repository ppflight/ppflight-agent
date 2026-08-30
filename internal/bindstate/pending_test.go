package bindstate

import (
	"errors"
	"os"
	"runtime"
	"testing"
)

func TestPendingBindingRequestReusesIDForSameFingerprint(t *testing.T) {
	directory := t.TempDir()
	fingerprint, err := RequestFingerprint(map[string]any{"bindingCode": "high-entropy-code", "deviceId": "device-1"})
	if err != nil {
		t.Fatal(err)
	}
	first, lock, err := PreparePending(directory, "website", fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	second, lock, err := PreparePending(directory, "website", fingerprint)
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

func TestPendingBindingChangedRequestGetsNewIDAndClears(t *testing.T) {
	directory := t.TempDir()
	firstHash, _ := RequestFingerprint(map[string]string{"bindingCode": "first-high-entropy-code"})
	secondHash, _ := RequestFingerprint(map[string]string{"bindingCode": "second-high-entropy-code"})
	first, lock, err := PreparePending(directory, "monitoring", firstHash)
	if err != nil {
		t.Fatal(err)
	}
	_ = lock.Close()
	second, lock, err := PreparePending(directory, "monitoring", secondHash)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("changed request reused idempotency ID")
	}
	if err := ClearPending(directory, "monitoring"); err != nil {
		t.Fatal(err)
	}
	_ = lock.Close()
	if _, err := os.Stat(PendingPath(directory, "monitoring")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending state still exists: %v", err)
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
