package scripts

import (
	"os/exec"
	"testing"
)

func TestLegacyTemplateTimezoneMigration(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is unavailable")
	}
	command := exec.Command("python3", "-I", "migrate-legacy-template-timezone_test.py")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("legacy template timezone migration tests failed: %v\n%s", err, output)
	}
}
