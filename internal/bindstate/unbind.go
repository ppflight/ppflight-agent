package bindstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ppflight/ppflight-agent/internal/fsutil"
)

const unbindSchemaVersion = 1

const (
	websiteUnbindCommitName    = ".website-unbind-commit.json"
	monitoringUnbindCommitName = ".monitoring-unbind-commit.json"
)

// UnbindCommit is the small, secret-free journal for a local binding removal.
// The state backup is private and lives in the same controlled directory. It
// lets a stopped Agent recover the preimage after a failed multi-file unbind,
// without confusing this operation with an enrollment commit marker.
type UnbindCommit struct {
	SchemaVersion   int    `json:"schemaVersion"`
	Domain          string `json:"domain"`
	BindingID       string `json:"bindingId"`
	CredentialEpoch uint64 `json:"credentialEpoch"`
	StateBackup     string `json:"stateBackup"`
}

func websiteUnbindCommitPath(stateDirectory string) string {
	return filepath.Join(Directory(stateDirectory), websiteUnbindCommitName)
}

func monitoringUnbindCommitPath(stateDirectory string) string {
	return filepath.Join(Directory(stateDirectory), monitoringUnbindCommitName)
}

// BeginWebsiteUnbind snapshots the current website private state and records
// the exact identity to be removed before the service lifecycle is disrupted.
func BeginWebsiteUnbind(stateDirectory string, state State) (UnbindCommit, error) {
	if err := state.Validate(); err != nil {
		return UnbindCommit{}, errors.New("invalid website binding state for unbind")
	}
	return beginUnbind(stateDirectory, "website", state.BindingID, state.CredentialEpoch, BackupWebsite, websiteUnbindCommitPath(stateDirectory))
}

// BeginMonitoringUnbind is the monitoring trust-domain equivalent.
func BeginMonitoringUnbind(stateDirectory string, state MonitoringState) (UnbindCommit, error) {
	if err := state.Validate(); err != nil {
		return UnbindCommit{}, errors.New("invalid monitoring binding state for unbind")
	}
	return beginUnbind(stateDirectory, "monitoring", state.BindingID, state.CredentialEpoch, BackupMonitoring, monitoringUnbindCommitPath(stateDirectory))
}

func beginUnbind(stateDirectory, domain, bindingID string, credentialEpoch uint64, backup func(string) (string, error), markerPath string) (UnbindCommit, error) {
	if domain != "website" && domain != "monitoring" || !bindingUUID.MatchString(bindingID) || credentialEpoch == 0 || backup == nil {
		return UnbindCommit{}, errors.New("invalid binding removal transaction")
	}
	if _, found, err := readUnbind(markerPath, domain); err != nil {
		return UnbindCommit{}, err
	} else if found {
		return UnbindCommit{}, fmt.Errorf("%s binding removal transaction already exists", domain)
	}
	backupPath, err := backup(stateDirectory)
	if err != nil || backupPath == "" {
		return UnbindCommit{}, errors.New("create private binding rollback backup")
	}
	marker := UnbindCommit{
		SchemaVersion: unbindSchemaVersion, Domain: domain, BindingID: bindingID, CredentialEpoch: credentialEpoch,
		StateBackup: filepath.Base(backupPath),
	}
	if !validUnbindCommit(marker) {
		_ = discardUnbindBackup(stateDirectory, marker)
		return UnbindCommit{}, errors.New("invalid binding removal transaction")
	}
	raw, err := json.Marshal(marker)
	if err != nil {
		_ = discardUnbindBackup(stateDirectory, marker)
		return UnbindCommit{}, errors.New("encode binding removal transaction")
	}
	if err := writePrivateExclusive(stateDirectory, markerPath, append(raw, '\n')); err != nil {
		_ = discardUnbindBackup(stateDirectory, marker)
		if errors.Is(err, os.ErrExist) {
			return UnbindCommit{}, fmt.Errorf("%s binding removal transaction already exists", domain)
		}
		return UnbindCommit{}, err
	}
	return marker, nil
}

func ReadWebsiteUnbind(stateDirectory string) (UnbindCommit, bool, error) {
	return readUnbind(websiteUnbindCommitPath(stateDirectory), "website")
}

func ReadMonitoringUnbind(stateDirectory string) (UnbindCommit, bool, error) {
	return readUnbind(monitoringUnbindCommitPath(stateDirectory), "monitoring")
}

func readUnbind(filename, domain string) (UnbindCommit, bool, error) {
	raw, err := readPrivateFile(filename, maxCommitMarkerBytes)
	if errors.Is(err, os.ErrNotExist) {
		return UnbindCommit{}, false, nil
	}
	if err != nil {
		return UnbindCommit{}, false, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var marker UnbindCommit
	if err := decoder.Decode(&marker); err != nil {
		return UnbindCommit{}, false, fmt.Errorf("decode %s binding removal transaction", domain)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF || !validUnbindCommit(marker) || marker.Domain != domain {
		return UnbindCommit{}, false, fmt.Errorf("invalid %s binding removal transaction", domain)
	}
	return marker, true, nil
}

func validUnbindCommit(marker UnbindCommit) bool {
	if marker.SchemaVersion != unbindSchemaVersion || (marker.Domain != "website" && marker.Domain != "monitoring") || !bindingUUID.MatchString(marker.BindingID) || marker.CredentialEpoch == 0 {
		return false
	}
	base := filepath.Base(marker.StateBackup)
	if base != marker.StateBackup || strings.ContainsAny(base, `/\\`) {
		return false
	}
	prefix := "binding-state.backup."
	if marker.Domain == "monitoring" {
		prefix = "monitoring-binding-state.backup."
	}
	return strings.HasPrefix(base, prefix) && strings.HasSuffix(base, ".json") && len(base) < 256
}

// RestoreWebsiteUnbind restores the validated private rollback preimage. It
// never accepts an arbitrary path from the journal.
func RestoreWebsiteUnbind(stateDirectory string, marker UnbindCommit) error {
	if !validUnbindCommit(marker) || marker.Domain != "website" {
		return errors.New("invalid website binding removal transaction")
	}
	return RestoreWebsite(stateDirectory, filepath.Join(Directory(stateDirectory), marker.StateBackup))
}

func RestoreMonitoringUnbind(stateDirectory string, marker UnbindCommit) error {
	if !validUnbindCommit(marker) || marker.Domain != "monitoring" {
		return errors.New("invalid monitoring binding removal transaction")
	}
	return RestoreMonitoring(stateDirectory, filepath.Join(Directory(stateDirectory), marker.StateBackup))
}

// Discard*UnbindBackup deletes only the exact backup named by a validated
// transaction. A missing backup is allowed for forward recovery after a crash
// between backup cleanup and journal cleanup.
func DiscardWebsiteUnbindBackup(stateDirectory string, marker UnbindCommit) error {
	if !validUnbindCommit(marker) || marker.Domain != "website" {
		return errors.New("invalid website binding removal transaction")
	}
	return discardUnbindBackup(stateDirectory, marker)
}

func DiscardMonitoringUnbindBackup(stateDirectory string, marker UnbindCommit) error {
	if !validUnbindCommit(marker) || marker.Domain != "monitoring" {
		return errors.New("invalid monitoring binding removal transaction")
	}
	return discardUnbindBackup(stateDirectory, marker)
}

func discardUnbindBackup(stateDirectory string, marker UnbindCommit) error {
	filename := filepath.Join(Directory(stateDirectory), marker.StateBackup)
	if marker.Domain == "website" {
		err := DiscardWebsiteBackup(stateDirectory, filename)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	err := DiscardMonitoringBackup(stateDirectory, filename)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func FinishWebsiteUnbind(stateDirectory string) error {
	return finishUnbind(stateDirectory, websiteUnbindCommitPath(stateDirectory), "website")
}

func FinishMonitoringUnbind(stateDirectory string) error {
	return finishUnbind(stateDirectory, monitoringUnbindCommitPath(stateDirectory), "monitoring")
}

func finishUnbind(stateDirectory, filename, domain string) error {
	if _, found, err := readUnbind(filename, domain); err != nil {
		return err
	} else if !found {
		return nil
	}
	directory, err := ensureBindingDirectory(stateDirectory)
	if err != nil {
		return err
	}
	file, err := fsutil.OpenRegularInDirectoryNoFollow(directory, filepath.Base(filename))
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s binding removal transaction disappeared while finishing", domain)
	}
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Remove(filename); err != nil {
		return err
	}
	return fsutil.SyncDir(directory)
}
