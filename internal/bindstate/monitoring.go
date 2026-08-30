package bindstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ppflight/ppflight-agent/internal/fsutil"
	"github.com/ppflight/ppflight-agent/internal/monitorenrollment"
	"github.com/ppflight/ppflight-agent/internal/netpolicy"
)

type MonitoringState struct {
	SchemaVersion      int                                 `json:"schemaVersion"`
	BindingEndpoint    string                              `json:"bindingEndpoint"`
	BindingID          string                              `json:"bindingId"`
	DeviceID           string                              `json:"deviceId"`
	MonitoringAgentRef string                              `json:"monitoringAgentRef"`
	IngestEndpoint     string                              `json:"ingestEndpoint"`
	HMACCredential     monitorenrollment.HMACCredential    `json:"hmacCredential"`
	Telemetry          monitorenrollment.TelemetryContract `json:"telemetry"`
	NetworkPolicy      netpolicy.NetworkPolicy             `json:"networkPolicy"`
	CredentialEpoch    uint64                              `json:"credentialEpoch"`
	IssuedAt           time.Time                           `json:"issuedAt"`
}

func (s *MonitoringState) UnmarshalJSON(raw []byte) error {
	type stateAlias MonitoringState
	value := struct {
		*stateAlias
		NetworkPolicy storedNetworkPolicy `json:"networkPolicy"`
	}{stateAlias: (*stateAlias)(s)}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("monitoring binding state must contain one JSON object")
	}
	s.NetworkPolicy = netpolicy.NetworkPolicy{AgentObservedIPv4: value.NetworkPolicy.AgentObservedIPv4}
	return nil
}

func MonitoringPath(stateDirectory string) string {
	return filepath.Join(Directory(stateDirectory), "monitoring-binding-state.json")
}

func MonitoringFromResponse(bindingEndpoint, deviceID string, response monitorenrollment.Response) MonitoringState {
	return MonitoringState{SchemaVersion: SchemaVersion, BindingEndpoint: bindingEndpoint, BindingID: response.BindingID, DeviceID: deviceID, MonitoringAgentRef: response.MonitoringAgentRef, IngestEndpoint: response.IngestEndpoint, HMACCredential: response.HMACCredential, Telemetry: response.Telemetry, NetworkPolicy: cloneNetworkPolicy(response.NetworkPolicy), CredentialEpoch: response.CredentialEpoch, IssuedAt: response.IssuedAt}
}

func (s MonitoringState) Response() monitorenrollment.Response {
	return monitorenrollment.Response{SchemaVersion: monitorenrollment.SchemaVersion, BindingID: s.BindingID, DeviceID: s.DeviceID, MonitoringAgentRef: s.MonitoringAgentRef, IngestEndpoint: s.IngestEndpoint, HMACCredential: s.HMACCredential, Telemetry: s.Telemetry, NetworkPolicy: cloneNetworkPolicy(s.NetworkPolicy), CredentialEpoch: s.CredentialEpoch, IssuedAt: s.IssuedAt}
}

func (s MonitoringState) Validate() error {
	if s.SchemaVersion != SchemaVersion || !safeDeviceID.MatchString(s.DeviceID) {
		return errors.New("invalid monitoring binding state")
	}
	if _, err := monitorenrollment.NewClient(monitorenrollment.Config{Endpoint: s.BindingEndpoint}); err != nil {
		return errors.New("invalid monitoring binding state")
	}
	endpoint, err := url.Parse(s.BindingEndpoint)
	if err != nil || s.Response().Validate(endpoint) != nil {
		return errors.New("invalid monitoring binding state")
	}
	return nil
}

func SaveMonitoring(stateDirectory string, state MonitoringState) error {
	if err := state.Validate(); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return errors.New("encode monitoring binding state")
	}
	return writePrivateAtomic(stateDirectory, MonitoringPath(stateDirectory), append(raw, '\n'))
}

func LoadMonitoring(stateDirectory string) (MonitoringState, error) {
	raw, err := readPrivateFile(MonitoringPath(stateDirectory), maxStateBytes)
	if err != nil {
		return MonitoringState{}, err
	}
	return decodeMonitoringState(raw)
}

func decodeMonitoringState(raw []byte) (MonitoringState, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value MonitoringState
	if err := decoder.Decode(&value); err != nil {
		return MonitoringState{}, errors.New("decode monitoring binding state")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return MonitoringState{}, errors.New("monitoring binding state must contain one JSON object")
	}
	if err := value.Validate(); err != nil {
		return MonitoringState{}, err
	}
	return value, nil
}

// BackupMonitoring creates a private, validated rollback copy of the current
// monitoring trust-domain state. A missing first-time binding has no backup.
func BackupMonitoring(stateDirectory string) (string, error) {
	state, err := LoadMonitoring(stateDirectory)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return "", errors.New("encode monitoring binding backup")
	}
	filename := filepath.Join(Directory(stateDirectory), "monitoring-binding-state.backup."+time.Now().UTC().Format("20060102T150405.000000000Z")+".json")
	if err := writePrivateAtomic(stateDirectory, filename, append(raw, '\n')); err != nil {
		return "", err
	}
	return filename, nil
}

// RestoreMonitoring restores a prior backup, or removes a first-time state
// when backup is empty. The backup remains available after restoration.
func RestoreMonitoring(stateDirectory, backup string) error {
	if backup == "" {
		return RemoveMonitoring(stateDirectory)
	}
	if err := validateMonitoringBackupPath(stateDirectory, backup); err != nil {
		return err
	}
	raw, err := readPrivateFile(backup, maxStateBytes)
	if err != nil {
		return err
	}
	state, err := decodeMonitoringState(raw)
	if err != nil {
		return err
	}
	return SaveMonitoring(stateDirectory, state)
}

func RemoveMonitoring(stateDirectory string) error {
	directory, err := ensureBindingDirectory(stateDirectory)
	if err != nil {
		return err
	}
	filename := MonitoringPath(stateDirectory)
	file, err := fsutil.OpenRegularInDirectoryNoFollow(directory, filepath.Base(filename))
	if errors.Is(err, os.ErrNotExist) {
		return nil
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

func DiscardMonitoringBackup(stateDirectory, backup string) error {
	if backup == "" {
		return nil
	}
	if err := validateMonitoringBackupPath(stateDirectory, backup); err != nil {
		return err
	}
	file, err := fsutil.OpenRegularInDirectoryNoFollow(filepath.Dir(backup), filepath.Base(backup))
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Remove(backup); err != nil {
		return err
	}
	return fsutil.SyncDir(filepath.Dir(backup))
}

func validateMonitoringBackupPath(stateDirectory, backup string) error {
	directory := filepath.Clean(Directory(stateDirectory))
	cleaned := filepath.Clean(backup)
	base := filepath.Base(cleaned)
	if filepath.Dir(cleaned) != directory || !strings.HasPrefix(base, "monitoring-binding-state.backup.") || !strings.HasSuffix(base, ".json") {
		return errors.New("monitoring binding backup path is invalid")
	}
	return nil
}
