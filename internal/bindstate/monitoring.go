package bindstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"path/filepath"
	"time"

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
