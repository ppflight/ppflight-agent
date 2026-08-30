// Package bindstate persists the result of an enrollment binding locally.
//
// The enrollment service returns credentials which cannot safely be put in the
// agent's public configuration. This package keeps them in a root-controlled,
// service-group-readable directory, using descriptor-relative atomic writes so
// readers observe either the old complete state or the new complete state.
package bindstate

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ppflight/ppflight-agent/internal/enrollment"
	"github.com/ppflight/ppflight-agent/internal/fsutil"
	"github.com/ppflight/ppflight-agent/internal/netpolicy"
)

const (
	SchemaVersion        = 1
	bindingDirectoryName = "bindings"
	maxStateBytes        = enrollment.MaxResponseBytes + (16 << 10)
)

var safeDeviceID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$`)

// State is the complete service-issued enrollment state.  It is intentionally
// separate from config.Config because it includes HMAC secrets.
type State struct {
	SchemaVersion            int                                 `json:"schemaVersion"`
	BindingEndpoint          string                              `json:"bindingEndpoint"`
	BindingID                string                              `json:"bindingId"`
	DeviceID                 string                              `json:"deviceId"`
	CredentialEpoch          uint64                              `json:"credentialEpoch"`
	IssuedAt                 time.Time                           `json:"issuedAt"`
	Identity                 Identity                            `json:"identity"`
	Endpoints                enrollment.Endpoints                `json:"endpoints"`
	HMACCredentials          enrollment.HMACCredentials          `json:"hmacCredentials"`
	CommandSigningCredential enrollment.CommandSigningCredential `json:"commandSigningCredential"`
	AllowedActions           []string                            `json:"allowedActions"`
	AssignmentDocument       json.RawMessage                     `json:"assignmentDocument"`
	NetworkPolicy            netpolicy.NetworkPolicy             `json:"networkPolicy"`
}

// Identity contains only the service-issued public identifiers.
type Identity struct {
	AgentRef     string `json:"agentRef"`
	CollectorRef string `json:"collectorRef"`
	SourceRef    string `json:"sourceRef"`
	ClusterRef   string `json:"clusterRef"`
	NodeRef      string `json:"nodeRef"`
	Site         string `json:"site"`
}

// storedNetworkPolicy accepts the retired destination allowlist only while
// reading an existing RC binding-state file. New state marshaling and all bind
// responses use the exact one-field netpolicy.NetworkPolicy shape.
type storedNetworkPolicy struct {
	AgentObservedIPv4   string   `json:"agentObservedIPv4"`
	ServerIPv4Allowlist []string `json:"serverIPv4Allowlist,omitempty"`
}

func (s *State) UnmarshalJSON(raw []byte) error {
	type stateAlias State
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
		return errors.New("binding state must contain one JSON object")
	}
	s.NetworkPolicy = netpolicy.NetworkPolicy{AgentObservedIPv4: value.NetworkPolicy.AgentObservedIPv4}
	return nil
}

// Directory returns the controlled binding-state directory below the general
// agent state root. The service may write elsewhere in the state root, but is
// intended to have read-only access to this subtree in production.
func Directory(stateDirectory string) string {
	return filepath.Join(stateDirectory, bindingDirectoryName)
}

// Path returns the fixed website binding-state path.
func Path(stateDirectory string) string {
	return filepath.Join(Directory(stateDirectory), "binding-state.json")
}

// DeviceIDPath returns the fixed private device identifier path.
func DeviceIDPath(stateDirectory string) string {
	return filepath.Join(Directory(stateDirectory), "device-id")
}

// FromResponse converts a validated enrollment response into local state.
func FromResponse(bindingEndpoint, deviceID string, response enrollment.Response) State {
	return State{
		SchemaVersion: SchemaVersion, BindingEndpoint: bindingEndpoint, BindingID: response.BindingID, DeviceID: deviceID,
		CredentialEpoch: response.CredentialEpoch, IssuedAt: response.IssuedAt,
		Identity:  Identity{AgentRef: response.AgentRef, CollectorRef: response.CollectorRef, SourceRef: response.SourceRef, ClusterRef: response.ClusterRef, NodeRef: response.NodeRef, Site: response.Site},
		Endpoints: response.Endpoints, HMACCredentials: response.HMACCredentials,
		CommandSigningCredential: response.CommandSigningCredential,
		AllowedActions:           append([]string(nil), response.AllowedActions...),
		AssignmentDocument:       append(json.RawMessage(nil), response.AssignmentDocument...),
		NetworkPolicy:            cloneNetworkPolicy(response.NetworkPolicy),
	}
}

// Response reconstructs the enrollment response represented by state.
func (s State) Response() enrollment.Response {
	return enrollment.Response{
		SchemaVersion: enrollment.SchemaVersion,
		BindingID:     s.BindingID, DeviceID: s.DeviceID,
		AgentRef: s.Identity.AgentRef, CollectorRef: s.Identity.CollectorRef, SourceRef: s.Identity.SourceRef,
		ClusterRef: s.Identity.ClusterRef, NodeRef: s.Identity.NodeRef, Site: s.Identity.Site,
		Endpoints: s.Endpoints, HMACCredentials: s.HMACCredentials,
		CommandSigningCredential: s.CommandSigningCredential,
		AllowedActions:           append([]string(nil), s.AllowedActions...), AssignmentDocument: append(json.RawMessage(nil), s.AssignmentDocument...),
		NetworkPolicy:   cloneNetworkPolicy(s.NetworkPolicy),
		CredentialEpoch: s.CredentialEpoch, IssuedAt: s.IssuedAt,
	}
}

func cloneNetworkPolicy(value netpolicy.NetworkPolicy) netpolicy.NetworkPolicy {
	return netpolicy.NetworkPolicy{AgentObservedIPv4: value.AgentObservedIPv4}
}

// Validate verifies the state using the enrollment response contract.  It
// never includes credential material in an error.
func (s State) Validate() error {
	if s.SchemaVersion != SchemaVersion || !safeDeviceID.MatchString(s.DeviceID) {
		return errors.New("invalid binding state")
	}
	if _, err := enrollment.NewClient(enrollment.Config{Endpoint: s.BindingEndpoint}); err != nil {
		return errors.New("invalid binding state")
	}
	endpoint, err := url.Parse(s.BindingEndpoint)
	if err != nil || endpoint == nil {
		return errors.New("invalid binding state")
	}
	if err := s.Response().Validate(endpoint); err != nil {
		return errors.New("invalid binding state")
	}
	return nil
}

// Load returns the complete state after validating its format and safe file
// properties.  A missing state is returned as os.ErrNotExist.
func Load(stateDirectory string) (State, error) {
	contents, err := readPrivateFile(Path(stateDirectory), maxStateBytes)
	if err != nil {
		return State{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var result State
	if err := decoder.Decode(&result); err != nil {
		return State{}, errors.New("decode binding state")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return State{}, errors.New("binding state must contain one JSON object")
	}
	if err := result.Validate(); err != nil {
		return State{}, err
	}
	return result, nil
}

// Save atomically replaces the private enrollment state.  The caller must
// validate the service response before calling Save; Save validates again to
// protect callers which construct State directly.
func Save(stateDirectory string, state State) error {
	if err := state.Validate(); err != nil {
		return err
	}
	contents, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return errors.New("encode binding state")
	}
	return writePrivateAtomic(stateDirectory, Path(stateDirectory), append(contents, '\n'))
}

// LoadOrCreateDeviceID returns an opaque stable identifier.  It is generated
// with crypto/rand once and stored in a private non-symlink file.
func LoadOrCreateDeviceID(stateDirectory string) (string, error) {
	if _, err := ensureBindingDirectory(stateDirectory); err != nil {
		return "", err
	}
	filename := DeviceIDPath(stateDirectory)
	contents, err := readPrivateFile(filename, 256)
	if err == nil {
		value := strings.TrimSpace(string(contents))
		if !safeDeviceID.MatchString(value) {
			return "", errors.New("invalid device ID state")
		}
		return value, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	bytes := make([]byte, 20)
	if _, err := rand.Read(bytes); err != nil {
		return "", errors.New("generate device ID")
	}
	value := "device-" + hex.EncodeToString(bytes)
	if err := writePrivateAtomic(stateDirectory, filename, []byte(value+"\n")); err != nil {
		return "", err
	}
	return value, nil
}

// WriteAssignment atomically replaces the service-issued initial assignment
// document. Assignment data is not a credential, but it is still written
// without following a symlink. Existing ownership and mode are preserved;
// a new file inherits the opened directory ownership and defaults to 0640.
func WriteAssignment(filename string, document json.RawMessage) error {
	if len(document) == 0 || len(document) > enrollment.MaxResponseBytes || !json.Valid(document) {
		return errors.New("invalid assignment document")
	}
	return fsutil.AtomicWriteFile(filename, append(append([]byte(nil), document...), '\n'), 0o640, true)
}

func readPrivateFile(filename string, limit int64) ([]byte, error) {
	file, err := fsutil.OpenRegularInDirectoryNoFollow(filepath.Dir(filename), filepath.Base(filename))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if err := checkPrivateFileMode(info); err != nil {
		return nil, err
	}
	contents, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(contents)) > limit {
		return nil, errors.New("private state file exceeds maximum size")
	}
	return contents, nil
}

func writePrivateAtomic(directory, filename string, contents []byte) error {
	bindingsDirectory, err := ensureBindingDirectory(directory)
	if err != nil {
		return err
	}
	if filepath.Clean(filepath.Dir(filename)) != filepath.Clean(bindingsDirectory) {
		return errors.New("private binding state escaped its controlled directory")
	}
	existing, err := fsutil.OpenRegularInDirectoryNoFollow(bindingsDirectory, filepath.Base(filename))
	if err == nil {
		info, statErr := existing.Stat()
		closeErr := existing.Close()
		if statErr != nil {
			return statErr
		}
		if closeErr != nil {
			return closeErr
		}
		if err := checkPrivateFileMode(info); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return fsutil.AtomicWriteFile(filename, contents, 0o640, false)
}

func ensureBindingDirectory(stateDirectory string) (string, error) {
	return fsutil.EnsureControlledSubdirectory(stateDirectory, bindingDirectoryName, 0o750)
}

// String deliberately does not implement a formatter for State: callers must
// never log it because it contains HMAC secrets.
func (s State) String() string {
	return fmt.Sprintf("binding state epoch=%d device=%s", s.CredentialEpoch, s.DeviceID)
}
