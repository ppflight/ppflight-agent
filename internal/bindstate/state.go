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
	websiteCommitName    = ".website-binding-commit.json"
	monitoringCommitName = ".monitoring-binding-commit.json"
	maxCommitMarkerBytes = 4096
)

var (
	safeDeviceID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$`)
	bindingUUID  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
)

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

// BindingCommit is a data-free crash-consistency marker tying a binding
// generation to its multi-file update. It deliberately contains only the
// public issued identity; credentials never appear in a marker.
//
// The agent refuses to load either trust domain while any validated or
// malformed commit marker exists, so a process crash cannot make it consume a
// partially-updated public config and private binding state.
type BindingCommit struct {
	SchemaVersion   int    `json:"schemaVersion"`
	BindingID       string `json:"bindingId"`
	CredentialEpoch uint64 `json:"credentialEpoch"`
}

// WebsiteCommit and MonitoringCommit are intentionally the same strict
// on-disk shape, but are distinct names at call sites to make trust-domain
// selection explicit.
type WebsiteCommit = BindingCommit
type MonitoringCommit = BindingCommit

func websiteCommitPath(stateDirectory string) string {
	return filepath.Join(Directory(stateDirectory), websiteCommitName)
}

func monitoringCommitPath(stateDirectory string) string {
	return filepath.Join(Directory(stateDirectory), monitoringCommitName)
}

// BeginWebsiteCommit durably marks a multi-file website binding update as
// incomplete before the first of its files is replaced. It never overwrites a
// prior marker: callers must recover or finish the existing transaction first.
func BeginWebsiteCommit(stateDirectory, bindingID string, credentialEpoch uint64) error {
	return beginCommit(stateDirectory, websiteCommitPath(stateDirectory), "website", bindingID, credentialEpoch)
}

// BeginMonitoringCommit is the monitoring-domain equivalent of
// BeginWebsiteCommit. The independent marker prevents a monitoring rebind from
// being mistaken for a complete state if the process stops halfway through.
func BeginMonitoringCommit(stateDirectory, bindingID string, credentialEpoch uint64) error {
	return beginCommit(stateDirectory, monitoringCommitPath(stateDirectory), "monitoring", bindingID, credentialEpoch)
}

// ReadWebsiteCommit strictly reads the pending website marker identity. found
// is false only when no marker exists. A malformed, unsafe, or unreadable
// marker returns an error so callers stay fail closed.
func ReadWebsiteCommit(stateDirectory string) (marker WebsiteCommit, found bool, err error) {
	return readCommit(websiteCommitPath(stateDirectory), "website")
}

// ReadMonitoringCommit strictly reads the pending monitoring marker identity.
// It is intentionally isolated from the website marker and state.
func ReadMonitoringCommit(stateDirectory string) (marker MonitoringCommit, found bool, err error) {
	return readCommit(monitoringCommitPath(stateDirectory), "monitoring")
}

// WebsiteCommitPending reports a validated incomplete website transaction.
// A malformed marker is an error so startup remains fail closed.
func WebsiteCommitPending(stateDirectory string) (bool, error) {
	_, pending, err := ReadWebsiteCommit(stateDirectory)
	return pending, err
}

// MonitoringCommitPending is the monitoring-domain equivalent of
// WebsiteCommitPending.
func MonitoringCommitPending(stateDirectory string) (bool, error) {
	_, pending, err := ReadMonitoringCommit(stateDirectory)
	return pending, err
}

// FinishWebsiteCommit removes the fail-closed marker only after config,
// binding state and assignment have all been written and cross-validated.
func FinishWebsiteCommit(stateDirectory string) error {
	return finishCommit(stateDirectory, websiteCommitPath(stateDirectory), "website")
}

// FinishMonitoringCommit removes a validated monitoring marker only after the
// monitoring binding files were written and cross-validated.
func FinishMonitoringCommit(stateDirectory string) error {
	return finishCommit(stateDirectory, monitoringCommitPath(stateDirectory), "monitoring")
}

func beginCommit(stateDirectory, filename, domain, bindingID string, credentialEpoch uint64) error {
	marker := BindingCommit{SchemaVersion: SchemaVersion, BindingID: bindingID, CredentialEpoch: credentialEpoch}
	if !validCommitMarker(marker) {
		return fmt.Errorf("invalid %s binding commit marker", domain)
	}
	if _, found, err := readCommit(filename, domain); err != nil {
		return err
	} else if found {
		return fmt.Errorf("%s binding commit marker already exists", domain)
	}
	raw, err := json.Marshal(marker)
	if err != nil {
		return fmt.Errorf("encode %s binding commit marker", domain)
	}
	if err := writePrivateExclusive(stateDirectory, filename, append(raw, '\n')); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s binding commit marker already exists", domain)
		}
		return err
	}
	return nil
}

func readCommit(filename, domain string) (BindingCommit, bool, error) {
	raw, err := readPrivateFile(filename, maxCommitMarkerBytes)
	if errors.Is(err, os.ErrNotExist) {
		return BindingCommit{}, false, nil
	}
	if err != nil {
		return BindingCommit{}, false, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var marker BindingCommit
	if err := decoder.Decode(&marker); err != nil {
		return BindingCommit{}, false, fmt.Errorf("decode %s binding commit marker", domain)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF || !validCommitMarker(marker) {
		return BindingCommit{}, false, fmt.Errorf("invalid %s binding commit marker", domain)
	}
	return marker, true, nil
}

func validCommitMarker(marker BindingCommit) bool {
	return marker.SchemaVersion == SchemaVersion && bindingUUID.MatchString(marker.BindingID) && marker.CredentialEpoch != 0
}

func finishCommit(stateDirectory, filename, domain string) error {
	if _, found, err := readCommit(filename, domain); err != nil {
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
		return fmt.Errorf("%s binding commit marker disappeared while finishing", domain)
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

// AcquireTransaction serializes root-run website, monitoring and real-PVE
// configuration changes across the two independent binding trust domains.
// The lock contains no data and is never read by the unprivileged service.
func AcquireTransaction(stateDirectory string) (*fsutil.Lock, error) {
	directory, err := ensureBindingDirectory(stateDirectory)
	if err != nil {
		return nil, err
	}
	return fsutil.AcquireExclusive(filepath.Join(directory, ".admin-transaction.lock"))
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

// BackupWebsite creates a private, validated rollback copy of the current
// website trust-domain state. A missing first-time binding has no backup.
func BackupWebsite(stateDirectory string) (string, error) {
	state, err := Load(stateDirectory)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return "", errors.New("encode website binding backup")
	}
	filename := filepath.Join(Directory(stateDirectory), "binding-state.backup."+time.Now().UTC().Format("20060102T150405.000000000Z")+".json")
	if err := writePrivateAtomic(stateDirectory, filename, append(raw, '\n')); err != nil {
		return "", err
	}
	return filename, nil
}

// RestoreWebsite restores a prior backup, or removes a first-time state when
// backup is empty. The backup remains available after restoration.
func RestoreWebsite(stateDirectory, backup string) error {
	if backup == "" {
		return RemoveWebsite(stateDirectory)
	}
	if err := validateWebsiteBackupPath(stateDirectory, backup); err != nil {
		return err
	}
	raw, err := readPrivateFile(backup, maxStateBytes)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var state State
	if err := decoder.Decode(&state); err != nil {
		return errors.New("decode website binding backup")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("website binding backup must contain one JSON object")
	}
	if err := state.Validate(); err != nil {
		return err
	}
	return Save(stateDirectory, state)
}

// DiscardWebsiteBackup removes a validated website rollback copy after the new
// binding has been loaded successfully.
func DiscardWebsiteBackup(stateDirectory, backup string) error {
	if backup == "" {
		return nil
	}
	if err := validateWebsiteBackupPath(stateDirectory, backup); err != nil {
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

func validateWebsiteBackupPath(stateDirectory, backup string) error {
	directory := filepath.Clean(Directory(stateDirectory))
	cleaned := filepath.Clean(backup)
	base := filepath.Base(cleaned)
	if filepath.Dir(cleaned) != directory || !strings.HasPrefix(base, "binding-state.backup.") || !strings.HasSuffix(base, ".json") {
		return errors.New("website binding backup path is invalid")
	}
	return nil
}

// RemoveWebsite removes only the website trust-domain credential state. The
// stable device ID and the independent monitoring state are deliberately kept.
func RemoveWebsite(stateDirectory string) error {
	directory, err := ensureBindingDirectory(stateDirectory)
	if err != nil {
		return err
	}
	filename := Path(stateDirectory)
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
	if err := checkManagedPrivateFileMetadata(filename, info); err != nil {
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

// writePrivateExclusive creates a private file exactly once. It is used for
// transaction markers because replacing a marker would silently discard the
// only durable evidence of an incomplete binding update. The controlled
// directory is checked before creation; O_EXCL then closes the create race.
//
// If a write fails after the name is reserved, the partial marker is left in
// place deliberately. Subsequent starts fail closed instead of guessing
// whether the interrupted transaction can be safely resumed.
func writePrivateExclusive(stateDirectory, filename string, contents []byte) error {
	bindingsDirectory, err := ensureBindingDirectory(stateDirectory)
	if err != nil {
		return err
	}
	if filepath.Clean(filepath.Dir(filename)) != filepath.Clean(bindingsDirectory) {
		return errors.New("private binding state escaped its controlled directory")
	}
	// Refuse an existing regular marker, malformed marker, or symlink before
	// opening the exclusive create. The exclusive create below also rejects a
	// marker which appears after this check.
	existing, err := fsutil.OpenRegularInDirectoryNoFollow(bindingsDirectory, filepath.Base(filename))
	if err == nil {
		closeErr := existing.Close()
		if closeErr != nil {
			return closeErr
		}
		return os.ErrExist
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	directoryInfo, err := os.Stat(bindingsDirectory)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	if err := fsutil.CopyOwnershipToFile(file, directoryInfo); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Chmod(0o640); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return fsutil.SyncDir(bindingsDirectory)
}

func ensureBindingDirectory(stateDirectory string) (string, error) {
	return ensureBindingDirectoryPlatform(stateDirectory)
}

// String deliberately does not implement a formatter for State: callers must
// never log it because it contains HMAC secrets.
func (s State) String() string {
	return fmt.Sprintf("binding state epoch=%d device=%s", s.CredentialEpoch, s.DeviceID)
}
