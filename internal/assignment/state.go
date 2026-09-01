package assignment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"github.com/ppflight/ppflight-agent/internal/fsutil"
	"github.com/ppflight/ppflight-agent/internal/inventory"
)

const (
	durableStateVersion     = 1
	durableAuthorityVersion = 2
	maxDurableAuthoritySize = MaxResponseBytes + (64 << 10)
)

var bindingUUID = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type durableState struct {
	Version  int    `json:"version"`
	Revision uint64 `json:"revision,string"`
	Cursor   string `json:"cursor"`
}

// Authority is the crash-consistent remote assignment authority. Version 2
// keeps the exact signed document beside its monotonic cursor so a restart can
// never combine a new inventory/allowedActions document with an old revision,
// or vice versa.
type Authority struct {
	State       State
	Document    inventory.Document
	DocumentRaw json.RawMessage
	Present     bool
}

// AuthorityScope binds a durable assignment authority to one website binding
// epoch. It prevents a copied or stale refresh-state file from authorizing a
// different enrollment even when the device and cluster are unchanged.
type AuthorityScope struct {
	BindingID       string
	DeviceID        string
	CredentialEpoch uint64
}

type durableAuthority struct {
	Version            int             `json:"version"`
	BindingID          string          `json:"bindingId"`
	DeviceID           string          `json:"deviceId"`
	CredentialEpoch    uint64          `json:"credentialEpoch,string"`
	Revision           uint64          `json:"revision,string"`
	Cursor             string          `json:"cursor"`
	ContentSHA256      string          `json:"contentSha256"`
	AssignmentDocument json.RawMessage `json:"assignmentDocument"`
}

type durableHeader struct {
	Version int `json:"version"`
}

// LoadState reads the opaque long-poll cursor. A missing file is the initial
// state; corruption fails closed instead of silently rolling the revision back.
func LoadState(filename string) (State, error) {
	authority, err := LoadAuthority(filename, "")
	return authority.State, err
}

// LoadAuthority accepts the legacy cursor-only v1 state and the atomic v2
// authority snapshot. A legacy result has Present=false and callers continue
// loading the separately persisted assignment file until the first v2 bundle.
func LoadAuthority(filename, expectedClusterRef string, expectedScope ...AuthorityScope) (Authority, error) {
	raw, err := os.ReadFile(filename)
	if errors.Is(err, fs.ErrNotExist) {
		return Authority{}, nil
	}
	if err != nil {
		return Authority{}, fmt.Errorf("read assignment refresh state: %w", err)
	}
	if len(raw) > maxDurableAuthoritySize {
		return Authority{}, errors.New("assignment refresh state exceeds maximum size")
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return Authority{}, errors.New("assignment refresh state is invalid")
	}
	var header durableHeader
	if err := json.Unmarshal(raw, &header); err != nil {
		return Authority{}, errors.New("assignment refresh state is invalid")
	}
	if header.Version == durableAuthorityVersion {
		return decodeAuthority(raw, expectedClusterRef, expectedScope...)
	}
	if len(raw) > 4096 {
		return Authority{}, errors.New("assignment refresh state exceeds maximum size")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value durableState
	if err := decoder.Decode(&value); err != nil {
		return Authority{}, errors.New("assignment refresh state is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF || value.Version != durableStateVersion || value.Revision == 0 || !safeID.MatchString(value.Cursor) {
		return Authority{}, errors.New("assignment refresh state is invalid")
	}
	return Authority{State: State{Revision: value.Revision, Cursor: value.Cursor}}, nil
}

func decodeAuthority(raw []byte, expectedClusterRef string, expectedScope ...AuthorityScope) (Authority, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value durableAuthority
	if err := decoder.Decode(&value); err != nil {
		return Authority{}, errors.New("assignment refresh authority is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF || value.Version != durableAuthorityVersion || !bindingUUID.MatchString(value.BindingID) || !safeID.MatchString(value.DeviceID) || value.CredentialEpoch == 0 || value.Revision == 0 || !safeID.MatchString(value.Cursor) || len(value.AssignmentDocument) == 0 || len(value.ContentSHA256) != sha256.Size*2 || !isLowerHex(value.ContentSHA256) {
		return Authority{}, errors.New("assignment refresh authority is invalid")
	}
	if len(expectedScope) > 1 || (len(expectedScope) == 1 && (expectedScope[0].BindingID != value.BindingID || expectedScope[0].DeviceID != value.DeviceID || expectedScope[0].CredentialEpoch != value.CredentialEpoch)) {
		return Authority{}, errors.New("assignment refresh authority binding scope mismatch")
	}
	digest := sha256.Sum256(value.AssignmentDocument)
	if !bytes.Equal([]byte(value.ContentSHA256), []byte(hex.EncodeToString(digest[:]))) {
		return Authority{}, errors.New("assignment refresh authority content hash mismatch")
	}
	document, err := inventory.Parse(value.AssignmentDocument, expectedClusterRef)
	if err != nil || document.AllowedActions == nil {
		return Authority{}, errors.New("assignment refresh authority document is invalid")
	}
	return Authority{
		State: State{Revision: value.Revision, Cursor: value.Cursor}, Document: document,
		DocumentRaw: append(json.RawMessage(nil), value.AssignmentDocument...), Present: true,
	}, nil
}

// SaveState atomically advances the durable cursor after the corresponding
// assignment document has been persisted successfully.
func SaveState(filename string, state State) error {
	if state.Revision == 0 || !safeID.MatchString(state.Cursor) {
		return errors.New("assignment refresh state is invalid")
	}
	if err := fsutil.EnsurePrivateDirectory(filepath.Dir(filename)); err != nil {
		return err
	}
	raw, err := json.Marshal(durableState{Version: durableStateVersion, Revision: state.Revision, Cursor: state.Cursor})
	if err != nil {
		return errors.New("encode assignment refresh state")
	}
	return fsutil.AtomicWriteFile(filename, append(raw, '\n'), 0o600, true)
}

// SaveAuthority atomically persists revision, cursor, inventory identities and
// signed allowedActions as one file. The compatibility assignments file may be
// refreshed afterwards, but version-2 readers never use it as authority.
func SaveAuthority(filename string, state State, documentRaw json.RawMessage, expectedClusterRef string, scope AuthorityScope) error {
	if state.Revision == 0 || !safeID.MatchString(state.Cursor) || !bindingUUID.MatchString(scope.BindingID) || !safeID.MatchString(scope.DeviceID) || scope.CredentialEpoch == 0 {
		return errors.New("assignment refresh authority state is invalid")
	}
	document, err := inventory.Parse(documentRaw, expectedClusterRef)
	if err != nil || document.AllowedActions == nil {
		return errors.New("assignment refresh authority document is invalid")
	}
	if err := fsutil.EnsurePrivateDirectory(filepath.Dir(filename)); err != nil {
		return err
	}
	digest := sha256.Sum256(documentRaw)
	raw, err := json.Marshal(durableAuthority{
		Version: durableAuthorityVersion, BindingID: scope.BindingID, DeviceID: scope.DeviceID, CredentialEpoch: scope.CredentialEpoch,
		Revision: state.Revision, Cursor: state.Cursor,
		ContentSHA256: hex.EncodeToString(digest[:]), AssignmentDocument: append(json.RawMessage(nil), documentRaw...),
	})
	if err != nil {
		return errors.New("encode assignment refresh authority")
	}
	if len(raw) > maxDurableAuthoritySize {
		return errors.New("assignment refresh authority exceeds maximum size")
	}
	return fsutil.AtomicWriteFile(filename, append(raw, '\n'), 0o600, true)
}
