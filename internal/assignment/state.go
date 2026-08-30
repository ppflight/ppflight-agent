package assignment

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/ppflight/ppflight-agent/internal/fsutil"
)

const durableStateVersion = 1

type durableState struct {
	Version  int    `json:"version"`
	Revision uint64 `json:"revision,string"`
	Cursor   string `json:"cursor"`
}

// LoadState reads the opaque long-poll cursor. A missing file is the initial
// state; corruption fails closed instead of silently rolling the revision back.
func LoadState(filename string) (State, error) {
	raw, err := os.ReadFile(filename)
	if errors.Is(err, fs.ErrNotExist) {
		return State{}, nil
	}
	if err != nil {
		return State{}, fmt.Errorf("read assignment refresh state: %w", err)
	}
	if len(raw) > 4096 {
		return State{}, errors.New("assignment refresh state exceeds maximum size")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value durableState
	if err := decoder.Decode(&value); err != nil {
		return State{}, errors.New("assignment refresh state is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF || value.Version != durableStateVersion || value.Revision == 0 || !safeID.MatchString(value.Cursor) {
		return State{}, errors.New("assignment refresh state is invalid")
	}
	return State{Revision: value.Revision, Cursor: value.Cursor}, nil
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
