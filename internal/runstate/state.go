// Package runstate persists wire sequences independently of delivery queues.
package runstate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/ppflight/ppflight-agent/internal/protocol"
)

const version = 1

type State struct {
	mu       sync.Mutex
	filename string
	value    document
}

type document struct {
	Version            int    `json:"version"`
	BootID             string `json:"bootId"`
	WebsiteSequence    uint64 `json:"websiteSequence,string"`
	MonitoringSequence uint64 `json:"monitoringSequence,string"`
}

func Open(filename string) (*State, error) {
	if filename == "" || filepath.Clean(filename) == string(filepath.Separator) {
		return nil, errors.New("run state filename is invalid")
	}
	result := &State{filename: filename, value: document{Version: version}}
	raw, err := os.ReadFile(filename)
	if err == nil {
		if json.Unmarshal(raw, &result.value) != nil || result.value.Version != version {
			return nil, errors.New("run state is corrupt or unsupported")
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("read run state: %w", err)
	}
	bootID, err := protocol.NewID()
	if err != nil {
		return nil, err
	}
	result.value.BootID, result.value.MonitoringSequence = bootID, 0
	if err := result.persist(); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *State) BootID() string { s.mu.Lock(); defer s.mu.Unlock(); return s.value.BootID }

func (s *State) NextWebsite() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.value.WebsiteSequence++
	if err := s.persist(); err != nil {
		s.value.WebsiteSequence--
		return 0, err
	}
	return s.value.WebsiteSequence, nil
}

func (s *State) NextMonitoring() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.value.MonitoringSequence++
	if err := s.persist(); err != nil {
		s.value.MonitoringSequence--
		return 0, err
	}
	return s.value.MonitoringSequence, nil
}

func (s *State) persist() error {
	if err := os.MkdirAll(filepath.Dir(s.filename), 0o750); err != nil {
		return err
	}
	raw, err := json.Marshal(s.value)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(s.filename), ".run-state-")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(raw); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, s.filename); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(s.filename))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
