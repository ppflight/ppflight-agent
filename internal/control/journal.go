package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var ErrCommandConflict = errors.New("command ID was reused with different content")

type Journal struct {
	mu        sync.Mutex
	directory string
}

type journalRecord struct {
	Version   int       `json:"version"`
	CommandID string    `json:"commandId"`
	Digest    string    `json:"digest"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	Receipt   *Receipt  `json:"receipt,omitempty"`
}

func OpenJournal(directory string) (*Journal, error) {
	if directory == "" || filepath.Clean(directory) == string(filepath.Separator) {
		return nil, errors.New("control journal directory is invalid")
	}
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return nil, err
	}
	return &Journal{directory: directory}, nil
}

// Claim records receipt before execution. Existing incomplete commands are
// returned as indeterminate and are never automatically executed again.
func (j *Journal) Claim(command Command, now time.Time) (Receipt, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	digest := Digest(command)
	filename := j.path(command.CommandID)
	existing, err := readJournal(filename)
	if err == nil {
		if existing.Digest != digest {
			return Receipt{}, false, ErrCommandConflict
		}
		if existing.Receipt != nil {
			return *existing.Receipt, true, nil
		}
		return Receipt{}, true, errors.New("command execution state is indeterminate; manual reconciliation required")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return Receipt{}, false, err
	}
	record := journalRecord{Version: SchemaVersion, CommandID: command.CommandID, Digest: digest, State: "received", CreatedAt: now.UTC(), UpdatedAt: now.UTC()}
	if err := writeJournal(filename, record); err != nil {
		return Receipt{}, false, err
	}
	return Receipt{}, false, nil
}

func (j *Journal) Complete(command Command, receipt Receipt) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	filename := j.path(command.CommandID)
	record, err := readJournal(filename)
	if err != nil {
		return err
	}
	if record.Digest != Digest(command) {
		return ErrCommandConflict
	}
	record.State, record.UpdatedAt, record.Receipt = receipt.State, receipt.FinishedAt.UTC(), &receipt
	return writeJournal(filename, record)
}

func (j *Journal) path(commandID string) string {
	sum := sha256.Sum256([]byte(commandID))
	return filepath.Join(j.directory, hex.EncodeToString(sum[:16])+".json")
}

func readJournal(filename string) (journalRecord, error) {
	raw, err := os.ReadFile(filename)
	if err != nil {
		return journalRecord{}, err
	}
	var record journalRecord
	if err := json.Unmarshal(raw, &record); err != nil || record.Version != SchemaVersion || record.CommandID == "" || record.Digest == "" {
		return journalRecord{}, fmt.Errorf("control journal record is corrupt")
	}
	return record, nil
}

func writeJournal(filename string, record journalRecord) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	directory := filepath.Dir(filename)
	temporary, err := os.CreateTemp(directory, ".journal-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
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
	if err := os.Rename(temporaryName, filename); err != nil {
		return err
	}
	handle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}
