package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ppflight/ppflight-agent/internal/inventory"
	"github.com/ppflight/ppflight-agent/internal/protocol"
	"github.com/ppflight/ppflight-agent/internal/store"
)

type ReceiptQueue interface {
	Enqueue(batchID string, payload []byte) (store.Item, bool, error)
}

type ServiceConfig struct {
	AgentRef       string
	ClusterRef     string
	Mode           string
	CommandSecret  []byte
	AllowedActions []string
	Assignments    *inventory.Store
	Poller         Poller
	Journal        *Journal
	Executor       Executor
	ReceiptQueue   ReceiptQueue
	CursorFile     string
	Now            func() time.Time
}

type Service struct {
	mu            sync.Mutex
	agentRef      string
	clusterRef    string
	mode          string
	commandSecret []byte
	allowed       map[string]bool
	assignments   *inventory.Store
	poller        Poller
	journal       *Journal
	executor      Executor
	receiptQueue  ReceiptQueue
	cursorFile    string
	cursor        string
	now           func() time.Time
}

func NewService(cfg ServiceConfig) (*Service, error) {
	if cfg.AgentRef == "" || cfg.ClusterRef == "" || cfg.Assignments == nil || cfg.Poller == nil || cfg.Journal == nil || cfg.ReceiptQueue == nil || cfg.CursorFile == "" {
		return nil, errors.New("control service dependencies are required")
	}
	if cfg.Mode != "test" && cfg.Mode != "production" {
		return nil, errors.New("control service mode is invalid")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	service := &Service{
		agentRef: cfg.AgentRef, clusterRef: cfg.ClusterRef, mode: cfg.Mode,
		commandSecret: append([]byte(nil), cfg.CommandSecret...), allowed: AllowedSet(cfg.AllowedActions),
		assignments: cfg.Assignments, poller: cfg.Poller, journal: cfg.Journal,
		executor: cfg.Executor, receiptQueue: cfg.ReceiptQueue, cursorFile: cfg.CursorFile, now: cfg.Now,
	}
	if err := service.loadCursor(); err != nil {
		return nil, err
	}
	return service, nil
}

// PollOnce advances the server cursor only after every command has a durable
// result in the receipt queue. A crash after PVE execution is reconciled from
// the command journal and cannot silently execute the command twice.
func (s *Service) PollOnce(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	response, err := s.poller.Poll(ctx, s.cursor)
	if err != nil {
		return 0, err
	}
	processed := 0
	for _, command := range response.Commands {
		now := s.now().UTC()
		if err := Verify(command, VerifyConfig{
			AgentRef: s.agentRef, ClusterRef: s.clusterRef, Secret: s.commandSecret,
			Allowed: s.allowed, Assignments: s.assignments, Now: now,
		}); err != nil {
			receipt, receiptErr := s.rejection(command, "COMMAND_REJECTED", now)
			if receiptErr != nil {
				return processed, receiptErr
			}
			if err := s.enqueue(receipt); err != nil {
				return processed, err
			}
			processed++
			continue
		}
		receipt, duplicate, claimErr := s.journal.Claim(command, now)
		switch {
		case errors.Is(claimErr, ErrCommandConflict):
			receipt, err = s.rejection(command, "COMMAND_ID_CONFLICT", now)
		case claimErr != nil:
			receipt, err = s.rejection(command, "EXECUTION_INDETERMINATE", now)
		case duplicate:
			err = nil
		default:
			receipt, err = s.executor.Execute(ctx, command, now)
			// The public receipt carries only bounded safe codes. The underlying
			// PVE error is intentionally not serialized or returned to the API.
			if completeErr := s.journal.Complete(command, receipt); completeErr != nil {
				return processed, completeErr
			}
		}
		if err != nil && receipt.ReceiptID == "" {
			return processed, err
		}
		if err := s.enqueue(receipt); err != nil {
			return processed, err
		}
		processed++
	}
	if err := s.saveCursor(response.Cursor); err != nil {
		return processed, err
	}
	return processed, nil
}

func (s *Service) rejection(command Command, code string, now time.Time) (Receipt, error) {
	id, err := protocol.NewID()
	if err != nil {
		return Receipt{}, err
	}
	return Receipt{
		SchemaVersion: SchemaVersion, ReceiptID: id, CommandID: command.CommandID,
		AgentRef: s.agentRef, State: "rejected", Code: code, ExecutionMode: s.mode,
		DryRun:    s.mode != "production" || !s.executor.ProductionExecution,
		StartedAt: now, FinishedAt: now, OperatorRef: command.OperatorRef,
	}, nil
}

func (s *Service) enqueue(receipt Receipt) error {
	if err := receipt.Validate(); err != nil {
		return err
	}
	payload, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	_, _, err = s.receiptQueue.Enqueue(receipt.ReceiptID, payload)
	return err
}

type cursorState struct {
	Version int    `json:"version"`
	Cursor  string `json:"cursor"`
}

func (s *Service) loadCursor() error {
	raw, err := os.ReadFile(s.cursorFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read control cursor: %w", err)
	}
	var state cursorState
	if err := json.Unmarshal(raw, &state); err != nil || state.Version != SchemaVersion {
		return errors.New("control cursor is corrupt or unsupported")
	}
	s.cursor = state.Cursor
	return nil
}

func (s *Service) saveCursor(cursor string) error {
	if cursor == "" {
		return errors.New("refusing to persist an empty control cursor")
	}
	if err := os.MkdirAll(filepath.Dir(s.cursorFile), 0o750); err != nil {
		return err
	}
	raw, err := json.Marshal(cursorState{Version: SchemaVersion, Cursor: cursor})
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(s.cursorFile), ".cursor-")
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
	if err := os.Rename(name, s.cursorFile); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(s.cursorFile))
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return err
	}
	s.cursor = cursor
	return nil
}
