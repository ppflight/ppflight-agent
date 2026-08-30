package control

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ppflight/ppflight-agent/internal/auditlog"
	"github.com/ppflight/ppflight-agent/internal/fsutil"
	"github.com/ppflight/ppflight-agent/internal/inventory"
	"github.com/ppflight/ppflight-agent/internal/protocol"
	"github.com/ppflight/ppflight-agent/internal/store"
)

type ReceiptQueue interface {
	Enqueue(batchID string, payload []byte) (store.Item, bool, error)
}

// TaskResolver isolates recovery from the PVE client. Implementations resolve
// one already-submitted UPID and must not submit or mutate anything.
type TaskResolver interface {
	ResolveTask(ctx context.Context, nodeRef, upid string) (TaskResolution, error)
}

// UpgradeResolver reads the root helper's durable terminal result. It never
// performs, retries, or downloads an upgrade.
type UpgradeResolver interface {
	ResolveUpgrade(ctx context.Context, upgradeID string) (UpgradeResolution, error)
}

type UpgradeResolution struct {
	Status  string
	Version string
	Code    string
}

// TaskResolution is intentionally a small PVE-neutral task view. Status is
// normally "queued", "running", or a terminal value; ExitStatus is "OK" only
// for a successful terminal task.
type TaskResolution struct {
	Status     string
	ExitStatus string
}

type ServiceConfig struct {
	AgentRef            string
	ClusterRef          string
	BindingID           string
	DeviceID            string
	CredentialEpoch     uint64
	AssignmentRevision  func() uint64
	AgentVersion        string
	Mode                string
	CommandSecret       []byte
	CommandSigningKeyID string
	CommandPublicKey    ed25519.PublicKey
	AllowedActions      []string
	Assignments         *inventory.Store
	Poller              Poller
	Journal             *Journal
	Executor            Executor
	TaskResolver        TaskResolver
	UpgradeResolver     UpgradeResolver
	ReceiptQueue        ReceiptQueue
	AuditSink           auditlog.Sink
	CursorFile          string
	Now                 func() time.Time
}

type Service struct {
	mu                  sync.Mutex
	agentRef            string
	clusterRef          string
	bindingID           string
	deviceID            string
	credentialEpoch     uint64
	assignmentRevision  func() uint64
	agentVersion        string
	mode                string
	commandSecret       []byte
	commandSigningKeyID string
	commandPublicKey    ed25519.PublicKey
	allowed             map[string]bool
	assignments         *inventory.Store
	poller              Poller
	journal             *Journal
	executor            Executor
	taskResolver        TaskResolver
	upgradeResolver     UpgradeResolver
	receiptQueue        ReceiptQueue
	auditSink           auditlog.Sink
	cursorFile          string
	cursor              string
	now                 func() time.Time
}

func NewService(cfg ServiceConfig) (*Service, error) {
	if cfg.AgentRef == "" || cfg.ClusterRef == "" || cfg.Assignments == nil || cfg.Poller == nil || cfg.Journal == nil || cfg.ReceiptQueue == nil || cfg.CursorFile == "" {
		return nil, errors.New("control service dependencies are required")
	}
	if cfg.Mode != "test" && cfg.Mode != "production" {
		return nil, errors.New("control service mode is invalid")
	}
	for _, action := range cfg.AllowedActions {
		if _, ok := protocolActions[action]; !ok {
			return nil, fmt.Errorf("control action %q is not part of the protocol", action)
		}
	}
	if cfg.Mode == "production" && (cfg.CommandSigningKeyID == "" || len(cfg.CommandPublicKey) != ed25519.PublicKeySize) {
		return nil, errors.New("production control requires an Ed25519 signing key")
	}
	if cfg.Mode == "production" && (!uuidRE.MatchString(cfg.BindingID) || !commandIDRE.MatchString(cfg.DeviceID) || cfg.CredentialEpoch == 0 || cfg.AssignmentRevision == nil) {
		return nil, errors.New("production control requires active binding authority")
	}
	if cfg.AuditSink != nil && !validAuditText(cfg.AgentVersion, 128) {
		return nil, errors.New("control audit agent version is invalid")
	}
	if cfg.CommandSigningKeyID != "" && !commandIDRE.MatchString(cfg.CommandSigningKeyID) {
		return nil, errors.New("control signing key ID is invalid")
	}
	if cfg.Mode == "test" && len(cfg.CommandPublicKey) > 0 && (cfg.CommandSigningKeyID == "" || len(cfg.CommandPublicKey) != ed25519.PublicKeySize) {
		return nil, errors.New("control Ed25519 signing key is invalid")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.TaskResolver == nil && cfg.Executor.ReadClient != nil {
		cfg.TaskResolver = pveClientTaskResolver{client: cfg.Executor.ReadClient}
	} else if cfg.TaskResolver == nil && cfg.Executor.Client != nil {
		cfg.TaskResolver = pveClientTaskResolver{client: cfg.Executor.Client}
	}
	cfg.Executor.Mode = cfg.Mode
	service := &Service{
		agentRef: cfg.AgentRef, clusterRef: cfg.ClusterRef, bindingID: cfg.BindingID, deviceID: cfg.DeviceID,
		credentialEpoch: cfg.CredentialEpoch, assignmentRevision: cfg.AssignmentRevision,
		agentVersion: cfg.AgentVersion, mode: cfg.Mode,
		commandSecret: append([]byte(nil), cfg.CommandSecret...), commandSigningKeyID: cfg.CommandSigningKeyID,
		commandPublicKey: append(ed25519.PublicKey(nil), cfg.CommandPublicKey...), allowed: AllowedSet(cfg.AllowedActions),
		assignments: cfg.Assignments, poller: cfg.Poller, journal: cfg.Journal,
		executor: cfg.Executor, taskResolver: cfg.TaskResolver, upgradeResolver: cfg.UpgradeResolver, receiptQueue: cfg.ReceiptQueue,
		auditSink: cfg.AuditSink, cursorFile: cfg.CursorFile, now: cfg.Now,
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
		verifyErr := Verify(command, VerifyConfig{
			AgentRef: s.agentRef, ClusterRef: s.clusterRef, Mode: s.mode, Secret: s.commandSecret,
			BindingID: s.bindingID, DeviceID: s.deviceID, CredentialEpoch: s.credentialEpoch,
			AssignmentRevision: s.assignmentRevision,
			SigningKeyID:       s.commandSigningKeyID, PublicKey: s.commandPublicKey,
			Allowed: s.allowed, Assignments: s.assignments, Now: now,
		})
		if verifyErr != nil {
			code := "COMMAND_REJECTED"
			if errors.Is(verifyErr, ErrAuthenticatedPolicy) && requiresApproval(command.Action) && s.auditSink == nil {
				code = "AUDIT_UNAVAILABLE"
			}
			receipt, receiptErr := s.rejection(command, code, now)
			if receiptErr != nil {
				return processed, receiptErr
			}
			if errors.Is(verifyErr, ErrAuthenticatedPolicy) && requiresApproval(command.Action) && s.auditSink != nil {
				if err := s.enqueueDeniedAudit(command, receipt, now); err != nil {
					return processed, err
				}
			} else if err := s.enqueue(receipt); err != nil {
				return processed, err
			}
			processed++
			continue
		}
		auditable := requiresApproval(command.Action)
		if auditable && s.auditSink == nil {
			receipt, receiptErr := s.rejection(command, "AUDIT_UNAVAILABLE", now)
			if receiptErr != nil {
				return processed, receiptErr
			}
			if err := s.enqueue(receipt); err != nil {
				return processed, err
			}
			processed++
			continue
		}
		var receipt Receipt
		var duplicate bool
		var claimErr error
		if auditable && s.auditSink != nil {
			receipt, duplicate, claimErr = s.journal.ClaimWithAudit(command, now, s.agentVersion)
		} else {
			receipt, duplicate, claimErr = s.journal.Claim(command, now)
		}
		journaled := false
		switch {
		case errors.Is(claimErr, ErrCommandConflict):
			receipt, err = s.rejection(command, "COMMAND_ID_CONFLICT", now)
		case errors.Is(claimErr, ErrResourceBusy):
			receipt, err = s.rejection(command, "RESOURCE_BUSY", now)
		case claimErr != nil:
			receipt, err = s.rejection(command, "JOURNAL_UNAVAILABLE", now)
		case duplicate:
			journaled = true
			err = nil
		default:
			receipt, err = s.executor.Execute(ctx, command, now)
			receipt.OperationID = command.OperationID
			ApplyReceiptCompatibility(&receipt)
			// The public receipt carries only bounded safe codes. The underlying
			// PVE error is intentionally not serialized or returned to the API.
			if completeErr := s.journal.Complete(command, receipt); completeErr != nil {
				return processed, completeErr
			}
			journaled = true
		}
		if err != nil && receipt.ReceiptID == "" {
			return processed, err
		}
		if journaled {
			err = s.enqueueJournaled(command.CommandID, receipt)
		} else if auditable && s.auditSink != nil {
			err = s.enqueueDeniedAudit(command, receipt, now)
		} else {
			err = s.enqueue(receipt)
		}
		if err != nil {
			return processed, err
		}
		processed++
	}
	if err := s.saveCursor(response.Cursor); err != nil {
		return processed, err
	}
	return processed, nil
}

// ReconcileOnce turns durable submitted/waiting UPIDs into fresh receipt
// updates. It is safe to call after every poll and after process restart: no
// command parameters are required and no task is ever submitted again.
func (s *Service) ReconcileOnce(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	updated := 0
	incomplete, err := s.journal.RecoverIncomplete(s.now().UTC(), s.mode)
	if err != nil {
		return updated, err
	}
	for _, receipt := range incomplete {
		if err := s.enqueueJournaled(receipt.CommandID, receipt); err != nil {
			return updated, err
		}
		updated++
	}
	pending, err := s.journal.PendingReceipts()
	if err != nil {
		return updated, err
	}
	for _, item := range pending {
		if err := s.enqueueJournaled(item.CommandID, item.Receipt); err != nil {
			return updated, err
		}
		updated++
	}
	// A replayed waiting receipt is delivered before another status observation
	// for the same task, preserving receipt order across a queue outage.
	if len(pending) > 0 {
		return updated, nil
	}
	tasks, err := s.journal.SubmittedWaiting()
	if err != nil {
		return updated, err
	}
	for _, task := range tasks {
		now := s.now().UTC()
		var receipt Receipt
		if task.AgentUpgradeID != "" {
			if s.upgradeResolver == nil {
				return updated, errors.New("control upgrade resolver is not configured")
			}
			result, resolveErr := s.upgradeResolver.ResolveUpgrade(ctx, task.AgentUpgradeID)
			receipt, err = s.reconciledUpgradeReceipt(task, result, resolveErr, now)
		} else {
			if s.taskResolver == nil {
				return updated, errors.New("control task resolver is not configured")
			}
			result, resolveErr := s.taskResolver.ResolveTask(ctx, task.NodeRef, task.PVETaskUPID)
			receipt, err = s.reconciledReceipt(task, result, resolveErr, now)
		}
		if err != nil {
			return updated, err
		}
		if err := s.journal.CompleteSubmitted(task, receipt); err != nil {
			return updated, err
		}
		if err := s.enqueueJournaled(task.CommandID, receipt); err != nil {
			return updated, err
		}
		updated++
	}
	return updated, nil
}

func (s *Service) reconciledUpgradeReceipt(task SubmittedTask, result UpgradeResolution, resolveErr error, now time.Time) (Receipt, error) {
	id, err := protocol.NewID()
	if err != nil {
		return Receipt{}, err
	}
	receipt := task.Receipt
	receipt.ReceiptID, receipt.OperationID, receipt.AgentUpgradeID, receipt.FinishedAt = id, task.OperationID, task.AgentUpgradeID, now
	if receipt.StartedAt.IsZero() {
		receipt.StartedAt = now
	}
	if receipt.FinishedAt.Before(receipt.StartedAt) {
		receipt.FinishedAt = receipt.StartedAt
	}
	if resolveErr != nil {
		receipt.State, receipt.Code = "waiting", "AGENT_UPGRADE_STATUS_INDETERMINATE"
	} else {
		switch strings.ToLower(strings.TrimSpace(result.Status)) {
		case "pending", "running":
			receipt.State, receipt.Code = "waiting", "AGENT_UPGRADE_WAITING"
		case "succeeded":
			receipt.State, receipt.Code = "succeeded", "AGENT_UPGRADE_SUCCEEDED"
		case "rolled_back":
			receipt.State, receipt.Code = "failed", "AGENT_UPGRADE_ROLLED_BACK"
		case "failed":
			receipt.State, receipt.Code = "failed", "AGENT_UPGRADE_FAILED"
		default:
			receipt.State, receipt.Code = "waiting", "AGENT_UPGRADE_STATUS_INDETERMINATE"
		}
	}
	ApplyReceiptCompatibility(&receipt)
	return receipt, nil
}

func (s *Service) reconciledReceipt(task SubmittedTask, result TaskResolution, resolveErr error, now time.Time) (Receipt, error) {
	id, err := protocol.NewID()
	if err != nil {
		return Receipt{}, err
	}
	receipt := task.Receipt
	receipt.ReceiptID = id
	receipt.OperationID = task.OperationID
	receipt.PVETaskUPID = task.PVETaskUPID
	receipt.FinishedAt = now
	if receipt.StartedAt.IsZero() {
		receipt.StartedAt = now
	}
	if receipt.FinishedAt.Before(receipt.StartedAt) {
		receipt.FinishedAt = receipt.StartedAt
	}
	if resolveErr != nil {
		// A status read failure says nothing about the already-submitted task.
		// Keep the durable UPID eligible for the next reconciliation pass.
		receipt.State, receipt.Code = "waiting", "PVE_TASK_STATUS_INDETERMINATE"
	} else {
		switch strings.ToLower(strings.TrimSpace(result.Status)) {
		case "queued", "running":
			receipt.State, receipt.Code = "waiting", "PVE_TASK_WAITING"
		case "stopped":
			if strings.EqualFold(strings.TrimSpace(result.ExitStatus), "OK") {
				receipt.State, receipt.Code = "succeeded", "SUCCEEDED"
			} else {
				receipt.State, receipt.Code = "failed", "PVE_TASK_FAILED"
			}
		default:
			receipt.State, receipt.Code = "waiting", "PVE_TASK_STATUS_INDETERMINATE"
		}
	}
	ApplyReceiptCompatibility(&receipt)
	return receipt, nil
}

func (s *Service) rejection(command Command, code string, now time.Time) (Receipt, error) {
	id, err := protocol.NewID()
	if err != nil {
		return Receipt{}, err
	}
	return Receipt{
		SchemaVersion: SchemaVersion, ReceiptID: id, CommandID: command.CommandID, OperationID: command.OperationID,
		AgentRef: s.agentRef, State: "rejected", Code: code, ExecutionMode: s.mode,
		DryRun:    s.mode != "production" || !s.executor.ProductionExecution,
		StartedAt: now, FinishedAt: now, OperatorRef: command.OperatorRef,
	}, nil
}

func (s *Service) enqueue(receipt Receipt) error {
	ApplyReceiptCompatibility(&receipt)
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

func (s *Service) enqueueJournaled(commandID string, receipt Receipt) error {
	event, pending, err := s.journal.PendingAuditForReceipt(commandID, receipt.ReceiptID)
	if err != nil {
		return err
	}
	if pending {
		if s.auditSink == nil {
			return errors.New("control audit sink is unavailable")
		}
		if err := s.auditSink.Enqueue(event); err != nil {
			return err
		}
		if err := s.journal.MarkAuditQueued(commandID, event.EventID); err != nil {
			return err
		}
	}
	if err := s.enqueue(receipt); err != nil {
		return err
	}
	return s.journal.MarkReceiptQueued(commandID, receipt.ReceiptID)
}

func (s *Service) enqueueDeniedAudit(command Command, receipt Receipt, receivedAt time.Time) error {
	if s.auditSink == nil {
		return errors.New("control audit sink is unavailable")
	}
	context, err := newAuditContext(command, receivedAt, s.agentVersion)
	if err != nil {
		return err
	}
	event, err := auditEventFromReceipt(context, receipt)
	if err != nil {
		return err
	}
	// A denied command was authenticated but never accepted for execution.
	event.AcceptedAt = nil
	event.StartedAt = nil
	if err := event.Validate(); err != nil {
		return err
	}
	if err := s.auditSink.Enqueue(event); err != nil {
		return err
	}
	return s.enqueue(receipt)
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
	if err := fsutil.EnsurePrivateDirectory(filepath.Dir(s.cursorFile)); err != nil {
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
	if err := fsutil.SyncDir(filepath.Dir(s.cursorFile)); err != nil {
		return err
	}
	s.cursor = cursor
	return nil
}
