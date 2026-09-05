package control

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
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
	Error   *ExecutionError
}

// TaskResolution is intentionally a small PVE-neutral task view. Status is
// normally "queued", "running", or a terminal value; ExitStatus is "OK" only
// for a successful terminal task.
type TaskResolution struct {
	Status     string
	ExitStatus string
}

type ServiceConfig struct {
	AgentRef           string
	ClusterRef         string
	BindingID          string
	DeviceID           string
	CredentialEpoch    uint64
	AssignmentRevision func() uint64
	// AssignmentAuthorityDynamic means revision, inventory and allowedActions
	// were restored from one atomic signed authority snapshot. Legacy callers
	// keep using AssignmentRevision until the first dynamic authority is applied.
	AssignmentAuthorityDynamic bool
	AgentVersion               string
	Mode                       string
	CommandSecret              []byte
	CommandSigningKeyID        string
	CommandPublicKey           ed25519.PublicKey
	AllowedActions             []string
	Assignments                *inventory.Store
	Poller                     Poller
	Journal                    *Journal
	Executor                   Executor
	TaskResolver               TaskResolver
	UpgradeResolver            UpgradeResolver
	ReceiptQueue               ReceiptQueue
	AuditSink                  auditlog.Sink
	CursorFile                 string
	Now                        func() time.Time
}

type Service struct {
	mu                   sync.Mutex
	agentRef             string
	clusterRef           string
	bindingID            string
	deviceID             string
	credentialEpoch      uint64
	assignmentRevision   uint64
	assignmentRevisionFn func() uint64
	dynamicAuthority     bool
	agentVersion         string
	mode                 string
	commandSecret        []byte
	commandSigningKeyID  string
	commandPublicKey     ed25519.PublicKey
	allowed              map[string]bool
	assignments          *inventory.Store
	poller               Poller
	journal              *Journal
	executor             Executor
	taskResolver         TaskResolver
	upgradeResolver      UpgradeResolver
	receiptQueue         ReceiptQueue
	auditSink            auditlog.Sink
	cursorFile           string
	cursor               string
	now                  func() time.Time
	dispatcher           *commandDispatcher
}

func NewService(cfg ServiceConfig) (*Service, error) {
	if cfg.AgentRef == "" || cfg.ClusterRef == "" || cfg.Assignments == nil || cfg.Poller == nil || cfg.Journal == nil || cfg.ReceiptQueue == nil || cfg.CursorFile == "" {
		return nil, errors.New("control service dependencies are required")
	}
	if cfg.Mode != "test" && cfg.Mode != "production" {
		return nil, errors.New("control service mode is invalid")
	}
	if err := validateAllowedActions(cfg.AllowedActions, false); err != nil {
		return nil, err
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
	if cfg.Executor.InitialResources == nil {
		cfg.Executor.InitialResources = cfg.Journal
	}
	if cfg.Executor.LegacyJournal == nil {
		cfg.Executor.LegacyJournal = cfg.Journal
	}
	if cfg.Executor.Delete501Journal == nil {
		cfg.Executor.Delete501Journal = cfg.Journal
	}
	if cfg.Executor.IPFilterDeleteJournal == nil {
		cfg.Executor.IPFilterDeleteJournal = cfg.Journal
	}
	if cfg.Executor.CloudInitSnippets == nil {
		cfg.Executor.CloudInitSnippets = cfg.Journal
	}
	cfg.Executor.Mode = cfg.Mode
	service := &Service{
		agentRef: cfg.AgentRef, clusterRef: cfg.ClusterRef, bindingID: cfg.BindingID, deviceID: cfg.DeviceID,
		credentialEpoch: cfg.CredentialEpoch, assignmentRevision: assignmentRevision(cfg.AssignmentRevision), assignmentRevisionFn: cfg.AssignmentRevision,
		dynamicAuthority: cfg.AssignmentAuthorityDynamic,
		agentVersion:     cfg.AgentVersion, mode: cfg.Mode,
		commandSecret: append([]byte(nil), cfg.CommandSecret...), commandSigningKeyID: cfg.CommandSigningKeyID,
		commandPublicKey: append(ed25519.PublicKey(nil), cfg.CommandPublicKey...), allowed: AllowedSet(cfg.AllowedActions),
		assignments: cfg.Assignments, poller: cfg.Poller, journal: cfg.Journal,
		executor: cfg.Executor, taskResolver: cfg.TaskResolver, upgradeResolver: cfg.UpgradeResolver, receiptQueue: cfg.ReceiptQueue,
		auditSink: cfg.AuditSink, cursorFile: cfg.CursorFile, now: cfg.Now,
	}
	if err := service.loadCursor(); err != nil {
		return nil, err
	}
	service.dispatcher = newCommandDispatcher(service.executeDispatched)
	return service, nil
}

func assignmentRevision(current func() uint64) uint64 {
	if current == nil {
		return 0
	}
	return current()
}

// ValidateAllowedActions rejects empty, duplicate and locally unknown remote
// authorization. A signed assignment may narrow or expand its previous set,
// but it can never expand the Agent's compiled protocol registry.
func ValidateAllowedActions(actions []string) error {
	return validateAllowedActions(actions, true)
}

func validateAllowedActions(actions []string, requireNonEmpty bool) error {
	if (requireNonEmpty && len(actions) == 0) || len(actions) > 64 {
		return errors.New("control allowed actions must contain 1-64 actions")
	}
	seen := make(map[string]struct{}, len(actions))
	for _, action := range actions {
		if _, ok := protocolActions[action]; !ok {
			return fmt.Errorf("control action %q is not part of the protocol", action)
		}
		if _, duplicate := seen[action]; duplicate {
			return fmt.Errorf("control action %q is duplicated", action)
		}
		seen[action] = struct{}{}
	}
	return nil
}

// ApplyAssignmentAuthority switches the signed inventory, monotonic revision
// and allowed action set under the same mutex used by PollOnce. Command
// verification therefore observes either the complete old authority or the
// complete new authority, never a mixed revision/action/inventory view.
func (s *Service) ApplyAssignmentAuthority(document inventory.Document, revision uint64, actions []string) error {
	if s == nil || revision == 0 {
		return errors.New("assignment authority revision is invalid")
	}
	if err := document.Validate(s.clusterRef); err != nil {
		return fmt.Errorf("assignment authority document is invalid: %w", err)
	}
	if err := ValidateAllowedActions(actions); err != nil {
		return err
	}
	if len(document.AllowedActions) != len(actions) {
		return errors.New("assignment authority actions do not match signed document")
	}
	for index := range actions {
		if document.AllowedActions[index] != actions[index] {
			return errors.New("assignment authority actions do not match signed document")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	currentRevision := s.assignmentRevision
	if !s.dynamicAuthority && s.assignmentRevisionFn != nil {
		currentRevision = s.assignmentRevisionFn()
	}
	if revision <= currentRevision {
		return errors.New("assignment authority revision did not advance")
	}
	s.assignments.Replace(document)
	s.allowed = AllowedSet(actions)
	s.assignmentRevision = revision
	s.dynamicAuthority = true
	if s.executor.ConsoleSessions != nil {
		s.executor.ConsoleSessions.Invalidate()
	}
	return nil
}

// PollOnce durably admits at most one command, then hands execution to a
// bounded class-specific worker. The cursor advances only after a running or
// terminal receipt is durably queued. A crash after admission is reconciled
// from the journal and cannot silently execute a mutation twice.
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
		slog.Info("control command received",
			"operationId", command.OperationID,
			"commandId", command.CommandID,
			"action", command.Action,
			"scope", command.Scope,
			"targetNode", command.Identity.NodeRef,
			"targetVMID", command.Identity.VMID,
			"assignmentRevision", command.AssignmentRevision,
		)
		assignmentRevision := s.assignmentRevisionFn
		if s.dynamicAuthority {
			assignmentRevision = func() uint64 { return s.assignmentRevision }
		}
		verifyErr := Verify(command, VerifyConfig{
			AgentRef: s.agentRef, ClusterRef: s.clusterRef, Mode: s.mode, Secret: s.commandSecret,
			BindingID: s.bindingID, DeviceID: s.deviceID, CredentialEpoch: s.credentialEpoch,
			AssignmentRevision: assignmentRevision,
			SigningKeyID:       s.commandSigningKeyID, PublicKey: s.commandPublicKey,
			Allowed: s.allowed, Assignments: s.assignments, Now: now,
		})
		if verifyErr != nil {
			code := verificationRejectionCode(verifyErr)
			if errors.Is(verifyErr, ErrAuthenticatedPolicy) && requiresApproval(command.Action) && s.auditSink == nil {
				code = "AUDIT_UNAVAILABLE"
			}
			slog.Warn("control command rejected",
				"operationId", command.OperationID,
				"commandId", command.CommandID,
				"action", command.Action,
				"code", code,
			)
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
			slog.Error("control command audit unavailable",
				"operationId", command.OperationID,
				"commandId", command.CommandID,
				"action", command.Action,
			)
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
		// Check the class-specific executor lane before any durable claim. The
		// service admission mutex stays held through dispatcher.submit below, so
		// another poll cannot consume capacity between this check and enqueue.
		// A busy lane therefore leaves the opaque website command unclaimed and
		// its cursor unadvanced, instead of stranding a running journal record
		// which no worker owns.
		if s.mode == "production" && s.executor.ProductionExecution && !s.dispatcher.hasCapacity(ctx, command) {
			return processed, errors.New("control dispatcher lane is full")
		}
		var receipt Receipt
		var duplicate bool
		var claimErr error
		if auditable && s.auditSink != nil {
			receipt, duplicate, claimErr = s.journal.ClaimWithAudit(command, now, s.agentVersion)
		} else {
			receipt, duplicate, claimErr = s.journal.Claim(command, now)
		}
		switch {
		case claimErr != nil:
			receipt, err = s.rejection(command, claimRejectionCode(claimErr), now)
		case duplicate:
			if err = s.enqueueJournaled(command.CommandID, receipt); err == nil {
				processed++
			}
			if err != nil {
				return processed, err
			}
			continue
		default:
			// Test/dry-run execution remains synchronous so the non-production
			// contract stays deterministic. Production mutations use the
			// bounded dispatcher below.
			if s.mode != "production" || !s.executor.ProductionExecution {
				receipt, err = s.executor.Execute(ctx, command, now)
				receipt.OperationID = command.OperationID
				ApplyReceiptCompatibility(&receipt)
				if completeErr := s.journal.Complete(command, receipt); completeErr != nil {
					return processed, completeErr
				}
				logCommandReceipt(command, receipt)
				if err != nil && receipt.ReceiptID == "" {
					return processed, err
				}
				if err = s.enqueueJournaled(command.CommandID, receipt); err != nil {
					return processed, err
				}
				processed++
				continue
			}
			started, startedErr := s.runningReceipt(command, now)
			if startedErr != nil {
				return processed, startedErr
			}
			if startedErr = s.journal.BeginRunning(command, started); startedErr != nil {
				return processed, startedErr
			}
			if startedErr = s.enqueueJournaled(command.CommandID, started); startedErr != nil {
				return processed, startedErr
			}
			if !s.dispatcher.submit(ctx, command) {
				// The command is not claimed by an in-memory worker. Leave its
				// website cursor unadvanced so it cannot strand an opaque body;
				// the durable running marker makes any process loss fail closed.
				return processed, errors.New("control dispatcher lane is full")
			}
			processed++
			continue
		}
		if err != nil {
			return processed, err
		}
		logCommandReceipt(command, receipt)
		if auditable && s.auditSink != nil {
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

// executeDispatched runs outside the admission mutex. Journal resource keys
// are the durable same-VM mutation fence; different VM short operations and
// console setup can progress without waiting for a heavyweight workflow.
func (s *Service) executeDispatched(ctx context.Context, command Command) {
	now := s.now().UTC()
	slog.Info("control command execution started",
		"operationId", command.OperationID,
		"commandId", command.CommandID,
		"action", command.Action,
		"scope", command.Scope,
	)
	receipt, err := s.executor.Execute(ctx, command, now)
	receipt.OperationID = command.OperationID
	ApplyReceiptCompatibility(&receipt)
	if completeErr := s.journal.Complete(command, receipt); completeErr != nil {
		slog.Error("control command journal completion failed", "commandId", command.CommandID, "error", safeControlLogError(completeErr))
		return
	}
	logCommandReceipt(command, receipt)
	if err != nil && receipt.ReceiptID == "" {
		slog.Error("control command execution failed without receipt", "commandId", command.CommandID, "error", safeControlLogError(err))
		return
	}
	if err := s.enqueueJournaled(command.CommandID, receipt); err != nil {
		slog.Error("control command receipt delivery deferred", "commandId", command.CommandID, "error", safeControlLogError(err))
	}
}

func safeControlLogError(err error) string {
	if err == nil {
		return ""
	}
	value := err.Error()
	if len(value) > 512 {
		return value[:512]
	}
	return value
}

// logCommandReceipt emits only bounded identifiers and the same sanitized
// provider diagnostic accepted by the signed receipt contract. Parameters,
// credentials, response bodies and guest output are deliberately excluded.
func logCommandReceipt(command Command, receipt Receipt) {
	attributes := []any{
		"operationId", command.OperationID,
		"commandId", command.CommandID,
		"action", command.Action,
		"state", receipt.State,
		"code", receipt.Code,
		"durationMs", max(receipt.FinishedAt.Sub(receipt.StartedAt).Milliseconds(), 0),
		"pveTask", receipt.PVETaskUPID != "",
		"agentUpgrade", receipt.AgentUpgradeID != "",
	}
	if receipt.Error != nil {
		attributes = append(attributes,
			"errorSource", receipt.Error.Source,
			"errorStage", receipt.Error.Stage,
			"httpMethod", receipt.Error.Method,
			"httpPath", receipt.Error.Path,
			"httpStatus", receipt.Error.HTTPStatus,
			"reason", receipt.Error.Reason,
		)
		slog.Error("control command completed", attributes...)
		return
	}
	slog.Info("control command completed", attributes...)
}

// verificationRejectionCode exposes only a fixed authentication or policy
// category. Do not return wrapped errors: in particular, they can include
// local authority and assignment identifiers.
func verificationRejectionCode(err error) string {
	switch {
	case errors.Is(err, ErrCommandBodyHashInvalid):
		return "COMMAND_BODY_HASH_INVALID"
	case errors.Is(err, ErrCommandSigningKeyMismatch):
		return "COMMAND_SIGNING_KEY_MISMATCH"
	case errors.Is(err, ErrCommandSignatureInvalid):
		return "COMMAND_SIGNATURE_INVALID"
	}
	if !errors.Is(err, ErrAuthenticatedPolicy) {
		return "COMMAND_REJECTED"
	}
	switch {
	case errors.Is(err, ErrCommandAuthorityMismatch):
		return "COMMAND_AUTHORITY_MISMATCH"
	case errors.Is(err, ErrCommandActionNotAllowed):
		return "COMMAND_ACTION_NOT_ALLOWED"
	case errors.Is(err, ErrCommandExpired):
		return "COMMAND_EXPIRED"
	case errors.Is(err, ErrCommandInventoryUnavailable):
		return "COMMAND_INVENTORY_UNAVAILABLE"
	case errors.Is(err, ErrCommandIdentityMismatch):
		return "COMMAND_IDENTITY_MISMATCH"
	case errors.Is(err, ErrCommandScopeInvalid):
		return "COMMAND_SCOPE_INVALID"
	case errors.Is(err, ErrCommandParametersInvalid):
		return "INVALID_PARAMETERS"
	case errors.Is(err, ErrCommandApprovalMissing):
		return "APPROVAL_REQUIRED"
	case errors.Is(err, ErrCommandEnvelopeInvalid):
		return "COMMAND_ENVELOPE_INVALID"
	default:
		return "COMMAND_REJECTED"
	}
}

func claimRejectionCode(err error) string {
	var ipFilterEligibility *ipFilterDeleteRecoveryEligibilityError
	if errors.As(err, &ipFilterEligibility) {
		return ipFilterEligibility.receiptCode()
	}
	switch {
	case errors.Is(err, ErrCommandConflict):
		return "COMMAND_ID_CONFLICT"
	case errors.Is(err, ErrOperationConflict):
		return "OPERATION_ID_CONFLICT"
	case errors.Is(err, ErrIdempotencyConflict):
		return "IDEMPOTENCY_KEY_CONFLICT"
	case errors.Is(err, ErrResourceBusy):
		return "RESOURCE_BUSY"
	case errors.Is(err, ErrUnlistedActiveMutation):
		return "UNLISTED_ACTIVE_MUTATION"
	case errors.Is(err, ErrListedRecordNotEligible):
		return "LISTED_RECORD_NOT_ELIGIBLE"
	case errors.Is(err, ErrCloneJournalNotFound):
		return "CLONE_JOURNAL_NOT_FOUND"
	case errors.Is(err, ErrCloneDigestMismatch):
		return "CLONE_DIGEST_MISMATCH"
	case errors.Is(err, ErrCloneResourceIdentityMismatch):
		return "CLONE_RESOURCE_IDENTITY_MISMATCH"
	case errors.Is(err, ErrCloneTerminalReceiptInvalid):
		return "CLONE_TERMINAL_RECEIPT_INVALID"
	case errors.Is(err, ErrCloneLegacyAuthorityMismatch):
		return "CLONE_LEGACY_AUTHORITY_MISMATCH"
	case errors.Is(err, ErrCloneAlreadyMigrated):
		return "CLONE_ALREADY_MIGRATED"
	default:
		return "JOURNAL_UNAVAILABLE"
	}
}

// ReconcileOnce turns durable submitted/waiting UPIDs into fresh receipt
// updates. It is safe to call after every poll and after process restart: no
// command parameters are required and no task is ever submitted again.
func (s *Service) ReconcileOnce(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	updated := 0
	incomplete, err := s.journal.RecoverIncompleteExcept(s.now().UTC(), s.mode, s.dispatcher.activeCommand)
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
			if task.Action == "vm.cloud-init-snippet.delete" {
				receipt, err = s.reconciledSnippetDeleteReceipt(ctx, task, result, resolveErr, now)
			} else {
				receipt, err = s.reconciledReceipt(task, result, resolveErr, now)
			}
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

func (s *Service) reconciledSnippetDeleteReceipt(ctx context.Context, task SubmittedTask, result TaskResolution, resolveErr error, now time.Time) (Receipt, error) {
	receipt, err := s.reconciledReceipt(task, result, resolveErr, now)
	if err != nil {
		return Receipt{}, err
	}
	currentRevision := s.assignmentRevision
	if !s.dynamicAuthority && s.assignmentRevisionFn != nil {
		currentRevision = s.assignmentRevisionFn()
	}
	authorityMatches := task.BindingID == s.bindingID && task.DeviceID == s.deviceID && uint64(task.CredentialEpoch) == s.credentialEpoch &&
		uint64(task.AssignmentRevision) == currentRevision && task.AgentRef == s.agentRef && task.ClusterRef == s.clusterRef
	if authorityMatches {
		if s.assignments == nil {
			authorityMatches = false
		} else {
			assignment, ok := s.assignments.Lookup(task.ClusterRef, task.GuestType, task.VMID)
			authorityMatches = ok && assignment.ServiceRef == task.ServiceRef && assignment.InstanceUUID == task.InstanceUUID &&
				assignment.Generation == uint64(task.Generation) && (assignment.NodeRef == "" || assignment.NodeRef == task.NodeRef)
		}
	}
	if !authorityMatches {
		receipt.State, receipt.Code, receipt.Result, receipt.PVETaskUPID = "indeterminate", "CLOUD_INIT_SNIPPET_DELETE_INDETERMINATE", nil, ""
		ApplyReceiptCompatibility(&receipt)
		return receipt, nil
	}
	if resolveErr != nil {
		receipt.State, receipt.Code, receipt.PVETaskUPID = "waiting", "CLOUD_INIT_SNIPPET_DELETE_INDETERMINATE", ""
		ApplyReceiptCompatibility(&receipt)
		return receipt, nil
	}
	if strings.ToLower(strings.TrimSpace(result.Status)) != "stopped" {
		receipt.PVETaskUPID = ""
		ApplyReceiptCompatibility(&receipt)
		return receipt, nil
	}
	if !strings.EqualFold(strings.TrimSpace(result.ExitStatus), "OK") {
		receipt.State, receipt.Code, receipt.Result, receipt.PVETaskUPID = "failed", "CLOUD_INIT_SNIPPET_DELETE_FAILED", nil, ""
		ApplyReceiptCompatibility(&receipt)
		return receipt, nil
	}
	if s.executor.Client == nil || task.GuestType != "qemu" || task.VMID < 1 || !storageRE.MatchString(task.SnippetStorageID) || !bodyHashRE.MatchString(task.SnippetVolumeSHA256) {
		return Receipt{}, errors.New("snippet delete recovery projection is invalid")
	}
	if err := s.journal.AdvanceSubmittedSnippetDelete(task, snippetPhaseDeleted, now); err != nil {
		return Receipt{}, err
	}
	if err := verifySnippetAbsentByDigest(ctx, s.executor.Client, task.NodeRef, task.VMID, task.SnippetStorageID, task.SnippetVolumeSHA256); err != nil {
		receipt.State, receipt.Code, receipt.Result, receipt.PVETaskUPID = "waiting", "CLOUD_INIT_SNIPPET_VERIFY_FAILED", nil, ""
		ApplyReceiptCompatibility(&receipt)
		return receipt, nil
	}
	if err := s.journal.AdvanceSubmittedSnippetDelete(task, snippetPhaseVerified, now); err != nil {
		return Receipt{}, err
	}
	receipt.State, receipt.Code = "succeeded", "SUCCEEDED"
	receipt.PVETaskUPID = ""
	receipt.Result, _ = json.Marshal(CloudInitSnippetDeleteResult{Detached: true, Deleted: true, AlreadyAbsent: false})
	ApplyReceiptCompatibility(&receipt)
	return receipt, nil
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
			receipt.Error = result.Error
		case "failed":
			receipt.State, receipt.Code = "failed", "AGENT_UPGRADE_FAILED"
			receipt.Error = result.Error
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
				reason := strings.TrimSpace(result.ExitStatus)
				if reason == "" {
					reason = "PVE task finished without a successful exit status"
				} else {
					reason = "PVE task failed: " + reason
				}
				receipt.Error = &ExecutionError{Source: "pve", Stage: "task_result", Reason: reason}
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

func (s *Service) runningReceipt(command Command, now time.Time) (Receipt, error) {
	id, err := protocol.NewID()
	if err != nil {
		return Receipt{}, err
	}
	return Receipt{
		SchemaVersion: SchemaVersion, ReceiptID: id, CommandID: command.CommandID, OperationID: command.OperationID,
		AgentRef: s.agentRef, State: "running", Code: "COMMAND_STARTED", ExecutionMode: s.mode,
		Accepted: true, Asynchronous: true, StartedAt: now, FinishedAt: now, OperatorRef: command.OperatorRef,
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
