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
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ppflight/ppflight-agent/internal/auditlog"
	"github.com/ppflight/ppflight-agent/internal/fsutil"
	"github.com/ppflight/ppflight-agent/internal/protocol"
)

var (
	ErrCommandConflict = errors.New("command ID was reused with different content")
	ErrResourceBusy    = errors.New("resource already has an active command")
)

var journalNodeRef = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// Journal is a small durable write-ahead record. It stores identifiers and
// receipt outcomes only: command Parameters (which may include credentials)
// are deliberately never persisted.
type Journal struct {
	mu        sync.Mutex
	directory string
}

type journalRecord struct {
	Version        int             `json:"version"`
	CommandID      string          `json:"commandId"`
	OperationID    string          `json:"operationId,omitempty"`
	AgentRef       string          `json:"agentRef"`
	OperatorRef    string          `json:"operatorRef,omitempty"`
	Scope          string          `json:"scope"`
	Mutating       bool            `json:"mutating"`
	Digest         string          `json:"digest"`
	ResourceKey    string          `json:"resourceKey"`
	NodeRef        string          `json:"nodeRef,omitempty"`
	PVETaskUPID    string          `json:"pveTaskUpid,omitempty"`
	State          string          `json:"state"`
	ReceiptPending bool            `json:"receiptPending,omitempty"`
	CreatedAt      time.Time       `json:"createdAt"`
	UpdatedAt      time.Time       `json:"updatedAt"`
	Receipt        *Receipt        `json:"receipt,omitempty"`
	AuditContext   *auditContext   `json:"auditContext,omitempty"`
	AuditPending   *auditlog.Event `json:"auditPending,omitempty"`
}

// auditContext is the safe, immutable command projection needed to rebuild a
// receipt audit event after a crash. It intentionally cannot represent
// Parameters, credentials, secrets, or a complete result.
type auditContext struct {
	AssignmentRevision  protocol.Counter `json:"assignmentRevision"`
	CommandID           string           `json:"commandId"`
	IdempotencyKey      string           `json:"idempotencyKey"`
	OperationID         string           `json:"operationId"`
	Action              string           `json:"action"`
	Scope               string           `json:"scope"`
	TargetRef           string           `json:"targetRef"`
	WebsiteCommandKeyID string           `json:"websiteCommandKeyId"`
	ReceivedAt          time.Time        `json:"receivedAt"`
	AcceptedAt          time.Time        `json:"acceptedAt"`
	ApprovalRef         string           `json:"approvalRef,omitempty"`
	RequestedByRef      string           `json:"requestedByRef"`
	PayloadDigest       string           `json:"payloadDigest"`
	AgentVersion        string           `json:"agentVersion"`
}

// SubmittedTask is the safe recovery view of an asynchronous command.
// It intentionally has no command parameters.
type SubmittedTask struct {
	CommandID   string
	OperationID string
	Digest      string
	ResourceKey string
	NodeRef     string
	PVETaskUPID string
	Receipt     Receipt
}

// PendingReceipt is an outbox entry whose journal state is durable but whose
// receipt queue acknowledgement has not yet been persisted.
type PendingReceipt struct {
	CommandID string
	Receipt   Receipt
}

type PendingAudit struct {
	CommandID string
	Event     auditlog.Event
}

func OpenJournal(directory string) (*Journal, error) {
	if directory == "" || filepath.Clean(directory) == string(filepath.Separator) {
		return nil, errors.New("control journal directory is invalid")
	}
	if err := fsutil.EnsurePrivateDirectory(directory); err != nil {
		return nil, err
	}
	return &Journal{directory: directory}, nil
}

// Claim durably records intent before execution. A matching record with no
// receipt means the process crashed between Claim and Complete; it is made
// explicitly indeterminate and is never submitted a second time.
func (j *Journal) Claim(command Command, now time.Time) (Receipt, bool, error) {
	return j.claim(command, now, nil)
}

// ClaimWithAudit atomically records execution intent and the safe metadata
// required to rebuild every receipt audit event after restart.
func (j *Journal) ClaimWithAudit(command Command, now time.Time, agentVersion string) (Receipt, bool, error) {
	context, err := newAuditContext(command, now, agentVersion)
	if err != nil {
		return Receipt{}, false, err
	}
	return j.claim(command, now, &context)
}

func (j *Journal) claim(command Command, now time.Time, audit *auditContext) (Receipt, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()

	resourceKey, err := journalResourceKey(command)
	if err != nil {
		return Receipt{}, false, err
	}
	digest := Digest(command)
	if digest == "" {
		return Receipt{}, false, errors.New("command canonical body is invalid")
	}
	filename := j.path(command.CommandID)
	existing, err := readJournal(filename)
	if err == nil {
		if existing.Digest != digest {
			return Receipt{}, false, ErrCommandConflict
		}
		if audit != nil && existing.AuditContext == nil {
			existing.AuditContext = audit
			if existing.Receipt != nil {
				event, eventErr := auditEventFromReceipt(*audit, *existing.Receipt)
				if eventErr != nil {
					return Receipt{}, false, eventErr
				}
				existing.AuditPending = &event
			}
			if writeErr := writeJournal(filename, existing); writeErr != nil {
				return Receipt{}, false, writeErr
			}
		}
		if existing.Receipt != nil {
			return *existing.Receipt, true, nil
		}
		if !existing.Mutating {
			// A read can be repeated safely after a crash. Keep the same durable
			// claim and let the redelivered command execute again.
			existing.UpdatedAt = now.UTC()
			if writeErr := writeJournal(filename, existing); writeErr != nil {
				return Receipt{}, false, writeErr
			}
			return Receipt{}, false, nil
		}
		receipt, makeErr := journalIndeterminate(command, now)
		if makeErr != nil {
			return Receipt{}, true, makeErr
		}
		existing.State, existing.UpdatedAt, existing.Receipt, existing.ReceiptPending = receipt.State, now.UTC(), &receipt, true
		if existing.AuditContext != nil {
			event, eventErr := auditEventFromReceipt(*existing.AuditContext, receipt)
			if eventErr != nil {
				return Receipt{}, true, eventErr
			}
			existing.AuditPending = &event
		}
		if writeErr := writeJournal(filename, existing); writeErr != nil {
			return Receipt{}, true, writeErr
		}
		return receipt, true, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return Receipt{}, false, err
	}
	mutating := requiresApproval(command.Action)
	if mutating {
		busy, err := j.resourceBusyLocked(resourceKey)
		if err != nil {
			return Receipt{}, false, err
		}
		if busy {
			return Receipt{}, false, ErrResourceBusy
		}
	}
	record := journalRecord{
		Version: SchemaVersion, CommandID: command.CommandID, OperationID: command.OperationID,
		AgentRef: command.AgentRef, OperatorRef: command.OperatorRef,
		Scope: command.Scope, Mutating: mutating, Digest: digest, ResourceKey: resourceKey, NodeRef: command.Identity.NodeRef,
		State: "received", CreatedAt: now.UTC(), UpdatedAt: now.UTC(), AuditContext: audit,
	}
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
	return j.completeLocked(filename, &record, receipt)
}

// CompleteSubmitted persists a terminal or waiting receipt produced while
// reconciling an existing UPID. Digest prevents a caller from changing an
// unrelated record with the same command ID.
func (j *Journal) CompleteSubmitted(task SubmittedTask, receipt Receipt) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	filename := j.path(task.CommandID)
	record, err := readJournal(filename)
	if err != nil {
		return err
	}
	if record.Digest != task.Digest || record.PVETaskUPID != task.PVETaskUPID {
		return ErrCommandConflict
	}
	return j.completeLocked(filename, &record, receipt)
}

func (j *Journal) completeLocked(filename string, record *journalRecord, receipt Receipt) error {
	if receipt.CommandID != record.CommandID {
		return errors.New("receipt command ID does not match journal record")
	}
	if receipt.OperationID == "" {
		receipt.OperationID = record.OperationID
	}
	ApplyReceiptCompatibility(&receipt)
	journalReceipt := receipt
	// Full results belong only to the website receipt delivery path. They are
	// neither required for recovery nor safe audit metadata.
	journalReceipt.Result = nil
	record.State, record.UpdatedAt, record.Receipt, record.ReceiptPending = receipt.State, receipt.FinishedAt.UTC(), &journalReceipt, true
	if receipt.PVETaskUPID != "" {
		record.PVETaskUPID = receipt.PVETaskUPID
	}
	if record.AuditContext != nil {
		event, err := auditEventFromReceipt(*record.AuditContext, receipt)
		if err != nil {
			return err
		}
		record.AuditPending = &event
	}
	return writeJournal(filename, *record)
}

// SubmittedWaiting returns work that can be recovered after a restart. The
// returned records contain no sensitive command body.
func (j *Journal) SubmittedWaiting() ([]SubmittedTask, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	entries, err := os.ReadDir(j.directory)
	if err != nil {
		return nil, err
	}
	result := make([]SubmittedTask, 0)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		record, err := readJournal(filepath.Join(j.directory, entry.Name()))
		if err != nil {
			return nil, err
		}
		if record.Receipt == nil || (record.State != "submitted" && record.State != "waiting") || record.PVETaskUPID == "" {
			continue
		}
		result = append(result, SubmittedTask{
			CommandID: record.CommandID, OperationID: record.OperationID, Digest: record.Digest,
			ResourceKey: record.ResourceKey, NodeRef: record.NodeRef, PVETaskUPID: record.PVETaskUPID,
			Receipt: *record.Receipt,
		})
	}
	sort.Slice(result, func(i, k int) bool { return result[i].CommandID < result[k].CommandID })
	return result, nil
}

// ListSubmittedWaiting is the explicit recovery-list name for callers that
// do not need to know how the journal is stored.
func (j *Journal) ListSubmittedWaiting() ([]SubmittedTask, error) {
	return j.SubmittedWaiting()
}

// PendingReceipts returns the durable receipt outbox. Re-enqueuing an item is
// safe because receipt queues use ReceiptID as their idempotency key.
func (j *Journal) PendingReceipts() ([]PendingReceipt, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	entries, err := os.ReadDir(j.directory)
	if err != nil {
		return nil, err
	}
	result := make([]PendingReceipt, 0)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		record, err := readJournal(filepath.Join(j.directory, entry.Name()))
		if err != nil {
			return nil, err
		}
		if record.ReceiptPending && record.Receipt != nil {
			result = append(result, PendingReceipt{CommandID: record.CommandID, Receipt: *record.Receipt})
		}
	}
	sort.Slice(result, func(i, k int) bool { return result[i].CommandID < result[k].CommandID })
	return result, nil
}

// PendingAudits returns the independent durable audit outbox. An event remains
// pending until its monitoring-only queue confirms a durable enqueue.
func (j *Journal) PendingAudits() ([]PendingAudit, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	entries, err := os.ReadDir(j.directory)
	if err != nil {
		return nil, err
	}
	result := make([]PendingAudit, 0)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		record, err := readJournal(filepath.Join(j.directory, entry.Name()))
		if err != nil {
			return nil, err
		}
		if record.AuditPending != nil {
			result = append(result, PendingAudit{CommandID: record.CommandID, Event: *record.AuditPending})
		}
	}
	sort.Slice(result, func(i, k int) bool { return result[i].CommandID < result[k].CommandID })
	return result, nil
}

// PendingAuditForReceipt returns only the exact event paired with the current
// receipt. This prevents an old receipt callback from acknowledging a newer
// task-status event.
func (j *Journal) PendingAuditForReceipt(commandID, receiptID string) (auditlog.Event, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	record, err := readJournal(j.path(commandID))
	if err != nil {
		return auditlog.Event{}, false, err
	}
	if record.Receipt == nil || record.Receipt.ReceiptID != receiptID {
		return auditlog.Event{}, false, errors.New("audit lookup does not match journal receipt")
	}
	if record.AuditPending == nil {
		return auditlog.Event{}, false, nil
	}
	if record.AuditPending.EventID != receiptID {
		return auditlog.Event{}, false, errors.New("audit event does not match journal receipt")
	}
	return *record.AuditPending, true, nil
}

func (j *Journal) MarkAuditQueued(commandID, eventID string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	filename := j.path(commandID)
	record, err := readJournal(filename)
	if err != nil {
		return err
	}
	if record.AuditPending == nil {
		return nil
	}
	if record.Receipt == nil || record.Receipt.ReceiptID != eventID || record.AuditPending.EventID != eventID {
		return errors.New("audit acknowledgement does not match journal")
	}
	record.AuditPending = nil
	return writeJournal(filename, record)
}

// MarkReceiptQueued acknowledges only the exact current receipt, preventing a
// stale queue callback from clearing a newer reconciliation update.
func (j *Journal) MarkReceiptQueued(commandID, receiptID string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	filename := j.path(commandID)
	record, err := readJournal(filename)
	if err != nil {
		return err
	}
	if record.Receipt == nil || record.Receipt.ReceiptID != receiptID {
		return errors.New("receipt acknowledgement does not match journal")
	}
	if record.AuditPending != nil {
		return errors.New("audit event must be durably queued before receipt acknowledgement")
	}
	if !record.ReceiptPending {
		return nil
	}
	record.ReceiptPending = false
	return writeJournal(filename, record)
}

// RecoverIncomplete marks claims which survived a crash before Complete as
// indeterminate. Such a record has no UPID, so retrying its mutation would be
// unsafe; a terminal receipt is the only honest recovery outcome.
func (j *Journal) RecoverIncomplete(now time.Time, mode string) ([]Receipt, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	entries, err := os.ReadDir(j.directory)
	if err != nil {
		return nil, err
	}
	receipts := make([]Receipt, 0)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		filename := filepath.Join(j.directory, entry.Name())
		record, err := readJournal(filename)
		if err != nil {
			return nil, err
		}
		if record.State != "received" || record.Receipt != nil || !record.Mutating {
			continue
		}
		id, err := protocol.NewID()
		if err != nil {
			return nil, err
		}
		receipt := Receipt{
			SchemaVersion: SchemaVersion, ReceiptID: id, CommandID: record.CommandID, OperationID: record.OperationID,
			AgentRef: record.AgentRef, State: "indeterminate", Code: "EXECUTION_INDETERMINATE",
			ExecutionMode: mode, StartedAt: record.CreatedAt.UTC(), FinishedAt: now.UTC(), OperatorRef: record.OperatorRef,
		}
		ApplyReceiptCompatibility(&receipt)
		record.State, record.UpdatedAt, record.Receipt, record.ReceiptPending = receipt.State, now.UTC(), &receipt, true
		if record.AuditContext != nil {
			event, eventErr := auditEventFromReceipt(*record.AuditContext, receipt)
			if eventErr != nil {
				return nil, eventErr
			}
			record.AuditPending = &event
		}
		if err := writeJournal(filename, record); err != nil {
			return nil, err
		}
		receipts = append(receipts, receipt)
	}
	return receipts, nil
}

func (j *Journal) resourceBusyLocked(resourceKey string) (bool, error) {
	entries, err := os.ReadDir(j.directory)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		record, err := readJournal(filepath.Join(j.directory, entry.Name()))
		if err != nil {
			return false, err
		}
		if record.Mutating && record.ResourceKey == resourceKey && (record.State == "received" || record.State == "submitted" || record.State == "waiting" || record.State == "indeterminate") {
			return true, nil
		}
	}
	return false, nil
}

func journalResourceKey(command Command) (string, error) {
	if !commandIDRE.MatchString(command.Identity.ClusterRef) || !validActionScope(command.Action, command.Scope) {
		return "", errors.New("command resource scope is invalid")
	}
	switch command.Scope {
	case ScopeCluster:
		return "cluster:" + command.Identity.ClusterRef, nil
	case ScopeNode:
		if !journalNodeRef.MatchString(command.Identity.NodeRef) {
			return "", errors.New("command node resource identity is invalid")
		}
		return fmt.Sprintf("node:%s:%s", command.Identity.ClusterRef, command.Identity.NodeRef), nil
	case ScopeVM:
		if !journalNodeRef.MatchString(command.Identity.NodeRef) || command.Identity.VMID < 1 || command.Identity.Generation == 0 || (command.Identity.GuestType != "qemu" && command.Identity.GuestType != "lxc") {
			return "", errors.New("command VM resource identity is invalid")
		}
		return fmt.Sprintf("vm:%s:%s:%d:%d", command.Identity.ClusterRef, command.Identity.GuestType, command.Identity.VMID, command.Identity.Generation), nil
	default:
		return "", errors.New("command resource scope is invalid")
	}
}

func journalIndeterminate(command Command, now time.Time) (Receipt, error) {
	id, err := protocol.NewID()
	if err != nil {
		return Receipt{}, err
	}
	receipt := Receipt{
		SchemaVersion: SchemaVersion, ReceiptID: id, CommandID: command.CommandID, OperationID: command.OperationID,
		AgentRef: command.AgentRef, State: "indeterminate", Code: "EXECUTION_INDETERMINATE",
		ExecutionMode: "production", StartedAt: now.UTC(), FinishedAt: now.UTC(), OperatorRef: command.OperatorRef,
	}
	ApplyReceiptCompatibility(&receipt)
	return receipt, nil
}

func newAuditContext(command Command, now time.Time, agentVersion string) (auditContext, error) {
	targetRef, err := auditTargetRef(command)
	if err != nil {
		return auditContext{}, err
	}
	idempotencyKey := command.IdempotencyKey
	if idempotencyKey == "" {
		idempotencyKey = command.CommandID
	}
	result := auditContext{
		AssignmentRevision: command.AssignmentRevision, CommandID: command.CommandID,
		IdempotencyKey: idempotencyKey, OperationID: command.OperationID, Action: command.Action,
		Scope: command.Scope, TargetRef: targetRef, WebsiteCommandKeyID: command.SigningKeyID,
		ReceivedAt: now.UTC(), AcceptedAt: now.UTC(), ApprovalRef: command.ApprovalRef,
		RequestedByRef: command.OperatorRef, PayloadDigest: "sha256:" + command.BodySHA256,
		AgentVersion: agentVersion,
	}
	if err := result.validate(); err != nil {
		return auditContext{}, err
	}
	return result, nil
}

func (c auditContext) validate() error {
	if c.AssignmentRevision == 0 || !commandIDRE.MatchString(c.CommandID) || !commandIDRE.MatchString(c.IdempotencyKey) || !commandIDRE.MatchString(c.OperationID) || !actionRE.MatchString(c.Action) || (c.Scope != ScopeCluster && c.Scope != ScopeNode && c.Scope != ScopeVM) || !validAuditText(c.TargetRef, 256) || !commandIDRE.MatchString(c.WebsiteCommandKeyID) {
		return errors.New("journal audit context identity is invalid")
	}
	if c.ReceivedAt.IsZero() || c.AcceptedAt.IsZero() || c.AcceptedAt.Before(c.ReceivedAt) {
		return errors.New("journal audit context timing is invalid")
	}
	if c.ApprovalRef != "" && !commandIDRE.MatchString(c.ApprovalRef) || !commandIDRE.MatchString(c.RequestedByRef) || strings.Contains(c.RequestedByRef, "@") {
		return errors.New("journal audit context actor reference is invalid")
	}
	if !strings.HasPrefix(c.PayloadDigest, "sha256:") || !bodyHashRE.MatchString(strings.TrimPrefix(c.PayloadDigest, "sha256:")) || !validAuditText(c.AgentVersion, 128) {
		return errors.New("journal audit context digest or version is invalid")
	}
	return nil
}

func auditEventFromReceipt(context auditContext, receipt Receipt) (auditlog.Event, error) {
	if err := context.validate(); err != nil {
		return auditlog.Event{}, err
	}
	resultDigest, err := AuditReceiptDigest(receipt)
	if err != nil {
		return auditlog.Event{}, err
	}
	acceptedAt := context.AcceptedAt.UTC()
	var startedAt, finishedAt *time.Time
	if !receipt.StartedAt.IsZero() {
		value := receipt.StartedAt.UTC()
		startedAt = &value
	}
	if !receipt.FinishedAt.IsZero() {
		value := receipt.FinishedAt.UTC()
		finishedAt = &value
	}
	policy := "allowed"
	if receipt.State == "rejected" {
		policy = "denied"
	}
	upidDigest := ""
	if receipt.PVETaskUPID != "" {
		sum := sha256.Sum256([]byte(receipt.PVETaskUPID))
		upidDigest = "sha256:" + hex.EncodeToString(sum[:])
	}
	event := auditlog.Event{
		EventID: receipt.ReceiptID, AssignmentRevision: context.AssignmentRevision,
		CommandID: context.CommandID, IdempotencyKey: context.IdempotencyKey,
		Action: context.Action, Scope: context.Scope, TargetRef: context.TargetRef,
		WebsiteCommandKeyID: context.WebsiteCommandKeyID, ReceivedAt: context.ReceivedAt.UTC(),
		AcceptedAt: &acceptedAt, StartedAt: startedAt, FinishedAt: finishedAt,
		Outcome: receipt.State, ErrorCode: receipt.Code, UPID: upidDigest,
		ApprovalRef: context.ApprovalRef, RequestedByRef: context.RequestedByRef,
		PayloadDigest: context.PayloadDigest, ResultDigest: resultDigest,
		PolicyDecision: policy, AgentVersion: context.AgentVersion,
	}
	if err := event.Validate(); err != nil {
		return auditlog.Event{}, err
	}
	return event, nil
}

func auditTargetRef(command Command) (string, error) {
	if !journalNodeRef.MatchString(command.Identity.ClusterRef) {
		return "", errors.New("audit target cluster reference is invalid")
	}
	var result string
	switch command.Scope {
	case ScopeCluster:
		result = "cluster:" + command.Identity.ClusterRef
	case ScopeNode:
		if !journalNodeRef.MatchString(command.Identity.NodeRef) {
			return "", errors.New("audit target node reference is invalid")
		}
		result = fmt.Sprintf("node:%s:%s", command.Identity.ClusterRef, command.Identity.NodeRef)
	case ScopeVM:
		if !journalNodeRef.MatchString(command.Identity.InstanceUUID) || (command.Identity.GuestType != "qemu" && command.Identity.GuestType != "lxc") || command.Identity.Generation == 0 {
			return "", errors.New("audit target VM reference is invalid")
		}
		result = fmt.Sprintf("vm:%s:%s:%s:%d", command.Identity.ClusterRef, command.Identity.GuestType, command.Identity.InstanceUUID, command.Identity.Generation)
	default:
		return "", errors.New("audit target scope is invalid")
	}
	if !validAuditText(result, 256) {
		return "", errors.New("audit target reference is invalid")
	}
	return result, nil
}

func validAuditText(value string, limit int) bool {
	if value == "" || len(value) > limit || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
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
	if err := json.Unmarshal(raw, &record); err != nil || record.Version != SchemaVersion || !commandIDRE.MatchString(record.CommandID) || record.Digest == "" || record.ResourceKey == "" || !validJournalScope(record.Scope, record.NodeRef) || (record.PVETaskUPID != "" && !upidRE.MatchString(record.PVETaskUPID)) || (record.AuditContext != nil && record.AuditContext.validate() != nil) || (record.AuditPending != nil && record.AuditPending.Validate() != nil) {
		return journalRecord{}, fmt.Errorf("control journal record is corrupt")
	}
	return record, nil
}

func validJournalScope(scope, nodeRef string) bool {
	switch scope {
	case ScopeCluster:
		return nodeRef == ""
	case ScopeNode, ScopeVM:
		return journalNodeRef.MatchString(nodeRef)
	default:
		return false
	}
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
	return fsutil.SyncDir(directory)
}
