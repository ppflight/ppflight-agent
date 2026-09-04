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
	ErrCommandConflict               = errors.New("command ID was reused with different content")
	ErrOperationConflict             = errors.New("operation ID was reused by another command")
	ErrIdempotencyConflict           = errors.New("idempotency key was reused by another command")
	ErrResourceBusy                  = errors.New("resource already has an active command")
	ErrUnlistedActiveMutation        = errors.New("legacy migration found an unlisted active mutation")
	ErrListedRecordNotEligible       = errors.New("listed legacy journal record is not eligible")
	ErrCloneJournalNotFound          = errors.New("legacy clone journal was not found")
	ErrCloneDigestMismatch           = errors.New("legacy clone digest does not match")
	ErrCloneResourceIdentityMismatch = errors.New("legacy clone resource identity does not match")
	ErrCloneTerminalReceiptInvalid   = errors.New("legacy clone terminal receipt is invalid")
	ErrCloneLegacyAuthorityMismatch  = errors.New("legacy clone authority does not match")
	ErrCloneAlreadyMigrated          = errors.New("legacy clone was already migrated")
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
	Version            int              `json:"version"`
	CommandID          string           `json:"commandId"`
	OperationID        string           `json:"operationId,omitempty"`
	IdempotencyKey     string           `json:"idempotencyKey,omitempty"`
	AgentRef           string           `json:"agentRef"`
	BindingID          string           `json:"bindingId,omitempty"`
	DeviceID           string           `json:"deviceId,omitempty"`
	CredentialEpoch    protocol.Counter `json:"credentialEpoch,omitempty"`
	AssignmentRevision protocol.Counter `json:"assignmentRevision,omitempty"`
	OperatorRef        string           `json:"operatorRef,omitempty"`
	Scope              string           `json:"scope"`
	Action             string           `json:"action,omitempty"`
	ClusterRef         string           `json:"clusterRef,omitempty"`
	ServiceRef         string           `json:"serviceRef,omitempty"`
	InstanceUUID       string           `json:"instanceUuid,omitempty"`
	GuestType          string           `json:"guestType,omitempty"`
	VMID               int              `json:"vmid,omitempty"`
	Generation         protocol.Counter `json:"generation,omitempty"`
	// SourceConfigSHA256 is safe clone-lineage metadata. It is the reviewed
	// template configuration digest, never a command body or credential.
	SourceConfigSHA256  string          `json:"sourceConfigSha256,omitempty"`
	SourceTemplateRef   string          `json:"sourceTemplateRef,omitempty"`
	SourceVMID          int             `json:"sourceVmid,omitempty"`
	MigratedByCommandID string          `json:"migratedByCommandId,omitempty"`
	MigratedAt          *time.Time      `json:"migratedAt,omitempty"`
	RetiredByCommandID  string          `json:"retiredByCommandId,omitempty"`
	RetiredAt           *time.Time      `json:"retiredAt,omitempty"`
	Mutating            bool            `json:"mutating"`
	Digest              string          `json:"digest"`
	ResourceKey         string          `json:"resourceKey"`
	NodeRef             string          `json:"nodeRef,omitempty"`
	PVETaskUPID         string          `json:"pveTaskUpid,omitempty"`
	AgentUpgradeID      string          `json:"agentUpgradeId,omitempty"`
	SnippetDeletePhase  string          `json:"snippetDeletePhase,omitempty"`
	SnippetStorageID    string          `json:"snippetStorageId,omitempty"`
	SnippetVolumeSHA256 string          `json:"snippetVolumeSha256,omitempty"`
	State               string          `json:"state"`
	ReceiptPending      bool            `json:"receiptPending,omitempty"`
	CreatedAt           time.Time       `json:"createdAt"`
	UpdatedAt           time.Time       `json:"updatedAt"`
	Receipt             *Receipt        `json:"receipt,omitempty"`
	AuditContext        *auditContext   `json:"auditContext,omitempty"`
	AuditPending        *auditlog.Event `json:"auditPending,omitempty"`
}

// auditContext is the safe, immutable command projection needed to rebuild a
// receipt audit event after a crash. It intentionally cannot represent
// Parameters, credentials, secrets, or a complete result.
type auditContext struct {
	AssignmentRevision  protocol.Counter      `json:"assignmentRevision"`
	CommandID           string                `json:"commandId"`
	IdempotencyKey      string                `json:"idempotencyKey"`
	OperationID         string                `json:"operationId"`
	Action              string                `json:"action"`
	Scope               string                `json:"scope"`
	TargetRef           string                `json:"targetRef"`
	Target              *auditlog.EventTarget `json:"target,omitempty"`
	WebsiteCommandKeyID string                `json:"websiteCommandKeyId"`
	ReceivedAt          time.Time             `json:"receivedAt"`
	AcceptedAt          time.Time             `json:"acceptedAt"`
	ApprovalRef         string                `json:"approvalRef,omitempty"`
	RequestedByRef      string                `json:"requestedByRef"`
	PayloadDigest       string                `json:"payloadDigest"`
	AgentVersion        string                `json:"agentVersion"`
}

// SubmittedTask is the safe recovery view of an asynchronous command.
// It intentionally has no command parameters.
type SubmittedTask struct {
	CommandID           string
	OperationID         string
	Digest              string
	ResourceKey         string
	NodeRef             string
	PVETaskUPID         string
	AgentUpgradeID      string
	Receipt             Receipt
	Action              string
	GuestType           string
	VMID                int
	SnippetDeletePhase  string
	SnippetStorageID    string
	SnippetVolumeSHA256 string
	BindingID           string
	DeviceID            string
	CredentialEpoch     protocol.Counter
	AssignmentRevision  protocol.Counter
	AgentRef            string
	ClusterRef          string
	ServiceRef          string
	InstanceUUID        string
	Generation          protocol.Counter
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
		if existing.Action == "vm.migrate-legacy-journal" || existing.Action == "vm.cloud-init-snippet.delete" {
			// These actions have their own durable, monotonic recovery markers. The
			// exact signed command may safely finish a partial operation; a different
			// command remains blocked by digest and resource identity.
			existing.UpdatedAt = now.UTC()
			if writeErr := writeJournal(filename, existing); writeErr != nil {
				return Receipt{}, false, writeErr
			}
			return Receipt{}, false, nil
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
	operationUsed, idempotencyUsed, err := j.identityUsedLocked(command.OperationID, command.IdempotencyKey, command.CommandID)
	if err != nil {
		return Receipt{}, false, err
	}
	if operationUsed {
		return Receipt{}, false, ErrOperationConflict
	}
	if idempotencyUsed {
		return Receipt{}, false, ErrIdempotencyConflict
	}
	mutating := requiresApproval(command.Action)
	if mutating {
		busy, err := j.resourceBusyLocked(resourceKey)
		if command.Action == "vm.migrate-legacy-journal" {
			if parameters, ok := decodeDelete501Recovery(command); ok {
				err = j.validateDelete501RecoveryClaimLocked(command, parameters)
			} else {
				var parameters legacyJournalMigrationP
				if decodeErr := strictParameters(command.Parameters, &parameters); decodeErr != nil {
					return Receipt{}, false, decodeErr
				}
				err = j.validateLegacyMigrationClaimLocked(command, parameters)
			}
			busy = false
		}
		if err != nil {
			return Receipt{}, false, err
		}
		if busy {
			return Receipt{}, false, ErrResourceBusy
		}
	}
	record := journalRecord{
		Version: SchemaVersion, CommandID: command.CommandID, OperationID: command.OperationID,
		IdempotencyKey: command.IdempotencyKey, AgentRef: command.AgentRef,
		BindingID: command.BindingID, DeviceID: command.DeviceID, CredentialEpoch: command.CredentialEpoch,
		AssignmentRevision: command.AssignmentRevision, OperatorRef: command.OperatorRef,
		Scope: command.Scope, Action: command.Action, Mutating: mutating, Digest: digest, ResourceKey: resourceKey, NodeRef: command.Identity.NodeRef,
		ClusterRef: command.Identity.ClusterRef, ServiceRef: command.Identity.ServiceRef,
		InstanceUUID: command.Identity.InstanceUUID, GuestType: command.Identity.GuestType,
		VMID: command.Identity.VMID, Generation: protocol.Counter(command.Identity.Generation),
		State: "received", CreatedAt: now.UTC(), UpdatedAt: now.UTC(), AuditContext: audit,
	}
	switch command.Action {
	case "vm.clone":
		var parameters cloneP
		if err := strictParameters(command.Parameters, &parameters); err != nil || !bodyHashRE.MatchString(parameters.SourceConfigSHA256) {
			return Receipt{}, false, errors.New("clone lineage is invalid")
		}
		record.SourceConfigSHA256 = parameters.SourceConfigSHA256
		record.SourceTemplateRef = parameters.TemplateRef
		record.SourceVMID = parameters.SourceVMID
	case "vm.set-initial-resources":
		var parameters initialResourcesP
		if err := strictParameters(command.Parameters, &parameters); err != nil || !validInitialResources(command, parameters) {
			return Receipt{}, false, errors.New("initial resource lineage is invalid")
		}
		record.SourceConfigSHA256 = parameters.TemplateConfigSHA256
		record.SourceTemplateRef = parameters.TemplateRef
		record.SourceVMID = parameters.SourceVMID
	}
	if err := writeJournal(filename, record); err != nil {
		return Receipt{}, false, err
	}
	return Receipt{}, false, nil
}

func (j *Journal) identityUsedLocked(operationID, idempotencyKey, commandID string) (bool, bool, error) {
	if !commandIDRE.MatchString(operationID) || !commandIDRE.MatchString(idempotencyKey) || !commandIDRE.MatchString(commandID) {
		return false, false, errors.New("journal operation identity is invalid")
	}
	entries, err := os.ReadDir(j.directory)
	if err != nil {
		return false, false, err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		record, readErr := readJournal(filepath.Join(j.directory, entry.Name()))
		if readErr != nil {
			return false, false, readErr
		}
		if record.OperationID == operationID && record.CommandID != commandID {
			return true, false, nil
		}
		if record.IdempotencyKey != "" && record.IdempotencyKey == idempotencyKey && record.CommandID != commandID {
			return false, true, nil
		}
	}
	return false, false, nil
}

// AuthorizeInitialResources proves that the target generation was created by
// a distinct, completed, journaled vm.clone operation under exactly the same
// signed authority and VM identity. It also refuses the one-time exception
// after any start, delivery verification, reinstall, or generation advance.
func (j *Journal) AuthorizeInitialResources(command Command, cloneOperationID, templateRef string, sourceVMID int, templateConfigSHA256 string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if command.Action != "vm.set-initial-resources" || cloneOperationID == command.OperationID || !commandIDRE.MatchString(cloneOperationID) || !nameRE.MatchString(templateRef) || sourceVMID < 100 || sourceVMID > 999999999 || !bodyHashRE.MatchString(templateConfigSHA256) || !validInitialLineageCommand(command) {
		return errors.New("initial resource lineage identity is invalid")
	}
	resourceKey, err := journalResourceKey(command)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(j.directory)
	if err != nil {
		return err
	}
	records := make([]journalRecord, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		record, readErr := readJournal(filepath.Join(j.directory, entry.Name()))
		if readErr != nil {
			return readErr
		}
		records = append(records, record)
	}
	var clone *journalRecord
	for index := range records {
		record := &records[index]
		if record.Action != "vm.clone" || record.OperationID != cloneOperationID {
			continue
		}
		if clone != nil || !recordMatchesInitialLineage(*record, command, templateRef, sourceVMID, templateConfigSHA256) || !recordSucceeded(*record) {
			return errors.New("completed clone lineage is ambiguous or does not match command authority")
		}
		clone = record
	}
	if clone == nil {
		return errors.New("completed clone lineage was not found")
	}
	for _, record := range records {
		mutationMayHaveHappened, mutationErr := j.recordMutationMayHaveHappenedLocked(record)
		if mutationErr != nil {
			return mutationErr
		}
		if record.ResourceKey == resourceKey {
			if record.Action == "vm.set-initial-resources" && record.CommandID != command.CommandID && mutationMayHaveHappened {
				return errors.New("VM generation already consumed its initial resource authorization")
			}
			if (record.Action == "vm.start" || record.Action == "vm.verify-delivery" || record.Action == "vm.reinstall") && mutationMayHaveHappened {
				return errors.New("VM generation has already been finalized, delivered, or started")
			}
		}
		if sameLineageVM(record, command) && uint64(record.Generation) != command.Identity.Generation && !record.CreatedAt.Before(clone.CreatedAt) && mutationMayHaveHappened {
			return errors.New("VM identity has advanced to another generation")
		}
	}
	return nil
}

func validInitialLineageCommand(command Command) bool {
	return uuidRE.MatchString(command.BindingID) && commandIDRE.MatchString(command.DeviceID) && commandIDRE.MatchString(command.AgentRef) &&
		command.CredentialEpoch > 0 && command.AssignmentRevision > 0 && commandIDRE.MatchString(command.Identity.ClusterRef) &&
		journalNodeRef.MatchString(command.Identity.NodeRef) && commandIDRE.MatchString(command.Identity.ServiceRef) &&
		commandIDRE.MatchString(command.Identity.InstanceUUID) && (command.Identity.GuestType == "qemu" || command.Identity.GuestType == "lxc") &&
		command.Identity.VMID > 0 && command.Identity.Generation > 0
}

func recordMatchesInitialLineage(record journalRecord, command Command, templateRef string, sourceVMID int, templateConfigSHA256 string) bool {
	return record.BindingID == command.BindingID && record.DeviceID == command.DeviceID && record.AgentRef == command.AgentRef &&
		record.ClusterRef == command.Identity.ClusterRef && record.NodeRef == command.Identity.NodeRef &&
		record.ServiceRef == command.Identity.ServiceRef && record.InstanceUUID == command.Identity.InstanceUUID &&
		record.GuestType == command.Identity.GuestType && record.VMID == command.Identity.VMID &&
		uint64(record.Generation) == command.Identity.Generation && record.CredentialEpoch == command.CredentialEpoch &&
		record.AssignmentRevision == command.AssignmentRevision && record.SourceTemplateRef == templateRef &&
		record.SourceVMID == sourceVMID && record.SourceConfigSHA256 == templateConfigSHA256
}

func sameLineageVM(record journalRecord, command Command) bool {
	return record.BindingID == command.BindingID && record.DeviceID == command.DeviceID && record.AgentRef == command.AgentRef &&
		record.ClusterRef == command.Identity.ClusterRef && record.NodeRef == command.Identity.NodeRef &&
		record.ServiceRef == command.Identity.ServiceRef && record.InstanceUUID == command.Identity.InstanceUUID &&
		record.GuestType == command.Identity.GuestType && record.VMID == command.Identity.VMID
}

func recordSucceeded(record journalRecord) bool {
	return record.State == "succeeded" && record.Receipt != nil && record.Receipt.State == "succeeded" &&
		record.Receipt.Code == "SUCCEEDED" && record.Receipt.CommandID == record.CommandID && record.Receipt.OperationID == record.OperationID
}

func recordMutationMayHaveHappened(record journalRecord) bool {
	if recordHasCompleteRetirementMarkers(record) {
		return false
	}
	if record.Receipt == nil {
		return record.State == "received" || record.State == "submitted" || record.State == "waiting" || record.State == "indeterminate"
	}
	switch record.Receipt.State {
	case "submitted", "waiting", "succeeded", "indeterminate":
		return true
	default:
		return false
	}
}

func recordHasCompleteRetirementMarkers(record journalRecord) bool {
	return record.RetiredByCommandID != "" && commandIDRE.MatchString(record.RetiredByCommandID) &&
		record.RetiredAt != nil && !record.RetiredAt.IsZero() && record.RetiredAt.Location() == time.UTC &&
		validJournalMigrationMarkers(record)
}

// recordMutationMayHaveHappenedLocked additionally proves that complete-looking
// retirement markers were committed by a successful, same-authority migration
// whose durable result explicitly lists this record. This prevents a crash
// between marker writes and migration completion from releasing the VM lock.
func (j *Journal) recordMutationMayHaveHappenedLocked(record journalRecord) (bool, error) {
	if recordHasCompleteRetirementMarkers(record) {
		retired, err := j.retirementCommittedLocked(record)
		if err != nil {
			return true, err
		}
		return !retired, nil
	}
	return recordMutationMayHaveHappened(record), nil
}

func (j *Journal) retirementCommittedLocked(record journalRecord) (bool, error) {
	if !recordHasCompleteRetirementMarkers(record) {
		return false, nil
	}
	migration, err := readJournal(j.path(record.RetiredByCommandID))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if migration.CommandID != record.RetiredByCommandID || migration.Action != "vm.migrate-legacy-journal" ||
		migration.ResourceKey != record.ResourceKey || !recordSucceeded(migration) || migration.AuditContext == nil ||
		migration.AuditContext.Action != migration.Action || migration.AuditContext.ApprovalRef == "" ||
		migration.BindingID != record.BindingID || migration.DeviceID != record.DeviceID ||
		migration.CredentialEpoch != record.CredentialEpoch || migration.AssignmentRevision != record.AssignmentRevision ||
		migration.AgentRef != record.AgentRef || migration.ClusterRef != record.ClusterRef || migration.NodeRef != record.NodeRef ||
		migration.ServiceRef != record.ServiceRef || migration.InstanceUUID != record.InstanceUUID || migration.GuestType != record.GuestType ||
		migration.VMID != record.VMID || migration.Generation != record.Generation || migration.Receipt == nil ||
		migration.CreatedAt.IsZero() || migration.UpdatedAt.IsZero() || record.RetiredAt.Before(migration.CreatedAt) ||
		record.RetiredAt.After(migration.UpdatedAt) {
		return false, nil
	}
	if knownDelete501RetirementShape(record) {
		var result Delete501RecoveryResult
		if !validDelete501RecoveryJournalResult(&migration, migration.Receipt.Result) ||
			strictParameters(migration.Receipt.Result, &result) != nil ||
			migration.AuditContext.WebsiteCommandKeyID != record.AuditContext.WebsiteCommandKeyID ||
			migration.AuditContext.TargetRef != record.AuditContext.TargetRef {
			return false, nil
		}
		return result.FailedCommandID == record.CommandID && result.FailedOperationID == record.OperationID &&
			result.FailedCommandDigest == record.Digest, nil
	}
	var result LegacyJournalMigrationResult
	if !validLegacyMigrationJournalResult(&migration, migration.Receipt.Result) ||
		strictParameters(migration.Receipt.Result, &result) != nil {
		return false, nil
	}
	for _, commandID := range result.RetiredIndeterminateCommandIDs {
		if commandID == record.CommandID {
			return true, nil
		}
	}
	return false, nil
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

// BeginCloudInitSnippetDelete binds a safe one-way projection of the exact
// volume to the existing signed claim. Raw volume IDs and config strings are
// deliberately not representable in the journal record.
func (j *Journal) BeginCloudInitSnippetDelete(command Command, storage, volumeSHA256 string, now time.Time) (CloudInitSnippetDeleteProgress, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	filename := j.path(command.CommandID)
	record, err := readJournal(filename)
	if err != nil {
		return CloudInitSnippetDeleteProgress{}, err
	}
	if record.Action != "vm.cloud-init-snippet.delete" || record.Digest != Digest(command) || !storageRE.MatchString(storage) || !bodyHashRE.MatchString(volumeSHA256) ||
		record.BindingID != command.BindingID || record.DeviceID != command.DeviceID || record.CredentialEpoch != command.CredentialEpoch ||
		record.AssignmentRevision != command.AssignmentRevision || record.AgentRef != command.AgentRef || record.ClusterRef != command.Identity.ClusterRef ||
		record.NodeRef != command.Identity.NodeRef || record.ServiceRef != command.Identity.ServiceRef || record.InstanceUUID != command.Identity.InstanceUUID ||
		record.GuestType != "qemu" || record.VMID != command.Identity.VMID || uint64(record.Generation) != command.Identity.Generation {
		return CloudInitSnippetDeleteProgress{}, ErrCommandConflict
	}
	resumed := record.SnippetDeletePhase != ""
	if record.SnippetDeletePhase == "" {
		record.SnippetDeletePhase = snippetPhaseValidated
		record.SnippetStorageID = storage
		record.SnippetVolumeSHA256 = volumeSHA256
	} else if record.SnippetStorageID != storage || record.SnippetVolumeSHA256 != volumeSHA256 {
		return CloudInitSnippetDeleteProgress{}, ErrCommandConflict
	}
	record.UpdatedAt = now.UTC()
	if err := writeJournal(filename, record); err != nil {
		return CloudInitSnippetDeleteProgress{}, err
	}
	return CloudInitSnippetDeleteProgress{Phase: record.SnippetDeletePhase, Resumed: resumed}, nil
}

func (j *Journal) AdvanceCloudInitSnippetDelete(command Command, phase string, now time.Time) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	filename := j.path(command.CommandID)
	record, err := readJournal(filename)
	if err != nil {
		return err
	}
	if record.Action != "vm.cloud-init-snippet.delete" || record.Digest != Digest(command) || !validDirectSnippetPhase(phase) ||
		snippetPhaseOrder[phase] < snippetPhaseOrder[record.SnippetDeletePhase] || record.SnippetStorageID == "" || record.SnippetVolumeSHA256 == "" {
		return ErrCommandConflict
	}
	record.SnippetDeletePhase, record.UpdatedAt = phase, now.UTC()
	return writeJournal(filename, record)
}

func (j *Journal) RecordCloudInitSnippetDeleteSubmitted(command Command, receipt Receipt, upid string, now time.Time) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	filename := j.path(command.CommandID)
	record, err := readJournal(filename)
	if err != nil {
		return err
	}
	if record.Action != "vm.cloud-init-snippet.delete" || record.Digest != Digest(command) || !upidRE.MatchString(upid) ||
		record.SnippetDeletePhase != snippetPhaseDetached || receipt.CommandID != command.CommandID || receipt.PVETaskUPID != "" {
		return ErrCommandConflict
	}
	record.PVETaskUPID = upid
	record.SnippetDeletePhase, record.UpdatedAt = snippetPhaseDeleteSubmitted, now.UTC()
	return j.completeLocked(filename, &record, receipt)
}

func validSnippetJournalPhase(phase string) bool {
	_, ok := snippetPhaseOrder[phase]
	return ok && phase != ""
}

func validDirectSnippetPhase(phase string) bool {
	switch phase {
	case snippetPhaseReferenceProven, snippetPhaseDetached, snippetPhaseDeleted, snippetPhaseVerified:
		return true
	default:
		return false
	}
}

func (j *Journal) AdvanceSubmittedSnippetDelete(task SubmittedTask, phase string, now time.Time) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	filename := j.path(task.CommandID)
	record, err := readJournal(filename)
	if err != nil {
		return err
	}
	if task.Action != "vm.cloud-init-snippet.delete" || record.Action != task.Action || record.Digest != task.Digest || record.PVETaskUPID != task.PVETaskUPID ||
		(phase != snippetPhaseDeleted && phase != snippetPhaseVerified) || snippetPhaseOrder[phase] < snippetPhaseOrder[record.SnippetDeletePhase] {
		return ErrCommandConflict
	}
	record.SnippetDeletePhase, record.UpdatedAt = phase, now.UTC()
	return writeJournal(filename, record)
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
	if record.Digest != task.Digest || record.PVETaskUPID != task.PVETaskUPID || record.AgentUpgradeID != task.AgentUpgradeID {
		return ErrCommandConflict
	}
	return j.completeLocked(filename, &record, receipt)
}

// AuthorizeUpgrade is the root helper's final durable handoff gate. It proves
// the unprivileged service recorded the same signed command as submitted
// before the helper mutates the installed binary.
func (j *Journal) AuthorizeUpgrade(commandID, digest, upgradeID string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	record, err := readJournal(j.path(commandID))
	if err != nil {
		return err
	}
	if record.Digest != digest || record.AgentUpgradeID != upgradeID || record.Receipt == nil || record.Receipt.AgentUpgradeID != upgradeID || record.State != "submitted" {
		return ErrCommandConflict
	}
	return nil
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
	// Full results belong only to the website receipt delivery path. The sole
	// exception is the strictly typed, secret-free initial-resource result,
	// which must survive a crash so an exact idempotent replay can return the
	// first result without touching PVE again.
	safeReplayResult := record.Action == "vm.set-initial-resources" && validInitialResourcesJournalResult(record, receipt.Result) ||
		record.Action == "vm.migrate-legacy-journal" && (validLegacyMigrationJournalResult(record, receipt.Result) || validDelete501RecoveryJournalResult(record, receipt.Result)) ||
		record.Action == "vm.cloud-init-snippet.delete" && validSnippetDeleteJournalResult(record, receipt.Result)
	if receipt.State != "succeeded" || receipt.Code != "SUCCEEDED" || !safeReplayResult {
		journalReceipt.Result = nil
	}
	record.State, record.UpdatedAt, record.Receipt, record.ReceiptPending = receipt.State, receipt.FinishedAt.UTC(), &journalReceipt, true
	if record.Action == "vm.cloud-init-snippet.delete" && receipt.State == "succeeded" && receipt.Code == "SUCCEEDED" && safeReplayResult {
		record.SnippetDeletePhase = snippetPhaseSucceeded
	}
	if receipt.PVETaskUPID != "" {
		record.PVETaskUPID = receipt.PVETaskUPID
	}
	if receipt.AgentUpgradeID != "" {
		record.AgentUpgradeID = receipt.AgentUpgradeID
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

func validSnippetDeleteJournalResult(record *journalRecord, raw json.RawMessage) bool {
	var result CloudInitSnippetDeleteResult
	return record != nil && record.SnippetDeletePhase == snippetPhaseVerified && strictParameters(raw, &result) == nil && result.Detached && result.Deleted
}

func validLegacyMigrationJournalResult(record *journalRecord, raw json.RawMessage) bool {
	if record == nil || len(raw) == 0 {
		return false
	}
	var result LegacyJournalMigrationResult
	if strictParameters(raw, &result) != nil || !result.Migrated || !commandIDRE.MatchString(result.LegacyCloneCommandID) ||
		!commandIDRE.MatchString(result.LegacyCloneOperationID) || !nameRE.MatchString(result.TemplateRef) ||
		result.LegacyAssignmentRevision == 0 || result.LegacyAssignmentRevision >= record.AssignmentRevision ||
		result.SourceVMID < 100 || result.SourceVMID > 999999999 ||
		!bodyHashRE.MatchString(result.SourceConfigSHA256) ||
		result.RetiredIndeterminateCommandIDs == nil || len(result.RetiredIndeterminateCommandIDs) > maxLegacyJournalRetirements {
		return false
	}
	previous := ""
	for _, commandID := range result.RetiredIndeterminateCommandIDs {
		if !commandIDRE.MatchString(commandID) || previous != "" && commandID <= previous {
			return false
		}
		previous = commandID
	}
	return true
}

func validInitialResourcesJournalResult(record *journalRecord, raw json.RawMessage) bool {
	if record == nil || len(raw) == 0 {
		return false
	}
	var result initialResourcesResult
	if strictParameters(raw, &result) != nil {
		return false
	}
	return result.Configured && result.Verified && result.Cores >= 1 && result.Cores <= 128 && result.Sockets >= 1 && result.Sockets <= 16 &&
		result.MemoryMiB >= 128 && result.MemoryMiB <= 4194304 && result.VMGeneration == record.Generation &&
		result.TemplateRef == record.SourceTemplateRef && result.SourceVMID == record.SourceVMID &&
		result.TemplateConfigSHA256 == record.SourceConfigSHA256
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
		if record.Receipt == nil || (record.State != "submitted" && record.State != "waiting") || (record.PVETaskUPID == "") == (record.AgentUpgradeID == "") {
			continue
		}
		result = append(result, SubmittedTask{
			CommandID: record.CommandID, OperationID: record.OperationID, Digest: record.Digest,
			ResourceKey: record.ResourceKey, NodeRef: record.NodeRef, PVETaskUPID: record.PVETaskUPID, AgentUpgradeID: record.AgentUpgradeID,
			Receipt: *record.Receipt, Action: record.Action, GuestType: record.GuestType, VMID: record.VMID,
			SnippetDeletePhase: record.SnippetDeletePhase, SnippetStorageID: record.SnippetStorageID, SnippetVolumeSHA256: record.SnippetVolumeSHA256,
			BindingID: record.BindingID, DeviceID: record.DeviceID, CredentialEpoch: record.CredentialEpoch, AssignmentRevision: record.AssignmentRevision,
			AgentRef: record.AgentRef, ClusterRef: record.ClusterRef, ServiceRef: record.ServiceRef, InstanceUUID: record.InstanceUUID, Generation: record.Generation,
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
		if record.State != "received" || record.Receipt != nil || !record.Mutating || record.Action == "vm.cloud-init-snippet.delete" {
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
			retired, retireErr := j.retirementCommittedLocked(record)
			if retireErr != nil {
				return false, retireErr
			}
			if !retired {
				return true, nil
			}
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
	if command.Scope == ScopeVM {
		result.Target = &auditlog.EventTarget{
			ClusterRef: command.Identity.ClusterRef,
			NodeRef:    command.Identity.NodeRef,
			GuestType:  command.Identity.GuestType,
			VMID:       command.Identity.VMID,
		}
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
	if c.Target != nil {
		probe := auditlog.Event{
			EventID: "11111111-1111-4111-8111-111111111111", AssignmentRevision: c.AssignmentRevision,
			CommandID: c.CommandID, OperationID: c.OperationID, IdempotencyKey: c.IdempotencyKey,
			Action: c.Action, Scope: c.Scope, TargetRef: c.TargetRef, Target: c.Target,
			WebsiteCommandKeyID: c.WebsiteCommandKeyID, ReceivedAt: c.ReceivedAt,
			Outcome: "succeeded", PayloadDigest: c.PayloadDigest, PolicyDecision: "allowed",
			AgentVersion: c.AgentVersion,
		}
		if err := probe.Validate(); err != nil {
			return errors.New("journal audit context target is invalid")
		}
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
	outcome := receipt.State
	if context.Action == "agent.upgrade" {
		switch {
		case receipt.State == "waiting":
			// The monitoring upgrade contract has no separate waiting enum;
			// repeated observations remain part of the submitted phase.
			outcome = "submitted"
		case receipt.State == "failed" && receipt.Code == "AGENT_UPGRADE_ROLLED_BACK":
			outcome = "rolled_back"
		}
	}
	upidDigest := ""
	if receipt.PVETaskUPID != "" {
		sum := sha256.Sum256([]byte(receipt.PVETaskUPID))
		upidDigest = "sha256:" + hex.EncodeToString(sum[:])
	}
	event := auditlog.Event{
		EventID: receipt.ReceiptID, AssignmentRevision: context.AssignmentRevision,
		CommandID: context.CommandID, OperationID: context.OperationID, IdempotencyKey: context.IdempotencyKey,
		Action: context.Action, Scope: context.Scope, TargetRef: context.TargetRef, Target: context.Target,
		WebsiteCommandKeyID: context.WebsiteCommandKeyID, ReceivedAt: context.ReceivedAt.UTC(),
		AcceptedAt: &acceptedAt, StartedAt: startedAt, FinishedAt: finishedAt,
		Outcome: outcome, ErrorCode: receipt.Code, UPID: upidDigest,
		ApprovalRef: context.ApprovalRef, RequestedByRef: context.RequestedByRef,
		PayloadDigest: context.PayloadDigest, ResultDigest: resultDigest,
		PolicyDecision: policy, AgentVersion: context.AgentVersion,
	}
	switch {
	case policy == "denied":
		event.FailureStage = "policy"
	case receipt.State == "failed" || outcome == "rolled_back":
		event.FailureStage = "execution"
	case receipt.State == "indeterminate":
		event.FailureStage = "receipt"
	}
	if receipt.Error != nil {
		event.Error = &auditlog.ExecutionError{
			Source: receipt.Error.Source, Stage: receipt.Error.Stage, Method: receipt.Error.Method,
			Path: receipt.Error.Path, HTTPStatus: receipt.Error.HTTPStatus, Reason: receipt.Error.Reason,
		}
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
	if err := json.Unmarshal(raw, &record); err != nil || record.Version != SchemaVersion || !commandIDRE.MatchString(record.CommandID) || record.Digest == "" || record.ResourceKey == "" || !validJournalScope(record.Scope, record.NodeRef) || (record.Action != "" && !actionRE.MatchString(record.Action)) || (record.SourceConfigSHA256 != "" && !bodyHashRE.MatchString(record.SourceConfigSHA256)) || (record.SourceTemplateRef != "" && !nameRE.MatchString(record.SourceTemplateRef)) || record.SourceVMID < 0 || (record.PVETaskUPID != "" && !upidRE.MatchString(record.PVETaskUPID)) || (record.AuditContext != nil && record.AuditContext.validate() != nil) || (record.AuditPending != nil && record.AuditPending.Validate() != nil) || !validOptionalJournalLineage(record) || !validJournalMigrationMarkers(record) || !validSnippetJournalRecord(record) {
		return journalRecord{}, fmt.Errorf("control journal record is corrupt")
	}
	return record, nil
}

func validSnippetJournalRecord(record journalRecord) bool {
	present := record.SnippetDeletePhase != "" || record.SnippetStorageID != "" || record.SnippetVolumeSHA256 != ""
	if !present {
		return true
	}
	return record.Action == "vm.cloud-init-snippet.delete" && validSnippetJournalPhase(record.SnippetDeletePhase) &&
		storageRE.MatchString(record.SnippetStorageID) && bodyHashRE.MatchString(record.SnippetVolumeSHA256) && record.GuestType == "qemu"
}

func validOptionalJournalLineage(record journalRecord) bool {
	fieldsPresent := record.BindingID != "" || record.DeviceID != "" || record.ClusterRef != "" || record.ServiceRef != "" || record.InstanceUUID != "" || record.GuestType != "" || record.VMID != 0 || record.Generation != 0 || record.CredentialEpoch != 0 || record.AssignmentRevision != 0
	if !fieldsPresent {
		// Pre-lineage journals remain readable for receipt recovery, but cannot
		// authorize vm.set-initial-resources because exact metadata is absent.
		return true
	}
	if record.BindingID == "" && record.DeviceID == "" && record.CredentialEpoch == 0 && record.AssignmentRevision == 0 {
		// Hermetic test claims and old records may contain target metadata but no
		// production authority. They remain readable but never satisfy lineage.
		return true
	}
	if record.Scope == ScopeVM {
		return uuidRE.MatchString(record.BindingID) && commandIDRE.MatchString(record.DeviceID) && commandIDRE.MatchString(record.AgentRef) &&
			commandIDRE.MatchString(record.ClusterRef) && commandIDRE.MatchString(record.ServiceRef) && commandIDRE.MatchString(record.InstanceUUID) &&
			(record.GuestType == "qemu" || record.GuestType == "lxc") && record.VMID > 0 && record.Generation > 0 &&
			record.CredentialEpoch > 0 && record.AssignmentRevision > 0
	}
	return record.ClusterRef != "" && record.ServiceRef == "" && record.InstanceUUID == "" && record.GuestType == "" && record.VMID == 0 && record.Generation == 0
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
