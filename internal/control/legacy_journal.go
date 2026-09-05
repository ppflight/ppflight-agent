package control

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/ppflight/ppflight-agent/internal/protocol"
)

const maxLegacyJournalRetirements = 64

type legacyJournalMigrationP struct {
	LegacyAssignmentRevision      protocol.Counter `json:"legacyAssignmentRevision"`
	LegacyCloneCommandID          string           `json:"legacyCloneCommandId"`
	LegacyCloneOperationID        string           `json:"legacyCloneOperationId"`
	LegacyCloneDigest             string           `json:"legacyCloneDigest"`
	TemplateRef                   string           `json:"templateRef"`
	SourceVMID                    int              `json:"sourceVmid"`
	SourceConfigSHA256            string           `json:"sourceConfigSha256"`
	RetireIndeterminateCommandIDs []string         `json:"retireIndeterminateCommandIds"`
}

type LegacyJournalMigrationResult struct {
	Migrated                       bool             `json:"migrated"`
	LegacyAssignmentRevision       protocol.Counter `json:"legacyAssignmentRevision"`
	LegacyCloneCommandID           string           `json:"legacyCloneCommandId"`
	LegacyCloneOperationID         string           `json:"legacyCloneOperationId"`
	TemplateRef                    string           `json:"templateRef"`
	SourceVMID                     int              `json:"sourceVmid"`
	SourceConfigSHA256             string           `json:"sourceConfigSha256"`
	RetiredIndeterminateCommandIDs []string         `json:"retiredIndeterminateCommandIds"`
}

func validLegacyJournalMigration(command Command, value legacyJournalMigrationP) bool {
	if command.Identity.GuestType != "qemu" || value.LegacyAssignmentRevision == 0 ||
		(command.AssignmentRevision > 0 && value.LegacyAssignmentRevision >= command.AssignmentRevision) ||
		!commandIDRE.MatchString(value.LegacyCloneCommandID) || !commandIDRE.MatchString(value.LegacyCloneOperationID) ||
		value.LegacyCloneCommandID == command.CommandID || value.LegacyCloneOperationID == command.OperationID ||
		!bodyHashRE.MatchString(value.LegacyCloneDigest) || !nameRE.MatchString(value.TemplateRef) ||
		value.SourceVMID < 100 || value.SourceVMID > 999999999 || !bodyHashRE.MatchString(value.SourceConfigSHA256) ||
		value.RetireIndeterminateCommandIDs == nil || len(value.RetireIndeterminateCommandIDs) > maxLegacyJournalRetirements {
		return false
	}
	previous := ""
	for _, commandID := range value.RetireIndeterminateCommandIDs {
		if !commandIDRE.MatchString(commandID) || commandID == command.CommandID || commandID == value.LegacyCloneCommandID ||
			(previous != "" && commandID <= previous) {
			return false
		}
		previous = commandID
	}
	return true
}

// MigrateLegacyVMJournal performs a fixed, one-time local metadata migration.
// It can touch only the explicitly named legacy clone and explicitly named
// no-UPID indeterminate records for the signed command's exact VM generation.
func (j *Journal) MigrateLegacyVMJournal(command Command, parameters legacyJournalMigrationP, now time.Time) (LegacyJournalMigrationResult, error) {
	result := LegacyJournalMigrationResult{}
	if j == nil || !validLegacyJournalMigration(command, parameters) || command.Scope != ScopeVM || command.ApprovalRef == "" || !validInitialLineageCommand(command) {
		return result, errors.New("legacy journal migration authority is invalid")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	resourceKey, err := journalResourceKey(command)
	if err != nil {
		return result, err
	}
	clonePath := j.path(parameters.LegacyCloneCommandID)
	clone, err := readJournal(clonePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return result, ErrCloneJournalNotFound
		}
		return result, err
	}
	if eligibilityErr := legacyCloneEligibilityError(clone, command, parameters, resourceKey); eligibilityErr != nil {
		return result, eligibilityErr
	}
	retirements := make([]struct {
		path   string
		record journalRecord
	}, 0, len(parameters.RetireIndeterminateCommandIDs))
	for _, commandID := range parameters.RetireIndeterminateCommandIDs {
		filename := j.path(commandID)
		record, readErr := readJournal(filename)
		if readErr != nil || !legacyIndeterminateEligible(record, command, parameters.LegacyAssignmentRevision, resourceKey, commandID) {
			return result, fmt.Errorf("%w: %s", ErrListedRecordNotEligible, commandID)
		}
		retirements = append(retirements, struct {
			path   string
			record journalRecord
		}{path: filename, record: record})
	}
	migratedAt := now.UTC()
	// A later Agent fix may need to retire a new no-UPID indeterminate
	// mutation on a lineage that an earlier migration already established.
	// Preserve the first immutable clone migration marker and authority; the
	// follow-up command can touch only its explicitly listed record.
	if clone.MigratedByCommandID == "" {
		backfillLegacyAuthority(&clone, command)
		clone.SourceConfigSHA256 = parameters.SourceConfigSHA256
		clone.SourceTemplateRef = parameters.TemplateRef
		clone.SourceVMID = parameters.SourceVMID
		clone.MigratedByCommandID = command.CommandID
		clone.MigratedAt = &migratedAt
		if err := writeJournal(clonePath, clone); err != nil {
			return result, err
		}
	}
	for index := range retirements {
		record := &retirements[index].record
		backfillLegacyAuthority(record, command)
		record.RetiredByCommandID = command.CommandID
		record.RetiredAt = &migratedAt
		if err := writeJournal(retirements[index].path, *record); err != nil {
			return result, err
		}
	}
	return LegacyJournalMigrationResult{Migrated: true, LegacyAssignmentRevision: parameters.LegacyAssignmentRevision,
		LegacyCloneCommandID:   parameters.LegacyCloneCommandID,
		LegacyCloneOperationID: parameters.LegacyCloneOperationID, TemplateRef: parameters.TemplateRef,
		SourceVMID: parameters.SourceVMID, SourceConfigSHA256: parameters.SourceConfigSHA256,
		RetiredIndeterminateCommandIDs: append([]string(nil), parameters.RetireIndeterminateCommandIDs...)}, nil
}

// validateLegacyMigrationClaimLocked makes the narrow migration exception to
// the normal per-resource mutation lock. Only the exact signed clone lineage
// and explicitly listed, no-UPID indeterminate records may pass. A record is
// eligible whether its authority columns are absent (older schema) or fully
// populated with the exact historical authority; partially or differently
// populated authority remains fail-closed.
func (j *Journal) validateLegacyMigrationClaimLocked(command Command, parameters legacyJournalMigrationP) error {
	resourceKey, err := journalResourceKey(command)
	if err != nil {
		return err
	}
	clone, err := readJournal(j.path(parameters.LegacyCloneCommandID))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrCloneJournalNotFound
		}
		return err
	}
	if eligibilityErr := legacyCloneEligibilityError(clone, command, parameters, resourceKey); eligibilityErr != nil {
		return eligibilityErr
	}
	allowed := make(map[string]struct{}, len(parameters.RetireIndeterminateCommandIDs))
	for _, commandID := range parameters.RetireIndeterminateCommandIDs {
		record, readErr := readJournal(j.path(commandID))
		if readErr != nil || !legacyIndeterminateEligible(record, command, parameters.LegacyAssignmentRevision, resourceKey, commandID) {
			return fmt.Errorf("%w: %s", ErrListedRecordNotEligible, commandID)
		}
		allowed[commandID] = struct{}{}
	}
	entries, err := os.ReadDir(j.directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		record, readErr := readJournal(filepath.Join(j.directory, entry.Name()))
		if readErr != nil {
			return readErr
		}
		if !record.Mutating || record.ResourceKey != resourceKey || record.RetiredByCommandID != "" ||
			(record.State != "received" && record.State != "submitted" && record.State != "waiting" && record.State != "indeterminate") {
			continue
		}
		if _, listed := allowed[record.CommandID]; !listed {
			return fmt.Errorf("%w: %s", ErrUnlistedActiveMutation, record.CommandID)
		}
		if !legacyIndeterminateEligible(record, command, parameters.LegacyAssignmentRevision, resourceKey, record.CommandID) {
			return fmt.Errorf("%w: %s", ErrListedRecordNotEligible, record.CommandID)
		}
	}
	return nil
}

func legacyCloneEligibilityError(record journalRecord, command Command, parameters legacyJournalMigrationP, resourceKey string) error {
	if record.CommandID != parameters.LegacyCloneCommandID || record.OperationID != parameters.LegacyCloneOperationID ||
		(record.ResourceKey != resourceKey && !migratedCloneAncestorIdentityMatches(record, command)) {
		return ErrCloneResourceIdentityMismatch
	}
	action, actionOK := legacyRecordAction(record)
	if !actionOK || action != "vm.clone" {
		return ErrCloneResourceIdentityMismatch
	}
	if record.Digest != parameters.LegacyCloneDigest ||
		(record.SourceConfigSHA256 != "" && record.SourceConfigSHA256 != parameters.SourceConfigSHA256) {
		return ErrCloneDigestMismatch
	}
	if !recordSucceeded(record) || record.Receipt.AgentRef != record.AgentRef {
		return ErrCloneTerminalReceiptInvalid
	}
	if record.MigratedByCommandID != "" {
		if record.MigratedByCommandID == command.CommandID && record.SourceConfigSHA256 == parameters.SourceConfigSHA256 &&
			record.SourceTemplateRef == parameters.TemplateRef &&
			record.SourceVMID == parameters.SourceVMID && recordAuthorityEquals(record, command) {
			return nil
		}
		if record.SourceConfigSHA256 == parameters.SourceConfigSHA256 &&
			record.SourceTemplateRef == parameters.TemplateRef &&
			record.SourceVMID == parameters.SourceVMID &&
			migratedCloneAuthorityMatches(record, command, parameters.LegacyAssignmentRevision) {
			return nil
		}
		return ErrCloneAlreadyMigrated
	}
	if !legacySourceIdentityMatches(record, parameters) {
		return ErrCloneResourceIdentityMismatch
	}
	if !legacyRecordAuthorityMatches(record, command, parameters.LegacyAssignmentRevision) {
		return ErrCloneLegacyAuthorityMismatch
	}
	return nil
}

func migratedCloneAuthorityMatches(record journalRecord, command Command, legacyAssignmentRevision protocol.Counter) bool {
	return record.MigratedAt != nil && !record.MigratedAt.IsZero() &&
		record.AssignmentRevision > 0 && record.AssignmentRevision <= legacyAssignmentRevision &&
		legacyAssignmentRevision < command.AssignmentRevision &&
		record.BindingID == command.BindingID && record.DeviceID == command.DeviceID &&
		record.CredentialEpoch == command.CredentialEpoch && record.AgentRef == command.AgentRef &&
		record.ClusterRef == command.Identity.ClusterRef && record.NodeRef == command.Identity.NodeRef &&
		record.ServiceRef == command.Identity.ServiceRef && record.InstanceUUID == command.Identity.InstanceUUID &&
		record.GuestType == command.Identity.GuestType && record.VMID == command.Identity.VMID &&
		record.Generation > 0 && uint64(record.Generation) <= command.Identity.Generation
}

// A successful clone remains the immutable lineage root when a reinstall
// advances an instance generation.  Once that clone has already passed the
// signed migration ceremony, a later generation may use it as an ancestor
// proof only when every stable resource identity matches and the generation
// moves strictly forward.  This does not relax the current-generation check
// on the explicitly listed indeterminate record.
func migratedCloneAncestorIdentityMatches(record journalRecord, command Command) bool {
	return record.MigratedAt != nil && !record.MigratedAt.IsZero() && record.MigratedByCommandID != "" &&
		record.ClusterRef == command.Identity.ClusterRef && record.NodeRef == command.Identity.NodeRef &&
		record.ServiceRef == command.Identity.ServiceRef && record.InstanceUUID == command.Identity.InstanceUUID &&
		record.GuestType == command.Identity.GuestType && record.VMID == command.Identity.VMID &&
		record.Generation > 0 && uint64(record.Generation) < command.Identity.Generation
}

func legacyIndeterminateEligible(record journalRecord, command Command, legacyAssignmentRevision protocol.Counter, resourceKey, commandID string) bool {
	action, actionOK := legacyRecordAction(record)
	if !actionOK || record.CommandID != commandID || record.ResourceKey != resourceKey || !record.Mutating || action == "vm.migrate-legacy-journal" ||
		record.State != "indeterminate" || record.PVETaskUPID != "" || record.AgentUpgradeID != "" || record.Receipt == nil ||
		record.Receipt.State != "indeterminate" || !legacyIndeterminateReceiptCode(record.Receipt.Code, action) ||
		record.Receipt.CommandID != record.CommandID || record.Receipt.OperationID != record.OperationID ||
		record.Receipt.AgentRef != record.AgentRef || record.Receipt.PVETaskUPID != "" || record.Receipt.AgentUpgradeID != "" {
		return false
	}
	if record.RetiredByCommandID != "" {
		return record.RetiredByCommandID == command.CommandID && recordAuthorityEquals(record, command)
	}
	return legacyRecordAuthorityMatches(record, command, legacyAssignmentRevision)
}

func legacyRecordAuthorityMatches(record journalRecord, command Command, legacyAssignmentRevision protocol.Counter) bool {
	_, actionOK := legacyRecordAction(record)
	if record.AuditContext == nil || record.AgentRef != command.AgentRef || record.NodeRef != command.Identity.NodeRef ||
		!actionOK ||
		record.Scope != ScopeVM || record.AuditContext.AssignmentRevision != legacyAssignmentRevision ||
		record.AuditContext.CommandID != record.CommandID || record.AuditContext.OperationID != record.OperationID ||
		record.AuditContext.Scope != ScopeVM ||
		record.AuditContext.WebsiteCommandKeyID != command.SigningKeyID || record.AuditContext.ApprovalRef == "" {
		return false
	}
	targetRef, err := auditTargetRef(command)
	if err != nil || record.AuditContext.TargetRef != targetRef {
		return false
	}
	return optionalStringMatches(record.BindingID, command.BindingID) && optionalStringMatches(record.DeviceID, command.DeviceID) &&
		optionalCounterMatches(record.CredentialEpoch, command.CredentialEpoch) && optionalCounterMatches(record.AssignmentRevision, legacyAssignmentRevision) &&
		optionalStringMatches(record.ClusterRef, command.Identity.ClusterRef) && optionalStringMatches(record.ServiceRef, command.Identity.ServiceRef) &&
		optionalStringMatches(record.InstanceUUID, command.Identity.InstanceUUID) && optionalStringMatches(record.GuestType, command.Identity.GuestType) &&
		optionalIntMatches(record.VMID, command.Identity.VMID) && optionalCounterMatches(record.Generation, protocol.Counter(command.Identity.Generation))
}

// legacyRecordAction accepts a missing record-level action only when the
// durable signed audit projection supplies a known, mutating VM action. This
// is the exact rc.27 production shape; it never derives an action from the
// migration request or from untrusted free-form data.
func legacyRecordAction(record journalRecord) (string, bool) {
	if record.AuditContext == nil || record.AuditContext.Action == "" ||
		!validActionScope(record.AuditContext.Action, ScopeVM) || !requiresApproval(record.AuditContext.Action) {
		return "", false
	}
	if record.Action != "" && record.Action != record.AuditContext.Action {
		return "", false
	}
	return record.AuditContext.Action, true
}

func legacySourceIdentityMatches(record journalRecord, parameters legacyJournalMigrationP) bool {
	templateMatches := record.SourceTemplateRef == "" || record.SourceTemplateRef == parameters.TemplateRef
	vmidMatches := record.SourceVMID == 0 || record.SourceVMID == parameters.SourceVMID
	// Reject partially populated old source identity. It must be entirely
	// absent or already equal to the independently re-read PVE source.
	identityAbsent := record.SourceTemplateRef == "" && record.SourceVMID == 0
	identityComplete := record.SourceTemplateRef != "" && record.SourceVMID != 0
	return templateMatches && vmidMatches && (identityAbsent || identityComplete)
}

func backfillLegacyAuthority(record *journalRecord, command Command) {
	if record.Action == "" && record.AuditContext != nil {
		record.Action = record.AuditContext.Action
	}
	record.IdempotencyKey = record.AuditContext.IdempotencyKey
	record.BindingID = command.BindingID
	record.DeviceID = command.DeviceID
	record.CredentialEpoch = command.CredentialEpoch
	record.AssignmentRevision = command.AssignmentRevision
	record.ClusterRef = command.Identity.ClusterRef
	record.NodeRef = command.Identity.NodeRef
	record.ServiceRef = command.Identity.ServiceRef
	record.InstanceUUID = command.Identity.InstanceUUID
	record.GuestType = command.Identity.GuestType
	record.VMID = command.Identity.VMID
	record.Generation = protocol.Counter(command.Identity.Generation)
}

func recordAuthorityEquals(record journalRecord, command Command) bool {
	return record.BindingID == command.BindingID && record.DeviceID == command.DeviceID && record.CredentialEpoch == command.CredentialEpoch &&
		record.AssignmentRevision == command.AssignmentRevision && record.AgentRef == command.AgentRef && record.ClusterRef == command.Identity.ClusterRef &&
		record.NodeRef == command.Identity.NodeRef && record.ServiceRef == command.Identity.ServiceRef && record.InstanceUUID == command.Identity.InstanceUUID &&
		record.GuestType == command.Identity.GuestType && record.VMID == command.Identity.VMID && uint64(record.Generation) == command.Identity.Generation
}

func optionalStringMatches(value, expected string) bool { return value == "" || value == expected }
func optionalIntMatches(value, expected int) bool       { return value == 0 || value == expected }
func optionalCounterMatches(value, expected protocol.Counter) bool {
	return value == 0 || value == expected
}

func legacyIndeterminateReceiptCode(code, action string) bool {
	if code == "EXECUTION_INDETERMINATE" || code == "PVE_RESULT_INDETERMINATE" {
		return true
	}
	if code != "PVE_ACTION_INDETERMINATE" {
		return false
	}
	switch action {
	case "vm.start", "vm.shutdown", "vm.stop", "vm.reboot", "vm.suspend", "vm.resume":
		return true
	default:
		return false
	}
}

func validJournalMigrationMarkers(record journalRecord) bool {
	if (record.MigratedByCommandID == "") != (record.MigratedAt == nil) ||
		(record.RetiredByCommandID == "") != (record.RetiredAt == nil) ||
		(record.MigratedByCommandID != "" && !commandIDRE.MatchString(record.MigratedByCommandID)) ||
		(record.RetiredByCommandID != "" && !commandIDRE.MatchString(record.RetiredByCommandID)) ||
		record.MigratedByCommandID == record.CommandID || record.RetiredByCommandID == record.CommandID ||
		(record.MigratedByCommandID != "" && record.RetiredByCommandID != "") {
		return false
	}
	if record.MigratedByCommandID != "" && (record.Action != "vm.clone" || record.SourceTemplateRef == "" ||
		record.SourceVMID < 100 || !recordSucceeded(record)) {
		return false
	}
	if record.RetiredByCommandID != "" {
		validLegacyRetirement := record.Action != "vm.migrate-legacy-journal" && record.State == "indeterminate" &&
			record.PVETaskUPID == "" && record.AgentUpgradeID == "" && record.Receipt != nil &&
			record.Receipt.State == "indeterminate" && legacyIndeterminateReceiptCode(record.Receipt.Code, record.Action) &&
			record.Receipt.PVETaskUPID == "" && record.Receipt.AgentUpgradeID == ""
		if !validLegacyRetirement && !knownDelete501RetirementShape(record) {
			return false
		}
	}
	if record.MigratedAt != nil && (record.MigratedAt.IsZero() || record.MigratedAt.Location() != time.UTC) {
		return false
	}
	if record.RetiredAt != nil && (record.RetiredAt.IsZero() || record.RetiredAt.Location() != time.UTC) {
		return false
	}
	return true
}
