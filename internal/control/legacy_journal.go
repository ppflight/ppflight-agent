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
	if value.LegacyAssignmentRevision == 0 ||
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
			return result, errors.New("legacy clone journal was not found")
		}
		return result, err
	}
	if !legacyCloneEligible(clone, command, parameters, resourceKey) {
		return result, errors.New("legacy clone journal does not match signed VM authority")
	}
	retirements := make([]struct {
		path   string
		record journalRecord
	}, 0, len(parameters.RetireIndeterminateCommandIDs))
	for _, commandID := range parameters.RetireIndeterminateCommandIDs {
		filename := j.path(commandID)
		record, readErr := readJournal(filename)
		if readErr != nil || !legacyIndeterminateEligible(record, command, parameters.LegacyAssignmentRevision, resourceKey, commandID) {
			return result, fmt.Errorf("legacy indeterminate journal %s is not eligible", commandID)
		}
		retirements = append(retirements, struct {
			path   string
			record journalRecord
		}{path: filename, record: record})
	}
	migratedAt := now.UTC()
	backfillLegacyAuthority(&clone, command)
	clone.SourceTemplateRef = parameters.TemplateRef
	clone.SourceVMID = parameters.SourceVMID
	clone.MigratedByCommandID = command.CommandID
	clone.MigratedAt = &migratedAt
	if err := writeJournal(clonePath, clone); err != nil {
		return result, err
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

func (j *Journal) resourceBusyForLegacyMigrationLocked(command Command, parameters legacyJournalMigrationP) (bool, error) {
	resourceKey, err := journalResourceKey(command)
	if err != nil {
		return false, err
	}
	allowed := make(map[string]struct{}, len(parameters.RetireIndeterminateCommandIDs))
	for _, commandID := range parameters.RetireIndeterminateCommandIDs {
		allowed[commandID] = struct{}{}
	}
	entries, err := os.ReadDir(j.directory)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		record, readErr := readJournal(filepath.Join(j.directory, entry.Name()))
		if readErr != nil {
			return false, readErr
		}
		if !record.Mutating || record.ResourceKey != resourceKey || record.RetiredByCommandID != "" ||
			(record.State != "received" && record.State != "submitted" && record.State != "waiting" && record.State != "indeterminate") {
			continue
		}
		if _, listed := allowed[record.CommandID]; !listed ||
			!legacyIndeterminateEligible(record, command, parameters.LegacyAssignmentRevision, resourceKey, record.CommandID) {
			return true, nil
		}
	}
	return false, nil
}

func legacyCloneEligible(record journalRecord, command Command, parameters legacyJournalMigrationP, resourceKey string) bool {
	if record.CommandID != parameters.LegacyCloneCommandID || record.OperationID != parameters.LegacyCloneOperationID ||
		record.Digest != parameters.LegacyCloneDigest || record.Action != "vm.clone" || record.SourceConfigSHA256 != parameters.SourceConfigSHA256 ||
		record.ResourceKey != resourceKey || !recordSucceeded(record) {
		return false
	}
	if record.MigratedByCommandID != "" {
		return record.MigratedByCommandID == command.CommandID && record.SourceTemplateRef == parameters.TemplateRef &&
			record.SourceVMID == parameters.SourceVMID && recordAuthorityEquals(record, command)
	}
	return record.SourceTemplateRef == "" && record.SourceVMID == 0 && isLegacyJournalRecord(record) &&
		legacyRecordAuthorityMatches(record, command, parameters.LegacyAssignmentRevision)
}

func legacyIndeterminateEligible(record journalRecord, command Command, legacyAssignmentRevision protocol.Counter, resourceKey, commandID string) bool {
	if record.CommandID != commandID || record.ResourceKey != resourceKey || !record.Mutating || record.Action == "vm.migrate-legacy-journal" ||
		record.State != "indeterminate" || record.PVETaskUPID != "" || record.AgentUpgradeID != "" || record.Receipt == nil ||
		record.Receipt.State != "indeterminate" || !legacyIndeterminateReceiptCode(record.Receipt.Code) ||
		record.Receipt.CommandID != record.CommandID || record.Receipt.OperationID != record.OperationID ||
		record.Receipt.AgentRef != record.AgentRef || record.Receipt.PVETaskUPID != "" || record.Receipt.AgentUpgradeID != "" {
		return false
	}
	if record.RetiredByCommandID != "" {
		return record.RetiredByCommandID == command.CommandID && recordAuthorityEquals(record, command)
	}
	return isLegacyJournalRecord(record) && legacyRecordAuthorityMatches(record, command, legacyAssignmentRevision)
}

func legacyRecordAuthorityMatches(record journalRecord, command Command, legacyAssignmentRevision protocol.Counter) bool {
	if record.AuditContext == nil || record.AgentRef != command.AgentRef || record.NodeRef != command.Identity.NodeRef ||
		record.Scope != ScopeVM || record.AuditContext.AssignmentRevision != legacyAssignmentRevision ||
		record.AuditContext.CommandID != record.CommandID || record.AuditContext.OperationID != record.OperationID ||
		record.AuditContext.Action != record.Action || record.AuditContext.Scope != ScopeVM ||
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

func isLegacyJournalRecord(record journalRecord) bool {
	return record.BindingID == "" || record.DeviceID == "" || record.CredentialEpoch == 0 || record.AssignmentRevision == 0 ||
		record.ClusterRef == "" || record.ServiceRef == "" || record.InstanceUUID == "" || record.GuestType == "" ||
		record.VMID == 0 || record.Generation == 0
}

func backfillLegacyAuthority(record *journalRecord, command Command) {
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

func legacyIndeterminateReceiptCode(code string) bool {
	return code == "EXECUTION_INDETERMINATE" || code == "PVE_RESULT_INDETERMINATE"
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
	if record.RetiredByCommandID != "" && (record.Action == "vm.migrate-legacy-journal" || record.State != "indeterminate" ||
		record.PVETaskUPID != "" || record.AgentUpgradeID != "" || record.Receipt == nil ||
		record.Receipt.State != "indeterminate" || !legacyIndeterminateReceiptCode(record.Receipt.Code) ||
		record.Receipt.PVETaskUPID != "" || record.Receipt.AgentUpgradeID != "") {
		return false
	}
	if record.MigratedAt != nil && (record.MigratedAt.IsZero() || record.MigratedAt.Location() != time.UTC) {
		return false
	}
	if record.RetiredAt != nil && (record.RetiredAt.IsZero() || record.RetiredAt.Location() != time.UTC) {
		return false
	}
	return true
}
