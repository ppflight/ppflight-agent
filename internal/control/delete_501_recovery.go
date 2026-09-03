package control

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// This is a one-incident compatibility repair for the rc.4 DELETE-body bug.
// The old journal did not persist PVE's 38-byte HTTP 501 response, so the
// durable recovery authority is intentionally pinned to the exact production
// command tuple whose matching pveproxy access record was independently
// audited. It is not a generic indeterminate-record retirement API.
const (
	delete501RecoveryKind       = "pve-delete-form-body-501-v1"
	delete501AffectedAgent      = "0.1.1-rc.4"
	delete501ExpectedPVEVersion = "8.4.0"
	delete501CommandID          = "c864ed6d-3d43-4fc9-b966-edaf7066cbb0"
	delete501OperationID        = "f967235b-a593-42fa-ae2d-f42219204d59"
	delete501CommandDigest      = "c1ed3db0b581f7891f3f917fbf9b42d2ffb86251d0cdf4b2a00cb0c6d48ab830"
	delete501VMID               = 100
	delete501Generation         = 1
)

type delete501RecoveryP struct {
	RecoveryKind        string `json:"recoveryKind"`
	FailedCommandID     string `json:"failedCommandId"`
	FailedOperationID   string `json:"failedOperationId"`
	FailedCommandDigest string `json:"failedCommandDigest"`
}

type Delete501RecoveryResult struct {
	Reconciled           bool   `json:"reconciled"`
	RecoveryKind         string `json:"recoveryKind"`
	FailedCommandID      string `json:"failedCommandId"`
	FailedOperationID    string `json:"failedOperationId"`
	FailedCommandDigest  string `json:"failedCommandDigest"`
	FailedReceiptCode    string `json:"failedReceiptCode"`
	AffectedAgentVersion string `json:"affectedAgentVersion"`
	PVEVersion           string `json:"pveVersion"`
	GuestType            string `json:"guestType"`
	VMID                 int    `json:"vmid"`
	Generation           uint64 `json:"generation"`
	GuestPresent         bool   `json:"guestPresent"`
	GuestStatus          string `json:"guestStatus"`
}

func decodeDelete501Recovery(command Command) (delete501RecoveryP, bool) {
	var parameters delete501RecoveryP
	if strictParameters(command.Parameters, &parameters) != nil || parameters.RecoveryKind != delete501RecoveryKind {
		return delete501RecoveryP{}, false
	}
	return parameters, validDelete501Recovery(command, parameters)
}

func validDelete501Recovery(command Command, parameters delete501RecoveryP) bool {
	return command.Action == "vm.migrate-legacy-journal" && command.Scope == ScopeVM && command.ApprovalRef != "" &&
		command.Identity.GuestType == "qemu" && command.Identity.VMID == delete501VMID && command.Identity.Generation == delete501Generation &&
		parameters.RecoveryKind == delete501RecoveryKind && parameters.FailedCommandID == delete501CommandID &&
		parameters.FailedOperationID == delete501OperationID && parameters.FailedCommandDigest == delete501CommandDigest &&
		command.CommandID != parameters.FailedCommandID && command.OperationID != parameters.FailedOperationID
}

func delete501RecordEligible(record journalRecord, command Command, parameters delete501RecoveryP, resourceKey string) bool {
	if !validDelete501Recovery(command, parameters) || record.CommandID != parameters.FailedCommandID ||
		record.OperationID != parameters.FailedOperationID || record.Digest != parameters.FailedCommandDigest ||
		record.ResourceKey != resourceKey || record.Action != "vm.delete" || !record.Mutating ||
		record.Scope != ScopeVM || record.GuestType != "qemu" || record.VMID != delete501VMID || uint64(record.Generation) != delete501Generation ||
		record.State != "indeterminate" || record.PVETaskUPID != "" || record.AgentUpgradeID != "" || record.Receipt == nil ||
		record.Receipt.State != "indeterminate" || record.Receipt.Code != "PVE_ACTION_INDETERMINATE" ||
		record.Receipt.CommandID != record.CommandID || record.Receipt.OperationID != record.OperationID ||
		record.Receipt.AgentRef != record.AgentRef || record.Receipt.Accepted || record.Receipt.Asynchronous ||
		!record.Receipt.MutationMayHaveSucceeded || record.Receipt.PVETaskUPID != "" || record.Receipt.AgentUpgradeID != "" ||
		record.AuditContext == nil || record.AuditContext.AgentVersion != delete501AffectedAgent ||
		record.AuditContext.Action != "vm.delete" || record.AuditContext.CommandID != record.CommandID ||
		record.AuditContext.OperationID != record.OperationID || record.AuditContext.IdempotencyKey != record.IdempotencyKey ||
		record.AuditContext.AssignmentRevision != record.AssignmentRevision || record.AuditContext.Scope != ScopeVM ||
		record.AuditContext.WebsiteCommandKeyID != command.SigningKeyID || record.AuditContext.ApprovalRef == "" ||
		!recordAuthorityEquals(record, command) {
		return false
	}
	targetRef, err := auditTargetRef(command)
	if err != nil || record.AuditContext.TargetRef != targetRef {
		return false
	}
	if record.RetiredByCommandID == "" && record.RetiredAt == nil {
		return true
	}
	return record.RetiredByCommandID == command.CommandID && record.RetiredAt != nil
}

func knownDelete501RetirementShape(record journalRecord) bool {
	return record.Action == "vm.delete" && record.Scope == ScopeVM && record.GuestType == "qemu" &&
		record.CommandID == delete501CommandID && record.OperationID == delete501OperationID && record.Digest == delete501CommandDigest &&
		record.VMID == delete501VMID && uint64(record.Generation) == delete501Generation && record.State == "indeterminate" &&
		record.PVETaskUPID == "" && record.AgentUpgradeID == "" && record.Receipt != nil &&
		record.Receipt.State == "indeterminate" && record.Receipt.Code == "PVE_ACTION_INDETERMINATE" &&
		record.Receipt.CommandID == record.CommandID && record.Receipt.OperationID == record.OperationID &&
		record.Receipt.AgentRef == record.AgentRef &&
		!record.Receipt.Accepted && !record.Receipt.Asynchronous && record.Receipt.MutationMayHaveSucceeded &&
		record.Receipt.PVETaskUPID == "" && record.Receipt.AgentUpgradeID == "" && record.AuditContext != nil &&
		record.AuditContext.AgentVersion == delete501AffectedAgent && record.AuditContext.Action == "vm.delete" &&
		record.AuditContext.Scope == ScopeVM && record.AuditContext.CommandID == record.CommandID &&
		record.AuditContext.OperationID == record.OperationID && record.AuditContext.IdempotencyKey == record.IdempotencyKey &&
		record.AuditContext.AssignmentRevision == record.AssignmentRevision && record.AuditContext.ApprovalRef != ""
}

func (j *Journal) validateDelete501RecoveryClaimLocked(command Command, parameters delete501RecoveryP) error {
	resourceKey, err := journalResourceKey(command)
	if err != nil {
		return err
	}
	record, err := readJournal(j.path(parameters.FailedCommandID))
	if err != nil || !delete501RecordEligible(record, command, parameters, resourceKey) {
		return fmt.Errorf("%w: %s", ErrListedRecordNotEligible, parameters.FailedCommandID)
	}
	entries, err := os.ReadDir(j.directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		candidate, readErr := readJournal(filepath.Join(j.directory, entry.Name()))
		if readErr != nil {
			return readErr
		}
		if candidate.Mutating && candidate.ResourceKey == resourceKey && candidate.RetiredByCommandID == "" &&
			(candidate.State == "received" || candidate.State == "submitted" || candidate.State == "waiting" || candidate.State == "indeterminate") &&
			candidate.CommandID != parameters.FailedCommandID {
			return fmt.Errorf("%w: %s", ErrUnlistedActiveMutation, candidate.CommandID)
		}
	}
	return nil
}

// ReconcileDelete501 appends retirement evidence to one exact historical
// record. It never rewrites the old command, receipt, digest, state, authority,
// or audit context.
func (j *Journal) ReconcileDelete501(command Command, parameters delete501RecoveryP, pveVersion, guestStatus string, now time.Time) (Delete501RecoveryResult, error) {
	result := Delete501RecoveryResult{}
	if j == nil || pveVersion != delete501ExpectedPVEVersion || guestStatus != "stopped" {
		return result, errors.New("delete 501 recovery read proof is invalid")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	resourceKey, err := journalResourceKey(command)
	if err != nil {
		return result, err
	}
	filename := j.path(parameters.FailedCommandID)
	record, err := readJournal(filename)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return result, ErrListedRecordNotEligible
		}
		return result, err
	}
	if !delete501RecordEligible(record, command, parameters, resourceKey) {
		return result, ErrListedRecordNotEligible
	}
	retiredAt := now.UTC()
	if record.RetiredAt != nil {
		retiredAt = record.RetiredAt.UTC()
	} else {
		record.RetiredByCommandID = command.CommandID
		record.RetiredAt = &retiredAt
		if err := writeJournal(filename, record); err != nil {
			return result, err
		}
	}
	return Delete501RecoveryResult{
		Reconciled: true, RecoveryKind: delete501RecoveryKind,
		FailedCommandID: parameters.FailedCommandID, FailedOperationID: parameters.FailedOperationID,
		FailedCommandDigest: parameters.FailedCommandDigest, FailedReceiptCode: "PVE_ACTION_INDETERMINATE",
		AffectedAgentVersion: delete501AffectedAgent, PVEVersion: pveVersion, GuestType: "qemu",
		VMID: delete501VMID, Generation: delete501Generation, GuestPresent: true, GuestStatus: guestStatus,
	}, nil
}

func validDelete501RecoveryJournalResult(record *journalRecord, raw []byte) bool {
	if record == nil || record.Action != "vm.migrate-legacy-journal" || len(raw) == 0 {
		return false
	}
	var result Delete501RecoveryResult
	return strictParameters(raw, &result) == nil && result.Reconciled && result.RecoveryKind == delete501RecoveryKind &&
		result.FailedCommandID == delete501CommandID && result.FailedOperationID == delete501OperationID &&
		result.FailedCommandDigest == delete501CommandDigest && result.FailedReceiptCode == "PVE_ACTION_INDETERMINATE" &&
		result.AffectedAgentVersion == delete501AffectedAgent && result.PVEVersion == delete501ExpectedPVEVersion &&
		result.GuestType == "qemu" && result.VMID == delete501VMID && result.Generation == delete501Generation &&
		result.GuestPresent && result.GuestStatus == "stopped"
}
