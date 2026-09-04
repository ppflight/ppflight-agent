package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/ppflight/ppflight-agent/internal/protocol"
)

const ipFilterDeleteRecoveryKind = "ipfilter-delete-readback-v1"

type ipFilterDeleteRecoveryP struct {
	RecoveryKind             string           `json:"recoveryKind"`
	LegacyAssignmentRevision protocol.Counter `json:"legacyAssignmentRevision"`
	FailedCommandID          string           `json:"failedCommandId"`
	FailedOperationID        string           `json:"failedOperationId"`
	FailedCommandDigest      string           `json:"failedCommandDigest"`
	FailedPayloadSHA256      string           `json:"failedPayloadSha256"`
	Name                     string           `json:"name"`
	CIDR                     string           `json:"cidr"`
}

type IPFilterDeleteRecoveryResult struct {
	Reconciled               bool             `json:"reconciled"`
	RecoveryKind             string           `json:"recoveryKind"`
	LegacyAssignmentRevision protocol.Counter `json:"legacyAssignmentRevision"`
	FailedCommandID          string           `json:"failedCommandId"`
	FailedOperationID        string           `json:"failedOperationId"`
	FailedCommandDigest      string           `json:"failedCommandDigest"`
	FailedPayloadSHA256      string           `json:"failedPayloadSha256"`
	FailedReceiptCode        string           `json:"failedReceiptCode"`
	Name                     string           `json:"name"`
	CIDR                     string           `json:"cidr"`
	ProviderReadVerified     bool             `json:"providerReadVerified"`
	TargetPresent            bool             `json:"targetPresent"`
	ObservedCIDR             string           `json:"observedCidr"`
}

func decodeIPFilterDeleteRecovery(command Command) (ipFilterDeleteRecoveryP, bool) {
	var parameters ipFilterDeleteRecoveryP
	if strictParameters(command.Parameters, &parameters) != nil || parameters.RecoveryKind != ipFilterDeleteRecoveryKind {
		return ipFilterDeleteRecoveryP{}, false
	}
	return parameters, validIPFilterDeleteRecovery(command, parameters)
}

func validIPFilterDeleteRecovery(command Command, parameters ipFilterDeleteRecoveryP) bool {
	return command.Action == "vm.migrate-legacy-journal" && command.Scope == ScopeVM && command.ApprovalRef != "" &&
		(command.Identity.GuestType == "qemu" || command.Identity.GuestType == "lxc") &&
		parameters.RecoveryKind == ipFilterDeleteRecoveryKind && parameters.LegacyAssignmentRevision > 0 &&
		(command.AssignmentRevision == 0 || parameters.LegacyAssignmentRevision < command.AssignmentRevision) &&
		commandIDRE.MatchString(parameters.FailedCommandID) && commandIDRE.MatchString(parameters.FailedOperationID) &&
		bodyHashRE.MatchString(parameters.FailedCommandDigest) && bodyHashRE.MatchString(parameters.FailedPayloadSHA256) &&
		parameters.FailedPayloadSHA256 == ipFilterDeletePayloadSHA256(parameters.Name, parameters.CIDR) &&
		validIPSetEntry(parameters.Name, parameters.CIDR) &&
		command.CommandID != parameters.FailedCommandID && command.OperationID != parameters.FailedOperationID
}

func ipFilterDeleteRecordEligible(record journalRecord, command Command, parameters ipFilterDeleteRecoveryP, resourceKey string) bool {
	if !validIPFilterDeleteRecovery(command, parameters) || record.CommandID != parameters.FailedCommandID ||
		record.OperationID != parameters.FailedOperationID || record.Digest != parameters.FailedCommandDigest ||
		record.ResourceKey != resourceKey || record.Action != "firewall.ipset.entry.delete" || !record.Mutating ||
		record.Scope != ScopeVM || record.State != "indeterminate" || record.PVETaskUPID != "" || record.AgentUpgradeID != "" ||
		record.Receipt == nil || record.Receipt.State != "indeterminate" || record.Receipt.Code != "PVE_RESULT_INDETERMINATE" ||
		record.Receipt.CommandID != record.CommandID || record.Receipt.OperationID != record.OperationID ||
		record.Receipt.AgentRef != record.AgentRef || record.Receipt.Accepted || record.Receipt.Asynchronous ||
		!record.Receipt.MutationMayHaveSucceeded || record.Receipt.PVETaskUPID != "" || record.Receipt.AgentUpgradeID != "" ||
		record.AuditContext == nil || record.AuditContext.Action != "firewall.ipset.entry.delete" ||
		record.AuditContext.CommandID != record.CommandID || record.AuditContext.OperationID != record.OperationID ||
		record.AuditContext.IdempotencyKey != record.IdempotencyKey ||
		record.AuditContext.AssignmentRevision != parameters.LegacyAssignmentRevision ||
		record.AuditContext.Scope != ScopeVM || record.AuditContext.WebsiteCommandKeyID != command.SigningKeyID ||
		record.AuditContext.ApprovalRef == "" || record.AuditContext.PayloadDigest != "sha256:"+parameters.FailedPayloadSHA256 {
		return false
	}
	targetRef, err := auditTargetRef(command)
	if err != nil || record.AuditContext.TargetRef != targetRef {
		return false
	}
	if record.RetiredByCommandID == "" && record.RetiredAt == nil {
		return legacyRecordAuthorityMatches(record, command, parameters.LegacyAssignmentRevision)
	}
	return record.RetiredByCommandID == command.CommandID && record.RetiredAt != nil &&
		legacyRecordAuthorityMatches(record, command, parameters.LegacyAssignmentRevision)
}

func (j *Journal) validateIPFilterDeleteRecoveryClaimLocked(command Command, parameters ipFilterDeleteRecoveryP) error {
	resourceKey, err := journalResourceKey(command)
	if err != nil {
		return err
	}
	record, err := readJournal(j.path(parameters.FailedCommandID))
	if err != nil || !ipFilterDeleteRecordEligible(record, command, parameters, resourceKey) {
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

// ReconcileIPFilterDelete appends retirement evidence only after the executor
// has independently read the exact PVE IPSet. It never edits the historical
// command, receipt, digest, state, or signed audit context.
func (j *Journal) ReconcileIPFilterDelete(command Command, parameters ipFilterDeleteRecoveryP, targetPresent bool, observedCIDR string, now time.Time) (IPFilterDeleteRecoveryResult, error) {
	result := IPFilterDeleteRecoveryResult{}
	expected, expectedOK := canonicalFirewallCIDR(parameters.CIDR)
	observed, observedOK := canonicalFirewallCIDR(observedCIDR)
	if j == nil || !validIPFilterDeleteRecovery(command, parameters) || !expectedOK ||
		(targetPresent && (!observedOK || observed != expected)) || (!targetPresent && observedCIDR != "") {
		return result, errors.New("IPFilter delete recovery read proof is invalid")
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
	if !ipFilterDeleteRecordEligible(record, command, parameters, resourceKey) {
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
	return IPFilterDeleteRecoveryResult{
		Reconciled: true, RecoveryKind: ipFilterDeleteRecoveryKind,
		LegacyAssignmentRevision: parameters.LegacyAssignmentRevision,
		FailedCommandID:          parameters.FailedCommandID, FailedOperationID: parameters.FailedOperationID,
		FailedCommandDigest: parameters.FailedCommandDigest, FailedPayloadSHA256: parameters.FailedPayloadSHA256,
		FailedReceiptCode: "PVE_RESULT_INDETERMINATE",
		Name:              parameters.Name, CIDR: parameters.CIDR, ProviderReadVerified: true,
		TargetPresent: targetPresent, ObservedCIDR: observedCIDR,
	}, nil
}

func validIPFilterDeleteRecoveryJournalResult(record *journalRecord, raw []byte) bool {
	if record == nil || record.Action != "vm.migrate-legacy-journal" || len(raw) == 0 {
		return false
	}
	var result IPFilterDeleteRecoveryResult
	if strictParameters(raw, &result) != nil || !result.Reconciled || result.RecoveryKind != ipFilterDeleteRecoveryKind ||
		result.LegacyAssignmentRevision == 0 || result.LegacyAssignmentRevision >= record.AssignmentRevision ||
		!commandIDRE.MatchString(result.FailedCommandID) || !commandIDRE.MatchString(result.FailedOperationID) ||
		!bodyHashRE.MatchString(result.FailedCommandDigest) || !bodyHashRE.MatchString(result.FailedPayloadSHA256) ||
		result.FailedPayloadSHA256 != ipFilterDeletePayloadSHA256(result.Name, result.CIDR) ||
		result.FailedReceiptCode != "PVE_RESULT_INDETERMINATE" ||
		!validIPSetEntry(result.Name, result.CIDR) || !result.ProviderReadVerified {
		return false
	}
	expected, expectedOK := canonicalFirewallCIDR(result.CIDR)
	observed, observedOK := canonicalFirewallCIDR(result.ObservedCIDR)
	return (result.TargetPresent && expectedOK && observedOK && expected == observed) ||
		(!result.TargetPresent && result.ObservedCIDR == "")
}

func ipFilterDeletePayloadSHA256(name, cidr string) string {
	raw, err := json.Marshal(map[string]string{"name": name, "cidr": cidr})
	if err != nil {
		return ""
	}
	return protocol.BodyHash(raw)
}
