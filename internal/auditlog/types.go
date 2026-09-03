// Package auditlog defines the monitoring-only control audit wire contract.
// It deliberately contains no command parameters, secrets, or full results.
package auditlog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ppflight/ppflight-agent/internal/protocol"
)

const SchemaVersion = 1

const (
	DeliveryErrorAuthBlocked   = "AUTH_BLOCKED"
	DeliveryErrorFailed        = "DELIVERY_FAILED"
	DeliveryErrorQueueCapacity = "QUEUE_CAPACITY"
)

var (
	uuidRE       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	safeRefRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	targetPartRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	actionRE     = regexp.MustCompile(`^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+$`)
	errorCodeRE  = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
	digestRE     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// DeliveryState is a bounded snapshot taken while an immutable batch is
// created. It is informational only and never participates in authorization.
type DeliveryState struct {
	PendingItems      protocol.Counter `json:"pendingItems"`
	PendingBytes      protocol.Counter `json:"pendingBytes"`
	LastDeliveryError string           `json:"lastDeliveryError"`
	AuthBlocked       bool             `json:"authBlocked"`
	AuthBlockedSince  *time.Time       `json:"authBlockedSince,omitempty"`
	OldestObservedAt  *time.Time       `json:"oldestObservedAt,omitempty"`
}

// Target is an optional, redacted VM/CT identity projection. It deliberately
// excludes command parameters, network addresses, credentials and PVE task
// identifiers. TargetRef remains the stable generation identity.
type Target struct {
	ClusterRef string `json:"clusterRef"`
	NodeRef    string `json:"nodeRef"`
	GuestType  string `json:"guestType"`
	VMID       int    `json:"vmid"`
	GuestName  string `json:"guestName,omitempty"`
}

// Event is the complete allowlist for a website control audit event. Do not
// add command parameters or Receipt.Result to this type.
type Event struct {
	EventID             string           `json:"eventId"`
	AssignmentRevision  protocol.Counter `json:"assignmentRevision"`
	CommandID           string           `json:"commandId"`
	IdempotencyKey      string           `json:"idempotencyKey"`
	Action              string           `json:"action"`
	Scope               string           `json:"scope"`
	TargetRef           string           `json:"targetRef"`
	Target              *Target          `json:"target,omitempty"`
	WebsiteCommandKeyID string           `json:"websiteCommandKeyId"`
	ReceivedAt          time.Time        `json:"receivedAt"`
	AcceptedAt          *time.Time       `json:"acceptedAt,omitempty"`
	StartedAt           *time.Time       `json:"startedAt,omitempty"`
	EndedAt             *time.Time       `json:"endedAt,omitempty"`
	// FinishedAt is retained as the audit-v1 compatibility name. New events
	// mirror EndedAt into this field; old payloads without EndedAt remain valid.
	FinishedAt     *time.Time `json:"finishedAt,omitempty"`
	Outcome        string     `json:"outcome"`
	ErrorCode      string     `json:"errorCode,omitempty"`
	FailureStage   string     `json:"failureStage,omitempty"`
	UPID           string     `json:"upid,omitempty"`
	ApprovalRef    string     `json:"approvalRef,omitempty"`
	RequestedByRef string     `json:"requestedByRef,omitempty"`
	PayloadDigest  string     `json:"payloadDigest"`
	ResultDigest   string     `json:"resultDigest,omitempty"`
	PolicyDecision string     `json:"policyDecision"`
	AgentVersion   string     `json:"agentVersion"`
}

// Batch is sent only to POST /internal/v1/monitoring/audit-events/batches.
// Every current batch contains one event and reuses its receipt UUID as the
// batch ID; the receiver still permits up to 500 for forward-compatible
// aggregation.
type Batch struct {
	SchemaVersion      int              `json:"schemaVersion"`
	BatchID            string           `json:"batchId"`
	MonitoringAgentRef string           `json:"monitoringAgentRef"`
	DeviceID           string           `json:"deviceId"`
	CredentialEpoch    protocol.Counter `json:"credentialEpoch"`
	Sequence           protocol.Counter `json:"sequence"`
	BootID             string           `json:"bootId"`
	ObservedAt         time.Time        `json:"observedAt"`
	SentAt             time.Time        `json:"sentAt"`
	DeliveryState      DeliveryState    `json:"deliveryState"`
	Events             []Event          `json:"events"`
}

func (d DeliveryState) Validate() error {
	if d.AuthBlockedSince != nil && !validUTCTime(*d.AuthBlockedSince) {
		return errors.New("deliveryState.authBlockedSince must be RFC3339 UTC")
	}
	if d.OldestObservedAt != nil && !validUTCTime(*d.OldestObservedAt) {
		return errors.New("deliveryState.oldestObservedAt must be RFC3339 UTC")
	}
	if d.AuthBlockedSince != nil && !d.AuthBlocked {
		return errors.New("deliveryState authBlockedSince requires authBlocked")
	}
	if d.LastDeliveryError != "" && d.LastDeliveryError != DeliveryErrorAuthBlocked && d.LastDeliveryError != DeliveryErrorFailed && d.LastDeliveryError != DeliveryErrorQueueCapacity {
		return errors.New("deliveryState.lastDeliveryError is not in the audit-v1 allowlist")
	}
	return nil
}

func (e Event) Validate() error {
	if !uuidRE.MatchString(e.EventID) || e.AssignmentRevision == 0 {
		return errors.New("audit event identity is invalid")
	}
	for label, value := range map[string]string{
		"commandId": e.CommandID, "idempotencyKey": e.IdempotencyKey,
		"websiteCommandKeyId": e.WebsiteCommandKeyID,
		"approvalRef":         e.ApprovalRef, "requestedByRef": e.RequestedByRef,
	} {
		if value == "" && (label == "approvalRef" || label == "requestedByRef") {
			continue
		}
		if !safeRefRE.MatchString(value) {
			return fmt.Errorf("audit event %s is invalid", label)
		}
	}
	if strings.Contains(e.RequestedByRef, "@") {
		return errors.New("audit event requestedByRef must be an opaque non-email reference")
	}
	if !actionRE.MatchString(e.Action) || !validTargetRef(e.Scope, e.TargetRef) {
		return errors.New("audit event action, scope, or targetRef is invalid")
	}
	if e.Target != nil {
		if e.Scope != "vm" || e.Target.Validate() != nil || !targetMatchesRef(*e.Target, e.TargetRef) {
			return errors.New("audit event target is invalid")
		}
	}
	if !validUTCTime(e.ReceivedAt) {
		return errors.New("audit event timing is invalid")
	}
	if e.FinishedAt != nil && (!validUTCTime(*e.FinishedAt) || e.FinishedAt.Before(e.ReceivedAt)) {
		return errors.New("audit event finishedAt is invalid")
	}
	if e.EndedAt != nil && (!validUTCTime(*e.EndedAt) || e.EndedAt.Before(e.ReceivedAt)) {
		return errors.New("audit event endedAt is invalid")
	}
	if e.EndedAt != nil && e.FinishedAt != nil && !e.EndedAt.Equal(*e.FinishedAt) {
		return errors.New("audit event endedAt and finishedAt differ")
	}
	if e.AcceptedAt != nil && (!validUTCTime(*e.AcceptedAt) || e.AcceptedAt.Before(e.ReceivedAt) ||
		e.FinishedAt != nil && e.AcceptedAt.After(*e.FinishedAt) || e.EndedAt != nil && e.AcceptedAt.After(*e.EndedAt)) {
		return errors.New("audit event acceptedAt is invalid")
	}
	if e.StartedAt != nil && (!validUTCTime(*e.StartedAt) || e.StartedAt.Before(e.ReceivedAt) ||
		e.AcceptedAt != nil && e.StartedAt.Before(*e.AcceptedAt) || e.FinishedAt != nil && e.StartedAt.After(*e.FinishedAt) ||
		e.EndedAt != nil && e.StartedAt.After(*e.EndedAt)) {
		return errors.New("audit event startedAt is invalid")
	}
	if !validOutcome(e.Outcome) || e.ErrorCode != "" && !errorCodeRE.MatchString(e.ErrorCode) {
		return errors.New("audit event outcome or errorCode is invalid")
	}
	if !validFailureStage(e.FailureStage) {
		return errors.New("audit event failureStage is invalid")
	}
	if e.UPID != "" && !digestRE.MatchString(e.UPID) {
		return errors.New("audit event UPID must be a SHA-256 digest")
	}
	if !digestRE.MatchString(e.PayloadDigest) || e.ResultDigest != "" && !digestRE.MatchString(e.ResultDigest) {
		return errors.New("audit event digest is invalid")
	}
	if e.PolicyDecision != "allowed" && e.PolicyDecision != "denied" {
		return errors.New("audit event policyDecision is invalid")
	}
	if (e.Outcome == "rejected") != (e.PolicyDecision == "denied") {
		return errors.New("audit event policyDecision does not match outcome")
	}
	if !failureStageMatchesOutcome(e.FailureStage, e.PolicyDecision, e.Outcome) {
		return errors.New("audit event failureStage does not match policy or outcome")
	}
	if !validBoundedText(e.AgentVersion, 128, false) {
		return errors.New("audit event agentVersion is invalid")
	}
	return nil
}

func (t Target) Validate() error {
	if !targetPartRE.MatchString(t.ClusterRef) || !targetPartRE.MatchString(t.NodeRef) ||
		(t.GuestType != "qemu" && t.GuestType != "lxc") || t.VMID < 1 ||
		(t.GuestName != "" && !validBoundedText(t.GuestName, 128, false)) {
		return errors.New("audit target is invalid")
	}
	return nil
}

func (t Target) MarshalJSON() ([]byte, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	type wire Target
	return json.Marshal(wire(t))
}

func (t *Target) UnmarshalJSON(raw []byte) error {
	type wire Target
	var value wire
	if err := decodeStrictObject(raw, &value); err != nil {
		return err
	}
	if err := rejectNullFields(raw, "clusterRef", "nodeRef", "guestType", "vmid", "guestName"); err != nil {
		return err
	}
	*t = Target(value)
	return t.Validate()
}

func (b Batch) Validate() error {
	if b.SchemaVersion != SchemaVersion || !uuidRE.MatchString(b.BatchID) || !safeRefRE.MatchString(b.MonitoringAgentRef) || !safeRefRE.MatchString(b.DeviceID) || b.CredentialEpoch == 0 || b.Sequence == 0 || !uuidRE.MatchString(b.BootID) {
		return errors.New("audit batch identity is invalid")
	}
	if !validUTCTime(b.ObservedAt) || !validUTCTime(b.SentAt) {
		return errors.New("audit batch timestamps must be RFC3339 UTC")
	}
	if err := b.DeliveryState.Validate(); err != nil {
		return err
	}
	if len(b.Events) < 1 || len(b.Events) > 500 {
		return errors.New("audit batch must contain 1..500 events")
	}
	seenEvents := make(map[string]struct{}, len(b.Events))
	for index := range b.Events {
		if err := b.Events[index].Validate(); err != nil {
			return fmt.Errorf("audit event[%d]: %w", index, err)
		}
		if _, duplicate := seenEvents[b.Events[index].EventID]; duplicate {
			return fmt.Errorf("audit event[%d] has a duplicate eventId", index)
		}
		seenEvents[b.Events[index].EventID] = struct{}{}
	}
	return nil
}

func (d DeliveryState) MarshalJSON() ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	type wire DeliveryState
	return json.Marshal(wire(d))
}

func (d *DeliveryState) UnmarshalJSON(raw []byte) error {
	type wire DeliveryState
	var value wire
	if err := decodeStrictObject(raw, &value); err != nil {
		return err
	}
	if err := rejectNullFields(raw, "pendingItems", "pendingBytes", "lastDeliveryError", "authBlocked", "authBlockedSince", "oldestObservedAt"); err != nil {
		return err
	}
	if err := requireUTCFields(raw, "authBlockedSince", "oldestObservedAt"); err != nil {
		return err
	}
	*d = DeliveryState(value)
	return d.Validate()
}

func (e Event) MarshalJSON() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	type wire Event
	return json.Marshal(wire(e))
}

func (e *Event) UnmarshalJSON(raw []byte) error {
	type wire Event
	var value wire
	if err := decodeStrictObject(raw, &value); err != nil {
		return err
	}
	if err := rejectNullFields(raw,
		"eventId", "assignmentRevision", "commandId", "idempotencyKey", "action", "scope", "targetRef", "target",
		"websiteCommandKeyId", "receivedAt", "acceptedAt", "startedAt", "endedAt", "finishedAt", "outcome", "errorCode",
		"failureStage", "upid", "approvalRef", "requestedByRef", "payloadDigest", "resultDigest", "policyDecision", "agentVersion"); err != nil {
		return err
	}
	if err := requireUTCFields(raw, "receivedAt", "acceptedAt", "startedAt", "endedAt", "finishedAt"); err != nil {
		return err
	}
	*e = Event(value)
	return e.Validate()
}

func (b Batch) MarshalJSON() ([]byte, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	type wire Batch
	return json.Marshal(wire(b))
}

func (b *Batch) UnmarshalJSON(raw []byte) error {
	type wire Batch
	var value wire
	if err := decodeStrictObject(raw, &value); err != nil {
		return err
	}
	if err := rejectNullFields(raw, "schemaVersion", "batchId", "monitoringAgentRef", "deviceId", "credentialEpoch", "sequence", "bootId", "observedAt", "sentAt", "deliveryState", "events"); err != nil {
		return err
	}
	if err := requireUTCFields(raw, "observedAt", "sentAt"); err != nil {
		return err
	}
	*b = Batch(value)
	return b.Validate()
}

func validOutcome(value string) bool {
	switch value {
	case "dry_run", "submitted", "waiting", "succeeded", "failed", "rolled_back", "indeterminate", "rejected":
		return true
	default:
		return false
	}
}

func validFailureStage(value string) bool {
	switch value {
	case "", "admission", "policy", "execution", "receipt":
		return true
	default:
		return false
	}
}

func failureStageMatchesOutcome(stage, policy, outcome string) bool {
	if stage == "" {
		return true // legacy audit-v1 payload
	}
	if policy == "denied" {
		return stage == "policy" && outcome == "rejected"
	}
	switch stage {
	case "admission":
		return outcome == "failed"
	case "policy":
		return false
	case "execution":
		return outcome == "failed" || outcome == "rolled_back"
	case "receipt":
		return outcome == "failed" || outcome == "indeterminate"
	default:
		return false
	}
}

func targetMatchesRef(target Target, targetRef string) bool {
	parts := strings.Split(targetRef, ":")
	return len(parts) == 5 && parts[0] == "vm" && parts[1] == target.ClusterRef && parts[2] == target.GuestType
}

func validTargetRef(scope, value string) bool {
	if !validBoundedText(value, 256, false) {
		return false
	}
	parts := strings.Split(value, ":")
	switch scope {
	case "cluster":
		return len(parts) == 2 && parts[0] == "cluster" && targetPartRE.MatchString(parts[1])
	case "node":
		return len(parts) == 3 && parts[0] == "node" && targetPartRE.MatchString(parts[1]) && targetPartRE.MatchString(parts[2])
	case "vm":
		if len(parts) != 5 || parts[0] != "vm" || !targetPartRE.MatchString(parts[1]) || (parts[2] != "qemu" && parts[2] != "lxc") || !targetPartRE.MatchString(parts[3]) {
			return false
		}
		generation, err := strconv.ParseUint(parts[4], 10, 64)
		return err == nil && generation > 0 && strconv.FormatUint(generation, 10) == parts[4]
	default:
		return false
	}
}

func validUTCTime(value time.Time) bool {
	if value.IsZero() {
		return false
	}
	_, offset := value.Zone()
	return offset == 0
}

func validBoundedText(value string, limit int, allowEmpty bool) bool {
	if len(value) > limit || (!allowEmpty && value == "") || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func decodeStrictObject(raw []byte, target any) error {
	if err := rejectDuplicateKeys(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("audit value must contain one JSON object")
	}
	return nil
}

func rejectDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return errors.New("audit value must be a JSON object")
	}
	if err := consumeObject(decoder, 1); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("audit value must contain one JSON object")
	}
	return nil
}

func consumeObject(decoder *json.Decoder, depth int) error {
	if depth > 16 {
		return errors.New("audit JSON nesting is too deep")
	}
	seen := map[string]struct{}{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("audit JSON object key is invalid")
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("duplicate audit JSON field %q", key)
		}
		seen[key] = struct{}{}
		if err := consumeValue(decoder, depth+1); err != nil {
			return err
		}
	}
	end, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := end.(json.Delim); !ok || delimiter != '}' {
		return errors.New("unterminated audit JSON object")
	}
	return nil
}

func consumeValue(decoder *json.Decoder, depth int) error {
	if depth > 16 {
		return errors.New("audit JSON nesting is too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		return consumeObject(decoder, depth)
	case '[':
		for decoder.More() {
			if err := consumeValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if close, ok := end.(json.Delim); !ok || close != ']' {
			return errors.New("unterminated audit JSON array")
		}
		return nil
	default:
		return errors.New("unexpected audit JSON delimiter")
	}
}

func requireUTCFields(raw []byte, names ...string) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return err
	}
	for _, name := range names {
		value, ok := object[name]
		if !ok || bytes.Equal(value, []byte("null")) {
			continue
		}
		var text string
		if json.Unmarshal(value, &text) != nil || !strings.HasSuffix(text, "Z") {
			return fmt.Errorf("%s must be RFC3339 UTC", name)
		}
		parsed, err := time.Parse(time.RFC3339Nano, text)
		if err != nil || parsed.UTC().Format(time.RFC3339Nano) != text {
			return fmt.Errorf("%s must be canonical RFC3339 UTC", name)
		}
	}
	return nil
}

func rejectNullFields(raw []byte, names ...string) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return err
	}
	for _, name := range names {
		if value, ok := object[name]; ok && bytes.Equal(value, []byte("null")) {
			return fmt.Errorf("%s must be omitted instead of null", name)
		}
	}
	return nil
}
