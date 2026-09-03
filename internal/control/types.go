// Package control validates signed website commands, journals idempotency and
// invokes a narrow PVE action allowlist. It never accepts arbitrary API paths
// or shell commands.
package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/ppflight/ppflight-agent/internal/inventory"
	"github.com/ppflight/ppflight-agent/internal/protocol"
)

const SchemaVersion = 1

const (
	ScopeCluster = "cluster"
	ScopeNode    = "node"
	ScopeVM      = "vm"
)

var (
	commandIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	uuidRE      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	actionRE    = regexp.MustCompile(`^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+$`)
	bodyHashRE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ErrCommandAuthorityMismatch identifies a correctly signed command which is
// not addressed to the active mutual binding, credential epoch, device, or
// assignment revision. Callers may safely emit a denied audit event for this
// class because the signature has already been verified.
var (
	ErrCommandAuthorityMismatch = errors.New("command authority does not match active binding")
	// ErrAuthenticatedPolicy marks a command whose website signature was valid
	// but which local authority, freshness, allowlist, target, or parameter
	// policy rejected. These rejections are safe to project as denied audits.
	ErrAuthenticatedPolicy = errors.New("authenticated command was denied by policy")
)

type actionSpec struct {
	scopes   map[string]bool
	readOnly bool
}

// protocolActions is the protocol-level allowlist. Deployment configuration
// may narrow this list, but it must never be able to add an arbitrary action.
// Keeping scope and read/write classification together makes approval checks
// fail closed when a new action is introduced.
var protocolActions = map[string]actionSpec{
	"pve.discover":                        {scopes: map[string]bool{ScopeCluster: true, ScopeNode: true}, readOnly: true},
	"task.status":                         {scopes: map[string]bool{ScopeNode: true}, readOnly: true},
	"vm.start":                            {scopes: map[string]bool{ScopeVM: true}},
	"vm.shutdown":                         {scopes: map[string]bool{ScopeVM: true}},
	"vm.stop":                             {scopes: map[string]bool{ScopeVM: true}},
	"vm.reboot":                           {scopes: map[string]bool{ScopeVM: true}},
	"vm.create":                           {scopes: map[string]bool{ScopeVM: true}},
	"vm.clone":                            {scopes: map[string]bool{ScopeVM: true}},
	"vm.set-initial-resources":            {scopes: map[string]bool{ScopeVM: true}},
	"vm.migrate-legacy-journal":           {scopes: map[string]bool{ScopeVM: true}},
	"vm.reinstall":                        {scopes: map[string]bool{ScopeVM: true}},
	"vm.set-resources":                    {scopes: map[string]bool{ScopeVM: true}},
	"vm.resize":                           {scopes: map[string]bool{ScopeVM: true}},
	"vm.set-disk-io":                      {scopes: map[string]bool{ScopeVM: true}},
	"vm.set-network":                      {scopes: map[string]bool{ScopeVM: true}},
	"vm.set-rate":                         {scopes: map[string]bool{ScopeVM: true}},
	"vm.set-cloud-init":                   {scopes: map[string]bool{ScopeVM: true}},
	"vm.set-timezone":                     {scopes: map[string]bool{ScopeVM: true}},
	"vm.verify-delivery":                  {scopes: map[string]bool{ScopeVM: true}, readOnly: true},
	"vm.delete":                           {scopes: map[string]bool{ScopeVM: true}},
	"vm.reset-password":                   {scopes: map[string]bool{ScopeVM: true}},
	"vm.suspend":                          {scopes: map[string]bool{ScopeVM: true}},
	"vm.resume":                           {scopes: map[string]bool{ScopeVM: true}},
	"vm.console.create-session":           {scopes: map[string]bool{ScopeVM: true}},
	"vm.console.revoke-session":           {scopes: map[string]bool{ScopeVM: true}},
	"snapshot.create":                     {scopes: map[string]bool{ScopeVM: true}},
	"snapshot.delete":                     {scopes: map[string]bool{ScopeVM: true}},
	"snapshot.rollback":                   {scopes: map[string]bool{ScopeVM: true}},
	"snapshot.list":                       {scopes: map[string]bool{ScopeVM: true}, readOnly: true},
	"snapshot.get":                        {scopes: map[string]bool{ScopeVM: true}, readOnly: true},
	"backup.create":                       {scopes: map[string]bool{ScopeVM: true}},
	"backup.delete":                       {scopes: map[string]bool{ScopeVM: true}},
	"backup.restore":                      {scopes: map[string]bool{ScopeVM: true}},
	"backup.list":                         {scopes: map[string]bool{ScopeVM: true}, readOnly: true},
	"backup.get":                          {scopes: map[string]bool{ScopeVM: true}, readOnly: true},
	"firewall.cluster.set-options":        {scopes: map[string]bool{ScopeCluster: true}},
	"firewall.node.set-options":           {scopes: map[string]bool{ScopeNode: true}},
	"firewall.guest.set-options":          {scopes: map[string]bool{ScopeVM: true}},
	"firewall.guest.verify-ipfilter":      {scopes: map[string]bool{ScopeVM: true}, readOnly: true},
	"firewall.guest.verify-ipfilter-sets": {scopes: map[string]bool{ScopeVM: true}, readOnly: true},
	"firewall.guest.rules.list":           {scopes: map[string]bool{ScopeVM: true}, readOnly: true},
	"firewall.guest.rules.get":            {scopes: map[string]bool{ScopeVM: true}, readOnly: true},
	"firewall.guest.rules.verify":         {scopes: map[string]bool{ScopeVM: true}, readOnly: true},
	"firewall.rule.create":                {scopes: map[string]bool{ScopeVM: true}},
	"firewall.rule.update":                {scopes: map[string]bool{ScopeVM: true}},
	"firewall.rule.delete":                {scopes: map[string]bool{ScopeVM: true}},
	"firewall.ipset.create":               {scopes: map[string]bool{ScopeVM: true}},
	"firewall.ipset.update":               {scopes: map[string]bool{ScopeVM: true}},
	"firewall.ipset.delete":               {scopes: map[string]bool{ScopeVM: true}},
	"firewall.ipset.entry.create":         {scopes: map[string]bool{ScopeVM: true}},
	"firewall.ipset.entry.update":         {scopes: map[string]bool{ScopeVM: true}},
	"firewall.ipset.entry.delete":         {scopes: map[string]bool{ScopeVM: true}},
	"agent.upgrade":                       {scopes: map[string]bool{ScopeNode: true}},
}

// KnownAction exposes the single protocol registry to configuration validation.
// Runtime allowlists may narrow this set, but cannot invent actions.
func KnownAction(action string) bool {
	_, ok := protocolActions[action]
	return ok
}

type Identity struct {
	ServiceRef   string `json:"serviceRef"`
	ClusterRef   string `json:"clusterRef"`
	NodeRef      string `json:"nodeRef"`
	VMID         int    `json:"vmid"`
	Generation   uint64 `json:"generation"`
	InstanceUUID string `json:"instanceUuid"`
	GuestType    string `json:"guestType"`
}

type Command struct {
	SchemaVersion int    `json:"schemaVersion"`
	CommandID     string `json:"commandId"`
	// OperationID is the unique control-plane operation represented by this
	// command. Retries keep both OperationID and CommandID; related operations
	// are linked only through typed fields such as cloneOperationId.
	OperationID        string           `json:"operationId,omitempty"`
	IdempotencyKey     string           `json:"idempotencyKey"`
	AgentRef           string           `json:"agentRef"`
	BindingID          string           `json:"bindingId"`
	DeviceID           string           `json:"deviceId"`
	CredentialEpoch    protocol.Counter `json:"credentialEpoch"`
	AssignmentRevision protocol.Counter `json:"assignmentRevision"`
	SigningKeyID       string           `json:"signingKeyId"`
	Scope              string           `json:"scope"`
	IssuedAt           time.Time        `json:"issuedAt"`
	ExpiresAt          time.Time        `json:"expiresAt"`
	Identity           Identity         `json:"identity"`
	Action             string           `json:"action"`
	Parameters         json.RawMessage  `json:"parameters"`
	OperatorRef        string           `json:"operatorRef"`
	ApprovalRef        string           `json:"approvalRef,omitempty"`
	BodySHA256         string           `json:"bodySha256"`
	Signature          string           `json:"signature"`
}

// UnmarshalJSON keeps Command strict even when it is decoded outside Client.
// Unknown or duplicate envelope/identity fields are rejected before signature
// verification, while action-specific parameter fields are checked later by
// validateParameters.
func (c *Command) UnmarshalJSON(raw []byte) error {
	if err := validateJSONObject(raw); err != nil {
		return err
	}
	type wireCommand Command
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value wireCommand
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("command must contain one JSON object")
	}
	*c = Command(value)
	return nil
}

type Receipt struct {
	SchemaVersion  int       `json:"schemaVersion"`
	ReceiptID      string    `json:"receiptId"`
	CommandID      string    `json:"commandId"`
	OperationID    string    `json:"operationId,omitempty"`
	AgentRef       string    `json:"agentRef"`
	State          string    `json:"state"`
	Code           string    `json:"code"`
	ExecutionMode  string    `json:"executionMode"`
	DryRun         bool      `json:"dryRun"`
	StartedAt      time.Time `json:"startedAt"`
	FinishedAt     time.Time `json:"finishedAt"`
	PVETaskUPID    string    `json:"pveTaskUpid,omitempty"`
	AgentUpgradeID string    `json:"agentUpgradeId,omitempty"`
	// These fields are additive compatibility signals for consumers which
	// cannot yet interpret the finer-grained State/Code pair.
	Accepted                 bool            `json:"accepted,omitempty"`
	Asynchronous             bool            `json:"asynchronous,omitempty"`
	MutationMayHaveSucceeded bool            `json:"mutationMayHaveSucceeded,omitempty"`
	OperatorRef              string          `json:"operatorRef,omitempty"`
	Result                   json.RawMessage `json:"result,omitempty"`
}

type VerifyConfig struct {
	AgentRef   string
	ClusterRef string
	// These values form the local side of the mutual binding gate. Production
	// accepts a command only when every signed value matches the active state.
	BindingID          string
	DeviceID           string
	CredentialEpoch    uint64
	AssignmentRevision func() uint64
	// SigningKeyID and PublicKey are the production command-verification
	// credential. PublicKey is the raw 32-byte Ed25519 public key.
	SigningKeyID string
	PublicKey    ed25519.PublicKey
	// Mode is only used to keep the HMAC helper available to hermetic tests.
	// Production verification never falls back to Secret.
	Mode         string
	Secret       []byte
	Allowed      map[string]bool
	Assignments  *inventory.Store
	Now          time.Time
	MaxClockSkew time.Duration
	MaxLifetime  time.Duration
}

func Verify(command Command, cfg VerifyConfig) error {
	// Only exact-body hash and signature failures happen before authentication.
	// Everything after verifySignature is a local policy decision and is tagged
	// so the service can emit a denied audit without auditing unauthenticated
	// internet input.
	if len(command.Parameters) == 0 || !json.Valid(command.Parameters) || !bodyHashRE.MatchString(command.BodySHA256) || protocol.BodyHash(command.Parameters) != command.BodySHA256 {
		return errors.New("command parameter hash is invalid")
	}
	if err := verifySignature(command, cfg); err != nil {
		return errors.New("command signature is invalid")
	}
	deny := func(err error) error { return fmt.Errorf("%w: %w", ErrAuthenticatedPolicy, err) }
	if command.SchemaVersion != SchemaVersion || !commandIDRE.MatchString(command.CommandID) || !commandIDRE.MatchString(command.OperationID) || command.AgentRef != cfg.AgentRef || !actionRE.MatchString(command.Action) || !commandIDRE.MatchString(command.OperatorRef) {
		return deny(errors.New("invalid command envelope"))
	}
	authorityPresent := command.BindingID != "" || command.DeviceID != "" || command.CredentialEpoch != 0 || command.AssignmentRevision != 0 || command.IdempotencyKey != ""
	if authorityPresent && (!uuidRE.MatchString(command.BindingID) || !commandIDRE.MatchString(command.DeviceID) || command.CredentialEpoch == 0 || command.AssignmentRevision == 0 || !commandIDRE.MatchString(command.IdempotencyKey)) {
		return deny(errors.New("invalid command authority envelope"))
	}
	if cfg.Mode != "test" && !authorityPresent {
		return deny(errors.New("production command authority envelope is required"))
	}
	if command.SigningKeyID != "" && !commandIDRE.MatchString(command.SigningKeyID) {
		return deny(errors.New("invalid command signing key ID"))
	}
	if command.ApprovalRef != "" && !commandIDRE.MatchString(command.ApprovalRef) {
		return deny(errors.New("invalid command approval reference"))
	}
	if _, ok := protocolActions[command.Action]; !ok {
		return deny(errors.New("command action is not part of the control protocol"))
	}
	if !cfg.Allowed[command.Action] {
		return deny(errors.New("command action is not allowed"))
	}
	now := cfg.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	skew := cfg.MaxClockSkew
	if skew == 0 {
		skew = 5 * time.Minute
	}
	lifetime := cfg.MaxLifetime
	if lifetime == 0 {
		lifetime = 15 * time.Minute
	}
	if command.IssuedAt.IsZero() || command.ExpiresAt.IsZero() || !command.ExpiresAt.After(command.IssuedAt) || command.IssuedAt.After(now.Add(skew)) || command.IssuedAt.Before(now.Add(-lifetime)) || !command.ExpiresAt.After(now) || command.ExpiresAt.Sub(command.IssuedAt) > lifetime {
		return deny(errors.New("command is expired or outside the allowed clock window"))
	}
	if err := verifyAuthority(command, cfg); err != nil {
		return deny(err)
	}
	if err := verifyScope(command, cfg); err != nil {
		return deny(err)
	}
	if err := validateParameters(command); err != nil {
		return deny(fmt.Errorf("command parameters are invalid: %w", err))
	}
	if requiresApproval(command.Action) && strings.TrimSpace(command.ApprovalRef) == "" {
		return deny(errors.New("high-risk command requires approvalRef"))
	}
	return nil
}

func verifyAuthority(command Command, cfg VerifyConfig) error {
	configured := cfg.BindingID != "" || cfg.DeviceID != "" || cfg.CredentialEpoch != 0 || cfg.AssignmentRevision != nil
	if cfg.Mode == "test" && !configured {
		return nil
	}
	if !uuidRE.MatchString(cfg.BindingID) || !commandIDRE.MatchString(cfg.DeviceID) || cfg.CredentialEpoch == 0 || cfg.AssignmentRevision == nil {
		return fmt.Errorf("%w: local authority is unavailable", ErrCommandAuthorityMismatch)
	}
	revision := cfg.AssignmentRevision()
	if revision == 0 || command.BindingID != cfg.BindingID || command.DeviceID != cfg.DeviceID || uint64(command.CredentialEpoch) != cfg.CredentialEpoch || uint64(command.AssignmentRevision) != revision {
		return ErrCommandAuthorityMismatch
	}
	return nil
}

func verifyScope(command Command, cfg VerifyConfig) error {
	if command.Identity.ClusterRef != cfg.ClusterRef {
		return errors.New("command cluster is invalid")
	}
	switch command.Scope {
	case ScopeCluster:
		if !validActionScope(command.Action, command.Scope) || command.Identity.NodeRef != "" || command.Identity.VMID != 0 || command.Identity.Generation != 0 || command.Identity.ServiceRef != "" || command.Identity.InstanceUUID != "" || command.Identity.GuestType != "" {
			return errors.New("command cluster scope is invalid")
		}
	case ScopeNode:
		if !validActionScope(command.Action, command.Scope) || !nodeRE.MatchString(command.Identity.NodeRef) || command.Identity.VMID != 0 || command.Identity.Generation != 0 || command.Identity.ServiceRef != "" || command.Identity.InstanceUUID != "" || command.Identity.GuestType != "" {
			return errors.New("command node scope is invalid")
		}
	case ScopeVM:
		if !validActionScope(command.Action, command.Scope) || command.Identity.VMID < 1 || command.Identity.Generation == 0 || (command.Identity.GuestType != "qemu" && command.Identity.GuestType != "lxc") || !nodeRE.MatchString(command.Identity.NodeRef) || !commandIDRE.MatchString(command.Identity.ServiceRef) || !commandIDRE.MatchString(command.Identity.InstanceUUID) {
			return errors.New("command VM target is invalid")
		}
		if cfg.Assignments == nil {
			return errors.New("command inventory is unavailable")
		}
		assignment, ok := cfg.Assignments.Lookup(command.Identity.ClusterRef, command.Identity.GuestType, command.Identity.VMID)
		if !ok || assignment.ServiceRef != command.Identity.ServiceRef || assignment.InstanceUUID != command.Identity.InstanceUUID || assignment.Generation != command.Identity.Generation || (assignment.NodeRef != "" && assignment.NodeRef != command.Identity.NodeRef) {
			return errors.New("command identity does not match current assignment")
		}
	default:
		return errors.New("command scope is invalid")
	}
	return nil
}

func validActionScope(action, scope string) bool {
	spec, ok := protocolActions[action]
	return ok && spec.scopes[scope]
}

func clusterAction(action string) bool {
	return validActionScope(action, ScopeCluster)
}
func nodeAction(action string) bool {
	return validActionScope(action, ScopeNode)
}
func vmAction(action string) bool {
	return validActionScope(action, ScopeVM)
}

func verifySignature(command Command, cfg VerifyConfig) error {
	if cfg.Mode == "test" && len(cfg.PublicKey) == 0 {
		if len(cfg.Secret) == 0 {
			return errors.New("test signing secret is unavailable")
		}
		provided, err := hex.DecodeString(command.Signature)
		if err != nil || hex.EncodeToString(provided) != command.Signature {
			return errors.New("invalid test HMAC encoding")
		}
		expected, _ := hex.DecodeString(SignCommand(command, cfg.Secret))
		if !hmac.Equal(provided, expected) {
			return errors.New("invalid test HMAC")
		}
		return nil
	}
	if cfg.SigningKeyID == "" || command.SigningKeyID != cfg.SigningKeyID || len(cfg.PublicKey) != ed25519.PublicKeySize {
		return errors.New("Ed25519 verification key is unavailable")
	}
	provided, err := base64.StdEncoding.Strict().DecodeString(command.Signature)
	if err != nil || base64.StdEncoding.EncodeToString(provided) != command.Signature || len(provided) != ed25519.SignatureSize {
		return errors.New("invalid Ed25519 signature encoding")
	}
	payload, err := CanonicalCommandBody(command)
	if err != nil || !ed25519.Verify(cfg.PublicKey, payload, provided) {
		return errors.New("invalid Ed25519 signature")
	}
	return nil
}

func SignCommand(command Command, secret []byte) string {
	canonical, err := CanonicalCommandBody(command)
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(canonical)
	return hex.EncodeToString(mac.Sum(nil))
}

// SignCommandEd25519 returns the canonical production signature. It is useful
// to control-plane implementations and test fixtures; agents only verify it.
func SignCommandEd25519(command Command, privateKey ed25519.PrivateKey) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", errors.New("invalid Ed25519 private key")
	}
	payload, err := CanonicalCommandBody(command)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)), nil
}

// CanonicalCommandBody is the complete unsigned command body used for both
// Ed25519 verification and idempotency. Parameters remain embedded as JSON and
// are also independently bound by bodySha256. A struct (rather than a map or a
// delimiter-joined string) gives every field an unambiguous name and order.
func CanonicalCommandBody(command Command) ([]byte, error) {
	if len(command.Parameters) == 0 || !json.Valid(command.Parameters) {
		return nil, errors.New("command parameters are not valid JSON")
	}
	body := struct {
		SchemaVersion      int              `json:"schemaVersion"`
		CommandID          string           `json:"commandId"`
		OperationID        string           `json:"operationId"`
		IdempotencyKey     string           `json:"idempotencyKey"`
		AgentRef           string           `json:"agentRef"`
		BindingID          string           `json:"bindingId"`
		DeviceID           string           `json:"deviceId"`
		CredentialEpoch    protocol.Counter `json:"credentialEpoch"`
		AssignmentRevision protocol.Counter `json:"assignmentRevision"`
		SigningKeyID       string           `json:"signingKeyId"`
		Scope              string           `json:"scope"`
		IssuedAt           time.Time        `json:"issuedAt"`
		ExpiresAt          time.Time        `json:"expiresAt"`
		Identity           Identity         `json:"identity"`
		Action             string           `json:"action"`
		Parameters         json.RawMessage  `json:"parameters"`
		OperatorRef        string           `json:"operatorRef"`
		ApprovalRef        string           `json:"approvalRef"`
		BodySHA256         string           `json:"bodySha256"`
	}{
		SchemaVersion: command.SchemaVersion, CommandID: command.CommandID, OperationID: command.OperationID,
		IdempotencyKey: command.IdempotencyKey, AgentRef: command.AgentRef, BindingID: command.BindingID,
		DeviceID: command.DeviceID, CredentialEpoch: command.CredentialEpoch, AssignmentRevision: command.AssignmentRevision,
		SigningKeyID: command.SigningKeyID, Scope: command.Scope,
		IssuedAt: command.IssuedAt.UTC(), ExpiresAt: command.ExpiresAt.UTC(), Identity: command.Identity,
		Action: command.Action, Parameters: command.Parameters, OperatorRef: command.OperatorRef,
		ApprovalRef: command.ApprovalRef, BodySHA256: command.BodySHA256,
	}
	return json.Marshal(body)
}

func Digest(command Command) string {
	raw, err := CanonicalCommandBody(command)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

// AuditReceiptDigest hashes the canonical safe receipt projection. Result is
// deliberately excluded: it may contain an upstream response body and must
// never become part of the monitoring audit event or its canonical contract.
func AuditReceiptDigest(receipt Receipt) (string, error) {
	ApplyReceiptCompatibility(&receipt)
	body := struct {
		SchemaVersion            int       `json:"schemaVersion"`
		ReceiptID                string    `json:"receiptId"`
		CommandID                string    `json:"commandId"`
		OperationID              string    `json:"operationId"`
		AgentRef                 string    `json:"agentRef"`
		State                    string    `json:"state"`
		Code                     string    `json:"code"`
		ExecutionMode            string    `json:"executionMode"`
		DryRun                   bool      `json:"dryRun"`
		StartedAt                time.Time `json:"startedAt"`
		FinishedAt               time.Time `json:"finishedAt"`
		PVETaskUPID              string    `json:"pveTaskUpid"`
		AgentUpgradeID           string    `json:"agentUpgradeId"`
		Accepted                 bool      `json:"accepted"`
		Asynchronous             bool      `json:"asynchronous"`
		MutationMayHaveSucceeded bool      `json:"mutationMayHaveSucceeded"`
		OperatorRef              string    `json:"operatorRef"`
	}{
		SchemaVersion: receipt.SchemaVersion, ReceiptID: receipt.ReceiptID, CommandID: receipt.CommandID,
		OperationID: receipt.OperationID, AgentRef: receipt.AgentRef, State: receipt.State, Code: receipt.Code,
		ExecutionMode: receipt.ExecutionMode, DryRun: receipt.DryRun, StartedAt: receipt.StartedAt.UTC(),
		FinishedAt: receipt.FinishedAt.UTC(), PVETaskUPID: receipt.PVETaskUPID, AgentUpgradeID: receipt.AgentUpgradeID, Accepted: receipt.Accepted,
		Asynchronous: receipt.Asynchronous, MutationMayHaveSucceeded: receipt.MutationMayHaveSucceeded,
		OperatorRef: receipt.OperatorRef,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func requiresApproval(action string) bool {
	spec, ok := protocolActions[action]
	return !ok || !spec.readOnly
}

func AllowedSet(actions []string) map[string]bool {
	result := make(map[string]bool, len(actions))
	for _, action := range actions {
		result[action] = true
	}
	return result
}

func SafeRejection(command Command, code string, now time.Time, mode string) (Receipt, error) {
	id, err := protocol.NewID()
	if err != nil {
		return Receipt{}, err
	}
	return Receipt{SchemaVersion: SchemaVersion, ReceiptID: id, CommandID: command.CommandID, OperationID: command.OperationID, AgentRef: command.AgentRef, State: "rejected", Code: code, ExecutionMode: mode, DryRun: mode != "production", StartedAt: now.UTC(), FinishedAt: now.UTC(), OperatorRef: command.OperatorRef}, nil
}

// ApplyReceiptCompatibility supplies the additive receipt fields for receipts
// produced by older Executor implementations as well as the current one.
func ApplyReceiptCompatibility(r *Receipt) {
	r.Accepted = false
	r.Asynchronous = false
	r.MutationMayHaveSucceeded = r.State == "indeterminate"
	switch r.State {
	case "submitted", "waiting":
		r.Accepted = true
		r.Asynchronous = true
	case "succeeded":
		r.Accepted = true
	case "failed":
		r.Accepted = r.PVETaskUPID != "" || r.AgentUpgradeID != ""
	}
	if (r.PVETaskUPID != "" || r.AgentUpgradeID != "") && r.Accepted {
		r.Asynchronous = true
	}
}

func (r Receipt) Validate() error {
	if r.SchemaVersion != SchemaVersion || r.ReceiptID == "" || r.CommandID == "" || r.AgentRef == "" || r.State == "" || r.Code == "" || r.StartedAt.IsZero() || r.FinishedAt.IsZero() {
		return fmt.Errorf("invalid control receipt")
	}
	if !commandIDRE.MatchString(r.ReceiptID) || !commandIDRE.MatchString(r.CommandID) || (r.OperationID != "" && !commandIDRE.MatchString(r.OperationID)) || (r.State != "rejected" && !commandIDRE.MatchString(r.OperationID)) {
		return fmt.Errorf("invalid control receipt identity")
	}
	if r.PVETaskUPID != "" && !upidRE.MatchString(r.PVETaskUPID) {
		return fmt.Errorf("invalid control receipt PVE task UPID")
	}
	if r.AgentUpgradeID != "" && !commandIDRE.MatchString(r.AgentUpgradeID) {
		return fmt.Errorf("invalid control receipt agent upgrade ID")
	}
	if r.ExecutionMode != "test" && r.ExecutionMode != "production" || r.FinishedAt.Before(r.StartedAt) {
		return fmt.Errorf("invalid control receipt timing or mode")
	}
	switch r.State {
	case "dry_run":
		if !r.DryRun {
			return fmt.Errorf("dry-run receipt is missing dryRun=true")
		}
	case "submitted", "waiting":
		if (r.PVETaskUPID == "") == (r.AgentUpgradeID == "") {
			return fmt.Errorf("asynchronous receipt must identify exactly one task")
		}
	case "succeeded", "failed", "indeterminate", "rejected":
	default:
		return fmt.Errorf("invalid control receipt state")
	}
	return nil
}
