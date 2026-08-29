// Package control validates signed website commands, journals idempotency and
// invokes a narrow PVE action allowlist. It never accepts arbitrary API paths
// or shell commands.
package control

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ppflight/ppflight-agent/internal/inventory"
	"github.com/ppflight/ppflight-agent/internal/protocol"
)

const SchemaVersion = 1

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
	SchemaVersion int             `json:"schemaVersion"`
	CommandID     string          `json:"commandId"`
	AgentRef      string          `json:"agentRef"`
	IssuedAt      time.Time       `json:"issuedAt"`
	ExpiresAt     time.Time       `json:"expiresAt"`
	Identity      Identity        `json:"identity"`
	Action        string          `json:"action"`
	Parameters    json.RawMessage `json:"parameters"`
	OperatorRef   string          `json:"operatorRef"`
	ApprovalRef   string          `json:"approvalRef,omitempty"`
	BodySHA256    string          `json:"bodySha256"`
	Signature     string          `json:"signature"`
}

type Receipt struct {
	SchemaVersion int             `json:"schemaVersion"`
	ReceiptID     string          `json:"receiptId"`
	CommandID     string          `json:"commandId"`
	AgentRef      string          `json:"agentRef"`
	State         string          `json:"state"`
	Code          string          `json:"code"`
	ExecutionMode string          `json:"executionMode"`
	DryRun        bool            `json:"dryRun"`
	StartedAt     time.Time       `json:"startedAt"`
	FinishedAt    time.Time       `json:"finishedAt"`
	PVETaskUPID   string          `json:"pveTaskUpid,omitempty"`
	OperatorRef   string          `json:"operatorRef,omitempty"`
	Result        json.RawMessage `json:"result,omitempty"`
}

type VerifyConfig struct {
	AgentRef     string
	ClusterRef   string
	Secret       []byte
	Allowed      map[string]bool
	Assignments  *inventory.Store
	Now          time.Time
	MaxClockSkew time.Duration
	MaxLifetime  time.Duration
}

func Verify(command Command, cfg VerifyConfig) error {
	if command.SchemaVersion != SchemaVersion || command.CommandID == "" || command.AgentRef != cfg.AgentRef || command.Action == "" || command.OperatorRef == "" {
		return errors.New("invalid command envelope")
	}
	if !cfg.Allowed[command.Action] {
		return errors.New("command action is not allowed")
	}
	if command.Identity.ClusterRef != cfg.ClusterRef || command.Identity.VMID < 1 || command.Identity.Generation == 0 || (command.Identity.GuestType != "qemu" && command.Identity.GuestType != "lxc") {
		return errors.New("command target is invalid")
	}
	if cfg.Assignments == nil {
		return errors.New("command inventory is unavailable")
	}
	assignment, ok := cfg.Assignments.Lookup(command.Identity.ClusterRef, command.Identity.GuestType, command.Identity.VMID)
	if !ok || assignment.ServiceRef != command.Identity.ServiceRef || assignment.InstanceUUID != command.Identity.InstanceUUID || assignment.Generation != command.Identity.Generation || (assignment.NodeRef != "" && assignment.NodeRef != command.Identity.NodeRef) {
		return errors.New("command identity does not match current assignment")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`).MatchString(command.Identity.NodeRef) {
		return errors.New("command nodeRef is invalid")
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
	if command.IssuedAt.IsZero() || command.ExpiresAt.IsZero() || command.IssuedAt.After(now.Add(skew)) || command.IssuedAt.Before(now.Add(-lifetime)) || !command.ExpiresAt.After(now) || command.ExpiresAt.Sub(command.IssuedAt) > lifetime {
		return errors.New("command is expired or outside the allowed clock window")
	}
	if len(command.Parameters) == 0 || !json.Valid(command.Parameters) || protocol.BodyHash(command.Parameters) != strings.ToLower(command.BodySHA256) {
		return errors.New("command parameter hash is invalid")
	}
	if len(cfg.Secret) == 0 {
		return errors.New("command verification secret is unavailable")
	}
	expected := SignCommand(command, cfg.Secret)
	provided, err := hex.DecodeString(strings.ToLower(command.Signature))
	if err != nil {
		return errors.New("command signature is invalid")
	}
	expectedBytes, _ := hex.DecodeString(expected)
	if !hmac.Equal(provided, expectedBytes) {
		return errors.New("command signature is invalid")
	}
	if requiresApproval(command.Action) && strings.TrimSpace(command.ApprovalRef) == "" {
		return errors.New("high-risk command requires approvalRef")
	}
	return nil
}

func SignCommand(command Command, secret []byte) string {
	canonical := strings.Join([]string{
		strconv.Itoa(command.SchemaVersion), command.CommandID, command.AgentRef,
		command.IssuedAt.UTC().Format(time.RFC3339Nano), command.ExpiresAt.UTC().Format(time.RFC3339Nano),
		command.Identity.ServiceRef, command.Identity.ClusterRef, command.Identity.NodeRef,
		strconv.Itoa(command.Identity.VMID), strconv.FormatUint(command.Identity.Generation, 10),
		command.Identity.InstanceUUID, command.Identity.GuestType, command.Action,
		command.OperatorRef, command.ApprovalRef, strings.ToLower(command.BodySHA256),
	}, "\n")
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

func Digest(command Command) string {
	value := command
	value.Signature = ""
	raw, _ := json.Marshal(value)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func requiresApproval(action string) bool {
	switch action {
	case "vm.stop", "vm.create", "vm.clone", "vm.resize", "vm.delete", "vm.set-rate", "vm.reset-password":
		return true
	default:
		return false
	}
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
	return Receipt{SchemaVersion: SchemaVersion, ReceiptID: id, CommandID: command.CommandID, AgentRef: command.AgentRef, State: "rejected", Code: code, ExecutionMode: mode, DryRun: mode != "production", StartedAt: now.UTC(), FinishedAt: now.UTC(), OperatorRef: command.OperatorRef}, nil
}

func (r Receipt) Validate() error {
	if r.SchemaVersion != SchemaVersion || r.ReceiptID == "" || r.CommandID == "" || r.AgentRef == "" || r.State == "" || r.Code == "" || r.StartedAt.IsZero() || r.FinishedAt.IsZero() {
		return fmt.Errorf("invalid control receipt")
	}
	if r.ExecutionMode != "test" && r.ExecutionMode != "production" || r.FinishedAt.Before(r.StartedAt) {
		return fmt.Errorf("invalid control receipt timing or mode")
	}
	switch r.State {
	case "dry_run":
		if !r.DryRun {
			return fmt.Errorf("dry-run receipt is missing dryRun=true")
		}
	case "submitted":
		if r.PVETaskUPID == "" {
			return fmt.Errorf("submitted receipt is missing PVE task UPID")
		}
	case "succeeded", "failed", "indeterminate", "rejected":
	default:
		return fmt.Errorf("invalid control receipt state")
	}
	return nil
}
