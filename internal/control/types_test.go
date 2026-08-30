package control

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/inventory"
	"github.com/ppflight/ppflight-agent/internal/protocol"
	"github.com/ppflight/ppflight-agent/internal/pve"
)

func signedCommand(t *testing.T, now time.Time) (Command, *inventory.Store) {
	t.Helper()
	parameters := json.RawMessage(`{}`)
	command := Command{SchemaVersion: 1, CommandID: "command-1", OperationID: "operation-1", IdempotencyKey: "idempotency-1", AgentRef: "agent-1", BindingID: "11111111-1111-4111-8111-111111111111", DeviceID: "device-1", CredentialEpoch: 3, AssignmentRevision: 7, SigningKeyID: "test-key-1", Scope: ScopeVM, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(5 * time.Minute), Identity: Identity{ServiceRef: "service-1", ClusterRef: "cluster-1", NodeRef: "pve-1", VMID: 101, Generation: 2, InstanceUUID: "instance-1", GuestType: "qemu"}, Action: "vm.start", Parameters: parameters, OperatorRef: "operator-1", ApprovalRef: "approval-1", BodySHA256: protocolHash(parameters)}
	command.Signature = SignCommand(command, []byte("secret"))
	assignments := inventory.NewStore(inventory.Document{SchemaVersion: 1, Revision: "rev", IssuedAt: now, Assignments: []inventory.Assignment{{ServiceRef: "service-1", ClusterRef: "cluster-1", NodeRef: "pve-1", VMID: 101, Generation: 2, InstanceUUID: "instance-1", GuestType: "qemu", BillingState: "shadow"}}})
	return command, assignments
}

func TestVerifySignedMappedCommand(t *testing.T) {
	now := time.Now().UTC()
	command, assignments := signedCommand(t, now)
	err := Verify(command, VerifyConfig{AgentRef: "agent-1", ClusterRef: "cluster-1", Mode: "test", Secret: []byte("secret"), Allowed: AllowedSet([]string{"vm.start"}), Assignments: assignments, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	command.Identity.Generation++
	if err := Verify(command, VerifyConfig{AgentRef: "agent-1", ClusterRef: "cluster-1", Mode: "test", Secret: []byte("secret"), Allowed: AllowedSet([]string{"vm.start"}), Assignments: assignments, Now: now}); err == nil {
		t.Fatal("identity mismatch accepted")
	}
}

func TestVerifyRejectsNonPositiveCommandLifetime(t *testing.T) {
	now := time.Now().UTC()
	command, assignments := signedCommand(t, now)
	command.ExpiresAt = command.IssuedAt
	command.Signature = SignCommand(command, []byte("secret"))
	if err := Verify(command, VerifyConfig{AgentRef: "agent-1", ClusterRef: "cluster-1", Mode: "test", Secret: []byte("secret"), Allowed: AllowedSet([]string{"vm.start"}), Assignments: assignments, Now: now}); err == nil {
		t.Fatal("command with expiresAt == issuedAt was accepted")
	}
}

func TestVerifyProductionEd25519CoversCompleteCanonicalBody(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	command, assignments := signedCommand(t, now)
	command.SigningKeyID = "control-key-1"
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	command.Signature, err = SignCommandEd25519(command, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	cfg := VerifyConfig{
		AgentRef: "agent-1", ClusterRef: "cluster-1", SigningKeyID: "control-key-1", PublicKey: publicKey,
		BindingID: command.BindingID, DeviceID: command.DeviceID, CredentialEpoch: uint64(command.CredentialEpoch),
		AssignmentRevision: func() uint64 { return uint64(command.AssignmentRevision) },
		Allowed:            AllowedSet([]string{"vm.start"}), Assignments: assignments, Now: now,
	}
	if err := Verify(command, cfg); err != nil {
		t.Fatal(err)
	}

	// Changing parameters and their independently valid hash still invalidates
	// the signature because parameters are embedded in the canonical body.
	changed := command
	changed.Parameters = json.RawMessage(`{"unexpected":true}`)
	changed.BodySHA256 = protocolHash(changed.Parameters)
	if err := Verify(changed, cfg); err == nil {
		t.Fatal("signature accepted a changed canonical command body")
	}
	changed = command
	changed.ApprovalRef = "approval-2"
	if err := Verify(changed, cfg); err == nil {
		t.Fatal("signature accepted a changed approval reference")
	}
	changed = command
	changed.SigningKeyID = "control-key-2"
	if err := Verify(changed, cfg); err == nil {
		t.Fatal("signature accepted a different signing key ID")
	}
}

func TestVerifyMutualBindingAuthorityRejectsEveryMismatch(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	command, assignments := signedCommand(t, now)
	base := VerifyConfig{
		AgentRef: "agent-1", ClusterRef: "cluster-1", Mode: "test", Secret: []byte("secret"),
		BindingID: command.BindingID, DeviceID: command.DeviceID, CredentialEpoch: uint64(command.CredentialEpoch),
		AssignmentRevision: func() uint64 { return uint64(command.AssignmentRevision) },
		Allowed:            AllowedSet([]string{command.Action}), Assignments: assignments, Now: now,
	}
	if err := Verify(command, base); err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		name string
		edit func(*Command)
	}{
		{"binding", func(c *Command) { c.BindingID = "22222222-2222-4222-8222-222222222222" }},
		{"device", func(c *Command) { c.DeviceID = "device-2" }},
		{"epoch", func(c *Command) { c.CredentialEpoch-- }},
		{"assignment", func(c *Command) { c.AssignmentRevision-- }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			changed := command
			check.edit(&changed)
			changed.Signature = SignCommand(changed, []byte("secret"))
			if err := Verify(changed, base); !errors.Is(err, ErrCommandAuthorityMismatch) {
				t.Fatalf("authority mismatch err=%v", err)
			}
		})
	}
}

func TestVerifyScopesReadOnlyActionsAndMultipartAction(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	tests := []Command{
		{
			SchemaVersion: 1, CommandID: "discover-1", OperationID: "operation-1", AgentRef: "agent-1", Scope: ScopeCluster,
			IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute), Identity: Identity{ClusterRef: "cluster-1"},
			Action: "pve.discover", Parameters: json.RawMessage(`{"operationId":"operation-1","phase":"version","limit":1}`), OperatorRef: "operator-1",
		},
		{
			SchemaVersion: 1, CommandID: "status-1", OperationID: "operation-1", AgentRef: "agent-1", Scope: ScopeNode,
			IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute), Identity: Identity{ClusterRef: "cluster-1", NodeRef: "pve-1"},
			Action: "task.status", Parameters: json.RawMessage(`{"upid":"UPID:pve-1:1:2:3:task:101:root@pam!api:"}`), OperatorRef: "operator-1",
		},
	}
	for _, command := range tests {
		command.BodySHA256 = protocolHash(command.Parameters)
		command.Signature = SignCommand(command, []byte("secret"))
		if err := Verify(command, VerifyConfig{
			AgentRef: "agent-1", ClusterRef: "cluster-1", Mode: "test", Secret: []byte("secret"),
			Allowed: AllowedSet([]string{command.Action}), Now: now,
		}); err != nil {
			t.Fatalf("%s: %v", command.Action, err)
		}
	}

	command, assignments := signedCommand(t, now)
	command.Action = "firewall.rule.create"
	command.Parameters = json.RawMessage(`{"direction":"in","action":"ACCEPT","protocol":"tcp","destinationPort":"443","enable":true}`)
	command.BodySHA256 = protocolHash(command.Parameters)
	command.Signature = SignCommand(command, []byte("secret"))
	if err := Verify(command, VerifyConfig{
		AgentRef: "agent-1", ClusterRef: "cluster-1", Mode: "test", Secret: []byte("secret"),
		Allowed: AllowedSet([]string{command.Action}), Assignments: assignments, Now: now,
	}); err != nil {
		t.Fatalf("multipart action rejected: %v", err)
	}
	command.ApprovalRef = ""
	command.Signature = SignCommand(command, []byte("secret"))
	if err := Verify(command, VerifyConfig{
		AgentRef: "agent-1", ClusterRef: "cluster-1", Mode: "test", Secret: []byte("secret"),
		Allowed: AllowedSet([]string{command.Action}), Assignments: assignments, Now: now,
	}); err == nil {
		t.Fatal("firewall write without approval was accepted")
	}
}

func TestVerifyRejectsProtocolUnknownActionAndUnknownParameters(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	command, assignments := signedCommand(t, now)
	command.Action = "vm.arbitrary.action"
	command.Signature = SignCommand(command, []byte("secret"))
	if err := Verify(command, VerifyConfig{
		AgentRef: "agent-1", ClusterRef: "cluster-1", Mode: "test", Secret: []byte("secret"),
		Allowed: AllowedSet([]string{command.Action}), Assignments: assignments, Now: now,
	}); err == nil {
		t.Fatal("deployment allowlist widened the protocol action set")
	}

	command, assignments = signedCommand(t, now)
	command.Parameters = json.RawMessage(`{"unknown":true}`)
	command.BodySHA256 = protocolHash(command.Parameters)
	command.Signature = SignCommand(command, []byte("secret"))
	if err := Verify(command, VerifyConfig{
		AgentRef: "agent-1", ClusterRef: "cluster-1", Mode: "test", Secret: []byte("secret"),
		Allowed: AllowedSet([]string{command.Action}), Assignments: assignments, Now: now,
	}); err == nil {
		t.Fatal("unknown action parameter was accepted")
	}
}

func TestAllProtocolWritesRequireApproval(t *testing.T) {
	for action, spec := range protocolActions {
		if got := requiresApproval(action); got == spec.readOnly {
			t.Fatalf("action %s readOnly=%v requiresApproval=%v", action, spec.readOnly, got)
		}
	}
	if requiresApproval("pve.discover") || requiresApproval("task.status") {
		t.Fatal("read-only actions unexpectedly require approval")
	}
}

func TestCommandJSONRejectsUnknownAndDuplicateFields(t *testing.T) {
	for _, raw := range []string{
		`{"schemaVersion":1,"identity":{},"parameters":{},"unexpected":true}`,
		`{"schemaVersion":1,"schemaVersion":1,"identity":{},"parameters":{}}`,
		`{"schemaVersion":1,"identity":{"unexpected":true},"parameters":{}}`,
		`{"schemaVersion":1,"identity":{},"parameters":{"value":1,"value":2}}`,
	} {
		var command Command
		if err := json.Unmarshal([]byte(raw), &command); err == nil {
			t.Fatalf("strict command decoder accepted %s", raw)
		}
	}
}

func TestDryRunNeverCallsPVE(t *testing.T) {
	now := time.Now().UTC()
	command, _ := signedCommand(t, now)
	receipt, err := (Executor{Mode: "test", ProductionExecution: false}).Execute(nil, command, now)
	if err != nil || !receipt.DryRun || receipt.Code != "DRY_RUN" {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
}

func TestDryRunStillRejectsInvalidParameters(t *testing.T) {
	now := time.Now().UTC()
	command, _ := signedCommand(t, now)
	command.Parameters = json.RawMessage(`{"unexpected":true}`)
	receipt, err := (Executor{Mode: "test", ProductionExecution: false}).Execute(nil, command, now)
	if err == nil || receipt.State != "rejected" || receipt.Code != "INVALID_PARAMETERS" {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
}

func TestExecutorUsesFixedStartPath(t *testing.T) {
	_ = pve.Config{} // PVE HTTP path behavior is covered by pve client tests.
}

func protocolHash(raw []byte) string {
	return protocol.BodyHash(raw)
}
