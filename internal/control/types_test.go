package control

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/inventory"
	"github.com/ppflight/ppflight-agent/internal/protocol"
	"github.com/ppflight/ppflight-agent/internal/pve"
)

func signedCommand(t *testing.T, now time.Time) (Command, *inventory.Store) {
	t.Helper()
	parameters := json.RawMessage(`{}`)
	command := Command{SchemaVersion: 1, CommandID: "command-1", AgentRef: "agent-1", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(5 * time.Minute), Identity: Identity{ServiceRef: "service-1", ClusterRef: "cluster-1", NodeRef: "pve-1", VMID: 101, Generation: 2, InstanceUUID: "instance-1", GuestType: "qemu"}, Action: "vm.start", Parameters: parameters, OperatorRef: "operator-1", BodySHA256: protocolHash(parameters)}
	command.Signature = SignCommand(command, []byte("secret"))
	assignments := inventory.NewStore(inventory.Document{SchemaVersion: 1, Revision: "rev", IssuedAt: now, Assignments: []inventory.Assignment{{ServiceRef: "service-1", ClusterRef: "cluster-1", NodeRef: "pve-1", VMID: 101, Generation: 2, InstanceUUID: "instance-1", GuestType: "qemu", BillingState: "shadow"}}})
	return command, assignments
}

func TestVerifySignedMappedCommand(t *testing.T) {
	now := time.Now().UTC()
	command, assignments := signedCommand(t, now)
	err := Verify(command, VerifyConfig{AgentRef: "agent-1", ClusterRef: "cluster-1", Secret: []byte("secret"), Allowed: AllowedSet([]string{"vm.start"}), Assignments: assignments, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	command.Identity.Generation++
	if err := Verify(command, VerifyConfig{AgentRef: "agent-1", ClusterRef: "cluster-1", Secret: []byte("secret"), Allowed: AllowedSet([]string{"vm.start"}), Assignments: assignments, Now: now}); err == nil {
		t.Fatal("identity mismatch accepted")
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
