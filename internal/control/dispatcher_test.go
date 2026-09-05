package control

import (
	"context"
	"testing"
	"time"
)

func TestCommandDispatcherLetsEightConsoleRequestsProgressWhileHeavyWorkflowIsBusy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	heavyStarted := make(chan struct{})
	releaseHeavy := make(chan struct{})
	consoleStarted := make(chan string, 8)
	dispatcher := newCommandDispatcher(func(_ context.Context, command Command) {
		if command.Action == "vm.reinstall" {
			close(heavyStarted)
			<-releaseHeavy
			return
		}
		consoleStarted <- command.CommandID
	})

	if !dispatcher.submit(ctx, Command{CommandID: "heavy-1", Action: "vm.reinstall"}) {
		t.Fatal("heavy workflow was not admitted")
	}
	select {
	case <-heavyStarted:
	case <-time.After(time.Second):
		t.Fatal("heavy workflow did not start")
	}

	for index := 0; index < 8; index++ {
		command := Command{CommandID: "console-" + string(rune('a'+index)), Action: "vm.console.create-session"}
		if !dispatcher.submit(ctx, command) {
			t.Fatalf("console command %d was not admitted", index)
		}
	}
	seen := map[string]bool{}
	deadline := time.After(time.Second)
	for len(seen) < 8 {
		select {
		case commandID := <-consoleStarted:
			seen[commandID] = true
		case <-deadline:
			t.Fatalf("only %d of 8 console commands ran while heavy work was blocked", len(seen))
		}
	}
	close(releaseHeavy)
}

func TestRunningJournalRecordSerializesSameVMAndFailsClosedAfterRestart(t *testing.T) {
	now := time.Now().UTC()
	command, _ := signedCommand(t, now)
	journal, err := OpenJournal(t.TempDir() + "/journal")
	if err != nil {
		t.Fatal(err)
	}
	if _, duplicate, err := journal.Claim(command, now); err != nil || duplicate {
		t.Fatalf("first claim duplicate=%v err=%v", duplicate, err)
	}
	running := Receipt{
		SchemaVersion: SchemaVersion, ReceiptID: "running-1", CommandID: command.CommandID, OperationID: command.OperationID,
		AgentRef: command.AgentRef, State: "running", Code: "COMMAND_STARTED", ExecutionMode: "production",
		Accepted: true, Asynchronous: true, StartedAt: now, FinishedAt: now, OperatorRef: command.OperatorRef,
	}
	if err := journal.BeginRunning(command, running); err != nil {
		t.Fatal(err)
	}

	second := command
	second.CommandID, second.OperationID, second.IdempotencyKey = "command-2", "operation-2", "idempotency-2"
	if _, _, err := journal.Claim(second, now); err != ErrResourceBusy {
		t.Fatalf("same VM mutation err=%v want ErrResourceBusy", err)
	}

	// A new process has no active in-memory dispatcher entry. It must not
	// replay the possibly-mutated command body, and instead projects one
	// truthful indeterminate receipt from the durable running marker.
	recovered, err := journal.RecoverIncomplete(now.Add(time.Second), "production")
	if err != nil || len(recovered) != 1 || recovered[0].State != "indeterminate" || recovered[0].Code != "EXECUTION_INDETERMINATE" {
		t.Fatalf("recovered=%#v err=%v", recovered, err)
	}
}

func TestDispatcherActiveEntryPreventsInProcessRecoveryFromTerminatingWorker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	release := make(chan struct{})
	dispatcher := newCommandDispatcher(func(context.Context, Command) {
		close(entered)
		<-release
	})
	command := Command{CommandID: "short-1", Action: "vm.start"}
	if !dispatcher.submit(ctx, command) {
		t.Fatal("short command was not admitted")
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("short command did not start")
	}
	if !dispatcher.activeCommand(command.CommandID) {
		t.Fatal("active command was not visible to reconciliation")
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for dispatcher.activeCommand(command.CommandID) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if dispatcher.activeCommand(command.CommandID) {
		t.Fatal("completed command remained active")
	}
}
