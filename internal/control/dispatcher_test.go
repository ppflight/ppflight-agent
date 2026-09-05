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

func TestCommandDispatcherReportsFullLaneBeforeDurableAdmission(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	release := make(chan struct{})
	dispatcher := newCommandDispatcher(func(_ context.Context, command Command) {
		if command.CommandID == "heavy-active" {
			close(started)
			<-release
		}
	})
	active := Command{CommandID: "heavy-active", Action: "vm.reinstall"}
	if !dispatcher.submit(ctx, active) {
		t.Fatal("active heavy command was not admitted")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("heavy worker did not start")
	}
	// One worker is blocked and the heavy lane has a four-command buffer.
	// Fill only that buffer; a fifth command must remain at the website
	// boundary rather than becoming a journaled-but-unowned running command.
	for index := 0; index < cap(dispatcher.heavy); index++ {
		command := Command{CommandID: "heavy-queued-" + string(rune('a'+index)), Action: "vm.reinstall"}
		if !dispatcher.submit(ctx, command) {
			t.Fatalf("heavy queue item %d was not admitted", index)
		}
	}
	if dispatcher.hasCapacity(ctx, Command{CommandID: "heavy-next", Action: "vm.reinstall"}) {
		t.Fatal("full heavy lane reported capacity")
	}
	close(release)
}

func TestCommandDispatcherSeparatesCriticalLifecycleAndNormalProgress(t *testing.T) {
	t.Run("critical operation progresses while normal lane is saturated", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		normalStarted := make(chan struct{}, 2)
		releaseNormal := make(chan struct{})
		criticalStarted := make(chan string, 1)
		dispatcher := newCommandDispatcher(func(_ context.Context, command Command) {
			if command.Action == "vm.set-rate" && command.CommandID[0:12] == "normal-block" {
				normalStarted <- struct{}{}
				<-releaseNormal
				return
			}
			if command.CommandID == "critical-probe" {
				criticalStarted <- command.CommandID
			}
		})

		for index := 0; index < 2; index++ {
			command := Command{CommandID: "normal-block-" + string(rune('a'+index)), Action: "vm.set-rate"}
			if !dispatcher.submit(ctx, command) {
				t.Fatalf("normal blocker %d was not admitted", index)
			}
		}
		for index := 0; index < 2; index++ {
			select {
			case <-normalStarted:
			case <-time.After(time.Second):
				t.Fatal("normal worker did not start")
			}
		}
		for index := 0; index < cap(dispatcher.normal); index++ {
			command := Command{CommandID: "normal-queued-" + string(rune('a'+index)), Action: "vm.set-rate"}
			if !dispatcher.submit(ctx, command) {
				t.Fatalf("normal queue item %d was not admitted", index)
			}
		}
		if !dispatcher.submit(ctx, Command{CommandID: "critical-probe", Action: "vm.create"}) {
			t.Fatal("critical lifecycle command was not admitted")
		}
		select {
		case <-criticalStarted:
		case <-time.After(time.Second):
			t.Fatal("critical lifecycle command was delayed by saturated normal lane")
		}
		close(releaseNormal)
	})

	t.Run("normal operation progresses while critical lane is saturated", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		criticalStarted := make(chan struct{}, 2)
		releaseCritical := make(chan struct{})
		normalStarted := make(chan string, 1)
		dispatcher := newCommandDispatcher(func(_ context.Context, command Command) {
			if command.Action == "vm.create" && command.CommandID[0:14] == "critical-block" {
				criticalStarted <- struct{}{}
				<-releaseCritical
				return
			}
			if command.CommandID == "normal-probe" {
				normalStarted <- command.CommandID
			}
		})

		for index := 0; index < 2; index++ {
			command := Command{CommandID: "critical-block-" + string(rune('a'+index)), Action: "vm.create"}
			if !dispatcher.submit(ctx, command) {
				t.Fatalf("critical blocker %d was not admitted", index)
			}
		}
		for index := 0; index < 2; index++ {
			select {
			case <-criticalStarted:
			case <-time.After(time.Second):
				t.Fatal("critical worker did not start")
			}
		}
		for index := 0; index < cap(dispatcher.critical); index++ {
			command := Command{CommandID: "critical-queued-" + string(rune('a'+index)), Action: "vm.create"}
			if !dispatcher.submit(ctx, command) {
				t.Fatalf("critical queue item %d was not admitted", index)
			}
		}
		if !dispatcher.submit(ctx, Command{CommandID: "normal-probe", Action: "vm.set-rate"}) {
			t.Fatal("normal command was not admitted")
		}
		select {
		case <-normalStarted:
		case <-time.After(time.Second):
			t.Fatal("normal command was starved by saturated critical lane")
		}
		close(releaseCritical)
	})
}

func TestCommandDispatcherClassifiesLifecycleActionsAsCritical(t *testing.T) {
	dispatcher := newCommandDispatcher(func(context.Context, Command) {})
	for _, action := range []string{
		"vm.create", "vm.clone", "vm.set-initial-resources", "vm.set-network",
		"vm.start", "vm.shutdown", "vm.stop", "vm.reboot", "vm.suspend", "vm.resume",
	} {
		if got := dispatcher.queueFor(Command{Action: action}); got != dispatcher.critical {
			t.Errorf("action %q was not classified as critical", action)
		}
	}
	if got := dispatcher.queueFor(Command{Action: "vm.set-rate"}); got != dispatcher.normal {
		t.Error("ordinary rate change was not classified as normal")
	}
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
