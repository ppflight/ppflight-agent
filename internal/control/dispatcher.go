package control

import (
	"context"
	"sync"
)

// commandDispatcher separates command admission from provider execution.  The
// journal remains the durable authority: this dispatcher only owns bounded
// in-memory work after the command has been durably claimed and its running
// receipt recorded.  A process loss therefore never retries an unknown
// mutation; recovery projects it as indeterminate instead.
//
// The pools deliberately reflect PVE risk, not request popularity.  Console
// session setup has its own bounded lane so it can continue while a lengthy
// reinstall/restore/delete is running.  Heavy provider workflows have a
// single lane, while unrelated short VM operations can make limited progress.
// Mutations for the same resource are still serialised by Journal.Claim.
type commandDispatcher struct {
	mu     sync.RWMutex
	active map[string]struct{}

	start sync.Once

	console chan Command
	heavy   chan Command
	short   chan Command
	execute func(context.Context, Command)
}

func newCommandDispatcher(execute func(context.Context, Command)) *commandDispatcher {
	return &commandDispatcher{
		active:  make(map[string]struct{}),
		console: make(chan Command, 16),
		heavy:   make(chan Command, 4),
		short:   make(chan Command, 32),
		execute: execute,
	}
}

func (d *commandDispatcher) startWorkers(ctx context.Context) {
	d.start.Do(func() {
		for range 8 {
			go d.worker(ctx, d.console)
		}
		for range 1 {
			go d.worker(ctx, d.heavy)
		}
		for range 4 {
			go d.worker(ctx, d.short)
		}
	})
}

// submit is intentionally non-blocking. A full lane leaves the server cursor
// unchanged, so the command remains at the website boundary instead of being
// falsely accepted without its parameter body being durable locally.
func (d *commandDispatcher) submit(ctx context.Context, command Command) bool {
	d.startWorkers(ctx)
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, exists := d.active[command.CommandID]; exists {
		return true
	}
	queue := d.queueFor(command)
	select {
	case queue <- command:
		d.active[command.CommandID] = struct{}{}
		return true
	default:
		return false
	}
}

func (d *commandDispatcher) activeCommand(commandID string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, ok := d.active[commandID]
	return ok
}

func (d *commandDispatcher) worker(ctx context.Context, queue <-chan Command) {
	for {
		select {
		case <-ctx.Done():
			return
		case command := <-queue:
			d.execute(ctx, command)
			d.mu.Lock()
			delete(d.active, command.CommandID)
			d.mu.Unlock()
		}
	}
}

func (d *commandDispatcher) queueFor(command Command) chan Command {
	switch command.Action {
	case "vm.console.create-session", "vm.console.revoke-session":
		return d.console
	case "vm.reinstall", "backup.restore", "vm.delete", "snapshot.rollback":
		return d.heavy
	default:
		return d.short
	}
}
