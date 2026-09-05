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
// reinstall/restore/delete is running. Heavy provider workflows have a single
// lane. Critical lifecycle changes use a separate, bounded lane from ordinary
// short operations; each gets two workers, so a sustained critical burst
// cannot starve routine work and a routine burst cannot delay a create, IP
// change, or power operation behind its entire FIFO backlog.
// Mutations for the same resource are still serialised by Journal.Claim.
type commandDispatcher struct {
	mu     sync.RWMutex
	active map[string]struct{}

	start sync.Once

	console  chan Command
	heavy    chan Command
	critical chan Command
	normal   chan Command
	execute  func(context.Context, Command)
}

func newCommandDispatcher(execute func(context.Context, Command)) *commandDispatcher {
	return &commandDispatcher{
		active:  make(map[string]struct{}),
		console: make(chan Command, 16),
		heavy:   make(chan Command, 4),
		// The critical and normal buffers deliberately split the old 32-command
		// short buffer. This keeps the aggregate non-console memory bound
		// unchanged while reserving progress for both priority classes.
		critical: make(chan Command, 16),
		normal:   make(chan Command, 16),
		execute:  execute,
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
		for range 2 {
			go d.worker(ctx, d.critical)
		}
		for range 2 {
			go d.worker(ctx, d.normal)
		}
	})
}

// hasCapacity is an admission preflight, not a reservation. Service.PollOnce
// holds its admission mutex from this check through submit, so no second poll
// can fill the selected lane in between. Workers can only drain a channel,
// which makes a successful preflight sufficient for the immediately following
// non-blocking submit.
//
// Keeping the check before Journal.Claim is important: a full in-memory lane
// must leave the command exclusively at the website cursor. If we first wrote
// a running receipt and only then discovered a full lane, a retry could
// advance the website cursor while no worker ever owned the command.
func (d *commandDispatcher) hasCapacity(ctx context.Context, command Command) bool {
	d.startWorkers(ctx)
	d.mu.RLock()
	defer d.mu.RUnlock()
	if _, exists := d.active[command.CommandID]; exists {
		return true
	}
	queue := d.queueFor(command)
	return len(queue) < cap(queue)
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
	case "vm.create", "vm.clone", "vm.set-initial-resources", "vm.set-network",
		"vm.start", "vm.shutdown", "vm.stop", "vm.reboot", "vm.suspend", "vm.resume":
		return d.critical
	default:
		return d.normal
	}
}
