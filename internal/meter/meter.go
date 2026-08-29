// Package meter turns exact PVE cumulative counters into crash-safe usage
// observations. It never computes customer usedBytes or billing periods.
package meter

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/ppflight/ppflight-agent/internal/inventory"
	"github.com/ppflight/ppflight-agent/internal/observation"
	"github.com/ppflight/ppflight-agent/internal/protocol"
	"github.com/ppflight/ppflight-agent/internal/store"
)

const stateVersion = 1

type Queue interface {
	Enqueue(batchID string, payload []byte) (store.Item, bool, error)
}

type Config struct {
	Directory    string
	Mode         string
	AgentRef     string
	CollectorRef string
	SourceRef    string
	ClusterRef   string
	Now          func() time.Time
}

type Manager struct {
	mu        sync.Mutex
	cfg       Config
	state     meterState
	statePath string
	txnPath   string
}

type meterState struct {
	Version           int                     `json:"version"`
	NextBatchSequence uint64                  `json:"nextBatchSequence,string"`
	NextEventSequence uint64                  `json:"nextEventSequence,string"`
	Counters          map[string]counterState `json:"counters"`
}

type counterState struct {
	ServiceRef   string    `json:"serviceRef"`
	Generation   uint64    `json:"generation,string"`
	InstanceUUID string    `json:"instanceUuid"`
	CounterEpoch string    `json:"counterEpoch"`
	Ingress      uint64    `json:"ingress,string"`
	Egress       uint64    `json:"egress,string"`
	ObservedAt   time.Time `json:"observedAt"`
}

type transaction struct {
	Version  int                 `json:"version"`
	Batch    protocol.UsageBatch `json:"batch"`
	NewState meterState          `json:"newState"`
}

func Open(cfg Config) (*Manager, error) {
	if cfg.Directory == "" || cfg.AgentRef == "" || cfg.CollectorRef == "" || cfg.SourceRef == "" || cfg.ClusterRef == "" {
		return nil, errors.New("meter directory and identity are required")
	}
	if cfg.Mode != "test" && cfg.Mode != "production" {
		return nil, errors.New("meter mode must be test or production")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if err := os.MkdirAll(cfg.Directory, 0o750); err != nil {
		return nil, fmt.Errorf("create meter directory: %w", err)
	}
	result := &Manager{
		cfg: cfg, statePath: filepath.Join(cfg.Directory, "state.json"),
		txnPath: filepath.Join(cfg.Directory, "pending-transaction.json"),
		state:   meterState{Version: stateVersion, Counters: make(map[string]counterState)},
	}
	if err := result.load(); err != nil {
		return nil, err
	}
	return result, nil
}

func (m *Manager) load() error {
	raw, err := os.ReadFile(m.statePath)
	if errors.Is(err, fs.ErrNotExist) {
		return atomicJSON(m.statePath, m.state)
	}
	if err != nil {
		return fmt.Errorf("read meter state: %w", err)
	}
	if err := json.Unmarshal(raw, &m.state); err != nil || m.state.Version != stateVersion || m.state.Counters == nil {
		return errors.New("meter state is corrupt or unsupported")
	}
	return nil
}

// Recover completes an interrupted state+queue transaction. It is idempotent:
// Queue.Enqueue deduplicates the original batch ID.
func (m *Manager) Recover(queue Queue) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.recoverLocked(queue)
}

func (m *Manager) recoverLocked(queue Queue) error {
	raw, err := os.ReadFile(m.txnPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read pending meter transaction: %w", err)
	}
	var txn transaction
	if err := json.Unmarshal(raw, &txn); err != nil || txn.Version != stateVersion || txn.NewState.Counters == nil || txn.Batch.Validate() != nil {
		return errors.New("pending meter transaction is corrupt")
	}
	payload, err := json.Marshal(txn.Batch)
	if err != nil {
		return err
	}
	if _, _, err := queue.Enqueue(txn.Batch.BatchID, payload); err != nil {
		return fmt.Errorf("recover meter queue item: %w", err)
	}
	if err := atomicJSON(m.statePath, txn.NewState); err != nil {
		return fmt.Errorf("recover meter state: %w", err)
	}
	m.state = txn.NewState
	if err := os.Remove(m.txnPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return syncDirectory(m.cfg.Directory)
}

// Observe records one snapshot in a local transaction before it becomes
// eligible for delivery. Unmapped guests and unavailable counters are skipped.
func (m *Manager) Observe(snapshot observation.Snapshot, assignments *inventory.Store, queue Queue) (protocol.UsageBatch, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if assignments == nil || queue == nil {
		return protocol.UsageBatch{}, false, errors.New("assignments and metering queue are required")
	}
	if err := m.recoverLocked(queue); err != nil {
		return protocol.UsageBatch{}, false, err
	}
	newState := cloneState(m.state)
	newState.NextBatchSequence++
	records := make([]protocol.UsageRecord, 0, len(snapshot.Guests))
	guests := append([]observation.Guest(nil), snapshot.Guests...)
	sort.Slice(guests, func(i, j int) bool {
		if guests[i].GuestType == guests[j].GuestType {
			return guests[i].VMID < guests[j].VMID
		}
		return guests[i].GuestType < guests[j].GuestType
	})
	for _, guest := range guests {
		if guest.Template || guest.PVE.IngressBytes == nil || guest.PVE.EgressBytes == nil || !guest.PVE.Availability.Available {
			continue
		}
		assignment, ok := assignments.Lookup(m.cfg.ClusterRef, guest.GuestType, guest.VMID)
		if !ok || assignment.BillingState == "disabled" {
			continue
		}
		billingState := assignment.BillingState
		if m.cfg.Mode != "production" || assignment.CutoverAt == nil || snapshot.ObservedAt.Before(*assignment.CutoverAt) {
			billingState = "shadow"
		}
		key := assignment.Key()
		previous, found := newState.Counters[key]
		epoch := previous.CounterEpoch
		if !found || previous.ServiceRef != assignment.ServiceRef || previous.InstanceUUID != assignment.InstanceUUID || previous.Generation != assignment.Generation || *guest.PVE.IngressBytes < previous.Ingress || *guest.PVE.EgressBytes < previous.Egress {
			var idErr error
			epoch, idErr = protocol.NewID()
			if idErr != nil {
				return protocol.UsageBatch{}, false, idErr
			}
		}
		eventID, err := protocol.NewID()
		if err != nil {
			return protocol.UsageBatch{}, false, err
		}
		newState.NextEventSequence++
		nodeRef := assignment.NodeRef
		if nodeRef == "" {
			nodeRef = guest.Node
		}
		records = append(records, protocol.UsageRecord{
			ServiceRef: assignment.ServiceRef, ClusterRef: assignment.ClusterRef, NodeRef: nodeRef,
			VMID: assignment.VMID, Generation: protocol.Counter(assignment.Generation), InstanceUUID: assignment.InstanceUUID,
			GuestType: assignment.GuestType, EventID: eventID, CounterEpoch: epoch,
			Sequence: protocol.Counter(newState.NextEventSequence), Source: "pve-cluster-resources",
			BillingState: billingState, CutoverAt: assignment.CutoverAt, ObservedAt: snapshot.ObservedAt,
			IngressBytes: protocol.Counter(*guest.PVE.IngressBytes), EgressBytes: protocol.Counter(*guest.PVE.EgressBytes),
		})
		newState.Counters[key] = counterState{
			ServiceRef: assignment.ServiceRef, Generation: assignment.Generation, InstanceUUID: assignment.InstanceUUID,
			CounterEpoch: epoch, Ingress: *guest.PVE.IngressBytes, Egress: *guest.PVE.EgressBytes, ObservedAt: snapshot.ObservedAt,
		}
	}
	if len(records) == 0 {
		return protocol.UsageBatch{}, false, nil
	}
	batchID, err := protocol.NewID()
	if err != nil {
		return protocol.UsageBatch{}, false, err
	}
	batch := protocol.UsageBatch{
		SchemaVersion: protocol.Version, BatchID: batchID, AgentRef: m.cfg.AgentRef,
		CollectorRef: m.cfg.CollectorRef, SourceRef: m.cfg.SourceRef, ClusterRef: m.cfg.ClusterRef,
		Mode: m.cfg.Mode, Sequence: protocol.Counter(newState.NextBatchSequence), ObservedAt: snapshot.ObservedAt, Events: records,
	}
	if err := batch.Validate(); err != nil {
		return protocol.UsageBatch{}, false, err
	}
	txn := transaction{Version: stateVersion, Batch: batch, NewState: newState}
	if err := atomicJSON(m.txnPath, txn); err != nil {
		return protocol.UsageBatch{}, false, fmt.Errorf("persist meter transaction: %w", err)
	}
	payload, err := json.Marshal(batch)
	if err != nil {
		return protocol.UsageBatch{}, false, err
	}
	if _, _, err := queue.Enqueue(batch.BatchID, payload); err != nil {
		return protocol.UsageBatch{}, false, err
	}
	if err := atomicJSON(m.statePath, newState); err != nil {
		return protocol.UsageBatch{}, false, err
	}
	m.state = newState
	if err := os.Remove(m.txnPath); err != nil {
		return protocol.UsageBatch{}, false, err
	}
	if err := syncDirectory(m.cfg.Directory); err != nil {
		return protocol.UsageBatch{}, false, err
	}
	return batch, true, nil
}

func cloneState(source meterState) meterState {
	result := source
	result.Counters = make(map[string]counterState, len(source.Counters))
	for key, value := range source.Counters {
		result.Counters[key] = value
	}
	return result
}

func atomicJSON(filename string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	directory := filepath.Dir(filename)
	temporary, err := os.CreateTemp(directory, ".meter-pending-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(raw); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, filename); err != nil {
		return err
	}
	if err := syncDirectory(directory); err != nil {
		return err
	}
	keep = true
	return nil
}

func syncDirectory(directory string) error {
	handle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}
