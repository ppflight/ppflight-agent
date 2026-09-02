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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ppflight/ppflight-agent/internal/exporter"
	"github.com/ppflight/ppflight-agent/internal/fsutil"
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
	InterfaceRef string    `json:"interfaceRef,omitempty"`
	CanonicalMAC string    `json:"canonicalMac,omitempty"`
	Source       string    `json:"source,omitempty"`
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
	if err := fsutil.EnsurePrivateDirectory(cfg.Directory); err != nil {
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
		if guest.Template {
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
		nodeRef := assignment.NodeRef
		if nodeRef == "" {
			nodeRef = guest.Node
		}
		perNIC, complete := resolvePerNICCounters(snapshot, guest, assignment)
		if complete {
			for _, counter := range perNIC {
				if err := appendUsageRecord(&records, &newState, assignment, nodeRef, snapshot.ObservedAt, billingState, counter); err != nil {
					return protocol.UsageBatch{}, false, err
				}
			}
			// A guest with only private/unmetered bindings is a complete
			// per-NIC observation with zero billable records. Never fall back
			// to the whole-guest aggregate for that case.
			continue
		}
		if guest.PVE.IngressBytes == nil || guest.PVE.EgressBytes == nil || !guest.PVE.Availability.Available {
			continue
		}
		if !assignment.AggregateMeteringCapability().Supported {
			billingState = "shadow"
		}
		// Legacy aggregate data is retained only as an explicitly source-labelled
		// shadow signal when the NIC policy cannot yet be satisfied. It is never
		// promoted to active billing for a mixed public/private guest.
		counter := nicCounter{Ingress: *guest.PVE.IngressBytes, Egress: *guest.PVE.EgressBytes, Source: "pve-cluster-resources"}
		if err := appendUsageRecord(&records, &newState, assignment, nodeRef, snapshot.ObservedAt, billingState, counter); err != nil {
			return protocol.UsageBatch{}, false, err
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

type nicCounter struct {
	InterfaceRef string
	CanonicalMAC string
	Role         string
	Source       string
	Ingress      uint64
	Egress       uint64
}

func resolvePerNICCounters(snapshot observation.Snapshot, guest observation.Guest, assignment inventory.Assignment) ([]nicCounter, bool) {
	if snapshot.Host == nil || len(assignment.NICBindings) == 0 {
		return nil, false
	}
	observed := make(map[string]observation.Network, len(guest.Networks))
	for _, network := range guest.Networks {
		observed[network.Interface] = network
	}
	host := make(map[string]exporter.InterfaceObservation, len(snapshot.Host.Interfaces))
	for _, item := range snapshot.Host.Interfaces {
		host[item.Device] = item
	}
	result := make([]nicCounter, 0, len(assignment.NICBindings))
	for _, binding := range assignment.NICBindings {
		if !binding.Metered {
			continue
		}
		network, ok := observed[binding.Interface]
		if !ok || !strings.EqualFold(network.MAC, binding.ExpectedMAC) {
			return nil, false
		}
		index, err := strconv.Atoi(strings.TrimPrefix(binding.Interface, "net"))
		if err != nil || index != network.Index {
			return nil, false
		}
		device := "tap" + strconv.Itoa(guest.VMID) + "i" + strconv.Itoa(index)
		if guest.GuestType == "lxc" {
			device = "veth" + strconv.Itoa(guest.VMID) + "i" + strconv.Itoa(index)
		}
		item, ok := host[device]
		if !ok {
			return nil, false
		}
		receiveText, receiveOK := exporter.CounterText(item.ReceiveBytes)
		transmitText, transmitOK := exporter.CounterText(item.TransmitBytes)
		receive, receiveErr := strconv.ParseUint(receiveText, 10, 64)
		transmit, transmitErr := strconv.ParseUint(transmitText, 10, 64)
		if !receiveOK || !transmitOK || receiveErr != nil || transmitErr != nil {
			return nil, false
		}
		// Linux sees RX as bytes sent by the guest and TX as bytes delivered to
		// it, so customer ingress/egress are intentionally reversed here.
		result = append(result, nicCounter{InterfaceRef: binding.Interface, CanonicalMAC: strings.ToUpper(binding.ExpectedMAC), Role: binding.Role, Source: "pve-host-netdev", Ingress: transmit, Egress: receive})
	}
	return result, true
}

func appendUsageRecord(records *[]protocol.UsageRecord, state *meterState, assignment inventory.Assignment, nodeRef string, observedAt time.Time, billingState string, counter nicCounter) error {
	key := assignment.Key()
	if counter.InterfaceRef != "" {
		key += "/" + counter.InterfaceRef
	}
	previous, found := state.Counters[key]
	epoch := previous.CounterEpoch
	if !found || previous.ServiceRef != assignment.ServiceRef || previous.InstanceUUID != assignment.InstanceUUID || previous.Generation != assignment.Generation || previous.InterfaceRef != counter.InterfaceRef || previous.CanonicalMAC != counter.CanonicalMAC || previous.Source != counter.Source || counter.Ingress < previous.Ingress || counter.Egress < previous.Egress {
		var err error
		epoch, err = protocol.NewID()
		if err != nil {
			return err
		}
	}
	eventID, err := protocol.NewID()
	if err != nil {
		return err
	}
	state.NextEventSequence++
	*records = append(*records, protocol.UsageRecord{
		ServiceRef: assignment.ServiceRef, ClusterRef: assignment.ClusterRef, NodeRef: nodeRef,
		VMID: assignment.VMID, Generation: protocol.Counter(assignment.Generation), InstanceUUID: assignment.InstanceUUID,
		GuestType: assignment.GuestType, EventID: eventID, CounterEpoch: epoch,
		Sequence: protocol.Counter(state.NextEventSequence), Source: counter.Source,
		InterfaceRef: counter.InterfaceRef, CanonicalMAC: counter.CanonicalMAC, NetworkRole: counter.Role, Metered: counter.InterfaceRef != "",
		BillingState: billingState, CutoverAt: assignment.CutoverAt, ObservedAt: observedAt,
		IngressBytes: protocol.Counter(counter.Ingress), EgressBytes: protocol.Counter(counter.Egress),
	})
	state.Counters[key] = counterState{ServiceRef: assignment.ServiceRef, Generation: assignment.Generation, InstanceUUID: assignment.InstanceUUID, InterfaceRef: counter.InterfaceRef, CanonicalMAC: counter.CanonicalMAC, Source: counter.Source, CounterEpoch: epoch, Ingress: counter.Ingress, Egress: counter.Egress, ObservedAt: observedAt}
	return nil
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
	return fsutil.SyncDir(directory)
}
