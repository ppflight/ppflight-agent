package auditlog

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/ppflight/ppflight-agent/internal/protocol"
	"github.com/ppflight/ppflight-agent/internal/store"
)

// Sink is the control service's narrow dependency. Implementations must make
// an event durable before returning nil.
type Sink interface {
	Enqueue(Event) error
}

// BatchBuilder injects monitoring-binding and process-run values without
// giving the control package access to monitoring credentials.
type BatchBuilder struct {
	MonitoringAgentRef string
	DeviceID           string
	CredentialEpoch    uint64
	BootID             string
	AgentVersion       string
	NextSequence       func() (uint64, error)
	Now                func() time.Time
}

// Build creates one immutable single-event batch. This implementation reuses
// event.EventID as batchId to give its queue item a stable retry key; the wire
// protocol itself does not require batch and event IDs to match.
func (b BatchBuilder) Build(event Event, state DeliveryState) (Batch, error) {
	if b.NextSequence == nil {
		return Batch{}, errors.New("audit sequence provider is required")
	}
	if b.Now == nil {
		b.Now = time.Now
	}
	if event.AgentVersion == "" {
		event.AgentVersion = b.AgentVersion
	}
	if err := event.Validate(); err != nil {
		return Batch{}, err
	}
	sequence, err := b.NextSequence()
	if err != nil {
		return Batch{}, err
	}
	observedAt := event.ReceivedAt
	if event.FinishedAt != nil {
		observedAt = *event.FinishedAt
	}
	result := Batch{
		SchemaVersion: SchemaVersion, BatchID: event.EventID,
		MonitoringAgentRef: b.MonitoringAgentRef, DeviceID: b.DeviceID,
		CredentialEpoch: protocol.Counter(b.CredentialEpoch), Sequence: protocol.Counter(sequence),
		BootID: b.BootID, ObservedAt: observedAt.UTC(), SentAt: b.Now().UTC(),
		DeliveryState: state, Events: []Event{event},
	}
	if err := result.Validate(); err != nil {
		return Batch{}, err
	}
	return result, nil
}

// DurableQueue is satisfied by store.Queue and kept as an interface for
// deterministic tests. Its kind must be store.Audit.
type DurableQueue interface {
	Enqueue(batchID string, payload []byte) (store.Item, bool, error)
	Stats() store.Stats
}

type QueueSinkConfig struct {
	Queue         DurableQueue
	Builder       BatchBuilder
	DeliveryState func() DeliveryState
}

type QueueSink struct {
	queue         DurableQueue
	builder       BatchBuilder
	deliveryState func() DeliveryState
}

func NewQueueSink(config QueueSinkConfig) (*QueueSink, error) {
	if config.Queue == nil {
		return nil, errors.New("audit durable queue is required")
	}
	return &QueueSink{queue: config.Queue, builder: config.Builder, deliveryState: config.DeliveryState}, nil
}

func (s *QueueSink) Enqueue(event Event) error {
	stats := s.queue.Stats()
	state := DeliveryState{PendingItems: protocol.Counter(stats.PendingItems), PendingBytes: protocol.Counter(stats.PendingBytes)}
	if s.deliveryState != nil {
		state = s.deliveryState()
	}
	batch, err := s.builder.Build(event, state)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	_, _, err = s.queue.Enqueue(batch.BatchID, payload)
	return err
}
