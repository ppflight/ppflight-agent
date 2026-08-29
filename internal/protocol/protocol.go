// Package protocol defines the wire format shared by PPFlight agents and APIs.
package protocol

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const Version = 1

type BatchKind string

const (
	Metering  BatchKind = "metering"
	Telemetry BatchKind = "telemetry"
)

func (k BatchKind) Valid() bool { return k == Metering || k == Telemetry }

// Counter is encoded as a decimal JSON string.  This prevents loss of precision
// in JavaScript and other JSON consumers which cannot exactly represent uint64.
type Counter uint64

func (c Counter) MarshalJSON() ([]byte, error) { return json.Marshal(fmt.Sprintf("%d", uint64(c))) }

func (c *Counter) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return fmt.Errorf("counter must be a decimal string: %w", err)
	}
	var value uint64
	if _, err := fmt.Sscan(text, &value); err != nil || fmt.Sprintf("%d", value) != text {
		return fmt.Errorf("invalid counter %q", text)
	}
	*c = Counter(value)
	return nil
}

// Batch has a stable batch ID and monotonic per-queue sequence. Sequence is
// deliberately string encoded for the same reason as Counter.
type Batch struct {
	Version int       `json:"version"`
	BatchID string    `json:"batchId"`
	Kind    BatchKind `json:"kind"`
	AgentID string    `json:"agentId"`
	// CollectorRef identifies the installed collector; SourceRef names the
	// authority being cut over. CutoverAt is supplied by the control plane and
	// prevents two collectors from being treated as simultaneous billable input.
	CollectorRef string          `json:"collectorRef"`
	SourceRef    string          `json:"sourceRef"`
	CutoverAt    *time.Time      `json:"cutoverAt,omitempty"`
	Sequence     uint64          `json:"sequence,string"`
	CreatedAt    time.Time       `json:"createdAt"`
	Records      json.RawMessage `json:"records"`
}

func NewBatch(kind BatchKind, agentID, collectorRef, sourceRef string, sequence uint64, records any) (Batch, error) {
	if !kind.Valid() {
		return Batch{}, fmt.Errorf("unknown batch kind %q", kind)
	}
	if strings.TrimSpace(agentID) == "" || strings.TrimSpace(collectorRef) == "" || strings.TrimSpace(sourceRef) == "" {
		return Batch{}, errors.New("agent ID, collector ref and source ref are required")
	}
	body, err := json.Marshal(records)
	if err != nil {
		return Batch{}, fmt.Errorf("marshal batch records: %w", err)
	}
	id, err := NewID()
	if err != nil {
		return Batch{}, err
	}
	return Batch{Version: Version, BatchID: id, Kind: kind, AgentID: agentID, CollectorRef: collectorRef, SourceRef: sourceRef, Sequence: sequence, CreatedAt: time.Now().UTC(), Records: body}, nil
}

func (b Batch) Validate() error {
	if b.Version != Version || !b.Kind.Valid() || b.BatchID == "" || b.AgentID == "" || b.CollectorRef == "" || b.SourceRef == "" || len(b.Records) == 0 || !json.Valid(b.Records) {
		return errors.New("invalid batch")
	}
	return nil
}

// UsageRecord is a raw cumulative counter observation. The website, not the
// agent, computes deltas, billing periods and usedBytes. All 64-bit values are
// Counter and therefore use decimal JSON strings.
type UsageRecord struct {
	ServiceRef   string     `json:"serviceRef"`
	ClusterRef   string     `json:"clusterRef"`
	NodeRef      string     `json:"nodeRef"`
	VMID         int        `json:"vmid"`
	Generation   Counter    `json:"generation"`
	InstanceUUID string     `json:"instanceUuid"`
	GuestType    string     `json:"guestType"`
	EventID      string     `json:"eventId"`
	CounterEpoch string     `json:"counterEpoch"`
	Sequence     Counter    `json:"sequence"`
	Source       string     `json:"source"`
	BillingState string     `json:"billingState"`
	CutoverAt    *time.Time `json:"cutoverAt,omitempty"`
	ObservedAt   time.Time  `json:"observedAt"`
	IngressBytes Counter    `json:"ingressBytes"`
	EgressBytes  Counter    `json:"egressBytes"`
}

// UsageBatch is the concrete payload for
// POST /internal/v1/metering/usage-batches. A generic Batch is retained for
// internal queues, while this public wire type avoids opaque records.
type UsageBatch struct {
	SchemaVersion int           `json:"schemaVersion"`
	BatchID       string        `json:"batchId"`
	AgentRef      string        `json:"agentRef"`
	CollectorRef  string        `json:"collectorRef"`
	SourceRef     string        `json:"sourceRef"`
	ClusterRef    string        `json:"clusterRef"`
	Mode          string        `json:"mode"`
	Sequence      Counter       `json:"sequence"`
	ObservedAt    time.Time     `json:"observedAt"`
	Events        []UsageRecord `json:"events"`
}

func (b UsageBatch) Validate() error {
	if b.SchemaVersion != Version || b.BatchID == "" || b.AgentRef == "" || b.CollectorRef == "" || b.SourceRef == "" || b.ClusterRef == "" || b.ObservedAt.IsZero() || len(b.Events) == 0 {
		return errors.New("invalid usage batch")
	}
	if b.Mode != "test" && b.Mode != "production" {
		return errors.New("usage batch mode must be test or production")
	}
	for _, event := range b.Events {
		if event.ServiceRef == "" || event.ClusterRef != b.ClusterRef || event.VMID < 1 || event.Generation == 0 || event.InstanceUUID == "" || event.EventID == "" || event.CounterEpoch == "" || event.Sequence == 0 || event.ObservedAt.IsZero() || (event.GuestType != "qemu" && event.GuestType != "lxc") || (event.BillingState != "shadow" && event.BillingState != "active") {
			return errors.New("invalid usage event")
		}
		if b.Mode != "production" && event.BillingState == "active" {
			return errors.New("non-production usage cannot be active")
		}
	}
	return nil
}

// MeteringRecord remains an alias for callers created before the identity
// schema was frozen. New code should use UsageRecord.
type MeteringRecord = UsageRecord

type TelemetryRecord struct {
	Name      string            `json:"name"`
	Value     float64           `json:"value"`
	Labels    map[string]string `json:"labels,omitempty"`
	SampledAt time.Time         `json:"sampledAt"`
}

// ControlCommand and ControlResult reserve stable signed payload envelopes for
// the executor. They carry no authority themselves; callers must verify request
// signatures and expiration before execution.
type ControlCommand struct {
	CommandID string          `json:"commandId"`
	Action    string          `json:"action"`
	ExpiresAt time.Time       `json:"expiresAt"`
	Payload   json.RawMessage `json:"payload"`
}

type ControlResult struct {
	CommandID  string          `json:"commandId"`
	Status     string          `json:"status"`
	Message    string          `json:"message,omitempty"`
	Result     json.RawMessage `json:"result,omitempty"`
	FinishedAt time.Time       `json:"finishedAt"`
}

func NewID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate ID: %w", err)
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:]), nil
}

func BodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
