// Package store provides a crash-safe, destination-isolated disk queue.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ppflight/ppflight-agent/internal/fsutil"
)

type Kind string

const (
	Metering  Kind = "metering"
	Telemetry Kind = "telemetry"
	// Audit is a monitoring-only, non-evicting outbox. It is intentionally a
	// different on-disk kind from telemetry so neither destination can
	// acknowledge, quarantine, or apply retention policy to the other.
	Audit Kind = "audit"
)

func (k Kind) Valid() bool { return k == Metering || k == Telemetry || k == Audit }

var ErrCapacity = errors.New("persistent queue capacity reached")

// AuditEnqueueDelay closes the small durability window between Queue.Enqueue
// and the control journal's MarkAuditQueued. The control reconciler runs
// before delivery starts, while other queue kinds remain immediately due.
const AuditEnqueueDelay = 5 * time.Second

// Policy applies to a single destination and kind. Zero limits mean unbounded.
// Metering and audit queues never evict; capacity is returned to the caller as ErrCapacity.
// Telemetry queues can evict their oldest pending records when DropOldest is true.
type Policy struct {
	MaxItems   int
	MaxBytes   int64
	DropOldest bool
}

type Config struct {
	Root        string
	Destination string
	Kind        Kind
	Policy      Policy
	Now         func() time.Time
}

type Item struct {
	BatchID     string    `json:"batchId"`
	Sequence    uint64    `json:"sequence,string"`
	Payload     []byte    `json:"payload"`
	CreatedAt   time.Time `json:"createdAt"`
	Attempts    int       `json:"attempts"`
	NextAttempt time.Time `json:"nextAttempt"`
	LastError   string    `json:"lastError,omitempty"`
}

type Stats struct {
	PendingItems    int    `json:"pendingItems"`
	PendingBytes    int64  `json:"pendingBytes"`
	DroppedItems    uint64 `json:"droppedItems,string"`
	DroppedBytes    uint64 `json:"droppedBytes,string"`
	DeadLetterItems uint64 `json:"deadLetterItems,string"`
	DeadLetterBytes uint64 `json:"deadLetterBytes,string"`
	NextSequence    uint64 `json:"nextSequence,string"`
}

type Queue struct {
	mu     sync.Mutex
	dir    string
	kind   Kind
	policy Policy
	now    func() time.Time
	items  map[string]Item
	stats  Stats
}

// Open loads one queue. Destinations are encoded as a directory name, so data
// for the control-plane and monitoring endpoints can never be acknowledged together.
func Open(config Config) (*Queue, error) {
	if config.Root == "" || config.Destination == "" || !config.Kind.Valid() {
		return nil, errors.New("root, destination and valid kind are required")
	}
	if strings.Contains(config.Destination, "/") || config.Destination == "." || config.Destination == ".." {
		return nil, errors.New("destination must be a simple identifier")
	}
	if (config.Kind == Metering || config.Kind == Audit) && config.Policy.DropOldest {
		return nil, fmt.Errorf("%s must not use an eviction policy", config.Kind)
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	dir := filepath.Join(config.Root, config.Destination, string(config.Kind))
	if err := fsutil.EnsurePrivateDirectory(dir); err != nil {
		return nil, fmt.Errorf("create queue directory: %w", err)
	}
	if err := fsutil.EnsurePrivateDirectory(filepath.Join(dir, ".dead-letter")); err != nil {
		return nil, fmt.Errorf("create dead-letter directory: %w", err)
	}
	q := &Queue{dir: dir, kind: config.Kind, policy: config.Policy, now: config.Now, items: make(map[string]Item)}
	if err := q.load(); err != nil {
		return nil, err
	}
	return q, nil
}

func (q *Queue) Enqueue(batchID string, payload []byte) (Item, bool, error) {
	if strings.TrimSpace(batchID) == "" || len(payload) == 0 {
		return Item{}, false, errors.New("batch ID and payload are required")
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if found, ok := q.items[batchID]; ok {
		return found, false, nil
	}
	if err := q.makeCapacity(int64(len(payload))); err != nil {
		return Item{}, false, err
	}
	q.stats.NextSequence++
	now := q.now().UTC()
	nextAttempt := now
	if q.kind == Audit {
		nextAttempt = nextAttempt.Add(AuditEnqueueDelay)
	}
	item := Item{BatchID: batchID, Sequence: q.stats.NextSequence, Payload: append([]byte(nil), payload...), CreatedAt: now, NextAttempt: nextAttempt}
	if err := q.writeItem(item); err != nil {
		q.stats.NextSequence--
		return Item{}, false, err
	}
	q.items[item.BatchID] = item
	q.stats.PendingItems++
	q.stats.PendingBytes += int64(len(payload))
	if err := q.writeStats(); err != nil {
		return Item{}, false, err
	}
	return item, true, nil
}

func (q *Queue) Next(now time.Time) (Item, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	var result Item
	found := false
	for _, item := range q.items {
		if !item.NextAttempt.After(now) && (!found || item.Sequence < result.Sequence) {
			result, found = item, true
		}
	}
	return result, found
}

func (q *Queue) Ack(batchID string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	item, found := q.items[batchID]
	if !found {
		return nil
	} // Idempotent acknowledgement.
	if err := os.Remove(q.itemPath(item)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove acknowledged batch: %w", err)
	}
	if err := syncDir(q.dir); err != nil {
		return err
	}
	delete(q.items, batchID)
	q.stats.PendingItems--
	q.stats.PendingBytes -= int64(len(item.Payload))
	return q.writeStats()
}

// Nack atomically persists retry metadata before a future delivery attempt.
func (q *Queue) Nack(batchID string, next time.Time, reason string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	item, found := q.items[batchID]
	if !found {
		return fs.ErrNotExist
	}
	item.Attempts++
	item.NextAttempt = next.UTC()
	item.LastError = truncate(reason, 512)
	if err := q.writeItem(item); err != nil {
		return err
	}
	q.items[batchID] = item
	return nil
}

// Quarantine atomically moves a rejected item out of the delivery queue. This
// is intentionally distinct from Ack: rejected metering is retained for audit
// and operator recovery rather than silently considered delivered.
func (q *Queue) Quarantine(batchID, reason string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	item, found := q.items[batchID]
	if !found {
		return fs.ErrNotExist
	}
	item.LastError = truncate(reason, 512)
	item.NextAttempt = time.Time{}
	item.Attempts++
	deadDir := filepath.Join(q.dir, ".dead-letter")
	deadPath := filepath.Join(deadDir, fmt.Sprintf("%020d-%s.dead.json", item.Sequence, safeID(item.BatchID)))
	raw, err := json.Marshal(item)
	if err != nil {
		return fmt.Errorf("encode dead letter: %w", err)
	}
	if err := atomicWrite(deadPath, raw, 0o600); err != nil {
		return fmt.Errorf("persist dead letter: %w", err)
	}
	if err := os.Remove(q.itemPath(item)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove rejected batch: %w", err)
	}
	if err := syncDir(q.dir); err != nil {
		return err
	}
	delete(q.items, batchID)
	q.stats.PendingItems--
	q.stats.PendingBytes -= int64(len(item.Payload))
	q.stats.DeadLetterItems++
	q.stats.DeadLetterBytes += uint64(len(item.Payload))
	return q.writeStats()
}

func (q *Queue) Stats() Stats { q.mu.Lock(); defer q.mu.Unlock(); return q.stats }
func (q *Queue) Len() int     { q.mu.Lock(); defer q.mu.Unlock(); return len(q.items) }

func (q *Queue) makeCapacity(newBytes int64) error {
	over := func() bool {
		return (q.policy.MaxItems > 0 && q.stats.PendingItems+1 > q.policy.MaxItems) || (q.policy.MaxBytes > 0 && q.stats.PendingBytes+newBytes > q.policy.MaxBytes)
	}
	if !over() {
		return nil
	}
	if q.kind != Telemetry || !q.policy.DropOldest {
		return ErrCapacity
	}
	for over() {
		oldest, ok := q.oldest()
		if !ok {
			return ErrCapacity
		}
		if err := os.Remove(q.itemPath(oldest)); err != nil {
			return fmt.Errorf("evict telemetry: %w", err)
		}
		delete(q.items, oldest.BatchID)
		q.stats.PendingItems--
		q.stats.PendingBytes -= int64(len(oldest.Payload))
		q.stats.DroppedItems++
		q.stats.DroppedBytes += uint64(len(oldest.Payload))
	}
	if err := syncDir(q.dir); err != nil {
		return err
	}
	// The drop counters are an observable telemetry-loss signal, not merely
	// in-memory diagnostics. Persist them before accepting the replacement item.
	return q.writeStats()
}

func (q *Queue) oldest() (Item, bool) {
	var value Item
	found := false
	for _, item := range q.items {
		if !found || item.Sequence < value.Sequence {
			value, found = item, true
		}
	}
	return value, found
}

func (q *Queue) load() error {
	if raw, err := os.ReadFile(filepath.Join(q.dir, "stats.json")); err == nil {
		if err := json.Unmarshal(raw, &q.stats); err != nil {
			return fmt.Errorf("read queue stats: %w", err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	// Pending values are always derived from WAL records. This repairs a crash
	// after the record rename but before the stats-file rewrite.
	q.stats.PendingItems = 0
	q.stats.PendingBytes = 0
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".wal.json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(q.dir, entry.Name()))
		if err != nil {
			return err
		}
		var item Item
		if err := json.Unmarshal(raw, &item); err != nil || item.BatchID == "" || item.Sequence == 0 {
			return fmt.Errorf("corrupt queue record %s", entry.Name())
		}
		q.items[item.BatchID] = item
		q.stats.PendingItems++
		q.stats.PendingBytes += int64(len(item.Payload))
		if item.Sequence > q.stats.NextSequence {
			q.stats.NextSequence = item.Sequence
		}
	}
	// Stats are derived from WAL records at startup to repair a crash between an
	// item write and a stats rewrite. Drop counters and sequence are retained.
	return q.writeStats()
}

func (q *Queue) itemPath(item Item) string {
	return filepath.Join(q.dir, fmt.Sprintf("%020d-%s.wal.json", item.Sequence, safeID(item.BatchID)))
}

func (q *Queue) writeItem(item Item) error {
	raw, err := json.Marshal(item)
	if err != nil {
		return err
	}
	return atomicWrite(q.itemPath(item), raw, 0o600)
}
func (q *Queue) writeStats() error {
	raw, err := json.Marshal(q.stats)
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(q.dir, "stats.json"), raw, 0o600)
}

func atomicWrite(path string, body []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".pending-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if err := syncDir(dir); err != nil {
		return err
	}
	ok = true
	return nil
}

func syncDir(dir string) error {
	return fsutil.SyncDir(dir)
}
func safeID(id string) string { sum := sha256.Sum256([]byte(id)); return hex.EncodeToString(sum[:16]) }
func truncate(value string, size int) string {
	if len(value) <= size {
		return value
	}
	return value[:size]
}

// Snapshot returns pending items in sequence order, intended for diagnostics and tests.
func (q *Queue) Snapshot() []Item {
	q.mu.Lock()
	defer q.mu.Unlock()
	items := make([]Item, 0, len(q.items))
	for _, item := range q.items {
		item.Payload = append([]byte(nil), item.Payload...)
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Sequence < items[j].Sequence })
	return items
}
