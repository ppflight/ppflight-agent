// Package health exposes a loopback-only operational view of the agent. The
// status document deliberately contains no configuration secrets or command
// parameters.
package health

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ppflight/ppflight-agent/internal/store"
)

type Queue interface{ Stats() store.Stats }

type EventState struct {
	LastAttempt      *time.Time `json:"lastAttempt,omitempty"`
	LastSuccess      *time.Time `json:"lastSuccess,omitempty"`
	LastError        string     `json:"lastError,omitempty"`
	AuthBlocked      bool       `json:"authBlocked"`
	AuthBlockedSince *time.Time `json:"authBlockedSince,omitempty"`
}

type ControlState struct {
	Enabled             bool       `json:"enabled"`
	Configured          bool       `json:"configured"`
	ProductionExecution bool       `json:"productionExecution"`
	LastPoll            *time.Time `json:"lastPoll,omitempty"`
	LastSuccess         *time.Time `json:"lastSuccess,omitempty"`
	LastError           string     `json:"lastError,omitempty"`
}

type Status struct {
	SchemaVersion int                    `json:"schemaVersion"`
	Version       string                 `json:"version"`
	Mode          string                 `json:"mode"`
	AgentRef      string                 `json:"agentRef"`
	ClusterRef    string                 `json:"clusterRef"`
	NodeRef       string                 `json:"nodeRef"`
	StartedAt     time.Time              `json:"startedAt"`
	Ready         bool                   `json:"ready"`
	Collection    EventState             `json:"collection"`
	Deliveries    map[string]EventState  `json:"deliveries"`
	Control       ControlState           `json:"control"`
	AssignmentRev string                 `json:"assignmentRevision,omitempty"`
	Assignments   int                    `json:"assignments"`
	Queues        map[string]store.Stats `json:"queues"`
}

type Registry struct {
	mu     sync.RWMutex
	status Status
	queues map[string]Queue
}

func New(version, mode, agentRef, clusterRef, nodeRef string, controlEnabled, controlConfigured, productionExecution bool, now time.Time) *Registry {
	return &Registry{status: Status{
		SchemaVersion: 1, Version: version, Mode: mode, AgentRef: agentRef, ClusterRef: clusterRef,
		NodeRef: nodeRef, StartedAt: now.UTC(), Deliveries: map[string]EventState{}, Queues: map[string]store.Stats{},
		Control: ControlState{Enabled: controlEnabled, Configured: controlConfigured, ProductionExecution: productionExecution},
	}, queues: map[string]Queue{}}
}

func (r *Registry) RegisterQueue(name string, queue Queue) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if name != "" && queue != nil {
		r.queues[name] = queue
	}
}

func (r *Registry) Assignment(revision string, count int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status.AssignmentRev, r.status.Assignments = revision, count
}

func (r *Registry) Collection(now time.Time, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	timestamp := now.UTC()
	r.status.Collection.LastAttempt = &timestamp
	if err == nil {
		r.status.Collection.LastSuccess, r.status.Collection.LastError, r.status.Ready = &timestamp, "", true
	} else {
		r.status.Collection.LastError = safeError(err)
	}
}

func (r *Registry) Delivery(name string, now time.Time, delivered bool, err error) {
	r.DeliveryState(name, now, delivered, false, err)
}

// DeliveryState records a destination authentication circuit separately from
// ordinary transient errors. authBlocked means the durable queue is preserved
// and delivery awaits a newer credential epoch.
func (r *Registry) DeliveryState(name string, now time.Time, delivered, authBlocked bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state := r.status.Deliveries[name]
	timestamp := now.UTC()
	state.LastAttempt = &timestamp
	if authBlocked && !state.AuthBlocked {
		state.AuthBlockedSince = &timestamp
	}
	if !authBlocked {
		state.AuthBlockedSince = nil
	}
	state.AuthBlocked = authBlocked
	if delivered {
		state.LastSuccess, state.LastError, state.AuthBlocked = &timestamp, "", false
	} else if err != nil {
		state.LastError = safeError(err)
	}
	r.status.Deliveries[name] = state
}

func (r *Registry) ControlPoll(now time.Time, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	timestamp := now.UTC()
	r.status.Control.LastPoll = &timestamp
	if err == nil {
		r.status.Control.LastSuccess, r.status.Control.LastError = &timestamp, ""
	} else {
		r.status.Control.LastError = safeError(err)
	}
}

func (r *Registry) Snapshot() Status {
	r.mu.RLock()
	copyValue := r.status
	copyValue.Deliveries = make(map[string]EventState, len(r.status.Deliveries))
	for key, value := range r.status.Deliveries {
		copyValue.Deliveries[key] = value
	}
	queues := make(map[string]Queue, len(r.queues))
	for key, value := range r.queues {
		queues[key] = value
	}
	r.mu.RUnlock()
	copyValue.Queues = make(map[string]store.Stats, len(queues))
	for key, queue := range queues {
		copyValue.Queues[key] = queue.Stats()
	}
	return copyValue
}

func (r *Registry) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { plain(w, http.StatusOK, "ok\n") })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !r.Snapshot().Ready {
			plain(w, http.StatusServiceUnavailable, "not ready\n")
			return
		}
		plain(w, http.StatusOK, "ready\n")
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(r.Snapshot())
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(r.metrics()))
	})
	return securityHeaders(mux)
}

func (r *Registry) metrics() string {
	status := r.Snapshot()
	ready := 0
	if status.Ready {
		ready = 1
	}
	controlExecution := 0
	if status.Control.ProductionExecution {
		controlExecution = 1
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# HELP ppflight_agent_ready Whether the first collection completed successfully.\n# TYPE ppflight_agent_ready gauge\nppflight_agent_ready %d\n", ready)
	fmt.Fprintf(&b, "# HELP ppflight_agent_control_production_execution Whether PVE writes are enabled.\n# TYPE ppflight_agent_control_production_execution gauge\nppflight_agent_control_production_execution %d\n", controlExecution)
	names := make([]string, 0, len(status.Queues))
	for name := range status.Queues {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		stats := status.Queues[name]
		label := strconv.Quote(name)
		fmt.Fprintf(&b, "ppflight_agent_queue_pending_items{queue=%s} %d\n", label, stats.PendingItems)
		fmt.Fprintf(&b, "ppflight_agent_queue_pending_bytes{queue=%s} %d\n", label, stats.PendingBytes)
		fmt.Fprintf(&b, "ppflight_agent_queue_dropped_items_total{queue=%s} %d\n", label, stats.DroppedItems)
		fmt.Fprintf(&b, "ppflight_agent_queue_dead_letter_items_total{queue=%s} %d\n", label, stats.DeadLetterItems)
	}
	deliveryNames := make([]string, 0, len(status.Deliveries))
	for name := range status.Deliveries {
		deliveryNames = append(deliveryNames, name)
	}
	sort.Strings(deliveryNames)
	for _, name := range deliveryNames {
		blocked := 0
		if status.Deliveries[name].AuthBlocked {
			blocked = 1
		}
		fmt.Fprintf(&b, "ppflight_agent_delivery_auth_blocked{destination=%s} %d\n", strconv.Quote(name), blocked)
	}
	return b.String()
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, req)
	})
}
func plain(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}
func safeError(err error) string {
	if err == nil {
		return ""
	}
	value := err.Error()
	if len(value) > 512 {
		value = value[:512]
	}
	return value
}
