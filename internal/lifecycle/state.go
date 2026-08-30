// Package lifecycle records process sessions so a restarted agent can report
// a previous unclean exit through both already-durable telemetry outboxes.
package lifecycle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/ppflight/ppflight-agent/internal/fsutil"
	"github.com/ppflight/ppflight-agent/internal/protocol"
)

const (
	version       = 1
	maximumBytes  = 1 << 20
	maximumEvents = 4096
	DomainWebsite = "website"
	DomainMonitor = "monitoring"
)

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type Incident struct {
	EventID           string    `json:"eventId"`
	PreviousBootID    string    `json:"previousBootId"`
	PreviousStartedAt time.Time `json:"previousStartedAt"`
	ObservedAt        time.Time `json:"observedAt"`
	WebsiteQueued     bool      `json:"websiteQueued"`
	MonitoringQueued  bool      `json:"monitoringQueued"`
}

type document struct {
	Version     int        `json:"version"`
	State       string     `json:"state"`
	BootID      string     `json:"bootId"`
	StartedAt   time.Time  `json:"startedAt"`
	CleanExitAt *time.Time `json:"cleanExitAt,omitempty"`
	Pending     []Incident `json:"pending"`
}

type Session struct {
	mu       sync.Mutex
	filename string
	value    document
}

func Begin(filename, bootID string, now time.Time) (*Session, error) {
	if filename == "" || !uuidRE.MatchString(bootID) || !validUTC(now) {
		return nil, errors.New("lifecycle session identity is invalid")
	}
	if err := fsutil.EnsurePrivateDirectory(filepath.Dir(filename)); err != nil {
		return nil, err
	}
	previous, found, err := load(filename)
	if err != nil {
		return nil, err
	}
	pending := []Incident{}
	if found {
		pending = append(pending, previous.Pending...)
		if previous.State == "running" {
			if len(pending) >= maximumEvents {
				return nil, errors.New("lifecycle incident backlog is full")
			}
			eventID, idErr := protocol.NewID()
			if idErr != nil {
				return nil, idErr
			}
			pending = append(pending, Incident{EventID: eventID, PreviousBootID: previous.BootID, PreviousStartedAt: previous.StartedAt, ObservedAt: now.UTC()})
		}
	}
	session := &Session{filename: filename, value: document{Version: version, State: "running", BootID: bootID, StartedAt: now.UTC(), Pending: pending}}
	if err := session.persist(); err != nil {
		return nil, err
	}
	return session, nil
}

func (s *Session) Pending(domain string) []Incident {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]Incident, 0, len(s.value.Pending))
	for _, incident := range s.value.Pending {
		if domain == DomainWebsite && !incident.WebsiteQueued || domain == DomainMonitor && !incident.MonitoringQueued {
			result = append(result, incident)
		}
	}
	return result
}

// MarkQueued is called only after the corresponding telemetry Queue.Enqueue
// has durably returned success. Repeating it is idempotent.
func (s *Session) MarkQueued(domain string) error {
	if s == nil || domain != DomainWebsite && domain != DomainMonitor {
		return errors.New("lifecycle delivery domain is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for index := range s.value.Pending {
		incident := &s.value.Pending[index]
		if domain == DomainWebsite && !incident.WebsiteQueued {
			incident.WebsiteQueued, changed = true, true
		}
		if domain == DomainMonitor && !incident.MonitoringQueued {
			incident.MonitoringQueued, changed = true, true
		}
	}
	if !changed {
		return nil
	}
	retained := s.value.Pending[:0]
	for _, incident := range s.value.Pending {
		if !incident.WebsiteQueued || !incident.MonitoringQueued {
			retained = append(retained, incident)
		}
	}
	s.value.Pending = retained
	return s.persist()
}

func (s *Session) MarkClean(now time.Time) error {
	if s == nil || !validUTC(now) {
		return errors.New("lifecycle clean exit time is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	value := now.UTC()
	s.value.State, s.value.CleanExitAt = "clean", &value
	return s.persist()
}

func load(filename string) (document, bool, error) {
	directory, base := filepath.Dir(filename), filepath.Base(filename)
	file, err := fsutil.OpenRegularInDirectoryNoFollow(directory, base)
	if errors.Is(err, fs.ErrNotExist) {
		return document{}, false, nil
	}
	if err != nil {
		return document{}, false, errors.New("lifecycle state file is unsafe")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maximumBytes+1))
	if err != nil || len(raw) > maximumBytes {
		return document{}, false, errors.New("lifecycle state exceeds maximum size")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value document
	if err := decoder.Decode(&value); err != nil {
		return document{}, false, errors.New("lifecycle state is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF || value.validate() != nil {
		return document{}, false, errors.New("lifecycle state is invalid")
	}
	return value, true, nil
}

func (d document) validate() error {
	if d.Version != version || (d.State != "running" && d.State != "clean") || !uuidRE.MatchString(d.BootID) || !validUTC(d.StartedAt) || len(d.Pending) > maximumEvents {
		return errors.New("invalid lifecycle state")
	}
	if d.State == "running" && d.CleanExitAt != nil || d.State == "clean" && (d.CleanExitAt == nil || !validUTC(*d.CleanExitAt) || d.CleanExitAt.Before(d.StartedAt)) {
		return errors.New("invalid lifecycle completion state")
	}
	seen := make(map[string]bool, len(d.Pending))
	for _, incident := range d.Pending {
		if !uuidRE.MatchString(incident.EventID) || !uuidRE.MatchString(incident.PreviousBootID) || !validUTC(incident.PreviousStartedAt) || !validUTC(incident.ObservedAt) || seen[incident.EventID] {
			return errors.New("invalid lifecycle incident")
		}
		seen[incident.EventID] = true
	}
	return nil
}

func (s *Session) persist() error {
	if err := s.value.validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(s.value)
	if err != nil || len(raw) > maximumBytes {
		return errors.New("encode lifecycle state")
	}
	if err := fsutil.AtomicWriteFile(s.filename, append(raw, '\n'), 0o600, true); err != nil {
		return fmt.Errorf("persist lifecycle state: %w", err)
	}
	return nil
}

func validUTC(value time.Time) bool {
	if value.IsZero() {
		return false
	}
	_, offset := value.Zone()
	return offset == 0
}
