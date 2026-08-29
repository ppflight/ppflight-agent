// Package inventory validates the website-issued mapping between a PVE guest
// and a billing service. VMID alone is never a stable customer identity.
package inventory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	SchemaVersion  = 1
	maxFileBytes   = 4 << 20
	maxAssignments = 100000
)

var safeRef = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{1,191}$`)

type Document struct {
	SchemaVersion int          `json:"schemaVersion"`
	Revision      string       `json:"revision"`
	IssuedAt      time.Time    `json:"issuedAt"`
	Assignments   []Assignment `json:"assignments"`
}

type Assignment struct {
	ServiceRef   string     `json:"serviceRef"`
	ClusterRef   string     `json:"clusterRef"`
	NodeRef      string     `json:"nodeRef,omitempty"`
	VMID         int        `json:"vmid"`
	Generation   uint64     `json:"generation"`
	InstanceUUID string     `json:"instanceUuid"`
	GuestType    string     `json:"guestType"`
	BillingState string     `json:"billingState"`
	CutoverAt    *time.Time `json:"cutoverAt,omitempty"`
}

func (a Assignment) Key() string {
	return fmt.Sprintf("%s/%s/%d/%d", a.ClusterRef, a.GuestType, a.VMID, a.Generation)
}

func (a Assignment) PVEKey() string {
	return fmt.Sprintf("%s/%s/%d", a.ClusterRef, a.GuestType, a.VMID)
}

func Parse(contents []byte, expectedClusterRef string) (Document, error) {
	if len(contents) > maxFileBytes {
		return Document{}, fmt.Errorf("assignment document exceeds %d bytes", maxFileBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var result Document
	if err := decoder.Decode(&result); err != nil {
		return Document{}, fmt.Errorf("decode assignments: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Document{}, errors.New("assignment document must contain one JSON object")
	}
	if err := result.Validate(expectedClusterRef); err != nil {
		return Document{}, err
	}
	return result, nil
}

func (d Document) Validate(expectedClusterRef string) error {
	if d.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported assignment schemaVersion %d", d.SchemaVersion)
	}
	if !safeRef.MatchString(d.Revision) {
		return errors.New("assignment revision is invalid")
	}
	if d.IssuedAt.IsZero() {
		return errors.New("assignment issuedAt is required")
	}
	if len(d.Assignments) > maxAssignments {
		return fmt.Errorf("assignment count exceeds %d", maxAssignments)
	}
	seenPVE, seenService := map[string]bool{}, map[string]bool{}
	for index, assignment := range d.Assignments {
		if err := assignment.validate(expectedClusterRef); err != nil {
			return fmt.Errorf("assignment[%d]: %w", index, err)
		}
		if seenPVE[assignment.PVEKey()] {
			return fmt.Errorf("assignment[%d]: duplicate PVE identity", index)
		}
		serviceGeneration := fmt.Sprintf("%s/%d", assignment.ServiceRef, assignment.Generation)
		if seenService[serviceGeneration] {
			return fmt.Errorf("assignment[%d]: duplicate service generation", index)
		}
		seenPVE[assignment.PVEKey()] = true
		seenService[serviceGeneration] = true
	}
	return nil
}

func (a Assignment) validate(expectedClusterRef string) error {
	for label, value := range map[string]string{
		"serviceRef": a.ServiceRef, "clusterRef": a.ClusterRef, "instanceUuid": a.InstanceUUID,
	} {
		if !safeRef.MatchString(value) {
			return fmt.Errorf("%s is invalid", label)
		}
	}
	if expectedClusterRef != "" && a.ClusterRef != expectedClusterRef {
		return fmt.Errorf("clusterRef %q does not match agent cluster %q", a.ClusterRef, expectedClusterRef)
	}
	if a.NodeRef != "" && !safeRef.MatchString(a.NodeRef) {
		return errors.New("nodeRef is invalid")
	}
	if a.VMID < 1 || a.VMID > 999999999 || a.Generation == 0 {
		return errors.New("vmid and generation must be positive")
	}
	if a.GuestType != "qemu" && a.GuestType != "lxc" {
		return errors.New("guestType must be qemu or lxc")
	}
	if a.BillingState != "disabled" && a.BillingState != "shadow" && a.BillingState != "active" {
		return errors.New("billingState must be disabled, shadow, or active")
	}
	if a.BillingState == "active" && a.CutoverAt == nil {
		return errors.New("active billing requires cutoverAt")
	}
	return nil
}

func LoadFile(filename, expectedClusterRef string) (Document, error) {
	file, err := os.Open(filename)
	if err != nil {
		return Document{}, fmt.Errorf("open assignments: %w", err)
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil {
		return Document{}, fmt.Errorf("read assignments: %w", err)
	}
	return Parse(contents, expectedClusterRef)
}

// Store provides an atomic in-memory view. A failed refresh leaves the last
// valid revision active; it never replaces valid identities with an empty map.
type Store struct {
	mu       sync.RWMutex
	document Document
	byPVE    map[string]Assignment
}

func NewStore(document Document) *Store {
	result := &Store{}
	result.Replace(document)
	return result
}

func (s *Store) Replace(document Document) {
	index := make(map[string]Assignment, len(document.Assignments))
	for _, assignment := range document.Assignments {
		index[assignment.PVEKey()] = assignment
	}
	s.mu.Lock()
	s.document, s.byPVE = document, index
	s.mu.Unlock()
}

func (s *Store) Lookup(clusterRef, guestType string, vmid int) (Assignment, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.byPVE[fmt.Sprintf("%s/%s/%d", clusterRef, guestType, vmid)]
	return value, ok
}

func (s *Store) Snapshot() Document {
	s.mu.RLock()
	defer s.mu.RUnlock()
	copyDocument := s.document
	copyDocument.Assignments = append([]Assignment(nil), s.document.Assignments...)
	sort.Slice(copyDocument.Assignments, func(i, j int) bool {
		return strings.Compare(copyDocument.Assignments[i].PVEKey(), copyDocument.Assignments[j].PVEKey()) < 0
	})
	return copyDocument
}
