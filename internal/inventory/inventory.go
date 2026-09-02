// Package inventory validates the website-issued mapping between a PVE guest
// and a billing service. VMID alone is never a stable customer identity.
package inventory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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

var (
	safeRef       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{1,191}$`)
	networkRef    = regexp.MustCompile(`^net(?:[0-9]|[12][0-9]|3[01])$`)
	attachmentRef = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)
	canonicalMAC  = regexp.MustCompile(`(?i)^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$`)
	actionRef     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}(?:\.[a-z][a-z0-9-]{0,31}){1,3}$`)
)

type Document struct {
	SchemaVersion  int          `json:"schemaVersion"`
	Revision       string       `json:"revision"`
	IssuedAt       time.Time    `json:"issuedAt"`
	AllowedActions []string     `json:"allowedActions,omitempty"`
	Assignments    []Assignment `json:"assignments"`
}

type Assignment struct {
	ServiceRef   string       `json:"serviceRef"`
	ClusterRef   string       `json:"clusterRef"`
	NodeRef      string       `json:"nodeRef,omitempty"`
	VMID         int          `json:"vmid"`
	Generation   uint64       `json:"generation"`
	InstanceUUID string       `json:"instanceUuid"`
	GuestType    string       `json:"guestType"`
	BillingState string       `json:"billingState"`
	CutoverAt    *time.Time   `json:"cutoverAt,omitempty"`
	NICBindings  []NICBinding `json:"nicBindings,omitempty"`
}

// NICBinding is the website-authoritative network role and policy for one
// stable PVE netN interface. PVE/QGA enumeration order is never an identity.
// VLAN and MTU are pointers so an explicit zero cannot be confused with a
// missing value during policy reconciliation.
type NICBinding struct {
	Interface      string `json:"interface"`
	Role           string `json:"role"`
	Primary        bool   `json:"primary"`
	Metered        bool   `json:"metered"`
	Monitoring     bool   `json:"monitoring"`
	ExpectedMAC    string `json:"expectedMac"`
	Bridge         string `json:"bridge,omitempty"`
	VNet           string `json:"vnet,omitempty"`
	VLAN           *int   `json:"vlan,omitempty"`
	MTU            *int   `json:"mtu,omitempty"`
	IPFilterPolicy string `json:"ipFilterPolicy"`
}

// Capability is deliberately typed so the website and APP can distinguish a
// safe aggregate counter from a merely present PVE counter.
type Capability struct {
	Supported bool   `json:"supported"`
	Reason    string `json:"reason,omitempty"`
	Source    string `json:"source,omitempty"`
}

func (a Assignment) Key() string {
	return fmt.Sprintf("%s/%s/%d/%d", a.ClusterRef, a.GuestType, a.VMID, a.Generation)
}

func (a Assignment) PVEKey() string {
	return fmt.Sprintf("%s/%s/%d", a.ClusterRef, a.GuestType, a.VMID)
}

// AggregateMeteringCapability reports whether PVE guest-level netin/netout can
// satisfy the signed NIC policy. It is safe only for exactly one public,
// metered NIC; with multiple NICs, private traffic cannot be separated.
func (a Assignment) AggregateMeteringCapability() Capability {
	if len(a.NICBindings) == 0 {
		return Capability{Reason: "nic_binding_required", Source: "pve-guest-aggregate"}
	}
	if len(a.NICBindings) != 1 {
		return Capability{Reason: "multi_nic_pve_aggregate_only", Source: "pve-guest-aggregate"}
	}
	binding := a.NICBindings[0]
	if binding.Role != "public" || !binding.Metered {
		return Capability{Reason: "no_metered_public_nic", Source: "pve-guest-aggregate"}
	}
	return Capability{Supported: true, Source: "pve-guest-aggregate"}
}

// PerNICMeteringCapability reports whether the signed assignment has enough
// stable netN/MAC policy to use PVE host tap/veth counters. Unlike the legacy
// guest aggregate, this remains safe for mixed public/private guests because
// only public, metered bindings are emitted.
func (a Assignment) PerNICMeteringCapability() Capability {
	if len(a.NICBindings) == 0 {
		return Capability{Reason: "nic_binding_required", Source: "pve-host-netdev"}
	}
	public := 0
	for _, binding := range a.NICBindings {
		if binding.Role == "public" && binding.Metered {
			public++
		}
		if binding.Role == "private" && binding.Metered {
			return Capability{Reason: "private_nic_must_not_be_metered", Source: "pve-host-netdev"}
		}
	}
	if public == 0 {
		return Capability{Reason: "public_metered_nic_required", Source: "pve-host-netdev"}
	}
	return Capability{Supported: true, Source: "pve-host-netdev"}
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
	if d.AllowedActions != nil {
		if len(d.AllowedActions) == 0 || len(d.AllowedActions) > 64 {
			return errors.New("assignment allowedActions must contain 1-64 actions")
		}
		seenActions := make(map[string]struct{}, len(d.AllowedActions))
		for index, action := range d.AllowedActions {
			if !actionRef.MatchString(action) {
				return fmt.Errorf("allowedActions[%d] is invalid", index)
			}
			if _, exists := seenActions[action]; exists {
				return fmt.Errorf("allowedActions[%d] is duplicated", index)
			}
			seenActions[action] = struct{}{}
		}
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
	if err := validateNICBindings(a.NICBindings); err != nil {
		return err
	}
	return nil
}

func validateNICBindings(bindings []NICBinding) error {
	if len(bindings) > 32 {
		return errors.New("nicBindings exceeds 32 interfaces")
	}
	if len(bindings) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(bindings))
	primary, monitoring, public := 0, 0, 0
	for index, binding := range bindings {
		if !networkRef.MatchString(binding.Interface) {
			return fmt.Errorf("nicBindings[%d].interface must be net0-net31", index)
		}
		if _, ok := seen[binding.Interface]; ok {
			return fmt.Errorf("nicBindings[%d].interface is duplicated", index)
		}
		seen[binding.Interface] = struct{}{}
		if binding.Role != "public" && binding.Role != "private" {
			return fmt.Errorf("nicBindings[%d].role must be public or private", index)
		}
		if binding.Role == "public" {
			public++
			if !binding.Metered {
				return fmt.Errorf("nicBindings[%d].public interface must be metered", index)
			}
		} else if binding.Metered {
			return fmt.Errorf("nicBindings[%d].private interface must not be metered", index)
		}
		if binding.Primary {
			primary++
			if binding.Role != "public" {
				return fmt.Errorf("nicBindings[%d].primary must have public role", index)
			}
		}
		if binding.Monitoring {
			monitoring++
		}
		if !validMAC(binding.ExpectedMAC) {
			return fmt.Errorf("nicBindings[%d].expectedMac must be a canonical unicast MAC", index)
		}
		if binding.Bridge != "" && binding.VNet != "" {
			return fmt.Errorf("nicBindings[%d] cannot set both bridge and vnet", index)
		}
		if binding.Bridge == "" && binding.VNet == "" {
			return fmt.Errorf("nicBindings[%d] requires bridge or vnet", index)
		}
		if binding.Bridge != "" && !attachmentRef.MatchString(binding.Bridge) || binding.VNet != "" && !attachmentRef.MatchString(binding.VNet) {
			return fmt.Errorf("nicBindings[%d] has an invalid bridge or vnet", index)
		}
		if binding.VLAN != nil && (*binding.VLAN < 0 || *binding.VLAN > 4094) {
			return fmt.Errorf("nicBindings[%d].vlan must be 0-4094", index)
		}
		if binding.MTU != nil && (*binding.MTU < 576 || *binding.MTU > 9216) {
			return fmt.Errorf("nicBindings[%d].mtu must be 576-9216", index)
		}
		if binding.IPFilterPolicy != "required" && binding.IPFilterPolicy != "disabled" {
			return fmt.Errorf("nicBindings[%d].ipFilterPolicy must be required or disabled", index)
		}
	}
	if primary != 1 || public == 0 {
		return errors.New("nicBindings requires exactly one primary public interface")
	}
	if monitoring != 1 {
		return errors.New("nicBindings requires exactly one monitoring interface")
	}
	return nil
}

func validMAC(value string) bool {
	if !canonicalMAC.MatchString(value) {
		return false
	}
	parsed, err := net.ParseMAC(value)
	if err != nil || len(parsed) != 6 || parsed[0]&1 != 0 {
		return false
	}
	allZero := true
	for _, part := range parsed {
		allZero = allZero && part == 0
	}
	return !allZero
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
	copyDocument.AllowedActions = append([]string(nil), s.document.AllowedActions...)
	copyDocument.Assignments = append([]Assignment(nil), s.document.Assignments...)
	sort.Slice(copyDocument.Assignments, func(i, j int) bool {
		return strings.Compare(copyDocument.Assignments[i].PVEKey(), copyDocument.Assignments[j].PVEKey()) < 0
	})
	return copyDocument
}
