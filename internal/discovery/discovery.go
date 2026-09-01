// Package discovery exposes a fixed, read-only PVE discovery protocol for the
// command worker. It deliberately has no facility for a caller to supply an
// HTTP method or PVE API path.
package discovery

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ppflight/ppflight-agent/internal/pve"
)

const (
	PhaseVersion     = "version"
	PhasePermissions = "permissions"
	PhaseNodes       = "nodes"
	PhaseStorage     = "storage"
	PhaseTemplates   = "templates"
	PhaseNetworks    = "networks"
	PhaseCapacity    = "capacity"
	PhaseFirewall    = "firewall"
	PhaseReadiness   = "readiness"

	defaultLimit = 20
	maxLimit     = 50
)

// Request is the complete, typed input accepted from a command thread.
// NodeRef is required by storage, capacity and node-network discovery. For
// networks without NodeRef, the result contains the cluster SDN/IPAM catalog.
type Request struct {
	OperationID string `json:"operationId"`
	Phase       string `json:"phase"`
	NodeRef     string `json:"nodeRef,omitempty"`
	Cursor      string `json:"cursor,omitempty"`
	Limit       int    `json:"limit,omitempty"`
}

// Result is safe to return to the website after a command thread has waited
// for Discover to finish. ErrorCode is a stable code; transport and PVE error
// text are intentionally not copied into the response.
type Result struct {
	OperationID string    `json:"operationId"`
	Phase       string    `json:"phase"`
	ObservedAt  time.Time `json:"observedAt"`
	Complete    bool      `json:"complete"`
	NextCursor  string    `json:"nextCursor,omitempty"`
	Data        Data      `json:"data"`
	ErrorCode   string    `json:"errorCode,omitempty"`
}

// Data is a tagged union keyed by Result.Phase. Only the field for the
// requested phase is populated, avoiding untyped map or raw JSON payloads.
type Data struct {
	Version     *pve.Version           `json:"version,omitempty"`
	Permissions []PermissionPath       `json:"permissions,omitempty"`
	Nodes       []pve.Node             `json:"nodes,omitempty"`
	Storage     []pve.Storage          `json:"storage,omitempty"`
	Templates   []pve.TemplateInfo     `json:"templates,omitempty"`
	Networks    []pve.NetworkInterface `json:"networks,omitempty"`
	SDN         []pve.SDNConfig        `json:"sdn,omitempty"`
	Capacity    *Capacity              `json:"capacity,omitempty"`
	Firewall    []FirewallScope        `json:"firewall,omitempty"`
	Readiness   *Readiness             `json:"readiness,omitempty"`
}

type PermissionPath struct {
	Path       string   `json:"path"`
	Privileges []string `json:"privileges"`
}

type Capacity struct {
	NodeRef string         `json:"nodeRef"`
	Status  pve.NodeStatus `json:"status"`
	Storage []pve.Storage  `json:"storage"`
}

// FirewallScope contains cluster, node or guest policy metadata. IP-set
// member values are deliberately excluded; only set names are disclosed.
type FirewallScope struct {
	Scope     string               `json:"scope"`
	NodeRef   string               `json:"nodeRef,omitempty"`
	GuestKind string               `json:"guestKind,omitempty"`
	VMID      int                  `json:"vmid,omitempty"`
	Options   *pve.FirewallOptions `json:"options,omitempty"`
	Rules     []pve.FirewallRule   `json:"rules,omitempty"`
	IPSets    []pve.FirewallIPSet  `json:"ipsets,omitempty"`
	ErrorCode string               `json:"errorCode,omitempty"`
}

type Readiness struct {
	Ready bool            `json:"ready"`
	Nodes []NodeReadiness `json:"nodes"`
}

type NodeReadiness struct {
	NodeRef string `json:"nodeRef"`
	Status  string `json:"status"`
	Ready   bool   `json:"ready"`
}

// Service is intended to be called synchronously by the existing command
// worker: ctx cancellation bounds the wait, and every outcome is returned in a
// Result rather than requiring the website to reach PVE directly.
type Service struct {
	client *pve.Client
	now    func() time.Time
}

func New(client *pve.Client) *Service {
	return &Service{client: client, now: time.Now}
}

var operationID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// Discover performs one bounded discovery phase using only fixed PVE GET
// endpoints. It never returns a Go error: callers can persist Result directly.
func (s *Service) Discover(ctx context.Context, request Request) Result {
	result := Result{OperationID: request.OperationID, Phase: request.Phase, ObservedAt: s.clock().UTC(), Complete: true}
	if s == nil || s.client == nil || !operationID.MatchString(request.OperationID) || !validPhase(request.Phase) || !validNode(request.NodeRef) {
		result.ErrorCode = "INVALID_REQUEST"
		return result
	}
	offset, limit, ok := page(request.Cursor, request.Limit)
	if !ok {
		result.ErrorCode = "INVALID_REQUEST"
		return result
	}

	switch request.Phase {
	case PhaseVersion:
		v, err := s.client.Version(ctx)
		if err != nil {
			return result.fail(err)
		}
		result.Data.Version = &v
	case PhasePermissions:
		v, err := s.client.EffectivePermissions(ctx)
		if err != nil {
			return result.fail(err)
		}
		values := permissionPaths(v)
		result.Data.Permissions, result.NextCursor, result.Complete = window(values, offset, limit)
	case PhaseNodes:
		v, err := s.client.Nodes(ctx)
		if err != nil {
			return result.fail(err)
		}
		if request.NodeRef != "" {
			v = onlyNode(v, request.NodeRef)
		}
		result.Data.Nodes, result.NextCursor, result.Complete = window(v, offset, limit)
	case PhaseStorage:
		if request.NodeRef == "" {
			return result.invalid()
		}
		v, err := s.client.NodeStorage(ctx, request.NodeRef)
		if err != nil {
			return result.fail(err)
		}
		result.Data.Storage, result.NextCursor, result.Complete = window(v, offset, limit)
	case PhaseTemplates:
		resources, err := s.client.ClusterResourcesPage(ctx, offset, limit)
		if err != nil {
			return result.fail(err)
		}
		for _, resource := range resources {
			kind, ok := resourceKind(resource)
			if !ok || resource.Template == 0 || (request.NodeRef != "" && resource.Node != request.NodeRef) {
				continue
			}
			info, infoErr := s.client.TemplateInfo(ctx, kind, resource.Node, resource.VMID, resource.Name)
			if infoErr != nil {
				return result.fail(infoErr)
			}
			result.Data.Templates = append(result.Data.Templates, info)
		}
		result.NextCursor, result.Complete = sourcePage(offset, limit, len(resources))
	case PhaseNetworks:
		if request.NodeRef == "" {
			v, err := s.client.ClusterSDN(ctx)
			if err != nil {
				return result.fail(err)
			}
			result.Data.SDN, result.NextCursor, result.Complete = window(v, offset, limit)
		} else {
			v, err := s.client.NodeNetworks(ctx, request.NodeRef)
			if err != nil {
				return result.fail(err)
			}
			result.Data.Networks, result.NextCursor, result.Complete = window(v, offset, limit)
		}
	case PhaseCapacity:
		if request.NodeRef == "" {
			return result.invalid()
		}
		status, err := s.client.NodeStatus(ctx, request.NodeRef)
		if err != nil {
			return result.fail(err)
		}
		storage, err := s.client.NodeStorage(ctx, request.NodeRef)
		if err != nil {
			return result.fail(err)
		}
		pageStorage, next, complete := window(storage, offset, limit)
		result.Data.Capacity = &Capacity{NodeRef: request.NodeRef, Status: status, Storage: pageStorage}
		result.NextCursor, result.Complete = next, complete
	case PhaseFirewall:
		s.discoverFirewall(ctx, request, offset, limit, &result)
	case PhaseReadiness:
		s.discoverReadiness(ctx, request, offset, limit, &result)
	}
	return result
}

func (s *Service) discoverFirewall(ctx context.Context, request Request, offset, limit int, result *Result) {
	cluster := s.firewallScope(ctx, pve.FirewallRef{}, "cluster")
	result.Data.Firewall = append(result.Data.Firewall, cluster)
	if cluster.ErrorCode != "" {
		result.ErrorCode = cluster.ErrorCode
	}
	if request.NodeRef == "" {
		return
	}
	node := s.firewallScope(ctx, pve.FirewallRef{Node: request.NodeRef}, "node")
	result.Data.Firewall = append(result.Data.Firewall, node)
	if node.ErrorCode != "" && result.ErrorCode == "" {
		result.ErrorCode = node.ErrorCode
	}
	resources, err := s.client.ClusterResourcesPage(ctx, offset, limit)
	if err != nil {
		result.ErrorCode, result.Complete = errorCode(err), true
		return
	}
	for _, resource := range resources {
		kind, ok := resourceKind(resource)
		if !ok || resource.Node != request.NodeRef {
			continue
		}
		guest := s.firewallScope(ctx, pve.FirewallRef{Node: resource.Node, Kind: kind, VMID: resource.VMID}, "guest")
		result.Data.Firewall = append(result.Data.Firewall, guest)
		if guest.ErrorCode != "" && result.ErrorCode == "" {
			result.ErrorCode = guest.ErrorCode
		}
	}
	result.NextCursor, result.Complete = sourcePage(offset, limit, len(resources))
}

func (s *Service) firewallScope(ctx context.Context, ref pve.FirewallRef, scope string) FirewallScope {
	value := FirewallScope{Scope: scope, NodeRef: ref.Node, GuestKind: ref.Kind, VMID: ref.VMID}
	options, err := s.client.FirewallOptions(ctx, ref)
	if err != nil {
		value.ErrorCode = errorCode(err)
		return value
	}
	value.Options = &options
	rules, err := s.client.FirewallRules(ctx, ref)
	if err != nil {
		value.ErrorCode = errorCode(err)
		return value
	}
	value.Rules = rules
	ipsets, err := s.client.FirewallIPSets(ctx, ref)
	if err != nil {
		value.ErrorCode = errorCode(err)
		return value
	}
	value.IPSets = ipsets
	return value
}

func (s *Service) discoverReadiness(ctx context.Context, request Request, offset, limit int, result *Result) {
	readiness := &Readiness{Ready: true}
	if request.NodeRef != "" {
		nodes, err := s.client.Nodes(ctx)
		if err != nil {
			result.ErrorCode = errorCode(err)
			return
		}
		matched := onlyNode(nodes, request.NodeRef)
		if len(matched) == 0 {
			result.ErrorCode = "PVE_NOT_FOUND"
			return
		}
		status, err := s.client.NodeStatus(ctx, request.NodeRef)
		if err != nil {
			result.ErrorCode = errorCode(err)
			return
		}
		ready := matched[0].Status == "online" && status.PVEVersion != ""
		readiness.Ready = ready
		readiness.Nodes = []NodeReadiness{{NodeRef: request.NodeRef, Status: matched[0].Status, Ready: ready}}
		result.Data.Readiness = readiness
		return
	}
	nodes, err := s.client.Nodes(ctx)
	if err != nil {
		result.ErrorCode = errorCode(err)
		return
	}
	paged, next, complete := window(nodes, offset, limit)
	readiness.Ready = complete && len(nodes) > 0
	for _, node := range paged {
		ready := node.Status == "online"
		readiness.Nodes = append(readiness.Nodes, NodeReadiness{NodeRef: node.Node, Status: node.Status, Ready: ready})
		if !ready {
			readiness.Ready = false
		}
	}
	result.Data.Readiness, result.NextCursor, result.Complete = readiness, next, complete
}

func (s *Service) clock() time.Time {
	if s != nil && s.now != nil {
		return s.now()
	}
	return time.Now()
}
func (r Result) fail(err error) Result { r.ErrorCode, r.Complete = errorCode(err), true; return r }
func (r Result) invalid() Result       { r.ErrorCode, r.Complete = "INVALID_REQUEST", true; return r }

func validPhase(phase string) bool {
	switch phase {
	case PhaseVersion, PhasePermissions, PhaseNodes, PhaseStorage, PhaseTemplates, PhaseNetworks, PhaseCapacity, PhaseFirewall, PhaseReadiness:
		return true
	}
	return false
}
func validNode(node string) bool {
	return node == "" || (strings.TrimSpace(node) == node && !strings.ContainsAny(node, "/\\\x00") && len(node) <= 128)
}
func page(cursor string, requested int) (int, int, bool) {
	limit := requested
	if limit == 0 {
		limit = defaultLimit
	}
	if limit < 1 || limit > maxLimit {
		return 0, 0, false
	}
	if cursor == "" {
		return 0, limit, true
	}
	offset, err := strconv.Atoi(cursor)
	return offset, limit, err == nil && offset >= 0
}
func sourcePage(offset, limit, count int) (string, bool) {
	if count < limit {
		return "", true
	}
	return strconv.Itoa(offset + count), false
}
func resourceKind(r pve.Resource) (string, bool) {
	if r.Type == "qemu" || r.Type == "lxc" {
		return r.Type, true
	}
	parts := strings.Split(r.ID, "/")
	if len(parts) == 2 && (parts[0] == "qemu" || parts[0] == "lxc") {
		return parts[0], true
	}
	return "", false
}
func onlyNode(nodes []pve.Node, wanted string) []pve.Node {
	for _, node := range nodes {
		if node.Node == wanted {
			return []pve.Node{node}
		}
	}
	return nil
}
func permissionPaths(value pve.Permissions) []PermissionPath {
	paths := make([]string, 0, len(value.Paths))
	for path := range value.Paths {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	result := make([]PermissionPath, 0, len(paths))
	for _, path := range paths {
		var privileges []string
		for privilege, allowed := range value.Paths[path] {
			if allowed != 0 {
				privileges = append(privileges, privilege)
			}
		}
		sort.Strings(privileges)
		result = append(result, PermissionPath{Path: path, Privileges: privileges})
	}
	return result
}
func errorCode(err error) string {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "PVE_UNAVAILABLE"
	}
	if errors.Is(err, pve.ErrTemplateBaselineInvalid) {
		return "PVE_ERROR"
	}
	var httpErr *pve.HTTPError
	if errors.As(err, &httpErr) {
		switch httpErr.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return "PVE_FORBIDDEN"
		case http.StatusNotFound:
			return "PVE_NOT_FOUND"
		default:
			return "PVE_ERROR"
		}
	}
	return "PVE_UNAVAILABLE"
}

func window[T any](values []T, offset, limit int) ([]T, string, bool) {
	if offset >= len(values) {
		return []T{}, "", true
	}
	end := offset + limit
	if end > len(values) {
		end = len(values)
	}
	page := values[offset:end]
	if end == len(values) {
		return page, "", true
	}
	return page, strconv.Itoa(end), false
}
