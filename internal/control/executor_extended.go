package control

// This file contains the bounded provisioning and read-only inventory actions
// added after the original control-v1 allowlist was frozen.  It deliberately
// uses only fixed PVE endpoints and typed forms; there is no endpoint, URL,
// ISO, shell, or guest-exec passthrough.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ppflight/ppflight-agent/internal/protocol"
	"github.com/ppflight/ppflight-agent/internal/pve"
)

var (
	ErrReinstallRolledBack    = errors.New("reinstall failed and the original VM was restored")
	ErrReinstallIndeterminate = errors.New("reinstall state is indeterminate and requires intervention")
	ErrReinstallPreflight     = errors.New("reinstall preflight rejected before mutation")
)

// reinstallExecutionError keeps the exact failed stage and underlying
// provider/QGA error after compensation. Older code returned only the
// ErrReinstallRolledBack sentinel, which made the website unable to explain a
// real failure even though the original VM had been restored safely.
type reinstallExecutionError struct {
	Stage string
	Cause error
}

func (e *reinstallExecutionError) Error() string {
	if e == nil || e.Cause == nil {
		return ErrReinstallRolledBack.Error()
	}
	return fmt.Sprintf("%s at %s: %v", ErrReinstallRolledBack, e.Stage, e.Cause)
}

func (e *reinstallExecutionError) Unwrap() []error {
	if e == nil || e.Cause == nil {
		return []error{ErrReinstallRolledBack}
	}
	return []error{ErrReinstallRolledBack, e.Cause}
}

func (e *reinstallExecutionError) FailureStage() string {
	if e == nil {
		return "reinstall"
	}
	return e.Stage
}

func reinstallRolledBack(stage string, cause error) error {
	if strings.TrimSpace(stage) == "" {
		stage = "reinstall"
	}
	return &reinstallExecutionError{Stage: stage, Cause: cause}
}

type reinstallP struct {
	TemplateRef          string           `json:"templateRef"`
	TemplateVersion      string           `json:"templateVersion"`
	TemplateNode         string           `json:"templateNode"`
	TemplateGuestType    string           `json:"templateGuestType"`
	TemplateVMID         int              `json:"templateVmid"`
	TemplateConfigSHA256 string           `json:"templateConfigSha256"`
	VMGeneration         uint64           `json:"vmGeneration"`
	TemporaryVMID        int              `json:"temporaryVmid"`
	Storage              string           `json:"storage"`
	NotBefore            time.Time        `json:"notBefore"`
	Expected             deliveryExpected `json:"expected"`
	ExpectedOS           reinstallOS      `json:"expectedOs"`
	Networks             []networkP       `json:"networks"`
	CloudInit            cloudInitP       `json:"cloudInit"`
	Start                *bool            `json:"start"`
}

type reinstallOS struct {
	Family    string `json:"family"`
	Name      string `json:"name"`
	VersionID string `json:"versionId"`
}

type SnapshotInventoryItem struct {
	SnapshotID  string           `json:"snapshotId"`
	Name        string           `json:"name"`
	CreatedAt   *time.Time       `json:"createdAt,omitempty"`
	State       string           `json:"state"`
	ParentID    string           `json:"parentId,omitempty"`
	HasRAMState bool             `json:"hasRamState"`
	Generation  protocol.Counter `json:"vmGeneration"`
}

type SnapshotInventoryResult struct {
	VMID       int                     `json:"vmid"`
	GuestType  string                  `json:"guestType"`
	Generation protocol.Counter        `json:"vmGeneration"`
	Items      []SnapshotInventoryItem `json:"items"`
}

type BackupInventoryItem struct {
	Storage     string           `json:"storage"`
	Volume      string           `json:"volume"`
	CreatedAt   *time.Time       `json:"createdAt,omitempty"`
	SizeBytes   protocol.Counter `json:"sizeBytes"`
	State       string           `json:"state"`
	GuestType   string           `json:"guestType"`
	VMID        int              `json:"vmid"`
	Generation  protocol.Counter `json:"vmGeneration"`
	Restorable  bool             `json:"restorable"`
	Compression string           `json:"compression,omitempty"`
	Notes       string           `json:"notes,omitempty"`
}

type BackupInventoryResult struct {
	VMID       int                   `json:"vmid"`
	GuestType  string                `json:"guestType"`
	Generation protocol.Counter      `json:"vmGeneration"`
	Items      []BackupInventoryItem `json:"items"`
}

type initialResourcesResult struct {
	Configured           bool             `json:"configured"`
	Verified             bool             `json:"verified"`
	Cores                int              `json:"cores"`
	Sockets              int              `json:"sockets"`
	MemoryMiB            int              `json:"memoryMiB"`
	VMGeneration         protocol.Counter `json:"vmGeneration"`
	TemplateRef          string           `json:"templateRef"`
	SourceVMID           int              `json:"sourceVmid"`
	TemplateConfigSHA256 string           `json:"templateConfigSha256"`
}

// ConsoleTunnelRegistration is the secret-free identity sent to the website
// broker before the Agent establishes its outbound WSS connection.
type ConsoleTunnelRegistration struct {
	SchemaVersion      int              `json:"schemaVersion"`
	Transport          string           `json:"transport"`
	SessionRef         string           `json:"sessionRef"`
	CommandID          string           `json:"commandId"`
	IdempotencyKey     string           `json:"idempotencyKey"`
	OperationID        string           `json:"operationId"`
	BindingID          string           `json:"bindingId"`
	DeviceID           string           `json:"deviceId"`
	CredentialEpoch    protocol.Counter `json:"credentialEpoch"`
	AssignmentRevision protocol.Counter `json:"assignmentRevision"`
	AgentRef           string           `json:"agentRef"`
	ClusterRef         string           `json:"clusterRef"`
	ServiceRef         string           `json:"serviceRef"`
	InstanceUUID       string           `json:"instanceUuid"`
	Generation         protocol.Counter `json:"generation"`
	NodeRef            string           `json:"nodeRef"`
	GuestType          string           `json:"guestType"`
	VMID               int              `json:"vmid"`
	ExpiresAt          time.Time        `json:"expiresAt"`
	OneTime            bool             `json:"oneTime"`
}

// ConsoleLocalEndpoint is intentionally not JSON serializable. It exists only
// long enough for the sink to authenticate the PVE localhost VNC socket.
type ConsoleLocalEndpoint struct {
	Port   int
	Ticket []byte
}

// pveConsolePort accepts both encodings emitted by supported PVE releases.
// PVE 8 may serialize the vncproxy port as a JSON string while other versions
// return a JSON number. Keep this compatibility local to the typed console
// response instead of weakening decoding for any other provider field.
type pveConsolePort int

func (p *pveConsolePort) UnmarshalJSON(raw []byte) error {
	value := strings.TrimSpace(string(raw))
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		var decoded string
		if err := json.Unmarshal(raw, &decoded); err != nil {
			return errors.New("invalid PVE console port")
		}
		value = decoded
	}
	if value == "" || len(value) > 5 {
		return errors.New("invalid PVE console port")
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return errors.New("invalid PVE console port")
		}
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("invalid PVE console port")
	}
	*p = pveConsolePort(port)
	return nil
}

type ConsoleSessionPublication struct {
	SessionRef  string    `json:"sessionRef"`
	State       string    `json:"state"`
	ExpiresAt   time.Time `json:"expiresAt"`
	BrowserPath string    `json:"browserPath"`
}

type ConsoleSessionRevoke struct {
	SchemaVersion      int              `json:"schemaVersion"`
	SessionRef         string           `json:"sessionRef"`
	CommandID          string           `json:"commandId"`
	IdempotencyKey     string           `json:"idempotencyKey"`
	OperationID        string           `json:"operationId"`
	BindingID          string           `json:"bindingId"`
	DeviceID           string           `json:"deviceId"`
	CredentialEpoch    protocol.Counter `json:"credentialEpoch"`
	AssignmentRevision protocol.Counter `json:"assignmentRevision"`
	AgentRef           string           `json:"agentRef"`
	ClusterRef         string           `json:"clusterRef"`
	ServiceRef         string           `json:"serviceRef"`
	InstanceUUID       string           `json:"instanceUuid"`
	Generation         protocol.Counter `json:"generation"`
	NodeRef            string           `json:"nodeRef"`
	GuestType          string           `json:"guestType"`
	VMID               int              `json:"vmid"`
}

func validInitialResources(command Command, value initialResourcesP) bool {
	return value.Cores >= 1 && value.Cores <= 128 && value.Sockets >= 1 && value.Sockets <= 16 &&
		value.MemoryMiB >= 128 && value.MemoryMiB <= 4194304 && uint64(value.VMGeneration) == command.Identity.Generation &&
		value.CloneOperationID != command.OperationID && commandIDRE.MatchString(value.CloneOperationID) &&
		nameRE.MatchString(value.TemplateRef) && value.SourceVMID >= 100 && value.SourceVMID <= 999999999 &&
		bodyHashRE.MatchString(value.TemplateConfigSHA256)
}

func validPasswordTarget(guestType string, value passwordP) bool {
	if value.OSFamily != "" && value.OSFamily != "linux" && value.OSFamily != "windows" {
		return false
	}
	if guestType == "lxc" {
		return value.Username == "root" && value.OSFamily != "windows" && value.Crypted != nil && !*value.Crypted
	}
	return guestType == "qemu"
}

func validReinstall(command Command, value reinstallP) bool {
	// QEMU is the only supported reinstall target in v1. LXC has materially
	// different rootfs and Cloud-Init semantics and is rejected rather than
	// being approximated with an unsafe generic restore.
	if command.Identity.GuestType != "qemu" || value.TemplateGuestType != "qemu" || value.VMGeneration != command.Identity.Generation ||
		!nameRE.MatchString(value.TemplateRef) || !nameRE.MatchString(value.TemplateVersion) || !nodeRE.MatchString(value.TemplateNode) ||
		value.TemplateVMID < 100 || value.TemplateVMID > 999999999 || value.TemporaryVMID < 100 || value.TemporaryVMID > 999999999 ||
		value.TemporaryVMID == command.Identity.VMID || value.TemporaryVMID == value.TemplateVMID || !storageRE.MatchString(value.Storage) ||
		!bodyHashRE.MatchString(value.TemplateConfigSHA256) || value.Start == nil || !*value.Start || !validCloudInit(value.CloudInit) ||
		value.ExpectedOS.Family != "linux" || !validOSIdentity(value.ExpectedOS.Name) || !validOSIdentity(value.ExpectedOS.VersionID) {
		return false
	}
	if !validDelivery(deliveryP{NotBefore: value.NotBefore, Expected: value.Expected}) || len(value.Networks) != len(value.Expected.Networks) {
		return false
	}
	expected := make(map[string]deliveryNetwork, len(value.Expected.Networks))
	for _, network := range value.Expected.Networks {
		expected[network.Interface] = network
	}
	for _, network := range value.Networks {
		match, ok := expected[network.Interface]
		if !ok || !validNetwork(network, command.Identity.GuestType) || network.Bridge == nil || network.MAC == nil || network.MTU == nil || network.Firewall == nil || network.RateMbps == nil || network.IPv4 == nil || network.IPv6 == nil ||
			*network.Bridge != match.Bridge || !strings.EqualFold(*network.MAC, match.MAC) || *network.MTU != match.MTU || *network.Firewall != *match.Firewall || *network.RateMbps != match.RateMbps || *network.IPv4 != match.IPv4 || *network.IPv6 != match.IPv6 {
			return false
		}
	}
	return true
}

func exactReinstallKeys(raw json.RawMessage) bool {
	var outer map[string]json.RawMessage
	if json.Unmarshal(raw, &outer) != nil || !hasExactKeys(outer,
		"templateRef", "templateVersion", "templateNode", "templateGuestType", "templateVmid",
		"templateConfigSha256", "vmGeneration", "temporaryVmid", "storage", "notBefore",
		"expected", "expectedOs", "networks", "cloudInit", "start") {
		return false
	}
	// Reuse the frozen delivery-contract key checker, including every nullable
	// disk limit and every network field. Missing and explicit null remain
	// distinguishable in the signed JSON contract.
	deliveryRaw, err := json.Marshal(map[string]json.RawMessage{"notBefore": outer["notBefore"], "expected": outer["expected"]})
	if err != nil || !exactDeliveryKeys(deliveryRaw) {
		return false
	}
	var expectedOS map[string]json.RawMessage
	if json.Unmarshal(outer["expectedOs"], &expectedOS) != nil || !hasExactKeys(expectedOS, "family", "name", "versionId") {
		return false
	}
	var cloudInit map[string]json.RawMessage
	if json.Unmarshal(outer["cloudInit"], &cloudInit) != nil || !hasExactKeys(cloudInit, "hostname", "username", "password", "passwordFormat", "sshAuthorizedKeys", "qgaEnabled") {
		return false
	}
	var networks []map[string]json.RawMessage
	if json.Unmarshal(outer["networks"], &networks) != nil {
		return false
	}
	for _, network := range networks {
		if !hasExactKeys(network, "interface", "bridge", "mac", "vlan", "mtu", "firewall", "rateMbps", "ipv4", "ipv6", "gateway4", "gateway6") {
			return false
		}
	}
	return true
}

func validOSIdentity(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func readInventoryAction(ctx context.Context, client *pve.Client, command Command) (json.RawMessage, error) {
	switch command.Action {
	case "snapshot.list", "snapshot.get":
		return readSnapshots(ctx, client, command)
	case "backup.list", "backup.get":
		return readBackups(ctx, client, command)
	default:
		return nil, ErrUnsupported
	}
}

func readSnapshots(ctx context.Context, client *pve.Client, command Command) (json.RawMessage, error) {
	base := fmt.Sprintf("/nodes/%s/%s/%d/snapshot", command.Identity.NodeRef, command.Identity.GuestType, command.Identity.VMID)
	var rows []struct {
		Name     string          `json:"name"`
		SnapName string          `json:"snapname"`
		Parent   string          `json:"parent"`
		SnapTime json.RawMessage `json:"snaptime"`
		VMState  json.RawMessage `json:"vmstate"`
	}
	if err := client.Do(ctx, http.MethodGet, base, nil, nil, &rows); err != nil {
		return nil, err
	}
	items := make([]SnapshotInventoryItem, 0, len(rows))
	for _, row := range rows {
		name := strings.TrimSpace(row.Name)
		if name == "" {
			name = strings.TrimSpace(row.SnapName)
		}
		if name == "current" {
			continue
		}
		if !snapRE.MatchString(name) || row.Parent != "" && !snapRE.MatchString(row.Parent) {
			return nil, errors.New("PVE returned an invalid snapshot identity")
		}
		item := SnapshotInventoryItem{SnapshotID: name, Name: name, State: "ready", ParentID: row.Parent, Generation: protocol.Counter(command.Identity.Generation)}
		if stamp, ok := boundedUnixTime(row.SnapTime); ok {
			item.CreatedAt = &stamp
		}
		if ram, ok := boolish(row.VMState); ok {
			item.HasRAMState = ram
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].CreatedAt == nil || items[j].CreatedAt == nil {
			return items[i].Name < items[j].Name
		}
		return items[i].CreatedAt.After(*items[j].CreatedAt)
	})
	if command.Action == "snapshot.get" {
		var parameters snapshotGetP
		_ = strictParameters(command.Parameters, &parameters)
		for _, item := range items {
			if item.Name == parameters.Name {
				return json.Marshal(SnapshotInventoryResult{VMID: command.Identity.VMID, GuestType: command.Identity.GuestType, Generation: protocol.Counter(command.Identity.Generation), Items: []SnapshotInventoryItem{item}})
			}
		}
		return nil, errors.New("snapshot was not found")
	}
	var parameters snapshotListP
	_ = strictParameters(command.Parameters, &parameters)
	if len(items) > parameters.Limit {
		items = items[:parameters.Limit]
	}
	return json.Marshal(SnapshotInventoryResult{VMID: command.Identity.VMID, GuestType: command.Identity.GuestType, Generation: protocol.Counter(command.Identity.Generation), Items: items})
}

func readBackups(ctx context.Context, client *pve.Client, command Command) (json.RawMessage, error) {
	storage := ""
	wanted := ""
	limit := 1
	if command.Action == "backup.list" {
		var p backupListP
		_ = strictParameters(command.Parameters, &p)
		storage, limit = p.Storage, p.Limit
	} else {
		var p backupGetP
		_ = strictParameters(command.Parameters, &p)
		storage, wanted = p.Storage, p.Volume
	}
	path := fmt.Sprintf("/nodes/%s/storage/%s/content", command.Identity.NodeRef, storage)
	query := url.Values{"content": {"backup"}, "vmid": {strconv.Itoa(command.Identity.VMID)}}
	var rows []struct {
		Volume      string          `json:"volid"`
		Content     string          `json:"content"`
		Format      string          `json:"format"`
		Notes       string          `json:"notes"`
		VMID        int             `json:"vmid"`
		Size        json.RawMessage `json:"size"`
		CreatedTime json.RawMessage `json:"ctime"`
	}
	if err := client.Do(ctx, http.MethodGet, path, query, nil, &rows); err != nil {
		return nil, err
	}
	items := make([]BackupInventoryItem, 0, len(rows))
	for _, row := range rows {
		if row.Content != "backup" || row.VMID != command.Identity.VMID || !validBackupVolume(row.Volume) || !strings.HasPrefix(row.Volume, storage+":") {
			continue
		}
		size, ok := rawUint64(row.Size)
		if !ok {
			return nil, errors.New("PVE returned an invalid backup size")
		}
		if !validBackupNotesTemplate(row.Notes) {
			return nil, errors.New("PVE returned invalid backup notes")
		}
		item := BackupInventoryItem{Storage: storage, Volume: row.Volume, SizeBytes: protocol.Counter(size), State: "ready", GuestType: command.Identity.GuestType, VMID: command.Identity.VMID, Generation: protocol.Counter(command.Identity.Generation), Restorable: size > 0, Compression: safeBackupFormat(row.Format), Notes: row.Notes}
		if stamp, ok := boundedUnixTime(row.CreatedTime); ok {
			item.CreatedAt = &stamp
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].CreatedAt == nil || items[j].CreatedAt == nil {
			return items[i].Volume < items[j].Volume
		}
		return items[i].CreatedAt.After(*items[j].CreatedAt)
	})
	if wanted != "" {
		for _, item := range items {
			if item.Volume == wanted {
				return json.Marshal(BackupInventoryResult{VMID: command.Identity.VMID, GuestType: command.Identity.GuestType, Generation: protocol.Counter(command.Identity.Generation), Items: []BackupInventoryItem{item}})
			}
		}
		return nil, errors.New("backup was not found")
	}
	if len(items) > limit {
		items = items[:limit]
	}
	return json.Marshal(BackupInventoryResult{VMID: command.Identity.VMID, GuestType: command.Identity.GuestType, Generation: protocol.Counter(command.Identity.Generation), Items: items})
}

func safeBackupFormat(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "raw", "tar", "vma", "zst", "gz", "lzo":
		return value
	default:
		return ""
	}
}

func boundedUnixTime(raw json.RawMessage) (time.Time, bool) {
	value, ok := rawUint64(raw)
	if !ok || value > uint64(time.Now().UTC().AddDate(10, 0, 0).Unix()) {
		return time.Time{}, false
	}
	return time.Unix(int64(value), 0).UTC(), true
}

func rawUint64(raw json.RawMessage) (uint64, bool) {
	var number json.Number
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if decoder.Decode(&number) != nil {
		return 0, false
	}
	value, err := strconv.ParseUint(number.String(), 10, 64)
	return value, err == nil
}

func setInitialResources(ctx context.Context, client *pve.Client, command Command, base string) (string, json.RawMessage, error) {
	var parameters initialResourcesP
	_ = strictParameters(command.Parameters, &parameters)
	if err := requireStoppedNonTemplate(ctx, client, command); err != nil {
		return "", nil, err
	}
	current, err := guestConfig(ctx, client, command)
	if err != nil {
		return "", nil, err
	}
	form := url.Values{
		"cores":   {strconv.Itoa(parameters.Cores)},
		"sockets": {strconv.Itoa(parameters.Sockets)},
		"memory":  {strconv.Itoa(parameters.MemoryMiB)},
	}
	if current.Digest != "" {
		form.Set("digest", current.Digest)
	}
	upid, _, err := doPVE(ctx, client, http.MethodPut, base+"/config", form)
	if err != nil {
		return upid, nil, err
	}
	if upid != "" {
		if err := waitPVEUPID(ctx, client, command.Identity.NodeRef, upid); err != nil {
			return upid, nil, err
		}
	}
	verified, err := guestConfig(ctx, client, command)
	if err != nil {
		return upid, nil, err
	}
	for key, expected := range map[string]int{"cores": parameters.Cores, "sockets": parameters.Sockets, "memory": parameters.MemoryMiB} {
		actual, ok := configInt(verified.Raw, key)
		if !ok || actual != expected {
			return upid, nil, errors.New("initial resource readback does not match")
		}
	}
	result, _ := json.Marshal(initialResourcesResult{Configured: true, Verified: true, Cores: parameters.Cores, Sockets: parameters.Sockets, MemoryMiB: parameters.MemoryMiB, VMGeneration: parameters.VMGeneration, TemplateRef: parameters.TemplateRef, SourceVMID: parameters.SourceVMID, TemplateConfigSHA256: parameters.TemplateConfigSHA256})
	return "", result, nil
}

func requireStoppedNonTemplate(ctx context.Context, client *pve.Client, command Command) error {
	resources, err := client.ClusterResources(ctx)
	if err != nil {
		return err
	}
	for _, resource := range resources {
		if resource.Node == command.Identity.NodeRef && resource.Type == command.Identity.GuestType && resource.VMID == command.Identity.VMID {
			if resource.Template != 0 || strings.ToLower(strings.TrimSpace(resource.Status)) != "stopped" {
				return errors.New("VM must be a stopped, non-template clone")
			}
			return nil
		}
	}
	return errors.New("assigned VM was not found")
}

func waitPVEUPID(ctx context.Context, client *pve.Client, node, upid string) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, err := resolvePVEStatus(ctx, client, node, upid)
		if err != nil {
			return err
		}
		if status.Status == "stopped" {
			if !strings.EqualFold(status.ExitStatus, "OK") {
				return errors.New("PVE task failed")
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func executePowerTransition(ctx context.Context, client *pve.Client, command Command, base string) (string, json.RawMessage, error) {
	if command.Identity.GuestType != "qemu" {
		return "", nil, errors.New("suspend and resume are unavailable for LXC")
	}
	wanted := strings.TrimPrefix(command.Action, "vm.")
	upid, _, err := doPVE(ctx, client, http.MethodPost, base+"/status/"+wanted, nil)
	if err != nil {
		return upid, nil, err
	}
	if upid != "" {
		if err := waitPVEUPID(ctx, client, command.Identity.NodeRef, upid); err != nil {
			return upid, nil, err
		}
	}
	current, err := client.GuestCurrent(ctx, command.Identity.GuestType, command.Identity.NodeRef, command.Identity.VMID)
	if err != nil {
		return upid, nil, err
	}
	qmpStatus, _ := configString(current.Raw, "qmpstatus")
	if wanted == "suspend" && !strings.EqualFold(qmpStatus, "paused") {
		return upid, nil, errors.New("suspend power-state readback does not match")
	}
	if wanted == "resume" && (strings.ToLower(strings.TrimSpace(current.Status)) != "running" || strings.EqualFold(qmpStatus, "paused")) {
		return upid, nil, errors.New("resume power-state readback does not match")
	}
	powerState := "running"
	if wanted == "suspend" {
		powerState = "suspended"
	}
	result, _ := json.Marshal(map[string]any{"powerState": powerState, "verified": true})
	return "", result, nil
}

func executeConsoleSession(ctx context.Context, client *pve.Client, sink ConsoleSessionSink, command Command, now time.Time) (json.RawMessage, error) {
	if command.Action == "vm.console.revoke-session" {
		var parameters consoleRevokeP
		_ = strictParameters(command.Parameters, &parameters)
		err := sink.Revoke(ctx, ConsoleSessionRevoke{SchemaVersion: 1, SessionRef: parameters.SessionRef, CommandID: command.CommandID, IdempotencyKey: command.IdempotencyKey, OperationID: command.OperationID, BindingID: command.BindingID, DeviceID: command.DeviceID, CredentialEpoch: command.CredentialEpoch, AssignmentRevision: command.AssignmentRevision, AgentRef: command.AgentRef, ClusterRef: command.Identity.ClusterRef, ServiceRef: command.Identity.ServiceRef, InstanceUUID: command.Identity.InstanceUUID, Generation: protocol.Counter(command.Identity.Generation), NodeRef: command.Identity.NodeRef, GuestType: command.Identity.GuestType, VMID: command.Identity.VMID})
		if err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"sessionRef": parameters.SessionRef, "revoked": true})
	}
	var parameters consoleCreateP
	_ = strictParameters(command.Parameters, &parameters)
	sessionRef, err := protocol.NewID()
	if err != nil {
		return nil, err
	}
	if err := sink.Reserve(sessionRef); err != nil {
		return nil, fmt.Errorf("console session capacity: %w", err)
	}
	published := false
	defer func() {
		if !published {
			sink.Release(sessionRef)
		}
	}()
	var response struct {
		Ticket string         `json:"ticket"`
		Port   pveConsolePort `json:"port"`
	}
	base := fmt.Sprintf("/nodes/%s/%s/%d/vncproxy", command.Identity.NodeRef, command.Identity.GuestType, command.Identity.VMID)
	if err := client.Do(ctx, http.MethodPost, base, nil, url.Values{"websocket": {"1"}}, &response); err != nil {
		return nil, err
	}
	if response.Ticket == "" || len(response.Ticket) > 8192 || response.Port < 1 || response.Port > 65535 || strings.ContainsAny(response.Ticket, "\x00") {
		return nil, errors.New("PVE returned invalid console material")
	}
	ticket := []byte(response.Ticket)
	response.Ticket = ""
	defer func() {
		for index := range ticket {
			ticket[index] = 0
		}
	}()
	// The website console registration contract uses canonical RFC3339 UTC
	// seconds. time.Time would otherwise preserve the executor clock's
	// fractional nanoseconds and PVE would succeed only for the broker to reject
	// the registration as a non-canonical timestamp.
	expiresAt := now.UTC().Truncate(time.Second).Add(time.Duration(parameters.TTLSeconds) * time.Second)
	registration := ConsoleTunnelRegistration{SchemaVersion: 1, Transport: "agent-reverse-wss-v1", SessionRef: sessionRef, CommandID: command.CommandID, IdempotencyKey: command.IdempotencyKey, OperationID: command.OperationID, BindingID: command.BindingID, DeviceID: command.DeviceID, CredentialEpoch: command.CredentialEpoch, AssignmentRevision: command.AssignmentRevision, AgentRef: command.AgentRef, ClusterRef: command.Identity.ClusterRef, ServiceRef: command.Identity.ServiceRef, InstanceUUID: command.Identity.InstanceUUID, Generation: protocol.Counter(command.Identity.Generation), NodeRef: command.Identity.NodeRef, GuestType: command.Identity.GuestType, VMID: command.Identity.VMID, ExpiresAt: expiresAt, OneTime: true}
	port := int(response.Port)
	response.Port = 0
	publication, err := sink.Publish(ctx, registration, ConsoleLocalEndpoint{Port: port, Ticket: ticket})
	if err != nil {
		return nil, err
	}
	if publication.SessionRef != sessionRef || publication.State != "ready" || publication.ExpiresAt.After(expiresAt) || publication.ExpiresAt.Before(now.UTC()) || publication.BrowserPath == "" || len(publication.BrowserPath) > 512 || strings.ContainsAny(publication.BrowserPath, "\x00\r\n") || !strings.HasPrefix(publication.BrowserPath, "/") {
		return nil, errors.New("console broker returned invalid publication")
	}
	published = true
	return json.Marshal(publication)
}

func reinstallGuest(ctx context.Context, client, readClient *pve.Client, command Command, readyWait, pollInterval time.Duration) (string, json.RawMessage, error) {
	var parameters reinstallP
	_ = strictParameters(command.Parameters, &parameters)
	// Reinstall becomes destructive after the compensation clone preflight. Its
	// fixed cloud-init and timezone guest-exec calls must therefore resolve a
	// supported PVE form contract before any clone, stop or delete operation.
	if _, err := client.QGAExecTransport(ctx); err != nil {
		return "", nil, fmt.Errorf("%w: QGA exec transport unavailable: %v", ErrReinstallPreflight, err)
	}
	resources, err := client.ClusterResources(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("%w: assigned VM inventory unavailable: %v", ErrReinstallPreflight, err)
	}
	originalRunning, err := reinstallTargetPowerState(resources, command)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v", ErrReinstallPreflight, err)
	}
	for _, resource := range resources {
		if resource.VMID == parameters.TemporaryVMID {
			return "", nil, fmt.Errorf("%w: compensation VMID is already in use", ErrReinstallPreflight)
		}
	}
	template, err := client.TemplateInfo(ctx, parameters.TemplateGuestType, parameters.TemplateNode, parameters.TemplateVMID, parameters.TemplateRef)
	if err != nil {
		return "", nil, fmt.Errorf("%w: template inspection failed: %v", ErrReinstallPreflight, err)
	}
	if !strings.EqualFold(template.ConfigSHA256, parameters.TemplateConfigSHA256) {
		return "", nil, fmt.Errorf("%w: template identity or configuration changed", ErrReinstallPreflight)
	}
	targetBase := fmt.Sprintf("/nodes/%s/qemu/%d", command.Identity.NodeRef, command.Identity.VMID)
	temporaryBase := fmt.Sprintf("/nodes/%s/qemu/%d", command.Identity.NodeRef, parameters.TemporaryVMID)
	templateBase := fmt.Sprintf("/nodes/%s/qemu/%d", parameters.TemplateNode, parameters.TemplateVMID)
	waitMutation := func(method, path string, form url.Values, node string) error {
		upid, _, mutationErr := doPVE(ctx, client, method, path, form)
		if mutationErr != nil {
			return mutationErr
		}
		if upid != "" {
			return waitPVEUPID(ctx, client, node, upid)
		}
		return nil
	}
	resourceExists := func(vmid int) (bool, error) {
		current, inventoryErr := client.ClusterResources(ctx)
		if inventoryErr != nil {
			return false, inventoryErr
		}
		for _, resource := range current {
			if resource.VMID == vmid {
				return true, nil
			}
		}
		return false, nil
	}
	restorePower := func() error {
		current, currentErr := client.GuestCurrent(ctx, command.Identity.GuestType, command.Identity.NodeRef, command.Identity.VMID)
		if currentErr != nil {
			return currentErr
		}
		running := strings.EqualFold(strings.TrimSpace(current.Status), "running")
		if originalRunning && !running {
			return waitMutation(http.MethodPost, targetBase+"/status/start", nil, command.Identity.NodeRef)
		}
		if !originalRunning && running {
			return waitMutation(http.MethodPost, targetBase+"/status/stop", nil, command.Identity.NodeRef)
		}
		return nil
	}
	cleanupTemporary := func() error {
		exists, inventoryErr := resourceExists(parameters.TemporaryVMID)
		if inventoryErr != nil {
			return inventoryErr
		}
		if !exists {
			return nil
		}
		return waitMutation(http.MethodDelete, temporaryBase, url.Values{"purge": {"1"}, "destroy-unreferenced-disks": {"1"}}, command.Identity.NodeRef)
	}
	rollbackBeforeTargetDelete := func(stage string, cause error) error {
		if cleanupErr := cleanupTemporary(); cleanupErr != nil {
			return fmt.Errorf("%w: compensation clone cleanup failed", ErrReinstallIndeterminate)
		}
		if powerErr := restorePower(); powerErr != nil {
			return fmt.Errorf("%w: original VM power restoration failed", ErrReinstallIndeterminate)
		}
		return reinstallRolledBack(stage, cause)
	}
	if originalRunning {
		if err := waitMutation(http.MethodPost, targetBase+"/status/shutdown", nil, command.Identity.NodeRef); err != nil {
			if powerErr := restorePower(); powerErr != nil {
				return "", nil, fmt.Errorf("%w: shutdown failed and original VM power could not be verified", ErrReinstallIndeterminate)
			}
			return "", nil, reinstallRolledBack("shutdown_original", err)
		}
	}
	// A full clone of the current stopped VM is the compensation boundary.
	if err := waitMutation(http.MethodPost, targetBase+"/clone", url.Values{"newid": {strconv.Itoa(parameters.TemporaryVMID)}, "full": {"1"}, "target": {command.Identity.NodeRef}, "storage": {parameters.Storage}, "name": {"ppflight-reinstall-rollback-" + strconv.Itoa(command.Identity.VMID)}}, command.Identity.NodeRef); err != nil {
		return "", nil, rollbackBeforeTargetDelete("create_compensation_clone", err)
	}
	compensate := func(stage string, cause error) error {
		targetExists, inventoryErr := resourceExists(command.Identity.VMID)
		if inventoryErr != nil {
			return fmt.Errorf("%w: replacement state could not be inspected", ErrReinstallIndeterminate)
		}
		if targetExists {
			_ = waitMutation(http.MethodPost, targetBase+"/status/stop", nil, command.Identity.NodeRef)
			if deleteErr := waitMutation(http.MethodDelete, targetBase, url.Values{"purge": {"0"}, "destroy-unreferenced-disks": {"0"}}, command.Identity.NodeRef); deleteErr != nil {
				return fmt.Errorf("%w: replacement cleanup failed", ErrReinstallIndeterminate)
			}
		}
		restoreErr := waitMutation(http.MethodPost, temporaryBase+"/clone", url.Values{"newid": {strconv.Itoa(command.Identity.VMID)}, "full": {"1"}, "target": {command.Identity.NodeRef}, "storage": {parameters.Storage}}, command.Identity.NodeRef)
		if restoreErr != nil {
			return fmt.Errorf("%w: replacement error and compensation error", ErrReinstallIndeterminate)
		}
		// PVE deliberately assigns fresh MAC addresses to every QEMU clone.  A
		// compensation clone is therefore not the original signed VM identity
		// until every website-owned network is replayed and read back.  Restoring
		// power or deleting the compensation source before this proof would turn
		// a recoverable replacement failure into a live VM whose NICs no longer
		// match the signed assignment (and would also disable safe metering and
		// IP-filter verification).
		if networkErr := restoreReinstallCompensationNetworks(ctx, client, readClient, command, targetBase, parameters); networkErr != nil {
			return fmt.Errorf("%w: %v", ErrReinstallIndeterminate, networkErr)
		}
		if powerErr := restorePower(); powerErr != nil {
			return fmt.Errorf("%w: original VM restored but power restoration failed", ErrReinstallIndeterminate)
		}
		if cleanupErr := waitMutation(http.MethodDelete, temporaryBase, url.Values{"purge": {"1"}, "destroy-unreferenced-disks": {"1"}}, command.Identity.NodeRef); cleanupErr != nil {
			return fmt.Errorf("%w: original VM restored but compensation clone cleanup failed", ErrReinstallIndeterminate)
		}
		return reinstallRolledBack(stage, cause)
	}
	if err := waitMutation(http.MethodDelete, targetBase, url.Values{"purge": {"0"}, "destroy-unreferenced-disks": {"0"}}, command.Identity.NodeRef); err != nil {
		targetExists, inventoryErr := resourceExists(command.Identity.VMID)
		if inventoryErr != nil {
			return "", nil, fmt.Errorf("%w: target delete result could not be inspected", ErrReinstallIndeterminate)
		}
		if targetExists {
			return "", nil, rollbackBeforeTargetDelete("delete_original", err)
		}
		return "", nil, compensate("delete_original", err)
	}
	if err := waitMutation(http.MethodPost, templateBase+"/clone", url.Values{"newid": {strconv.Itoa(command.Identity.VMID)}, "full": {"1"}, "target": {command.Identity.NodeRef}, "storage": {parameters.Storage}}, command.Identity.NodeRef); err != nil {
		return "", nil, compensate("clone_replacement", err)
	}
	resourceCommand := command
	resourceCommand.Parameters, _ = json.Marshal(initialResourcesP{Cores: parameters.Expected.Cores, Sockets: parameters.Expected.Sockets, MemoryMiB: parameters.Expected.MemoryMiB, CloneOperationID: command.OperationID, TemplateRef: parameters.TemplateRef, SourceVMID: parameters.TemplateVMID, VMGeneration: protocol.Counter(command.Identity.Generation), TemplateConfigSHA256: parameters.TemplateConfigSHA256})
	if _, _, err := setInitialResources(ctx, client, resourceCommand, targetBase); err != nil {
		return "", nil, compensate("set_resources", err)
	}
	for _, network := range parameters.Networks {
		networkCommand := command
		networkCommand.Parameters, _ = json.Marshal(network)
		if _, _, err := setNetwork(ctx, client, networkCommand, targetBase); err != nil {
			return "", nil, compensate("set_network", err)
		}
	}
	if err := restoreReinstallFirewall(ctx, client, command, parameters.Expected.Networks, waitMutation); err != nil {
		return "", nil, compensate("restore_firewall", err)
	}
	cloudCommand := command
	cloudCommand.Parameters, _ = json.Marshal(parameters.CloudInit)
	if _, _, err := setCloudInit(ctx, client, cloudCommand, targetBase); err != nil {
		return "", nil, compensate("set_cloud_init", err)
	}
	resizeCommand := command
	resizeCommand.Parameters, _ = json.Marshal(resizeP{Disk: parameters.Expected.Disk.Interface, TargetGiB: &parameters.Expected.Disk.MinimumGiB})
	if _, _, err := resizeDisk(ctx, client, resizeCommand, targetBase); err != nil {
		return "", nil, compensate("resize_disk", err)
	}
	ioCommand := command
	ioCommand.Parameters, _ = json.Marshal(diskIOP{Disk: parameters.Expected.Disk.Interface, Limits: parameters.Expected.Disk.Limits})
	if _, _, err := setDiskLimits(ctx, client, ioCommand, targetBase); err != nil {
		return "", nil, compensate("set_disk_io", err)
	}
	if err := waitMutation(http.MethodPost, targetBase+"/status/start", nil, command.Identity.NodeRef); err != nil {
		return "", nil, compensate("start_replacement", err)
	}
	if err := waitForReinstallReadiness(ctx, client, readClient, command, targetBase, parameters, readyWait, pollInterval); err != nil {
		return "", nil, compensate("verify_replacement", err)
	}
	if err := waitMutation(http.MethodDelete, temporaryBase, url.Values{"purge": {"1"}, "destroy-unreferenced-disks": {"1"}}, command.Identity.NodeRef); err != nil {
		return "", nil, fmt.Errorf("%w: replacement verified but compensation clone cleanup failed", ErrReinstallIndeterminate)
	}
	result, _ := json.Marshal(map[string]any{"reinstalled": true, "verified": true, "templateRef": parameters.TemplateRef, "templateVersion": parameters.TemplateVersion, "templateConfigSha256": parameters.TemplateConfigSHA256, "vmGeneration": protocol.Counter(parameters.VMGeneration)})
	return "", result, nil
}

func restoreReinstallCompensationNetworks(ctx context.Context, client, readClient *pve.Client, command Command, targetBase string, parameters reinstallP) error {
	for _, network := range parameters.Networks {
		networkCommand := command
		networkCommand.Parameters, _ = json.Marshal(network)
		if _, _, err := setNetwork(ctx, client, networkCommand, targetBase); err != nil {
			return fmt.Errorf("restored VM signed network %s could not be reapplied: %v", network.Interface, err)
		}
	}
	config, err := readClient.GuestConfig(ctx, command.Identity.GuestType, command.Identity.NodeRef, command.Identity.VMID)
	if err != nil {
		return fmt.Errorf("restored VM signed network readback failed: %v", err)
	}
	for _, expected := range parameters.Expected.Networks {
		value, exists := configString(config.Raw, expected.Interface)
		if !exists || !networkMatches(config.Raw, value, expected) {
			return fmt.Errorf("restored VM signed network %s does not match", expected.Interface)
		}
		if *expected.Firewall {
			if err := verifyExpectedIPFilter(ctx, readClient, command, expected.Interface, expected.IPFilterCIDRs); err != nil {
				return fmt.Errorf("restored VM signed network %s firewall proof failed: %v", expected.Interface, err)
			}
		} else if err := verifyGuestFirewallDisabled(ctx, readClient, command); err != nil {
			return fmt.Errorf("restored VM firewall proof failed: %v", err)
		}
	}
	return nil
}

func waitForReinstallReadiness(ctx context.Context, client, readClient *pve.Client, command Command, targetBase string, parameters reinstallP, readyWait, pollInterval time.Duration) error {
	if readyWait == 0 {
		readyWait = defaultReinstallReadyWait
	}
	if pollInterval <= 0 {
		pollInterval = defaultReinstallPollInterval
	}
	readinessCtx := ctx
	cancelReadiness := func() {}
	if readyWait > 0 {
		readinessCtx, cancelReadiness = context.WithTimeout(ctx, readyWait)
	}
	defer cancelReadiness()
	slog.Info("reinstall replacement verification started",
		"operationId", command.OperationID,
		"node", command.Identity.NodeRef,
		"vmid", command.Identity.VMID,
		"readinessBudgetMs", max(readyWait.Milliseconds(), 0),
	)
	timezoneCommand := command
	timezoneCommand.Parameters, _ = json.Marshal(timezoneP{Timezone: parameters.Expected.Timezone})
	verifyCommand := command
	verifyCommand.Parameters, _ = json.Marshal(deliveryP{NotBefore: parameters.NotBefore, Expected: parameters.Expected})
	cloudInitReady := false
	timezoneVerified := false
	verify := func() error {
		// QGA can become available while cloud-init is still applying the
		// template defaults. Wait for cloud-init's durable final state before
		// setting the signed timezone; otherwise cloud-init may overwrite a
		// successfully verified timedatectl change moments later.
		if !cloudInitReady {
			// cloud-init documents 0 as clean completion, 2 as completion with
			// recoverable errors, and 1 as completion with an unrecoverable
			// cloud-init error. Exit 1 still means the boot process settled, so
			// continue only into the full signed delivery proof below. That proof
			// fails closed on every required resource, QGA, network, firewall,
			// timezone and OS fact instead of treating cloud-init's aggregate
			// status as a substitute for the actual delivery contract.
			exitCode, err := runGuestCommandExitCode(readinessCtx, client, targetBase, "/usr/bin/cloud-init", "status", "--wait")
			if err != nil {
				return err
			}
			cloudInitHadError, statusErr := cloudInitTerminalStatus(exitCode)
			if statusErr != nil {
				return statusErr
			}
			if cloudInitHadError {
				slog.Warn("cloud-init settled with an error; continuing strict replacement verification",
					"operationId", command.OperationID,
					"node", command.Identity.NodeRef,
					"vmid", command.Identity.VMID,
					"exitCode", exitCode,
				)
			} else {
				slog.Info("cloud-init settled",
					"operationId", command.OperationID,
					"node", command.Identity.NodeRef,
					"vmid", command.Identity.VMID,
					"exitCode", exitCode,
				)
			}
			cloudInitReady = true
		}
		if !timezoneVerified {
			if _, _, err := setGuestTimezone(readinessCtx, client, timezoneCommand, targetBase); err != nil {
				return err
			}
			timezoneVerified = true
			slog.Info("reinstall replacement timezone verified",
				"operationId", command.OperationID,
				"node", command.Identity.NodeRef,
				"vmid", command.Identity.VMID,
			)
		}
		if _, err := verifyDelivery(readinessCtx, readClient, verifyCommand); err != nil {
			return err
		}
		if err := verifyReinstallOS(readinessCtx, readClient, command, parameters.ExpectedOS); err != nil {
			return err
		}
		slog.Info("reinstall replacement delivery verified",
			"operationId", command.OperationID,
			"node", command.Identity.NodeRef,
			"vmid", command.Identity.VMID,
		)
		return nil
	}
	lastErr := verify()
	if lastErr == nil || readyWait < 0 || !reinstallReadinessRetryable(lastErr) {
		return lastErr
	}
	if readinessCtx.Err() != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("reinstall readiness deadline exceeded: %w", lastErr)
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-readinessCtx.Done():
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("reinstall readiness deadline exceeded: %w", lastErr)
		case <-ticker.C:
			lastErr = verify()
			if lastErr == nil || !reinstallReadinessRetryable(lastErr) {
				return lastErr
			}
		}
	}
}

// cloudInitTerminalStatus distinguishes a settled cloud-init run from an
// invalid guest-exec result. A cloud-init exit 1 is not itself delivery
// success; it merely permits the stronger signed replacement proof to run.
func cloudInitTerminalStatus(exitCode int) (hadError bool, err error) {
	switch exitCode {
	case 0, 2:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, fmt.Errorf("guest cloud-init readiness command failed with exit code %d", exitCode)
	}
}

func reinstallReadinessRetryable(err error) bool {
	if err == nil {
		return false
	}
	var httpErr *pve.HTTPError
	if errors.As(err, &httpErr) && (httpErr.StatusCode == http.StatusUnauthorized || httpErr.StatusCode == http.StatusForbidden) {
		return false
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "invalid pid") || strings.Contains(message, "invalid status") || strings.Contains(message, "timezone command failed") || strings.Contains(message, "os identity does not match") {
		return false
	}
	switch deliveryFailureCheck(err) {
	case "config_cores", "config_sockets", "config_memory", "disk_missing", "disk_size", "disk_io", "network_config", "firewall":
		return false
	default:
		return true
	}
}

func reinstallTargetPowerState(resources []pve.Resource, command Command) (bool, error) {
	for _, resource := range resources {
		if resource.Node != command.Identity.NodeRef || resource.Type != command.Identity.GuestType || resource.VMID != command.Identity.VMID {
			continue
		}
		if resource.Template != 0 {
			return false, errors.New("assigned VM is a template")
		}
		switch strings.ToLower(strings.TrimSpace(resource.Status)) {
		case "running":
			return true, nil
		case "stopped":
			return false, nil
		default:
			return false, errors.New("assigned VM power state is unknown")
		}
	}
	return false, errors.New("assigned VM was not found")
}

func restoreReinstallFirewall(ctx context.Context, client *pve.Client, command Command, networks []deliveryNetwork, waitMutation func(string, string, url.Values, string) error) error {
	base := fmt.Sprintf("/nodes/%s/%s/%d/firewall", command.Identity.NodeRef, command.Identity.GuestType, command.Identity.VMID)
	enabled := len(networks) > 0 && networks[0].Firewall != nil && *networks[0].Firewall
	// Keep enforcement off until every signed host CIDR exists. A NIC may
	// already have firewall=1 after config restore, but guest enable=0 prevents
	// an incomplete IPFilter set becoming the live policy.
	if err := waitMutation(http.MethodPut, base+"/options", url.Values{
		"enable":     {"0"},
		"policy_in":  {"ACCEPT"},
		"policy_out": {"ACCEPT"},
		"macfilter":  {"1"},
	}, command.Identity.NodeRef); err != nil {
		return err
	}
	if !enabled {
		return nil
	}
	for _, network := range networks {
		name := "ipfilter-" + network.Interface
		if err := waitMutation(http.MethodPost, base+"/ipset", url.Values{"name": {name}}, command.Identity.NodeRef); err != nil {
			return err
		}
		for _, cidr := range network.IPFilterCIDRs {
			if err := waitMutation(http.MethodPost, base+"/ipset/"+name, url.Values{"cidr": {cidr}, "nomatch": {"0"}}, command.Identity.NodeRef); err != nil {
				return err
			}
		}
	}
	return waitMutation(http.MethodPut, base+"/options", url.Values{
		"enable":     {"1"},
		"policy_in":  {"ACCEPT"},
		"policy_out": {"ACCEPT"},
		"macfilter":  {"1"},
	}, command.Identity.NodeRef)
}

func verifyReinstallOS(ctx context.Context, client *pve.Client, command Command, expected reinstallOS) error {
	observation, err := client.ProbeGuestAgent(ctx, command.Identity.NodeRef, command.Identity.VMID)
	if err != nil || observation.Availability["os"] != pve.Available || observation.OS == nil {
		return errors.New("reinstall OS identity is unavailable")
	}
	actualName := strings.ToLower(strings.TrimSpace(observation.OS.Name))
	actualPretty := strings.ToLower(strings.TrimSpace(observation.OS.PrettyName))
	expectedName := strings.ToLower(expected.Name)
	if (actualName != expectedName && !strings.Contains(actualPretty, expectedName)) || !strings.EqualFold(strings.TrimSpace(observation.OS.VersionID), expected.VersionID) {
		return errors.New("reinstall OS identity does not match")
	}
	return nil
}
