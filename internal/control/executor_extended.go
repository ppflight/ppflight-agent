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
)

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
}

type BackupInventoryResult struct {
	VMID       int                   `json:"vmid"`
	GuestType  string                `json:"guestType"`
	Generation protocol.Counter      `json:"vmGeneration"`
	Items      []BackupInventoryItem `json:"items"`
}

// ConsoleSessionSecret is passed only to the ephemeral website escrow sink.
// Implementations must not persist or log this value.  JSON tags exist solely
// for the fixed HTTPS broker implementation and are never used by Receipt.
type ConsoleSessionSecret struct {
	SchemaVersion      int              `json:"schemaVersion"`
	SessionRef         string           `json:"sessionRef"`
	CommandID          string           `json:"commandId"`
	IdempotencyKey     string           `json:"idempotencyKey"`
	OperationID        string           `json:"operationId"`
	BindingID          string           `json:"bindingId"`
	DeviceID           string           `json:"deviceId"`
	AssignmentRevision protocol.Counter `json:"assignmentRevision"`
	ServiceRef         string           `json:"serviceRef"`
	InstanceUUID       string           `json:"instanceUuid"`
	Generation         protocol.Counter `json:"generation"`
	NodeRef            string           `json:"nodeRef"`
	GuestType          string           `json:"guestType"`
	VMID               int              `json:"vmid"`
	PVEUser            string           `json:"pveUser"`
	PVETicket          string           `json:"pveTicket"`
	PVECertificate     string           `json:"pveCertificate,omitempty"`
	PVEPort            int              `json:"pvePort"`
	ExpiresAt          time.Time        `json:"expiresAt"`
	OneTime            bool             `json:"oneTime"`
}

type ConsoleSessionPublication struct {
	SessionRef string    `json:"sessionRef"`
	Path       string    `json:"path"`
	ExpiresAt  time.Time `json:"expiresAt"`
	OneTime    bool      `json:"oneTime"`
}

type ConsoleSessionRevoke struct {
	SchemaVersion      int              `json:"schemaVersion"`
	SessionRef         string           `json:"sessionRef"`
	CommandID          string           `json:"commandId"`
	IdempotencyKey     string           `json:"idempotencyKey"`
	OperationID        string           `json:"operationId"`
	BindingID          string           `json:"bindingId"`
	DeviceID           string           `json:"deviceId"`
	AssignmentRevision protocol.Counter `json:"assignmentRevision"`
	ServiceRef         string           `json:"serviceRef"`
	InstanceUUID       string           `json:"instanceUuid"`
	Generation         protocol.Counter `json:"generation"`
	NodeRef            string           `json:"nodeRef"`
	GuestType          string           `json:"guestType"`
	VMID               int              `json:"vmid"`
}

func validInitialResources(command Command, value initialResourcesP) bool {
	return value.Cores >= 1 && value.Cores <= 128 && value.Sockets >= 1 && value.Sockets <= 16 &&
		value.MemoryMiB >= 128 && value.MemoryMiB <= 4194304 && value.VMGeneration == command.Identity.Generation &&
		value.CloneOperationID == command.OperationID && commandIDRE.MatchString(value.CloneOperationID) &&
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
		value.ExpectedOS.Family != "linux" && value.ExpectedOS.Family != "windows" || !validOSIdentity(value.ExpectedOS.Name) || !validOSIdentity(value.ExpectedOS.VersionID) {
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
		item := BackupInventoryItem{Storage: storage, Volume: row.Volume, SizeBytes: protocol.Counter(size), State: "ready", GuestType: command.Identity.GuestType, VMID: command.Identity.VMID, Generation: protocol.Counter(command.Identity.Generation), Restorable: size > 0, Compression: safeBackupFormat(row.Format)}
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
	result, _ := json.Marshal(map[string]any{"configured": true, "verified": true, "cores": parameters.Cores, "sockets": parameters.Sockets, "memoryMiB": parameters.MemoryMiB, "vmGeneration": protocol.Counter(parameters.VMGeneration), "templateConfigSha256": parameters.TemplateConfigSHA256})
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
		err := sink.Revoke(ctx, ConsoleSessionRevoke{SchemaVersion: 1, SessionRef: parameters.SessionRef, CommandID: command.CommandID, IdempotencyKey: command.IdempotencyKey, OperationID: command.OperationID, BindingID: command.BindingID, DeviceID: command.DeviceID, AssignmentRevision: command.AssignmentRevision, ServiceRef: command.Identity.ServiceRef, InstanceUUID: command.Identity.InstanceUUID, Generation: protocol.Counter(command.Identity.Generation), NodeRef: command.Identity.NodeRef, GuestType: command.Identity.GuestType, VMID: command.Identity.VMID})
		if err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"sessionRef": parameters.SessionRef, "revoked": true})
	}
	var parameters consoleCreateP
	_ = strictParameters(command.Parameters, &parameters)
	var response struct {
		User   string `json:"user"`
		Ticket string `json:"ticket"`
		Cert   string `json:"cert"`
		Port   int    `json:"port"`
	}
	base := fmt.Sprintf("/nodes/%s/%s/%d/vncproxy", command.Identity.NodeRef, command.Identity.GuestType, command.Identity.VMID)
	if err := client.Do(ctx, http.MethodPost, base, nil, url.Values{"websocket": {"1"}}, &response); err != nil {
		return nil, err
	}
	if response.Ticket == "" || len(response.Ticket) > 8192 || response.Port < 1 || response.Port > 65535 || response.User == "" || len(response.User) > 256 || strings.ContainsAny(response.Ticket+response.User+response.Cert, "\x00") {
		return nil, errors.New("PVE returned invalid console material")
	}
	sessionRef, err := protocol.NewID()
	if err != nil {
		return nil, err
	}
	expiresAt := now.UTC().Add(time.Duration(parameters.TTLSeconds) * time.Second)
	publication, err := sink.Publish(ctx, ConsoleSessionSecret{SchemaVersion: 1, SessionRef: sessionRef, CommandID: command.CommandID, IdempotencyKey: command.IdempotencyKey, OperationID: command.OperationID, BindingID: command.BindingID, DeviceID: command.DeviceID, AssignmentRevision: command.AssignmentRevision, ServiceRef: command.Identity.ServiceRef, InstanceUUID: command.Identity.InstanceUUID, Generation: protocol.Counter(command.Identity.Generation), NodeRef: command.Identity.NodeRef, GuestType: command.Identity.GuestType, VMID: command.Identity.VMID, PVEUser: response.User, PVETicket: response.Ticket, PVECertificate: response.Cert, PVEPort: response.Port, ExpiresAt: expiresAt, OneTime: true})
	// Drop every reference to PVE secret material before constructing Result.
	response = struct {
		User   string `json:"user"`
		Ticket string `json:"ticket"`
		Cert   string `json:"cert"`
		Port   int    `json:"port"`
	}{}
	if err != nil {
		return nil, err
	}
	if publication.SessionRef != sessionRef || publication.ExpiresAt.After(expiresAt) || publication.ExpiresAt.Before(now.UTC()) || !publication.OneTime || publication.Path == "" || len(publication.Path) > 512 || strings.ContainsAny(publication.Path, "\x00\r\n") {
		return nil, errors.New("console broker returned invalid publication")
	}
	return json.Marshal(publication)
}

func reinstallGuest(ctx context.Context, client *pve.Client, command Command) (string, json.RawMessage, error) {
	var parameters reinstallP
	_ = strictParameters(command.Parameters, &parameters)
	if err := requireStoppedNonTemplate(ctx, client, command); err != nil {
		return "", nil, err
	}
	template, err := client.TemplateInfo(ctx, parameters.TemplateGuestType, parameters.TemplateNode, parameters.TemplateVMID, parameters.TemplateRef)
	if err != nil || !strings.EqualFold(template.ConfigSHA256, parameters.TemplateConfigSHA256) {
		return "", nil, errors.New("reinstall template identity or configuration changed")
	}
	resources, err := client.ClusterResources(ctx)
	if err != nil {
		return "", nil, err
	}
	for _, resource := range resources {
		if resource.VMID == parameters.TemporaryVMID {
			return "", nil, errors.New("reinstall compensation VMID is already in use")
		}
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
	// A full clone of the current stopped VM is the compensation boundary.
	if err := waitMutation(http.MethodPost, targetBase+"/clone", url.Values{"newid": {strconv.Itoa(parameters.TemporaryVMID)}, "full": {"1"}, "target": {command.Identity.NodeRef}, "storage": {parameters.Storage}, "name": {"ppflight-reinstall-rollback-" + strconv.Itoa(command.Identity.VMID)}}, command.Identity.NodeRef); err != nil {
		return "", nil, err
	}
	replacementCreated := false
	compensate := func(_ error) error {
		if replacementCreated {
			_ = waitMutation(http.MethodPost, targetBase+"/status/stop", nil, command.Identity.NodeRef)
			_ = waitMutation(http.MethodDelete, targetBase, url.Values{"purge": {"0"}, "destroy-unreferenced-disks": {"0"}}, command.Identity.NodeRef)
		}
		restoreErr := waitMutation(http.MethodPost, temporaryBase+"/clone", url.Values{"newid": {strconv.Itoa(command.Identity.VMID)}, "full": {"1"}, "target": {command.Identity.NodeRef}, "storage": {parameters.Storage}}, command.Identity.NodeRef)
		if restoreErr != nil {
			return fmt.Errorf("%w: replacement error and compensation error", ErrReinstallIndeterminate)
		}
		if cleanupErr := waitMutation(http.MethodDelete, temporaryBase, url.Values{"purge": {"1"}, "destroy-unreferenced-disks": {"1"}}, command.Identity.NodeRef); cleanupErr != nil {
			return fmt.Errorf("%w: original VM restored but compensation clone cleanup failed", ErrReinstallIndeterminate)
		}
		return ErrReinstallRolledBack
	}
	if err := waitMutation(http.MethodDelete, targetBase, url.Values{"purge": {"0"}, "destroy-unreferenced-disks": {"0"}}, command.Identity.NodeRef); err != nil {
		_ = waitMutation(http.MethodDelete, temporaryBase, url.Values{"purge": {"1"}, "destroy-unreferenced-disks": {"1"}}, command.Identity.NodeRef)
		return "", nil, err
	}
	if err := waitMutation(http.MethodPost, templateBase+"/clone", url.Values{"newid": {strconv.Itoa(command.Identity.VMID)}, "full": {"1"}, "target": {command.Identity.NodeRef}, "storage": {parameters.Storage}}, command.Identity.NodeRef); err != nil {
		return "", nil, compensate(err)
	}
	replacementCreated = true
	resourceCommand := command
	resourceCommand.Parameters, _ = json.Marshal(initialResourcesP{Cores: parameters.Expected.Cores, Sockets: parameters.Expected.Sockets, MemoryMiB: parameters.Expected.MemoryMiB, CloneOperationID: command.OperationID, VMGeneration: command.Identity.Generation, TemplateConfigSHA256: parameters.TemplateConfigSHA256})
	if _, _, err := setInitialResources(ctx, client, resourceCommand, targetBase); err != nil {
		return "", nil, compensate(err)
	}
	for _, network := range parameters.Networks {
		networkCommand := command
		networkCommand.Parameters, _ = json.Marshal(network)
		if _, _, err := setNetwork(ctx, client, networkCommand, targetBase); err != nil {
			return "", nil, compensate(err)
		}
	}
	if err := restoreReinstallFirewall(ctx, client, command, parameters.Expected.Networks, waitMutation); err != nil {
		return "", nil, compensate(err)
	}
	cloudCommand := command
	cloudCommand.Parameters, _ = json.Marshal(parameters.CloudInit)
	if _, _, err := setCloudInit(ctx, client, cloudCommand, targetBase); err != nil {
		return "", nil, compensate(err)
	}
	resizeCommand := command
	resizeCommand.Parameters, _ = json.Marshal(resizeP{Disk: parameters.Expected.Disk.Interface, TargetGiB: &parameters.Expected.Disk.MinimumGiB})
	if _, _, err := resizeDisk(ctx, client, resizeCommand, targetBase); err != nil {
		return "", nil, compensate(err)
	}
	ioCommand := command
	ioCommand.Parameters, _ = json.Marshal(diskIOP{Disk: parameters.Expected.Disk.Interface, Limits: parameters.Expected.Disk.Limits})
	if _, _, err := setDiskLimits(ctx, client, ioCommand, targetBase); err != nil {
		return "", nil, compensate(err)
	}
	if err := waitMutation(http.MethodPost, targetBase+"/status/start", nil, command.Identity.NodeRef); err != nil {
		return "", nil, compensate(err)
	}
	timezoneCommand := command
	timezoneCommand.Parameters, _ = json.Marshal(timezoneP{Timezone: parameters.Expected.Timezone})
	if _, _, err := setGuestTimezone(ctx, client, timezoneCommand, targetBase); err != nil {
		return "", nil, compensate(err)
	}
	verifyCommand := command
	verifyCommand.Parameters, _ = json.Marshal(deliveryP{NotBefore: parameters.NotBefore, Expected: parameters.Expected})
	if _, err := verifyDelivery(ctx, client, verifyCommand); err != nil {
		return "", nil, compensate(err)
	}
	if err := verifyReinstallOS(ctx, client, command, parameters.ExpectedOS); err != nil {
		return "", nil, compensate(err)
	}
	if err := waitMutation(http.MethodDelete, temporaryBase, url.Values{"purge": {"1"}, "destroy-unreferenced-disks": {"1"}}, command.Identity.NodeRef); err != nil {
		return "", nil, fmt.Errorf("%w: replacement verified but compensation clone cleanup failed", ErrReinstallIndeterminate)
	}
	result, _ := json.Marshal(map[string]any{"reinstalled": true, "verified": true, "templateRef": parameters.TemplateRef, "templateVersion": parameters.TemplateVersion, "templateConfigSha256": parameters.TemplateConfigSHA256, "vmGeneration": protocol.Counter(parameters.VMGeneration)})
	return "", result, nil
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
