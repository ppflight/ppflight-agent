package control

// This file is the only place that turns a signed control action into a PVE
// write.  It intentionally has no escape hatch for paths, arbitrary forms or
// command execution.
import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ppflight/ppflight-agent/internal/discovery"
	"github.com/ppflight/ppflight-agent/internal/protocol"
	"github.com/ppflight/ppflight-agent/internal/pve"
	"github.com/ppflight/ppflight-agent/internal/upgradecontract"
)

var (
	ErrUnsupported           = errors.New("controlled PVE action is unsupported")
	ErrResultTooLarge        = errors.New("controlled PVE result is too large")
	ErrQGAUnavailable        = errors.New("QEMU guest agent is unavailable")
	ErrQGACommandUnsupported = errors.New("QEMU guest agent command is unsupported")
)

const maxControlResultBytes = 1 << 20
const maxJSONDepth = 64

var (
	nodeRE        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	netRE         = regexp.MustCompile(`^net([0-9]|[12][0-9]|3[01])$`)
	diskRE        = regexp.MustCompile(`^(scsi|virtio|sata|ide)[0-9]{1,2}$`)
	nameRE        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	macRE         = regexp.MustCompile(`(?i)^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)
	deliveryMACRE = regexp.MustCompile(`^[0-9A-F]{2}(:[0-9A-F]{2}){5}$`)
	storageRE     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	snapRE        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$`)
	upidRE        = regexp.MustCompile(`^UPID:[A-Za-z0-9@!+,:._-]{1,511}$`)
	portListRE    = regexp.MustCompile(`^[0-9]{1,5}(-[0-9]{1,5})?(,[0-9]{1,5}(-[0-9]{1,5})?)*$`)
)

type Executor struct {
	// Client is the mutation client and should use the dedicated control token.
	Client *pve.Client
	// ReadClient uses the least-privilege collection token for task status and
	// QGA capability preflight. It never becomes a mutation fallback.
	ReadClient          *pve.Client
	Discovery           *discovery.Service
	Capabilities        GuestCapabilityChecker
	Mode                string
	ProductionExecution bool
	UpgradeSubmitter    UpgradeSubmitter
}

// UpgradeSubmitter stages an already verified agent.upgrade command for the
// independently privileged systemd helper. It must not replace or restart the
// running binary in the control poller's process.
type UpgradeSubmitter interface {
	Prepare(context.Context, Command) (string, error)
}

type GuestCapability string

const (
	GuestCapabilityAvailable   GuestCapability = "available"
	GuestCapabilityUnavailable GuestCapability = "unavailable"
	GuestCapabilityUnsupported GuestCapability = "unsupported"
)

// GuestCapabilityChecker is read-only and must never invoke the capability it
// checks. It exists so production can use PVE's QGA info endpoint while tests
// and future cached capability sources can be injected explicitly.
type GuestCapabilityChecker interface {
	GuestAgentCommand(ctx context.Context, nodeRef string, vmid int, command string) (GuestCapability, error)
}

func (e Executor) Execute(ctx context.Context, command Command, now time.Time) (Receipt, error) {
	id, err := protocol.NewID()
	if err != nil {
		return Receipt{}, err
	}
	r := Receipt{SchemaVersion: SchemaVersion, ReceiptID: id, CommandID: command.CommandID, OperationID: command.OperationID, AgentRef: command.AgentRef, ExecutionMode: e.Mode, StartedAt: now.UTC(), OperatorRef: command.OperatorRef}
	finish := func(receiptErr error) (Receipt, error) {
		if r.FinishedAt.IsZero() || r.FinishedAt.Before(r.StartedAt) {
			r.FinishedAt = r.StartedAt
		}
		ApplyReceiptCompatibility(&r)
		return r, receiptErr
	}
	if err := validateParameters(command); err != nil {
		r.State, r.Code, r.DryRun, r.FinishedAt = "rejected", "INVALID_PARAMETERS", e.Mode != "production" || !e.ProductionExecution, time.Now().UTC()
		if errors.Is(err, ErrUnsupported) {
			r.Code = "UNSUPPORTED"
		}
		return finish(err)
	}
	if command.Action == "pve.discover" {
		if e.Discovery == nil {
			r.State, r.Code, r.FinishedAt = "failed", "EXECUTOR_NOT_CONFIGURED", time.Now().UTC()
			return finish(errors.New("PVE discovery service is unavailable"))
		}
		request, err := discoveryRequest(command)
		if err != nil {
			r.State, r.Code, r.FinishedAt = "rejected", "INVALID_PARAMETERS", time.Now().UTC()
			return finish(err)
		}
		result, err := json.Marshal(e.Discovery.Discover(ctx, request))
		if err != nil {
			r.State, r.Code, r.FinishedAt = "failed", "PVE_RESULT_INDETERMINATE", time.Now().UTC()
			return finish(err)
		}
		if len(result) > maxControlResultBytes {
			r.State, r.Code, r.FinishedAt = "failed", "RESULT_TOO_LARGE", time.Now().UTC()
			return finish(ErrResultTooLarge)
		}
		r.State, r.Code, r.Result, r.FinishedAt = "succeeded", "SUCCEEDED", result, time.Now().UTC()
		return finish(nil)
	}
	if command.Action == "task.status" {
		client := e.ReadClient
		if client == nil {
			client = e.Client // compatibility for injected test executors
		}
		if client == nil {
			r.State, r.Code, r.FinishedAt = "failed", "EXECUTOR_NOT_CONFIGURED", time.Now().UTC()
			return finish(errors.New("PVE read client is unavailable"))
		}
		result, err := readTaskStatus(ctx, client, command)
		r.FinishedAt = time.Now().UTC()
		if err != nil {
			r.State, r.Code = "failed", "PVE_TASK_STATUS_FAILED"
			return finish(err)
		}
		r.State, r.Code, r.Result = "succeeded", "SUCCEEDED", result
		return finish(nil)
	}
	if command.Action == "vm.verify-delivery" {
		client := e.ReadClient
		if client == nil {
			client = e.Client
		}
		if client == nil {
			r.State, r.Code, r.FinishedAt = "failed", "EXECUTOR_NOT_CONFIGURED", time.Now().UTC()
			return finish(errors.New("PVE read client is unavailable"))
		}
		result, verifyErr := verifyDelivery(ctx, client, command)
		r.FinishedAt = time.Now().UTC()
		if verifyErr != nil {
			r.State, r.Code = "failed", "DELIVERY_NOT_READY"
			return finish(verifyErr)
		}
		r.State, r.Code, r.Result = "succeeded", "SUCCEEDED", result
		return finish(nil)
	}
	if command.Action == "firewall.guest.verify-ipfilter" {
		client := e.ReadClient
		if client == nil {
			client = e.Client
		}
		if client == nil {
			r.State, r.Code, r.FinishedAt = "failed", "EXECUTOR_NOT_CONFIGURED", time.Now().UTC()
			return finish(errors.New("PVE read client is unavailable"))
		}
		result, verifyErr := verifyGuestIPFilter(ctx, client, command)
		r.FinishedAt = time.Now().UTC()
		if verifyErr != nil {
			r.State, r.Code = "failed", "IPFILTER_NOT_READY"
			return finish(verifyErr)
		}
		r.State, r.Code, r.Result = "succeeded", "SUCCEEDED", result
		return finish(nil)
	}
	if command.Action == "firewall.guest.verify-ipfilter-sets" {
		client := e.ReadClient
		if client == nil {
			client = e.Client
		}
		if client == nil {
			r.State, r.Code, r.FinishedAt = "failed", "EXECUTOR_NOT_CONFIGURED", time.Now().UTC()
			return finish(errors.New("PVE read client is unavailable"))
		}
		result, verifyErr := verifyGuestIPFilterSets(ctx, client, command)
		r.FinishedAt = time.Now().UTC()
		if verifyErr != nil {
			r.State, r.Code = "failed", "IPFILTER_SETS_NOT_READY"
			return finish(verifyErr)
		}
		r.State, r.Code, r.Result = "succeeded", "SUCCEEDED", result
		return finish(nil)
	}
	if e.Mode != "production" || !e.ProductionExecution {
		r.State, r.Code, r.DryRun, r.FinishedAt = "dry_run", "DRY_RUN", true, time.Now().UTC()
		return finish(nil)
	}
	if command.Action == "agent.upgrade" {
		if e.UpgradeSubmitter == nil {
			r.State, r.Code, r.FinishedAt = "failed", "UPGRADE_HELPER_UNAVAILABLE", time.Now().UTC()
			return finish(errors.New("agent upgrade helper is unavailable"))
		}
		upgradeID, prepareErr := e.UpgradeSubmitter.Prepare(ctx, command)
		r.FinishedAt = time.Now().UTC()
		if prepareErr != nil {
			r.State, r.Code = "failed", "UPGRADE_PREPARE_FAILED"
			return finish(prepareErr)
		}
		r.State, r.Code, r.AgentUpgradeID = "submitted", "AGENT_UPGRADE_SUBMITTED", upgradeID
		return finish(nil)
	}
	if e.Client == nil {
		r.State, r.Code, r.FinishedAt = "failed", "EXECUTOR_NOT_CONFIGURED", time.Now().UTC()
		return finish(errors.New("PVE control client is unavailable"))
	}
	if command.Action == "vm.reset-password" || command.Action == "vm.set-timezone" {
		wanted := "guest-set-user-password"
		if command.Action == "vm.set-timezone" {
			wanted = "guest-exec"
		}
		capability, capabilityErr := e.guestAgentCommand(ctx, command, wanted)
		r.FinishedAt = time.Now().UTC()
		switch {
		case capabilityErr != nil, capability == GuestCapabilityUnavailable:
			r.State, r.Code = "rejected", "QGA_UNAVAILABLE"
			return finish(ErrQGAUnavailable)
		case capability == GuestCapabilityUnsupported:
			r.State, r.Code = "rejected", "QGA_COMMAND_UNSUPPORTED"
			return finish(ErrQGACommandUnsupported)
		case capability != GuestCapabilityAvailable:
			r.State, r.Code = "rejected", "QGA_CAPABILITY_INDETERMINATE"
			return finish(ErrQGAUnavailable)
		}
	}
	upid, result, err := executePVE(ctx, e.Client, command)
	r.PVETaskUPID, r.FinishedAt = upid, time.Now().UTC()
	if err != nil {
		var httpErr *pve.HTTPError
		if errors.As(err, &httpErr) {
			r.State, r.Code = "failed", "PVE_ACTION_REJECTED"
		} else {
			r.State, r.Code = "indeterminate", "PVE_RESULT_INDETERMINATE"
		}
		return finish(err)
	}
	if upid != "" {
		r.State, r.Code = "submitted", "PVE_TASK_SUBMITTED"
	} else {
		r.State, r.Code = "succeeded", "SUCCEEDED"
	}
	if command.Action != "vm.reset-password" {
		r.Result = result
	}
	return finish(nil)
}

func (e Executor) guestAgentCommand(ctx context.Context, command Command, name string) (GuestCapability, error) {
	checker := e.Capabilities
	if checker == nil {
		client := e.ReadClient
		if client == nil {
			client = e.Client // compatibility for isolated/test executors
		}
		checker = pveGuestCapabilityChecker{client: client}
	}
	return checker.GuestAgentCommand(ctx, command.Identity.NodeRef, command.Identity.VMID, name)
}

type pveGuestCapabilityChecker struct{ client *pve.Client }

func (c pveGuestCapabilityChecker) GuestAgentCommand(ctx context.Context, nodeRef string, vmid int, wanted string) (GuestCapability, error) {
	if c.client == nil || !nodeRE.MatchString(nodeRef) || vmid < 1 {
		return GuestCapabilityUnavailable, nil
	}
	var info pve.GuestAgentInfo
	path := fmt.Sprintf("/nodes/%s/qemu/%d/agent/info", nodeRef, vmid)
	err := c.client.Do(ctx, http.MethodGet, path, nil, nil, &info)
	if err != nil {
		return GuestCapabilityUnavailable, err
	}
	for _, command := range info.SupportedCommands {
		if strings.TrimSpace(command.Name) == wanted {
			if command.Enabled {
				return GuestCapabilityAvailable, nil
			}
			return GuestCapabilityUnsupported, nil
		}
	}
	return GuestCapabilityUnsupported, nil
}

// TaskStatusResult is the bounded, read-only result returned by task.status.
// It intentionally excludes PVE's user and free-form task metadata.
type TaskStatusResult struct {
	NodeRef    string `json:"nodeRef"`
	UPID       string `json:"upid"`
	Status     string `json:"status"`
	ExitStatus string `json:"exitStatus,omitempty"`
}

func readTaskStatus(ctx context.Context, client *pve.Client, command Command) (json.RawMessage, error) {
	var parameters taskP
	if err := strictParameters(command.Parameters, &parameters); err != nil {
		return nil, err
	}
	result, err := resolvePVEStatus(ctx, client, command.Identity.NodeRef, parameters.UPID)
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
}

func resolvePVEStatus(ctx context.Context, client *pve.Client, nodeRef, upid string) (TaskStatusResult, error) {
	if client == nil || !nodeRE.MatchString(nodeRef) || !upidRE.MatchString(upid) {
		return TaskStatusResult{}, errors.New("invalid PVE task target")
	}
	var response struct {
		Status     string `json:"status"`
		ExitStatus string `json:"exitstatus"`
	}
	path := "/nodes/" + nodeRef + "/tasks/" + upid + "/status"
	if err := client.Do(ctx, http.MethodGet, path, nil, nil, &response); err != nil {
		return TaskStatusResult{}, err
	}
	status := strings.ToLower(strings.TrimSpace(response.Status))
	exitStatus := strings.TrimSpace(response.ExitStatus)
	if !validTaskState(status) || len(exitStatus) > 128 || strings.ContainsAny(exitStatus, "\x00\r\n") {
		return TaskStatusResult{}, errors.New("PVE returned an invalid task status")
	}
	return TaskStatusResult{NodeRef: nodeRef, UPID: upid, Status: status, ExitStatus: exitStatus}, nil
}

type pveClientTaskResolver struct{ client *pve.Client }

func (r pveClientTaskResolver) ResolveTask(ctx context.Context, nodeRef, upid string) (TaskResolution, error) {
	result, err := resolvePVEStatus(ctx, r.client, nodeRef, upid)
	if err != nil {
		return TaskResolution{}, err
	}
	return TaskResolution{Status: result.Status, ExitStatus: result.ExitStatus}, nil
}

func validTaskState(status string) bool {
	switch status {
	case "queued", "running", "stopped":
		return true
	default:
		return false
	}
}

type cloneP struct {
	SourceVMID         int    `json:"sourceVmid"`
	Name               string `json:"name"`
	Target             string `json:"target"`
	Storage            string `json:"storage"`
	Full               *bool  `json:"full"`
	SourceConfigSHA256 string `json:"sourceConfigSha256"`
}
type createP struct {
	Name      string `json:"name"`
	Cores     int    `json:"cores"`
	MemoryMiB int    `json:"memoryMiB"`
	Storage   string `json:"storage"`
	DiskGiB   int    `json:"diskGiB"`
	Template  string `json:"template,omitempty"`
	Start     *bool  `json:"start"`
}
type resourcesP struct {
	Cores     *int `json:"cores,omitempty"`
	Sockets   *int `json:"sockets,omitempty"`
	MemoryMiB *int `json:"memoryMiB,omitempty"`
}
type resizeP struct {
	Disk      string `json:"disk"`
	Size      string `json:"size,omitempty"`
	TargetGiB *int   `json:"targetGiB,omitempty"`
}
type diskIOP struct {
	Disk   string       `json:"disk"`
	Limits diskIOLimits `json:"limits"`
}
type diskIOLimits struct {
	IOPSRead           *int64 `json:"iopsRead,omitempty"`
	IOPSWrite          *int64 `json:"iopsWrite,omitempty"`
	IOPSReadMax        *int64 `json:"iopsReadMax,omitempty"`
	IOPSWriteMax       *int64 `json:"iopsWriteMax,omitempty"`
	IOPSReadMaxLength  *int64 `json:"iopsReadMaxLength,omitempty"`
	IOPSWriteMaxLength *int64 `json:"iopsWriteMaxLength,omitempty"`
	MBPSRead           *int64 `json:"mbpsRead,omitempty"`
	MBPSWrite          *int64 `json:"mbpsWrite,omitempty"`
	MBPSReadMax        *int64 `json:"mbpsReadMax,omitempty"`
	MBPSWriteMax       *int64 `json:"mbpsWriteMax,omitempty"`
}
type deleteP struct {
	Purge                    *bool `json:"purge"`
	DestroyUnreferencedDisks *bool `json:"destroyUnreferencedDisks"`
}
type rateP struct {
	Interface string `json:"interface"`
	RateMbps  string `json:"rateMbps"`
}
type networkP struct {
	Interface string  `json:"interface"`
	Bridge    *string `json:"bridge,omitempty"`
	Model     *string `json:"model,omitempty"`
	MAC       *string `json:"mac,omitempty"`
	VLAN      *int    `json:"vlan,omitempty"`
	MTU       *int    `json:"mtu,omitempty"`
	Firewall  *bool   `json:"firewall,omitempty"`
	RateMbps  *string `json:"rateMbps,omitempty"`
	IPv4      *string `json:"ipv4,omitempty"`
	IPv6      *string `json:"ipv6,omitempty"`
	Gateway4  *string `json:"gateway4,omitempty"`
	Gateway6  *string `json:"gateway6,omitempty"`
}
type passwordP struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password"`
	Crypted  *bool  `json:"crypted"`
}
type cloudInitP struct {
	Hostname          string   `json:"hostname"`
	Username          string   `json:"username"`
	Password          string   `json:"password"`
	PasswordFormat    string   `json:"passwordFormat"`
	SSHAuthorizedKeys []string `json:"sshAuthorizedKeys"`
	QGAEnabled        *bool    `json:"qgaEnabled"`
}
type timezoneP struct {
	Timezone string `json:"timezone"`
}
type deliveryP struct {
	NotBefore time.Time        `json:"notBefore"`
	Expected  deliveryExpected `json:"expected"`
}
type deliveryExpected struct {
	Cores     int               `json:"cores"`
	Sockets   int               `json:"sockets"`
	MemoryMiB int               `json:"memoryMiB"`
	Disk      deliveryDisk      `json:"disk"`
	Networks  []deliveryNetwork `json:"networks"`
	Timezone  string            `json:"timezone"`
}
type deliveryDisk struct {
	Interface  string       `json:"interface"`
	MinimumGiB int          `json:"minimumGiB"`
	Limits     diskIOLimits `json:"limits"`
}
type deliveryNetwork struct {
	Interface     string   `json:"interface"`
	Bridge        string   `json:"bridge"`
	MAC           string   `json:"mac"`
	VLAN          *int     `json:"vlan,omitempty"`
	MTU           int      `json:"mtu"`
	Firewall      *bool    `json:"firewall"`
	RateMbps      string   `json:"rateMbps"`
	IPv4          string   `json:"ipv4"`
	IPv6          string   `json:"ipv6"`
	IPFilterCIDRs []string `json:"ipFilterCidrs"`
}
type snapP struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	IncludeRAM  *bool  `json:"includeRam"`
}
type namedP struct {
	Name string `json:"name"`
}
type backupCreateP struct {
	Storage  string `json:"storage"`
	Mode     string `json:"mode"`
	Compress string `json:"compress,omitempty"`
}
type backupVolumeP struct {
	Storage string `json:"storage"`
	Volume  string `json:"volume"`
}
type backupRestoreP struct {
	Storage string `json:"storage"`
	Volume  string `json:"volume"`
	Force   *bool  `json:"force"`
}
type taskP struct {
	UPID string `json:"upid"`
}
type firewallP struct {
	Position        *int   `json:"position,omitempty"`
	Direction       string `json:"direction"`
	Action          string `json:"action"`
	Protocol        string `json:"protocol,omitempty"`
	Source          string `json:"source,omitempty"`
	Destination     string `json:"destination,omitempty"`
	DestinationPort string `json:"destinationPort,omitempty"`
	Enable          *bool  `json:"enable"`
	Comment         string `json:"comment,omitempty"`
}
type firewallDeleteP struct {
	Position *int `json:"position"`
}
type firewallOptionsP struct {
	Enable *bool `json:"enable"`
}
type firewallGuestOptionsP struct {
	Enable    *bool  `json:"enable"`
	PolicyIn  string `json:"policyIn,omitempty"`
	PolicyOut string `json:"policyOut,omitempty"`
	MacFilter *bool  `json:"macFilter,omitempty"`
}
type ipsetP struct {
	Name    string `json:"name"`
	Comment string `json:"comment,omitempty"`
}
type ipsetEntryP struct {
	Name     string `json:"name"`
	CIDR     string `json:"cidr"`
	Comment  string `json:"comment,omitempty"`
	NoSubnet *bool  `json:"noSubnet"`
}
type ipsetEntryUpdateP struct {
	Name     string  `json:"name"`
	CIDR     string  `json:"cidr"`
	Comment  *string `json:"comment,omitempty"`
	NoSubnet *bool   `json:"noSubnet,omitempty"`
}
type ipsetEntryDeleteP struct {
	Name string `json:"name"`
	CIDR string `json:"cidr"`
}
type ipFilterVerifyP struct {
	Networks []ipFilterVerifyNetwork `json:"networks"`
}
type ipFilterVerifyNetwork struct {
	Interface     string   `json:"interface"`
	MACAddress    *string  `json:"macAddress,omitempty"`
	IPFilterCIDRs []string `json:"ipFilterCidrs"`
}

func validateParameters(c Command) error {
	if !commandIDRE.MatchString(c.Identity.ClusterRef) || !validActionScope(c.Action, c.Scope) {
		return errors.New("invalid PVE action or cluster target")
	}
	switch c.Scope {
	case ScopeVM:
		if c.Identity.VMID < 1 || c.Identity.Generation == 0 || !nodeRE.MatchString(c.Identity.NodeRef) || !commandIDRE.MatchString(c.Identity.ServiceRef) || !commandIDRE.MatchString(c.Identity.InstanceUUID) || (c.Identity.GuestType != "qemu" && c.Identity.GuestType != "lxc") {
			return errors.New("invalid PVE VM target")
		}
	case ScopeNode:
		if !nodeRE.MatchString(c.Identity.NodeRef) || c.Identity.VMID != 0 || c.Identity.Generation != 0 || c.Identity.ServiceRef != "" || c.Identity.InstanceUUID != "" || c.Identity.GuestType != "" {
			return errors.New("invalid PVE node target")
		}
	case ScopeCluster:
		if c.Identity.NodeRef != "" || c.Identity.VMID != 0 || c.Identity.Generation != 0 || c.Identity.ServiceRef != "" || c.Identity.InstanceUUID != "" || c.Identity.GuestType != "" {
			return errors.New("invalid PVE cluster target")
		}
	default:
		return errors.New("invalid PVE command scope")
	}
	switch c.Action {
	case "pve.discover":
		_, err := discoveryRequest(c)
		return err
	case "agent.upgrade":
		_, err := upgradecontract.DecodeParameters(c.Parameters)
		return err
	case "vm.start", "vm.shutdown", "vm.stop", "vm.reboot":
		return requireEmptyObject(c.Parameters)
	case "vm.create":
		var p createP
		if strictParameters(c.Parameters, &p) != nil || p.Start == nil || !nameRE.MatchString(p.Name) || p.Cores < 1 || p.Cores > 128 || p.MemoryMiB < 128 || p.MemoryMiB > 4194304 || !storageRE.MatchString(p.Storage) || p.DiskGiB < 1 || p.DiskGiB > 1048576 || (c.Identity.GuestType == "lxc" && !validTemplate(p.Template)) || (c.Identity.GuestType == "qemu" && p.Template != "") {
			return errors.New("invalid create parameters")
		}
		return nil
	case "vm.clone":
		var p cloneP
		if strictParameters(c.Parameters, &p) != nil || p.Full == nil || !*p.Full || p.SourceVMID < 100 || p.SourceVMID > 999999999 || !nameRE.MatchString(p.Name) || !nodeRE.MatchString(p.Target) || !storageRE.MatchString(p.Storage) || !bodyHashRE.MatchString(p.SourceConfigSHA256) {
			return errors.New("invalid clone parameters")
		}
		return nil
	case "vm.set-resources":
		var p resourcesP
		if strictParameters(c.Parameters, &p) != nil || !validResources(p) {
			return errors.New("invalid resource parameters")
		}
		return nil
	case "vm.resize":
		var p resizeP
		if strictParameters(c.Parameters, &p) != nil {
			return errors.New("invalid grow-only resize parameters")
		}
		validRelative := p.TargetGiB == nil && regexp.MustCompile(`^\+[1-9][0-9]*(K|M|G|T)$`).MatchString(p.Size)
		validTarget := p.Size == "" && p.TargetGiB != nil && *p.TargetGiB >= 1 && *p.TargetGiB <= 1048576
		if !diskRE.MatchString(p.Disk) || (!validRelative && !validTarget) {
			return errors.New("invalid grow-only resize parameters")
		}
		return nil
	case "vm.set-disk-io":
		var p diskIOP
		if strictParameters(c.Parameters, &p) != nil || c.Identity.GuestType != "qemu" || !exactDiskIOKeys(c.Parameters) || !validDiskLimits(p) {
			return errors.New("invalid disk IO limit parameters")
		}
		return nil
	case "vm.set-network":
		var p networkP
		if strictParameters(c.Parameters, &p) != nil || !validNetwork(p, c.Identity.GuestType) {
			return errors.New("invalid network parameters")
		}
		return nil
	case "vm.set-rate":
		var p rateP
		if strictParameters(c.Parameters, &p) != nil || !netRE.MatchString(p.Interface) || !validRate(p.RateMbps) {
			return errors.New("invalid network rate parameters")
		}
		return nil
	case "vm.set-cloud-init":
		var p cloudInitP
		if strictParameters(c.Parameters, &p) != nil || p.QGAEnabled == nil || c.Identity.GuestType != "qemu" || !validCloudInit(p) {
			return errors.New("invalid Cloud-Init parameters")
		}
		return nil
	case "vm.set-timezone":
		var p timezoneP
		if strictParameters(c.Parameters, &p) != nil || c.Identity.GuestType != "qemu" || !validTimezone(p.Timezone) {
			return errors.New("invalid guest timezone parameters")
		}
		return nil
	case "vm.verify-delivery":
		var p deliveryP
		if strictParameters(c.Parameters, &p) != nil || c.Identity.GuestType != "qemu" || !exactDeliveryKeys(c.Parameters) || !validDelivery(p) {
			return errors.New("invalid delivery verification parameters")
		}
		return nil
	case "firewall.guest.verify-ipfilter":
		var p ipFilterVerifyP
		if strictParameters(c.Parameters, &p) != nil || !validIPFilterVerification(p) {
			return errors.New("invalid guest IP filter verification parameters")
		}
		return nil
	case "firewall.guest.verify-ipfilter-sets":
		var p ipFilterVerifyP
		if strictParameters(c.Parameters, &p) != nil || !validIPFilterVerification(p) {
			return errors.New("invalid guest IP filter set verification parameters")
		}
		return nil
	case "vm.delete":
		var p deleteP
		if err := strictParameters(c.Parameters, &p); err != nil || p.Purge == nil || p.DestroyUnreferencedDisks == nil {
			return errors.New("purge and destroyUnreferencedDisks are required")
		}
		return nil
	case "vm.reset-password":
		var p passwordP
		if c.Identity.GuestType != "qemu" {
			return ErrUnsupported
		}
		if strictParameters(c.Parameters, &p) != nil || p.Crypted == nil || p.Password == "" || len(p.Password) > 1024 || strings.ContainsAny(p.Password, "\x00\r\n") || !nameRE.MatchString(p.Username) {
			return errors.New("invalid password reset parameters")
		}
		return nil
	case "snapshot.create":
		var p snapP
		if strictParameters(c.Parameters, &p) != nil || p.IncludeRAM == nil || !snapRE.MatchString(p.Name) || len(p.Description) > 1024 || strings.ContainsAny(p.Description, "\x00\r\n") || (c.Identity.GuestType == "lxc" && *p.IncludeRAM) {
			return errors.New("invalid snapshot parameters")
		}
		return nil
	case "snapshot.delete", "snapshot.rollback":
		var p namedP
		if strictParameters(c.Parameters, &p) != nil || !snapRE.MatchString(p.Name) {
			return errors.New("invalid snapshot parameters")
		}
		return nil
	case "backup.create":
		var p backupCreateP
		if strictParameters(c.Parameters, &p) != nil || !storageRE.MatchString(p.Storage) || (p.Mode != "snapshot" && p.Mode != "suspend" && p.Mode != "stop") || !validCompress(p.Compress) {
			return errors.New("invalid backup parameters")
		}
		return nil
	case "backup.delete":
		var p backupVolumeP
		if strictParameters(c.Parameters, &p) != nil || !storageRE.MatchString(p.Storage) || !validBackupVolume(p.Volume) {
			return errors.New("invalid backup parameters")
		}
		return nil
	case "backup.restore":
		var p backupRestoreP
		if strictParameters(c.Parameters, &p) != nil || p.Force == nil || !storageRE.MatchString(p.Storage) || !validBackupVolume(p.Volume) {
			return errors.New("invalid backup parameters")
		}
		return nil
	case "task.status":
		var p taskP
		if strictParameters(c.Parameters, &p) != nil || !upidRE.MatchString(p.UPID) || !strings.HasPrefix(p.UPID, "UPID:"+c.Identity.NodeRef+":") {
			return errors.New("invalid task parameters")
		}
		return nil
	case "firewall.rule.create":
		var p firewallP
		if strictParameters(c.Parameters, &p) != nil || p.Position != nil || !validFirewall(p) {
			return errors.New("invalid firewall rule")
		}
		return nil
	case "firewall.rule.delete":
		var p firewallDeleteP
		if strictParameters(c.Parameters, &p) != nil || p.Position == nil || *p.Position < 0 || *p.Position > 999 {
			return errors.New("invalid firewall position")
		}
		return nil
	case "firewall.rule.update":
		var p firewallP
		if strictParameters(c.Parameters, &p) != nil || p.Position == nil || *p.Position < 0 || *p.Position > 999 || !validFirewall(p) {
			return errors.New("invalid firewall rule")
		}
		return nil
	case "firewall.cluster.set-options", "firewall.node.set-options":
		var p firewallOptionsP
		if err := strictParameters(c.Parameters, &p); err != nil || p.Enable == nil {
			return errors.New("invalid firewall options")
		}
		return nil
	case "firewall.guest.set-options":
		var p firewallGuestOptionsP
		if err := strictParameters(c.Parameters, &p); err != nil || p.Enable == nil ||
			!validFirewallPolicy(p.PolicyIn) || !validFirewallPolicy(p.PolicyOut) {
			return errors.New("invalid guest firewall options")
		}
		return nil
	case "firewall.ipset.create", "firewall.ipset.update":
		var p ipsetP
		if strictParameters(c.Parameters, &p) != nil || !nameRE.MatchString(p.Name) || len(p.Comment) > 256 || strings.ContainsAny(p.Comment, "\x00\r\n") {
			return errors.New("invalid ipset")
		}
		return nil
	case "firewall.ipset.delete":
		var p namedP
		if strictParameters(c.Parameters, &p) != nil || !nameRE.MatchString(p.Name) {
			return errors.New("invalid ipset")
		}
		return nil
	case "firewall.ipset.entry.create":
		var p ipsetEntryP
		if strictParameters(c.Parameters, &p) != nil || p.NoSubnet == nil || !validIPSetEntry(p.Name, p.CIDR) || !validIPSetComment(p.Comment) {
			return errors.New("invalid ipset entry")
		}
		return nil
	case "firewall.ipset.entry.update":
		var p ipsetEntryUpdateP
		if strictParameters(c.Parameters, &p) != nil || !validIPSetEntry(p.Name, p.CIDR) || p.Comment == nil && p.NoSubnet == nil || p.Comment != nil && !validIPSetComment(*p.Comment) {
			return errors.New("invalid ipset entry update")
		}
		return nil
	case "firewall.ipset.entry.delete":
		var p ipsetEntryDeleteP
		if strictParameters(c.Parameters, &p) != nil || !validIPSetEntry(p.Name, p.CIDR) {
			return errors.New("invalid ipset entry delete")
		}
		return nil
	default:
		return ErrUnsupported
	}
}

func discoveryRequest(c Command) (discovery.Request, error) {
	var request discovery.Request
	if err := strictParameters(c.Parameters, &request); err != nil || request.OperationID != c.OperationID {
		return discovery.Request{}, errors.New("invalid discovery request")
	}
	// Node discovery is bound to the signed node identity. Cluster discovery
	// must not smuggle a node selector through its body.
	if c.Scope == ScopeNode && request.NodeRef != c.Identity.NodeRef {
		return discovery.Request{}, errors.New("discovery node does not match command scope")
	}
	if c.Scope == ScopeCluster && request.NodeRef != "" {
		return discovery.Request{}, errors.New("cluster discovery has a node selector")
	}
	if !validDiscoveryPhase(request.Phase) || !validDiscoveryScope(request.Phase, c.Scope) || request.Limit < 0 || request.Limit > 50 {
		return discovery.Request{}, errors.New("invalid discovery phase or limit")
	}
	if request.Cursor != "" {
		offset, err := strconv.Atoi(request.Cursor)
		if err != nil || offset < 0 || strconv.Itoa(offset) != request.Cursor {
			return discovery.Request{}, errors.New("invalid discovery cursor")
		}
	}
	return request, nil
}

func validDiscoveryScope(phase, scope string) bool {
	switch phase {
	case discovery.PhaseVersion, discovery.PhasePermissions:
		return scope == ScopeCluster
	case discovery.PhaseStorage, discovery.PhaseCapacity:
		return scope == ScopeNode
	default:
		return scope == ScopeCluster || scope == ScopeNode
	}
}

func validDiscoveryPhase(phase string) bool {
	switch phase {
	case discovery.PhaseVersion, discovery.PhasePermissions, discovery.PhaseNodes, discovery.PhaseStorage, discovery.PhaseTemplates, discovery.PhaseNetworks, discovery.PhaseCapacity, discovery.PhaseFirewall, discovery.PhaseReadiness:
		return true
	default:
		return false
	}
}

func executePVE(ctx context.Context, client *pve.Client, c Command) (string, json.RawMessage, error) {
	if err := validateParameters(c); err != nil {
		return "", nil, err
	}
	base := fmt.Sprintf("/nodes/%s/%s/%d", c.Identity.NodeRef, c.Identity.GuestType, c.Identity.VMID)
	node := "/nodes/" + c.Identity.NodeRef
	var method, path string
	var form url.Values
	switch c.Action {
	case "vm.start", "vm.shutdown", "vm.stop", "vm.reboot":
		method, path = http.MethodPost, base+"/status/"+strings.TrimPrefix(c.Action, "vm.")
	case "vm.create":
		var p createP
		_ = strictParameters(c.Parameters, &p)
		form = url.Values{"vmid": {strconv.Itoa(c.Identity.VMID)}, "cores": {strconv.Itoa(p.Cores)}, "memory": {strconv.Itoa(p.MemoryMiB)}, "start": {boolText(*p.Start)}}
		if c.Identity.GuestType == "qemu" {
			form.Set("name", p.Name)
			form.Set("scsi0", p.Storage+":0,size="+strconv.Itoa(p.DiskGiB)+"G")
		} else {
			form.Set("hostname", p.Name)
			form.Set("ostemplate", p.Template)
			form.Set("rootfs", p.Storage+":"+strconv.Itoa(p.DiskGiB))
		}
		method, path = http.MethodPost, node+"/"+c.Identity.GuestType
	case "vm.clone":
		var p cloneP
		_ = strictParameters(c.Parameters, &p)
		if err := verifyCloneSource(ctx, client, c, p); err != nil {
			return "", nil, err
		}
		form = url.Values{"newid": {strconv.Itoa(c.Identity.VMID)}, "name": {p.Name}, "full": {boolText(*p.Full)}}
		form.Set("target", p.Target)
		form.Set("storage", p.Storage)
		method, path = http.MethodPost, fmt.Sprintf("/nodes/%s/%s/%d/clone", c.Identity.NodeRef, c.Identity.GuestType, p.SourceVMID)
	case "vm.set-resources":
		return setResources(ctx, client, c, base)
	case "vm.resize":
		return resizeDisk(ctx, client, c, base)
	case "vm.set-disk-io":
		return setDiskLimits(ctx, client, c, base)
	case "vm.set-network":
		return setNetwork(ctx, client, c, base)
	case "vm.set-rate":
		return setRate(ctx, client, c, base)
	case "vm.set-cloud-init":
		return setCloudInit(ctx, client, c, base)
	case "vm.set-timezone":
		return setGuestTimezone(ctx, client, c, base)
	case "vm.delete":
		var p deleteP
		_ = strictParameters(c.Parameters, &p)
		method, path, form = http.MethodDelete, base, url.Values{"purge": {boolText(*p.Purge)}, "destroy-unreferenced-disks": {boolText(*p.DestroyUnreferencedDisks)}}
	case "vm.reset-password":
		return resetPassword(ctx, client, c, base)
	case "snapshot.create":
		var p snapP
		_ = strictParameters(c.Parameters, &p)
		form = url.Values{"snapname": {p.Name}, "vmstate": {boolText(*p.IncludeRAM)}}
		if p.Description != "" {
			form.Set("description", p.Description)
		}
		method, path = http.MethodPost, base+"/snapshot"
	case "snapshot.delete":
		var p namedP
		_ = strictParameters(c.Parameters, &p)
		method, path = http.MethodDelete, base+"/snapshot/"+p.Name
	case "snapshot.rollback":
		var p namedP
		_ = strictParameters(c.Parameters, &p)
		method, path = http.MethodPost, base+"/snapshot/"+p.Name+"/rollback"
	case "backup.create":
		var p backupCreateP
		_ = strictParameters(c.Parameters, &p)
		form = url.Values{"vmid": {strconv.Itoa(c.Identity.VMID)}, "storage": {p.Storage}, "mode": {p.Mode}}
		if p.Compress != "" {
			form.Set("compress", p.Compress)
		}
		method, path = http.MethodPost, node+"/vzdump"
	case "backup.delete":
		var p backupVolumeP
		_ = strictParameters(c.Parameters, &p)
		method, path = http.MethodDelete, node+"/storage/"+p.Storage+"/content/"+p.Volume
	case "backup.restore":
		var p backupRestoreP
		_ = strictParameters(c.Parameters, &p)
		form = url.Values{"vmid": {strconv.Itoa(c.Identity.VMID)}, "archive": {p.Volume}, "storage": {p.Storage}, "force": {boolText(*p.Force)}}
		method, path = http.MethodPost, node+"/"+c.Identity.GuestType
	case "firewall.rule.create":
		var p firewallP
		_ = strictParameters(c.Parameters, &p)
		method, path, form = http.MethodPost, base+"/firewall/rules", firewallForm(p)
	case "firewall.rule.delete":
		var p firewallDeleteP
		_ = strictParameters(c.Parameters, &p)
		method, path = http.MethodDelete, base+"/firewall/rules/"+strconv.Itoa(*p.Position)
	case "firewall.rule.update":
		var p firewallP
		_ = strictParameters(c.Parameters, &p)
		method, path, form = http.MethodPut, base+"/firewall/rules/"+strconv.Itoa(*p.Position), firewallForm(p)
	case "firewall.cluster.set-options":
		var p firewallOptionsP
		_ = strictParameters(c.Parameters, &p)
		method, path, form = http.MethodPut, "/cluster/firewall/options", url.Values{"enable": {boolText(*p.Enable)}}
	case "firewall.node.set-options":
		var p firewallOptionsP
		_ = strictParameters(c.Parameters, &p)
		method, path, form = http.MethodPut, node+"/firewall/options", url.Values{"enable": {boolText(*p.Enable)}}
	case "firewall.guest.set-options":
		var p firewallGuestOptionsP
		_ = strictParameters(c.Parameters, &p)
		form = url.Values{"enable": {boolText(*p.Enable)}}
		if p.PolicyIn != "" {
			form.Set("policy_in", p.PolicyIn)
		}
		if p.PolicyOut != "" {
			form.Set("policy_out", p.PolicyOut)
		}
		if p.MacFilter != nil {
			form.Set("macfilter", boolText(*p.MacFilter))
		}
		method, path = http.MethodPut, base+"/firewall/options"
	case "firewall.ipset.create":
		var p ipsetP
		_ = strictParameters(c.Parameters, &p)
		form = url.Values{"name": {p.Name}}
		if p.Comment != "" {
			form.Set("comment", p.Comment)
		}
		method, path = http.MethodPost, base+"/firewall/ipset"
	case "firewall.ipset.delete":
		var p namedP
		_ = strictParameters(c.Parameters, &p)
		method, path = http.MethodDelete, base+"/firewall/ipset/"+p.Name
	case "firewall.ipset.update":
		var p ipsetP
		_ = strictParameters(c.Parameters, &p)
		method, path, form = http.MethodPut, base+"/firewall/ipset/"+p.Name, url.Values{"comment": {p.Comment}}
	case "firewall.ipset.entry.create":
		var p ipsetEntryP
		_ = strictParameters(c.Parameters, &p)
		form = url.Values{"cidr": {p.CIDR}, "nomatch": {boolText(*p.NoSubnet)}}
		if p.Comment != "" {
			form.Set("comment", p.Comment)
		}
		method, path = http.MethodPost, base+"/firewall/ipset/"+p.Name
	case "firewall.ipset.entry.update":
		var p ipsetEntryUpdateP
		_ = strictParameters(c.Parameters, &p)
		form = url.Values{}
		if p.Comment != nil {
			form.Set("comment", *p.Comment)
		}
		if p.NoSubnet != nil {
			form.Set("nomatch", boolText(*p.NoSubnet))
		}
		method, path = http.MethodPut, base+"/firewall/ipset/"+p.Name+"/"+p.CIDR
	case "firewall.ipset.entry.delete":
		var p ipsetEntryDeleteP
		_ = strictParameters(c.Parameters, &p)
		method, path = http.MethodDelete, base+"/firewall/ipset/"+p.Name+"/"+p.CIDR
	default:
		return "", nil, ErrUnsupported
	}
	return doPVE(ctx, client, method, path, form)
}

func doPVE(ctx context.Context, c *pve.Client, method, path string, form url.Values) (string, json.RawMessage, error) {
	var out json.RawMessage
	if err := c.Do(ctx, method, path, nil, form, &out); err != nil {
		return "", nil, err
	}
	var text string
	upid := ""
	if json.Unmarshal(out, &text) == nil && strings.HasPrefix(text, "UPID:") {
		if !upidRE.MatchString(text) {
			return "", nil, errors.New("PVE returned an invalid task UPID")
		}
		upid = text
	}
	if len(out) > 4096 {
		out = nil
	}
	return upid, out, nil
}
func guestConfig(ctx context.Context, c *pve.Client, cmd Command) (pve.GuestConfig, error) {
	return c.GuestConfig(ctx, cmd.Identity.GuestType, cmd.Identity.NodeRef, cmd.Identity.VMID)
}
func verifyCloneSource(ctx context.Context, c *pve.Client, cmd Command, parameters cloneP) error {
	resources, err := c.ClusterResources(ctx)
	if err != nil {
		return err
	}
	found := false
	for _, resource := range resources {
		if resource.VMID == parameters.SourceVMID && resource.Node == cmd.Identity.NodeRef && resource.Type == cmd.Identity.GuestType && resource.Template == 1 {
			found = true
			break
		}
	}
	if !found {
		return errors.New("clone source is not the assigned PVE template")
	}
	info, err := c.TemplateInfo(ctx, cmd.Identity.GuestType, cmd.Identity.NodeRef, parameters.SourceVMID, "")
	if err != nil {
		return err
	}
	if !strings.EqualFold(info.ConfigSHA256, parameters.SourceConfigSHA256) {
		return errors.New("clone source configuration changed after discovery")
	}
	return nil
}
func setResources(ctx context.Context, c *pve.Client, cmd Command, base string) (string, json.RawMessage, error) {
	var p resourcesP
	_ = strictParameters(cmd.Parameters, &p)
	current, err := guestConfig(ctx, c, cmd)
	if err != nil {
		return "", nil, err
	}
	form, changed := url.Values{}, false
	for _, x := range []struct {
		key string
		val *int
	}{{"cores", p.Cores}, {"sockets", p.Sockets}, {"memory", p.MemoryMiB}} {
		if x.val == nil {
			continue
		}
		old, ok := configInt(current.Raw, x.key)
		if !ok {
			return "", nil, fmt.Errorf("current %s is unavailable", x.key)
		}
		if *x.val < old {
			return "", nil, fmt.Errorf("%s may only increase", x.key)
		}
		if *x.val > old {
			form.Set(x.key, strconv.Itoa(*x.val))
			changed = true
		}
	}
	if !changed {
		return "", nil, errors.New("requested resources do not increase current configuration")
	}
	if current.Digest != "" {
		form.Set("digest", current.Digest)
	}
	return doPVE(ctx, c, http.MethodPut, base+"/config", form)
}
func resizeDisk(ctx context.Context, c *pve.Client, cmd Command, base string) (string, json.RawMessage, error) {
	var p resizeP
	_ = strictParameters(cmd.Parameters, &p)
	current, err := guestConfig(ctx, c, cmd)
	if err != nil {
		return "", nil, err
	}
	drive, ok := configString(current.Raw, p.Disk)
	if !ok {
		return "", nil, errors.New("target disk does not exist")
	}
	size := p.Size
	if p.TargetGiB != nil {
		currentBytes, parseErr := diskSizeBytes(drive)
		if parseErr != nil {
			return "", nil, parseErr
		}
		targetBytes := uint64(*p.TargetGiB) << 30
		if targetBytes < currentBytes {
			return "", nil, errors.New("disk may only increase")
		}
		if targetBytes == currentBytes {
			result, _ := json.Marshal(map[string]any{"changed": false, "disk": p.Disk, "sizeGiB": *p.TargetGiB})
			return "", result, nil
		}
		size = strconv.Itoa(*p.TargetGiB) + "G"
	}
	return doPVE(ctx, c, http.MethodPut, base+"/resize", url.Values{"disk": {p.Disk}, "size": {size}})
}
func setDiskLimits(ctx context.Context, c *pve.Client, cmd Command, base string) (string, json.RawMessage, error) {
	var p diskIOP
	_ = strictParameters(cmd.Parameters, &p)
	current, err := guestConfig(ctx, c, cmd)
	if err != nil {
		return "", nil, err
	}
	drive, ok := configString(current.Raw, p.Disk)
	if !ok {
		return "", nil, errors.New("target disk does not exist")
	}
	updated, err := mergeDiskLimits(drive, p)
	if err != nil {
		return "", nil, err
	}
	if updated == drive {
		result, _ := json.Marshal(map[string]any{"changed": false, "disk": p.Disk, "verified": true})
		return "", result, nil
	}
	form := url.Values{p.Disk: {updated}}
	if current.Digest != "" {
		form.Set("digest", current.Digest)
	}
	return doPVE(ctx, c, http.MethodPut, base+"/config", form)
}
func setRate(ctx context.Context, c *pve.Client, cmd Command, base string) (string, json.RawMessage, error) {
	var p rateP
	_ = strictParameters(cmd.Parameters, &p)
	current, err := guestConfig(ctx, c, cmd)
	if err != nil {
		return "", nil, err
	}
	old, ok := configString(current.Raw, p.Interface)
	if !ok {
		return "", nil, errors.New("target network interface does not exist")
	}
	updated, err := replaceRate(old, p.RateMbps)
	if err != nil {
		return "", nil, err
	}
	form := url.Values{p.Interface: {updated}}
	if current.Digest != "" {
		form.Set("digest", current.Digest)
	}
	return doPVE(ctx, c, http.MethodPut, base+"/config", form)
}
func setNetwork(ctx context.Context, c *pve.Client, cmd Command, base string) (string, json.RawMessage, error) {
	var p networkP
	_ = strictParameters(cmd.Parameters, &p)
	current, err := guestConfig(ctx, c, cmd)
	if err != nil {
		return "", nil, err
	}
	old, ok := configString(current.Raw, p.Interface)
	if !ok {
		return "", nil, errors.New("target network interface does not exist")
	}
	network, err := mergeNetwork(cmd.Identity.GuestType, old, p)
	if err != nil {
		return "", nil, err
	}
	form := url.Values{p.Interface: {network}}
	if cmd.Identity.GuestType == "qemu" && (p.IPv4 != nil || p.IPv6 != nil || p.Gateway4 != nil || p.Gateway6 != nil) {
		oldIP, _ := configString(current.Raw, "ipconfig"+strings.TrimPrefix(p.Interface, "net"))
		ip, err := mergeIP(oldIP, p)
		if err != nil {
			return "", nil, err
		}
		form.Set("ipconfig"+strings.TrimPrefix(p.Interface, "net"), ip)
	}
	if current.Digest != "" {
		form.Set("digest", current.Digest)
	}
	return doPVE(ctx, c, http.MethodPut, base+"/config", form)
}
func setCloudInit(ctx context.Context, c *pve.Client, cmd Command, base string) (string, json.RawMessage, error) {
	var p cloudInitP
	_ = strictParameters(cmd.Parameters, &p)
	current, err := guestConfig(ctx, c, cmd)
	if err != nil {
		return "", nil, err
	}
	form := url.Values{"ciuser": {p.Username}, "cipassword": {p.Password}, "sshkeys": {url.QueryEscape(strings.Join(p.SSHAuthorizedKeys, "\n"))}, "name": {p.Hostname}, "agent": {"enabled=1"}}
	if current.Digest != "" {
		form.Set("digest", current.Digest)
	}
	upid, _, err := doPVE(ctx, c, http.MethodPut, base+"/config", form)
	if err != nil || upid != "" {
		return upid, nil, err
	}
	result, _ := json.Marshal(map[string]any{"configured": true, "qgaDeviceEnabled": true})
	return "", result, nil
}
func setGuestTimezone(ctx context.Context, c *pve.Client, cmd Command, base string) (string, json.RawMessage, error) {
	var p timezoneP
	_ = strictParameters(cmd.Parameters, &p)
	_, raw, err := doPVE(ctx, c, http.MethodPost, base+"/agent/exec", url.Values{"command": {"/usr/bin/timedatectl", "set-timezone", p.Timezone}})
	if err != nil {
		return "", nil, err
	}
	var pid int
	if json.Unmarshal(raw, &pid) != nil {
		var result struct {
			PID int `json:"pid"`
		}
		if json.Unmarshal(raw, &result) != nil || result.PID < 1 {
			return "", nil, errors.New("QGA guest-exec returned an invalid pid")
		}
		pid = result.PID
	}
	if pid < 1 {
		return "", nil, errors.New("QGA guest-exec returned an invalid pid")
	}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		var status struct {
			Exited   json.RawMessage `json:"exited"`
			ExitCode int             `json:"exitcode"`
		}
		if err := c.Do(ctx, http.MethodGet, base+"/agent/exec-status", url.Values{"pid": {strconv.Itoa(pid)}}, nil, &status); err != nil {
			return "", nil, err
		}
		exited, valid := boolish(status.Exited)
		if !valid {
			return "", nil, errors.New("QGA guest-exec returned an invalid status")
		}
		if exited {
			if status.ExitCode != 0 {
				return "", nil, errors.New("guest timezone command failed")
			}
			observed, readErr := c.ReadGuestTimezone(ctx, cmd.Identity.NodeRef, cmd.Identity.VMID)
			if readErr != nil || observed.Zone != p.Timezone {
				return "", nil, errors.New("guest timezone readback does not match")
			}
			result, _ := json.Marshal(map[string]any{"configured": true, "verified": true})
			return "", result, nil
		}
		select {
		case <-ctx.Done():
			return "", nil, ctx.Err()
		case <-ticker.C:
		}
	}
}
func boolish(raw json.RawMessage) (bool, bool) {
	var boolean bool
	if json.Unmarshal(raw, &boolean) == nil {
		return boolean, true
	}
	var integer int
	if json.Unmarshal(raw, &integer) == nil && (integer == 0 || integer == 1) {
		return integer == 1, true
	}
	return false, false
}
func resetPassword(ctx context.Context, c *pve.Client, cmd Command, base string) (string, json.RawMessage, error) {
	var p passwordP
	_ = strictParameters(cmd.Parameters, &p)
	if cmd.Identity.GuestType == "qemu" {
		upid, _, err := doPVE(ctx, c, http.MethodPost, base+"/agent/set-user-password", url.Values{"username": {p.Username}, "password": {p.Password}, "crypted": {boolText(*p.Crypted)}})
		return upid, nil, err
	}
	upid, _, err := doPVE(ctx, c, http.MethodPut, base+"/config", url.Values{"password": {p.Password}})
	return upid, nil, err
}

func validResources(p resourcesP) bool {
	any := false
	for _, n := range []*int{p.Cores, p.Sockets, p.MemoryMiB} {
		if n != nil {
			any = true
			if *n < 1 || *n > 4194304 {
				return false
			}
		}
	}
	return any && (p.Cores == nil || *p.Cores <= 128) && (p.Sockets == nil || *p.Sockets <= 16)
}
func validDiskLimits(p diskIOP) bool {
	if !diskRE.MatchString(p.Disk) {
		return false
	}
	limits := p.Limits
	for _, value := range []*int64{limits.IOPSRead, limits.IOPSWrite, limits.IOPSReadMax, limits.IOPSWriteMax} {
		if value != nil && (*value < 1 || *value > 1000000000) {
			return false
		}
	}
	for _, value := range []*int64{limits.MBPSRead, limits.MBPSWrite, limits.MBPSReadMax, limits.MBPSWriteMax} {
		if value != nil && (*value < 1 || *value > 1000000) {
			return false
		}
	}
	for _, value := range []*int64{limits.IOPSReadMaxLength, limits.IOPSWriteMaxLength} {
		if value != nil && (*value < 1 || *value > 86400) {
			return false
		}
	}
	if !validBurst(limits.IOPSRead, limits.IOPSReadMax, limits.IOPSReadMaxLength, true) || !validBurst(limits.IOPSWrite, limits.IOPSWriteMax, limits.IOPSWriteMaxLength, true) || !validBurst(limits.MBPSRead, limits.MBPSReadMax, nil, false) || !validBurst(limits.MBPSWrite, limits.MBPSWriteMax, nil, false) {
		return false
	}
	return true
}
func exactDiskIOKeys(raw json.RawMessage) bool {
	var outer map[string]json.RawMessage
	if json.Unmarshal(raw, &outer) != nil || len(outer) != 2 || outer["disk"] == nil || outer["limits"] == nil {
		return false
	}
	var limits map[string]json.RawMessage
	if json.Unmarshal(outer["limits"], &limits) != nil || len(limits) != 10 {
		return false
	}
	for _, key := range []string{"iopsRead", "iopsWrite", "iopsReadMax", "iopsWriteMax", "iopsReadMaxLength", "iopsWriteMaxLength", "mbpsRead", "mbpsWrite", "mbpsReadMax", "mbpsWriteMax"} {
		if _, ok := limits[key]; !ok {
			return false
		}
	}
	return true
}
func exactDeliveryKeys(raw json.RawMessage) bool {
	var outer map[string]json.RawMessage
	if json.Unmarshal(raw, &outer) != nil || !hasExactKeys(outer, "notBefore", "expected") {
		return false
	}
	var notBefore string
	if json.Unmarshal(outer["notBefore"], &notBefore) != nil || !regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`).MatchString(notBefore) {
		return false
	}
	var expected map[string]json.RawMessage
	if json.Unmarshal(outer["expected"], &expected) != nil || !hasExactKeys(expected, "cores", "sockets", "memoryMiB", "disk", "networks", "timezone") {
		return false
	}
	var disk map[string]json.RawMessage
	if json.Unmarshal(expected["disk"], &disk) != nil || !hasExactKeys(disk, "interface", "minimumGiB", "limits") {
		return false
	}
	var limits map[string]json.RawMessage
	if json.Unmarshal(disk["limits"], &limits) != nil || !hasExactKeys(limits, "iopsRead", "iopsWrite", "iopsReadMax", "iopsWriteMax", "iopsReadMaxLength", "iopsWriteMaxLength", "mbpsRead", "mbpsWrite", "mbpsReadMax", "mbpsWriteMax") {
		return false
	}
	var networks []map[string]json.RawMessage
	if json.Unmarshal(expected["networks"], &networks) != nil {
		return false
	}
	for _, network := range networks {
		required := []string{"interface", "bridge", "mac", "vlan", "mtu", "firewall", "rateMbps", "ipv4", "ipv6", "ipFilterCidrs"}
		if !hasExactKeys(network, required...) {
			return false
		}
	}
	return true
}
func hasExactKeys(values map[string]json.RawMessage, keys ...string) bool {
	if len(values) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := values[key]; !ok {
			return false
		}
	}
	return true
}
func validBurst(base, maximum, length *int64, requireLength bool) bool {
	if maximum != nil && (base == nil || *maximum < *base) {
		return false
	}
	if requireLength {
		return (maximum == nil) == (length == nil)
	}
	return length == nil
}
func validCloudInit(p cloudInitP) bool {
	if !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,63}$`).MatchString(p.Username) || !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$`).MatchString(p.Hostname) || p.Password == "" || len(p.Password) > 1024 || strings.ContainsAny(p.Password, "\x00\r\n") || (p.PasswordFormat != "plain" && p.PasswordFormat != "crypt") || len(p.SSHAuthorizedKeys) > 16 || !*p.QGAEnabled {
		return false
	}
	seen := map[string]bool{}
	for _, key := range p.SSHAuthorizedKeys {
		if !validSSHKey(key) || seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}
func validSSHKey(value string) bool {
	if len(value) > 4096 || strings.TrimSpace(value) != value {
		return false
	}
	match := regexp.MustCompile(`^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) ([A-Za-z0-9+/=]+)(?: [^\r\n]{1,128})?$`).FindStringSubmatch(value)
	if len(match) != 3 {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(match[2])
	return err == nil && len(decoded) >= 16 && len(decoded) <= 2048
}
func validTimezone(value string) bool {
	if value == "UTC" {
		return true
	}
	if len(value) > 64 || !regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._+-]*(?:/[A-Za-z0-9][A-Za-z0-9._+-]*)+$`).MatchString(value) {
		return false
	}
	_, err := time.LoadLocation(value)
	return err == nil
}
func validDelivery(p deliveryP) bool {
	e := p.Expected
	if p.NotBefore.IsZero() || p.NotBefore.Location() != time.UTC || e.Cores < 1 || e.Cores > 128 || e.Sockets < 1 || e.Sockets > 16 || e.MemoryMiB < 128 || e.MemoryMiB > 4194304 || !diskRE.MatchString(e.Disk.Interface) || e.Disk.MinimumGiB < 1 || e.Disk.MinimumGiB > 1048576 || !validTimezone(e.Timezone) || len(e.Networks) < 1 || len(e.Networks) > 8 {
		return false
	}
	if !validDiskLimits(diskIOP{Disk: e.Disk.Interface, Limits: e.Disk.Limits}) {
		return false
	}
	seen := map[string]bool{}
	seenMAC := map[string]bool{}
	var firewallState bool
	firewallStateSet := false
	for _, network := range e.Networks {
		ipv4Filter, ipv4OK := deliveryAddressFilter(network.IPv4, 4)
		ipv6Filter, ipv6OK := deliveryAddressFilter(network.IPv6, 6)
		dynamicAddress := network.IPv4 == "dhcp" || network.IPv4 == "manual" || network.IPv6 == "auto" || network.IPv6 == "dhcp" || network.IPv6 == "manual"
		if !netRE.MatchString(network.Interface) || seen[network.Interface] || !nodeRE.MatchString(network.Bridge) || !deliveryMACRE.MatchString(network.MAC) || seenMAC[network.MAC] || network.MTU < 576 || network.MTU > 9216 || network.Firewall == nil || !validRate(network.RateMbps) || !ipv4OK || !ipv6OK || *network.Firewall && dynamicAddress || len(network.IPFilterCIDRs) > 16 || network.VLAN != nil && (*network.VLAN < 0 || *network.VLAN > 4094) {
			return false
		}
		if firewallStateSet && firewallState != *network.Firewall {
			return false
		}
		firewallState = *network.Firewall
		firewallStateSet = true
		// The delivery contract has two exact, non-overlapping firewall
		// states.  An enabled NIC must carry at least one canonical host
		// filter.  A customer-controlled, disabled NIC must carry no filter
		// claims at all; otherwise the receipt could imply enforcement that
		// PVE is not actually applying.
		if *network.Firewall && len(network.IPFilterCIDRs) == 0 || !*network.Firewall && len(network.IPFilterCIDRs) != 0 {
			return false
		}
		seen[network.Interface] = true
		seenMAC[network.MAC] = true
		expectedCIDRs := map[string]bool{}
		if ipv4Filter != "" {
			expectedCIDRs[ipv4Filter] = true
		}
		if ipv6Filter != "" {
			expectedCIDRs[ipv6Filter] = true
		}
		if *network.Firewall && len(expectedCIDRs) != len(network.IPFilterCIDRs) {
			return false
		}
		cidrs := map[string]bool{}
		for _, cidr := range network.IPFilterCIDRs {
			ip, parsed, err := net.ParseCIDR(cidr)
			if err != nil || !ip.Equal(parsed.IP) || parsed.String() != cidr || cidrs[cidr] {
				return false
			}
			ones, bits := parsed.Mask.Size()
			if ones != bits || bits != 32 && bits != 128 {
				return false
			}
			if !expectedCIDRs[cidr] {
				return false
			}
			cidrs[cidr] = true
		}
	}
	return true
}

func deliveryAddressFilter(value string, family int) (string, bool) {
	if value == "" {
		return "", true
	}
	if family == 4 && (value == "dhcp" || value == "manual") || family == 6 && (value == "auto" || value == "dhcp" || value == "manual") {
		return "", true
	}
	ip, network, err := net.ParseCIDR(value)
	if err != nil || family == 4 && (ip.To4() == nil || network.IP.To4() == nil) || family == 6 && (ip.To4() != nil || network.IP.To4() != nil) {
		return "", false
	}
	ones, bits := network.Mask.Size()
	if ones < 0 || bits != 32 && bits != 128 {
		return "", false
	}
	canonical := ip.String() + "/" + strconv.Itoa(ones)
	if canonical != value {
		return "", false
	}
	return ip.String() + "/" + strconv.Itoa(bits), true
}
func validIPFilterVerification(p ipFilterVerifyP) bool {
	if len(p.Networks) < 1 || len(p.Networks) > 8 {
		return false
	}
	interfaces := map[string]bool{}
	macs := map[string]bool{}
	for _, network := range p.Networks {
		if !netRE.MatchString(network.Interface) || interfaces[network.Interface] || len(network.IPFilterCIDRs) < 1 || len(network.IPFilterCIDRs) > 16 {
			return false
		}
		interfaces[network.Interface] = true
		if network.MACAddress != nil {
			if !validSignedMAC(*network.MACAddress) || macs[*network.MACAddress] {
				return false
			}
			macs[*network.MACAddress] = true
		}
		cidrs := map[string]bool{}
		for _, value := range network.IPFilterCIDRs {
			ip, parsed, err := net.ParseCIDR(value)
			if err != nil || !ip.Equal(parsed.IP) || parsed.String() != value || cidrs[value] {
				return false
			}
			ones, bits := parsed.Mask.Size()
			if ones != bits || bits != 32 && bits != 128 {
				return false
			}
			cidrs[value] = true
		}
	}
	return true
}
func diskSizeBytes(drive string) (uint64, error) {
	for _, segment := range strings.Split(drive, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(segment), "=")
		if !ok || key != "size" {
			continue
		}
		match := regexp.MustCompile(`^([0-9]+(?:\.[0-9]{1,3})?)([KMGT])$`).FindStringSubmatch(value)
		if len(match) != 3 {
			return 0, errors.New("current disk size is invalid")
		}
		number, err := strconv.ParseFloat(match[1], 64)
		if err != nil || number <= 0 {
			return 0, errors.New("current disk size is invalid")
		}
		shift := map[string]uint{"K": 10, "M": 20, "G": 30, "T": 40}[match[2]]
		bytes := number * float64(uint64(1)<<shift)
		if bytes > float64(^uint64(0)) {
			return 0, errors.New("current disk size is too large")
		}
		return uint64(bytes), nil
	}
	return 0, errors.New("current disk size is unavailable")
}
func mergeDiskLimits(drive string, p diskIOP) (string, error) {
	if len(drive) > 4096 || strings.ContainsAny(drive, "\x00\r\n") {
		return "", errors.New("unsafe existing disk configuration")
	}
	managed := map[string]bool{"iops_rd": true, "iops_wr": true, "iops_rd_max": true, "iops_wr_max": true, "iops_rd_max_length": true, "iops_wr_max_length": true, "mbps_rd": true, "mbps_wr": true, "mbps_rd_max": true, "mbps_wr_max": true}
	parts := strings.Split(drive, ",")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" || strings.Contains(parts[0], "=") {
		return "", errors.New("unsafe disk volume identity")
	}
	out := []string{strings.TrimSpace(parts[0])}
	for _, segment := range parts[1:] {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		key, _, ok := strings.Cut(segment, "=")
		if !ok || key == "" {
			return "", errors.New("invalid existing disk configuration")
		}
		if !managed[key] {
			out = append(out, segment)
		}
	}
	for _, item := range []struct {
		key string
		val *int64
	}{{"iops_rd", p.Limits.IOPSRead}, {"iops_wr", p.Limits.IOPSWrite}, {"iops_rd_max", p.Limits.IOPSReadMax}, {"iops_wr_max", p.Limits.IOPSWriteMax}, {"iops_rd_max_length", p.Limits.IOPSReadMaxLength}, {"iops_wr_max_length", p.Limits.IOPSWriteMaxLength}, {"mbps_rd", p.Limits.MBPSRead}, {"mbps_wr", p.Limits.MBPSWrite}, {"mbps_rd_max", p.Limits.MBPSReadMax}, {"mbps_wr_max", p.Limits.MBPSWriteMax}} {
		if item.val != nil {
			out = append(out, item.key+"="+strconv.FormatInt(*item.val, 10))
		}
	}
	return strings.Join(out, ","), nil
}

type DeliveryVerificationResult struct {
	Ready               bool      `json:"ready"`
	ObservedAt          time.Time `json:"observedAt"`
	PowerState          string    `json:"powerState"`
	ConfigMatched       bool      `json:"configMatched"`
	DiskIOMatched       bool      `json:"diskIoMatched"`
	NetworkMatched      bool      `json:"networkMatched"`
	FirewallMatched     bool      `json:"firewallMatched"`
	QGAFresh            bool      `json:"qgaFresh"`
	GuestAddressMatched bool      `json:"guestAddressMatched"`
	TimezoneMatched     bool      `json:"timezoneMatched"`
}

func verifyDelivery(ctx context.Context, client *pve.Client, command Command) (json.RawMessage, error) {
	var p deliveryP
	if err := strictParameters(command.Parameters, &p); err != nil {
		return nil, err
	}
	current, err := client.GuestCurrent(ctx, command.Identity.GuestType, command.Identity.NodeRef, command.Identity.VMID)
	if err != nil {
		return nil, err
	}
	if strings.ToLower(strings.TrimSpace(current.Status)) != "running" {
		return nil, errors.New("guest is not running")
	}
	config, err := client.GuestConfig(ctx, command.Identity.GuestType, command.Identity.NodeRef, command.Identity.VMID)
	if err != nil {
		return nil, err
	}
	for key, expected := range map[string]int{"cores": p.Expected.Cores, "sockets": p.Expected.Sockets, "memory": p.Expected.MemoryMiB} {
		actual, ok := configInt(config.Raw, key)
		if !ok || actual != expected {
			return nil, fmt.Errorf("guest %s does not match delivery contract", key)
		}
	}
	drive, ok := configString(config.Raw, p.Expected.Disk.Interface)
	if !ok {
		return nil, errors.New("delivery disk does not exist")
	}
	diskBytes, err := diskSizeBytes(drive)
	if err != nil || diskBytes < uint64(p.Expected.Disk.MinimumGiB)<<30 {
		return nil, errors.New("delivery disk size is below the required minimum")
	}
	if !diskLimitsMatch(drive, p.Expected.Disk.Limits) {
		return nil, errors.New("delivery disk IO limits do not match")
	}
	observation, err := client.ProbeGuestAgent(ctx, command.Identity.NodeRef, command.Identity.VMID)
	if err != nil {
		return nil, err
	}
	if observation.Availability["info"] != pve.Available || observation.Availability["interfaces"] != pve.Available {
		return nil, errors.New("QGA delivery information is unavailable")
	}
	for _, expected := range p.Expected.Networks {
		value, exists := configString(config.Raw, expected.Interface)
		if !exists || !networkMatches(config.Raw, value, expected) {
			return nil, fmt.Errorf("delivery network %s does not match", expected.Interface)
		}
		if !qgaAddressesMatch(observation.Interfaces, expected) {
			return nil, fmt.Errorf("delivery network %s guest addresses are not ready", expected.Interface)
		}
		if *expected.Firewall {
			if err := verifyIPFilter(ctx, client, command, expected); err != nil {
				return nil, err
			}
		} else if err := verifyGuestFirewallDisabled(ctx, client, command); err != nil {
			return nil, err
		}
	}
	timezone, err := client.ReadGuestTimezone(ctx, command.Identity.NodeRef, command.Identity.VMID)
	if err != nil || timezone.Zone != p.Expected.Timezone {
		return nil, errors.New("guest timezone does not match delivery contract")
	}
	// The frozen cross-language receipt contract uses whole-second UTC. Keep
	// the observation boundary deterministic instead of emitting RFC3339Nano.
	observedAt := time.Now().UTC().Truncate(time.Second)
	if observedAt.Before(p.NotBefore) {
		return nil, errors.New("delivery verification observation predates the command boundary")
	}
	result, err := json.Marshal(DeliveryVerificationResult{Ready: true, ObservedAt: observedAt, PowerState: "running", ConfigMatched: true, DiskIOMatched: true, NetworkMatched: true, FirewallMatched: true, QGAFresh: true, GuestAddressMatched: true, TimezoneMatched: true})
	return result, err
}
func diskLimitsMatch(drive string, expected diskIOLimits) bool {
	actual := map[string]string{}
	for _, segment := range strings.Split(drive, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(segment), "=")
		if ok {
			actual[key] = value
		}
	}
	for _, item := range []struct {
		key   string
		value *int64
	}{{"iops_rd", expected.IOPSRead}, {"iops_wr", expected.IOPSWrite}, {"iops_rd_max", expected.IOPSReadMax}, {"iops_wr_max", expected.IOPSWriteMax}, {"iops_rd_max_length", expected.IOPSReadMaxLength}, {"iops_wr_max_length", expected.IOPSWriteMaxLength}, {"mbps_rd", expected.MBPSRead}, {"mbps_wr", expected.MBPSWrite}, {"mbps_rd_max", expected.MBPSReadMax}, {"mbps_wr_max", expected.MBPSWriteMax}} {
		value, exists := actual[item.key]
		if item.value == nil && exists || item.value != nil && (!exists || value != strconv.FormatInt(*item.value, 10)) {
			return false
		}
	}
	return true
}
func networkMatches(raw map[string]json.RawMessage, value string, expected deliveryNetwork) bool {
	parts := map[string]string{}
	for _, segment := range strings.Split(value, ",") {
		key, candidate, ok := strings.Cut(strings.TrimSpace(segment), "=")
		if !ok {
			return false
		}
		parts[key] = candidate
	}
	configuredMAC := ""
	for _, model := range []string{"virtio", "e1000", "e1000e", "vmxnet3", "rtl8139"} {
		if parts[model] != "" {
			configuredMAC = parts[model]
		}
	}
	if !strings.EqualFold(configuredMAC, expected.MAC) || parts["bridge"] != expected.Bridge || parts["mtu"] != strconv.Itoa(expected.MTU) || !deliveryFirewallMatches(parts["firewall"], *expected.Firewall) || normalizedRate(parts["rate"]) != normalizedRate(expected.RateMbps) {
		return false
	}
	if expected.VLAN == nil && parts["tag"] != "" || expected.VLAN != nil && parts["tag"] != strconv.Itoa(*expected.VLAN) {
		return false
	}
	ipconfig, ok := configString(raw, "ipconfig"+strings.TrimPrefix(expected.Interface, "net"))
	if !ok {
		return false
	}
	addresses := map[string]string{}
	for _, segment := range strings.Split(ipconfig, ",") {
		key, value, valid := strings.Cut(strings.TrimSpace(segment), "=")
		if valid {
			addresses[key] = value
		}
	}
	return addresses["ip"] == expected.IPv4 && addresses["ip6"] == expected.IPv6
}
func deliveryFirewallMatches(raw string, expected bool) bool {
	raw = strings.TrimSpace(raw)
	if expected {
		return raw == "1"
	}
	// PVE may serialize an explicit false as firewall=0 or omit the
	// default-valued property entirely.  Both are authoritative disabled
	// states; every other representation is rejected.
	return raw == "" || raw == "0"
}
func normalizedRate(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "0" || value == "0.0" {
		return "0"
	}
	number, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return value
	}
	return strconv.FormatFloat(number, 'f', -1, 64)
}
func qgaAddressesMatch(interfaces []pve.GuestInterface, expected deliveryNetwork) bool {
	wanted := map[string]bool{}
	for _, configured := range []string{expected.IPv4, expected.IPv6} {
		address := strings.SplitN(configured, "/", 2)[0]
		if net.ParseIP(address) != nil {
			wanted[address] = true
		}
	}
	for _, iface := range interfaces {
		if !strings.EqualFold(strings.TrimSpace(iface.HardwareAddress), expected.MAC) {
			continue
		}
		present := map[string]bool{}
		for _, address := range iface.IPAddresses {
			present[strings.TrimSpace(address.Address)] = true
		}
		for address := range wanted {
			if !present[address] {
				return false
			}
		}
		return true
	}
	return false
}
func verifyIPFilter(ctx context.Context, client *pve.Client, command Command, expected deliveryNetwork) error {
	return verifyExpectedIPFilter(ctx, client, command, expected.Interface, expected.IPFilterCIDRs)
}
func verifyGuestFirewallDisabled(ctx context.Context, client *pve.Client, command Command) error {
	ref := pve.FirewallRef{Node: command.Identity.NodeRef, Kind: command.Identity.GuestType, VMID: command.Identity.VMID}
	options, err := client.FirewallOptions(ctx, ref)
	if err != nil {
		return err
	}
	if options.Enable != nil && *options.Enable != 0 {
		return errors.New("guest firewall is enabled but delivery expects it disabled")
	}
	return nil
}
func verifyExpectedIPFilter(ctx context.Context, client *pve.Client, command Command, interfaceRef string, expectedCIDRs []string) error {
	if _, err := verifyGuestFirewallProtection(ctx, client, command); err != nil {
		return err
	}
	config, err := client.GuestConfig(ctx, command.Identity.GuestType, command.Identity.NodeRef, command.Identity.VMID)
	if err != nil {
		return err
	}
	if !guestNetworkFirewallEnabled(config, interfaceRef) {
		return fmt.Errorf("guest network %s firewall is not enabled", interfaceRef)
	}
	return verifyExpectedIPFilterSet(ctx, client, command, interfaceRef, expectedCIDRs)
}
func verifyGuestFirewallProtection(ctx context.Context, client *pve.Client, command Command) (pve.FirewallOptions, error) {
	clusterOptions, err := client.FirewallOptions(ctx, pve.FirewallRef{})
	if err != nil || clusterOptions.Enable == nil || *clusterOptions.Enable != 1 {
		return pve.FirewallOptions{}, errors.New("cluster firewall is not enabled")
	}
	// On PVE's iptables firewall, the cluster-wide ebtables switch controls
	// generation of the layer-2 source-MAC rules. The documented default is
	// enabled when absent, but an explicit zero makes guest macfilter=1
	// ineffective and must therefore fail the protection proof.
	if clusterOptions.Ebtables != nil && *clusterOptions.Ebtables != 1 {
		return pve.FirewallOptions{}, errors.New("cluster layer-2 firewall is not enabled")
	}
	ref := pve.FirewallRef{Node: command.Identity.NodeRef, Kind: command.Identity.GuestType, VMID: command.Identity.VMID}
	options, err := client.FirewallOptions(ctx, ref)
	if err != nil || options.Enable == nil || *options.Enable != 1 {
		return pve.FirewallOptions{}, errors.New("guest firewall is not enabled")
	}
	policyIn := options.PolicyIn
	if policyIn == "" {
		policyIn = "DROP"
	}
	policyOut := options.PolicyOut
	if policyOut == "" {
		policyOut = "ACCEPT"
	}
	macFilterEnabled := options.MACFilter == nil || *options.MACFilter == 1
	if policyIn != "ACCEPT" || policyOut != "ACCEPT" || !macFilterEnabled {
		return pve.FirewallOptions{}, errors.New("guest firewall anti-spoof policy is not delivery-safe")
	}
	return options, nil
}
func verifyExpectedIPFilterSet(ctx context.Context, client *pve.Client, command Command, interfaceRef string, expectedCIDRs []string) error {
	ref := pve.FirewallRef{Node: command.Identity.NodeRef, Kind: command.Identity.GuestType, VMID: command.Identity.VMID}
	name := "ipfilter-" + interfaceRef
	sets, err := client.FirewallIPSets(ctx, ref)
	if err != nil {
		return err
	}
	found := false
	for _, set := range sets {
		found = found || set.Name == name
	}
	if !found {
		return fmt.Errorf("guest IP filter %s does not exist", name)
	}
	entries, err := client.FirewallIPSetEntries(ctx, ref, name)
	if err != nil {
		return err
	}
	actual := map[string]bool{}
	for _, entry := range entries {
		if entry.NoMatch != nil && *entry.NoMatch != 0 {
			return fmt.Errorf("guest IP filter %s contains a negative entry", name)
		}
		actual[entry.CIDR] = true
	}
	if len(actual) != len(expectedCIDRs) {
		return fmt.Errorf("guest IP filter %s does not match assigned addresses", name)
	}
	for _, cidr := range expectedCIDRs {
		if !actual[cidr] {
			return fmt.Errorf("guest IP filter %s does not match assigned addresses", name)
		}
	}
	return nil
}

type IPFilterVerificationResult struct {
	Verified             bool                                `json:"verified"`
	ObservedAt           time.Time                           `json:"observedAt"`
	GuestFirewallEnabled bool                                `json:"guestFirewallEnabled"`
	PolicyIn             string                              `json:"policyIn"`
	PolicyOut            string                              `json:"policyOut"`
	MACFilterEnabled     bool                                `json:"macFilterEnabled"`
	Networks             []IPFilterVerificationNetworkResult `json:"networks"`
}
type IPFilterVerificationNetworkResult struct {
	Interface       string   `json:"interface"`
	MACAddress      *string  `json:"macAddress,omitempty"`
	FirewallEnabled bool     `json:"firewallEnabled"`
	IPFilterEnabled bool     `json:"ipFilterEnabled"`
	IPSet           string   `json:"ipSet"`
	IPFilterCIDRs   []string `json:"ipFilterCidrs"`
}

func verifyGuestIPFilter(ctx context.Context, client *pve.Client, command Command) (json.RawMessage, error) {
	var parameters ipFilterVerifyP
	if err := strictParameters(command.Parameters, &parameters); err != nil {
		return nil, err
	}
	if _, err := verifyGuestFirewallProtection(ctx, client, command); err != nil {
		return nil, err
	}
	config, err := client.GuestConfig(ctx, command.Identity.GuestType, command.Identity.NodeRef, command.Identity.VMID)
	if err != nil {
		return nil, err
	}
	result := IPFilterVerificationResult{
		Verified: true, ObservedAt: time.Now().UTC().Truncate(time.Second), GuestFirewallEnabled: true,
		PolicyIn: "ACCEPT", PolicyOut: "ACCEPT", MACFilterEnabled: true,
		Networks: make([]IPFilterVerificationNetworkResult, 0, len(parameters.Networks)),
	}
	for _, expected := range parameters.Networks {
		if err := verifyExpectedNetworkMAC(config, command.Identity.GuestType, expected); err != nil {
			return nil, err
		}
		if !guestNetworkFirewallEnabled(config, expected.Interface) {
			return nil, fmt.Errorf("guest network %s firewall is not enabled", expected.Interface)
		}
		if err := verifyExpectedIPFilterSet(ctx, client, command, expected.Interface, expected.IPFilterCIDRs); err != nil {
			return nil, err
		}
		result.Networks = append(result.Networks, IPFilterVerificationNetworkResult{
			Interface:       expected.Interface,
			MACAddress:      cloneString(expected.MACAddress),
			FirewallEnabled: true,
			IPFilterEnabled: true,
			IPSet:           "ipfilter-" + expected.Interface,
			IPFilterCIDRs:   append([]string(nil), expected.IPFilterCIDRs...),
		})
	}
	return json.Marshal(result)
}

type IPFilterSetVerificationResult struct {
	Verified             bool                                   `json:"verified"`
	ObservedAt           time.Time                              `json:"observedAt"`
	EnforcementState     string                                 `json:"enforcementState"`
	GuestFirewallEnabled bool                                   `json:"guestFirewallEnabled"`
	Networks             []IPFilterSetVerificationNetworkResult `json:"networks"`
}

type IPFilterSetVerificationNetworkResult struct {
	Interface       string   `json:"interface"`
	MACAddress      *string  `json:"macAddress,omitempty"`
	FirewallEnabled bool     `json:"firewallEnabled"`
	IPSet           string   `json:"ipSet"`
	IPFilterCIDRs   []string `json:"ipFilterCidrs"`
}

// verifyGuestIPFilterSets proves that per-NIC anti-spoof sets are ready while
// enforcement is deliberately off. PVE activates a set named ipfilter-netN
// when guest and NIC firewalls are later enabled; ipfilter-netN is not a guest
// firewall option and must never be sent to /firewall/options.
func verifyGuestIPFilterSets(ctx context.Context, client *pve.Client, command Command) (json.RawMessage, error) {
	var parameters ipFilterVerifyP
	if err := strictParameters(command.Parameters, &parameters); err != nil {
		return nil, err
	}
	if err := verifyGuestFirewallDisabled(ctx, client, command); err != nil {
		return nil, err
	}
	config, err := client.GuestConfig(ctx, command.Identity.GuestType, command.Identity.NodeRef, command.Identity.VMID)
	if err != nil {
		return nil, err
	}
	result := IPFilterSetVerificationResult{
		Verified: true, ObservedAt: time.Now().UTC().Truncate(time.Second),
		EnforcementState: "preconfigured-not-enforcing", GuestFirewallEnabled: false,
		Networks: make([]IPFilterSetVerificationNetworkResult, 0, len(parameters.Networks)),
	}
	for _, expected := range parameters.Networks {
		if err := verifyExpectedNetworkMAC(config, command.Identity.GuestType, expected); err != nil {
			return nil, err
		}
		if !guestNetworkFirewallDisabled(config, expected.Interface) {
			return nil, fmt.Errorf("guest network %s firewall is not disabled", expected.Interface)
		}
		if err := verifyExpectedIPFilterSet(ctx, client, command, expected.Interface, expected.IPFilterCIDRs); err != nil {
			return nil, err
		}
		result.Networks = append(result.Networks, IPFilterSetVerificationNetworkResult{
			Interface: expected.Interface, MACAddress: cloneString(expected.MACAddress), FirewallEnabled: false, IPSet: "ipfilter-" + expected.Interface,
			IPFilterCIDRs: append([]string(nil), expected.IPFilterCIDRs...),
		})
	}
	return json.Marshal(result)
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func validSignedMAC(value string) bool {
	if !deliveryMACRE.MatchString(value) {
		return false
	}
	parsed, err := net.ParseMAC(value)
	if err != nil || len(parsed) != 6 || parsed[0]&1 != 0 {
		return false
	}
	for _, part := range parsed {
		if part != 0 {
			return true
		}
	}
	return false
}

func verifyExpectedNetworkMAC(config pve.GuestConfig, kind string, expected ipFilterVerifyNetwork) error {
	if expected.MACAddress == nil {
		return nil
	}
	actual, ok := guestNetworkMAC(config, kind, expected.Interface)
	if !ok || actual != *expected.MACAddress {
		return fmt.Errorf("guest network %s MAC address does not match the signed assignment", expected.Interface)
	}
	return nil
}

func guestNetworkMAC(config pve.GuestConfig, kind, interfaceRef string) (string, bool) {
	value, ok := configString(config.Raw, interfaceRef)
	if !ok {
		return "", false
	}
	actual := ""
	for _, segment := range strings.Split(value, ",") {
		key, candidate, present := strings.Cut(strings.TrimSpace(segment), "=")
		if !present {
			return "", false
		}
		if kind == "qemu" && validModel(key) || kind == "lxc" && key == "hwaddr" {
			candidate = strings.ToUpper(candidate)
			if actual != "" || !validSignedMAC(candidate) {
				return "", false
			}
			actual = candidate
		}
	}
	return actual, actual != ""
}

func guestNetworkFirewallEnabled(config pve.GuestConfig, interfaceRef string) bool {
	value, ok := configString(config.Raw, interfaceRef)
	if !ok {
		return false
	}
	for _, segment := range strings.Split(value, ",") {
		key, candidate, present := strings.Cut(strings.TrimSpace(segment), "=")
		if present && key == "firewall" {
			return candidate == "1"
		}
	}
	return false
}

func guestNetworkFirewallDisabled(config pve.GuestConfig, interfaceRef string) bool {
	value, ok := configString(config.Raw, interfaceRef)
	if !ok {
		return false
	}
	rawFirewall := ""
	seenFirewall := false
	for _, segment := range strings.Split(value, ",") {
		key, candidate, present := strings.Cut(strings.TrimSpace(segment), "=")
		if !present || strings.TrimSpace(key) == "" {
			return false
		}
		if key == "firewall" {
			if seenFirewall {
				return false
			}
			seenFirewall, rawFirewall = true, candidate
		}
	}
	return deliveryFirewallMatches(rawFirewall, false)
}
func validNetwork(p networkP, kind string) bool {
	if !netRE.MatchString(p.Interface) || (p.Bridge == nil && p.Model == nil && p.MAC == nil && p.VLAN == nil && p.MTU == nil && p.Firewall == nil && p.RateMbps == nil && p.IPv4 == nil && p.IPv6 == nil && p.Gateway4 == nil && p.Gateway6 == nil) || (kind == "lxc" && p.Model != nil) {
		return false
	}
	if p.Bridge != nil && !nodeRE.MatchString(*p.Bridge) || p.Model != nil && !validModel(*p.Model) || p.MAC != nil && !macRE.MatchString(*p.MAC) || p.VLAN != nil && (*p.VLAN < 0 || *p.VLAN > 4094) || p.MTU != nil && (*p.MTU < 576 || *p.MTU > 9216) || p.RateMbps != nil && !validRate(*p.RateMbps) || p.IPv4 != nil && !validIP(*p.IPv4, 4) || p.IPv6 != nil && !validIP(*p.IPv6, 6) || p.Gateway4 != nil && !validGateway(*p.Gateway4, 4) || p.Gateway6 != nil && !validGateway(*p.Gateway6, 6) {
		return false
	}
	return true
}
func validModel(v string) bool {
	switch v {
	case "virtio", "e1000", "e1000e", "vmxnet3", "rtl8139":
		return true
	}
	return false
}
func validIP(v string, family int) bool {
	if v == "" {
		return true
	}
	if family == 4 && (v == "dhcp" || v == "manual") || family == 6 && (v == "auto" || v == "dhcp" || v == "manual") {
		return true
	}
	ip, n, err := net.ParseCIDR(v)
	return err == nil && ((family == 4 && ip.To4() != nil && n.IP.To4() != nil) || (family == 6 && ip.To4() == nil && n.IP.To4() == nil))
}
func validGateway(v string, family int) bool {
	if v == "" {
		return true
	}
	ip := net.ParseIP(v)
	return ip != nil && ((family == 4 && ip.To4() != nil) || (family == 6 && ip.To4() == nil))
}
func validTemplate(v string) bool {
	return regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`).MatchString(v) && !strings.Contains(v, "..")
}
func validCompress(v string) bool {
	return v == "" || v == "zstd" || v == "lzo" || v == "gzip" || v == "0"
}
func validBackupVolume(v string) bool {
	return regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}:(backup/)?[A-Za-z0-9][A-Za-z0-9._-]{0,191}$`).MatchString(v) && !strings.Contains(v, "..")
}
func validFirewall(p firewallP) bool {
	if p.Enable == nil || (p.Direction != "in" && p.Direction != "out") || (p.Action != "ACCEPT" && p.Action != "DROP" && p.Action != "REJECT") || (p.Protocol != "" && p.Protocol != "tcp" && p.Protocol != "udp" && p.Protocol != "icmp" && p.Protocol != "icmpv6") || !validFirewallAddress(p.Source) || !validFirewallAddress(p.Destination) || !validPortList(p.DestinationPort) || (p.DestinationPort != "" && p.Protocol != "tcp" && p.Protocol != "udp") || len(p.Comment) > 256 || strings.ContainsAny(p.Comment, "\x00\r\n") {
		return false
	}
	return true
}

func validFirewallPolicy(value string) bool {
	return value == "" || value == "ACCEPT" || value == "DROP" || value == "REJECT"
}

func validPortList(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > 512 || !portListRE.MatchString(value) {
		return false
	}
	for _, item := range strings.Split(value, ",") {
		firstText, lastText, ranged := strings.Cut(item, "-")
		first, err := strconv.Atoi(firstText)
		if err != nil || first < 1 || first > 65535 {
			return false
		}
		if !ranged {
			continue
		}
		last, err := strconv.Atoi(lastText)
		if err != nil || last < first || last > 65535 || strings.Contains(lastText, "-") {
			return false
		}
	}
	return true
}
func validFirewallAddress(v string) bool {
	if v == "" {
		return true
	}
	// PVE firewall rules may reference an IPSet as +set (or negate it as
	// -set). Treat it as a typed name, never a free-form rule fragment.
	if (strings.HasPrefix(v, "+") || strings.HasPrefix(v, "-")) && nameRE.MatchString(v[1:]) {
		return true
	}
	_, _, err := net.ParseCIDR(v)
	return err == nil
}

func validIPSetEntry(name, cidr string) bool {
	return nameRE.MatchString(name) && cidr != "" && validFirewallAddress(cidr)
}

func validIPSetComment(comment string) bool {
	return len(comment) <= 256 && !strings.ContainsAny(comment, "\x00\r\n")
}
func firewallForm(p firewallP) url.Values {
	f := url.Values{"type": {p.Direction}, "action": {p.Action}, "enable": {boolText(*p.Enable)}}
	if p.Protocol != "" {
		f.Set("proto", p.Protocol)
	}
	if p.Source != "" {
		f.Set("source", p.Source)
	}
	if p.Destination != "" {
		f.Set("dest", p.Destination)
	}
	if p.DestinationPort != "" {
		f.Set("dport", p.DestinationPort)
	}
	if p.Comment != "" {
		f.Set("comment", p.Comment)
	}
	return f
}

func configString(raw map[string]json.RawMessage, key string) (string, bool) {
	v, ok := raw[key]
	if !ok {
		return "", false
	}
	var s string
	if json.Unmarshal(v, &s) != nil || s == "" || len(s) > 4096 || strings.ContainsAny(s, "\r\n\x00") {
		return "", false
	}
	return s, true
}
func configInt(raw map[string]json.RawMessage, key string) (int, bool) {
	v, ok := raw[key]
	if !ok {
		return 0, false
	}
	var n int
	if json.Unmarshal(v, &n) == nil {
		return n, true
	}
	var s string
	if json.Unmarshal(v, &s) == nil {
		n, err := strconv.Atoi(s)
		return n, err == nil
	}
	return 0, false
}
func mergeNetwork(kind, old string, p networkP) (string, error) {
	if len(old) > 4096 || strings.ContainsAny(old, "\r\n\x00") {
		return "", errors.New("unsafe existing network configuration")
	}
	parts := strings.Split(old, ",")
	out := make([]string, 0, len(parts)+6)
	model, mac := "", ""
	for _, part := range parts {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return "", errors.New("invalid existing network configuration")
		}
		if kind == "qemu" && validModel(key) {
			model, mac = key, value
			continue
		}
		if replaceKey(kind, key, p) {
			continue
		}
		out = append(out, key+"="+value)
	}
	if kind == "qemu" {
		if p.Model != nil {
			model = *p.Model
		}
		if p.MAC != nil {
			mac = *p.MAC
		}
		if !validModel(model) || !macRE.MatchString(mac) {
			return "", errors.New("unsafe qemu network configuration")
		}
		out = append([]string{model + "=" + mac}, out...)
	} else {
		if p.MAC != nil {
			out = append(out, "hwaddr="+*p.MAC)
		}
		if p.IPv4 != nil {
			out = append(out, "ip="+*p.IPv4)
		}
		if p.IPv6 != nil {
			out = append(out, "ip6="+*p.IPv6)
		}
		if p.Gateway4 != nil {
			out = append(out, "gw="+*p.Gateway4)
		}
		if p.Gateway6 != nil {
			out = append(out, "gw6="+*p.Gateway6)
		}
	}
	if p.Bridge != nil {
		out = append(out, "bridge="+*p.Bridge)
	}
	if p.VLAN != nil {
		out = append(out, "tag="+strconv.Itoa(*p.VLAN))
	}
	if p.MTU != nil {
		out = append(out, "mtu="+strconv.Itoa(*p.MTU))
	}
	if p.Firewall != nil {
		out = append(out, "firewall="+boolText(*p.Firewall))
	}
	if p.RateMbps != nil && *p.RateMbps != "0" {
		out = append(out, "rate="+*p.RateMbps)
	}
	return strings.Join(out, ","), nil
}
func replaceKey(kind, key string, p networkP) bool {
	switch key {
	case "bridge":
		return p.Bridge != nil
	case "tag":
		return p.VLAN != nil
	case "mtu":
		return p.MTU != nil
	case "firewall":
		return p.Firewall != nil
	case "rate":
		return p.RateMbps != nil
	case "hwaddr":
		return kind == "lxc" && p.MAC != nil
	case "ip":
		return kind == "lxc" && p.IPv4 != nil
	case "ip6":
		return kind == "lxc" && p.IPv6 != nil
	case "gw":
		return kind == "lxc" && p.Gateway4 != nil
	case "gw6":
		return kind == "lxc" && p.Gateway6 != nil
	}
	return false
}
func mergeIP(old string, p networkP) (string, error) {
	if len(old) > 4096 || strings.ContainsAny(old, "\r\n\x00") {
		return "", errors.New("unsafe existing ip configuration")
	}
	out := []string{}
	if old != "" {
		for _, part := range strings.Split(old, ",") {
			key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
			if !ok {
				return "", errors.New("invalid existing ip configuration")
			}
			if (key == "ip" && p.IPv4 != nil) || (key == "ip6" && p.IPv6 != nil) || (key == "gw" && p.Gateway4 != nil) || (key == "gw6" && p.Gateway6 != nil) {
				continue
			}
			out = append(out, key+"="+value)
		}
	}
	if p.IPv4 != nil {
		out = append(out, "ip="+*p.IPv4)
	}
	if p.IPv6 != nil {
		out = append(out, "ip6="+*p.IPv6)
	}
	if p.Gateway4 != nil {
		out = append(out, "gw="+*p.Gateway4)
	}
	if p.Gateway6 != nil {
		out = append(out, "gw6="+*p.Gateway6)
	}
	return strings.Join(out, ","), nil
}

func strictParameters(raw json.RawMessage, target any) error {
	if err := validateJSONObject(raw); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := d.Decode(&trailing); err != io.EOF {
		return errors.New("multiple parameter values")
	}
	return nil
}

// validateJSONObject rejects non-object parameter values and duplicate keys
// at every nesting level. encoding/json otherwise silently accepts the last
// duplicate, which makes a signed body ambiguous across implementations.
func validateJSONObject(raw json.RawMessage) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '{' {
		return errors.New("parameters must be a JSON object")
	}
	if err := consumeJSONObject(d, 1); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		if err == nil {
			return errors.New("parameters contain multiple JSON values")
		}
		return err
	}
	return nil
}

func consumeJSONObject(d *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return errors.New("JSON nesting is too deep")
	}
	seen := map[string]struct{}{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("object key is not a string")
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("duplicate JSON field %q", key)
		}
		seen[key] = struct{}{}
		if err := consumeJSONValue(d, depth+1); err != nil {
			return err
		}
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	if delim, ok := token.(json.Delim); !ok || delim != '}' {
		return errors.New("unterminated JSON object")
	}
	return nil
}

func consumeJSONValue(d *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return errors.New("JSON nesting is too deep")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		return consumeJSONObject(d, depth)
	case '[':
		for d.More() {
			if err := consumeJSONValue(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil {
			return err
		}
		if close, ok := end.(json.Delim); !ok || close != ']' {
			return errors.New("unterminated JSON array")
		}
		return nil
	default:
		return errors.New("unexpected JSON delimiter")
	}
}
func requireEmptyObject(raw json.RawMessage) error {
	var v map[string]any
	if err := strictParameters(raw, &v); err != nil {
		return err
	}
	if len(v) != 0 {
		return errors.New("action accepts no parameters")
	}
	return nil
}
func boolText(v bool) string {
	if v {
		return "1"
	}
	return "0"
}
func validRate(v string) bool {
	if !regexp.MustCompile(`^(0|[1-9][0-9]{0,5})(\.[0-9]{1,3})?$`).MatchString(v) {
		return false
	}
	n, err := strconv.ParseFloat(v, 64)
	return err == nil && n <= 100000
}
func replaceRate(network, rate string) (string, error) {
	if strings.ContainsAny(network, "\r\n\x00") || len(network) > 4096 {
		return "", errors.New("unsafe existing network configuration")
	}
	parts := strings.Split(network, ",")
	out := parts[:0]
	for _, part := range parts {
		if !strings.HasPrefix(strings.TrimSpace(part), "rate=") {
			out = append(out, part)
		}
	}
	if rate != "0" {
		out = append(out, "rate="+rate)
	}
	return strings.Join(out, ","), nil
}
