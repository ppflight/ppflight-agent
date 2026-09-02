package admincli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	templateBridgeApplyTimeout       = 2 * time.Minute
	templateBridgeOperationTimeout   = 3 * time.Minute
	templateBridgeNetworkLockTimeout = 12 * time.Second
	templateBridgeNetworkFileMaxSize = 4 << 20
	templateBridgeOwnershipComment   = "PPFlight private template bridge"
	templateBridgePerl               = "/usr/bin/perl"
	templateBridgePVESh              = "/usr/bin/pvesh"
	templateBridgeIP                 = "/usr/sbin/ip"
	templateBridgePerlParser         = `use strict; use warnings; my $path = shift @ARGV; open(my $fh, '<', $path) or die "open: $!"; my $cfg = PVE::INotify::__read_etc_network_interfaces($fh, {}, []); close($fh) or die "close: $!"; print JSON::PP->new->canonical(1)->encode($cfg);`
)

var templateBridgeUPIDPattern = regexp.MustCompile(`\AUPID:[A-Za-z0-9@!+,:._-]{1,511}\z`)

type templateBridgeState struct {
	Exists        bool
	Iface         string
	Type          string
	Autostart     bool
	BridgePorts   string
	BridgeSTP     string
	BridgeFD      string
	Comments      string
	Method        string
	Method6       string
	Address       string
	Address6      string
	CIDR          string
	CIDR6         string
	Gateway       string
	Gateway6      string
	KernelPresent bool
	KernelType    string
	KernelUp      bool
	KernelAddress []templateBridgeKernelAddress
	KernelMembers []string
}

type templateBridgeKernelAddress struct {
	Family string
	Local  string
	Scope  string
}

type templateBridgeManager interface {
	Inspect(context.Context, string) (templateBridgeState, error)
	Create(context.Context, string) (templateBridgeState, error)
}

func (c *cli) ensureTemplateInternalBridge(ctx context.Context, reader *bufio.Reader, name string) (bool, error) {
	if !safeTemplateBridgeName(name) {
		return false, errors.New("内网网桥名称无效")
	}
	manager := c.templateBridges
	if manager == nil {
		node, err := c.localPVENodeName()
		if err != nil {
			return false, err
		}
		manager = newPVETemplateBridgeManager(node, templateBridgeExecRunner{})
	}
	inspectCtx, cancelInspect := context.WithTimeout(ctx, templateBridgeOperationTimeout)
	state, err := manager.Inspect(inspectCtx, name)
	cancelInspect()
	if err != nil {
		return false, fmt.Errorf("读取 PVE 网桥失败: %w", err)
	}
	if state.Exists {
		if err := validateExistingTemplateBridge(name, state); err != nil {
			return false, err
		}
		fmt.Fprintf(c.out, "检测到已有 PVE Linux bridge %s；将原样使用，不修改其端口、IP 或网关配置。\n", name)
		return true, nil
	}
	if state.KernelPresent {
		return false, fmt.Errorf("PVE 配置中没有接口 %s，但内核已有同名接口；为避免覆盖手工或其他管理器创建的网络，拒绝自动创建", name)
	}

	fmt.Fprintf(c.out, "内网网桥 %s 当前不存在。\n", name)
	fmt.Fprintln(c.out, "如继续，将创建以下本机 PVE Linux bridge：")
	fmt.Fprintln(c.out, "  物理端口：无（bridge-ports none）")
	fmt.Fprintln(c.out, "  STP/转发延迟：PVE Linux bridge 默认值（off / 0）")
	fmt.Fprintln(c.out, "  IPv4/IPv6 地址：无")
	fmt.Fprintln(c.out, "  默认网关：无")
	fmt.Fprintln(c.out, "  开机自动启动：是")
	confirmed, err := c.promptYesNo(reader, fmt.Sprintf("确认创建内网网桥 %s？[y/N]: ", name), false)
	if err != nil || !confirmed {
		return false, err
	}
	// The administrator may take as long as needed to review the exact change
	// before confirming. Start a fresh operation deadline only after the prompt.
	createCtx, cancelCreate := context.WithTimeout(ctx, templateBridgeOperationTimeout)
	defer cancelCreate()
	created, err := manager.Create(createCtx, name)
	if err != nil {
		return false, fmt.Errorf("创建或应用 PVE 网桥失败: %w", err)
	}
	if err := validateCreatedTemplateBridge(name, created); err != nil {
		return false, fmt.Errorf("创建后的严格回读未通过: %w", err)
	}
	fmt.Fprintf(c.out, "内网网桥 %s 已创建并通过 PVE 配置与内核接口回读。\n", name)
	return true, nil
}

func validateExistingTemplateBridge(name string, state templateBridgeState) error {
	if !state.Exists || state.Iface != name {
		return fmt.Errorf("%s 的 PVE 网桥身份回读不一致", name)
	}
	if state.Type != "bridge" {
		return fmt.Errorf("接口 %s 已存在但类型为 %q，不是 PVE Linux bridge；不会修改现有接口", name, state.Type)
	}
	if !state.KernelPresent {
		return fmt.Errorf("PVE Linux bridge %s 已配置但尚未应用到内核；请先在 PVE 应用网络配置", name)
	}
	if state.KernelType != "bridge" || !state.KernelUp {
		return fmt.Errorf("接口 %s 的内核回读不是已启用的 Linux bridge", name)
	}
	if len(state.KernelMembers) != 0 {
		return fmt.Errorf("接口 %s 的运行态仍挂载端口 %s，不是隔离内网桥", name, strings.Join(state.KernelMembers, ","))
	}
	for _, address := range state.KernelAddress {
		if address.Local == "" {
			continue
		}
		ip := net.ParseIP(address.Local)
		if address.Family == "inet6" && address.Scope == "link" && ip != nil && ip.IsLinkLocalUnicast() {
			continue
		}
		return fmt.Errorf("接口 %s 的内核回读含有非 IPv6 link-local 地址 %s", name, address.Local)
	}
	if err := validateCreatedTemplateBridgeConfig(state); err != nil {
		return fmt.Errorf("已有接口 %s 不是安全隔离的 PPFlight 内网桥；不会修改现有接口: %w", name, err)
	}
	return nil
}

func validateCreatedTemplateBridge(name string, state templateBridgeState) error {
	if err := validateExistingTemplateBridge(name, state); err != nil {
		return err
	}
	if strings.TrimSpace(state.Comments) != templateBridgeOwnershipComment {
		return errors.New("创建后的 ownership comment 回读不一致")
	}
	return nil
}

func validateCreatedTemplateBridgeConfig(state templateBridgeState) error {
	ports := strings.TrimSpace(state.BridgePorts)
	if ports != "" && !strings.EqualFold(ports, "none") {
		return fmt.Errorf("bridge-ports 回读为 %q，不是无物理端口配置", state.BridgePorts)
	}
	if !state.Autostart {
		return errors.New("autostart 回读未启用")
	}
	if strings.TrimSpace(state.Method) != "manual" {
		return fmt.Errorf("IPv4 method 回读为 %q，不是 manual", state.Method)
	}
	if value := strings.TrimSpace(state.Method6); value != "" && value != "manual" {
		return fmt.Errorf("IPv6 method 回读为 %q，不是 manual", state.Method6)
	}
	if hasAnyValue(state.Address, state.Address6, state.CIDR, state.CIDR6) {
		return errors.New("回读发现网桥带有 IPv4/IPv6 地址")
	}
	if hasAnyValue(state.Gateway, state.Gateway6) {
		return errors.New("回读发现网桥带有默认网关")
	}
	if value := strings.ToLower(strings.TrimSpace(state.BridgeSTP)); value != "" && value != "off" && value != "0" && value != "false" {
		return fmt.Errorf("bridge-stp 回读为 %q，不是 off", state.BridgeSTP)
	}
	if value := strings.TrimSpace(state.BridgeFD); value != "" && value != "0" {
		return fmt.Errorf("bridge-fd 回读为 %q，不是 0", state.BridgeFD)
	}
	return nil
}

func hasAnyValue(values ...string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

func safeTemplateBridgeName(value string) bool {
	// Linux IFNAMSIZ includes the terminating NUL, so an interface name is at
	// most 15 bytes even though the template contract accepts longer references
	// for already-existing non-kernel network objects.
	if value == "" || len(value) > 15 {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || index > 0 && strings.ContainsRune("._-", character) {
			continue
		}
		return false
	}
	return true
}

type templateBridgeRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type templateBridgeExecRunner struct{}

func (templateBridgeExecRunner) Run(ctx context.Context, program string, args ...string) ([]byte, error) {
	limit := 16 << 10
	switch program {
	case templateBridgePerl:
		limit = templateBridgeNetworkFileMaxSize
	case templateBridgePVESh, templateBridgeIP:
	default:
		return nil, errors.New("不允许的内网网桥本机命令")
	}
	command := exec.CommandContext(ctx, program, args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
	output := &templateBridgeCappedBuffer{maximum: limit}
	command.Stdout = output
	command.Stderr = output
	err := command.Run()
	if output.overflow {
		return nil, errors.New("内网网桥命令输出超出安全上限")
	}
	if err != nil {
		message := strings.TrimSpace(output.String())
		if message == "" {
			message = err.Error()
		}
		return output.Bytes(), errors.New(message)
	}
	return output.Bytes(), nil
}

type templateBridgeCappedBuffer struct {
	bytes.Buffer
	maximum  int
	overflow bool
}

func (buffer *templateBridgeCappedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	remaining := buffer.maximum - buffer.Len()
	if remaining <= 0 {
		buffer.overflow = true
		return original, nil
	}
	if len(value) > remaining {
		buffer.overflow = true
		value = value[:remaining]
	}
	_, _ = buffer.Buffer.Write(value)
	return original, nil
}

type pveTemplateBridgeManager struct {
	node               string
	runner             templateBridgeRunner
	activeNetworkPath  string
	pendingNetworkPath string
	networkLockPath    string
	kernelProbe        func(string) (bool, error)
	kernelMembers      func(string) ([]string, error)
	requireRootFiles   bool
}

func newPVETemplateBridgeManager(node string, runner templateBridgeRunner) *pveTemplateBridgeManager {
	return &pveTemplateBridgeManager{
		node: node, runner: runner, requireRootFiles: true,
		kernelMembers: templateBridgeKernelMembers,
	}
}

type templateBridgeFileSnapshot struct {
	SHA256 [32]byte
	Size   int64
}

type templateBridgeNetworkBaseline struct {
	file     templateBridgeFileSnapshot
	semantic templateBridgeNetworkSemantic
}

type templateBridgeNetworkSemantic struct {
	root      map[string]any
	canonical []byte
}

func (m *pveTemplateBridgeManager) Inspect(ctx context.Context, name string) (templateBridgeState, error) {
	if !safeTemplateBridgeName(name) || !localPVENodeNamePattern.MatchString(m.node) {
		return templateBridgeState{}, errors.New("PVE 节点或网桥名称无效")
	}
	path := "/nodes/" + m.node + "/network"
	raw, err := m.runner.Run(ctx, templateBridgePVESh, "get", path, "--output-format", "json")
	if err != nil {
		return templateBridgeState{}, err
	}
	var entries []struct {
		Iface string `json:"iface"`
		Type  string `json:"type"`
	}
	if err := decodeSingleJSON(raw, &entries); err != nil {
		return templateBridgeState{}, fmt.Errorf("PVE network 列表不是有效 JSON: %w", err)
	}
	matches := 0
	for _, entry := range entries {
		if entry.Iface == name {
			matches++
		}
	}
	if matches == 0 {
		present, err := m.kernelInterfaceExists(name)
		if err != nil {
			return templateBridgeState{}, fmt.Errorf("检查同名内核接口失败: %w", err)
		}
		return templateBridgeState{KernelPresent: present}, nil
	}
	if matches != 1 {
		return templateBridgeState{}, fmt.Errorf("PVE network 列表中接口 %s 不唯一", name)
	}
	detailRaw, err := m.runner.Run(ctx, templateBridgePVESh, "get", path+"/"+name, "--output-format", "json")
	if err != nil {
		return templateBridgeState{}, err
	}
	var detail map[string]json.RawMessage
	if err := decodeSingleJSON(detailRaw, &detail); err != nil {
		return templateBridgeState{}, fmt.Errorf("PVE network 详情不是有效 JSON: %w", err)
	}
	state, err := decodeTemplateBridgeState(detail)
	if err != nil {
		return templateBridgeState{}, err
	}
	state.Exists = true
	linkRaw, linkErr := m.runner.Run(ctx, templateBridgeIP, "-json", "-details", "link", "show", "dev", name)
	if linkErr == nil {
		var links []struct {
			IfName   string   `json:"ifname"`
			Flags    []string `json:"flags"`
			LinkInfo struct {
				Kind string `json:"info_kind"`
			} `json:"linkinfo"`
		}
		if err := decodeSingleJSON(linkRaw, &links); err != nil {
			return templateBridgeState{}, fmt.Errorf("内核接口回读不是有效 JSON: %w", err)
		}
		if len(links) != 1 || links[0].IfName != name {
			return templateBridgeState{}, fmt.Errorf("内核接口 %s 的身份回读不一致", name)
		}
		state.KernelPresent = true
		state.KernelType = links[0].LinkInfo.Kind
		for _, flag := range links[0].Flags {
			if flag == "UP" {
				state.KernelUp = true
			}
		}
		if state.KernelType == "bridge" {
			members, err := m.bridgeKernelMembers(name)
			if err != nil {
				return templateBridgeState{}, fmt.Errorf("读取内核 bridge 端口失败: %w", err)
			}
			state.KernelMembers = members
		}
		addressRaw, err := m.runner.Run(ctx, templateBridgeIP, "-json", "address", "show", "dev", name)
		if err != nil {
			return templateBridgeState{}, fmt.Errorf("读取内核接口地址失败: %w", err)
		}
		var addresses []struct {
			IfName   string `json:"ifname"`
			AddrInfo []struct {
				Family string `json:"family"`
				Local  string `json:"local"`
				Scope  string `json:"scope"`
			} `json:"addr_info"`
		}
		if err := decodeSingleJSON(addressRaw, &addresses); err != nil {
			return templateBridgeState{}, fmt.Errorf("内核接口地址回读不是有效 JSON: %w", err)
		}
		if len(addresses) != 1 || addresses[0].IfName != name {
			return templateBridgeState{}, fmt.Errorf("内核接口 %s 的地址身份回读不一致", name)
		}
		for _, address := range addresses[0].AddrInfo {
			state.KernelAddress = append(state.KernelAddress, templateBridgeKernelAddress{Family: address.Family, Local: address.Local, Scope: address.Scope})
		}
	}
	return state, nil
}

func (m *pveTemplateBridgeManager) kernelInterfaceExists(name string) (bool, error) {
	if m.kernelProbe != nil {
		return m.kernelProbe(name)
	}
	return templateBridgeKernelInterfaceExists(name)
}

func (m *pveTemplateBridgeManager) bridgeKernelMembers(name string) ([]string, error) {
	if m.kernelMembers == nil {
		// Direct manager values are deterministic test doubles. The production
		// constructor always wires the Linux sysfs bridge-member reader.
		return nil, nil
	}
	return m.kernelMembers(name)
}

func (m *pveTemplateBridgeManager) Create(ctx context.Context, name string) (templateBridgeState, error) {
	return m.createSafely(ctx, name)
}

func (m *pveTemplateBridgeManager) waitForTask(ctx context.Context, upid string) (bool, error) {
	deadline := time.NewTimer(templateBridgeApplyTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		raw, err := m.runner.Run(ctx, templateBridgePVESh, "get", "/nodes/"+m.node+"/tasks/"+upid+"/status", "--output-format", "json")
		if err != nil {
			return false, err
		}
		var status struct {
			Status     string `json:"status"`
			ExitStatus string `json:"exitstatus"`
		}
		if err := decodeSingleJSON(raw, &status); err != nil {
			return false, fmt.Errorf("PVE network apply task 状态不是有效 JSON: %w", err)
		}
		if status.Status == "stopped" {
			if status.ExitStatus != "OK" {
				return true, fmt.Errorf("PVE network apply task 结束状态为 %q", status.ExitStatus)
			}
			return true, nil
		}
		if status.Status != "running" {
			return false, fmt.Errorf("PVE network apply task 状态无效: %q", status.Status)
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-deadline.C:
			return false, errors.New("等待 PVE 应用网络配置超时")
		case <-ticker.C:
		}
	}
}

func parseTemplateBridgeUPID(raw []byte) (string, error) {
	var value string
	if err := decodeSingleJSON(raw, &value); err != nil {
		return "", errors.New("PVE network apply 未返回 JSON UPID")
	}
	if !templateBridgeUPIDPattern.MatchString(value) {
		return "", errors.New("PVE network apply 未返回有效 UPID")
	}
	return value, nil
}

func decodeTemplateBridgeState(detail map[string]json.RawMessage) (templateBridgeState, error) {
	var state templateBridgeState
	var err error
	for key, target := range map[string]*string{
		"iface": &state.Iface, "type": &state.Type, "bridge_ports": &state.BridgePorts,
		"comments": &state.Comments,
		"method":   &state.Method, "method6": &state.Method6,
		"address": &state.Address, "address6": &state.Address6,
		"cidr": &state.CIDR, "cidr6": &state.CIDR6,
		"gateway": &state.Gateway, "gateway6": &state.Gateway6,
	} {
		if raw, ok := detail[key]; ok {
			*target, err = jsonText(raw)
			if err != nil {
				return templateBridgeState{}, fmt.Errorf("PVE network 字段 %s 类型无效", key)
			}
		}
	}
	for key, target := range map[string]*string{"bridge_stp": &state.BridgeSTP, "bridge_fd": &state.BridgeFD} {
		if raw, ok := detail[key]; ok {
			*target, err = jsonScalarText(raw)
			if err != nil {
				return templateBridgeState{}, fmt.Errorf("PVE network 字段 %s 类型无效", key)
			}
		}
	}
	state.Autostart, err = jsonBoolean(detail["autostart"])
	if err != nil {
		return templateBridgeState{}, errors.New("PVE network 字段 autostart 类型无效")
	}
	return state, nil
}

func jsonText(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", err
	}
	return value, nil
}

func jsonScalarText(raw json.RawMessage) (string, error) {
	if value, err := jsonText(raw); err == nil {
		return value, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", err
	}
	switch typed := value.(type) {
	case json.Number:
		return typed.String(), nil
	case bool:
		return strconv.FormatBool(typed), nil
	case nil:
		return "", nil
	default:
		return "", errors.New("not a scalar")
	}
}

func jsonBoolean(raw json.RawMessage) (bool, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return false, nil
	}
	var boolean bool
	if err := json.Unmarshal(raw, &boolean); err == nil {
		return boolean, nil
	}
	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&number); err == nil {
		switch number.String() {
		case "1":
			return true, nil
		case "0":
			return false, nil
		default:
			return false, errors.New("not a boolean")
		}
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		switch strings.ToLower(strings.TrimSpace(text)) {
		case "1", "true", "yes", "on":
			return true, nil
		case "0", "false", "no", "off", "":
			return false, nil
		}
	}
	return false, errors.New("not a boolean")
}

func decodeSingleJSON(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); errors.Is(err, io.EOF) {
		return nil
	} else if err == nil {
		return errors.New("包含额外 JSON")
	} else {
		return err
	}
}
