package hostfirewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type firewallOptions struct {
	Values map[string]any
	Digest string
}

type firewallRule struct {
	Position  int
	Direction string
	Action    string
	Interface string
	Enabled   bool
	Comment   string
}

type firewallRuleSet struct {
	Items  []firewallRule
	Digest string
}

type inputChainOrder struct {
	Family          string
	PVEJumpPosition int
	PrecedingRules  []string
}

type backend interface {
	LocalNode(context.Context) (string, error)
	ClusterNodes(context.Context) ([]string, error)
	DefaultRouteInterfaces(context.Context) ([]string, error)
	ClusterOptions(context.Context) (firewallOptions, error)
	SetClusterOptions(context.Context, map[string]string, []string, string) error
	NodeOptions(context.Context, string) (firewallOptions, error)
	SetNodeOptions(context.Context, string, map[string]string, []string, string) error
	NodeRules(context.Context, string) (firewallRuleSet, error)
	CreateNodeRule(context.Context, string, string, string, bool, int, string) error
	SetNodeRuleEnabled(context.Context, string, int, bool, string) error
	DeleteNodeRule(context.Context, string, int, string) error
	VerifyIngressBackend(context.Context) error
	CaptureIngressGuard(context.Context) ([]nativeInputHookSnapshot, error)
	EnsureIngressGuard(context.Context, Journal) error
	MaintainIngressGuard(context.Context, Journal) (bool, error)
	VerifyIngressGuard(context.Context, Journal) error
	RemoveIngressGuard(context.Context, Journal) error
	EnableIngressGuardPersistence(context.Context) error
	DisableIngressGuardPersistence(context.Context) error
	VerifyIngressGuardPersistence(context.Context) error
	InputChainOrder(context.Context) ([]inputChainOrder, error)
	VerifyRuntimeIngressDrops(context.Context, Journal) error
	Health(context.Context) error
}

type commandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
	RunInput(context.Context, []byte, string, ...string) ([]byte, error)
}

type execRunner struct{}

type firewallNetfilterLockContextKey struct{}

func firewallNetfilterLockHeld(ctx context.Context) bool {
	held, _ := ctx.Value(firewallNetfilterLockContextKey{}).(bool)
	return held
}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return execRunner{}.run(ctx, nil, name, args...)
}

func (execRunner) RunInput(ctx context.Context, input []byte, name string, args ...string) ([]byte, error) {
	if len(input) == 0 || len(input) > 64<<10 {
		return nil, errors.New("command stdin is empty or exceeds safety limit")
	}
	return execRunner{}.run(ctx, input, name, args...)
}

func (execRunner) run(ctx context.Context, input []byte, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	if input != nil {
		command.Stdin = bytes.NewReader(input)
	}
	var output cappedBuffer
	output.maximum = 2 << 20
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(ctx.Err(), context.Canceled) {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%s failed: %w", name, err)
	}
	if output.overflow {
		return nil, fmt.Errorf("%s output exceeded safety limit", name)
	}
	return output.Bytes(), nil
}

type cappedBuffer struct {
	bytes.Buffer
	maximum  int
	overflow bool
}

func (buffer *cappedBuffer) Write(value []byte) (int, error) {
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

type commandBackend struct {
	runner      commandRunner
	client      *http.Client
	pathProbe   func(string) (bool, error)
	processLock func(context.Context) (func(), error)
}

func productionBackend() *commandBackend {
	return &commandBackend{
		runner:      execRunner{},
		pathProbe:   inspectFirewallSelectorPath,
		processLock: acquireFirewallProcessLock,
		client: &http.Client{
			Timeout: 8 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("loopback health redirect rejected")
			},
		},
	}
}

func (b *commandBackend) lockProcess(ctx context.Context) (func(), error) {
	if b.processLock == nil {
		// Direct commandBackend values are test doubles. All production callers
		// are created through productionBackend, which always wires the root-only
		// no-follow flock implementation.
		return func() {}, nil
	}
	return b.processLock(ctx)
}

func (b *commandBackend) pveshGet(ctx context.Context, path string) (json.RawMessage, error) {
	raw, err := b.runner.Run(ctx, "pvesh", "get", path, "--output-format", "json")
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > 2<<20 || !json.Valid(raw) {
		return nil, errors.New("PVE returned invalid JSON")
	}
	return raw, nil
}

func (b *commandBackend) LocalNode(ctx context.Context) (string, error) {
	status, err := b.clusterStatus(ctx)
	if err != nil {
		return "", err
	}
	var found string
	for _, item := range status {
		if canonicalBool(item["local"]) {
			name := strings.TrimSpace(fmt.Sprint(item["name"]))
			if !validNodeName(name) || found != "" {
				return "", errors.New("PVE local node identity is ambiguous")
			}
			found = name
		}
	}
	if found == "" {
		return "", errors.New("PVE local node identity is missing")
	}
	return found, nil
}

func (b *commandBackend) ClusterNodes(ctx context.Context) ([]string, error) {
	status, err := b.clusterStatus(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, item := range status {
		if strings.TrimSpace(fmt.Sprint(item["type"])) != "node" {
			continue
		}
		name := strings.TrimSpace(fmt.Sprint(item["name"]))
		if !validNodeName(name) || seen[name] {
			return nil, errors.New("PVE cluster node inventory is invalid")
		}
		seen[name] = true
	}
	if len(seen) == 0 {
		return nil, errors.New("PVE cluster has no node inventory")
	}
	result := make([]string, 0, len(seen))
	for name := range seen {
		result = append(result, name)
	}
	sort.Strings(result)
	return result, nil
}

func (b *commandBackend) clusterStatus(ctx context.Context) ([]map[string]any, error) {
	raw, err := b.pveshGet(ctx, "/cluster/status")
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var result []map[string]any
	if err := decoder.Decode(&result); err != nil {
		return nil, errors.New("PVE cluster status shape is invalid")
	}
	return result, nil
}

func (b *commandBackend) DefaultRouteInterfaces(ctx context.Context) ([]string, error) {
	var values []string
	for _, family := range []string{"-4", "-6"} {
		raw, err := b.runner.Run(ctx, "ip", "-j", family, "route", "show", "default")
		if err != nil {
			return nil, err
		}
		parsed, err := parseDefaultRouteInterfaces(raw)
		if err != nil {
			return nil, err
		}
		values = append(values, parsed...)
	}
	return sortedInterfaces(values)
}

func parseDefaultRouteInterfaces(raw []byte) ([]string, error) {
	if len(raw) == 0 || len(raw) > 1<<20 || !json.Valid(raw) {
		return nil, errors.New("ip route returned invalid JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var routes []map[string]any
	if err := decoder.Decode(&routes); err != nil {
		return nil, errors.New("ip route JSON shape is invalid")
	}
	var result []string
	for _, route := range routes {
		if destination := strings.TrimSpace(fmt.Sprint(route["dst"])); destination != "" && destination != "default" {
			continue
		}
		if dev := strings.TrimSpace(fmt.Sprint(route["dev"])); dev != "" && dev != "<nil>" {
			result = append(result, dev)
		}
		if next, ok := route["nexthops"].([]any); ok {
			for _, rawHop := range next {
				hop, ok := rawHop.(map[string]any)
				if !ok {
					return nil, errors.New("ip route nexthop shape is invalid")
				}
				if dev := strings.TrimSpace(fmt.Sprint(hop["dev"])); dev != "" && dev != "<nil>" {
					result = append(result, dev)
				}
			}
		}
	}
	return result, nil
}

func (b *commandBackend) ClusterOptions(ctx context.Context) (firewallOptions, error) {
	return b.options(ctx, "/cluster/firewall/options")
}

func (b *commandBackend) NodeOptions(ctx context.Context, node string) (firewallOptions, error) {
	if !validNodeName(node) {
		return firewallOptions{}, errors.New("invalid PVE node")
	}
	return b.options(ctx, "/nodes/"+node+"/firewall/options")
}

func (b *commandBackend) options(ctx context.Context, path string) (firewallOptions, error) {
	raw, err := b.pveshGet(ctx, path)
	if err != nil {
		return firewallOptions{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	values := map[string]any{}
	if err := decoder.Decode(&values); err != nil {
		return firewallOptions{}, errors.New("PVE firewall options shape is invalid")
	}
	digest := strings.TrimSpace(fmt.Sprint(values["digest"]))
	if !validDigest(digest) {
		return firewallOptions{}, errors.New("PVE firewall digest is missing or invalid")
	}
	delete(values, "digest")
	return firewallOptions{Values: values, Digest: digest}, nil
}

func (b *commandBackend) SetClusterOptions(ctx context.Context, values map[string]string, deleted []string, digest string) error {
	return b.setOptions(ctx, "/cluster/firewall/options", values, deleted, digest)
}

func (b *commandBackend) SetNodeOptions(ctx context.Context, node string, values map[string]string, deleted []string, digest string) error {
	if !validNodeName(node) {
		return errors.New("invalid PVE node")
	}
	return b.setOptions(ctx, "/nodes/"+node+"/firewall/options", values, deleted, digest)
}

func (b *commandBackend) setOptions(ctx context.Context, path string, values map[string]string, deleted []string, digest string) error {
	if !validDigest(digest) {
		return errors.New("invalid PVE firewall digest")
	}
	args := []string{"set", path, "--digest", digest}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value, err := canonicalOptionValue(key, values[key])
		if err != nil {
			return err
		}
		args = append(args, "--"+key, value)
	}
	if len(deleted) > 0 {
		copyDeleted := append([]string(nil), deleted...)
		sort.Strings(copyDeleted)
		for _, key := range copyDeleted {
			if key != "enable" && key != "policy_in" && key != "policy_out" {
				return errors.New("unsupported firewall option deletion")
			}
		}
		args = append(args, "--delete", strings.Join(copyDeleted, ","))
	}
	_, err := b.runner.Run(ctx, "pvesh", args...)
	return err
}

func (b *commandBackend) NodeRules(ctx context.Context, node string) (firewallRuleSet, error) {
	if !validNodeName(node) {
		return firewallRuleSet{}, errors.New("invalid PVE node")
	}
	raw, err := b.pveshGet(ctx, "/nodes/"+node+"/firewall/rules")
	if err != nil {
		return firewallRuleSet{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var rows []map[string]any
	if err := decoder.Decode(&rows); err != nil {
		return firewallRuleSet{}, errors.New("PVE node firewall rules shape is invalid")
	}
	result := make([]firewallRule, 0, len(rows))
	// PVE attaches the list digest to every returned rule. For an empty list
	// there is no row to carry it, and the canonical digest is SHA1(empty).
	digest := "da39a3ee5e6b4b0d3255bfef95601890afd80709"
	for _, row := range rows {
		rowDigest := strings.TrimSpace(fmt.Sprint(row["digest"]))
		if !validDigest(rowDigest) || (len(result) > 0 && rowDigest != digest) {
			return firewallRuleSet{}, errors.New("PVE node firewall rule digest is missing or inconsistent")
		}
		if len(result) == 0 {
			digest = rowDigest
		}
		position, err := integerValue(row["pos"])
		if err != nil || position < 0 {
			return firewallRuleSet{}, errors.New("PVE node firewall rule position is invalid")
		}
		direction := strings.ToLower(strings.TrimSpace(fmt.Sprint(row["type"])))
		action := strings.ToUpper(strings.TrimSpace(fmt.Sprint(row["action"])))
		iface := strings.TrimSpace(fmt.Sprint(row["iface"]))
		comment := strings.TrimSpace(fmt.Sprint(row["comment"]))
		if iface == "<nil>" {
			iface = ""
		}
		if comment == "<nil>" {
			comment = ""
		}
		result = append(result, firewallRule{
			Position: position, Direction: direction, Action: action,
			Interface: iface, Enabled: canonicalBool(row["enable"]), Comment: comment,
		})
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Position < result[right].Position })
	return firewallRuleSet{Items: result, Digest: digest}, nil
}

func (b *commandBackend) CreateNodeRule(ctx context.Context, node, iface, comment string, enabled bool, position int, digest string) error {
	if !validNodeName(node) || !validInterfaceName(iface) || position < 0 || !validDigest(digest) || !validOwnedComment(comment) {
		return errors.New("invalid owned node firewall rule")
	}
	_, err := b.runner.Run(ctx, "pvesh", "create", "/nodes/"+node+"/firewall/rules",
		"--type", "in", "--action", "DROP", "--iface", iface, "--enable", boolDigit(enabled),
		"--pos", strconv.Itoa(position), "--comment", comment, "--digest", digest)
	return err
}

func (b *commandBackend) SetNodeRuleEnabled(ctx context.Context, node string, position int, enabled bool, digest string) error {
	if !validNodeName(node) || position < 0 || !validDigest(digest) {
		return errors.New("invalid node firewall rule update")
	}
	_, err := b.runner.Run(ctx, "pvesh", "set", "/nodes/"+node+"/firewall/rules/"+strconv.Itoa(position),
		"--enable", boolDigit(enabled), "--digest", digest)
	return err
}

func (b *commandBackend) DeleteNodeRule(ctx context.Context, node string, position int, digest string) error {
	if !validNodeName(node) || position < 0 || !validDigest(digest) {
		return errors.New("invalid node firewall rule deletion")
	}
	_, err := b.runner.Run(ctx, "pvesh", "delete", "/nodes/"+node+"/firewall/rules/"+strconv.Itoa(position), "--digest", digest)
	return err
}

func (b *commandBackend) Health(ctx context.Context) error {
	for _, unit := range []string{
		"ppflight-agent.service",
		"ppflight-agent-upgrade.path",
		"ppflight-node-exporter.service",
		"ppflight-smartctl-exporter.service",
	} {
		if _, err := b.runner.Run(ctx, "systemctl", "is-active", "--quiet", unit); err != nil {
			return fmt.Errorf("required local service is not active: %s", unit)
		}
	}
	firewallActive := false
	for _, unit := range []string{"pve-firewall.service", "proxmox-firewall.service"} {
		if _, err := b.runner.Run(ctx, "systemctl", "is-active", "--quiet", unit); err == nil {
			firewallActive = true
			break
		}
	}
	if !firewallActive {
		return errors.New("PVE host firewall service is not active")
	}
	listeners, err := b.runner.Run(ctx, "ss", "-H", "-lnt")
	if err != nil {
		return errors.New("cannot verify Agent loopback listeners")
	}
	if err := validateLoopbackListeners(listeners); err != nil {
		return err
	}
	checks := []struct {
		url      string
		contains string
		status   bool
	}{
		{"http://127.0.0.1:9745/status", `"ready":true`, true},
		{"http://127.0.0.1:9100/metrics", "node_network_receive_bytes_total", false},
		{"http://127.0.0.1:9633/metrics", "smartctl_device_", false},
	}
	for _, check := range checks {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, check.url, nil)
		if err != nil {
			return err
		}
		response, err := b.client.Do(request)
		if err != nil {
			return errors.New("required loopback health endpoint is unavailable")
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 2<<20))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(check.contains)) {
			return errors.New("required loopback health endpoint is invalid")
		}
		if check.status && !json.Valid(body) {
			return errors.New("Agent loopback status is invalid")
		}
	}
	return nil
}

func validateLoopbackListeners(raw []byte) error {
	if len(raw) == 0 || len(raw) > 2<<20 {
		return errors.New("local listener inventory is empty or too large")
	}
	wanted := map[string]bool{"9745": false, "9100": false, "9633": false}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != "LISTEN" {
			continue
		}
		address := fields[3]
		for port := range wanted {
			if !strings.HasSuffix(address, ":"+port) {
				continue
			}
			if address != "127.0.0.1:"+port {
				return fmt.Errorf("required Agent port %s is not IPv4 loopback-only", port)
			}
			if wanted[port] {
				return fmt.Errorf("required Agent port %s has duplicate listeners", port)
			}
			wanted[port] = true
		}
	}
	for port, found := range wanted {
		if !found {
			return fmt.Errorf("required Agent loopback port %s is not listening", port)
		}
	}
	return nil
}

var digestPattern = regexp.MustCompile(`\A[0-9a-fA-F]{40,64}\z`)

func validDigest(value string) bool { return digestPattern.MatchString(value) }

func validOwnedComment(value string) bool {
	return strings.HasPrefix(value, "PPFlight host firewall:") && len(value) <= 255 && !strings.ContainsAny(value, "\r\n\x00")
}

func canonicalBool(value any) bool {
	switch strings.ToLower(strings.TrimSpace(fmt.Sprint(value))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func integerValue(value any) (int, error) {
	switch typed := value.(type) {
	case json.Number:
		parsed, err := strconv.ParseInt(string(typed), 10, 32)
		return int(parsed), err
	case float64:
		if typed != float64(int(typed)) {
			return 0, errors.New("not an integer")
		}
		return int(typed), nil
	case int:
		return typed, nil
	default:
		parsed, err := strconv.Atoi(strings.TrimSpace(fmt.Sprint(value)))
		return parsed, err
	}
}

func boolDigit(value bool) string {
	if value {
		return "1"
	}
	return "0"
}
