package hostfirewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type systemdUnitState struct {
	LoadState     string
	UnitFileState string
	ActiveState   string
	MainPID       int
}

func (b *commandBackend) VerifyIngressBackend(ctx context.Context) error {
	for _, family := range iptablesFamilies {
		version, err := b.runner.Run(ctx, family.command, "--version")
		if err != nil || !strings.Contains(strings.ToLower(string(version)), "legacy") {
			return fmt.Errorf("%s legacy netfilter backend is unavailable", family.name)
		}
	}
	deadline := time.NewTimer(12 * time.Second)
	defer deadline.Stop()
	var lastErr error
	for {
		if lastErr = b.verifyLegacySelectorOnce(ctx); lastErr == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("legacy PVE firewall backend selection is not stable: %w", lastErr)
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (b *commandBackend) verifyLegacySelectorOnce(ctx context.Context) error {
	legacy, err := b.readSystemdUnitState(ctx, "pve-firewall.service")
	if err != nil {
		return err
	}
	if legacy.LoadState != "loaded" || legacy.ActiveState != "active" || legacy.MainPID <= 0 {
		return errors.New("legacy pve-firewall.service is not active")
	}
	nft, err := b.readSystemdUnitState(ctx, "proxmox-firewall.service")
	if err != nil {
		return err
	}
	switch nft.LoadState {
	case "not-found":
		if nft.UnitFileState != "" || nft.ActiveState != "inactive" || nft.MainPID != 0 {
			return errors.New("missing proxmox-firewall unit has inconsistent state")
		}
	case "loaded":
		if nft.ActiveState != "active" && nft.ActiveState != "inactive" {
			return errors.New("proxmox-firewall unit has ambiguous active state")
		}
		if nft.ActiveState == "active" && nft.MainPID <= 0 {
			return errors.New("active proxmox-firewall unit lacks a process")
		}
		if nft.ActiveState == "inactive" && nft.MainPID != 0 {
			return errors.New("inactive proxmox-firewall unit unexpectedly has a process")
		}
	default:
		return errors.New("proxmox-firewall nft backend state is ambiguous")
	}
	node, err := b.LocalNode(ctx)
	if err != nil {
		return fmt.Errorf("cannot inspect local PVE firewall backend selector: %w", err)
	}
	nodeOptions, err := b.NodeOptions(ctx, node)
	if err != nil {
		return fmt.Errorf("cannot inspect local PVE firewall options: %w", err)
	}
	if !legacyNodeSelector(nodeOptions.Values) {
		return errors.New("local PVE node selects the nftables firewall backend")
	}
	clusterOptions, err := b.ClusterOptions(ctx)
	if err != nil {
		return fmt.Errorf("cannot inspect PVE Cluster firewall options: %w", err)
	}
	probe := b.pathProbe
	if probe == nil {
		probe = inspectFirewallSelectorPath
	}
	forceLegacy, err := probe("/run/proxmox-nftables-firewall-force-disable")
	if err != nil {
		return err
	}
	rustBinary, err := probe("/usr/libexec/proxmox/proxmox-firewall")
	if err != nil {
		return err
	}
	// pve-firewall's own Helpers.pm defines force-disable presence as the
	// authoritative legacy selector. Older PVE installations without the Rust
	// binary predate that flag and are also unambiguously legacy.
	// During a fresh cluster-off activation pve-firewall may not create the
	// force-disable flag until its next daemon cycle. The Node selector plus an
	// active legacy daemon is the safe precondition; once Cluster enable=1, the
	// official flag (or absence of the Rust executable) becomes mandatory.
	if canonicalBool(clusterOptions.Values["enable"]) && !legacyRuntimeSelector(forceLegacy, rustBinary) {
		return errors.New("Rust firewall is installed without the legacy force-disable selector")
	}
	return nil
}

func legacyRuntimeSelector(forceLegacy, rustBinary bool) bool {
	return forceLegacy || !rustBinary
}

func legacyNodeSelector(values map[string]any) bool {
	value, present := values["nftables"]
	if !present {
		return true
	}
	switch typed := value.(type) {
	case bool:
		return !typed
	case json.Number:
		return string(typed) == "0"
	case float64:
		return typed == 0
	case int:
		return typed == 0
	case string:
		return strings.TrimSpace(typed) == "0"
	default:
		return false
	}
}

func (b *commandBackend) VerifyRuntimeIngressDrops(ctx context.Context, journal Journal) error {
	unlock, err := acquireFirewallProcessLock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	expected := map[string]bool{}
	for _, item := range journal.OwnedRules {
		expected[item.Interface] = true
	}
	if len(expected) == 0 {
		return errors.New("runtime ingress DROP verification has no expected interfaces")
	}
	for _, family := range iptablesFamilies {
		input, err := b.runner.Run(ctx, family.command, "-w", "10", "-S", "PVEFW-INPUT")
		if err != nil {
			return fmt.Errorf("cannot inspect %s PVEFW-INPUT", family.name)
		}
		if err := validatePVEInputHostJump(family.name, input); err != nil {
			return err
		}
		raw, err := b.runner.Run(ctx, family.command, "-w", "10", "-S", "PVEFW-HOST-IN")
		if err != nil {
			return fmt.Errorf("cannot inspect %s PVEFW-HOST-IN", family.name)
		}
		if err := validateRuntimeIngressDrops(family.name, raw, expected); err != nil {
			return err
		}
	}
	return nil
}

func validateRuntimeIngressDrops(family string, raw []byte, expected map[string]bool) error {
	if len(raw) == 0 || len(raw) > 2<<20 {
		return fmt.Errorf("%s PVEFW-HOST-IN inventory is invalid", family)
	}
	var rules []string
	for _, rawLine := range strings.Split(string(raw), "\n") {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "-A PVEFW-HOST-IN ") {
			rules = append(rules, line)
		}
	}
	cursor, err := validateRuntimePrelude(family, rules)
	if err != nil {
		return err
	}
	first := cursor
	if first+len(expected) > len(rules) {
		return fmt.Errorf("%s PVEFW-HOST-IN lacks the expected runtime DROP block", family)
	}
	seen := map[string]bool{}
	for _, rule := range rules[first : first+len(expected)] {
		iface, ok := exactRuntimeInterfaceDrop(rule)
		if !ok || !expected[iface] || seen[iface] {
			return fmt.Errorf("%s PVEFW-HOST-IN runtime DROP block is not exact", family)
		}
		seen[iface] = true
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("%s PVEFW-HOST-IN runtime DROP block is incomplete", family)
	}
	counts := map[string]int{}
	for _, rule := range rules {
		if iface, ok := exactRuntimeInterfaceDrop(rule); ok && expected[iface] {
			counts[iface]++
		}
	}
	for iface := range expected {
		if counts[iface] != 1 {
			return fmt.Errorf("%s PVEFW-HOST-IN contains %d runtime DROP rules for %s", family, counts[iface], iface)
		}
	}
	// PVE emits its fixed safety prelude before Node rules and management
	// accepts after Node/Cluster rules. This proves our contiguous first user
	// block is in force before the standard management port acceptance block.
	managementPosition := -1
	for index, rule := range rules {
		if strings.Contains(rule, "--dport 8006") && index < first+len(expected) {
			return fmt.Errorf("%s PVE management accept precedes owned runtime DROP rules", family)
		}
		if strings.Contains(rule, "--dport 8006") && managementPosition < 0 {
			managementPosition = index
		}
	}
	if managementPosition < first+len(expected) {
		return fmt.Errorf("%s PVE management accept readback is missing after owned runtime DROP rules", family)
	}
	return nil
}

func validatePVEInputHostJump(family string, raw []byte) error {
	if len(raw) == 0 || len(raw) > 2<<20 {
		return fmt.Errorf("%s PVEFW-INPUT inventory is invalid", family)
	}
	var rules []string
	for _, rawLine := range strings.Split(string(raw), "\n") {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "-A PVEFW-INPUT ") {
			rules = append(rules, line)
		}
	}
	if len(rules) == 0 || rules[0] != "-A PVEFW-INPUT -j PVEFW-HOST-IN" {
		return fmt.Errorf("%s PVEFW-INPUT does not begin with the exact PVEFW-HOST-IN jump", family)
	}
	count := 0
	for _, rule := range rules {
		if firewallTarget(strings.Fields(rule)) == "PVEFW-HOST-IN" {
			count++
		}
	}
	if count != 1 {
		return fmt.Errorf("%s PVEFW-INPUT must contain exactly one PVEFW-HOST-IN jump", family)
	}
	return nil
}

func validateRuntimePrelude(family string, rules []string) (int, error) {
	if family != "ipv4" && family != "ipv6" {
		return 0, errors.New("runtime PVE family is invalid")
	}
	cursor := 0
	require := func(want string) error {
		if cursor >= len(rules) || rules[cursor] != want {
			return fmt.Errorf("%s PVEFW-HOST-IN prelude rule %d is not exact", family, cursor+1)
		}
		cursor++
		return nil
	}
	for _, want := range []string{
		"-A PVEFW-HOST-IN -i lo -j ACCEPT",
		"-A PVEFW-HOST-IN -m conntrack --ctstate INVALID -j DROP",
		"-A PVEFW-HOST-IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
	} {
		if err := require(want); err != nil {
			return 0, err
		}
	}
	if family == "ipv6" && cursor < len(rules) && isNDPRule(rules[cursor], 0) {
		for index := 0; index < 4; index++ {
			if cursor >= len(rules) || !isNDPRule(rules[cursor], index) {
				return 0, errors.New("ipv6 PVEFW-HOST-IN NDP prelude must contain all four exact rules")
			}
			cursor++
		}
	}
	blacklist := "-A PVEFW-HOST-IN -m set --match-set PVEFW-0-blacklist-" + map[string]string{"ipv4": "v4", "ipv6": "v6"}[family] + " src -j PVEFW-blacklist"
	if cursor < len(rules) && rules[cursor] == blacklist {
		cursor++
	}
	if family == "ipv4" && cursor < len(rules) && rules[cursor] == "-A PVEFW-HOST-IN -m conntrack --ctstate INVALID,NEW -j PVEFW-smurfs" {
		cursor++
	}
	if cursor < len(rules) && rules[cursor] == "-A PVEFW-HOST-IN -p tcp -j PVEFW-tcpflags" {
		cursor++
	}
	if err := require("-A PVEFW-HOST-IN -p igmp -j RETURN"); err != nil {
		return 0, err
	}
	return cursor, nil
}

func isNDPRule(rule string, index int) bool {
	types := [][]string{
		{"133", "router-solicitation"},
		{"134", "router-advertisement"},
		{"135", "neighbor-solicitation"},
		{"136", "neighbor-advertisement"},
	}
	if index < 0 || index >= len(types) {
		return false
	}
	fields := strings.Fields(rule)
	if len(fields) != 10 || fields[0] != "-A" || fields[1] != "PVEFW-HOST-IN" || fields[2] != "-p" ||
		(fields[3] != "ipv6-icmp" && fields[3] != "icmpv6") || fields[4] != "-m" || fields[5] != "icmp6" ||
		fields[6] != "--icmpv6-type" || fields[8] != "-j" || fields[9] != "RETURN" {
		return false
	}
	return fields[7] == types[index][0] || fields[7] == types[index][1]
}

func exactRuntimeInterfaceDrop(rule string) (string, bool) {
	fields := strings.Fields(rule)
	if len(fields) != 6 || fields[0] != "-A" || fields[1] != "PVEFW-HOST-IN" || fields[2] != "-i" || fields[4] != "-j" || fields[5] != "DROP" {
		return "", false
	}
	if !validInterfaceName(fields[3]) {
		return "", false
	}
	return fields[3], true
}

func (b *commandBackend) EnableIngressGuardPersistence(ctx context.Context) error {
	if _, err := b.runner.Run(ctx, "systemctl", "enable", ingressGuardUnit); err != nil {
		return errors.New("cannot enable INPUT priority supervisor for boot")
	}
	// start is intentionally idempotent and never stops an existing supervisor
	// or moves the native hook away from its fail-closed first position.
	if _, err := b.runner.Run(ctx, "systemctl", "start", ingressGuardUnit); err != nil {
		return errors.New("cannot start INPUT priority supervisor")
	}
	return b.VerifyIngressGuardPersistence(ctx)
}

func (b *commandBackend) DisableIngressGuardPersistence(ctx context.Context) error {
	if _, err := b.runner.Run(ctx, "systemctl", "disable", "--now", ingressGuardUnit); err != nil {
		return errors.New("cannot disable or stop INPUT priority supervisor")
	}
	state, err := b.readSystemdUnitState(ctx, ingressGuardUnit)
	if err != nil {
		return err
	}
	if state.LoadState != "loaded" || state.UnitFileState != "disabled" || state.ActiveState != "inactive" || state.MainPID != 0 {
		return fmt.Errorf("INPUT priority supervisor stop readback is invalid: %+v", state)
	}
	return nil
}

func (b *commandBackend) VerifyIngressGuardPersistence(ctx context.Context) error {
	state, err := b.readSystemdUnitState(ctx, ingressGuardUnit)
	if err != nil {
		return err
	}
	if state.LoadState != "loaded" || state.UnitFileState != "enabled" || state.ActiveState != "active" || state.MainPID <= 0 {
		return fmt.Errorf("INPUT priority supervisor state is invalid: %+v", state)
	}
	return nil
}

func (b *commandBackend) readSystemdUnitState(ctx context.Context, unit string) (systemdUnitState, error) {
	if unit != ingressGuardUnit && unit != "pve-firewall.service" && unit != "proxmox-firewall.service" {
		return systemdUnitState{}, errors.New("unsupported systemd unit inspection")
	}
	raw, err := b.runner.Run(ctx, "systemctl", "show",
		"--property=LoadState", "--property=UnitFileState", "--property=ActiveState", "--property=MainPID", unit)
	if err != nil || len(raw) == 0 || len(raw) > 16<<10 {
		return systemdUnitState{}, fmt.Errorf("cannot inspect systemd unit %s", unit)
	}
	values := map[string]string{}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || seen[key] {
			return systemdUnitState{}, fmt.Errorf("invalid systemd state for %s", unit)
		}
		switch key {
		case "LoadState", "UnitFileState", "ActiveState", "MainPID":
			values[key] = value
			seen[key] = true
		default:
			return systemdUnitState{}, fmt.Errorf("unexpected systemd state for %s", unit)
		}
	}
	if len(seen) != 4 || values["LoadState"] == "" || values["ActiveState"] == "" || values["MainPID"] == "" {
		return systemdUnitState{}, fmt.Errorf("incomplete systemd state for %s", unit)
	}
	if values["LoadState"] == "loaded" && values["UnitFileState"] == "" {
		return systemdUnitState{}, fmt.Errorf("loaded systemd unit %s lacks UnitFileState", unit)
	}
	pid, err := strconv.Atoi(values["MainPID"])
	if err != nil || pid < 0 {
		return systemdUnitState{}, fmt.Errorf("invalid systemd MainPID for %s", unit)
	}
	return systemdUnitState{
		LoadState: values["LoadState"], UnitFileState: values["UnitFileState"],
		ActiveState: values["ActiveState"], MainPID: pid,
	}, nil
}
