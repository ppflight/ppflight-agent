package hostfirewall

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const ingressGuardUnit = "ppflight-host-firewall.service"

type iptablesFamily struct {
	name    string
	command string
	save    string
	restore string
}

var iptablesFamilies = []iptablesFamily{
	{name: "ipv4", command: "/usr/sbin/iptables-legacy", save: "/usr/sbin/iptables-legacy-save", restore: "/usr/sbin/iptables-legacy-restore"},
	{name: "ipv6", command: "/usr/sbin/ip6tables-legacy", save: "/usr/sbin/ip6tables-legacy-save", restore: "/usr/sbin/ip6tables-legacy-restore"},
}

type parsedInputChain struct {
	family         string
	rules          []string
	nativePosition int
	nativeCount    int
	pveJumpCount   int
}

type parsedForwardChain struct {
	family         string
	policy         string
	rules          []string
	nativePosition int
	nativeCount    int
	pveJumpCount   int
}

// CaptureIngressGuard is read-only. The caller must durably persist both
// family snapshots before any native-hook movement is permitted.
func (b *commandBackend) CaptureIngressGuard(ctx context.Context) ([]nativeInputHookSnapshot, error) {
	unlock, err := b.lockProcess(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	result := make([]nativeInputHookSnapshot, 0, len(iptablesFamilies))
	for _, family := range iptablesFamilies {
		parsed, err := b.readInputChain(ctx, family)
		if err != nil {
			return nil, err
		}
		available, err := validateNativeHookInventory(parsed)
		if err != nil {
			return nil, err
		}
		if !available {
			return nil, fmt.Errorf("%s PVE native INPUT hook is unavailable", family.name)
		}
		if parsed.nativePosition != len(parsed.rules)-1 {
			return nil, fmt.Errorf("%s PVE native INPUT hook is not in its canonical tail position", family.name)
		}
		result = append(result, nativeInputHookSnapshot{Family: family.name, Captured: true, WasTail: true})
	}
	if err := validateNativeHookSnapshots(result); err != nil {
		return nil, err
	}
	return result, nil
}

// CaptureRetainedIngressGuard recognizes only the exact first-position hook
// deliberately left by a prior PPFlight uninstall. It is not a tail-restore
// snapshot; UFWPhase prevents that irreversible migration from using rollback.
func (b *commandBackend) CaptureRetainedIngressGuard(ctx context.Context) ([]nativeInputHookSnapshot, error) {
	unlock, err := b.lockProcess(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	result := make([]nativeInputHookSnapshot, 0, len(iptablesFamilies))
	for _, family := range iptablesFamilies {
		parsed, err := b.readInputChain(ctx, family)
		if err != nil {
			return nil, err
		}
		available, err := validateNativeHookInventory(parsed)
		if err != nil {
			return nil, err
		}
		if !available || parsed.nativePosition != 0 {
			return nil, fmt.Errorf("%s retained PVE native INPUT hook is not first", family.name)
		}
		result = append(result, nativeInputHookSnapshot{Family: family.name, Captured: true, RetainedFirst: true})
	}
	return result, validateNativeHookSnapshots(result)
}

func (b *commandBackend) EnsureIngressGuard(ctx context.Context, journal Journal) error {
	unlock, err := b.lockProcess(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	_, err = b.maintainIngressGuard(ctx, journal, true)
	return err
}

// MaintainIngressGuard never creates PVEFW-INPUT or a new reference. During
// Cluster disable/reload, zero native hooks is an expected transient. When
// PVE appends its sole exact hook again, one atomic restore batch moves it.
func (b *commandBackend) MaintainIngressGuard(ctx context.Context, journal Journal) (bool, error) {
	unlock, err := b.lockProcess(ctx)
	if err != nil {
		return false, err
	}
	defer unlock()
	return b.maintainIngressGuard(ctx, journal, false)
}

func (b *commandBackend) maintainIngressGuard(ctx context.Context, journal Journal, requireAvailable bool) (bool, error) {
	if err := requireNativeHookSnapshots(journal); err != nil {
		return false, err
	}
	changed := false
	for _, family := range iptablesFamilies {
		parsed, err := b.readInputChain(ctx, family)
		if err != nil {
			return changed, err
		}
		available, err := validateNativeHookInventory(parsed)
		if err != nil {
			return changed, err
		}
		if !available {
			if requireAvailable {
				return changed, fmt.Errorf("%s PVE native INPUT hook is unavailable", family.name)
			}
			continue
		}
		if parsed.nativePosition == 0 {
			continue
		}
		if err := b.moveNativeHookAtomic(ctx, family, true); err != nil {
			return changed, err
		}
		changed = true
		if err := b.verifyNativeHookPosition(ctx, family, 0, requireAvailable); err != nil {
			return changed, err
		}
	}
	if journal.UFWPhase == UFWPhaseRemoving || journal.UFWPhase == UFWPhaseRemoved {
		for _, family := range iptablesFamilies {
			familyChanged, err := b.maintainForwardGuard(ctx, family, requireAvailable)
			if err != nil {
				return changed, err
			}
			changed = changed || familyChanged
		}
	}
	return changed, nil
}

func (b *commandBackend) VerifyIngressGuard(ctx context.Context, journal Journal) error {
	unlock, err := b.lockProcess(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	if err := requireNativeHookSnapshots(journal); err != nil {
		return err
	}
	for _, family := range iptablesFamilies {
		if err := b.verifyNativeHookPosition(ctx, family, 0, true); err != nil {
			return err
		}
		if journal.UFWPhase == UFWPhaseRemoving || journal.UFWPhase == UFWPhaseRemoved {
			if err := b.verifyForwardGuard(ctx, family, true); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *commandBackend) maintainForwardGuard(ctx context.Context, family iptablesFamily, requireAvailable bool) (bool, error) {
	parsed, err := b.readForwardChain(ctx, family)
	if err != nil {
		return false, err
	}
	available, err := validateForwardHookInventory(parsed)
	if err != nil {
		return false, err
	}
	if !available {
		if requireAvailable {
			return false, fmt.Errorf("%s PVE native FORWARD hook is unavailable", family.name)
		}
		return false, nil
	}
	if parsed.nativePosition == 0 && parsed.policy == "ACCEPT" {
		return false, nil
	}
	var commands []string
	if parsed.nativePosition != 0 {
		commands = append(commands, "-D FORWARD -j PVEFW-FORWARD", "-I FORWARD 1 -j PVEFW-FORWARD")
	}
	if parsed.policy != "ACCEPT" {
		commands = append(commands, "-P FORWARD ACCEPT")
	}
	payload := []byte("*filter\n" + strings.Join(commands, "\n") + "\nCOMMIT\n")
	if _, err := b.runner.RunInput(ctx, payload, family.restore, "-w", "10", "-n"); err != nil {
		return false, fmt.Errorf("cannot atomically restore %s PVE native FORWARD guard: %w", family.name, err)
	}
	if err := b.verifyForwardGuard(ctx, family, requireAvailable); err != nil {
		return true, err
	}
	return true, nil
}

func (b *commandBackend) verifyForwardGuard(ctx context.Context, family iptablesFamily, requireAvailable bool) error {
	parsed, err := b.readForwardChain(ctx, family)
	if err != nil {
		return err
	}
	available, err := validateForwardHookInventory(parsed)
	if err != nil {
		return err
	}
	if !available {
		if requireAvailable {
			return fmt.Errorf("%s PVE native FORWARD hook is unavailable", family.name)
		}
		return nil
	}
	if parsed.nativePosition != 0 || parsed.policy != "ACCEPT" {
		return fmt.Errorf("%s PVE native FORWARD guard is not first with ACCEPT base policy", family.name)
	}
	return nil
}

func (b *commandBackend) readForwardChain(ctx context.Context, family iptablesFamily) (parsedForwardChain, error) {
	raw, err := b.runner.Run(ctx, family.command, "-w", "10", "-S", "FORWARD")
	if err != nil {
		return parsedForwardChain{}, fmt.Errorf("cannot inspect %s base FORWARD chain", family.name)
	}
	return parseForwardChain(family.name, raw)
}

func parseForwardChain(family string, raw []byte) (parsedForwardChain, error) {
	if (family != "ipv4" && family != "ipv6") || len(raw) == 0 || len(raw) > 2<<20 {
		return parsedForwardChain{}, errors.New("base FORWARD chain inventory is invalid")
	}
	result := parsedForwardChain{family: family, nativePosition: -1}
	for _, rawLine := range strings.Split(string(raw), "\n") {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "-P FORWARD ") {
			fields := strings.Fields(line)
			if len(fields) != 3 || result.policy != "" {
				return parsedForwardChain{}, errors.New("base FORWARD policy inventory is ambiguous")
			}
			result.policy = fields[2]
			continue
		}
		if !strings.HasPrefix(line, "-A FORWARD ") {
			continue
		}
		position := len(result.rules)
		result.rules = append(result.rules, line)
		fields := strings.Fields(line)
		target := firewallTarget(fields)
		if isUFWChain(target) {
			return parsedForwardChain{}, fmt.Errorf("%s FORWARD contains a reintroduced UFW jump", family)
		}
		if target != "PVEFW-FORWARD" {
			continue
		}
		result.pveJumpCount++
		if len(fields) == 4 && fields[0] == "-A" && fields[1] == "FORWARD" && fields[2] == "-j" && fields[3] == "PVEFW-FORWARD" {
			result.nativeCount++
			result.nativePosition = position
		}
	}
	if result.policy == "" {
		return parsedForwardChain{}, errors.New("base FORWARD policy is missing")
	}
	return result, nil
}

func validateForwardHookInventory(parsed parsedForwardChain) (bool, error) {
	if parsed.pveJumpCount == 0 {
		return false, nil
	}
	if parsed.pveJumpCount != 1 || parsed.nativeCount != 1 {
		return false, fmt.Errorf("%s FORWARD must contain exactly one unmodified PVE native jump", parsed.family)
	}
	return true, nil
}

// RemoveIngressGuard restores the sole PVE-native hook to PVE's canonical
// appended position. It never deletes that hook and never touches aaPanel/UFW
// rules. The historical internal method name is retained for a narrow API diff.
func (b *commandBackend) RemoveIngressGuard(ctx context.Context, journal Journal) error {
	if len(journal.NativeHooks) == 0 {
		// An old committed rc.26 journal that was never priority-migrated.
		return nil
	}
	if err := requireNativeHookSnapshots(journal); err != nil {
		return err
	}
	for _, snapshot := range journal.NativeHooks {
		if snapshot.RetainedFirst {
			return errors.New("retained first-position PVE hook has no safe tail rollback")
		}
	}
	unlock, err := b.lockProcess(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	var restore []iptablesFamily
	for _, family := range iptablesFamilies {
		parsed, err := b.readInputChain(ctx, family)
		if err != nil {
			return err
		}
		available, err := validateNativeHookInventory(parsed)
		if err != nil {
			return err
		}
		if !available {
			// PVE disabled its firewall and removed its own hook. PPFlight must
			// not recreate either the chain or the reference.
			continue
		}
		if parsed.nativePosition != 0 {
			// Rollback must begin from the fail-closed state maintained by the
			// supervisor. Repair a displaced unique hook, then require explicit
			// retry instead of completing from an ambiguous precondition.
			promoteErr := b.moveNativeHookAtomic(ctx, family, true)
			if promoteErr != nil {
				return errors.Join(fmt.Errorf("%s native hook was displaced before rollback", family.name), promoteErr)
			}
			return fmt.Errorf("%s native hook was displaced before rollback and was re-promoted; retry required", family.name)
		}
		if len(parsed.rules) == 1 {
			continue
		}
		restore = append(restore, family)
	}
	var restored []iptablesFamily
	for _, family := range restore {
		if err := b.moveNativeHookAtomic(ctx, family, false); err != nil {
			compensationErr := b.promoteNativeHooksBestEffort(ctx, append(restored, family))
			return errors.Join(err, compensationErr)
		}
		restored = append(restored, family)
	}
	for _, family := range restored {
		verified, err := b.readInputChain(ctx, family)
		if err != nil {
			return errors.Join(err, b.promoteNativeHooksBestEffort(ctx, restored))
		}
		available, inventoryErr := validateNativeHookInventory(verified)
		if inventoryErr == nil && !available {
			// Cluster disable removed PVE's own chain and hook after restoration.
			// It is safe and must not be recreated.
			continue
		}
		if inventoryErr == nil && available && verified.nativePosition == len(verified.rules)-1 {
			continue
		}
		// A concurrent local firewall rewrite raced the restoration. Compensate
		// every family back to fail-closed first position before returning.
		compensationErr := b.promoteNativeHooksBestEffort(ctx, restored)
		if inventoryErr != nil {
			return errors.Join(inventoryErr, compensationErr)
		}
		return errors.Join(fmt.Errorf("%s PVE native INPUT hook tail restoration was not stable", family.name), compensationErr)
	}
	return nil
}

func (b *commandBackend) promoteNativeHooksBestEffort(ctx context.Context, families []iptablesFamily) error {
	var failures []error
	seen := map[string]bool{}
	for _, family := range families {
		if seen[family.name] {
			continue
		}
		seen[family.name] = true
		parsed, err := b.readInputChain(ctx, family)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		available, err := validateNativeHookInventory(parsed)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if !available || parsed.nativePosition == 0 {
			continue
		}
		if err := b.moveNativeHookAtomic(ctx, family, true); err != nil {
			failures = append(failures, err)
			continue
		}
		if err := b.verifyNativeHookPosition(ctx, family, 0, false); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (b *commandBackend) moveNativeHookAtomic(ctx context.Context, family iptablesFamily, first bool) error {
	insert := "-A INPUT -j PVEFW-INPUT"
	if first {
		insert = "-I INPUT 1 -j PVEFW-INPUT"
	}
	payload := []byte("*filter\n-D INPUT -j PVEFW-INPUT\n" + insert + "\nCOMMIT\n")
	if _, err := b.runner.RunInput(ctx, payload, family.restore, "-w", "10", "-n"); err != nil {
		return fmt.Errorf("cannot atomically reorder %s PVE native INPUT hook: %w", family.name, err)
	}
	return nil
}

func (b *commandBackend) verifyNativeHookPosition(ctx context.Context, family iptablesFamily, wanted int, requireAvailable bool) error {
	parsed, err := b.readInputChain(ctx, family)
	if err != nil {
		return err
	}
	available, err := validateNativeHookInventory(parsed)
	if err != nil {
		return err
	}
	if !available {
		if requireAvailable {
			return fmt.Errorf("%s PVE native INPUT hook is unavailable", family.name)
		}
		return nil
	}
	if parsed.nativePosition != wanted {
		return fmt.Errorf("%s PVE native INPUT hook is at position %d, want %d", family.name, parsed.nativePosition, wanted)
	}
	return nil
}

func (b *commandBackend) readInputChain(ctx context.Context, family iptablesFamily) (parsedInputChain, error) {
	raw, err := b.runner.Run(ctx, family.command, "-w", "10", "-S", "INPUT")
	if err != nil {
		return parsedInputChain{}, fmt.Errorf("cannot inspect %s base INPUT chain", family.name)
	}
	return parseInputChain(family.name, raw)
}

func parseInputChain(family string, raw []byte) (parsedInputChain, error) {
	if (family != "ipv4" && family != "ipv6") || len(raw) == 0 || len(raw) > 2<<20 {
		return parsedInputChain{}, errors.New("base INPUT chain inventory is invalid")
	}
	result := parsedInputChain{family: family, nativePosition: -1}
	for _, rawLine := range strings.Split(string(raw), "\n") {
		line := strings.TrimSpace(rawLine)
		if !strings.HasPrefix(line, "-A INPUT ") {
			continue
		}
		position := len(result.rules)
		result.rules = append(result.rules, line)
		fields := strings.Fields(line)
		if firewallTarget(fields) != "PVEFW-INPUT" {
			continue
		}
		result.pveJumpCount++
		if exactNativeInputRule(fields) {
			result.nativeCount++
			result.nativePosition = position
		}
	}
	return result, nil
}

func exactNativeInputRule(fields []string) bool {
	return len(fields) == 4 && fields[0] == "-A" && fields[1] == "INPUT" && fields[2] == "-j" && fields[3] == "PVEFW-INPUT"
}

func validateNativeHookInventory(parsed parsedInputChain) (bool, error) {
	if parsed.pveJumpCount == 0 {
		return false, nil
	}
	if parsed.pveJumpCount != 1 || parsed.nativeCount != 1 {
		return false, fmt.Errorf("%s INPUT must contain exactly one unmodified PVE native jump", parsed.family)
	}
	return true, nil
}

func requireNativeHookSnapshots(journal Journal) error {
	if len(journal.NativeHooks) == 0 {
		return errors.New("PVE native INPUT hook restore snapshot is missing")
	}
	return validateNativeHookSnapshots(journal.NativeHooks)
}

func fieldAfter(fields []string, key string) string {
	for index := 0; index+1 < len(fields); index++ {
		if fields[index] == key {
			return fields[index+1]
		}
	}
	return ""
}

func firewallTarget(fields []string) string {
	for _, key := range []string{"-j", "--jump", "-g", "--goto"} {
		if value := fieldAfter(fields, key); value != "" {
			return value
		}
	}
	return ""
}

func (b *commandBackend) InputChainOrder(ctx context.Context) ([]inputChainOrder, error) {
	unlock, err := b.lockProcess(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	result := make([]inputChainOrder, 0, len(iptablesFamilies))
	for _, family := range iptablesFamilies {
		parsed, err := b.readInputChain(ctx, family)
		if err != nil {
			return nil, err
		}
		available, err := validateNativeHookInventory(parsed)
		if err != nil {
			return nil, err
		}
		order := inputChainOrder{Family: family.name, PVEJumpPosition: -1}
		if available {
			order.PVEJumpPosition = parsed.nativePosition
			order.PrecedingRules = append([]string(nil), parsed.rules[:parsed.nativePosition]...)
		}
		result = append(result, order)
	}
	return result, nil
}

func validateInputChainInspection(values []inputChainOrder) error {
	if len(values) != 2 {
		return errors.New("base INPUT chain inspection is incomplete")
	}
	families := make([]string, 0, len(values))
	for _, value := range values {
		if value.Family != "ipv4" && value.Family != "ipv6" {
			return errors.New("base INPUT chain inspection has invalid family")
		}
		if value.PVEJumpPosition != 0 || len(value.PrecedingRules) != 0 {
			return fmt.Errorf("%s base INPUT does not begin with PVE's native PVEFW-INPUT hook", value.Family)
		}
		families = append(families, value.Family)
	}
	sort.Strings(families)
	if strings.Join(families, ",") != "ipv4,ipv6" {
		return errors.New("base INPUT chain inspection is duplicated")
	}
	return nil
}
