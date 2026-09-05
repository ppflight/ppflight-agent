package hostfirewall

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
)

const ufwUnit = "ufw.service"

type ufwPackageState struct {
	present   bool
	installed bool
	status    string
}

type savedNetfilterRule struct {
	line   string
	source string
	target string
}

type savedNetfilterTable struct {
	name   string
	chains map[string]bool
	policy map[string]string
	rules  []savedNetfilterRule
}

func (b *commandBackend) PreflightUFW(ctx context.Context) error {
	return b.preflightUFW(ctx, false)
}

func (b *commandBackend) preflightUFW(ctx context.Context, removalRecovery bool) error {
	slog.Info("host firewall UFW preflight started", "step", "ufw.preflight")
	state, err := b.ufwPackageState(ctx)
	if err != nil {
		return fmt.Errorf("UFW package inventory failed: %w", err)
	}
	unit, err := b.readSystemdUnitState(ctx, ufwUnit)
	if err != nil {
		return err
	}
	if !state.present {
		if unit.LoadState != "not-found" {
			if !removalRecovery {
				return errors.New("an unowned ufw.service exists while the ufw package is absent")
			}
			if err := b.verifyRecoverableStaleUFWUnit(ctx, unit); err != nil {
				return err
			}
		}
		slog.Info("host firewall UFW preflight complete; package is absent", "step", "ufw.preflight.complete")
		return nil
	}
	if !state.installed && unit.LoadState != "not-found" {
		if !removalRecovery {
			return errors.New("ufw.service remains loaded for a non-installed ufw package; refusing to execute an unowned stop action")
		}
		if err := b.verifyRecoverableStaleUFWUnit(ctx, unit); err != nil {
			return err
		}
	}
	if state.installed {
		libraryPrefix, err := b.verifyUFWPackageFiles(ctx)
		if err != nil {
			return err
		}
		preflight := b.ufwPreflight
		if preflight == nil {
			preflight = inspectUFWDisablePreconditions
		}
		if err := preflight(libraryPrefix); err != nil {
			return err
		}
		if unit.LoadState == "loaded" {
			if err := b.verifyUFWUnitDefinition(ctx, libraryPrefix); err != nil {
				return err
			}
		}
	}
	slog.Info("host firewall UFW preflight complete", "step", "ufw.preflight.complete", "packageStatus", state.status)
	return nil
}

// RemoveUFW removes only the package-owned UFW manager and the ufw-/ufw6-
// netfilter namespace. The caller must first establish and verify PVE host
// protection. We deliberately do not invoke `ufw disable`: its force-stop path
// can run custom hooks and, with MANAGE_BUILTINS=yes, flush every PVEFW chain.
func (b *commandBackend) RemoveUFW(ctx context.Context) (bool, error) {
	unlock, err := b.lockProcess(ctx)
	if err != nil {
		return false, err
	}
	defer unlock()

	slog.Info("host firewall UFW removal started", "step", "ufw.remove")
	// A committed removal may have crashed after dpkg deleted the unit file but
	// before our explicit daemon-reload. Permit only that inert, exact packaged
	// unit cache here; the public pre-install preflight remains strictly
	// read-only and rejects any unit without live package ownership.
	if err := b.preflightUFW(ctx, true); err != nil {
		return false, err
	}
	packageState, err := b.ufwPackageState(ctx)
	if err != nil {
		return false, err
	}
	unitState, err := b.readSystemdUnitState(ctx, ufwUnit)
	if err != nil {
		return false, err
	}

	// Prove the PVE replacement before changing UFW's boot state or live rules.
	for _, family := range iptablesFamilies {
		raw, err := b.runner.Run(ctx, family.save)
		if err != nil {
			return false, fmt.Errorf("cannot capture %s legacy netfilter state before UFW removal: %w", family.name, err)
		}
		if err := validatePVEProtectionBeforeUFWRemoval(family.name, raw); err != nil {
			return false, err
		}
	}
	recoveredCachedUnit := false
	if !packageState.present && unitState.LoadState == "loaded" {
		slog.Info("discarding inert cached ufw.service after interrupted package purge", "step", "ufw.unit.recover")
		if _, err := b.runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return false, fmt.Errorf("systemd daemon-reload during UFW purge recovery failed: %w", err)
		}
		unitState, err = b.readSystemdUnitState(ctx, ufwUnit)
		if err != nil {
			return false, err
		}
		if unitState.LoadState != "not-found" || unitState.ActiveState != "inactive" || unitState.MainPID != 0 {
			return false, fmt.Errorf("cached ufw.service remains after purge recovery: %+v", unitState)
		}
		recoveredCachedUnit = true
	}

	changed := packageState.present || unitState.LoadState != "not-found" || recoveredCachedUnit
	// Atomically remove only UFW-namespaced rules, promote PVE forwarding and
	// set PVE-compatible base policies while PVE's replacement protection is
	// already live. This occurs before making the package boot configuration
	// inert, so every later ordinary stop/prerm is a no-op.
	cleanupChanged, err := b.cleanupUFWNetfilter(ctx)
	if err != nil {
		return false, err
	}
	changed = changed || cleanupChanged

	if packageState.installed {
		slog.Info("disabling UFW boot configuration without executing UFW stop hooks", "step", "ufw.config.disable")
		disable := b.disableUFWConfig
		if disable == nil {
			disable = disableUFWAtBoot
		}
		if err := disable(); err != nil {
			return false, err
		}
	}

	if packageState.installed && unitState.LoadState == "loaded" {
		slog.Info("stopping and disabling ufw.service after its configuration was made inert", "step", "ufw.unit.disable")
		if _, err := b.runner.Run(ctx, "systemctl", "disable", "--now", ufwUnit); err != nil {
			return false, fmt.Errorf("cannot stop and disable %s: %w", ufwUnit, err)
		}
		unitState, err = b.readSystemdUnitState(ctx, ufwUnit)
		if err != nil {
			return false, err
		}
		if unitState.ActiveState != "inactive" || unitState.MainPID != 0 || unitFileEnabled(unitState.UnitFileState) {
			return false, fmt.Errorf("ufw.service did not become stopped and disabled: %+v", unitState)
		}
	}

	if packageState.present {
		slog.Info("validating exact single-package UFW purge", "step", "ufw.package.no-act")
		if _, err := b.runner.Run(ctx, "/usr/bin/dpkg", "--no-act", "--purge", "ufw"); err != nil {
			return false, fmt.Errorf("UFW single-package purge validation failed: %w", err)
		}
		slog.Info("purging exact UFW package without apt dependency solving", "step", "ufw.package.purge")
		if _, err := b.runner.Run(ctx, "/usr/bin/dpkg", "--purge", "ufw"); err != nil {
			return false, fmt.Errorf("UFW single-package purge failed: %w", err)
		}
		if _, err := b.runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return false, fmt.Errorf("systemd daemon-reload after UFW purge failed: %w", err)
		}
	}

	// Maintainer scripts vary between Debian releases. Re-run the scoped cleanup
	// and then prove the final package, unit, PVE and netfilter state.
	postPurgeChanged, err := b.cleanupUFWNetfilter(ctx)
	if err != nil {
		return false, err
	}
	changed = changed || postPurgeChanged
	if err := b.VerifyUFWAbsent(ctx); err != nil {
		return false, err
	}
	slog.Info("host firewall UFW removal strictly verified", "step", "ufw.remove.complete", "changed", changed)
	return changed, nil
}

func (b *commandBackend) verifyRecoverableStaleUFWUnit(ctx context.Context, unit systemdUnitState) error {
	if unit.LoadState != "loaded" || unit.ActiveState != "inactive" || unit.MainPID != 0 || unitFileEnabled(unit.UnitFileState) {
		return errors.New("stale ufw.service is not inert and disabled; refusing removal recovery")
	}
	var failures []error
	for _, libraryPrefix := range []string{"/usr/lib", "/lib"} {
		if err := b.verifyUFWUnitDefinition(ctx, libraryPrefix); err == nil {
			return nil
		} else {
			failures = append(failures, err)
		}
	}
	return fmt.Errorf("stale ufw.service is not an exact Debian packaged definition: %w", errors.Join(failures...))
}

func (b *commandBackend) VerifyUFWAbsent(ctx context.Context) error {
	state, err := b.ufwPackageState(ctx)
	if err != nil {
		return err
	}
	if state.status != "" {
		return fmt.Errorf("ufw package state remains after purge: %s", state.status)
	}
	unit, err := b.readSystemdUnitState(ctx, ufwUnit)
	if err != nil {
		return err
	}
	if unit.LoadState != "not-found" || unit.UnitFileState != "" || unit.ActiveState != "inactive" || unit.MainPID != 0 {
		return fmt.Errorf("ufw.service remains after purge: %+v", unit)
	}
	for _, family := range iptablesFamilies {
		raw, err := b.runner.Run(ctx, family.save)
		if err != nil {
			return fmt.Errorf("cannot verify %s legacy netfilter state after UFW purge: %w", family.name, err)
		}
		if err := verifyUFWFreePVEState(family.name, raw); err != nil {
			return err
		}
	}
	return nil
}

func (b *commandBackend) ufwPackageState(ctx context.Context) (ufwPackageState, error) {
	raw, err := b.runner.Run(ctx, "/usr/bin/dpkg-query", "--show", "--showformat=${binary:Package}\\t${db:Status-Abbrev}\\n")
	if err != nil {
		return ufwPackageState{}, err
	}
	if len(raw) > 2<<20 {
		return ufwPackageState{}, errors.New("dpkg package inventory exceeds safety limit")
	}
	var result ufwPackageState
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" {
			continue
		}
		name, status, ok := strings.Cut(line, "\t")
		if !ok || name != "ufw" {
			continue
		}
		if result.status != "" || len(status) != 3 {
			return ufwPackageState{}, errors.New("ufw package inventory is ambiguous")
		}
		result.status = status
		result.present = status[1] != 'n'
		result.installed = status[1] == 'i'
	}
	return result, nil
}

func (b *commandBackend) verifyUFWPackageFiles(ctx context.Context) (string, error) {
	raw, err := b.runner.Run(ctx, "/usr/bin/dpkg-query", "--listfiles", "ufw")
	if err != nil {
		return "", fmt.Errorf("cannot inspect files owned by the installed ufw package: %w", err)
	}
	found := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		found[line] = true
	}
	for _, required := range []string{"/usr/sbin/ufw", "/etc/default/ufw"} {
		if !found[required] {
			return "", fmt.Errorf("installed ufw package does not own required file %s", required)
		}
	}
	prefixSets := [][]string{
		{"/usr/lib/ufw/ufw-init", "/usr/lib/ufw/ufw-init-functions", "/usr/lib/systemd/system/ufw.service"},
		{"/lib/ufw/ufw-init", "/lib/ufw/ufw-init-functions", "/lib/systemd/system/ufw.service"},
	}
	completeSets := 0
	libraryPrefix := ""
	for _, set := range prefixSets {
		complete := true
		for _, path := range set {
			complete = complete && found[path]
		}
		if complete {
			completeSets++
			libraryPrefix = strings.TrimSuffix(strings.TrimSuffix(set[0], "/ufw/ufw-init"), "/")
		}
	}
	if completeSets != 1 {
		return "", errors.New("installed ufw package does not own one consistent Debian /lib or /usr/lib runtime set")
	}
	return libraryPrefix, nil
}

func (b *commandBackend) verifyUFWUnitDefinition(ctx context.Context, libraryPrefix string) error {
	raw, err := b.runner.Run(ctx, "systemctl", "show",
		"--property=FragmentPath", "--property=DropInPaths", "--property=ExecStop", "--property=ExecStopPost", ufwUnit)
	if err != nil || len(raw) == 0 || len(raw) > 32<<10 {
		return errors.New("cannot inspect ufw.service stop definition")
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return errors.New("ufw.service stop definition is invalid")
		}
		switch key {
		case "FragmentPath", "DropInPaths", "ExecStop", "ExecStopPost":
			if _, duplicate := values[key]; duplicate {
				return errors.New("ufw.service stop definition is ambiguous")
			}
			values[key] = value
		default:
			return errors.New("ufw.service stop definition contains an unexpected property")
		}
	}
	if len(values) < 3 || len(values) > 4 || values["DropInPaths"] != "" || values["ExecStopPost"] != "" {
		return errors.New("ufw.service has a drop-in or additional stop command")
	}
	for _, required := range []string{"FragmentPath", "DropInPaths", "ExecStop"} {
		if _, ok := values[required]; !ok {
			return errors.New("ufw.service stop definition is incomplete")
		}
	}
	fragment := values["FragmentPath"]
	if fragment != libraryPrefix+"/systemd/system/ufw.service" {
		return errors.New("ufw.service is not loaded from the packaged unit path")
	}
	initPath := libraryPrefix + "/ufw/ufw-init"
	normalized := strings.Join(strings.Fields(values["ExecStop"]), " ")
	prefix := "{ path=" + initPath + " ; argv[]=" + initPath + " stop ; ignore_errors=no ;"
	validStop := strings.HasPrefix(normalized, prefix) && strings.Count(normalized, "{ path=") == 1 && strings.HasSuffix(normalized, " }")
	if !validStop {
		return errors.New("ufw.service ExecStop is not the exact packaged ordinary stop command")
	}
	return nil
}

func unitFileEnabled(value string) bool {
	switch value {
	case "enabled", "enabled-runtime", "alias", "indirect", "linked", "linked-runtime":
		return true
	default:
		return false
	}
}

func (b *commandBackend) cleanupUFWNetfilter(ctx context.Context) (bool, error) {
	changed := false
	for _, family := range iptablesFamilies {
		raw, err := b.runner.Run(ctx, family.save)
		if err != nil {
			return changed, fmt.Errorf("cannot inspect %s UFW netfilter residue: %w", family.name, err)
		}
		payloads, needsChange, err := buildUFWCleanupPayloads(family.name, raw)
		if err != nil {
			return changed, err
		}
		for _, payload := range payloads {
			slog.Info("removing scoped UFW netfilter residue", "step", "ufw.netfilter.cleanup", "family", family.name)
			if _, err := b.runner.RunInput(ctx, payload, family.restore, "-w", "10", "-n"); err != nil {
				return changed, fmt.Errorf("cannot atomically remove %s UFW netfilter residue: %w", family.name, err)
			}
		}
		changed = changed || needsChange
		after, err := b.runner.Run(ctx, family.save)
		if err != nil {
			return changed, fmt.Errorf("cannot read back %s UFW cleanup: %w", family.name, err)
		}
		if err := verifyUFWFreePVEState(family.name, after); err != nil {
			return changed, err
		}
	}
	return changed, nil
}

func buildUFWCleanupPayloads(family string, raw []byte) ([][]byte, bool, error) {
	tables, err := parseNetfilterSave(raw)
	if err != nil {
		return nil, false, fmt.Errorf("%s legacy netfilter save is invalid: %w", family, err)
	}
	filter, ok := tables["filter"]
	if !ok {
		return nil, false, fmt.Errorf("%s legacy netfilter save lacks filter table", family)
	}
	forwardPosition, err := validatePVEProtectionTable(family, filter)
	if err != nil {
		return nil, false, err
	}
	ufwResidue := false
	for _, table := range tables {
		for chain := range table.chains {
			ufwResidue = ufwResidue || isUFWChain(chain)
		}
		for _, rule := range table.rules {
			ufwResidue = ufwResidue || isUFWChain(rule.source) || isUFWChain(rule.target)
		}
	}
	if !ufwResidue {
		if builtinPolicy(filter, "FORWARD") != "ACCEPT" {
			return nil, false, fmt.Errorf("%s base FORWARD policy is non-ACCEPT without UFW ownership evidence", family)
		}
	}

	names := make([]string, 0, len(tables))
	for name := range tables {
		names = append(names, name)
	}
	sort.Strings(names)
	var payloads [][]byte
	changed := forwardPosition != 0
	if ufwResidue {
		changed = changed || builtinPolicy(filter, "INPUT") != "ACCEPT" ||
			builtinPolicy(filter, "OUTPUT") != "ACCEPT" || builtinPolicy(filter, "FORWARD") != "ACCEPT"
	}
	for _, tableName := range names {
		table := tables[tableName]
		var commands []string
		for _, rule := range table.rules {
			if isUFWChain(rule.target) && !isUFWChain(rule.source) {
				commands = append(commands, "-D "+strings.TrimPrefix(rule.line, "-A "))
				changed = true
			}
		}
		var ufwChains []string
		for chain := range table.chains {
			if isUFWChain(chain) {
				ufwChains = append(ufwChains, chain)
			}
		}
		sort.Strings(ufwChains)
		for _, chain := range ufwChains {
			commands = append(commands, "-F "+chain)
		}
		for _, chain := range ufwChains {
			commands = append(commands, "-X "+chain)
		}
		if len(ufwChains) > 0 {
			changed = true
		}
		if tableName == "filter" {
			if forwardPosition != 0 {
				commands = append(commands, "-D FORWARD -j PVEFW-FORWARD", "-I FORWARD 1 -j PVEFW-FORWARD")
			}
			if ufwResidue {
				for _, chain := range []string{"INPUT", "OUTPUT", "FORWARD"} {
					if builtinPolicy(filter, chain) != "ACCEPT" {
						commands = append(commands, "-P "+chain+" ACCEPT")
					}
				}
			}
		}
		if len(commands) == 0 {
			continue
		}
		payloads = append(payloads, []byte("*"+tableName+"\n"+strings.Join(commands, "\n")+"\nCOMMIT\n"))
	}
	return payloads, changed, nil
}

func validatePVEProtectionBeforeUFWRemoval(family string, raw []byte) error {
	tables, err := parseNetfilterSave(raw)
	if err != nil {
		return fmt.Errorf("%s legacy netfilter save is invalid: %w", family, err)
	}
	filter, ok := tables["filter"]
	if !ok {
		return fmt.Errorf("%s legacy netfilter save lacks filter table", family)
	}
	_, err = validatePVEProtectionTable(family, filter)
	return err
}

func verifyUFWFreePVEState(family string, raw []byte) error {
	tables, err := parseNetfilterSave(raw)
	if err != nil {
		return fmt.Errorf("%s legacy netfilter save is invalid: %w", family, err)
	}
	for _, table := range tables {
		for chain := range table.chains {
			if isUFWChain(chain) {
				return fmt.Errorf("%s still contains UFW chain %s", family, chain)
			}
		}
		for _, rule := range table.rules {
			if isUFWChain(rule.source) || isUFWChain(rule.target) {
				return fmt.Errorf("%s still contains UFW rule %s", family, rule.line)
			}
		}
	}
	filter, ok := tables["filter"]
	if !ok {
		return fmt.Errorf("%s legacy netfilter save lacks filter table", family)
	}
	forwardPosition, err := validatePVEProtectionTable(family, filter)
	if err != nil {
		return err
	}
	if forwardPosition != 0 {
		return fmt.Errorf("%s PVEFW-FORWARD jump is not first", family)
	}
	if builtinPolicy(filter, "FORWARD") != "ACCEPT" {
		return fmt.Errorf("%s base FORWARD policy is not PVE-compatible ACCEPT", family)
	}
	return nil
}

func validatePVEProtectionTable(family string, filter savedNetfilterTable) (int, error) {
	for _, chain := range []string{"PVEFW-INPUT", "PVEFW-FORWARD"} {
		if !filter.chains[chain] {
			return -1, fmt.Errorf("%s PVE protection chain %s is unavailable", family, chain)
		}
	}
	inputPosition, inputCount, inputExact := -1, 0, 0
	forwardPosition, forwardCount, forwardExact := -1, 0, 0
	inputRulePosition, forwardRulePosition := 0, 0
	for _, rule := range filter.rules {
		switch rule.source {
		case "INPUT":
			if rule.target == "PVEFW-INPUT" {
				inputCount++
				if rule.line == "-A INPUT -j PVEFW-INPUT" {
					inputExact++
					inputPosition = inputRulePosition
				}
			}
			inputRulePosition++
		case "FORWARD":
			if rule.target == "PVEFW-FORWARD" {
				forwardCount++
				if rule.line == "-A FORWARD -j PVEFW-FORWARD" {
					forwardExact++
					forwardPosition = forwardRulePosition
				}
			}
			forwardRulePosition++
		}
	}
	if inputCount != 1 || inputExact != 1 || inputPosition != 0 {
		return -1, fmt.Errorf("%s INPUT must begin with exactly one unmodified PVEFW-INPUT jump", family)
	}
	if forwardCount != 1 || forwardExact != 1 {
		return -1, fmt.Errorf("%s FORWARD must contain exactly one unmodified PVEFW-FORWARD jump", family)
	}
	return forwardPosition, nil
}

func parseNetfilterSave(raw []byte) (map[string]savedNetfilterTable, error) {
	if len(raw) == 0 || len(raw) > 2<<20 {
		return nil, errors.New("netfilter save is empty or exceeds safety limit")
	}
	result := map[string]savedNetfilterTable{}
	var current *savedNetfilterTable
	for _, rawLine := range strings.Split(string(raw), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "*") {
			if current != nil {
				return nil, errors.New("nested netfilter table")
			}
			name := strings.TrimPrefix(line, "*")
			if !validSavedTableName(name) {
				return nil, errors.New("invalid netfilter table name")
			}
			if _, duplicate := result[name]; duplicate {
				return nil, errors.New("duplicate netfilter table")
			}
			current = &savedNetfilterTable{name: name, chains: map[string]bool{}, policy: map[string]string{}}
			continue
		}
		if line == "COMMIT" {
			if current == nil {
				return nil, errors.New("orphan netfilter COMMIT")
			}
			result[current.name] = *current
			current = nil
			continue
		}
		if current == nil {
			return nil, errors.New("netfilter content outside a table")
		}
		if strings.HasPrefix(line, ":") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return nil, errors.New("invalid netfilter chain declaration")
			}
			name := strings.TrimPrefix(fields[0], ":")
			if name == "" || current.chains[name] {
				return nil, errors.New("invalid or duplicate netfilter chain declaration")
			}
			current.chains[name] = true
			current.policy[name] = fields[1]
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "-A" {
			current.rules = append(current.rules, savedNetfilterRule{line: line, source: fields[1], target: firewallTarget(fields)})
		}
	}
	if current != nil || len(result) == 0 {
		return nil, errors.New("unterminated or empty netfilter save")
	}
	return result, nil
}

func validSavedTableName(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func isUFWChain(value string) bool {
	if !(strings.HasPrefix(value, "ufw-") || strings.HasPrefix(value, "ufw6-")) {
		return false
	}
	if len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && !strings.ContainsRune("_.:+-", character) {
			return false
		}
	}
	return true
}

func builtinPolicy(table savedNetfilterTable, chain string) string {
	return table.policy[chain]
}

func rewriteUFWEnabled(raw []byte) ([]byte, bool, error) {
	if len(raw) == 0 || len(raw) > 64<<10 {
		return nil, false, errors.New("UFW boot configuration is empty or exceeds safety limit")
	}
	lines := strings.Split(string(raw), "\n")
	found := map[string]int{}
	current := ""
	for index, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != key || (key != "ENABLED" && key != "LOGLEVEL") {
			return nil, false, errors.New("/etc/ufw/ufw.conf contains an unsafe active line")
		}
		if _, duplicate := found[key]; duplicate {
			return nil, false, fmt.Errorf("/etc/ufw/ufw.conf contains duplicate %s assignments", key)
		}
		found[key] = index
		value, err := safeUFWAssignmentValue(value, false)
		if err != nil {
			return nil, false, fmt.Errorf("/etc/ufw/ufw.conf %s value is unsafe", key)
		}
		switch key {
		case "ENABLED":
			current = strings.ToLower(value)
			if current != "yes" && current != "no" {
				return nil, false, errors.New("/etc/ufw/ufw.conf has an ambiguous ENABLED value")
			}
		case "LOGLEVEL":
			switch strings.ToLower(value) {
			case "off", "low", "medium", "high", "full":
			default:
				return nil, false, errors.New("/etc/ufw/ufw.conf has an ambiguous LOGLEVEL value")
			}
		}
	}
	enabledIndex, ok := found["ENABLED"]
	if !ok {
		return nil, false, errors.New("/etc/ufw/ufw.conf lacks ENABLED assignment")
	}
	if current == "no" {
		return append([]byte(nil), raw...), false, nil
	}
	indent := lines[enabledIndex][:len(lines[enabledIndex])-len(strings.TrimLeft(lines[enabledIndex], " \t"))]
	lines[enabledIndex] = indent + "ENABLED=no"
	return []byte(strings.Join(lines, "\n")), true, nil
}

func parseSafeUFWDefaults(raw []byte) (string, error) {
	if len(raw) == 0 || len(raw) > 64<<10 {
		return "", errors.New("UFW defaults are empty or exceed safety limit")
	}
	allowed := map[string]bool{
		"IPV6": true, "DEFAULT_INPUT_POLICY": true, "DEFAULT_OUTPUT_POLICY": true,
		"DEFAULT_FORWARD_POLICY": true, "DEFAULT_APPLICATION_POLICY": true,
		"MANAGE_BUILTINS": true, "IPT_SYSCTL": true, "IPT_MODULES": true,
	}
	seen := map[string]bool{}
	manageBuiltins := ""
	for _, rawLine := range strings.Split(string(raw), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, rawValue, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != key || !allowed[key] || seen[key] {
			return "", errors.New("/etc/default/ufw contains an unsafe or duplicate active line")
		}
		seen[key] = true
		value, err := safeUFWAssignmentValue(rawValue, key == "IPT_MODULES")
		if err != nil {
			return "", fmt.Errorf("/etc/default/ufw %s value is unsafe", key)
		}
		switch key {
		case "IPV6", "MANAGE_BUILTINS":
			value = strings.ToLower(value)
			if value != "yes" && value != "no" {
				return "", fmt.Errorf("/etc/default/ufw %s value is ambiguous", key)
			}
			if key == "MANAGE_BUILTINS" {
				manageBuiltins = value
			}
		case "DEFAULT_INPUT_POLICY", "DEFAULT_OUTPUT_POLICY", "DEFAULT_FORWARD_POLICY":
			switch strings.ToUpper(value) {
			case "ACCEPT", "DROP", "REJECT":
			default:
				return "", fmt.Errorf("/etc/default/ufw %s value is ambiguous", key)
			}
		case "DEFAULT_APPLICATION_POLICY":
			switch strings.ToUpper(value) {
			case "ACCEPT", "DROP", "REJECT", "SKIP":
			default:
				return "", errors.New("/etc/default/ufw DEFAULT_APPLICATION_POLICY value is ambiguous")
			}
		case "IPT_SYSCTL":
			if !strings.HasPrefix(value, "/") {
				return "", errors.New("/etc/default/ufw IPT_SYSCTL must be an absolute safe path")
			}
		}
	}
	if manageBuiltins == "" {
		return "", errors.New("/etc/default/ufw lacks MANAGE_BUILTINS assignment")
	}
	return manageBuiltins, nil
}

func safeUFWAssignmentValue(raw string, allowSpaces bool) (string, error) {
	value := strings.TrimSpace(raw)
	if len(value) >= 2 && ((value[0] == '\'' && value[len(value)-1] == '\'') || (value[0] == '"' && value[len(value)-1] == '"')) {
		value = value[1 : len(value)-1]
	} else if strings.ContainsAny(value, "'\"") {
		return "", errors.New("unbalanced assignment quoting")
	}
	if len(value) > 4096 {
		return "", errors.New("assignment value exceeds safety limit")
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("_./+-", character) ||
			(allowSpaces && (character == ' ' || character == '\t')) {
			continue
		}
		return "", errors.New("assignment value contains shell syntax")
	}
	return value, nil
}
