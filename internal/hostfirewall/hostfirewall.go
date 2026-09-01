package hostfirewall

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

type InstallMode string

const (
	ModeFresh  InstallMode = "fresh"
	ModeResume InstallMode = "resume"
	ModeUpdate InstallMode = "update"
)

var productionEvidence = []string{
	"/usr/local/bin/ppflight-agent",
	"/usr/local/bin/ag-pve",
	"/usr/local/bin/ag",
	"/usr/local/bin/AG",
	"/etc/systemd/system/ppflight-agent.service",
	"/etc/systemd/system/ppflight-agent-upgrade.path",
	"/etc/ppflight-agent",
	"/var/lib/ppflight-agent",
}

type Service struct {
	store    store
	backend  backend
	evidence []string
}

// TransactionOverview is a non-secret, read-only view used by the local AG
// system overview. It reports ownership state, not a substitute for the
// activation helper's strict live PVE readback.
type TransactionOverview struct {
	Present    bool
	Phase      string
	Node       string
	Interfaces []string
}

func InspectTransaction() (TransactionOverview, error) {
	storage := productionStore()
	exists, err := storage.exists()
	if err != nil || !exists {
		return TransactionOverview{}, err
	}
	journal, err := storage.load()
	if err != nil {
		return TransactionOverview{}, err
	}
	return TransactionOverview{
		Present: true, Phase: journal.Phase, Node: journal.Node,
		Interfaces: append([]string(nil), journal.Interfaces...),
	}, nil
}

func productionService() *Service {
	return &Service{store: productionStore(), backend: productionBackend(), evidence: productionEvidence}
}

func (service *Service) Classify() (InstallMode, error) {
	exists, err := service.store.exists()
	if err != nil {
		return "", err
	}
	if exists {
		journal, err := service.store.load()
		if err != nil {
			return "", err
		}
		switch journal.Phase {
		case PhaseInstalling, PhasePrepared, PhaseRulesDisabled, PhaseOptionsApplied,
			PhaseRulesEnabled, PhaseRollbackPending, PhaseRolledBack:
			return ModeResume, nil
		case PhaseCommitted, PhaseUninstalled:
			return ModeUpdate, nil
		default:
			return "", errors.New("unsupported host firewall journal phase")
		}
	}
	installed := false
	for _, path := range service.evidence {
		present, err := validateInstallationEvidence(path)
		if err != nil {
			return "", err
		}
		installed = installed || present
	}
	if installed {
		return ModeUpdate, nil
	}
	if _, err := service.store.createInitial(); err != nil {
		return "", err
	}
	return ModeFresh, nil
}

func validateInstallationEvidence(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		base := filepath.Base(path)
		if base != "ag-pve" && base != "ag" && base != "AG" {
			return false, fmt.Errorf("unexpected symlink at installation evidence %s", path)
		}
		target, err := filepath.EvalSymlinks(path)
		if err != nil || filepath.Clean(target) != "/usr/local/bin/ppflight-agent" {
			return false, fmt.Errorf("unsafe Agent command symlink %s", path)
		}
		return true, nil
	}
	if strings.HasSuffix(path, ".service") || strings.HasSuffix(path, ".path") || filepath.Base(path) == "ppflight-agent" {
		if !info.Mode().IsRegular() {
			return false, fmt.Errorf("installation evidence is not a regular file: %s", path)
		}
	} else if !info.IsDir() {
		return false, fmt.Errorf("installation evidence is not a directory: %s", path)
	}
	return true, nil
}

func (service *Service) Activate(ctx context.Context) (returnErr error) {
	journal, err := service.store.load()
	if err != nil {
		return err
	}
	if journal.Phase == PhaseUninstalled {
		return errors.New("host firewall transaction belongs to an uninstalled Agent")
	}
	if journal.Phase == PhaseCommitted {
		if err := service.verify(ctx, journal, true); err != nil {
			return fmt.Errorf("committed host firewall no longer verifies: %w", err)
		}
		return service.backend.Health(ctx)
	}
	if journal.Phase == PhaseRollbackPending {
		if err := service.rollback(ctx, &journal, false); err != nil {
			return fmt.Errorf("cannot finish prior host firewall rollback: %w", err)
		}
	}
	defer func() {
		if returnErr == nil {
			return
		}
		rollbackContext, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if rollbackErr := service.rollback(rollbackContext, &journal, false); rollbackErr != nil {
			returnErr = fmt.Errorf("%w; automatic rollback also failed: %v", returnErr, rollbackErr)
		}
	}()

	if journal.Phase == PhaseInstalling || journal.Phase == PhaseRolledBack {
		if err := service.prepare(ctx, &journal); err != nil {
			return err
		}
	}
	if journal.Phase == PhasePrepared {
		if err := service.ensureDisabledRules(ctx, &journal); err != nil {
			return err
		}
	}
	if journal.Phase == PhaseRulesDisabled {
		if err := service.applyOptions(ctx, &journal); err != nil {
			return err
		}
	}
	if journal.Phase == PhaseOptionsApplied {
		if err := service.enableRules(ctx, &journal); err != nil {
			return err
		}
	}
	if journal.Phase != PhaseRulesEnabled {
		return errors.New("host firewall transaction did not reach verification")
	}
	if err := service.verify(ctx, journal, true); err != nil {
		return err
	}
	if err := service.backend.Health(ctx); err != nil {
		return err
	}
	journal.Phase = PhaseCommitted
	if err := service.store.save(journal); err != nil {
		return err
	}
	return nil
}

func (service *Service) prepare(ctx context.Context, journal *Journal) error {
	node, err := service.backend.LocalNode(ctx)
	if err != nil {
		return err
	}
	nodes, err := service.backend.ClusterNodes(ctx)
	if err != nil {
		return err
	}
	interfaces, err := service.backend.DefaultRouteInterfaces(ctx)
	if err != nil {
		return err
	}
	cluster, err := service.backend.ClusterOptions(ctx)
	if err != nil {
		return err
	}
	clusterEnable, err := snapshotValue(cluster.Values, "enable")
	if err != nil {
		return err
	}
	if len(nodes) > 1 && (!clusterEnable.Present || clusterEnable.Value != "1") {
		return errors.New("refusing cluster-wide firewall activation from one node of a multi-node cluster")
	}
	nodeOptions, err := service.backend.NodeOptions(ctx, node)
	if err != nil {
		return err
	}
	ruleSet, err := service.backend.NodeRules(ctx, node)
	if err != nil {
		return err
	}
	for _, rule := range ruleSet.Items {
		if strings.HasPrefix(rule.Comment, "PPFlight host firewall:") {
			return errors.New("an unowned or duplicate PPFlight host firewall rule already exists")
		}
	}
	clusterPolicyIn, err := snapshotValue(cluster.Values, "policy_in")
	if err != nil {
		return err
	}
	clusterPolicyOut, err := snapshotValue(cluster.Values, "policy_out")
	if err != nil {
		return err
	}
	nodeEnable, err := snapshotValue(nodeOptions.Values, "enable")
	if err != nil {
		return err
	}
	rulePlan := make([]ownedRule, 0, len(interfaces))
	for _, iface := range interfaces {
		rulePlan = append(rulePlan, ownedRule{Interface: iface, Comment: ownedRuleComment(journal.InstallID, iface)})
	}
	journal.Node = node
	journal.Interfaces = interfaces
	journal.Preimage = journalPreimage{
		Cluster: optionSnapshot{Enable: clusterEnable, PolicyIn: clusterPolicyIn, PolicyOut: clusterPolicyOut},
		Node:    optionSnapshot{Enable: nodeEnable},
	}
	journal.OwnedRules = rulePlan
	journal.Phase = PhasePrepared
	return service.store.save(*journal)
}

func (service *Service) ensureDisabledRules(ctx context.Context, journal *Journal) error {
	for _, expected := range journal.OwnedRules {
		ruleSet, err := service.backend.NodeRules(ctx, journal.Node)
		if err != nil {
			return err
		}
		matches := rulesWithComment(ruleSet.Items, expected.Comment)
		if len(matches) > 1 {
			return errors.New("duplicate owned host firewall rule")
		}
		if len(matches) == 1 {
			if err := validateOwnedRule(matches[0], expected, false); err != nil {
				return err
			}
			continue
		}
		if err := service.backend.CreateNodeRule(ctx, journal.Node, expected.Interface, expected.Comment, false, 0, ruleSet.Digest); err != nil {
			return err
		}
	}
	if err := service.verifyRules(ctx, *journal, false); err != nil {
		return err
	}
	journal.Phase = PhaseRulesDisabled
	return service.store.save(*journal)
}

func (service *Service) applyOptions(ctx context.Context, journal *Journal) error {
	clusterDesired := map[string]string{"enable": "1", "policy_in": "DROP", "policy_out": "ACCEPT"}
	clusterOriginal := map[string]optionValue{
		"enable": journal.Preimage.Cluster.Enable, "policy_in": journal.Preimage.Cluster.PolicyIn, "policy_out": journal.Preimage.Cluster.PolicyOut,
	}
	cluster, err := service.backend.ClusterOptions(ctx)
	if err != nil {
		return err
	}
	needsClusterWrite, err := verifyApplicableOptions(cluster.Values, clusterOriginal, clusterDesired)
	if err != nil {
		return err
	}
	if needsClusterWrite {
		if err := service.backend.SetClusterOptions(ctx, clusterDesired, nil, cluster.Digest); err != nil {
			return err
		}
	}
	nodeDesired := map[string]string{"enable": "1"}
	nodeOriginal := map[string]optionValue{"enable": journal.Preimage.Node.Enable}
	nodeOptions, err := service.backend.NodeOptions(ctx, journal.Node)
	if err != nil {
		return err
	}
	needsNodeWrite, err := verifyApplicableOptions(nodeOptions.Values, nodeOriginal, nodeDesired)
	if err != nil {
		return err
	}
	if needsNodeWrite {
		if err := service.backend.SetNodeOptions(ctx, journal.Node, nodeDesired, nil, nodeOptions.Digest); err != nil {
			return err
		}
	}
	if err := service.verifyOptions(ctx, *journal); err != nil {
		return err
	}
	journal.Phase = PhaseOptionsApplied
	return service.store.save(*journal)
}

func verifyApplicableOptions(current map[string]any, original map[string]optionValue, desired map[string]string) (bool, error) {
	needsWrite := false
	for key, wanted := range desired {
		observed, err := snapshotValue(current, key)
		if err != nil {
			return false, err
		}
		if observed.Present && observed.Value == wanted {
			continue
		}
		if observed != original[key] {
			return false, errors.New("firewall options changed concurrently")
		}
		needsWrite = true
	}
	return needsWrite, nil
}

func (service *Service) enableRules(ctx context.Context, journal *Journal) error {
	for _, expected := range journal.OwnedRules {
		ruleSet, err := service.backend.NodeRules(ctx, journal.Node)
		if err != nil {
			return err
		}
		matches := rulesWithComment(ruleSet.Items, expected.Comment)
		if len(matches) != 1 {
			return errors.New("owned host firewall rule is missing or duplicated")
		}
		if matches[0].Enabled {
			if err := validateOwnedRule(matches[0], expected, true); err != nil {
				return err
			}
			continue
		}
		if err := validateOwnedRule(matches[0], expected, false); err != nil {
			return err
		}
		if err := service.backend.SetNodeRuleEnabled(ctx, journal.Node, matches[0].Position, true, ruleSet.Digest); err != nil {
			return err
		}
	}
	if err := service.verify(ctx, *journal, true); err != nil {
		return err
	}
	journal.Phase = PhaseRulesEnabled
	return service.store.save(*journal)
}

func (service *Service) verify(ctx context.Context, journal Journal, enabled bool) error {
	if err := service.verifyOptions(ctx, journal); err != nil {
		return err
	}
	return service.verifyRules(ctx, journal, enabled)
}

func (service *Service) verifyOptions(ctx context.Context, journal Journal) error {
	cluster, err := service.backend.ClusterOptions(ctx)
	if err != nil {
		return err
	}
	for key, wanted := range map[string]string{"enable": "1", "policy_in": "DROP", "policy_out": "ACCEPT"} {
		observed, err := snapshotValue(cluster.Values, key)
		if err != nil || !observed.Present || observed.Value != wanted {
			return errors.New("cluster firewall option readback mismatch")
		}
	}
	node, err := service.backend.NodeOptions(ctx, journal.Node)
	if err != nil {
		return err
	}
	observed, err := snapshotValue(node.Values, "enable")
	if err != nil || !observed.Present || observed.Value != "1" {
		return errors.New("node firewall option readback mismatch")
	}
	return nil
}

func (service *Service) verifyRules(ctx context.Context, journal Journal, enabled bool) error {
	ruleSet, err := service.backend.NodeRules(ctx, journal.Node)
	if err != nil {
		return err
	}
	expected := map[string]ownedRule{}
	for _, rule := range journal.OwnedRules {
		expected[rule.Comment] = rule
	}
	seen := map[string]bool{}
	maxOwned := -1
	minOther := int(^uint(0) >> 1)
	for _, rule := range ruleSet.Items {
		if strings.HasPrefix(rule.Comment, "PPFlight host firewall:") {
			wanted, ok := expected[rule.Comment]
			if !ok || seen[rule.Comment] {
				return errors.New("unknown or duplicate PPFlight host firewall rule")
			}
			if err := validateOwnedRule(rule, wanted, enabled); err != nil {
				return err
			}
			seen[rule.Comment] = true
			if rule.Position > maxOwned {
				maxOwned = rule.Position
			}
		} else if rule.Position < minOther {
			minOther = rule.Position
		}
	}
	if len(seen) != len(expected) {
		return errors.New("owned host firewall rule set is incomplete")
	}
	if minOther != int(^uint(0)>>1) && maxOwned >= minOther {
		return errors.New("owned host firewall rules do not precede administrator rules")
	}
	return nil
}

func validateOwnedRule(actual firewallRule, expected ownedRule, enabled bool) error {
	if actual.Direction != "in" || actual.Action != "DROP" || actual.Interface != expected.Interface ||
		actual.Comment != expected.Comment || actual.Enabled != enabled {
		return errors.New("owned host firewall rule readback mismatch")
	}
	return nil
}

func rulesWithComment(rules []firewallRule, comment string) []firewallRule {
	var result []firewallRule
	for _, rule := range rules {
		if rule.Comment == comment {
			result = append(result, rule)
		}
	}
	return result
}

func (service *Service) Rollback(ctx context.Context, uninstall bool) error {
	journal, err := service.store.load()
	if err != nil {
		return err
	}
	return service.rollback(ctx, &journal, uninstall)
}

func (service *Service) rollback(ctx context.Context, journal *Journal, uninstall bool) error {
	if journal.Phase == PhaseUninstalled {
		return nil
	}
	if journal.Phase == PhaseInstalling {
		if uninstall {
			journal.Phase = PhaseUninstalled
		} else {
			journal.Phase = PhaseRolledBack
		}
		return service.store.save(*journal)
	}
	journal.Phase = PhaseRollbackPending
	if err := service.store.save(*journal); err != nil {
		return err
	}
	if err := service.removeOwnedRules(ctx, *journal); err != nil {
		return err
	}
	var drift []string
	if err := service.restoreOption(ctx, false, journal.Node, "enable", journal.Preimage.Node.Enable, "1"); err != nil {
		drift = append(drift, "node.enable")
	}
	for _, item := range []struct {
		key      string
		original optionValue
		desired  string
	}{
		{"enable", journal.Preimage.Cluster.Enable, "1"},
		{"policy_in", journal.Preimage.Cluster.PolicyIn, "DROP"},
		{"policy_out", journal.Preimage.Cluster.PolicyOut, "ACCEPT"},
	} {
		if err := service.restoreOption(ctx, true, "", item.key, item.original, item.desired); err != nil {
			drift = append(drift, "cluster."+item.key)
		}
	}
	if len(drift) > 0 {
		sort.Strings(drift)
		return fmt.Errorf("administrator firewall changes were preserved; intervention required for %s", strings.Join(drift, ","))
	}
	if uninstall {
		journal.Phase = PhaseUninstalled
	} else {
		journal.Phase = PhaseRolledBack
	}
	return service.store.save(*journal)
}

func (service *Service) removeOwnedRules(ctx context.Context, journal Journal) error {
	prefix := "PPFlight host firewall:" + journal.InstallID + ":"
	for attempt := 0; attempt < 64; attempt++ {
		ruleSet, err := service.backend.NodeRules(ctx, journal.Node)
		if err != nil {
			return err
		}
		var found *firewallRule
		for index := range ruleSet.Items {
			if strings.HasPrefix(ruleSet.Items[index].Comment, prefix) {
				candidate := ruleSet.Items[index]
				found = &candidate
				break
			}
		}
		if found == nil {
			return nil
		}
		if found.Enabled {
			if err := service.backend.SetNodeRuleEnabled(ctx, journal.Node, found.Position, false, ruleSet.Digest); err != nil {
				return err
			}
			continue
		}
		if err := service.backend.DeleteNodeRule(ctx, journal.Node, found.Position, ruleSet.Digest); err != nil {
			return err
		}
	}
	return errors.New("owned host firewall rule removal exceeded safety bound")
}

func (service *Service) restoreOption(ctx context.Context, cluster bool, node, key string, original optionValue, desired string) error {
	var current firewallOptions
	var err error
	if cluster {
		current, err = service.backend.ClusterOptions(ctx)
	} else {
		current, err = service.backend.NodeOptions(ctx, node)
	}
	if err != nil {
		return err
	}
	observed, err := snapshotValue(current.Values, key)
	if err != nil {
		return err
	}
	if observed == original {
		return nil
	}
	if !observed.Present || observed.Value != desired {
		return errors.New("firewall option changed after PPFlight activation")
	}
	values := map[string]string{}
	var deleted []string
	if original.Present {
		values[key] = original.Value
	} else {
		deleted = []string{key}
	}
	if cluster {
		return service.backend.SetClusterOptions(ctx, values, deleted, current.Digest)
	}
	return service.backend.SetNodeOptions(ctx, node, values, deleted, current.Digest)
}

func Run(args []string, out, errOut io.Writer) int {
	if out == nil {
		out = os.Stdout
	}
	if errOut == nil {
		errOut = os.Stderr
	}
	if effectiveUID() != 0 {
		fmt.Fprintln(errOut, "host firewall helper must run as root")
		return 1
	}
	if len(args) == 0 {
		fmt.Fprintln(errOut, "host firewall helper requires classify, activate, or rollback")
		return 2
	}
	service := productionService()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	switch args[0] {
	case "classify":
		if len(args) != 1 {
			fmt.Fprintln(errOut, "classify accepts no arguments")
			return 2
		}
		mode, err := service.Classify()
		if err != nil {
			fmt.Fprintf(errOut, "host firewall classification failed: %v\n", err)
			return 1
		}
		fmt.Fprintln(out, mode)
		return 0
	case "activate":
		if len(args) != 1 {
			fmt.Fprintln(errOut, "activate accepts no arguments")
			return 2
		}
		activationContext, activationCancel := context.WithTimeout(ctx, 3*time.Minute)
		defer activationCancel()
		if err := service.Activate(activationContext); err != nil {
			fmt.Fprintf(errOut, "host firewall activation failed: %v\n", err)
			return 1
		}
		fmt.Fprintln(out, "PPFlight 全新安装主机防火墙已提交并严格回验。")
		return 0
	case "rollback":
		flags := flag.NewFlagSet("rollback", flag.ContinueOnError)
		flags.SetOutput(errOut)
		uninstall := flags.Bool("uninstall", false, "mark the transaction uninstalled after rollback")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
			return 2
		}
		rollbackContext, rollbackCancel := context.WithTimeout(ctx, 2*time.Minute)
		defer rollbackCancel()
		if err := service.Rollback(rollbackContext, *uninstall); err != nil {
			fmt.Fprintf(errOut, "host firewall rollback failed: %v\n", err)
			return 1
		}
		fmt.Fprintln(out, "PPFlight 自有主机防火墙规则已移除，未冲突的原选项已恢复。")
		return 0
	default:
		fmt.Fprintln(errOut, "unknown host firewall helper command")
		return 2
	}
}
