package hostfirewall

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	journalSchema = 1
	journalKind   = "ppflight-host-firewall-initial/v1"

	PhaseInstalling      = "installing"
	PhasePrepared        = "prepared"
	PhaseRulesDisabled   = "rules-disabled"
	PhaseOptionsApplied  = "options-applied"
	PhaseRulesEnabled    = "rules-enabled"
	PhaseCommitted       = "committed"
	PhaseRollbackPending = "rollback-pending"
	PhaseRolledBack      = "rolled-back"
	PhaseUninstalled     = "uninstalled"
)

const (
	productionStateDirectory = "/var/lib/ppflight-agent/host-firewall"
	productionJournalPath    = productionStateDirectory + "/transaction.json"
)

type optionValue struct {
	Present bool   `json:"present"`
	Value   string `json:"value,omitempty"`
}

type optionSnapshot struct {
	Enable    optionValue `json:"enable"`
	PolicyIn  optionValue `json:"policyIn,omitempty"`
	PolicyOut optionValue `json:"policyOut,omitempty"`
}

type journalPreimage struct {
	Cluster optionSnapshot `json:"cluster"`
	Node    optionSnapshot `json:"node"`
}

type ownedRule struct {
	Interface string `json:"interface"`
	Comment   string `json:"comment"`
}

type Journal struct {
	SchemaVersion int             `json:"schemaVersion"`
	Kind          string          `json:"kind"`
	InstallID     string          `json:"installId"`
	Phase         string          `json:"phase"`
	Node          string          `json:"node,omitempty"`
	Interfaces    []string        `json:"interfaces,omitempty"`
	Preimage      journalPreimage `json:"preimage,omitempty"`
	OwnedRules    []ownedRule     `json:"ownedRules,omitempty"`
	CreatedAt     string          `json:"createdAt"`
	UpdatedAt     string          `json:"updatedAt"`
}

func (j Journal) validate() error {
	if j.SchemaVersion != journalSchema || j.Kind != journalKind {
		return errors.New("unsupported host firewall journal")
	}
	if len(j.InstallID) != 32 {
		return errors.New("invalid host firewall install identity")
	}
	if _, err := hex.DecodeString(j.InstallID); err != nil {
		return errors.New("invalid host firewall install identity")
	}
	switch j.Phase {
	case PhaseInstalling, PhasePrepared, PhaseRulesDisabled, PhaseOptionsApplied,
		PhaseRulesEnabled, PhaseCommitted, PhaseRollbackPending, PhaseRolledBack, PhaseUninstalled:
	default:
		return errors.New("invalid host firewall journal phase")
	}
	if j.CreatedAt == "" || j.UpdatedAt == "" {
		return errors.New("host firewall journal timestamp missing")
	}
	if _, err := time.Parse(time.RFC3339Nano, j.CreatedAt); err != nil {
		return errors.New("invalid host firewall journal timestamp")
	}
	if _, err := time.Parse(time.RFC3339Nano, j.UpdatedAt); err != nil {
		return errors.New("invalid host firewall journal timestamp")
	}
	if j.Phase != PhaseInstalling {
		if !validNodeName(j.Node) {
			return errors.New("invalid journal node")
		}
		if len(j.Interfaces) == 0 || len(j.Interfaces) > 32 {
			return errors.New("invalid journal ingress interface set")
		}
		seen := map[string]bool{}
		for _, iface := range j.Interfaces {
			if !validInterfaceName(iface) || seen[iface] {
				return errors.New("invalid journal ingress interface")
			}
			seen[iface] = true
		}
		if len(j.OwnedRules) != len(j.Interfaces) {
			return errors.New("journal rule set does not cover every ingress interface")
		}
		for _, rule := range j.OwnedRules {
			if !seen[rule.Interface] || rule.Comment != ownedRuleComment(j.InstallID, rule.Interface) {
				return errors.New("invalid journal owned rule")
			}
		}
	}
	return nil
}

type store struct {
	stateDirectory string
	journalPath    string
	requireRoot    bool
	now            func() time.Time
}

func productionStore() store {
	return store{
		stateDirectory: productionStateDirectory,
		journalPath:    productionJournalPath,
		requireRoot:    true,
		now:            time.Now,
	}
}

func (s store) exists() (bool, error) {
	info, err := os.Lstat(s.journalPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := validateJournalMetadata(info, s.requireRoot); err != nil {
		return false, err
	}
	return true, nil
}

func (s store) load() (Journal, error) {
	info, err := os.Lstat(s.journalPath)
	if err != nil {
		return Journal{}, err
	}
	if err := validateJournalMetadata(info, s.requireRoot); err != nil {
		return Journal{}, err
	}
	file, err := os.Open(s.journalPath)
	if err != nil {
		return Journal{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 64<<10))
	decoder.DisallowUnknownFields()
	var result Journal
	if err := decoder.Decode(&result); err != nil {
		return Journal{}, errors.New("invalid host firewall journal JSON")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Journal{}, errors.New("host firewall journal contains trailing data")
	}
	if err := result.validate(); err != nil {
		return Journal{}, err
	}
	return result, nil
}

func (s store) createInitial() (Journal, error) {
	if err := ensureStateDirectory(s.stateDirectory, s.requireRoot); err != nil {
		return Journal{}, err
	}
	identity := make([]byte, 16)
	if _, err := rand.Read(identity); err != nil {
		return Journal{}, errors.New("cannot generate host firewall ownership identity")
	}
	now := s.now().UTC().Format(time.RFC3339Nano)
	result := Journal{
		SchemaVersion: journalSchema,
		Kind:          journalKind,
		InstallID:     hex.EncodeToString(identity),
		Phase:         PhaseInstalling,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := s.write(result, true); err != nil {
		return Journal{}, err
	}
	return result, nil
}

func (s store) save(journal Journal) error {
	journal.UpdatedAt = s.now().UTC().Format(time.RFC3339Nano)
	return s.write(journal, false)
}

func (s store) write(journal Journal, exclusive bool) error {
	if err := journal.validate(); err != nil {
		return err
	}
	if err := ensureStateDirectory(s.stateDirectory, s.requireRoot); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return errors.New("cannot encode host firewall journal")
	}
	encoded = append(encoded, '\n')
	temporary, err := os.CreateTemp(s.stateDirectory, ".transaction.tmp.*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}
	if err := temporary.Chmod(0o600); err != nil {
		cleanup()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		cleanup()
		return err
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return err
	}
	if exclusive {
		// A hard link is the portable atomic create-if-absent primitive needed
		// here. Rename would overwrite another concurrent install classifier.
		if err := os.Link(temporaryPath, s.journalPath); err != nil {
			_ = os.Remove(temporaryPath)
			if errors.Is(err, os.ErrExist) {
				return errors.New("host firewall journal already exists")
			}
			return err
		}
		if err := os.Remove(temporaryPath); err != nil {
			return err
		}
	} else {
		if err := os.Rename(temporaryPath, s.journalPath); err != nil {
			_ = os.Remove(temporaryPath)
			return err
		}
	}
	if err := os.Chmod(s.journalPath, 0o600); err != nil {
		return err
	}
	directory, err := os.Open(s.stateDirectory)
	if err != nil {
		return err
	}
	defer directory.Close()
	return syncDirectory(directory)
}

func ensureStateDirectory(path string, requireRoot bool) error {
	parent := filepath.Dir(path)
	if info, err := os.Lstat(parent); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("host firewall state parent is unsafe")
		}
		if requireRoot && !ownedByRoot(info) {
			return errors.New("host firewall state parent is not root-owned")
		}
		if requireRoot && info.Mode().Perm() != 0o750 {
			return errors.New("host firewall state parent mode is unsafe")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(parent, 0o750); err != nil {
			return err
		}
		// quick-install runs with umask 077. Make the intended root-only
		// group-traversable parent mode explicit instead of inheriting 0700.
		if err := os.Chmod(parent, 0o750); err != nil {
			return err
		}
	} else {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("host firewall state directory is unsafe")
		}
		if requireRoot && !ownedByRoot(info) {
			return errors.New("host firewall state directory is not root-owned")
		}
		if requireRoot && info.Mode().Perm() != 0o700 {
			return errors.New("host firewall state directory mode is unsafe")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Mkdir(path, 0o700)
}

func validateJournalMetadata(info os.FileInfo, requireRoot bool) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("host firewall journal is not a safe regular file")
	}
	if requireRoot && info.Mode().Perm() != 0o600 {
		return errors.New("host firewall journal mode is unsafe")
	}
	if requireRoot && !ownedByRoot(info) {
		return errors.New("host firewall journal is not root-owned")
	}
	return nil
}

func snapshotValue(values map[string]any, key string) (optionValue, error) {
	value, ok := values[key]
	if !ok || value == nil {
		return optionValue{}, nil
	}
	text, err := canonicalOptionValue(key, value)
	if err != nil {
		return optionValue{}, err
	}
	return optionValue{Present: true, Value: text}, nil
}

func canonicalOptionValue(key string, value any) (string, error) {
	text := strings.TrimSpace(fmt.Sprint(value))
	switch key {
	case "enable":
		switch strings.ToLower(text) {
		case "1", "true":
			return "1", nil
		case "0", "false":
			return "0", nil
		default:
			return "", errors.New("invalid firewall enable option")
		}
	case "policy_in", "policy_out":
		text = strings.ToUpper(text)
		if text != "ACCEPT" && text != "DROP" && text != "REJECT" {
			return "", errors.New("invalid firewall policy option")
		}
		return text, nil
	default:
		return "", errors.New("unsupported firewall option")
	}
}

func sortedInterfaces(values []string) ([]string, error) {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !validInterfaceName(value) || value == "lo" {
			return nil, errors.New("invalid default-route interface")
		}
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	if len(result) == 0 || len(result) > 32 {
		return nil, errors.New("no safe default-route interface found")
	}
	sort.Strings(result)
	return result, nil
}

func ownedRuleComment(installID, iface string) string {
	return "PPFlight host firewall:" + installID + ":" + iface
}

func validNodeName(value string) bool {
	if len(value) == 0 || len(value) > 63 {
		return false
	}
	for index, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			if index == 0 && (r == '.' || r == '-' || r == '_') {
				return false
			}
			continue
		}
		return false
	}
	return true
}

func validInterfaceName(value string) bool {
	if len(value) == 0 || len(value) > 15 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}
