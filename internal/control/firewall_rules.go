package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/ppflight/ppflight-agent/internal/pve"
)

const maxGuestFirewallRules = 1000

var pveDigestRE = regexp.MustCompile(`^[0-9a-f]{40}$`)

type guestFirewallRulesListP struct{}

type guestFirewallRulesGetP struct {
	Position int `json:"position"`
}

type guestFirewallRulesVerifyP struct {
	ExpectedDigest string              `json:"expectedDigest"`
	Rules          []GuestFirewallRule `json:"rules"`
}

// GuestFirewallRule is the canonical, secret-free projection used by all
// guest firewall rule reads. Every semantically relevant supported field is
// included so its digest cannot stay unchanged when a managed rule changes.
type GuestFirewallRule struct {
	Position        int    `json:"position"`
	Type            string `json:"type"`
	Action          string `json:"action"`
	Macro           string `json:"macro,omitempty"`
	Protocol        string `json:"protocol,omitempty"`
	ICMPType        string `json:"icmpType,omitempty"`
	Source          string `json:"source,omitempty"`
	Destination     string `json:"destination,omitempty"`
	SourcePort      string `json:"sourcePort,omitempty"`
	DestinationPort string `json:"destinationPort,omitempty"`
	Interface       string `json:"interface,omitempty"`
	IPVersion       string `json:"ipVersion,omitempty"`
	LogLevel        string `json:"logLevel,omitempty"`
	Enabled         bool   `json:"enabled"`
	Comment         string `json:"comment,omitempty"`
}

type GuestFirewallRulesResult struct {
	Rules  []GuestFirewallRule `json:"rules"`
	Digest string              `json:"digest"`
}

type GuestFirewallRuleResult struct {
	Rule   GuestFirewallRule `json:"rule"`
	Digest string            `json:"digest"`
}

type GuestFirewallRulesVerifyResult struct {
	Verified bool                `json:"verified"`
	Rules    []GuestFirewallRule `json:"rules"`
	Digest   string              `json:"digest"`
}

// pveGuestFirewallRule is deliberately strict. Unsupported PVE rule features
// fail closed rather than disappearing from the deterministic digest.
type pveGuestFirewallRule struct {
	Position  *int            `json:"pos"`
	Type      string          `json:"type"`
	Action    string          `json:"action"`
	Enable    *int            `json:"enable,omitempty"`
	Interface string          `json:"iface,omitempty"`
	Source    string          `json:"source,omitempty"`
	Dest      string          `json:"dest,omitempty"`
	Proto     string          `json:"proto,omitempty"`
	DPort     string          `json:"dport,omitempty"`
	SPort     string          `json:"sport,omitempty"`
	Comment   string          `json:"comment,omitempty"`
	Log       string          `json:"log,omitempty"`
	Macro     string          `json:"macro,omitempty"`
	ICMPType  string          `json:"icmp-type,omitempty"`
	IPVersion json.RawMessage `json:"ipversion,omitempty"`
	Digest    string          `json:"digest,omitempty"`
	Errors    json.RawMessage `json:"errors,omitempty"`
}

func executeGuestFirewallRules(ctx context.Context, client *pve.Client, command Command, base string) (json.RawMessage, error) {
	rules, digest, err := readGuestFirewallRules(ctx, client, base)
	if err != nil {
		return nil, err
	}
	switch command.Action {
	case "firewall.guest.rules.list":
		return json.Marshal(GuestFirewallRulesResult{Rules: rules, Digest: digest})
	case "firewall.guest.rules.get":
		var parameters guestFirewallRulesGetP
		_ = strictParameters(command.Parameters, &parameters)
		for _, rule := range rules {
			if rule.Position == parameters.Position {
				ruleDigest, digestErr := guestFirewallRulesDigest([]GuestFirewallRule{rule})
				if digestErr != nil {
					return nil, digestErr
				}
				return json.Marshal(GuestFirewallRuleResult{Rule: rule, Digest: ruleDigest})
			}
		}
		return nil, errors.New("guest firewall rule position was not found")
	case "firewall.guest.rules.verify":
		var parameters guestFirewallRulesVerifyP
		_ = strictParameters(command.Parameters, &parameters)
		expectedDigest, digestErr := guestFirewallRulesDigest(parameters.Rules)
		if digestErr != nil || expectedDigest != parameters.ExpectedDigest {
			return nil, errors.New("expected guest firewall rules contract is invalid")
		}
		if digest != expectedDigest || !equalGuestFirewallRules(rules, parameters.Rules) {
			return nil, errors.New("guest firewall rules do not match the signed expected state")
		}
		return json.Marshal(GuestFirewallRulesVerifyResult{Verified: true, Rules: rules, Digest: digest})
	default:
		return nil, ErrUnsupported
	}
}

func readGuestFirewallRules(ctx context.Context, client *pve.Client, base string) ([]GuestFirewallRule, string, error) {
	var rows []json.RawMessage
	if err := client.Do(ctx, http.MethodGet, base+"/firewall/rules", nil, nil, &rows); err != nil {
		return nil, "", err
	}
	if len(rows) > maxGuestFirewallRules {
		return nil, "", errors.New("guest firewall rule collection exceeds limit")
	}
	rules := make([]GuestFirewallRule, 0, len(rows))
	seen := make(map[int]struct{}, len(rows))
	for _, raw := range rows {
		var upstream pveGuestFirewallRule
		if err := strictParameters(raw, &upstream); err != nil {
			return nil, "", errors.New("PVE returned an unsupported guest firewall rule field")
		}
		rule, err := normalizeGuestFirewallRule(upstream)
		if err != nil {
			return nil, "", err
		}
		if _, exists := seen[rule.Position]; exists {
			return nil, "", errors.New("PVE returned duplicate guest firewall rule positions")
		}
		seen[rule.Position] = struct{}{}
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Position < rules[j].Position })
	digest, err := guestFirewallRulesDigest(rules)
	return rules, digest, err
}

func normalizeGuestFirewallRule(value pveGuestFirewallRule) (GuestFirewallRule, error) {
	if value.Position == nil || *value.Position < 0 || *value.Position > 999 || !validFirewallRuleType(value.Type) ||
		(value.Interface != "" && !netRE.MatchString(value.Interface)) || !validFirewallLogLevel(value.Log) ||
		(value.Digest != "" && !pveDigestRE.MatchString(value.Digest)) || !emptyPVEFirewallErrors(value.Errors) ||
		!safeFirewallRuleField(value.Action, 128) || !safeOptionalFirewallRuleField(value.Macro, 128) ||
		!safeOptionalFirewallRuleField(value.Proto, 32) || !safeOptionalFirewallRuleField(value.ICMPType, 128) ||
		!safeOptionalFirewallRuleField(value.Source, 512) || !safeOptionalFirewallRuleField(value.Dest, 512) ||
		!safeOptionalFirewallRuleField(value.SPort, 512) || !safeOptionalFirewallRuleField(value.DPort, 512) ||
		!safeOptionalFirewallRuleField(value.Comment, 256) {
		return GuestFirewallRule{}, errors.New("PVE returned an unsupported or invalid guest firewall rule")
	}
	enabled := false
	if value.Enable != nil {
		if *value.Enable != 0 && *value.Enable != 1 {
			return GuestFirewallRule{}, errors.New("PVE returned an invalid guest firewall rule enable value")
		}
		enabled = *value.Enable == 1
	}
	ipVersion, err := normalizeFirewallIPVersion(value.IPVersion)
	if err != nil {
		return GuestFirewallRule{}, err
	}
	projection := GuestFirewallRule{Position: *value.Position, Type: value.Type, Action: value.Action, Macro: value.Macro,
		Protocol: value.Proto, ICMPType: value.ICMPType,
		Source: value.Source, Destination: value.Dest, SourcePort: value.SPort, DestinationPort: value.DPort,
		Interface: value.Interface, IPVersion: ipVersion, LogLevel: value.Log, Enabled: enabled, Comment: value.Comment}
	if (projection.Type == "group" && projection.Macro != "") ||
		(projection.Type == "group" && !nameRE.MatchString(projection.Action)) ||
		(projection.Macro != "" && !nameRE.MatchString(projection.Macro)) {
		return GuestFirewallRule{}, errors.New("PVE returned a guest firewall rule outside the typed contract")
	}
	return projection, nil
}

func guestFirewallRulesDigest(rules []GuestFirewallRule) (string, error) {
	if len(rules) > maxGuestFirewallRules {
		return "", errors.New("guest firewall rule collection exceeds limit")
	}
	previous := -1
	for _, rule := range rules {
		if rule.Position <= previous || !validCanonicalGuestFirewallRule(rule) {
			return "", errors.New("guest firewall rules are not canonical")
		}
		previous = rule.Position
	}
	raw, err := json.Marshal(rules)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func validCanonicalGuestFirewallRule(rule GuestFirewallRule) bool {
	return rule.Position >= 0 && rule.Position <= 999 && validFirewallRuleType(rule.Type) &&
		(rule.Interface == "" || netRE.MatchString(rule.Interface)) &&
		(rule.IPVersion == "" || rule.IPVersion == "4" || rule.IPVersion == "6") && validFirewallLogLevel(rule.LogLevel) &&
		safeFirewallRuleField(rule.Action, 128) && safeOptionalFirewallRuleField(rule.Macro, 128) &&
		safeOptionalFirewallRuleField(rule.Protocol, 32) && safeOptionalFirewallRuleField(rule.ICMPType, 128) &&
		safeOptionalFirewallRuleField(rule.Source, 512) && safeOptionalFirewallRuleField(rule.Destination, 512) &&
		safeOptionalFirewallRuleField(rule.SourcePort, 512) && safeOptionalFirewallRuleField(rule.DestinationPort, 512) &&
		safeOptionalFirewallRuleField(rule.Comment, 256) &&
		(rule.Type != "group" || rule.Macro == "") && (rule.Type != "group" || nameRE.MatchString(rule.Action)) &&
		(rule.Macro == "" || nameRE.MatchString(rule.Macro))
}

func equalGuestFirewallRules(left, right []GuestFirewallRule) bool {
	leftRaw, leftErr := json.Marshal(left)
	rightRaw, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftRaw, rightRaw)
}

func normalizeFirewallIPVersion(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return "", nil
	}
	var text string
	if json.Unmarshal(raw, &text) == nil && (text == "4" || text == "6") {
		return text, nil
	}
	var number int
	if json.Unmarshal(raw, &number) == nil && (number == 4 || number == 6) {
		return fmt.Sprint(number), nil
	}
	return "", errors.New("PVE returned an invalid guest firewall IP version")
}

func validFirewallLogLevel(value string) bool {
	switch strings.ToLower(value) {
	case "", "nolog", "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug":
		return value == strings.ToLower(value)
	default:
		return false
	}
}

func emptyPVEFirewallErrors(raw json.RawMessage) bool {
	return len(raw) == 0 || bytes.Equal(raw, []byte("null")) || bytes.Equal(raw, []byte(`""`)) ||
		bytes.Equal(raw, []byte("[]")) || bytes.Equal(raw, []byte("{}"))
}

func validFirewallRuleType(value string) bool {
	return value == "in" || value == "out" || value == "group"
}

func safeOptionalFirewallRuleField(value string, limit int) bool {
	return value == "" || safeFirewallRuleField(value, limit)
}

func safeFirewallRuleField(value string, limit int) bool {
	if value == "" || len(value) > limit || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
