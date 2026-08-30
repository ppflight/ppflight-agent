// Package bindingoverlay resolves endpoint credentials from the two private
// binding trust domains without copying secrets into environment variables or
// the public agent configuration.
package bindingoverlay

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/ppflight/ppflight-agent/internal/bindstate"
	"github.com/ppflight/ppflight-agent/internal/config"
	"github.com/ppflight/ppflight-agent/internal/enrollment"
	"github.com/ppflight/ppflight-agent/internal/monitorenrollment"
	"github.com/ppflight/ppflight-agent/internal/netpolicy"
)

const (
	WebsiteMeteringKeyIDEnv    = "PPFLIGHT_BINDING_METERING_KEY_ID"
	WebsiteMeteringSecretEnv   = "PPFLIGHT_BINDING_METERING_SECRET"
	WebsiteTelemetryKeyIDEnv   = "PPFLIGHT_BINDING_TELEMETRY_KEY_ID"
	WebsiteTelemetrySecretEnv  = "PPFLIGHT_BINDING_TELEMETRY_SECRET"
	WebsiteCommandKeyIDEnv     = "PPFLIGHT_BINDING_COMMAND_KEY_ID"
	WebsiteCommandSecretEnv    = "PPFLIGHT_BINDING_COMMAND_SECRET"
	WebsiteSigningKeyIDEnv     = "PPFLIGHT_BINDING_COMMAND_SIGNING_KEY_ID"
	WebsiteCommandPublicKeyEnv = "PPFLIGHT_BINDING_COMMAND_PUBLIC_KEY"
	MonitoringKeyIDEnv         = "PPFLIGHT_MONITORING_BINDING_KEY_ID"
	MonitoringSecretEnv        = "PPFLIGHT_MONITORING_BINDING_SECRET"
)

var reserved = map[string]struct{}{
	WebsiteMeteringKeyIDEnv: {}, WebsiteMeteringSecretEnv: {},
	WebsiteTelemetryKeyIDEnv: {}, WebsiteTelemetrySecretEnv: {},
	WebsiteCommandKeyIDEnv: {}, WebsiteCommandSecretEnv: {},
	WebsiteSigningKeyIDEnv: {}, WebsiteCommandPublicKeyEnv: {},
	MonitoringKeyIDEnv: {}, MonitoringSecretEnv: {},
}

// WebsiteNetworkPolicy returns only the website-domain destination policy.
// It deliberately reads no monitoring state, so callers cannot accidentally
// share allowlists across the two independent trust domains.
func WebsiteNetworkPolicy(stateDirectory string) (netpolicy.NetworkPolicy, error) {
	state, err := bindstate.Load(stateDirectory)
	if err != nil {
		return netpolicy.NetworkPolicy{}, errors.New("website binding state is required or unreadable")
	}
	return copyNetworkPolicy(state.NetworkPolicy), nil
}

// MonitoringNetworkPolicy is the equivalent isolated accessor for monitoring.
func MonitoringNetworkPolicy(stateDirectory string) (netpolicy.NetworkPolicy, error) {
	state, err := bindstate.LoadMonitoring(stateDirectory)
	if err != nil {
		return netpolicy.NetworkPolicy{}, errors.New("monitoring binding state is required or unreadable")
	}
	return copyNetworkPolicy(state.NetworkPolicy), nil
}

func copyNetworkPolicy(value netpolicy.NetworkPolicy) netpolicy.NetworkPolicy {
	return netpolicy.NetworkPolicy{AgentObservedIPv4: value.AgentObservedIPv4, ServerIPv4Allowlist: append([]string(nil), value.ServerIPv4Allowlist...)}
}

// Resolve gives private binding state priority only for exact reserved labels.
// Any other environment-variable label remains a manual configuration and is
// resolved with lookup. Unknown labels in the reserved namespaces fail closed.
func Resolve(cfg config.Config, lookup func(string) (string, bool)) (config.Secrets, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	labels := configLabels(cfg)
	for _, label := range labels {
		if (strings.HasPrefix(label, "PPFLIGHT_BINDING_") || strings.HasPrefix(label, "PPFLIGHT_MONITORING_BINDING_")) && !isReserved(label) {
			return config.Secrets{}, errors.New("configuration uses an unknown binding credential label")
		}
	}
	usesWebsite := cfg.Assignments.RefreshURL != "" || containsWebsiteLabel(labels)
	usesMonitoring := containsLabel(labels, MonitoringKeyIDEnv) || containsLabel(labels, MonitoringSecretEnv)
	resolved, err := cfg.ResolveSecrets(func(name string) (string, bool) {
		if isReserved(name) {
			return "binding-state-placeholder", true
		}
		return lookup(name)
	})
	if err != nil {
		return config.Secrets{}, err
	}
	if usesWebsite {
		state, loadErr := bindstate.Load(cfg.Runtime.StateDirectory)
		if loadErr != nil {
			return config.Secrets{}, errors.New("website binding state is required or unreadable")
		}
		if err := applyWebsite(cfg, state, &resolved); err != nil {
			return config.Secrets{}, err
		}
	}
	if usesMonitoring {
		state, loadErr := bindstate.LoadMonitoring(cfg.Runtime.StateDirectory)
		if loadErr != nil {
			return config.Secrets{}, errors.New("monitoring binding state is required or unreadable")
		}
		if err := applyMonitoring(cfg, state, &resolved); err != nil {
			return config.Secrets{}, err
		}
	}
	return resolved, nil
}

func applyWebsite(cfg config.Config, state bindstate.State, secrets *config.Secrets) error {
	identity := state.Identity
	if cfg.Identity.AgentRef != identity.AgentRef || cfg.Identity.CollectorRef != identity.CollectorRef || cfg.Identity.SourceRef != identity.SourceRef || cfg.Identity.ClusterRef != identity.ClusterRef || cfg.Identity.NodeRef != identity.NodeRef || cfg.Identity.Site != identity.Site {
		return errors.New("public configuration identity does not match website binding state")
	}
	if cfg.Destinations.WebsiteMetering.Enabled {
		if cfg.Destinations.WebsiteMetering.URL != state.Endpoints.Metering || !exactHMACLabels(cfg.Destinations.WebsiteMetering.Auth, WebsiteMeteringKeyIDEnv, WebsiteMeteringSecretEnv) {
			return errors.New("website metering configuration does not match binding state")
		}
		value, err := destinationSecret(state.HMACCredentials.Metering, state.CredentialEpoch)
		if err != nil {
			return err
		}
		secrets.WebsiteMetering = value
	}
	if cfg.Destinations.WebsiteTelemetry.Enabled {
		if cfg.Destinations.WebsiteTelemetry.URL != state.Endpoints.Telemetry || !exactHMACLabels(cfg.Destinations.WebsiteTelemetry.Auth, WebsiteTelemetryKeyIDEnv, WebsiteTelemetrySecretEnv) {
			return errors.New("website telemetry configuration does not match binding state")
		}
		value, err := destinationSecret(state.HMACCredentials.Telemetry, state.CredentialEpoch)
		if err != nil {
			return err
		}
		secrets.WebsiteTelemetry = value
	}
	if cfg.Assignments.RefreshURL != "" {
		if cfg.Assignments.RefreshURL != state.Endpoints.Assignments {
			return errors.New("assignment refresh configuration does not match binding state")
		}
		value, err := destinationSecret(state.HMACCredentials.Assignments, state.CredentialEpoch)
		if err != nil {
			return err
		}
		secrets.Assignments = value
	}
	publicKey, err := decodeBoundSecret(state.CommandSigningCredential.PublicKey, 32, 32)
	if err != nil {
		return errors.New("website binding signing public key is invalid")
	}
	secrets.ControlSigningKeyID = state.CommandSigningCredential.KeyID
	secrets.ControlPublicKey = publicKey
	if cfg.Control.Enabled && cfg.Control.PollURL != "" {
		if cfg.Control.PollURL != state.Endpoints.Commands || cfg.Control.ResultURL != state.Endpoints.Receipts ||
			!exactHMACLabels(cfg.Control.Auth, WebsiteCommandKeyIDEnv, WebsiteCommandSecretEnv) ||
			cfg.Control.CommandSigningKeyIDEnv != WebsiteSigningKeyIDEnv || cfg.Control.CommandPublicKeyEnv != WebsiteCommandPublicKeyEnv {
			return errors.New("control configuration does not match website binding state")
		}
		if !allowedSubset(cfg.Control.AllowedActions, state.AllowedActions) {
			return errors.New("control allowlist exceeds website binding grant")
		}
		commands, err := destinationSecret(state.HMACCredentials.Commands, state.CredentialEpoch)
		if err != nil {
			return err
		}
		receipts, err := destinationSecret(state.HMACCredentials.Receipts, state.CredentialEpoch)
		if err != nil {
			return err
		}
		secrets.ControlAPI = commands
		secrets.ControlReceipts = receipts
		secrets.ControlCommandSecret = nil
	}
	secrets.DeviceID = state.DeviceID
	secrets.WebsiteBindingID = state.BindingID
	secrets.WebsiteCredentialEpoch = state.CredentialEpoch
	return nil
}

func applyMonitoring(cfg config.Config, state bindstate.MonitoringState, secrets *config.Secrets) error {
	auditEndpoint, err := monitorenrollment.AuditEndpoint(state.IngestEndpoint)
	if err != nil {
		return errors.New("monitoring binding endpoint contract is invalid")
	}
	if !cfg.Destinations.Monitoring.Enabled || cfg.Destinations.Monitoring.URL != state.IngestEndpoint ||
		!exactHMACLabels(cfg.Destinations.Monitoring.Auth, MonitoringKeyIDEnv, MonitoringSecretEnv) ||
		cfg.Destinations.Monitoring.PayloadFormat != state.Telemetry.PayloadFormat || cfg.Destinations.Monitoring.Compression != state.Telemetry.Compression ||
		cfg.Destinations.Monitoring.MaxCompressedBytes != state.Telemetry.MaxCompressedBytes || cfg.Destinations.Monitoring.MaxUncompressedBytes != state.Telemetry.MaxUncompressedBytes {
		return errors.New("monitoring configuration does not match monitoring binding state")
	}
	if !cfg.Destinations.MonitoringAudit.Enabled || cfg.Destinations.MonitoringAudit.URL != auditEndpoint ||
		!exactHMACLabels(cfg.Destinations.MonitoringAudit.Auth, MonitoringKeyIDEnv, MonitoringSecretEnv) ||
		cfg.Destinations.MonitoringAudit.PayloadFormat != "audit-v1" || cfg.Destinations.MonitoringAudit.Compression != state.Telemetry.Compression ||
		cfg.Destinations.MonitoringAudit.MaxCompressedBytes != monitorenrollment.AuditMaxCompressedBytes || cfg.Destinations.MonitoringAudit.MaxUncompressedBytes != monitorenrollment.AuditMaxUncompressedBytes {
		return errors.New("monitoring audit configuration does not match monitoring binding state")
	}
	secret, err := decodeBoundSecret(string(state.HMACCredential.Secret), 16, 4096)
	if err != nil {
		return errors.New("monitoring binding credential is invalid")
	}
	secrets.Monitoring = config.DestinationSecret{KeyID: state.HMACCredential.KeyID, Secret: secret, CredentialEpoch: state.CredentialEpoch}
	secrets.MonitoringAudit = config.DestinationSecret{KeyID: state.HMACCredential.KeyID, Secret: append([]byte(nil), secret...), CredentialEpoch: state.CredentialEpoch}
	secrets.MonitoringAgentRef = state.MonitoringAgentRef
	secrets.MonitoringBindingID = state.BindingID
	if secrets.DeviceID != "" && secrets.DeviceID != state.DeviceID {
		return errors.New("website and monitoring bindings identify different devices")
	}
	secrets.DeviceID = state.DeviceID
	return nil
}

func destinationSecret(credential enrollment.HMACCredential, epoch uint64) (config.DestinationSecret, error) {
	secret, err := decodeBoundSecret(string(credential.Secret), 16, 4096)
	if err != nil {
		return config.DestinationSecret{}, errors.New("website binding credential is invalid")
	}
	return config.DestinationSecret{KeyID: credential.KeyID, Secret: secret, CredentialEpoch: epoch}, nil
}

func decodeBoundSecret(value string, minimum, maximum int) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) < minimum || len(decoded) > maximum {
		return nil, errors.New("invalid encoded credential")
	}
	return decoded, nil
}

func exactHMACLabels(auth config.AuthConfig, keyID, secret string) bool {
	return auth.Mode == "hmac-sha256" && auth.KeyIDEnv == keyID && auth.SecretEnv == secret && auth.BearerTokenEnv == ""
}

func allowedSubset(configured, granted []string) bool {
	grant := make(map[string]bool, len(granted))
	for _, action := range granted {
		grant[action] = true
	}
	for _, action := range configured {
		if !grant[action] {
			return false
		}
	}
	return true
}

func configLabels(cfg config.Config) []string {
	return []string{
		cfg.Destinations.WebsiteMetering.Auth.KeyIDEnv, cfg.Destinations.WebsiteMetering.Auth.SecretEnv, cfg.Destinations.WebsiteMetering.Auth.BearerTokenEnv,
		cfg.Destinations.WebsiteTelemetry.Auth.KeyIDEnv, cfg.Destinations.WebsiteTelemetry.Auth.SecretEnv, cfg.Destinations.WebsiteTelemetry.Auth.BearerTokenEnv,
		cfg.Destinations.Monitoring.Auth.KeyIDEnv, cfg.Destinations.Monitoring.Auth.SecretEnv, cfg.Destinations.Monitoring.Auth.BearerTokenEnv,
		cfg.Destinations.MonitoringAudit.Auth.KeyIDEnv, cfg.Destinations.MonitoringAudit.Auth.SecretEnv, cfg.Destinations.MonitoringAudit.Auth.BearerTokenEnv,
		cfg.Control.Auth.KeyIDEnv, cfg.Control.Auth.SecretEnv, cfg.Control.Auth.BearerTokenEnv,
		cfg.Control.CommandSecretEnv, cfg.Control.CommandSigningKeyIDEnv, cfg.Control.CommandPublicKeyEnv,
	}
}

func containsWebsiteLabel(labels []string) bool {
	for _, label := range labels {
		if strings.HasPrefix(label, "PPFLIGHT_BINDING_") {
			return true
		}
	}
	return false
}

func containsLabel(labels []string, wanted string) bool { return slices.Contains(labels, wanted) }
func isReserved(label string) bool {
	_, ok := reserved[label]
	return ok
}

// Summary returns only non-secret binding metadata suitable for diagnostics.
func Summary(secrets config.Secrets) string {
	return fmt.Sprintf("device=%s websiteEpoch=%d monitoringEpoch=%d", secrets.DeviceID, secrets.WebsiteTelemetry.CredentialEpoch, secrets.Monitoring.CredentialEpoch)
}
