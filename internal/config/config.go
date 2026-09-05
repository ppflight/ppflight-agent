// Package config loads and validates the PPFlight Agent configuration.
// Secrets are referenced by environment-variable name and are never stored in
// the JSON configuration or returned by the status endpoint.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ppflight/ppflight-agent/internal/control"
	"github.com/ppflight/ppflight-agent/internal/netpolicy"
	"github.com/ppflight/ppflight-agent/internal/pve"
)

const (
	SchemaVersion    = 1
	maxConfigBytes   = 1 << 20
	LocalPVEEndpoint = "https://127.0.0.1:8006"
)

var safeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$`)

// Duration is a JSON string such as "30s" or "5m".
type Duration struct{ time.Duration }

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

func (d *Duration) UnmarshalJSON(value []byte) error {
	var text string
	if err := json.Unmarshal(value, &text); err != nil {
		return errors.New("duration must be a string such as 30s or 5m")
	}
	parsed, err := time.ParseDuration(text)
	if err != nil || parsed <= 0 {
		return fmt.Errorf("invalid positive duration %q", text)
	}
	d.Duration = parsed
	return nil
}

type Config struct {
	SchemaVersion int                `json:"schemaVersion"`
	Mode          string             `json:"mode"`
	Identity      IdentityConfig     `json:"identity"`
	Runtime       RuntimeConfig      `json:"runtime"`
	Collection    CollectionConfig   `json:"collection"`
	PVE           PVEConfig          `json:"pve"`
	Exporters     ExportersConfig    `json:"exporters"`
	Assignments   AssignmentsConfig  `json:"assignments"`
	Destinations  DestinationsConfig `json:"destinations"`
	Control       ControlConfig      `json:"control"`
}

type IdentityConfig struct {
	AgentRef     string `json:"agentRef"`
	CollectorRef string `json:"collectorRef"`
	SourceRef    string `json:"sourceRef"`
	ClusterRef   string `json:"clusterRef"`
	NodeRef      string `json:"nodeRef"`
	Site         string `json:"site"`
}

type RuntimeConfig struct {
	StateDirectory string   `json:"stateDirectory"`
	ListenAddress  string   `json:"listenAddress"`
	ShutdownGrace  Duration `json:"shutdownGrace"`
	LogLevel       string   `json:"logLevel"`
}

type CollectionConfig struct {
	SampleInterval          Duration `json:"sampleInterval"`
	MonitoringInterval      Duration `json:"monitoringInterval"`
	MeteringInterval        Duration `json:"meteringInterval"`
	InventoryInterval       Duration `json:"inventoryInterval"`
	GuestInterval           Duration `json:"guestInterval"`
	SMARTInterval           Duration `json:"smartInterval"`
	RequestConcurrency      int      `json:"requestConcurrency"`
	GuestRequestConcurrency int      `json:"guestRequestConcurrency"`
}

type PVEConfig struct {
	Source             string   `json:"source"`
	Endpoint           string   `json:"endpoint"`
	TokenIDEnv         string   `json:"tokenIdEnv"`
	TokenSecretEnv     string   `json:"tokenSecretEnv"`
	CAFile             string   `json:"caFile"`
	TLSServerName      string   `json:"tlsServerName"`
	InsecureSkipTLS    bool     `json:"insecureSkipTls"`
	Timeout            Duration `json:"timeout"`
	MaxResponseBytes   int64    `json:"maxResponseBytes"`
	LocalNode          string   `json:"localNode"`
	CollectClusterWide bool     `json:"collectClusterWide"`
}

type ExportersConfig struct {
	Node  ExporterConfig `json:"node"`
	SMART ExporterConfig `json:"smart"`
}

type ExporterConfig struct {
	Enabled          bool     `json:"enabled"`
	URL              string   `json:"url"`
	Timeout          Duration `json:"timeout"`
	MaxResponseBytes int64    `json:"maxResponseBytes"`
}

type AssignmentsConfig struct {
	File            string   `json:"file"`
	RefreshURL      string   `json:"refreshUrl"`
	RefreshInterval Duration `json:"refreshInterval"`
}

type DestinationsConfig struct {
	WebsiteMetering  DestinationConfig `json:"websiteMetering"`
	WebsiteTelemetry DestinationConfig `json:"websiteTelemetry"`
	Monitoring       DestinationConfig `json:"monitoring"`
	MonitoringAudit  DestinationConfig `json:"monitoringAudit"`
}

type DestinationConfig struct {
	Enabled              bool       `json:"enabled"`
	URL                  string     `json:"url"`
	Auth                 AuthConfig `json:"auth"`
	Timeout              Duration   `json:"timeout"`
	MaxResponseBytes     int64      `json:"maxResponseBytes"`
	MaxCompressedBytes   int64      `json:"maxCompressedBytes"`
	MaxUncompressedBytes int64      `json:"maxUncompressedBytes"`
	MaxQueueBytes        int64      `json:"maxQueueBytes"`
	Compression          string     `json:"compression"`
	PayloadFormat        string     `json:"payloadFormat"`
}

type AuthConfig struct {
	Mode           string `json:"mode"`
	KeyIDEnv       string `json:"keyIdEnv"`
	SecretEnv      string `json:"secretEnv"`
	BearerTokenEnv string `json:"bearerTokenEnv"`
}

type ControlConfig struct {
	Enabled        bool       `json:"enabled"`
	PollURL        string     `json:"pollUrl"`
	ResultURL      string     `json:"resultUrl"`
	Auth           AuthConfig `json:"auth"`
	PollInterval   Duration   `json:"pollInterval"`
	RequestTimeout Duration   `json:"requestTimeout"`
	// CommandSecretEnv is a legacy HMAC verifier accepted only in test mode.
	CommandSecretEnv       string   `json:"commandSecretEnv"`
	CommandSigningKeyIDEnv string   `json:"commandSigningKeyIdEnv"`
	CommandPublicKeyEnv    string   `json:"commandPublicKeyEnv"`
	PVETokenIDEnv          string   `json:"pveTokenIdEnv"`
	PVETokenSecretEnv      string   `json:"pveTokenSecretEnv"`
	MaxCommandsPerPoll     int      `json:"maxCommandsPerPoll"`
	AllowedActions         []string `json:"allowedActions"`
	ProductionExecution    bool     `json:"productionExecution"`
}

// Secrets is populated from environment variables after config validation.
type Secrets struct {
	PVETokenID             string
	PVETokenSecret         string
	WebsiteMetering        DestinationSecret
	WebsiteTelemetry       DestinationSecret
	Monitoring             DestinationSecret
	MonitoringAudit        DestinationSecret
	Assignments            DestinationSecret
	ControlAPI             DestinationSecret
	ControlReceipts        DestinationSecret
	ControlCommandSecret   []byte
	ControlSigningKeyID    string
	ControlPublicKey       []byte
	ControlPVETokenID      string
	ControlPVETokenSecret  string
	DeviceID               string
	WebsiteBindingID       string
	WebsiteCredentialEpoch uint64
	MonitoringAgentRef     string
	MonitoringBindingID    string
}

type DestinationSecret struct {
	KeyID           string
	Secret          []byte
	Bearer          string
	CredentialEpoch uint64
}

func defaults() Config {
	return Config{
		SchemaVersion: SchemaVersion,
		// A newly installed node is deliberately inert.  It becomes a running
		// collector only after the root-only AG readiness flow has verified the
		// local PVE API and changed this to the api source.
		Mode:     "production",
		Identity: IdentityConfig{NodeRef: "auto", Site: "primary"},
		Runtime: RuntimeConfig{
			StateDirectory: "/var/lib/ppflight-agent", ListenAddress: "127.0.0.1:9745",
			ShutdownGrace: Duration{15 * time.Second}, LogLevel: "info",
		},
		Collection: CollectionConfig{
			SampleInterval: Duration{10 * time.Second}, MonitoringInterval: Duration{30 * time.Second},
			MeteringInterval: Duration{time.Minute}, InventoryInterval: Duration{5 * time.Minute},
			GuestInterval: Duration{2 * time.Minute}, SMARTInterval: Duration{5 * time.Minute},
			RequestConcurrency: 8, GuestRequestConcurrency: 4,
		},
		PVE: PVEConfig{
			Source: "disabled", Endpoint: LocalPVEEndpoint, CAFile: "/etc/ppflight-agent/pve-root-ca.pem",
			Timeout: Duration{10 * time.Second}, MaxResponseBytes: 8 << 20, LocalNode: "auto",
		},
		Exporters: ExportersConfig{
			Node:  ExporterConfig{Enabled: true, URL: "http://127.0.0.1:9100/metrics", Timeout: Duration{5 * time.Second}, MaxResponseBytes: 16 << 20},
			SMART: ExporterConfig{Enabled: true, URL: "http://127.0.0.1:9633/metrics", Timeout: Duration{15 * time.Second}, MaxResponseBytes: 32 << 20},
		},
		Assignments: AssignmentsConfig{File: "/var/lib/ppflight-agent/assignments/assignments.json", RefreshInterval: Duration{5 * time.Minute}},
		Destinations: DestinationsConfig{
			WebsiteMetering:  defaultDestination(64<<20, "usage-v1"),
			WebsiteTelemetry: defaultDestination(256<<20, "telemetry-v1"),
			Monitoring:       defaultDestination(512<<20, "legacy-ingest-v1"),
			MonitoringAudit:  defaultDestination(512<<20, "audit-v1"),
		},
		Control: ControlConfig{
			Enabled: false, PollInterval: Duration{5 * time.Second}, RequestTimeout: Duration{10 * time.Second},
			MaxCommandsPerPoll: 20, ProductionExecution: false,
			Auth:           AuthConfig{Mode: "hmac-sha256"},
			AllowedActions: []string{"vm.start", "vm.shutdown", "vm.reboot"},
		},
	}
}

func defaultDestination(maxQueueBytes int64, payloadFormat string) DestinationConfig {
	return DestinationConfig{
		Timeout: Duration{15 * time.Second}, MaxResponseBytes: 2 << 20,
		MaxCompressedBytes: 64 << 20, MaxUncompressedBytes: 256 << 20,
		MaxQueueBytes: maxQueueBytes, Compression: "none", PayloadFormat: payloadFormat, Auth: AuthConfig{Mode: "hmac-sha256"},
	}
}

func LoadFile(filename string) (Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return Config{}, fmt.Errorf("open config: %w", err)
	}
	defer file.Close()
	limited := io.LimitReader(file, maxConfigBytes+1)
	contents, err := io.ReadAll(limited)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if len(contents) > maxConfigBytes {
		return Config{}, fmt.Errorf("config exceeds %d bytes", maxConfigBytes)
	}
	return Parse(contents)
}

func Parse(contents []byte) (Config, error) {
	result := defaults()
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := ensureEOF(decoder); err != nil {
		return Config{}, err
	}
	if err := result.Validate(); err != nil {
		return Config{}, err
	}
	return result, nil
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("config must contain one JSON object")
		}
		return fmt.Errorf("decode trailing config data: %w", err)
	}
	return nil
}

func (c Config) Validate() error {
	if c.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schemaVersion %d", c.SchemaVersion)
	}
	if c.Mode != "test" && c.Mode != "production" {
		return errors.New("mode must be test or production")
	}
	for label, value := range map[string]string{
		"identity.agentRef": c.Identity.AgentRef, "identity.collectorRef": c.Identity.CollectorRef,
		"identity.sourceRef": c.Identity.SourceRef, "identity.clusterRef": c.Identity.ClusterRef,
	} {
		if !safeID.MatchString(value) {
			return fmt.Errorf("%s must be 2-128 safe characters", label)
		}
	}
	if c.Identity.NodeRef != "auto" && !safeID.MatchString(c.Identity.NodeRef) {
		return errors.New("identity.nodeRef must be auto or a safe identifier")
	}
	if !isAbsoluteNonRootPath(c.Runtime.StateDirectory) {
		return errors.New("runtime.stateDirectory must be an absolute non-root path")
	}
	listenHost, _, err := net.SplitHostPort(c.Runtime.ListenAddress)
	if err != nil {
		return fmt.Errorf("runtime.listenAddress: %w", err)
	}
	if !isLoopback(listenHost) {
		return errors.New("runtime.listenAddress must bind to loopback")
	}
	if c.Runtime.LogLevel != "debug" && c.Runtime.LogLevel != "info" && c.Runtime.LogLevel != "warn" && c.Runtime.LogLevel != "error" {
		return errors.New("runtime.logLevel must be debug, info, warn, or error")
	}
	if c.Runtime.ShutdownGrace.Duration > 30*time.Second {
		return errors.New("runtime.shutdownGrace must not exceed the systemd 30s stop timeout")
	}
	if err := validateIntervals(c.Collection); err != nil {
		return err
	}
	if c.PVE.Source != "api" && c.PVE.Source != "disabled" {
		return errors.New("pve.source must be api or disabled")
	}
	if c.PVE.Source == "api" {
		if c.PVE.Endpoint != LocalPVEEndpoint {
			return fmt.Errorf("pve.endpoint must be exactly %s for api source", LocalPVEEndpoint)
		}
		if err := validateURL(c.PVE.Endpoint, c.Mode, true); err != nil {
			return fmt.Errorf("pve.endpoint: %w", err)
		}
		if c.PVE.TokenIDEnv == "" || c.PVE.TokenSecretEnv == "" {
			return errors.New("pve tokenIdEnv and tokenSecretEnv are required for api source")
		}
		if c.PVE.TokenIDEnv != PVEReadTokenIDEnv || c.PVE.TokenSecretEnv != PVEReadTokenSecretEnv {
			return fmt.Errorf("pve api source must use %s and %s from the root-only environment file", PVEReadTokenIDEnv, PVEReadTokenSecretEnv)
		}
		if c.PVE.Timeout.Duration < time.Second || c.PVE.Timeout.Duration > 30*time.Second {
			return errors.New("pve.timeout must be between 1s and 30s")
		}
		if c.PVE.MaxResponseBytes < 1<<10 || c.PVE.MaxResponseBytes > 32<<20 {
			return errors.New("pve.maxResponseBytes must be between 1 KiB and 32 MiB")
		}
		if c.PVE.InsecureSkipTLS {
			return errors.New("pve.insecureSkipTls is forbidden for api source")
		}
		if c.PVE.TLSServerName == "" {
			return errors.New("pve.tlsServerName is required for api source")
		}
		if err := pve.ValidateTLSServerName(c.PVE.TLSServerName); err != nil {
			return fmt.Errorf("pve.tlsServerName: %w", err)
		}
	}
	if c.PVE.Source == "api" && c.Mode == "production" && (c.PVE.LocalNode == "" || c.PVE.LocalNode == "auto") {
		return errors.New("pve.localNode must be explicit in production to avoid hostname/PVE-node mismatches")
	}
	for label, exporter := range map[string]ExporterConfig{"exporters.node": c.Exporters.Node, "exporters.smart": c.Exporters.SMART} {
		if !exporter.Enabled {
			continue
		}
		if err := validateLoopbackURL(exporter.URL); err != nil {
			return fmt.Errorf("%s.url: %w", label, err)
		}
		if exporter.MaxResponseBytes < 1024 || exporter.MaxResponseBytes > 64<<20 {
			return fmt.Errorf("%s.maxResponseBytes must be between 1 KiB and 64 MiB", label)
		}
		if exporter.Timeout.Duration < time.Second || exporter.Timeout.Duration > 30*time.Second {
			return fmt.Errorf("%s.timeout must be between 1s and 30s", label)
		}
	}
	for label, destination := range map[string]DestinationConfig{
		"destinations.websiteMetering":  c.Destinations.WebsiteMetering,
		"destinations.websiteTelemetry": c.Destinations.WebsiteTelemetry,
		"destinations.monitoring":       c.Destinations.Monitoring,
		"destinations.monitoringAudit":  c.Destinations.MonitoringAudit,
	} {
		if err := validateDestination(label, destination, c.Mode); err != nil {
			return err
		}
	}
	if c.Control.Enabled {
		if c.Control.MaxCommandsPerPoll < 1 || c.Control.MaxCommandsPerPoll > 100 {
			return errors.New("control.maxCommandsPerPoll must be 1-100")
		}
		if c.Control.ProductionExecution && c.Mode != "production" {
			return errors.New("control.productionExecution requires production mode")
		}
		if c.Control.ProductionExecution && c.PVE.Source != "api" {
			return errors.New("control.productionExecution requires pve.source=api")
		}
		if c.Control.ProductionExecution && (!c.Destinations.Monitoring.Enabled || !c.Destinations.MonitoringAudit.Enabled) {
			return errors.New("control.productionExecution requires bound monitoring telemetry and audit destinations")
		}
		configured := c.Control.PollURL != "" || c.Control.ResultURL != ""
		if configured {
			if c.Control.PollURL == "" || c.Control.ResultURL == "" {
				return errors.New("control.pollUrl and resultUrl must be configured together")
			}
			if err := validateURL(c.Control.PollURL, c.Mode, false); err != nil {
				return fmt.Errorf("control.pollUrl: %w", err)
			}
			if err := validateURL(c.Control.ResultURL, c.Mode, false); err != nil {
				return fmt.Errorf("control.resultUrl: %w", err)
			}
			if c.Mode == "production" && (c.Control.CommandSigningKeyIDEnv == "" || c.Control.CommandPublicKeyEnv == "") {
				return errors.New("production control requires commandSigningKeyIdEnv and commandPublicKeyEnv")
			}
			if c.Mode == "test" && c.Control.CommandSecretEnv == "" && (c.Control.CommandSigningKeyIDEnv == "" || c.Control.CommandPublicKeyEnv == "") {
				return errors.New("test control requires a legacy commandSecretEnv or Ed25519 verification key")
			}
			if c.Control.Auth.Mode != "hmac-sha256" && c.Control.Auth.Mode != "bearer" && !(c.Mode == "test" && c.Control.Auth.Mode == "none") {
				return errors.New("control API authentication mode is unsupported")
			}
			if c.Control.Auth.Mode == "hmac-sha256" && (c.Control.Auth.KeyIDEnv == "" || c.Control.Auth.SecretEnv == "") {
				return errors.New("control HMAC auth requires keyIdEnv and secretEnv")
			}
			if c.Control.Auth.Mode == "bearer" && c.Control.Auth.BearerTokenEnv == "" {
				return errors.New("control bearer auth requires bearerTokenEnv")
			}
			if c.Mode == "production" && c.Control.Auth.Mode != "hmac-sha256" {
				return errors.New("control production API requires hmac-sha256 auth")
			}
		}
		if c.Mode == "production" && !configured {
			return errors.New("enabled control requires pollUrl and resultUrl in production")
		}
		if c.Control.ProductionExecution && (c.Control.PVETokenIDEnv == "" || c.Control.PVETokenSecretEnv == "") {
			return errors.New("production control execution requires separate PVE token environment names")
		}
		if c.Control.ProductionExecution && (c.Control.PVETokenIDEnv != PVEControlTokenIDEnv || c.Control.PVETokenSecretEnv != PVEControlTokenSecretEnv) {
			return fmt.Errorf("production control execution must use %s and %s from the root-only environment file", PVEControlTokenIDEnv, PVEControlTokenSecretEnv)
		}
		if err := validateActions(c.Control.AllowedActions); err != nil {
			return err
		}
	}
	if c.Assignments.RefreshURL != "" {
		if err := validateURL(c.Assignments.RefreshURL, c.Mode, false); err != nil {
			return fmt.Errorf("assignments.refreshUrl: %w", err)
		}
	}
	return nil
}

// isAbsoluteNonRootPath accepts the POSIX paths used by Linux deployments even
// when validation runs on a Windows development machine. Native Windows paths
// remain supported when the agent is tested there.
func isAbsoluteNonRootPath(value string) bool {
	if value == "" {
		return false
	}
	if strings.HasPrefix(value, "/") {
		return path.Clean(value) != "/"
	}
	if !filepath.IsAbs(value) {
		return false
	}
	clean := filepath.Clean(value)
	volume := filepath.VolumeName(clean)
	return clean != volume+string(filepath.Separator) && clean != string(filepath.Separator)
}

func validateIntervals(c CollectionConfig) error {
	for label, value := range map[string]time.Duration{
		"sampleInterval": c.SampleInterval.Duration, "monitoringInterval": c.MonitoringInterval.Duration,
		"meteringInterval": c.MeteringInterval.Duration, "inventoryInterval": c.InventoryInterval.Duration,
		"guestInterval": c.GuestInterval.Duration, "smartInterval": c.SMARTInterval.Duration,
	} {
		if value < time.Second || value > 24*time.Hour {
			return fmt.Errorf("collection.%s must be between 1s and 24h", label)
		}
	}
	if c.RequestConcurrency < 1 || c.RequestConcurrency > 64 || c.GuestRequestConcurrency < 1 || c.GuestRequestConcurrency > 32 {
		return errors.New("collection request concurrency is outside the safe range")
	}
	return nil
}

func validateDestination(label string, d DestinationConfig, mode string) error {
	if !d.Enabled {
		return nil
	}
	if err := validateURL(d.URL, mode, false); err != nil {
		return fmt.Errorf("%s.url: %w", label, err)
	}
	if d.MaxQueueBytes < 1<<20 || d.MaxQueueBytes > 64<<30 {
		return fmt.Errorf("%s.maxQueueBytes must be between 1 MiB and 64 GiB", label)
	}
	if d.MaxResponseBytes < 1<<10 || d.MaxResponseBytes > 8<<20 {
		return fmt.Errorf("%s.maxResponseBytes must be between 1 KiB and 8 MiB", label)
	}
	if d.MaxCompressedBytes < 1<<20 || d.MaxCompressedBytes > 64<<20 || d.MaxUncompressedBytes < d.MaxCompressedBytes || d.MaxUncompressedBytes > 256<<20 {
		return fmt.Errorf("%s request size limits are invalid", label)
	}
	if d.Auth.Mode != "hmac-sha256" && d.Auth.Mode != "bearer" && !(mode == "test" && d.Auth.Mode == "none") {
		return fmt.Errorf("%s.auth.mode is unsupported", label)
	}
	if d.Auth.Mode == "hmac-sha256" && (d.Auth.KeyIDEnv == "" || d.Auth.SecretEnv == "") {
		return fmt.Errorf("%s HMAC auth requires keyIdEnv and secretEnv", label)
	}
	if d.Auth.Mode == "bearer" && d.Auth.BearerTokenEnv == "" {
		return fmt.Errorf("%s bearer auth requires bearerTokenEnv", label)
	}
	if d.Compression != "none" && d.Compression != "gzip" {
		return fmt.Errorf("%s.compression must be none or gzip", label)
	}
	validFormat := label == "destinations.websiteMetering" && d.PayloadFormat == "usage-v1" ||
		label == "destinations.websiteTelemetry" && d.PayloadFormat == "telemetry-v1" ||
		label == "destinations.monitoring" && (d.PayloadFormat == "legacy-ingest-v1" || d.PayloadFormat == "telemetry-v1") ||
		label == "destinations.monitoringAudit" && d.PayloadFormat == "audit-v1"
	if !validFormat {
		return fmt.Errorf("%s.payloadFormat is unsupported", label)
	}
	return nil
}

func validateURL(value, mode string, allowPVEHTTP bool) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || netpolicy.ValidateIPv4URL(parsed) != nil {
		return errors.New("invalid URL")
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return errors.New("URL cannot contain credentials or fragments")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme != "http" {
		return errors.New("URL must use HTTPS")
	}
	if mode != "test" || (!allowPVEHTTP && !isLoopback(parsed.Hostname())) || (allowPVEHTTP && !isLoopback(parsed.Hostname())) {
		return errors.New("plain HTTP is allowed only for loopback in test mode")
	}
	return nil
}

func validateLoopbackURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || netpolicy.ValidateIPv4URL(parsed) != nil || !isLoopback(parsed.Hostname()) {
		return errors.New("exporter must use a loopback HTTP URL")
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return errors.New("exporter URL cannot contain credentials or fragments")
	}
	return nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() != nil && ip.IsLoopback()
}

func validateActions(actions []string) error {
	if len(actions) == 0 || len(actions) > 64 {
		return errors.New("control.allowedActions must contain 1-64 actions")
	}
	seen := make(map[string]bool, len(actions))
	for _, action := range actions {
		if !control.KnownAction(action) || seen[action] {
			return fmt.Errorf("invalid or duplicate control action %q", action)
		}
		seen[action] = true
	}
	return nil
}

func (c Config) ResolveSecrets(lookup func(string) (string, bool)) (Secrets, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	result := Secrets{}
	var err error
	if c.PVE.Source == "api" {
		if result.PVETokenID, err = requiredEnv(lookup, c.PVE.TokenIDEnv); err != nil {
			return Secrets{}, err
		}
		if result.PVETokenSecret, err = requiredEnv(lookup, c.PVE.TokenSecretEnv); err != nil {
			return Secrets{}, err
		}
	}
	for item, target := range map[*DestinationConfig]*DestinationSecret{
		&c.Destinations.WebsiteMetering:  &result.WebsiteMetering,
		&c.Destinations.WebsiteTelemetry: &result.WebsiteTelemetry,
		&c.Destinations.Monitoring:       &result.Monitoring,
		&c.Destinations.MonitoringAudit:  &result.MonitoringAudit,
	} {
		if !item.Enabled {
			continue
		}
		resolved, resolveErr := resolveDestination(*item, lookup)
		if resolveErr != nil {
			return Secrets{}, resolveErr
		}
		*target = resolved
	}
	if c.Control.Enabled && c.Control.PollURL != "" && c.Control.CommandSecretEnv != "" {
		value, resolveErr := requiredEnv(lookup, c.Control.CommandSecretEnv)
		if resolveErr != nil {
			return Secrets{}, resolveErr
		}
		result.ControlCommandSecret = []byte(value)
	}
	if c.Control.Enabled && c.Control.PollURL != "" && c.Control.CommandSigningKeyIDEnv != "" {
		if result.ControlSigningKeyID, err = requiredEnv(lookup, c.Control.CommandSigningKeyIDEnv); err != nil {
			return Secrets{}, err
		}
	}
	if c.Control.Enabled && c.Control.PollURL != "" && c.Control.CommandPublicKeyEnv != "" {
		value, resolveErr := requiredEnv(lookup, c.Control.CommandPublicKeyEnv)
		if resolveErr != nil {
			return Secrets{}, resolveErr
		}
		result.ControlPublicKey = []byte(value)
	}
	if c.Control.Enabled && c.Control.PollURL != "" {
		controlDestination := DestinationConfig{Enabled: true, Auth: c.Control.Auth}
		resolved, resolveErr := resolveDestination(controlDestination, lookup)
		if resolveErr != nil {
			return Secrets{}, resolveErr
		}
		result.ControlAPI = resolved
	}
	if c.Control.Enabled && c.Control.ProductionExecution {
		if result.ControlPVETokenID, err = requiredEnv(lookup, c.Control.PVETokenIDEnv); err != nil {
			return Secrets{}, err
		}
		if result.ControlPVETokenSecret, err = requiredEnv(lookup, c.Control.PVETokenSecretEnv); err != nil {
			return Secrets{}, err
		}
		if result.ControlPVETokenID == result.PVETokenID {
			return Secrets{}, errors.New("control PVE token must be distinct from the collection token")
		}
	}
	return result, nil
}

func resolveDestination(c DestinationConfig, lookup func(string) (string, bool)) (DestinationSecret, error) {
	result := DestinationSecret{}
	var err error
	switch c.Auth.Mode {
	case "hmac-sha256":
		if result.KeyID, err = requiredEnv(lookup, c.Auth.KeyIDEnv); err != nil {
			return result, err
		}
		value, envErr := requiredEnv(lookup, c.Auth.SecretEnv)
		if envErr != nil {
			return result, envErr
		}
		result.Secret = []byte(value)
	case "bearer":
		if result.Bearer, err = requiredEnv(lookup, c.Auth.BearerTokenEnv); err != nil {
			return result, err
		}
	}
	return result, nil
}

func requiredEnv(lookup func(string) (string, bool), name string) (string, error) {
	value, ok := lookup(name)
	if !ok || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("required environment variable %s is not set", name)
	}
	return value, nil
}
