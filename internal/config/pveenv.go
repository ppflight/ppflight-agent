package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strings"
)

const (
	// DefaultPVEEnvironmentFile is consumed by systemd as an EnvironmentFile.
	// Direct root invocations use the same file through the no-follow reader in
	// this package; its contents are never copied into agent.yaml or output.
	DefaultPVEEnvironmentFile = "/etc/ppflight-agent/agent.env"
	maxPVEEnvironmentBytes    = 16 << 10

	PVEReadTokenIDEnv        = "PVE_READ_TOKEN_ID"
	PVEReadTokenSecretEnv    = "PVE_READ_TOKEN_SECRET"
	PVEControlTokenIDEnv     = "PVE_CONTROL_TOKEN_ID"
	PVEControlTokenSecretEnv = "PVE_CONTROL_TOKEN_SECRET"
)

var (
	pveEnvironmentKeys = map[string]bool{
		PVEReadTokenIDEnv: true, PVEReadTokenSecretEnv: true,
		PVEControlTokenIDEnv: true, PVEControlTokenSecretEnv: true,
	}
	pveTokenID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}@[A-Za-z0-9][A-Za-z0-9._-]{0,63}![A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	pveSecret  = regexp.MustCompile(`^[A-Za-z0-9._:+/@=-]{8,512}$`)
)

// secureEnvironmentFile is the result of opening and fstat'ing a file through
// the platform no-follow implementation.  Keeping validation independent of
// the syscall makes all security checks testable on non-Linux development
// hosts without weakening the Linux implementation.
type secureEnvironmentFile struct {
	contents  []byte
	mode      fs.FileMode
	ownerUID  uint32
	linkCount uint64
	regular   bool
}

// LoadPVEEnvironmentFile securely reads the root-only PVE credential file.
// Linux opens it with O_NOFOLLOW and validates the opened descriptor. Other
// platforms fail closed; tests can exercise parsePVEEnvironment directly.
func LoadPVEEnvironmentFile(filename string) (map[string]string, error) {
	opened, err := openSecurePVEEnvironment(filename, maxPVEEnvironmentBytes)
	if err != nil {
		return nil, err
	}
	if err := validateSecurePVEEnvironment(opened); err != nil {
		return nil, err
	}
	return parsePVEEnvironment(opened.contents)
}

func validateSecurePVEEnvironment(file secureEnvironmentFile) error {
	if !file.regular {
		return errors.New("PVE environment file is not a regular file")
	}
	if file.ownerUID != 0 {
		return errors.New("PVE environment file is not owned by root")
	}
	if file.mode.Perm() != 0o600 {
		return errors.New("PVE environment file permissions must be 0600")
	}
	if file.linkCount != 1 {
		return errors.New("PVE environment file must have exactly one hard link")
	}
	if len(file.contents) == 0 || len(file.contents) > maxPVEEnvironmentBytes {
		return errors.New("PVE environment file has an invalid size")
	}
	return nil
}

func parsePVEEnvironment(contents []byte) (map[string]string, error) {
	if len(contents) == 0 || len(contents) > maxPVEEnvironmentBytes || bytes.IndexByte(contents, 0) >= 0 {
		return nil, errors.New("PVE environment file has invalid contents")
	}
	result := make(map[string]string, len(pveEnvironmentKeys))
	lines := strings.Split(strings.ReplaceAll(string(contents), "\r\n", "\n"), "\n")
	for lineNumber, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.TrimSpace(line) != line {
			return nil, fmt.Errorf("PVE environment line %d has surrounding whitespace", lineNumber+1)
		}
		name, value, found := strings.Cut(line, "=")
		if !found || !pveEnvironmentKeys[name] || value == "" {
			return nil, fmt.Errorf("PVE environment line %d is not an allowed assignment", lineNumber+1)
		}
		if _, duplicate := result[name]; duplicate {
			return nil, fmt.Errorf("PVE environment variable %s is duplicated", name)
		}
		if strings.HasSuffix(name, "_TOKEN_ID") {
			if !pveTokenID.MatchString(value) {
				return nil, fmt.Errorf("PVE environment variable %s has an invalid token ID", name)
			}
		} else if !pveSecret.MatchString(value) {
			return nil, fmt.Errorf("PVE environment variable %s has an invalid secret encoding", name)
		}
		result[name] = value
	}
	for name := range pveEnvironmentKeys {
		if result[name] == "" {
			return nil, fmt.Errorf("PVE environment variable %s is missing", name)
		}
	}
	return result, nil
}

// ResolvePVEEnvironmentLookup returns a process-local lookup overlay for
// direct invocations. If all required values are already present (as they are
// when systemd PID 1 loaded EnvironmentFile), the service account never needs
// read access to the root-only file. When fallback is needed, every PVE value
// comes from one validated file so ambient and file credentials cannot mix.
func ResolvePVEEnvironmentLookup(cfg Config, base func(string) (string, bool)) (func(string) (string, bool), error) {
	return resolvePVEEnvironmentLookup(cfg, base, pveEnvironmentRunningAsRoot(), LoadPVEEnvironmentFile)
}

func resolvePVEEnvironmentLookup(cfg Config, base func(string) (string, bool), runningAsRoot bool, load func(string) (map[string]string, error)) (func(string) (string, bool), error) {
	if base == nil {
		return nil, errors.New("environment lookup is required")
	}
	if load == nil {
		return nil, errors.New("PVE environment loader is required")
	}
	required := []string{}
	if cfg.PVE.Source == "api" {
		required = append(required, cfg.PVE.TokenIDEnv, cfg.PVE.TokenSecretEnv)
	}
	if cfg.Control.Enabled && cfg.Control.ProductionExecution {
		required = append(required, cfg.Control.PVETokenIDEnv, cfg.Control.PVETokenSecretEnv)
	}
	if len(required) == 0 {
		return base, nil
	}
	// A direct root invocation always prefers the descriptor-validated file,
	// even if sudo preserved ambient PVE_* variables. A non-root systemd
	// service cannot read 0600 by design and uses only the complete environment
	// that PID 1 supplied; partial sources are never mixed.
	if !runningAsRoot {
		if environmentHasAll(base, required) {
			return base, nil
		}
		return nil, errors.New("required PVE environment was not supplied by the service manager")
	}
	values, err := load(DefaultPVEEnvironmentFile)
	if err != nil {
		return nil, fmt.Errorf("load root-only PVE environment: %w", err)
	}
	return OverlayPVEEnvironment(base, values), nil
}

func environmentHasAll(lookup func(string) (string, bool), names []string) bool {
	for _, name := range names {
		value, ok := lookup(name)
		if name == "" || !ok || strings.TrimSpace(value) == "" {
			return false
		}
	}
	return true
}

// OverlayPVEEnvironment gives the validated PVE file priority only for the
// four fixed PVE names. It does not mutate the parent process environment and
// does not expose values to configuration, logs, argv, or child processes.
func OverlayPVEEnvironment(base func(string) (string, bool), values map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		if pveEnvironmentKeys[name] {
			value, ok := values[name]
			return value, ok
		}
		return base(name)
	}
}
