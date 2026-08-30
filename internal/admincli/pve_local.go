package admincli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/ppflight/ppflight-agent/internal/bindstate"
	"github.com/ppflight/ppflight-agent/internal/config"
	"github.com/ppflight/ppflight-agent/internal/pve"
)

const localPVEEndpoint = config.LocalPVEEndpoint

type credentialProbe struct {
	Attempted        bool        `json:"attempted"`
	Succeeded        bool        `json:"succeeded"`
	CredentialReady  bool        `json:"credentialReady"`
	Code             string      `json:"code"`
	PermissionPaths  int         `json:"permissionPaths"`
	PermissionGrants int         `json:"permissionGrants"`
	Version          pve.Version `json:"version,omitempty"`
}

type localPVEStatus struct {
	PVESource           string          `json:"pveSource"`
	Endpoint            string          `json:"endpoint"`
	TLSServerName       string          `json:"tlsServerName"`
	Read                credentialProbe `json:"read"`
	Control             credentialProbe `json:"control"`
	ProductionExecution bool            `json:"productionExecution"`
	ProductionReady     bool            `json:"productionReady"`
}

type rawCredentialProbe struct {
	version     pve.Version
	permissions pve.Permissions
}

func (c *cli) pve(filename string, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.errOut, "pve 需要 prepare 或 status")
		return 2
	}
	if (args[0] == "prepare" || args[0] == "status") && !c.isRoot() {
		fmt.Fprintf(c.errOut, "pve %s 必须由 root 显式执行\n", args[0])
		return 1
	}
	cfg, ok := c.load(filename)
	if !ok {
		return 1
	}
	switch args[0] {
	case "status":
		if len(args) != 1 {
			fmt.Fprintln(c.errOut, "pve status 不接受额外参数")
			return 2
		}
		status, code := c.inspectLocalPVE(cfg)
		if printJSON(c.out, status) != 0 {
			return 1
		}
		if code != 0 && status.Read.Code == "PVE_ENV_UNAVAILABLE" {
			fmt.Fprintln(c.errOut, "未找到安全的本机 PVE token；请先以 root 运行 /usr/local/lib/ppflight-agent/create-pve-tokens.sh --write-env，再执行 ag-pve pve prepare。")
		}
		return code
	case "prepare":
		return c.preparePVE(filename, cfg, args[1:])
	default:
		fmt.Fprintf(c.errOut, "未知 pve 操作 %q\n", args[0])
		return 2
	}
}

func (c *cli) preparePVE(filename string, cfg config.Config, args []string) int {
	set := flag.NewFlagSet("pve prepare", flag.ContinueOnError)
	set.SetOutput(c.errOut)
	tlsServerName := set.String("tls-server-name", cfg.PVE.TLSServerName, "DNS name in the PVE API certificate (TCP remains 127.0.0.1)")
	caFile := set.String("ca-file", cfg.PVE.CAFile, "trusted PVE root CA PEM file")
	if err := set.Parse(args); err != nil || set.NArg() != 0 {
		return 2
	}
	if !c.isRoot() {
		fmt.Fprintln(c.errOut, "pve prepare 必须由 root 显式执行")
		return 1
	}
	if cfg.Mode != "test" || cfg.Control.ProductionExecution {
		fmt.Fprintln(c.errOut, "pve prepare 只允许保持 mode=test 且 productionExecution=false；未修改配置")
		return 1
	}
	serverName := *tlsServerName
	if serverName == "" {
		serverName = c.detectTrustedTLSServerName()
	}
	if err := pve.ValidateTLSServerName(serverName); err != nil {
		fmt.Fprintln(c.errOut, "无法确定安全的 PVE TLS 主机名；请用 --tls-server-name 指定证书中的 DNS 名称")
		return 1
	}
	if strings.TrimSpace(*caFile) == "" {
		fmt.Fprintln(c.errOut, "pve prepare 需要本机可信 PVE CA 文件；未修改配置")
		return 1
	}
	values, err := c.loadPVEEnvironment()
	if err != nil {
		fmt.Fprintln(c.errOut, "无法安全读取 root-only PVE token；未修改配置。请运行 /usr/local/lib/ppflight-agent/create-pve-tokens.sh --write-env")
		return 1
	}
	prepared := cfg
	prepared.PVE.Source = "api"
	prepared.PVE.Endpoint = localPVEEndpoint
	prepared.PVE.TokenIDEnv = config.PVEReadTokenIDEnv
	prepared.PVE.TokenSecretEnv = config.PVEReadTokenSecretEnv
	prepared.PVE.CAFile = strings.TrimSpace(*caFile)
	prepared.PVE.TLSServerName = serverName
	prepared.PVE.InsecureSkipTLS = false
	prepared.Control.PVETokenIDEnv = config.PVEControlTokenIDEnv
	prepared.Control.PVETokenSecretEnv = config.PVEControlTokenSecretEnv

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	read, err := c.runPVEProbe(ctx, pveConfig(prepared, values[config.PVEReadTokenIDEnv], values[config.PVEReadTokenSecretEnv]), true)
	if err != nil || read.version.Version == "" || permissionCounts(read.permissions).grants == 0 {
		fmt.Fprintln(c.errOut, "PVE 只读 token 的 /version 或 /access/permissions 探测失败；未修改配置")
		return 1
	}
	control, controlErr := c.runPVEProbe(ctx, pveConfig(prepared, values[config.PVEControlTokenIDEnv], values[config.PVEControlTokenSecretEnv]), false)
	controlCounts := permissionCounts(pve.Permissions{})
	if controlErr == nil {
		controlCounts = permissionCounts(control.permissions)
	}
	if code := c.save(filename, prepared); code != 0 {
		return code
	}
	fmt.Fprintf(c.out, "PVE 本地采集已就绪：version=%s readPermissionGrants=%d。\n", read.version.Version, permissionCounts(read.permissions).grants)
	if controlErr != nil || controlCounts.grants == 0 {
		fmt.Fprintln(c.out, "控制 token 尚未具备已验证的非空权限；不会声明 pve.control.v1，也不会开启生产写操作。")
	} else {
		fmt.Fprintf(c.out, "控制 token 权限探测成功（grants=%d），但 productionExecution 仍保持 false。\n", controlCounts.grants)
	}
	return 0
}

func (c *cli) inspectLocalPVE(cfg config.Config) (localPVEStatus, int) {
	status := localPVEStatus{
		PVESource: cfg.PVE.Source, Endpoint: cfg.PVE.Endpoint, TLSServerName: cfg.PVE.TLSServerName,
		ProductionExecution: cfg.Control.ProductionExecution,
		Read:                credentialProbe{Code: "NOT_PROBED"}, Control: credentialProbe{Code: "NOT_PROBED"},
	}
	if cfg.PVE.Source != "api" {
		status.Read.Code, status.Control.Code = "SOURCE_SIMULATOR", "SOURCE_SIMULATOR"
		return status, 1
	}
	if cfg.PVE.Endpoint != localPVEEndpoint || cfg.PVE.InsecureSkipTLS || pve.ValidateTLSServerName(cfg.PVE.TLSServerName) != nil {
		status.Read.Code, status.Control.Code = "UNSAFE_PVE_CONFIGURATION", "UNSAFE_PVE_CONFIGURATION"
		return status, 1
	}
	if !c.isRoot() {
		status.Read.Code, status.Control.Code = "ROOT_REQUIRED", "ROOT_REQUIRED"
		return status, 1
	}
	values, err := c.loadPVEEnvironment()
	if err != nil {
		status.Read.Code, status.Control.Code = "PVE_ENV_UNAVAILABLE", "PVE_ENV_UNAVAILABLE"
		return status, 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	status.Read = c.probeView(ctx, pveConfig(cfg, values[cfg.PVE.TokenIDEnv], values[cfg.PVE.TokenSecretEnv]), true)
	status.Control = c.probeView(ctx, pveConfig(cfg, values[cfg.Control.PVETokenIDEnv], values[cfg.Control.PVETokenSecretEnv]), false)
	_, websiteBindingErr := bindstate.Load(cfg.Runtime.StateDirectory)
	_, monitoringBindingErr := bindstate.LoadMonitoring(cfg.Runtime.StateDirectory)
	status.ProductionReady = cfg.Mode == "production" && cfg.Control.ProductionExecution && status.Read.CredentialReady && status.Control.CredentialReady && websiteBindingErr == nil && monitoringBindingErr == nil
	if !status.Read.CredentialReady || !status.Control.Succeeded {
		return status, 1
	}
	return status, 0
}

func (c *cli) probeView(ctx context.Context, cfg pve.Config, includeVersion bool) credentialProbe {
	view := credentialProbe{Attempted: true, Code: "PVE_PROBE_FAILED"}
	if cfg.TokenID == "" || cfg.TokenSecret == "" {
		view.Code = "PVE_CREDENTIAL_UNAVAILABLE"
		return view
	}
	result, err := c.runPVEProbe(ctx, cfg, includeVersion)
	if err != nil {
		return view
	}
	counts := permissionCounts(result.permissions)
	view.Succeeded, view.PermissionPaths, view.PermissionGrants, view.Version = true, counts.paths, counts.grants, result.version
	view.CredentialReady = counts.grants > 0 && (!includeVersion || result.version.Version != "")
	if view.CredentialReady {
		view.Code = "READY"
	} else {
		view.Code = "NO_EFFECTIVE_PERMISSIONS"
	}
	return view
}

type permissionSummary struct{ paths, grants int }

func permissionCounts(value pve.Permissions) permissionSummary {
	result := permissionSummary{}
	for _, privileges := range value.Paths {
		pathHasGrant := false
		for _, allowed := range privileges {
			if allowed > 0 {
				result.grants++
				pathHasGrant = true
			}
		}
		if pathHasGrant {
			result.paths++
		}
	}
	return result
}

func pveConfig(cfg config.Config, tokenID, tokenSecret string) pve.Config {
	return pve.Config{
		Endpoint: cfg.PVE.Endpoint, TokenID: tokenID, TokenSecret: tokenSecret,
		CAFile: cfg.PVE.CAFile, TLSServerName: cfg.PVE.TLSServerName, InsecureSkipTLS: false,
		Timeout: cfg.PVE.Timeout.Duration, MaxResponseBytes: cfg.PVE.MaxResponseBytes,
	}
}

func defaultPVEProbe(ctx context.Context, cfg pve.Config, includeVersion bool) (rawCredentialProbe, error) {
	client, err := pve.NewClient(cfg)
	if err != nil {
		return rawCredentialProbe{}, err
	}
	result := rawCredentialProbe{}
	if includeVersion {
		if result.version, err = client.Version(ctx); err != nil {
			return rawCredentialProbe{}, err
		}
	}
	if result.permissions, err = client.EffectivePermissions(ctx); err != nil {
		return rawCredentialProbe{}, err
	}
	return result, nil
}

func (c *cli) runPVEProbe(ctx context.Context, cfg pve.Config, includeVersion bool) (rawCredentialProbe, error) {
	if c.pveProbe != nil {
		return c.pveProbe(ctx, cfg, includeVersion)
	}
	return defaultPVEProbe(ctx, cfg, includeVersion)
}

func (c *cli) loadPVEEnvironment() (map[string]string, error) {
	if c.pveEnvironment != nil {
		return c.pveEnvironment(config.DefaultPVEEnvironmentFile)
	}
	return config.LoadPVEEnvironmentFile(config.DefaultPVEEnvironmentFile)
}

func (c *cli) isRoot() bool {
	if c.effectiveUID != nil {
		return c.effectiveUID() == 0
	}
	return platformEffectiveUID() == 0
}

func (c *cli) detectTrustedTLSServerName() string {
	if c.tlsServerName != nil {
		return strings.ToLower(strings.TrimSpace(c.tlsServerName()))
	}
	if runtime.GOOS == "windows" {
		return ""
	}
	for _, binary := range []string{"/bin/hostname", "/usr/bin/hostname"} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		output, err := exec.CommandContext(ctx, binary, "-f").Output()
		cancel()
		if err != nil || len(output) > 254 {
			continue
		}
		value := strings.ToLower(strings.TrimSpace(string(output)))
		if pve.ValidateTLSServerName(value) == nil {
			return value
		}
	}
	return ""
}

func (c *cli) websiteCapabilities(cfg config.Config, raw string, explicit bool) ([]string, error) {
	requested := splitCapabilities(raw)
	controlReady := false
	if !explicit {
		requested = []string{"pve.discovery.v1", "pve.telemetry.v1"}
		controlReady = c.controlCapabilityReady(cfg)
		if controlReady {
			requested = append(requested, "pve.control.v1")
		}
	}
	allowed := map[string]bool{"pve.discovery.v1": true, "pve.telemetry.v1": true, "pve.control.v1": true}
	seen := map[string]bool{}
	for _, capability := range requested {
		if !allowed[capability] || seen[capability] {
			return nil, errors.New("unsupported or duplicate website capability")
		}
		seen[capability] = true
	}
	if len(requested) == 0 {
		return nil, errors.New("website capability list is empty")
	}
	if seen["pve.control.v1"] {
		if explicit {
			controlReady = c.controlCapabilityReady(cfg)
		}
		if !controlReady {
			return nil, errors.New("pve.control.v1 requires a verified local control token with effective permissions")
		}
	}
	return requested, nil
}

func (c *cli) controlCapabilityReady(cfg config.Config) bool {
	if cfg.PVE.Source != "api" || cfg.PVE.Endpoint != localPVEEndpoint || cfg.PVE.InsecureSkipTLS || pve.ValidateTLSServerName(cfg.PVE.TLSServerName) != nil || !c.isRoot() {
		return false
	}
	values, err := c.loadPVEEnvironment()
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := c.runPVEProbe(ctx, pveConfig(cfg, values[cfg.Control.PVETokenIDEnv], values[cfg.Control.PVETokenSecretEnv]), false)
	return err == nil && permissionCounts(result.permissions).grants > 0
}

func (c *cli) menuPVEHeader(filename string) {
	cfg, err := config.LoadFile(filename)
	if err != nil {
		fmt.Fprintln(c.out, "PVE 本地接入：source=unknown read=not-ready control=not-ready（运行 ag-pve pve status）")
		return
	}
	status, _ := c.inspectLocalPVE(cfg)
	read, control := "not-ready", "not-ready"
	if status.Read.CredentialReady {
		read = "ready"
	}
	if status.Control.CredentialReady {
		control = "credential-ready/execution-disabled"
	}
	if status.ProductionExecution {
		control = "production-configured/not-ready"
		if status.ProductionReady {
			control = "production-ready"
		}
	}
	fmt.Fprintf(c.out, "PVE 本地接入：source=%s read=%s control=%s productionReady=%t\n", status.PVESource, read, control, status.ProductionReady)
}
