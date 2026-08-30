package admincli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/ppflight/ppflight-agent/internal/bindstate"
	"github.com/ppflight/ppflight-agent/internal/config"
	"github.com/ppflight/ppflight-agent/internal/fsutil"
	"github.com/ppflight/ppflight-agent/internal/pve"
)

const (
	localPVEEndpoint   = config.LocalPVEEndpoint
	pveBootstrapHelper = "/usr/local/lib/ppflight-agent/create-pve-tokens.sh"
	managedPVECAFile   = "/etc/ppflight-agent/pve-root-ca.pem"
	maxPVECABytes      = 1 << 20
)

var localPVENodeNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

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
	version            pve.Version
	permissions        pve.Permissions
	nodes              []string
	nodeStatusVerified bool
	storageVerified    bool
}

var requiredPVEReadPrivileges = []string{"Sys.Audit", "VM.Audit", "VM.Monitor", "Datastore.Audit"}

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
	caFile := set.String("ca-file", cfg.PVE.CAFile, "managed PVE root CA PEM file (must be /etc/ppflight-agent/pve-root-ca.pem)")
	if err := set.Parse(args); err != nil || set.NArg() != 0 {
		return 2
	}
	latest, transaction, err := c.acquireStableMutationTransaction(filename, cfg.Runtime.StateDirectory)
	if err != nil {
		fmt.Fprintln(c.errOut, "PVE 配置未修改：另一个 Agent 管理事务正在执行，或存在未完成的官网/监控绑定事务")
		return 1
	}
	defer transaction.Close()
	cfg = latest
	// A busy node can need more than one inventory period before the first
	// authoritative collection finishes. Do not report a healthy real PVE as
	// failed merely because a large guest/storage inventory takes longer than
	// the old five-minute bootstrap window.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	result, err := c.prepareRealPVE(ctx, filename, cfg, strings.TrimSpace(*tlsServerName), strings.TrimSpace(*caFile))
	if err != nil {
		var activationErr *realPVEActivationError
		if errors.As(err, &activationErr) && activationErr.localReady {
			fmt.Fprintln(c.errOut, "PVE_REAL_UPLOAD_UNCONFIRMED: 本机真实 PVE 采集已启用，但官网或监控 telemetry 尚未确认接收；不会回退并继续上报模拟数据，请检查 AG 通信状态后重试")
			return 1
		}
		fmt.Fprintln(c.errOut, "PVE_REAL_READINESS_FAILED: 本机 PVE API、TLS、只读权限或 Agent 真实采集回验失败；未报告就绪")
		return 1
	}
	fmt.Fprintf(c.out, "PVE 真实采集已就绪并自动生效：mode=production source=api node=%s version=%s readPermissionGrants=%d，%s active。\n", result.Config.PVE.LocalNode, result.Version, result.ReadPermissionGrants, agentServiceUnit)
	if result.ControlPermissionGrants == 0 {
		fmt.Fprintln(c.out, "控制 token 尚未授予资源范围；真实监控已启用，但 productionExecution 保持 false，VPS 写操作不会越权执行。")
	} else {
		fmt.Fprintf(c.out, "控制 token 已验证 %d 项权限；productionExecution 仍保持原有显式安全开关。\n", result.ControlPermissionGrants)
	}
	if result.ConfigBackup != "" {
		fmt.Fprintf(c.out, "配置备份=%s\n", result.ConfigBackup)
	}
	return 0
}

type realPVEPreparation struct {
	Config                  config.Config
	Version                 string
	ReadPermissionGrants    int
	ControlPermissionGrants int
	ConfigBackup            string
}

func (c *cli) ensureBindingPVEReady(ctx context.Context, filename string, cfg config.Config) (config.Config, error) {
	if c.bindingPVE != nil {
		return c.bindingPVE(ctx, filename, cfg)
	}
	result, err := c.prepareRealPVEWithRequirement(ctx, filename, cfg, "", "", false)
	if err != nil {
		return config.Config{}, err
	}
	return result.Config, nil
}

func (c *cli) prepareRealPVE(ctx context.Context, filename string, cfg config.Config, requestedServerName, requestedCAFile string) (realPVEPreparation, error) {
	return c.prepareRealPVEWithRequirement(ctx, filename, cfg, requestedServerName, requestedCAFile, true)
}

func (c *cli) prepareRealPVEWithRequirement(ctx context.Context, filename string, cfg config.Config, requestedServerName, requestedCAFile string, requireDeliveries bool) (realPVEPreparation, error) {
	if !c.isRoot() {
		return realPVEPreparation{}, errors.New("real PVE preparation requires root")
	}
	// Complete every deterministic, non-mutating host/TLS/configuration check
	// before creating PVE users, roles, ACLs or one-time token secrets.
	serverName := strings.TrimSpace(requestedServerName)
	if serverName == "" {
		serverName = strings.TrimSpace(cfg.PVE.TLSServerName)
	}
	if serverName == "" || strings.HasSuffix(strings.ToLower(serverName), ".invalid") {
		serverName = c.detectTrustedTLSServerName()
	}
	if err := pve.ValidateTLSServerName(serverName); err != nil || strings.EqualFold(serverName, "localhost") {
		return realPVEPreparation{}, errors.New("cannot determine a safe PVE TLS server name")
	}
	caFile := strings.TrimSpace(requestedCAFile)
	if caFile == "" {
		caFile = strings.TrimSpace(cfg.PVE.CAFile)
	}
	if !isManagedPVECAPath(caFile) {
		return realPVEPreparation{}, fmt.Errorf("PVE CA file must be the managed service-readable path %s", managedPVECAFile)
	}
	localNode, err := c.localPVENodeName()
	if err != nil {
		return realPVEPreparation{}, err
	}
	prepared := cfg
	prepared.Mode = "production"
	prepared.PVE.Source = "api"
	prepared.PVE.Endpoint = localPVEEndpoint
	prepared.PVE.TokenIDEnv = config.PVEReadTokenIDEnv
	prepared.PVE.TokenSecretEnv = config.PVEReadTokenSecretEnv
	prepared.PVE.CAFile = caFile
	prepared.PVE.TLSServerName = serverName
	prepared.PVE.InsecureSkipTLS = false
	prepared.PVE.LocalNode = localNode
	prepared.Control.PVETokenIDEnv = config.PVEControlTokenIDEnv
	prepared.Control.PVETokenSecretEnv = config.PVEControlTokenSecretEnv
	if prepared.Control.PollURL == "" && prepared.Control.ResultURL == "" {
		prepared.Control.Enabled = false
		prepared.Control.ProductionExecution = false
	}
	if err := prepared.Validate(); err != nil {
		return realPVEPreparation{}, errors.New("prepared real PVE configuration is invalid")
	}
	localVersionContext, cancelVersion := context.WithTimeout(ctx, 3*time.Second)
	localVersion, versionErr := c.localPVEVersion(localVersionContext)
	cancelVersion()
	if versionErr != nil {
		return realPVEPreparation{}, errors.New("local PVE version discovery failed")
	}
	if err := c.preflightLocalPVETLS(ctx, serverName, caFile); err != nil {
		return realPVEPreparation{}, errors.New("managed PVE CA or TLS identity preflight failed")
	}
	values, err := c.loadPVEEnvironment()
	if err != nil {
		if err := c.bootstrapPVECredentials(ctx); err != nil {
			return realPVEPreparation{}, errors.New("bootstrap dedicated PVE credentials")
		}
		values, err = c.loadPVEEnvironment()
		if err != nil {
			return realPVEPreparation{}, errors.New("reload bootstrapped PVE credentials")
		}
	}
	read, err := c.runPVEProbe(ctx, pveConfig(prepared, values[config.PVEReadTokenIDEnv], values[config.PVEReadTokenSecretEnv]), true, localNode)
	readCounts := permissionCounts(read.permissions)
	if err != nil || read.version.Version == "" || !hasRequiredPVEReadPermissions(read.permissions) || !containsLocalPVENode(read.nodes, localNode) || !read.nodeStatusVerified || !read.storageVerified {
		return realPVEPreparation{}, errors.New("PVE read probe did not verify required audit privileges, local node status, and storage inventory")
	}
	if localVersion != read.version.Version {
		return realPVEPreparation{}, errors.New("local and API PVE versions do not match")
	}
	controlGrants := 0
	if control, controlErr := c.runPVEProbe(ctx, pveConfig(prepared, values[config.PVEControlTokenIDEnv], values[config.PVEControlTokenSecretEnv]), false, ""); controlErr == nil {
		controlGrants = permissionCounts(control.permissions).grants
	}
	backup := ""
	changed := !reflect.DeepEqual(cfg, prepared)
	if changed {
		backup, err = atomicUpdate(filename, prepared)
		if err != nil {
			return realPVEPreparation{}, errors.New("persist real PVE configuration")
		}
	}
	var activateErr error
	if requireDeliveries {
		activateErr = c.activateRealPVE(ctx, prepared)
	} else {
		activateErr = c.activateRealPVELocal(ctx, prepared)
	}
	if activateErr != nil {
		var readinessErr *realPVEActivationError
		if errors.As(activateErr, &readinessErr) && readinessErr.localReady {
			// Keep the authoritative production/api configuration: reverting to a
			// disabled source would stop authoritative collection. The next retry
			// only has to confirm the already-durable delivery channels.
			return realPVEPreparation{}, fmt.Errorf("real PVE collection is active but telemetry delivery is unconfirmed: %w", activateErr)
		}
		_, websiteBindingErr := bindstate.Load(cfg.Runtime.StateDirectory)
		_, monitoringBindingErr := bindstate.LoadMonitoring(cfg.Runtime.StateDirectory)
		if changed && cfg.PVE.Source != "api" && (websiteBindingErr == nil || monitoringBindingErr == nil) {
			// A released Agent cannot run a bound non-API source. Keep the
			// authoritative API configuration fail-closed so a failed activation
			// can never resurrect synthetic/disabled collection after an upgrade.
			return realPVEPreparation{}, errors.New("activate real PVE collection on previously bound node; production API configuration preserved")
		}
		var rollbackErr error
		if changed {
			_, configRollbackErr := atomicUpdate(filename, cfg)
			var lifecycleErr error
			if cfg.PVE.Source == "api" {
				recoveryContext, cancelRecovery := context.WithTimeout(context.Background(), 15*time.Minute)
				lifecycleErr = c.recoverAgentBinding(recoveryContext, cfg)
				cancelRecovery()
			} else {
				// The API process may already be running even though the original
				// configuration was disabled. After restoring that disabled file,
				// explicitly stop and verify the unit so it cannot keep collecting
				// with the transient API credentials in memory.
				stopContext, cancelStop := context.WithTimeout(context.Background(), 30*time.Second)
				lifecycleErr = c.quiesceAgentForBinding(stopContext)
				cancelStop()
			}
			rollbackErr = errors.Join(configRollbackErr, lifecycleErr)
		}
		if rollbackErr != nil {
			return realPVEPreparation{}, errors.New("activate real PVE collection; automatic rollback was not fully confirmed")
		}
		return realPVEPreparation{}, errors.New("activate real PVE collection")
	}
	return realPVEPreparation{Config: prepared, Version: read.version.Version, ReadPermissionGrants: readCounts.grants, ControlPermissionGrants: controlGrants, ConfigBackup: backup}, nil
}

func (c *cli) bootstrapPVECredentials(ctx context.Context) error {
	if c.pveBootstrap != nil {
		return c.pveBootstrap(ctx)
	}
	// This helper mutates PVE RBAC and owns compensating rollback traps. Do not
	// wrap it in CommandContext: an abrupt SIGKILL at a caller deadline can
	// bypass those traps and strand an unrecoverable one-time token secret.
	command := exec.Command(pveBootstrapHelper, "--write-env", config.DefaultPVEEnvironmentFile)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	command.Stdout = c.out
	command.Stderr = c.errOut
	return command.Run()
}

func (c *cli) localPVENodeName() (string, error) {
	if c.pveNodeName != nil {
		return c.pveNodeName()
	}
	value, err := os.Hostname()
	value = strings.TrimSpace(value)
	if err != nil || !localPVENodeNamePattern.MatchString(value) {
		return "", errors.New("cannot determine local PVE node name")
	}
	return value, nil
}

func containsLocalPVENode(nodes []string, localNode string) bool {
	for _, node := range nodes {
		if node == localNode {
			return true
		}
	}
	return false
}

func hasRequiredPVEReadPermissions(value pve.Permissions) bool {
	root := value.Paths["/"]
	for _, privilege := range requiredPVEReadPrivileges {
		if root[privilege] <= 0 {
			return false
		}
	}
	return true
}

func isManagedPVECAPath(value string) bool {
	return strings.ReplaceAll(filepath.Clean(value), `\`, "/") == managedPVECAFile
}

func (c *cli) preflightLocalPVETLS(ctx context.Context, serverName, caFile string) error {
	if c.pveTLSPreflight != nil {
		return c.pveTLSPreflight(ctx, serverName, caFile)
	}
	return defaultLocalPVETLSPreflight(ctx, serverName, caFile)
}

func defaultLocalPVETLSPreflight(ctx context.Context, serverName, caFile string) error {
	if runtime.GOOS != "linux" || !isManagedPVECAPath(caFile) {
		return errors.New("managed PVE TLS preflight requires Linux and the fixed CA path")
	}
	file, err := fsutil.OpenRegularInDirectoryNoFollow(filepath.Dir(caFile), filepath.Base(caFile))
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Mode().Perm() != 0o644 {
		return errors.New("managed PVE CA must be a regular service-readable 0644 file")
	}
	pem, err := io.ReadAll(io.LimitReader(file, maxPVECABytes+1))
	if err != nil || len(pem) == 0 || len(pem) > maxPVECABytes {
		return errors.New("managed PVE CA is empty or too large")
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return errors.New("managed PVE CA contains no certificate")
	}
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config:    &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName, RootCAs: pool},
	}
	connection, err := dialer.DialContext(ctx, "tcp4", "127.0.0.1:8006")
	if err != nil {
		return err
	}
	return connection.Close()
}

func (c *cli) inspectLocalPVE(cfg config.Config) (localPVEStatus, int) {
	status := localPVEStatus{
		PVESource: cfg.PVE.Source, Endpoint: cfg.PVE.Endpoint, TLSServerName: cfg.PVE.TLSServerName,
		ProductionExecution: cfg.Control.ProductionExecution,
		Read:                credentialProbe{Code: "NOT_PROBED"}, Control: credentialProbe{Code: "NOT_PROBED"},
	}
	if cfg.PVE.Source != "api" {
		status.Read.Code, status.Control.Code = "SOURCE_NOT_CONFIGURED", "SOURCE_NOT_CONFIGURED"
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
	status.Read = c.probeView(ctx, pveConfig(cfg, values[cfg.PVE.TokenIDEnv], values[cfg.PVE.TokenSecretEnv]), true, cfg.PVE.LocalNode)
	status.Control = c.probeView(ctx, pveConfig(cfg, values[cfg.Control.PVETokenIDEnv], values[cfg.Control.PVETokenSecretEnv]), false, "")
	_, websiteBindingErr := bindstate.Load(cfg.Runtime.StateDirectory)
	_, monitoringBindingErr := bindstate.LoadMonitoring(cfg.Runtime.StateDirectory)
	// productionReady describes authoritative real-data onboarding, not
	// permission to mutate PVE. Writes remain independently gated by
	// ProductionExecution, a scoped control token, assignment policy, signed
	// commands, and the monitoring audit sink.
	status.ProductionReady = cfg.Mode == "production" && cfg.PVE.Source == "api" && status.Read.CredentialReady && websiteBindingErr == nil && monitoringBindingErr == nil
	// A deliberately unscoped control token is expected during read-only
	// onboarding. It remains visible in the response but does not make a real,
	// verified monitoring setup fail its command exit status.
	if !status.Read.CredentialReady {
		return status, 1
	}
	return status, 0
}

func (c *cli) probeView(ctx context.Context, cfg pve.Config, includeVersion bool, localNode string) credentialProbe {
	view := credentialProbe{Attempted: true, Code: "PVE_PROBE_FAILED"}
	if cfg.TokenID == "" || cfg.TokenSecret == "" {
		view.Code = "PVE_CREDENTIAL_UNAVAILABLE"
		return view
	}
	result, err := c.runPVEProbe(ctx, cfg, includeVersion, localNode)
	if err != nil {
		return view
	}
	counts := permissionCounts(result.permissions)
	view.Succeeded, view.PermissionPaths, view.PermissionGrants, view.Version = true, counts.paths, counts.grants, result.version
	view.CredentialReady = counts.grants > 0
	if includeVersion {
		view.CredentialReady = result.version.Version != "" && hasRequiredPVEReadPermissions(result.permissions) && result.nodeStatusVerified && result.storageVerified
	}
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

func defaultPVEProbe(ctx context.Context, cfg pve.Config, includeVersion bool, localNode string) (rawCredentialProbe, error) {
	client, err := pve.NewClient(cfg)
	if err != nil {
		return rawCredentialProbe{}, err
	}
	result := rawCredentialProbe{}
	if includeVersion {
		if result.version, err = client.Version(ctx); err != nil {
			return rawCredentialProbe{}, err
		}
		nodes, nodeErr := client.Nodes(ctx)
		if nodeErr != nil {
			return rawCredentialProbe{}, nodeErr
		}
		result.nodes = make([]string, 0, len(nodes))
		for _, node := range nodes {
			result.nodes = append(result.nodes, node.Node)
		}
		if strings.TrimSpace(localNode) == "" {
			return rawCredentialProbe{}, errors.New("local PVE node is required for readiness probe")
		}
		if _, nodeErr := client.NodeStatus(ctx, localNode); nodeErr != nil {
			return rawCredentialProbe{}, nodeErr
		}
		result.nodeStatusVerified = true
		if _, storageErr := client.NodeStorage(ctx, localNode); storageErr != nil {
			return rawCredentialProbe{}, storageErr
		}
		result.storageVerified = true
	}
	if result.permissions, err = client.EffectivePermissions(ctx); err != nil {
		return rawCredentialProbe{}, err
	}
	return result, nil
}

func (c *cli) runPVEProbe(ctx context.Context, cfg pve.Config, includeVersion bool, localNode string) (rawCredentialProbe, error) {
	if c.pveProbe != nil {
		return c.pveProbe(ctx, cfg, includeVersion, localNode)
	}
	return defaultPVEProbe(ctx, cfg, includeVersion, localNode)
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
	result, err := c.runPVEProbe(ctx, pveConfig(cfg, values[cfg.Control.PVETokenIDEnv], values[cfg.Control.PVETokenSecretEnv]), false, "")
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
