// Package admincli implements the local ag-pve SSH administration command.
// It never reads or prints secret values; only environment-variable names are
// stored in the Agent configuration.
package admincli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ppflight/ppflight-agent/internal/assignment"
	"github.com/ppflight/ppflight-agent/internal/bindingoverlay"
	"github.com/ppflight/ppflight-agent/internal/bindstate"
	"github.com/ppflight/ppflight-agent/internal/config"
	"github.com/ppflight/ppflight-agent/internal/enrollment"
	"github.com/ppflight/ppflight-agent/internal/fsutil"
	"github.com/ppflight/ppflight-agent/internal/health"
	"github.com/ppflight/ppflight-agent/internal/inventory"
	"github.com/ppflight/ppflight-agent/internal/monitorenrollment"
	"github.com/ppflight/ppflight-agent/internal/netpolicy"
	"github.com/ppflight/ppflight-agent/internal/protocol"
	"github.com/ppflight/ppflight-agent/internal/pve"
	"github.com/ppflight/ppflight-agent/internal/templatebootstrap"
)

type cli struct {
	in              io.Reader
	out, errOut     io.Writer
	version         string
	pveEnvironment  func(string) (map[string]string, error)
	pveProbe        func(context.Context, pve.Config, bool) (rawCredentialProbe, error)
	effectiveUID    func() int
	tlsServerName   func() string
	templateRun     func(context.Context, []string, io.Writer) (templatebootstrap.Result, error)
	pvesmSetContent func(context.Context, string, string) error
}

func Run(args []string, version string, out, errOut io.Writer) int {
	if out == nil {
		out = os.Stdout
	}
	if errOut == nil {
		errOut = os.Stderr
	}
	return RunWithInput(args, version, os.Stdin, out, errOut)
}

// RunWithInput is Run with an explicit stdin reader.  It exists so callers
// can supply a binding code without ever placing it in argv.
func RunWithInput(args []string, version string, in io.Reader, out, errOut io.Writer) int {
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}
	if errOut == nil {
		errOut = os.Stderr
	}
	return (&cli{in: in, out: out, errOut: errOut, version: version}).run(args)
}

func (c *cli) run(args []string) int {
	flags := flag.NewFlagSet("ag-pve", flag.ContinueOnError)
	flags.SetOutput(c.errOut)
	filename := flags.String("config", "/etc/ppflight-agent/agent.yaml", "Agent config file")
	flags.Usage = c.usage
	if err := flags.Parse(args); err != nil {
		return 2
	}
	args = flags.Args()
	if len(args) == 0 {
		return c.menu(*filename)
	}
	if args[0] == "help" {
		c.usage()
		return 0
	}
	if args[0] == "version" {
		fmt.Fprintln(c.out, c.version)
		return 0
	}
	switch args[0] {
	case "bind":
		return c.bind(*filename, args[1:])
	case "status":
		return c.status(*filename)
	case "validate":
		return c.validate(*filename)
	case "monitor", "monitoring":
		return c.monitoring(*filename, args[1:])
	case "website":
		return c.website(*filename, args[1:])
	case "template", "templates":
		return c.template(args[1:])
	case "pve":
		return c.pve(*filename, args[1:])
	case "menu":
		return c.menu(*filename)
	default:
		fmt.Fprintf(c.errOut, "未知命令 %q\n", args[0])
		return 2
	}
}

func (c *cli) usage() {
	fmt.Fprintln(c.out, `ag-pve - PPFlight Agent SSH 管理命令

  ag-pve [--config FILE] status
	AG | ag | ag-pve                                     # 五项交互菜单
  ag-pve [--config FILE] validate
  ag-pve [--config FILE] pve prepare [--tls-server-name DNS_NAME] [--ca-file FILE]
  ag-pve [--config FILE] pve status
  ag-pve [--config FILE] bind --endpoint HTTPS_URL --pve-version VERSION [--code-file FILE] [--replace]
  ag-pve [--config FILE] website bind --endpoint HTTPS_URL --pve-version VERSION [--code-file FILE] [--replace]
  ag-pve [--config FILE] website status
	  ag-pve [--config FILE] monitoring preflight --endpoint HTTPS_URL
	  ag-pve [--config FILE] monitoring bind --endpoint HTTPS_URL --pve-version VERSION [--code-file FILE] [--replace]
  ag-pve [--config FILE] monitoring status
  ag-pve [--config FILE] monitoring show|test|set [选项]
  ag-pve [--config FILE] monitoring query|modify     # 预留，v0.1 返回未实现
  ag-pve [--config FILE] website bind|status|show|test
  ag-pve [--config FILE] website metering|telemetry set [选项]
  ag-pve [--config FILE] website control set [选项]
  ag-pve [--config FILE] website query|modify        # 预留，v0.1 返回未实现
  ag-pve template init                               # 交互选择镜像/模板/备份存储并二次确认
  ag-pve template catalog|discover
  ag-pve template bootstrap [helper 参数]            # plan；--execute 还需原 plan ID/摘要

bind 的一次性绑定码只能经标准输入或 --code-file 私密文件提供，绝不接受命令行参数。show 只显示脱敏配置；test 只做 DNS/TCP/TLS 探测，不发送业务数据；set 原子写入并保留 .bak 备份，不自动重启服务。官网/监控站的远程资产查询修改 API 已预留，待服务端契约完成后补入。`)
}

func (c *cli) menu(filename string) int {
	reader := bufio.NewReader(io.LimitReader(c.in, 64<<10))
	fmt.Fprintln(c.out, "PPFlight Agent")
	c.menuPVEHeader(filename)
	fmt.Fprintln(c.out, `
  1) 初始化/克隆 Cloud-Init 模板
  2) 使用一次性绑定码绑定 PPFlight 官网
  3) 使用独立一次性绑定码绑定监控站
  4) 查看 PPFlight 官网通信状态
  5) 查看监控站通信状态
  0) 退出`)
	choice, err := c.promptLine(reader, "请选择 [0-5]: ")
	if err != nil {
		fmt.Fprintln(c.errOut, "无法读取菜单选择")
		return 2
	}
	switch choice {
	case "0", "q", "quit", "exit":
		return 0
	case "1":
		original := c.in
		c.in = reader
		defer func() { c.in = original }()
		return c.templateInit()
	case "2":
		return c.menuBind(reader, filename, false)
	case "3":
		return c.menuBind(reader, filename, true)
	case "4":
		return c.website(filename, []string{"status"})
	case "5":
		return c.monitoring(filename, []string{"status"})
	default:
		fmt.Fprintln(c.errOut, "菜单选择无效")
		return 2
	}
}

func (c *cli) menuBind(reader *bufio.Reader, filename string, monitoring bool) int {
	target := "官网"
	if monitoring {
		target = "监控站"
	}
	endpoint, err := c.promptLine(reader, target+"一次性绑定 API 地址（HTTPS）: ")
	if err != nil || endpoint == "" {
		fmt.Fprintln(c.errOut, "绑定 API 地址不能为空")
		return 2
	}
	detected := detectPVEVersion()
	versionPrompt := "PVE 版本: "
	if detected != "" {
		versionPrompt = fmt.Sprintf("PVE 版本 [%s]: ", detected)
	}
	pveVersion, err := c.promptLine(reader, versionPrompt)
	if err != nil {
		return 2
	}
	if pveVersion == "" {
		pveVersion = detected
	}
	if pveVersion == "" {
		fmt.Fprintln(c.errOut, "无法自动检测 PVE 版本，请手工输入")
		return 2
	}
	code, err := c.promptLine(reader, "输入一次性绑定码（不会写入 argv、配置或日志）: ")
	if err != nil || code == "" || len(code) > 128 {
		fmt.Fprintln(c.errOut, "一次性绑定码无效")
		return 2
	}
	args := []string{"bind", "--endpoint", endpoint, "--pve-version", pveVersion}
	if monitoring {
		args = append([]string{"monitoring"}, args...)
	} else {
		args = append([]string{"website"}, args...)
	}
	original := c.in
	c.in = strings.NewReader(code + "\n")
	defer func() { c.in = original }()
	if monitoring {
		return c.monitoring(filename, args[1:])
	}
	return c.website(filename, args[1:])
}

func detectPVEVersion() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "/usr/bin/pveversion").Output()
	if err != nil || len(output) > 4096 {
		return ""
	}
	line := strings.TrimSpace(strings.SplitN(string(output), "\n", 2)[0])
	parts := strings.Split(line, "/")
	if len(parts) < 2 || parts[0] != "pve-manager" || !safeMenuVersion(parts[1]) {
		return ""
	}
	return parts[1]
}

func safeMenuVersion(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || index > 0 && strings.ContainsRune("._+:-", character) {
			continue
		}
		return false
	}
	return true
}

func (c *cli) load(filename string) (config.Config, bool) {
	cfg, err := config.LoadFile(filename)
	if err != nil {
		fmt.Fprintf(c.errOut, "读取配置失败: %v\n", err)
		return config.Config{}, false
	}
	return cfg, true
}

func (c *cli) validate(filename string) int {
	cfg, ok := c.load(filename)
	if !ok {
		return 1
	}
	lookup, err := config.ResolvePVEEnvironmentLookup(cfg, os.LookupEnv)
	if err != nil {
		fmt.Fprintf(c.errOut, "本机 PVE 密钥检查失败: %v\n", err)
		return 1
	}
	if _, err := bindingoverlay.Resolve(cfg, lookup); err != nil {
		fmt.Fprintf(c.errOut, "运行时密钥检查失败: %v\n", err)
		return 1
	}
	fmt.Fprintf(c.out, "配置有效 mode=%s control.enabled=%t productionExecution=%t\n", cfg.Mode, cfg.Control.Enabled, cfg.Control.ProductionExecution)
	return 0
}

func (c *cli) status(filename string) int {
	cfg, ok := c.load(filename)
	if !ok {
		return 1
	}
	value, err := fetchLocalStatus(cfg)
	if err != nil {
		fmt.Fprintf(c.errOut, "Agent 状态查询失败: %v\n", err)
		return 1
	}
	pveStatus, pveCode := c.inspectLocalPVE(cfg)
	if printJSON(c.out, map[string]any{"localAgent": value, "pve": pveStatus}) != 0 {
		return 1
	}
	return pveCode
}

func fetchLocalStatus(cfg config.Config) (health.Status, error) {
	client := &http.Client{Timeout: 5 * time.Second, Transport: netpolicy.ApplyIPv4Only(&http.Transport{Proxy: nil}), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Get("http://" + cfg.Runtime.ListenAddress + "/status")
	if err != nil {
		return health.Status{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil || response.StatusCode != http.StatusOK {
		return health.Status{}, fmt.Errorf("Agent 状态接口 HTTP %d", response.StatusCode)
	}
	var value health.Status
	if json.Unmarshal(body, &value) != nil {
		return health.Status{}, errors.New("Agent 状态不是有效 JSON")
	}
	return value, nil
}

func (c *cli) bind(filename string, args []string) int {
	cfg, ok := c.load(filename)
	if !ok {
		return 1
	}
	set := flag.NewFlagSet("bind", flag.ContinueOnError)
	set.SetOutput(c.errOut)
	endpoint := set.String("endpoint", "", "HTTPS enrollment endpoint")
	codeFile := set.String("code-file", "", "private file containing exactly one binding code")
	pveVersion := set.String("pve-version", "", "PVE version for this node")
	nodeRef := set.String("node-ref", cfg.Identity.NodeRef, "node claim (defaults to identity.nodeRef)")
	hostname, hostErr := os.Hostname()
	if hostErr != nil {
		fmt.Fprintln(c.errOut, "无法读取本机主机名")
		return 1
	}
	host := set.String("hostname", hostname, "host claim (defaults to local hostname)")
	capabilities := set.String("capabilities", "pve.discovery.v1,pve.telemetry.v1", "comma-separated supported capabilities; pve.control.v1 requires a verified local control token")
	replace := set.Bool("replace", false, "replace an existing local binding after obtaining a new code")
	if err := set.Parse(args); err != nil || set.NArg() != 0 || strings.TrimSpace(*endpoint) == "" || strings.TrimSpace(*pveVersion) == "" {
		if err == nil {
			fmt.Fprintln(c.errOut, "bind 需要 --endpoint 和 --pve-version，且不接受绑定码位置参数")
		}
		return 2
	}
	explicitCapabilities := false
	set.Visit(func(item *flag.Flag) {
		if item.Name == "capabilities" {
			explicitCapabilities = true
		}
	})
	resolvedCapabilities, capabilityErr := c.websiteCapabilities(cfg, *capabilities, explicitCapabilities)
	if capabilityErr != nil {
		fmt.Fprintln(c.errOut, "官网能力声明与本机已验证能力不一致；未发送绑定请求")
		return 2
	}

	// A malformed or unsafe existing state is never overwritten, even with
	// --replace.  This makes accidental replacement and symlink attacks fail
	// closed before the one-time code is sent to the service.
	var previous bindstate.State
	if existing, err := bindstate.Load(cfg.Runtime.StateDirectory); err == nil {
		if !*replace {
			fmt.Fprintln(c.errOut, "本机已经绑定；如需轮换请使用新的绑定码和 --replace")
			return 1
		}
		previous = existing
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(c.errOut, "现有绑定状态不安全或无效，未执行替换")
		return 1
	}

	code, err := c.readBindingCode(*codeFile)
	if err != nil {
		fmt.Fprintln(c.errOut, "读取绑定码失败")
		return 1
	}
	deviceID, err := bindstate.LoadOrCreateDeviceID(cfg.Runtime.StateDirectory)
	if err != nil {
		fmt.Fprintln(c.errOut, "设备状态目录不安全或不可写")
		return 1
	}
	if cfg.Mode != "test" {
		parsed, parseErr := url.Parse(strings.TrimSpace(*endpoint))
		if parseErr != nil || !strings.EqualFold(parsed.Scheme, "https") {
			fmt.Fprintln(c.errOut, "生产模式下绑定地址必须使用 HTTPS")
			return 2
		}
	}
	client, err := enrollment.NewClient(enrollment.Config{Endpoint: strings.TrimSpace(*endpoint)})
	if err != nil {
		fmt.Fprintln(c.errOut, "绑定地址必须是 HTTPS（测试时仅允许 loopback HTTP）")
		return 2
	}
	request := enrollment.Request{
		SchemaVersion: enrollment.SchemaVersion, BindingCode: code, DeviceID: deviceID,
		AgentVersion: c.version, Hostname: strings.TrimSpace(*host),
		NodeClaim:    enrollment.NodeClaim{NodeRef: strings.TrimSpace(*nodeRef), PVEVersion: strings.TrimSpace(*pveVersion)},
		Capabilities: resolvedCapabilities,
	}
	fingerprint, err := bindstate.RequestFingerprint(request)
	if err != nil {
		fmt.Fprintln(c.errOut, "无法生成绑定请求指纹")
		return 1
	}
	requestID, bindingLock, err := bindstate.PreparePending(cfg.Runtime.StateDirectory, "website", fingerprint)
	if err != nil {
		fmt.Fprintln(c.errOut, "无法持久化绑定请求；未发送绑定码")
		return 1
	}
	defer bindingLock.Close()
	request.RequestID = requestID
	response, err := client.Bind(context.Background(), request)
	if err != nil {
		// enrollment errors intentionally redact both the submitted code and all
		// returned credential values.  Do not decorate this error with request data.
		fmt.Fprintln(c.errOut, "绑定请求失败")
		return 1
	}
	if _, err := inventory.Parse(response.AssignmentDocument, response.ClusterRef); err != nil {
		fmt.Fprintln(c.errOut, "绑定响应中的初始分配无效")
		return 1
	}
	if previous.CredentialEpoch != 0 && response.CredentialEpoch <= previous.CredentialEpoch {
		fmt.Fprintln(c.errOut, "绑定响应的凭据版本未前进，未替换本地绑定")
		return 1
	}
	if err := bindstate.WriteAssignment(cfg.Assignments.File, response.AssignmentDocument); err != nil {
		fmt.Fprintln(c.errOut, "初始分配保存失败")
		return 1
	}
	applyBinding(&cfg, response)
	if code := c.save(filename, cfg); code != 0 {
		return code
	}
	// Persist credentials last. If an earlier public-file write fails, the
	// pending request ID remains and the same code can recover the service's
	// original response without issuing a second credential set.
	state := bindstate.FromResponse(strings.TrimSpace(*endpoint), deviceID, response)
	if err := bindstate.Save(cfg.Runtime.StateDirectory, state); err != nil {
		fmt.Fprintln(c.errOut, "绑定密钥状态保存失败；可用同一绑定码安全重试")
		return 1
	}
	if err := bindstate.ClearPending(cfg.Runtime.StateDirectory, "website"); err != nil {
		fmt.Fprintln(c.errOut, "绑定已完成，但清理本地 pending 标记失败")
		return 1
	}
	fmt.Fprintln(c.out, "绑定完成；凭据已保存在私有本地状态中，未输出。")
	return 0
}

func (c *cli) readBindingCode(filename string) (string, error) {
	var reader io.Reader = c.in
	if filename != "" {
		info, err := os.Lstat(filename)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", errors.New("binding code file is unsafe")
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			return "", errors.New("binding code file must be private")
		}
		file, err := os.Open(filename)
		if err != nil {
			return "", err
		}
		defer file.Close()
		reader = file
	}
	if reader == nil {
		return "", errors.New("binding code input is unavailable")
	}
	contents, err := io.ReadAll(io.LimitReader(reader, 1025))
	if err != nil || len(contents) > 1024 {
		return "", errors.New("binding code input is invalid")
	}
	code := strings.TrimSpace(string(contents))
	if len(code) > 128 {
		return "", errors.New("binding code input is invalid")
	}
	return code, nil
}

func splitCapabilities(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		result = append(result, strings.TrimSpace(part))
	}
	return result
}

// applyBinding changes public configuration only.  Credential values remain
// exclusively in bindstate; the stable labels are resolved from it at runtime.
func applyBinding(cfg *config.Config, response enrollment.Response) {
	cfg.Identity = config.IdentityConfig{AgentRef: response.AgentRef, CollectorRef: response.CollectorRef, SourceRef: response.SourceRef, ClusterRef: response.ClusterRef, NodeRef: response.NodeRef, Site: response.Site}
	cfg.Destinations.WebsiteMetering.Enabled, cfg.Destinations.WebsiteMetering.URL = true, response.Endpoints.Metering
	cfg.Destinations.WebsiteMetering.Auth = config.AuthConfig{Mode: "hmac-sha256", KeyIDEnv: bindingoverlay.WebsiteMeteringKeyIDEnv, SecretEnv: bindingoverlay.WebsiteMeteringSecretEnv}
	cfg.Destinations.WebsiteTelemetry.Enabled, cfg.Destinations.WebsiteTelemetry.URL = true, response.Endpoints.Telemetry
	cfg.Destinations.WebsiteTelemetry.Auth = config.AuthConfig{Mode: "hmac-sha256", KeyIDEnv: bindingoverlay.WebsiteTelemetryKeyIDEnv, SecretEnv: bindingoverlay.WebsiteTelemetrySecretEnv}
	cfg.Assignments.RefreshURL = response.Endpoints.Assignments
	// Do not alter Control.Enabled or ProductionExecution.  The endpoint values
	// are recorded for an already-enabled control plane, while the distinct
	// command/receipt credentials and Ed25519 key stay in bindstate.
	cfg.Control.PollURL, cfg.Control.ResultURL = response.Endpoints.Commands, response.Endpoints.Receipts
	cfg.Control.Auth = config.AuthConfig{Mode: "hmac-sha256", KeyIDEnv: bindingoverlay.WebsiteCommandKeyIDEnv, SecretEnv: bindingoverlay.WebsiteCommandSecretEnv}
	cfg.Control.CommandSecretEnv = ""
	cfg.Control.CommandSigningKeyIDEnv = bindingoverlay.WebsiteSigningKeyIDEnv
	cfg.Control.CommandPublicKeyEnv = bindingoverlay.WebsiteCommandPublicKeyEnv
	cfg.Control.AllowedActions = append([]string(nil), response.AllowedActions...)
}

func (c *cli) monitoring(filename string, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.errOut, "monitoring 需要 preflight、bind、status、show、test 或 set")
		return 2
	}
	cfg, ok := c.load(filename)
	if !ok {
		return 1
	}
	switch args[0] {
	case "preflight":
		return c.monitoringPreflight(args[1:])
	case "bind":
		return c.monitoringBind(filename, cfg, args[1:])
	case "status":
		return c.monitoringStatus(cfg)
	case "show":
		return printJSON(c.out, map[string]any{"telemetry": cfg.Destinations.Monitoring, "audit": cfg.Destinations.MonitoringAudit})
	case "test":
		return c.testURLs(map[string]string{"monitoringTelemetry": cfg.Destinations.Monitoring.URL, "monitoringAudit": cfg.Destinations.MonitoringAudit.URL})
	case "set":
		value, parsed := destinationFlags("monitoring set", cfg.Destinations.Monitoring, args[1:], c.errOut)
		if !parsed {
			return 2
		}
		cfg.Destinations.Monitoring = value
		return c.save(filename, cfg)
	case "query", "modify":
		return c.reserved("monitoring", args[0])
	default:
		fmt.Fprintf(c.errOut, "未知 monitoring 操作 %q\n", args[0])
		return 2
	}
}

type monitoringPreflightCheck struct {
	IPv4                string     `json:"ipv4"`
	Status              string     `json:"status"`
	TLSVersion          string     `json:"tlsVersion,omitempty"`
	CertificateNotAfter *time.Time `json:"certificateNotAfter,omitempty"`
	ErrorCode           string     `json:"errorCode,omitempty"`
}

type monitoringPreflightResult struct {
	SchemaVersion               int                        `json:"schemaVersion"`
	Endpoint                    string                     `json:"endpoint"`
	Hostname                    string                     `json:"hostname"`
	ResolvedAt                  time.Time                  `json:"resolvedAt"`
	ResolvedA                   []string                   `json:"resolvedA"`
	EligibleServerIPv4Allowlist []string                   `json:"eligibleServerIPv4Allowlist"`
	ReadyForOperatorApproval    bool                       `json:"readyForOperatorApproval"`
	Checks                      []monitoringPreflightCheck `json:"checks"`
}

type monitoringTLSDial func(context.Context, string, string, time.Duration) (tls.ConnectionState, error)

func (c *cli) monitoringPreflight(args []string) int {
	set := flag.NewFlagSet("monitoring preflight", flag.ContinueOnError)
	set.SetOutput(c.errOut)
	endpoint := set.String("endpoint", "", "HTTPS monitoring enrollment endpoint")
	if err := set.Parse(args); err != nil || set.NArg() != 0 || strings.TrimSpace(*endpoint) == "" {
		if err == nil {
			fmt.Fprintln(c.errOut, "monitoring preflight 需要且仅接受 --endpoint HTTPS_URL")
		}
		return 2
	}
	result, err := buildMonitoringPreflight(context.Background(), strings.TrimSpace(*endpoint), 8*time.Second, nil, nil, time.Now)
	if err != nil {
		fmt.Fprintf(c.errOut, "监控 IPv4/TLS 预检失败: %v\n", err)
		return 1
	}
	if printJSON(c.out, result) != 0 {
		return 1
	}
	if !result.ReadyForOperatorApproval {
		return 1
	}
	return 0
}

// buildMonitoringPreflight produces evidence for a human allowlist decision.
// It never writes binding state, calls an HTTP route, or approves addresses.
func buildMonitoringPreflight(ctx context.Context, raw string, timeout time.Duration, resolver netpolicy.Resolver, dial monitoringTLSDial, now func() time.Time) (monitoringPreflightResult, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || netpolicy.ValidateIPv4URL(parsed) != nil {
		return monitoringPreflightResult{}, errors.New("endpoint 必须是有效的 IPv4-capable HTTPS URL")
	}
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	if now == nil {
		now = time.Now
	}
	hostname := parsed.Hostname()
	var values []net.IP
	if literal := net.ParseIP(hostname); literal != nil {
		values = []net.IP{literal}
	} else {
		lookupCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		values, err = resolver.LookupIP(lookupCtx, "ip4", hostname)
		if err != nil {
			return monitoringPreflightResult{}, errors.New("无法解析监控 endpoint 的 A 记录")
		}
	}
	unique := make(map[string]struct{}, len(values))
	addresses := make([]string, 0, len(values))
	for _, value := range values {
		if value.To4() == nil {
			continue
		}
		canonical := value.String()
		parsedIP := net.ParseIP(canonical)
		if parsedIP == nil || parsedIP.IsUnspecified() || parsedIP.IsMulticast() || canonical == "255.255.255.255" {
			continue
		}
		if _, exists := unique[canonical]; exists {
			continue
		}
		unique[canonical] = struct{}{}
		addresses = append(addresses, canonical)
	}
	sort.Strings(addresses)
	if len(addresses) == 0 || len(addresses) > netpolicy.MaxServerIPv4Allowlist {
		return monitoringPreflightResult{}, errors.New("A 记录数量不符合 monitoring allowlist 合同")
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	if dial == nil {
		dial = dialMonitoringTLS
	}
	result := monitoringPreflightResult{SchemaVersion: 1, Endpoint: parsed.String(), Hostname: hostname, ResolvedAt: now().UTC(), ResolvedA: append([]string(nil), addresses...), EligibleServerIPv4Allowlist: []string{}, Checks: make([]monitoringPreflightCheck, 0, len(addresses))}
	for _, ipv4 := range addresses {
		state, dialErr := dial(ctx, net.JoinHostPort(ipv4, port), hostname, timeout)
		check := monitoringPreflightCheck{IPv4: ipv4}
		if dialErr != nil {
			check.Status, check.ErrorCode = "failed", "TCP4_TLS_VERIFICATION_FAILED"
			result.Checks = append(result.Checks, check)
			continue
		}
		check.Status = "verified"
		check.TLSVersion = tlsName(state.Version)
		if len(state.PeerCertificates) > 0 {
			notAfter := state.PeerCertificates[0].NotAfter.UTC()
			check.CertificateNotAfter = &notAfter
		}
		result.EligibleServerIPv4Allowlist = append(result.EligibleServerIPv4Allowlist, ipv4)
		result.Checks = append(result.Checks, check)
	}
	result.ReadyForOperatorApproval = len(result.EligibleServerIPv4Allowlist) == len(result.ResolvedA)
	return result, nil
}

func dialMonitoringTLS(ctx context.Context, address, hostname string, timeout time.Duration) (tls.ConnectionState, error) {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	connection, err := (&net.Dialer{Timeout: timeout}).DialContext(dialCtx, "tcp4", address)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	tlsConnection := tls.Client(connection, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: hostname})
	defer tlsConnection.Close()
	if err := tlsConnection.HandshakeContext(dialCtx); err != nil {
		return tls.ConnectionState{}, err
	}
	return tlsConnection.ConnectionState(), nil
}

func (c *cli) monitoringStatus(cfg config.Config) int {
	state, err := bindstate.LoadMonitoring(cfg.Runtime.StateDirectory)
	if err != nil {
		fmt.Fprintln(c.errOut, "监控绑定状态不存在或不安全")
		return 1
	}
	result := map[string]any{
		"binding": map[string]any{"bindingId": state.BindingID, "deviceId": state.DeviceID, "monitoringAgentRef": state.MonitoringAgentRef, "credentialEpoch": fmt.Sprintf("%d", state.CredentialEpoch), "issuedAt": state.IssuedAt},
	}
	exitCode := 0
	if local, localErr := fetchLocalStatus(cfg); localErr == nil {
		result["localAgent"] = local
	} else {
		result["localAgent"] = map[string]any{"available": false, "code": "LOCAL_AGENT_UNREACHABLE"}
		exitCode = 1
	}
	client, err := monitorenrollment.NewStatusClient(monitorenrollment.StatusClientConfig{BindingEndpoint: state.BindingEndpoint, Credential: state.HMACCredential, NetworkPolicy: state.NetworkPolicy})
	if err == nil {
		var remote monitorenrollment.StatusResponse
		remote, err = client.Get(context.Background(), monitorenrollment.StatusExpected{BindingID: state.BindingID, DeviceID: state.DeviceID, MonitoringAgentRef: state.MonitoringAgentRef, CredentialEpoch: state.CredentialEpoch})
		if err == nil {
			result["remoteMonitoring"] = remote
		}
	}
	if err != nil {
		result["remoteMonitoring"] = map[string]any{"available": false, "code": "REMOTE_STATUS_UNAVAILABLE"}
		exitCode = 1
	}
	if printJSON(c.out, result) != 0 {
		return 1
	}
	return exitCode
}

func (c *cli) monitoringBind(filename string, cfg config.Config, args []string) int {
	set := flag.NewFlagSet("monitoring bind", flag.ContinueOnError)
	set.SetOutput(c.errOut)
	endpoint := set.String("endpoint", "", "HTTPS monitoring enrollment endpoint")
	codeFile := set.String("code-file", "", "private file containing exactly one binding code")
	pveVersion := set.String("pve-version", "", "PVE version for this node")
	nodeRef := set.String("node-ref", cfg.Identity.NodeRef, "node claim")
	hostname, err := os.Hostname()
	if err != nil {
		fmt.Fprintln(c.errOut, "无法读取本机主机名")
		return 1
	}
	host := set.String("hostname", hostname, "host claim")
	capabilities := set.String("capabilities", "telemetry-v1,audit-v1,delivery-state-v1,ipv4-only,mutual-whitelist-v1", "comma-separated monitoring capabilities")
	replace := set.Bool("replace", false, "rotate an existing monitoring binding")
	if err := set.Parse(args); err != nil || set.NArg() != 0 || strings.TrimSpace(*endpoint) == "" || strings.TrimSpace(*pveVersion) == "" {
		if err == nil {
			fmt.Fprintln(c.errOut, "monitoring bind 需要 --endpoint 和 --pve-version，且不接受绑定码位置参数")
		}
		return 2
	}
	var previous bindstate.MonitoringState
	if existing, err := bindstate.LoadMonitoring(cfg.Runtime.StateDirectory); err == nil {
		if !*replace {
			fmt.Fprintln(c.errOut, "监控信任域已经绑定；轮换需使用新绑定码和 --replace")
			return 1
		}
		previous = existing
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(c.errOut, "现有监控绑定状态不安全或无效，未执行替换")
		return 1
	}
	code, err := c.readBindingCode(*codeFile)
	if err != nil {
		fmt.Fprintln(c.errOut, "读取监控绑定码失败")
		return 1
	}
	deviceID, err := bindstate.LoadOrCreateDeviceID(cfg.Runtime.StateDirectory)
	if err != nil {
		fmt.Fprintln(c.errOut, "设备状态目录不安全或不可写")
		return 1
	}
	if cfg.Mode != "test" {
		parsed, parseErr := url.Parse(strings.TrimSpace(*endpoint))
		if parseErr != nil || !strings.EqualFold(parsed.Scheme, "https") {
			fmt.Fprintln(c.errOut, "生产模式下监控绑定地址必须使用 HTTPS")
			return 2
		}
	}
	client, err := monitorenrollment.NewClient(monitorenrollment.Config{Endpoint: strings.TrimSpace(*endpoint)})
	if err != nil {
		fmt.Fprintln(c.errOut, "监控绑定地址必须是 HTTPS（测试时仅允许 loopback HTTP）")
		return 2
	}
	request := monitorenrollment.Request{SchemaVersion: monitorenrollment.SchemaVersion, BindingCode: code, DeviceID: deviceID, AgentVersion: c.version, Hostname: strings.TrimSpace(*host), NodeClaim: enrollment.NodeClaim{NodeRef: strings.TrimSpace(*nodeRef), PVEVersion: strings.TrimSpace(*pveVersion)}, Capabilities: splitCapabilities(*capabilities)}
	fingerprint, err := bindstate.RequestFingerprint(request)
	if err != nil {
		fmt.Fprintln(c.errOut, "无法生成监控绑定请求指纹")
		return 1
	}
	requestID, lock, err := bindstate.PreparePending(cfg.Runtime.StateDirectory, "monitoring", fingerprint)
	if err != nil {
		fmt.Fprintln(c.errOut, "无法持久化监控绑定请求；未发送绑定码")
		return 1
	}
	defer lock.Close()
	request.RequestID = requestID
	response, err := client.Bind(context.Background(), request)
	if err != nil {
		fmt.Fprintln(c.errOut, "监控绑定请求失败")
		return 1
	}
	if previous.CredentialEpoch != 0 && response.CredentialEpoch <= previous.CredentialEpoch {
		fmt.Fprintln(c.errOut, "监控绑定凭据版本未前进")
		return 1
	}
	// Only the monitoring destination is changed. Website identity, endpoint and
	// control credentials are intentionally untouched.
	cfg.Destinations.Monitoring.Enabled = true
	cfg.Destinations.Monitoring.URL = response.IngestEndpoint
	cfg.Destinations.Monitoring.Auth = config.AuthConfig{Mode: "hmac-sha256", KeyIDEnv: bindingoverlay.MonitoringKeyIDEnv, SecretEnv: bindingoverlay.MonitoringSecretEnv}
	cfg.Destinations.Monitoring.PayloadFormat = response.Telemetry.PayloadFormat
	cfg.Destinations.Monitoring.Compression = response.Telemetry.Compression
	cfg.Destinations.Monitoring.MaxCompressedBytes = response.Telemetry.MaxCompressedBytes
	cfg.Destinations.Monitoring.MaxUncompressedBytes = response.Telemetry.MaxUncompressedBytes
	auditEndpoint, err := monitorenrollment.AuditEndpoint(response.IngestEndpoint)
	if err != nil {
		fmt.Fprintln(c.errOut, "监控绑定响应缺少受支持的审计路由")
		return 1
	}
	cfg.Destinations.MonitoringAudit.Enabled = true
	cfg.Destinations.MonitoringAudit.URL = auditEndpoint
	cfg.Destinations.MonitoringAudit.Auth = config.AuthConfig{Mode: "hmac-sha256", KeyIDEnv: bindingoverlay.MonitoringKeyIDEnv, SecretEnv: bindingoverlay.MonitoringSecretEnv}
	cfg.Destinations.MonitoringAudit.PayloadFormat = "audit-v1"
	cfg.Destinations.MonitoringAudit.Compression = response.Telemetry.Compression
	cfg.Destinations.MonitoringAudit.MaxCompressedBytes = monitorenrollment.AuditMaxCompressedBytes
	cfg.Destinations.MonitoringAudit.MaxUncompressedBytes = monitorenrollment.AuditMaxUncompressedBytes
	if code := c.save(filename, cfg); code != 0 {
		return code
	}
	state := bindstate.MonitoringFromResponse(strings.TrimSpace(*endpoint), deviceID, response)
	if err := bindstate.SaveMonitoring(cfg.Runtime.StateDirectory, state); err != nil {
		fmt.Fprintln(c.errOut, "监控绑定密钥保存失败；可用同一绑定码安全重试")
		return 1
	}
	if err := bindstate.ClearPending(cfg.Runtime.StateDirectory, "monitoring"); err != nil {
		fmt.Fprintln(c.errOut, "监控绑定已完成，但清理 pending 标记失败")
		return 1
	}
	fmt.Fprintln(c.out, "监控绑定完成；凭据仅授权 monitoring telemetry/audit 写入，未触碰官网绑定。")
	return 0
}

func (c *cli) website(filename string, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.errOut, "website 需要 bind、status、show、test、metering、telemetry 或 control")
		return 2
	}
	// Preserve the existing top-level binding workflow exactly, including its
	// stdin-only one-time code handling and replacement safeguards.
	if args[0] == "bind" {
		return c.bind(filename, args[1:])
	}
	cfg, ok := c.load(filename)
	if !ok {
		return 1
	}
	switch args[0] {
	case "status":
		if len(args) != 1 {
			fmt.Fprintln(c.errOut, "website status 不接受额外参数")
			return 2
		}
		return c.websiteStatus(cfg)
	case "show":
		return printJSON(c.out, map[string]any{"metering": cfg.Destinations.WebsiteMetering, "telemetry": cfg.Destinations.WebsiteTelemetry, "control": cfg.Control})
	case "test":
		return c.testURLs(map[string]string{"metering": cfg.Destinations.WebsiteMetering.URL, "telemetry": cfg.Destinations.WebsiteTelemetry.URL, "controlPoll": cfg.Control.PollURL, "controlResult": cfg.Control.ResultURL})
	case "metering", "telemetry":
		if len(args) < 2 || args[1] != "set" {
			fmt.Fprintf(c.errOut, "website %s 需要 set\n", args[0])
			return 2
		}
		current := cfg.Destinations.WebsiteMetering
		if args[0] == "telemetry" {
			current = cfg.Destinations.WebsiteTelemetry
		}
		value, parsed := destinationFlags("website "+args[0]+" set", current, args[2:], c.errOut)
		if !parsed {
			return 2
		}
		if args[0] == "metering" {
			cfg.Destinations.WebsiteMetering = value
		} else {
			cfg.Destinations.WebsiteTelemetry = value
		}
		return c.save(filename, cfg)
	case "control":
		if len(args) < 2 || args[1] != "set" {
			fmt.Fprintln(c.errOut, "website control 需要 set")
			return 2
		}
		return c.controlSet(filename, cfg, args[2:])
	case "query", "modify":
		return c.reserved("website", args[0])
	default:
		fmt.Fprintf(c.errOut, "未知 website 操作 %q\n", args[0])
		return 2
	}
}

func (c *cli) websiteStatus(cfg config.Config) int {
	result := map[string]any{}
	exitCode := 0
	state, stateErr := bindstate.Load(cfg.Runtime.StateDirectory)
	if stateErr != nil {
		result["binding"] = map[string]any{"available": false, "code": "WEBSITE_BINDING_UNAVAILABLE"}
		exitCode = 1
	} else {
		assignmentState, assignmentErr := assignment.LoadState(filepath.Join(cfg.Runtime.StateDirectory, "assignments", "refresh-state.json"))
		assignmentRevision := assignmentState.Revision
		binding := map[string]any{
			"bindingId": state.BindingID, "deviceId": state.DeviceID, "agentRef": state.Identity.AgentRef,
			"credentialEpoch": fmt.Sprintf("%d", state.CredentialEpoch), "issuedAt": state.IssuedAt,
		}
		if assignmentRevision > 0 {
			binding["assignmentRevision"] = fmt.Sprintf("%d", assignmentRevision)
		}
		result["binding"] = binding
		if assignmentErr != nil || assignmentRevision == 0 {
			result["remoteWebsite"] = map[string]any{"available": false, "code": "LOCAL_ASSIGNMENT_STATE_UNAVAILABLE"}
			exitCode = 1
		} else {
			client, err := enrollment.NewStatusClient(enrollment.StatusClientConfig{
				BindingEndpoint: state.BindingEndpoint, Credential: state.HMACCredentials.Commands, NetworkPolicy: state.NetworkPolicy,
			})
			if err == nil {
				var remote enrollment.StatusResponse
				remote, err = client.Get(context.Background(), enrollment.StatusExpected{
					BindingID: state.BindingID, DeviceID: state.DeviceID, AgentRef: state.Identity.AgentRef,
					CredentialEpoch: state.CredentialEpoch, AssignmentRevision: assignmentRevision,
				})
				if err == nil {
					result["remoteWebsite"] = remote
				}
			}
			if err != nil {
				result["remoteWebsite"] = map[string]any{"available": false, "code": "REMOTE_STATUS_UNAVAILABLE"}
				exitCode = 1
			}
		}
	}
	if local, err := fetchLocalStatus(cfg); err == nil {
		result["localAgent"] = local
	} else {
		result["localAgent"] = map[string]any{"available": false, "code": "LOCAL_AGENT_UNREACHABLE"}
		exitCode = 1
	}
	if _, ok := result["remoteWebsite"]; !ok {
		result["remoteWebsite"] = map[string]any{"available": false, "code": "REMOTE_STATUS_UNAVAILABLE"}
	}
	if printJSON(c.out, result) != 0 {
		return 1
	}
	return exitCode
}

type templateRole struct {
	Allowed bool     `json:"allowed"`
	Reasons []string `json:"reasons"`
}

type templateStorage struct {
	StorageID           string   `json:"storageId"`
	Type                string   `json:"type"`
	ContentTypes        []string `json:"contentTypes"`
	Enabled             bool     `json:"enabled"`
	Active              bool     `json:"active"`
	Shared              bool     `json:"shared"`
	AvailableBytes      string   `json:"availableBytes"`
	AvailableBytesKnown bool     `json:"availableBytesKnown"`
	RoleEligibility     struct {
		Image    templateRole `json:"image"`
		Template templateRole `json:"template"`
		Backup   templateRole `json:"backup"`
	} `json:"roleEligibility"`
	Remediations []templateRemediation `json:"remediations"`
}

type templateRemediationCommand struct {
	Program string   `json:"program"`
	Argv    []string `json:"argv"`
}

type templateRemediation struct {
	Code            string                     `json:"code"`
	StorageID       string                     `json:"storageId"`
	CurrentContent  string                     `json:"currentContent"`
	RequiredContent string                     `json:"requiredContent"`
	ProposedContent string                     `json:"proposedContent"`
	Command         templateRemediationCommand `json:"command"`
	Automatic       *bool                      `json:"automatic"`
}

type templateDiscovery struct {
	SchemaVersion string            `json:"schemaVersion"`
	Mode          string            `json:"mode"`
	State         string            `json:"state"`
	Storages      []templateStorage `json:"storages"`
}

type templateCatalog struct {
	CatalogSHA256 string `json:"catalogSha256"`
	Catalog       struct {
		CatalogRevision string `json:"catalogRevision"`
		Items           []struct {
			TemplateRef string   `json:"templateRef"`
			Version     string   `json:"version"`
			DisplayName string   `json:"displayName"`
			Aliases     []string `json:"aliases"`
			Target      struct {
				VMID int `json:"vmid"`
			} `json:"target"`
		} `json:"items"`
	} `json:"catalog"`
}

type templatePlan struct {
	State      string `json:"state"`
	Executable bool   `json:"executable"`
	Catalog    struct {
		CatalogRevision string `json:"catalogRevision"`
		CatalogSHA256   string `json:"catalogSha256"`
	} `json:"catalog"`
}

func (c *cli) template(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.errOut, "template 需要 init、catalog、discover 或 bootstrap")
		return 2
	}
	if args[0] == "init" {
		if len(args) != 1 {
			fmt.Fprintln(c.errOut, "template init 不接受额外参数；所有选择在交互确认中完成")
			return 2
		}
		return c.templateInit()
	}
	if args[0] != "catalog" && args[0] != "discover" && args[0] != "bootstrap" {
		fmt.Fprintf(c.errOut, "未知 template 操作 %q\n", args[0])
		return 2
	}
	result, err := (templatebootstrap.Runner{}).Run(context.Background(), args, c.errOut)
	if err != nil {
		fmt.Fprintf(c.errOut, "模板工具不可用: %v\n", err)
		return 1
	}
	if _, err := c.out.Write(result.Stdout); err != nil {
		return 1
	}
	if result.ExitCode < 0 || result.ExitCode > 125 {
		return 1
	}
	return result.ExitCode
}

func (c *cli) templateInit() int {
	ctx := context.Background()
	discovery, code, err := c.discoverTemplateStorages(ctx)
	if err != nil {
		fmt.Fprintf(c.errOut, "PVE 存储发现失败: %v\n", err)
		return code
	}
	if len(discovery.Storages) == 0 {
		fmt.Fprintln(c.errOut, "PVE 没有返回任何存储")
		return 1
	}
	catalogResult, err := c.runTemplateBootstrap(ctx, []string{"catalog"})
	if err != nil || catalogResult.ExitCode != 0 {
		fmt.Fprintln(c.errOut, "内置模板目录校验失败")
		return 1
	}
	var catalog templateCatalog
	if json.Unmarshal(catalogResult.Stdout, &catalog) != nil || catalog.Catalog.CatalogRevision == "" || catalog.CatalogSHA256 == "" || len(catalog.Catalog.Items) == 0 {
		fmt.Fprintln(c.errOut, "内置模板目录结果无效")
		return 1
	}
	reader := bufio.NewReader(io.LimitReader(c.in, 64<<10))
	fmt.Fprintf(c.out, "PPFlight 模板初始化  catalog=%s  sha256=%s\n", catalog.Catalog.CatalogRevision, catalog.CatalogSHA256)
	for index, item := range catalog.Catalog.Items {
		fmt.Fprintf(c.out, "  %d) %s  %s  VMID=%d\n", index+1, item.DisplayName, item.Version, item.Target.VMID)
	}
	items, err := c.promptTemplateItems(reader, catalog)
	if err != nil {
		fmt.Fprintf(c.errOut, "模板选择无效: %v\n", err)
		return 2
	}
	imageStorage, refreshed, err := c.chooseTemplateStorage(ctx, reader, discovery.Storages, "image", "选择镜像缓存存储")
	if err != nil {
		fmt.Fprintf(c.errOut, "镜像存储选择失败: %v\n", err)
		return 2
	}
	discovery.Storages = refreshed
	templateStorage, refreshed, err := c.chooseTemplateStorage(ctx, reader, discovery.Storages, "template", "选择模板磁盘存储")
	if err != nil {
		fmt.Fprintf(c.errOut, "模板存储选择失败: %v\n", err)
		return 2
	}
	discovery.Storages = refreshed
	backupAnswer, err := c.promptLine(reader, "创建完成后备份模板？[Y/n]: ")
	if err != nil {
		return 2
	}
	backupPolicy, backupStorage := "required", ""
	if strings.EqualFold(backupAnswer, "n") || strings.EqualFold(backupAnswer, "no") {
		backupPolicy = "disabled"
	} else {
		backupStorage, refreshed, err = c.chooseTemplateStorage(ctx, reader, discovery.Storages, "backup", "选择模板备份存储")
		if err != nil {
			fmt.Fprintf(c.errOut, "备份存储选择失败: %v\n", err)
			return 2
		}
		discovery.Storages = refreshed
	}
	bridge, err := c.promptLine(reader, "模板默认网桥 [vmbr0]: ")
	if err != nil {
		return 2
	}
	if bridge == "" {
		bridge = "vmbr0"
	}
	requestID, err := protocol.NewID()
	if err != nil {
		return 1
	}
	operationID, err := protocol.NewID()
	if err != nil {
		return 1
	}
	baseArgs := []string{"bootstrap", "--image-storage", imageStorage, "--template-storage", templateStorage, "--backup-policy", backupPolicy, "--items", items, "--bridge", bridge, "--request-id", requestID, "--operation-id", operationID}
	if backupPolicy == "required" {
		baseArgs = append(baseArgs, "--backup-storage", backupStorage)
	}
	planResult, err := c.runTemplateBootstrap(ctx, baseArgs)
	if err != nil {
		fmt.Fprintf(c.errOut, "模板计划失败: %v\n", err)
		return 1
	}
	_, _ = c.out.Write(planResult.Stdout)
	var plan templatePlan
	if json.Unmarshal(planResult.Stdout, &plan) != nil || planResult.ExitCode != 0 || !plan.Executable || plan.State != "ready" || plan.Catalog.CatalogRevision == "" || plan.Catalog.CatalogSHA256 == "" {
		return max(planResult.ExitCode, 1)
	}
	confirmation, err := c.promptLine(reader, "核对以上计划后输入 EXECUTE 执行；直接回车仅保留计划: ")
	if err != nil || confirmation != "EXECUTE" {
		fmt.Fprintln(c.out, "未执行任何模板变更。")
		return 0
	}
	executeArgs := append(append([]string(nil), baseArgs...), "--execute", "--expected-catalog-revision", plan.Catalog.CatalogRevision, "--expected-catalog-sha256", plan.Catalog.CatalogSHA256)
	executeResult, err := c.runTemplateBootstrap(ctx, executeArgs)
	if err != nil {
		fmt.Fprintf(c.errOut, "模板执行器失败: %v\n", err)
		return 1
	}
	_, _ = c.out.Write(executeResult.Stdout)
	return executeResult.ExitCode
}

func (c *cli) runTemplateBootstrap(ctx context.Context, args []string) (templatebootstrap.Result, error) {
	if c.templateRun != nil {
		return c.templateRun(ctx, args, c.errOut)
	}
	return (templatebootstrap.Runner{}).Run(ctx, args, c.errOut)
}

func (c *cli) discoverTemplateStorages(ctx context.Context) (templateDiscovery, int, error) {
	result, err := c.runTemplateBootstrap(ctx, []string{"discover"})
	if err != nil {
		return templateDiscovery{}, 1, fmt.Errorf("存储发现工具不可用: %w", err)
	}
	if result.ExitCode != 0 {
		_, _ = c.out.Write(result.Stdout)
		return templateDiscovery{}, result.ExitCode, errors.New("存储发现命令失败")
	}
	discovery, err := decodeTemplateDiscovery(result.Stdout)
	if err != nil {
		return templateDiscovery{}, 1, errors.New("存储发现结果无效")
	}
	return discovery, 0, nil
}

func (c *cli) promptTemplateItems(reader *bufio.Reader, catalog templateCatalog) (string, error) {
	value, err := c.promptLine(reader, "选择模板（all 或逗号分隔编号/templateRef）[all]: ")
	if err != nil || value == "" || strings.EqualFold(value, "all") {
		return "all", err
	}
	parts := strings.Split(value, ",")
	for index := range parts {
		part := strings.TrimSpace(parts[index])
		var number int
		if _, scanErr := fmt.Sscanf(part, "%d", &number); scanErr == nil && fmt.Sprintf("%d", number) == part {
			if number < 1 || number > len(catalog.Catalog.Items) {
				return "", errors.New("模板编号超出范围")
			}
			part = catalog.Catalog.Items[number-1].TemplateRef
		}
		if part == "" {
			return "", errors.New("模板选择包含空值")
		}
		parts[index] = part
	}
	return strings.Join(parts, ","), nil
}

type templateStorageChoice struct {
	StorageID   string
	Storage     templateStorage
	Remediation *templateRemediation
}

func templateRoleState(storage templateStorage, role string) templateRole {
	switch role {
	case "template":
		return storage.RoleEligibility.Template
	case "backup":
		return storage.RoleEligibility.Backup
	default:
		return storage.RoleEligibility.Image
	}
}

func roleRequiredContent(role string) []string {
	switch role {
	case "image":
		return []string{"iso", "snippets"}
	case "template":
		return []string{"images"}
	case "backup":
		return []string{"backup"}
	default:
		return nil
	}
}

func templateRolePurpose(role string) string {
	switch role {
	case "image":
		return "保存下载的系统镜像和 Cloud-Init 配置文件"
	case "template":
		return "保存克隆完成后的 PVE 虚拟机模板磁盘"
	case "backup":
		return "保存模板创建完成后的备份文件"
	default:
		return "模板初始化存储"
	}
}

func templateRoleLabel(role string) string {
	switch role {
	case "image":
		return "镜像缓存"
	case "template":
		return "模板磁盘"
	case "backup":
		return "模板备份"
	default:
		return "存储"
	}
}

func humanStorageContentCSV(value string) string {
	if value == "" {
		return "无"
	}
	parts := strings.Split(value, ",")
	labels := make([]string, 0, len(parts))
	for _, part := range parts {
		label := map[string]string{
			"backup":   "备份",
			"images":   "虚拟机磁盘",
			"iso":      "ISO 镜像",
			"rootdir":  "容器磁盘",
			"snippets": "Cloud-Init 配置",
			"vztmpl":   "LXC 模板",
		}[part]
		if label == "" {
			label = part
		}
		labels = append(labels, fmt.Sprintf("%s (%s)", label, part))
	}
	return strings.Join(labels, "、")
}

func humanAvailableBytes(value string, known bool) string {
	if !known {
		return "未知"
	}
	bytesValue, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return "未知"
	}
	const (
		gib = uint64(1 << 30)
		tib = uint64(1 << 40)
	)
	if bytesValue >= tib {
		return fmt.Sprintf("%.2f TiB", float64(bytesValue)/float64(tib))
	}
	if bytesValue >= gib {
		return fmt.Sprintf("%.1f GiB", float64(bytesValue)/float64(gib))
	}
	return fmt.Sprintf("%d MiB", bytesValue/(1<<20))
}

func remediationForTemplateRole(storage templateStorage, role string) *templateRemediation {
	roleState := templateRoleState(storage, role)
	if !storage.Active || !storage.Enabled || roleState.Allowed || len(roleState.Reasons) == 0 {
		return nil
	}
	for _, reason := range roleState.Reasons {
		if !strings.HasPrefix(reason, "MISSING_CONTENT_") {
			return nil
		}
	}
	for index := range storage.Remediations {
		remediation := &storage.Remediations[index]
		if !validTemplateRemediation(storage, *remediation) {
			continue
		}
		proposed, ok := parseContentCSV(remediation.ProposedContent, false)
		if !ok {
			continue
		}
		matches := true
		for _, required := range roleRequiredContent(role) {
			if _, exists := proposed[required]; !exists {
				matches = false
				break
			}
		}
		if matches {
			copy := *remediation
			copy.Command.Argv = append([]string(nil), remediation.Command.Argv...)
			return &copy
		}
	}
	return nil
}

func (c *cli) promptTemplateStorage(reader *bufio.Reader, storages []templateStorage, role, title string) (templateStorageChoice, error) {
	candidates := make([]templateStorageChoice, 0, len(storages))
	for _, storage := range storages {
		if templateRoleState(storage, role).Allowed {
			candidates = append(candidates, templateStorageChoice{StorageID: storage.StorageID, Storage: storage})
		} else if remediation := remediationForTemplateRole(storage, role); remediation != nil {
			candidates = append(candidates, templateStorageChoice{StorageID: storage.StorageID, Storage: storage, Remediation: remediation})
		}
	}
	if len(candidates) == 0 {
		fmt.Fprintf(c.out, "%s：当前没有符合条件或可安全配置的存储。Agent 未修改任何 PVE storage 配置。\n", title)
		for _, storage := range storages {
			roleState := templateRoleState(storage, role)
			fmt.Fprintf(c.out, "  - %s active=%t enabled=%t content=%s 原因=%s\n", storage.StorageID, storage.Active, storage.Enabled, strings.Join(storage.ContentTypes, ","), strings.Join(roleState.Reasons, ","))
			for _, remediation := range storage.Remediations {
				if !validTemplateRemediation(storage, remediation) {
					fmt.Fprintln(c.out, "    存储发现返回了不安全或不一致的配置建议，Agent 已拒绝使用。")
				}
			}
		}
		return templateStorageChoice{}, errors.New("没有符合该角色的 active/enabled 存储")
	}
	fmt.Fprintln(c.out, title+":")
	fmt.Fprintf(c.out, "  用途：%s\n", templateRolePurpose(role))
	for index, candidate := range candidates {
		storage := candidate.Storage
		fmt.Fprintf(c.out, "\n  %d) %s\n", index+1, storage.StorageID)
		fmt.Fprintf(c.out, "     类型：%s    共享：%s\n", storage.Type, map[bool]string{true: "是", false: "否"}[storage.Shared])
		fmt.Fprintf(c.out, "     可用空间：%s\n", humanAvailableBytes(storage.AvailableBytes, storage.AvailableBytesKnown))
		fmt.Fprintf(c.out, "     当前能力：%s\n", humanStorageContentCSV(strings.Join(storage.ContentTypes, ",")))
		if candidate.Remediation != nil {
			fmt.Fprintf(c.out, "     选择后新增：%s（不会删除现有能力）\n", humanStorageContentCSV(candidate.Remediation.RequiredContent))
		} else {
			fmt.Fprintln(c.out, "     状态：可直接使用")
		}
	}
	fmt.Fprintln(c.out)
	value, err := c.promptLine(reader, "请输入编号（也可输入 storage ID）: ")
	if err != nil {
		return templateStorageChoice{}, err
	}
	for index, candidate := range candidates {
		if value == candidate.StorageID || value == fmt.Sprintf("%d", index+1) {
			return candidate, nil
		}
	}
	return templateStorageChoice{}, errors.New("选择不在可用列表中")
}

func (c *cli) chooseTemplateStorage(ctx context.Context, reader *bufio.Reader, storages []templateStorage, role, title string) (string, []templateStorage, error) {
	choice, err := c.promptTemplateStorage(reader, storages, role, title)
	if err != nil {
		return "", storages, err
	}
	if choice.Remediation == nil {
		fmt.Fprintf(c.out, "已选择 %s：%s\n", templateRoleLabel(role), choice.StorageID)
		return choice.StorageID, storages, nil
	}
	remediation := *choice.Remediation
	fmt.Fprintf(c.out, "\n已选择 %s：%s\n", templateRoleLabel(role), choice.StorageID)
	fmt.Fprintf(c.out, "  当前能力：%s\n", humanStorageContentCSV(remediation.CurrentContent))
	fmt.Fprintf(c.out, "  需要新增：%s\n", humanStorageContentCSV(remediation.RequiredContent))
	fmt.Fprintf(c.out, "  完成以后：%s\n", humanStorageContentCSV(remediation.ProposedContent))
	fmt.Fprintln(c.out, "  说明：只增加上述能力，不删除当前已有内容或数据。")
	fmt.Fprintf(c.out, "  底层命令：%s %s %s\n", remediation.Command.Argv[0], remediation.Command.Argv[1], remediation.Command.Argv[2])
	fmt.Fprintf(c.out, "            %s %s\n", remediation.Command.Argv[3], remediation.Command.Argv[4])
	confirmation, err := c.promptLine(reader, "输入 Y 确认配置并继续 [y/N]: ")
	if err != nil || !strings.EqualFold(confirmation, "y") {
		return "", storages, errors.New("未确认 storage content 配置，未执行任何变更")
	}
	if err := c.applyTemplateRemediation(ctx, choice.Storage, remediation); err != nil {
		return "", storages, err
	}
	refreshed, _, err := c.discoverTemplateStorages(ctx)
	if err != nil {
		return "", storages, fmt.Errorf("storage content 已提交，但重新检测失败: %w", err)
	}
	for _, storage := range refreshed.Storages {
		if storage.StorageID == choice.StorageID {
			if !storage.Active || !storage.Enabled || !templateRoleState(storage, role).Allowed {
				return "", refreshed.Storages, errors.New("重新检测后所选存储仍不满足该用途")
			}
			fmt.Fprintf(c.out, "存储 %s 已配置并通过重新检测。\n", choice.StorageID)
			return choice.StorageID, refreshed.Storages, nil
		}
	}
	return "", refreshed.Storages, errors.New("重新检测后所选存储不存在")
}

func (c *cli) applyTemplateRemediation(ctx context.Context, storage templateStorage, remediation templateRemediation) error {
	if !validTemplateRemediation(storage, remediation) {
		return errors.New("storage content 配置指令未通过安全校验")
	}
	if c.pvesmSetContent != nil {
		return c.pvesmSetContent(ctx, storage.StorageID, remediation.ProposedContent)
	}
	command := exec.CommandContext(ctx, "/usr/sbin/pvesm", "set", storage.StorageID, "--content", remediation.ProposedContent)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
	output, err := command.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if len(message) > 4096 {
			message = message[:4096]
		}
		if message == "" {
			message = err.Error()
		}
		return fmt.Errorf("pvesm 配置失败: %s", message)
	}
	return nil
}

func safeStorageID(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || index > 0 && strings.ContainsRune("._-", character) {
			continue
		}
		return false
	}
	return true
}

func decodeTemplateDiscovery(raw []byte) (templateDiscovery, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var discovery templateDiscovery
	if err := decoder.Decode(&discovery); err != nil {
		return templateDiscovery{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return templateDiscovery{}, errors.New("存储发现结果包含额外 JSON")
	}
	if discovery.SchemaVersion != "ppflight.template-bootstrap-result/v1" || discovery.Mode != "discover" || discovery.State != "succeeded" {
		return templateDiscovery{}, errors.New("存储发现身份无效")
	}
	for _, storage := range discovery.Storages {
		if !safeStorageID(storage.StorageID) || storage.Remediations == nil {
			return templateDiscovery{}, errors.New("存储发现字段不完整")
		}
		if _, ok := contentSet(storage.ContentTypes); !ok {
			return templateDiscovery{}, errors.New("存储 content 类型无效")
		}
		for _, remediation := range storage.Remediations {
			if !validTemplateRemediation(storage, remediation) {
				return templateDiscovery{}, errors.New("存储修复建议与冻结命令不一致")
			}
		}
	}
	return discovery, nil
}

func validTemplateRemediation(storage templateStorage, remediation templateRemediation) bool {
	if remediation.Code != "ENABLE_STORAGE_CONTENT" || remediation.StorageID != storage.StorageID || remediation.Automatic == nil || *remediation.Automatic || remediation.Command.Program != "pvesm" || len(remediation.Command.Argv) != 5 {
		return false
	}
	argv := remediation.Command.Argv
	if argv[0] != remediation.Command.Program || argv[1] != "set" || argv[2] != storage.StorageID || argv[3] != "--content" || argv[4] != remediation.ProposedContent {
		return false
	}
	current, ok := parseContentCSV(remediation.CurrentContent, true)
	if !ok {
		return false
	}
	required, ok := parseContentCSV(remediation.RequiredContent, false)
	if !ok {
		return false
	}
	proposed, ok := parseContentCSV(remediation.ProposedContent, false)
	if !ok {
		return false
	}
	storageContent, ok := contentSet(storage.ContentTypes)
	if !ok || !sameContentSet(current, storageContent) {
		return false
	}
	expected := make(map[string]struct{}, len(current)+len(required))
	for value := range current {
		expected[value] = struct{}{}
	}
	for value := range required {
		if value != "iso" && value != "snippets" {
			return false
		}
		if _, exists := current[value]; exists {
			return false
		}
		expected[value] = struct{}{}
	}
	return sameContentSet(proposed, expected)
}

func parseContentCSV(value string, allowEmpty bool) (map[string]struct{}, bool) {
	if value == "" {
		return map[string]struct{}{}, allowEmpty
	}
	return contentSet(strings.Split(value, ","))
}

func contentSet(values []string) (map[string]struct{}, bool) {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !safeContentType(value) {
			return nil, false
		}
		if _, exists := result[value]; exists {
			return nil, false
		}
		result[value] = struct{}{}
	}
	return result, true
}

func safeContentType(value string) bool {
	if value == "" || len(value) > 32 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func sameContentSet(left, right map[string]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for value := range left {
		if _, exists := right[value]; !exists {
			return false
		}
	}
	return true
}

func (c *cli) promptLine(reader *bufio.Reader, prompt string) (string, error) {
	fmt.Fprint(c.out, prompt)
	value, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	value = strings.TrimSpace(value)
	if len(value) > 2048 {
		return "", errors.New("输入过长")
	}
	return value, nil
}

func (c *cli) reserved(target, operation string) int {
	fmt.Fprintf(c.errOut, "%s %s：远程资产接口已预留，但 v0.1 尚未实现；本命令未发送请求、未修改任何远端数据。\n", target, operation)
	return 3
}

func destinationFlags(name string, current config.DestinationConfig, args []string, output io.Writer) (config.DestinationConfig, bool) {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(output)
	enabled := set.Bool("enabled", current.Enabled, "enable destination")
	endpoint := set.String("url", current.URL, "destination URL")
	authMode := set.String("auth-mode", current.Auth.Mode, "hmac-sha256, bearer, or test-only none")
	keyEnv := set.String("key-id-env", current.Auth.KeyIDEnv, "HMAC key ID environment name")
	secretEnv := set.String("secret-env", current.Auth.SecretEnv, "HMAC secret environment name")
	bearerEnv := set.String("bearer-token-env", current.Auth.BearerTokenEnv, "Bearer environment name")
	compression := set.String("compression", current.Compression, "none or gzip")
	payloadFormat := set.String("payload-format", current.PayloadFormat, "usage-v1, telemetry-v1, or legacy-ingest-v1")
	if err := set.Parse(args); err != nil || set.NArg() != 0 {
		return current, false
	}
	current.Enabled, current.URL, current.Compression, current.PayloadFormat = *enabled, strings.TrimSpace(*endpoint), *compression, *payloadFormat
	current.Auth = config.AuthConfig{Mode: *authMode, KeyIDEnv: *keyEnv, SecretEnv: *secretEnv, BearerTokenEnv: *bearerEnv}
	return current, true
}

func (c *cli) controlSet(filename string, cfg config.Config, args []string) int {
	set := flag.NewFlagSet("website control set", flag.ContinueOnError)
	set.SetOutput(c.errOut)
	enabled := set.Bool("enabled", cfg.Control.Enabled, "enable control channel")
	poll := set.String("poll-url", cfg.Control.PollURL, "command polling URL")
	result := set.String("result-url", cfg.Control.ResultURL, "receipt URL")
	authMode := set.String("auth-mode", cfg.Control.Auth.Mode, "HMAC/bearer/none auth mode")
	keyEnv := set.String("key-id-env", cfg.Control.Auth.KeyIDEnv, "API HMAC key ID environment name")
	secretEnv := set.String("secret-env", cfg.Control.Auth.SecretEnv, "API HMAC secret environment name")
	bearerEnv := set.String("bearer-token-env", cfg.Control.Auth.BearerTokenEnv, "API Bearer environment name")
	commandEnv := set.String("command-secret-env", cfg.Control.CommandSecretEnv, "command signature secret environment name")
	production := set.Bool("production-execution", cfg.Control.ProductionExecution, "allow real PVE writes")
	if err := set.Parse(args); err != nil || set.NArg() != 0 {
		return 2
	}
	cfg.Control.Enabled, cfg.Control.PollURL, cfg.Control.ResultURL, cfg.Control.ProductionExecution = *enabled, strings.TrimSpace(*poll), strings.TrimSpace(*result), *production
	cfg.Control.Auth = config.AuthConfig{Mode: *authMode, KeyIDEnv: *keyEnv, SecretEnv: *secretEnv, BearerTokenEnv: *bearerEnv}
	cfg.Control.CommandSecretEnv = *commandEnv
	return c.save(filename, cfg)
}

func (c *cli) save(filename string, cfg config.Config) int {
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(c.errOut, "修改无效，未写入: %v\n", err)
		return 1
	}
	backup, err := atomicUpdate(filename, cfg)
	if err != nil {
		fmt.Fprintf(c.errOut, "配置保存失败: %v\n", err)
		return 1
	}
	fmt.Fprintf(c.out, "配置已更新，备份为 %s\n请执行 ag-pve validate；确认后手动 systemctl restart ppflight-agent。\n", backup)
	return 0
}

func atomicUpdate(filename string, cfg config.Config) (string, error) {
	lock, err := os.OpenFile(filename+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return "", err
	}
	defer lock.Close()
	if err := fsutil.LockExclusive(lock); err != nil {
		return "", err
	}
	defer fsutil.Unlock(lock)
	info, err := os.Lstat(filename)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("refusing to replace a symlink or non-regular config file")
	}
	original, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	backup := filename + ".bak." + time.Now().UTC().Format("20060102T150405.000000000Z")
	if err := os.WriteFile(backup, original, info.Mode().Perm()); err != nil {
		return "", err
	}
	backupHandle, err := os.OpenFile(backup, os.O_RDWR, 0)
	if err != nil {
		return "", err
	}
	if err := backupHandle.Sync(); err != nil {
		_ = backupHandle.Close()
		return "", err
	}
	if err := backupHandle.Close(); err != nil {
		return "", err
	}
	_ = fsutil.CopyOwnership(backup, info)
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	raw = append(raw, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(filename), ".agent-config-")
	if err != nil {
		return "", err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(info.Mode().Perm()); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := fsutil.CopyOwnership(name, info); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if _, err := temporary.Write(raw); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(name, filename); err != nil {
		return "", err
	}
	if err := fsutil.SyncDir(filepath.Dir(filename)); err != nil {
		return "", err
	}
	return backup, nil
}

func (c *cli) testURLs(values map[string]string) int {
	failed := false
	for name, raw := range values {
		if raw == "" {
			fmt.Fprintf(c.out, "%s: 未配置（远程 API 接口已预留）\n", name)
			continue
		}
		result, err := probe(raw, 8*time.Second)
		if err != nil {
			failed = true
			fmt.Fprintf(c.errOut, "%s: 失败: %v\n", name, err)
			continue
		}
		fmt.Fprintf(c.out, "%s: %s\n", name, result)
	}
	if failed {
		return 1
	}
	return 0
}

func probe(raw string, timeout time.Duration) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" || netpolicy.ValidateIPv4URL(parsed) != nil {
		return "", errors.New("URL 无效")
	}
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else if parsed.Scheme == "http" {
			port = "80"
		} else {
			return "", errors.New("仅支持 http/https")
		}
	}
	address := net.JoinHostPort(parsed.Hostname(), port)
	started := time.Now()
	dialer := &net.Dialer{Timeout: timeout}
	if parsed.Scheme == "https" {
		conn, err := tls.DialWithDialer(dialer, "tcp4", address, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: parsed.Hostname()})
		if err != nil {
			return "", err
		}
		defer conn.Close()
		state := conn.ConnectionState()
		expiry := "unknown"
		if len(state.PeerCertificates) > 0 {
			expiry = state.PeerCertificates[0].NotAfter.UTC().Format(time.RFC3339)
		}
		return fmt.Sprintf("连接成功 address=%s tls=%s certificateNotAfter=%s latency=%s", address, tlsName(state.Version), expiry, time.Since(started).Round(time.Millisecond)), nil
	}
	conn, err := dialer.DialContext(context.Background(), "tcp4", address)
	if err != nil {
		return "", err
	}
	_ = conn.Close()
	return fmt.Sprintf("连接成功 address=%s latency=%s", address, time.Since(started).Round(time.Millisecond)), nil
}

func tlsName(v uint16) string {
	if v == tls.VersionTLS13 {
		return "TLS1.3"
	}
	if v == tls.VersionTLS12 {
		return "TLS1.2"
	}
	return fmt.Sprintf("0x%x", v)
}
func printJSON(out io.Writer, value any) int {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return 1
	}
	fmt.Fprintln(out, string(raw))
	return 0
}
