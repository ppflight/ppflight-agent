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
	"reflect"
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
	"github.com/ppflight/ppflight-agent/internal/exporter"
	"github.com/ppflight/ppflight-agent/internal/fsutil"
	"github.com/ppflight/ppflight-agent/internal/health"
	"github.com/ppflight/ppflight-agent/internal/hostfirewall"
	"github.com/ppflight/ppflight-agent/internal/inventory"
	"github.com/ppflight/ppflight-agent/internal/monitorenrollment"
	"github.com/ppflight/ppflight-agent/internal/netpolicy"
	"github.com/ppflight/ppflight-agent/internal/protocol"
	"github.com/ppflight/ppflight-agent/internal/pve"
	"github.com/ppflight/ppflight-agent/internal/templatebootstrap"
)

type cli struct {
	in                io.Reader
	out, errOut       io.Writer
	version           string
	pveEnvironment    func(string) (map[string]string, error)
	pveProbe          func(context.Context, pve.Config, bool, string) (rawCredentialProbe, error)
	effectiveUID      func() int
	tlsServerName     func() string
	templateRun       func(context.Context, []string, io.Writer) (templatebootstrap.Result, error)
	pvesmSetContent   func(context.Context, string, string) error
	templateBridges   templateBridgeManager
	pveVersion        func(context.Context) (string, error)
	pveBootstrap      func(context.Context) error
	pveReadACL        func(context.Context) error
	pveControlACL     func(context.Context) error
	pveNodeName       func() (string, error)
	pveTLSPreflight   func(context.Context, string, string) error
	exporterProbe     func(context.Context, config.ExportersConfig) error
	bindingPVE        func(context.Context, string, config.Config) (config.Config, error)
	bindingCodePrompt func() (string, error)
	activatePVE       func(context.Context, config.Config) error
	activateBinding   func(context.Context, config.Config, bindingActivationExpectation) error
	// armBinding is a test-only boundary for the systemd start --no-block
	// activation arm. Production callers leave it nil.
	armBinding          func(context.Context) error
	finishBindingCommit func(stateDirectory, domain string) error
	clearBindingPending func(stateDirectory, domain string) error
	// restartUnbind is the test boundary for the systemd restart-and-arm job
	// used by the durable unbind transaction. Production callers leave it nil.
	restartUnbind     func(context.Context) error
	writeUnbindConfig func(string, config.Config) (string, error)
	removeUnbindState func(string, string) error
	finishUnbind      func(string, string) error
	// quiesceBinding is a test-only boundary for the systemd stop/verify
	// operation. Production callers leave it nil and use the fixed systemd
	// commands in binding_activation.go.
	quiesceBinding    func(context.Context) error
	completeUninstall func(context.Context) error
	completeUpdate    func(context.Context) (string, error)
	// managedWritePolicy is an explicit in-process test/embedding boundary for
	// production-path ownership validation. Real CLI construction leaves it nil
	// and therefore always uses the fixed installer paths on Linux root.
	managedWritePolicy func(string, config.Config) error
}

func (c *cli) verifyLocalExporters(ctx context.Context, exporters config.ExportersConfig) error {
	if c.exporterProbe != nil {
		return c.exporterProbe(ctx, exporters)
	}
	// Tests and embedded callers that replace the complete activation boundary
	// do not own real loopback exporter services. Production never injects that
	// boundary and must pass the same parser/normalizer used by the Agent before
	// a configuration can be reported ready.
	if c.activatePVE != nil {
		return nil
	}
	return verifyLocalExporterData(ctx, exporters)
}

func verifyLocalExporterData(ctx context.Context, exporters config.ExportersConfig) error {
	nodeSamples, err := exporter.Fetch(ctx, exporter.FetchConfig{
		URL: exporters.Node.URL, Timeout: exporters.Node.Timeout.Duration, MaxBodyBytes: exporters.Node.MaxResponseBytes,
	})
	if err != nil {
		return errors.New("node exporter response failed Agent parsing")
	}
	host := exporter.NormalizeHost(nodeSamples, time.Now().UTC())
	hasInterface := false
	for _, item := range host.Interfaces {
		if _, receiveOK := exporter.CounterText(item.ReceiveBytes); receiveOK {
			if _, transmitOK := exporter.CounterText(item.TransmitBytes); !transmitOK {
				continue
			}
			hasInterface = true
			break
		}
	}
	hasDisk := false
	for _, item := range host.Disks {
		if _, readOK := exporter.CounterText(item.ReadBytes); readOK {
			if _, writeOK := exporter.CounterText(item.WrittenBytes); !writeOK {
				continue
			}
			hasDisk = true
			break
		}
	}
	if !hasInterface || !hasDisk {
		return errors.New("node exporter lacks parsed network or disk counters")
	}
	smartSamples, err := exporter.Fetch(ctx, exporter.FetchConfig{
		URL: exporters.SMART.URL, Timeout: exporters.SMART.Timeout.Duration, MaxBodyBytes: exporters.SMART.MaxResponseBytes,
	})
	if err != nil {
		return errors.New("smartctl exporter response failed Agent parsing")
	}
	smart := exporter.NormalizeSMART(smartSamples, time.Now().UTC())
	if len(smart.Devices) == 0 {
		return errors.New("smartctl exporter has no parsed physical devices")
	}
	return nil
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
	case "overview":
		return c.systemOverview(*filename)
	case "monitor", "monitoring":
		return c.monitoring(*filename, args[1:])
	case "website":
		return c.website(*filename, args[1:])
	case "template", "templates":
		return c.template(args[1:])
	case "pve":
		return c.pve(*filename, args[1:])
	case "uninstall":
		return c.menuCompleteUninstallAt(bufio.NewReader(io.LimitReader(c.in, 64<<10)), *filename)
	case "update", "upgrade":
		return c.update(args[1:])
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
  AG | ag | ag-pve                                   # 六项主菜单；含系统概况和一键更新
  ag-pve [--config FILE] validate
  ag-pve [--config FILE] overview                    # 系统、PVE、绑定、通信和队列概况
  ag-pve [--config FILE] pve prepare [--tls-server-name DNS_NAME] [--ca-file FILE] [--local-only]
  ag-pve [--config FILE] pve status
  ag-pve [--config FILE] bind --endpoint HTTPS_URL [--code-file FILE] [--replace]
  ag-pve [--config FILE] website bind --endpoint HTTPS_URL [--code-file FILE] [--replace]
  ag-pve [--config FILE] website status
  ag-pve [--config FILE] website unbind
  ag-pve [--config FILE] monitoring preflight --endpoint HTTPS_URL
  ag-pve [--config FILE] monitoring bind --endpoint HTTPS_URL [--code-file FILE] [--replace]
  ag-pve [--config FILE] monitoring status
  ag-pve [--config FILE] monitoring unbind
  ag-pve [--config FILE] monitoring show|test|set [选项]
  ag-pve [--config FILE] monitoring query|modify     # 预留，v0.1 返回未实现
  ag-pve [--config FILE] website bind|status|show|test
  ag-pve [--config FILE] website metering|telemetry set [选项]
  ag-pve [--config FILE] website control set [选项]
  ag-pve [--config FILE] website query|modify        # 预留，v0.1 返回未实现
  ag-pve template init                               # 交互选择存储、外网/内网桥并二次确认
  ag-pve template catalog|discover
  ag-pve template bootstrap [helper 参数]            # plan；--execute 还需原 plan ID/摘要
  ag-pve update                                      # 校验 rolling-main 制品并保留状态更新
  ag-pve uninstall                                   # 完全卸载，必须交互输入 y 确认

bind 的一次性绑定码只能经标准输入或 --code-file 私密文件提供，绝不接受命令行参数。website bind 与 monitoring bind 都从本机 /usr/bin/pveversion 自动读取版本，成功写入后会严格回验并自动重启、确认服务加载对应新绑定。show 只显示脱敏配置；test 只做 DNS/TCP/TLS 探测，不发送业务数据；普通 set 原子写入并保留 .bak 备份，不自动重启服务。官网/监控站的远程资产查询修改 API 已预留，待服务端契约完成后补入。`)
}

func (c *cli) menu(filename string) int {
	reader := bufio.NewReader(io.LimitReader(c.in, 64<<10))
	fmt.Fprintln(c.out, "PPFlight Agent")
	for {
		c.menuPVEHeader(filename)
		fmt.Fprintln(c.out, `
  1) 初始化/克隆 Cloud-Init 模板
  2) 官网绑定设置
  3) 监控绑定设置
  4) 系统概况
  5) 一键更新 PPFlight Agent
  6) 完全卸载 PPFlight Agent
  0) 退出`)
		choice, err := c.promptLine(reader, "请选择 [0-6]: ")
		if err != nil {
			fmt.Fprintln(c.errOut, "无法读取菜单选择")
			return 2
		}
		switch choice {
		case "", "0", "q", "quit", "exit":
			return 0
		case "1":
			original := c.in
			c.in = reader
			defer func() { c.in = original }()
			return c.templateInit()
		case "2":
			if code, back := c.menuBindingSettings(reader, filename, false); !back {
				return code
			}
		case "3":
			if code, back := c.menuBindingSettings(reader, filename, true); !back {
				return code
			}
		case "4":
			_ = c.systemOverview(filename)
		case "5":
			return c.update(nil)
		case "6":
			return c.menuCompleteUninstallAt(reader, filename)
		default:
			fmt.Fprintln(c.errOut, "菜单选择无效")
			return 2
		}
	}
}

func (c *cli) update(args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(c.errOut, "update 不接受参数")
		return 2
	}
	if !c.isRoot() {
		fmt.Fprintln(c.errOut, "一键更新必须由 PVE root 执行")
		return 1
	}
	if c.completeUpdate != nil {
		version, err := c.completeUpdate(context.Background())
		if err != nil || strings.TrimSpace(version) == "" {
			fmt.Fprintln(c.errOut, "一键更新失败；未报告成功，请按上方错误修复后重试")
			return 1
		}
		fmt.Fprintf(c.out, "一键更新完成并已回验：Agent %s；服务、真实 PVE 采集和开机启动均由安装流程验证。\n", strings.TrimSpace(version))
		return 0
	}
	helper := "/usr/local/lib/ppflight-agent/quick-install.sh"
	info, err := os.Lstat(helper)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > 1<<20 {
		fmt.Fprintln(c.errOut, "一键更新脚本缺失或权限不安全；未修改 Agent")
		return 1
	}
	tempDir, err := os.MkdirTemp("", "ppflight-agent-update.")
	if err != nil {
		fmt.Fprintln(c.errOut, "无法创建私有更新暂存目录；未修改 Agent")
		return 1
	}
	defer os.RemoveAll(tempDir)
	if err := os.Chmod(tempDir, 0o700); err != nil {
		fmt.Fprintln(c.errOut, "无法保护更新暂存目录；未修改 Agent")
		return 1
	}
	tempHelper := filepath.Join(tempDir, "quick-install.sh")
	source, err := os.Open(helper)
	if err != nil {
		fmt.Fprintln(c.errOut, "无法读取一键更新脚本；未修改 Agent")
		return 1
	}
	destination, err := os.OpenFile(tempHelper, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		source.Close()
		fmt.Fprintln(c.errOut, "无法创建私有更新脚本副本；未修改 Agent")
		return 1
	}
	copied, copyErr := io.Copy(destination, io.LimitReader(source, info.Size()+1))
	syncErr := destination.Sync()
	closeDestinationErr := destination.Close()
	closeSourceErr := source.Close()
	if copyErr != nil || syncErr != nil || closeDestinationErr != nil || closeSourceErr != nil || copied != info.Size() {
		fmt.Fprintln(c.errOut, "无法完整暂存一键更新脚本；未修改 Agent")
		return 1
	}
	fmt.Fprintln(c.out, "正在校验并安装 PPFlight Agent rolling-main 最新制品；现有配置、绑定和持久队列将保留。")
	command := exec.Command(tempHelper)
	command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	command.Stdout, command.Stderr = c.out, c.errOut
	if err := command.Run(); err != nil {
		fmt.Fprintln(c.errOut, "一键更新失败；未报告成功，请按上方错误修复后重试")
		return 1
	}
	versionCommand := exec.Command("/usr/local/bin/ag-pve", "version")
	versionCommand.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	version, err := versionCommand.Output()
	if err != nil || strings.TrimSpace(string(version)) == "" {
		fmt.Fprintln(c.errOut, "更新安装已结束，但无法回验新 Agent 版本；请运行 ag-pve version")
		return 1
	}
	fmt.Fprintf(c.out, "一键更新完成并已回验：Agent %s；服务、真实 PVE 采集和开机启动均由安装流程验证。\n", strings.TrimSpace(string(version)))
	return 0
}

// menuCompleteUninstall retains the historical direct-test entry point. Real
// command dispatch always supplies the selected configuration path through
// menuCompleteUninstallAt, so the purge participates in the same state
// transaction lock as bind, unbind and PVE preparation.
func (c *cli) menuCompleteUninstall(reader *bufio.Reader) int {
	return c.menuCompleteUninstallAt(reader, "/etc/ppflight-agent/agent.yaml")
}

func (c *cli) menuCompleteUninstallAt(reader *bufio.Reader, filename string) int {
	if !c.isRoot() {
		fmt.Fprintln(c.errOut, "完全卸载必须由 PVE root 显式执行")
		return 1
	}
	fmt.Fprintln(c.out, `完全卸载会停止并删除 PPFlight Agent、systemd 服务、PPFlight 专用 PVE Token/用户/ACL、官网/监控绑定凭据、配置、持久队列和本地审计状态。
不会删除 PVE 虚拟机、Cloud-Init 模板、镜像缓存或备份文件。`)
	confirmed, err := c.promptYesNo(reader, "确认完全卸载 PPFlight Agent？", false)
	if err != nil {
		fmt.Fprintln(c.errOut, "无法读取卸载确认；未执行任何修改")
		return 2
	}
	if !confirmed {
		fmt.Fprintln(c.out, "已取消，未卸载任何内容。")
		return 0
	}
	_, transaction, err := c.acquireCompleteUninstallTransaction(filename)
	if err != nil {
		fmt.Fprintln(c.errOut, "完全卸载已拒绝：另一个 Agent 管理命令仍在执行，或本机配置/权限状态不安全；未删除任何内容")
		return 1
	}
	defer transaction.Close()
	// Keep the exclusive management lock until the root helper and every
	// pveum/systemd child it waits for have exited. A CommandContext timeout
	// would kill only the shell process, potentially releasing this lock while
	// an orphaned child was still mutating PVE state.
	ctx := context.Background()
	var uninstallErr error
	if c.completeUninstall != nil {
		uninstallErr = c.completeUninstall(ctx)
	} else {
		command := exec.Command("/usr/local/lib/ppflight-agent/uninstall.sh", "--remove-exporters", "--purge")
		command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
		command.Stdout = c.out
		command.Stderr = c.errOut
		uninstallErr = command.Run()
	}
	if uninstallErr != nil {
		fmt.Fprintln(c.errOut, "完全卸载失败；请检查上方错误，PVE 虚拟机、模板、镜像和备份未被修改")
		return 1
	}
	fmt.Fprintln(c.out, "PPFlight Agent 已完全卸载；PVE 虚拟机、模板、镜像和备份保持不变。")
	return 0
}

func (c *cli) menuBindingSettings(reader *bufio.Reader, filename string, monitoring bool) (int, bool) {
	cfg, ok := c.load(filename)
	if !ok {
		return 1, false
	}
	target := "PPFlight 官网"
	bound := false
	bindingID := ""
	credentialEpoch := uint64(0)
	pending := false
	if monitoring {
		target = "监控站"
		state, err := bindstate.LoadMonitoring(cfg.Runtime.StateDirectory)
		if err == nil {
			bound, bindingID, credentialEpoch = true, state.BindingID, state.CredentialEpoch
		} else if !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(c.errOut, "监控绑定状态不安全或无效；已禁止添加、替换和删除，请先检查本机状态文件")
			return 1, false
		}
	} else {
		state, err := bindstate.Load(cfg.Runtime.StateDirectory)
		if err == nil {
			bound, bindingID, credentialEpoch = true, state.BindingID, state.CredentialEpoch
		} else if !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(c.errOut, "官网绑定状态不安全或无效；已禁止添加、替换和删除，请先检查本机状态文件")
			return 1, false
		}
	}
	if !bound {
		domain := "website"
		if monitoring {
			domain = "monitoring"
		}
		var err error
		pending, err = bindstate.PendingRequestExists(cfg.Runtime.StateDirectory, domain)
		if err != nil {
			fmt.Fprintf(c.errOut, "%s绑定 pending 状态不安全或损坏；拒绝继续\n", target)
			return 1, false
		}
	}

	fmt.Fprintf(c.out, "\n%s绑定设置\n", target)
	if bound {
		fmt.Fprintf(c.out, "当前状态：已绑定  bindingId=%s  credentialEpoch=%d\n", bindingID, credentialEpoch)
	} else {
		if pending {
			fmt.Fprintln(c.out, "当前状态：未绑定（存在上一次结果未确定的绑定请求）")
		} else {
			fmt.Fprintln(c.out, "当前状态：未绑定")
		}
	}
	fmt.Fprintln(c.out, "  1) 查看绑定与通信状态")
	if bound {
		fmt.Fprintln(c.out, "  2) 删除绑定")
	} else {
		if pending {
			fmt.Fprintln(c.out, "  2) 使用上一次原绑定码重试")
			fmt.Fprintln(c.out, "  3) 清除未决绑定请求（仅在服务端已撤销后）")
		} else {
			fmt.Fprintln(c.out, "  2) 添加绑定")
		}
	}
	fmt.Fprintln(c.out, "  0) 返回主菜单")
	choiceRange := "[0-2]"
	if pending {
		choiceRange = "[0-3]"
	}
	choice, err := c.promptLine(reader, "请选择 "+choiceRange+": ")
	if err != nil {
		fmt.Fprintln(c.errOut, "无法读取绑定设置选择")
		return 2, false
	}
	switch choice {
	case "", "0", "q", "quit", "back":
		return 0, true
	case "1":
		if monitoring {
			return c.monitoring(filename, []string{"status"}), false
		}
		return c.website(filename, []string{"status"}), false
	case "2":
		if bound {
			return c.menuRemoveBinding(reader, filename, monitoring), false
		}
		return c.menuBind(reader, filename, monitoring, false, ""), false
	case "3":
		if pending && !bound {
			return c.menuDiscardPendingBinding(reader, filename, monitoring), false
		}
		fmt.Fprintln(c.errOut, "绑定设置选择无效")
		return 2, false
	default:
		fmt.Fprintln(c.errOut, "绑定设置选择无效")
		return 2, false
	}
}

// menuDiscardPendingBinding is the explicit recovery boundary for an
// enrollment request whose response was ambiguous and which the operator has
// since revoked on the authoritative service. It never removes a completed
// binding and never mutates the independent trust domain.
func (c *cli) menuDiscardPendingBinding(reader *bufio.Reader, filename string, monitoring bool) int {
	if !c.isRoot() {
		fmt.Fprintln(c.errOut, "清除未决绑定请求必须由 PVE root 显式执行")
		return 1
	}
	cfg, ok := c.load(filename)
	if !ok {
		return 1
	}
	if err := c.requireManagedWriteTarget(filename, cfg); err != nil {
		fmt.Fprintln(c.errOut, "清除未决绑定请求已拒绝：生产管理配置或状态目录不安全")
		return 1
	}
	domain, target := "website", "PPFlight 官网"
	if monitoring {
		domain, target = "monitoring", "监控站"
	}
	fmt.Fprintf(c.out, "仅当你已在%s确认撤销旧请求后才能继续；不会删除另一侧绑定、PVE 凭据或运行数据。\n", target)
	confirmed, err := c.promptYesNo(reader, fmt.Sprintf("确认清除%s未决绑定请求？", target), false)
	if err != nil || !confirmed {
		fmt.Fprintln(c.out, "已取消，未修改本机。")
		return 0
	}
	transaction, err := bindstate.AcquireTransaction(cfg.Runtime.StateDirectory)
	if err != nil {
		fmt.Fprintln(c.errOut, "另一个 Agent 管理事务正在执行；未修改本机")
		return 1
	}
	defer transaction.Close()
	latest, err := config.LoadFile(filename)
	if err != nil || latest.Runtime.StateDirectory != cfg.Runtime.StateDirectory {
		fmt.Fprintln(c.errOut, "配置在清除未决请求前发生变化；请重试")
		return 1
	}
	if err := requireNoUnbindTransaction(latest.Runtime.StateDirectory); err != nil {
		fmt.Fprintln(c.errOut, "绑定删除事务尚未完成；拒绝清除未决请求")
		return 1
	}
	if _, found, markerErr := bindstate.ReadWebsiteCommit(latest.Runtime.StateDirectory); markerErr != nil || found {
		fmt.Fprintln(c.errOut, "官网绑定提交事务尚未完成；拒绝清除未决请求")
		return 1
	}
	if _, found, markerErr := bindstate.ReadMonitoringCommit(latest.Runtime.StateDirectory); markerErr != nil || found {
		fmt.Fprintln(c.errOut, "监控绑定提交事务尚未完成；拒绝清除未决请求")
		return 1
	}
	if monitoring {
		if _, stateErr := bindstate.LoadMonitoring(latest.Runtime.StateDirectory); stateErr == nil || !errors.Is(stateErr, os.ErrNotExist) {
			fmt.Fprintln(c.errOut, "监控站当前已绑定或绑定状态不安全；拒绝清除未决请求")
			return 1
		}
	} else if _, stateErr := bindstate.Load(latest.Runtime.StateDirectory); stateErr == nil || !errors.Is(stateErr, os.ErrNotExist) {
		fmt.Fprintln(c.errOut, "PPFlight 官网当前已绑定或绑定状态不安全；拒绝清除未决请求")
		return 1
	}
	present, pendingErr := bindstate.PendingRequestExists(latest.Runtime.StateDirectory, domain)
	if pendingErr != nil || !present {
		fmt.Fprintln(c.errOut, "未找到可安全清除的未决绑定请求；未修改本机")
		return 1
	}
	if err := bindstate.ClearPending(latest.Runtime.StateDirectory, domain); err != nil {
		fmt.Fprintln(c.errOut, "清除未决绑定请求失败；未修改另一侧绑定或 PVE 配置")
		return 1
	}
	fmt.Fprintf(c.out, "%s未决绑定请求已清除；另一侧绑定、PVE 凭据和 Agent 服务保持不变。现在可使用新的绑定码重新绑定。\n", target)
	return 0
}

func (c *cli) menuBind(reader *bufio.Reader, filename string, monitoring, replace bool, currentEndpoint string) int {
	target := "官网"
	if monitoring {
		target = "监控站"
	}
	endpointPrompt := target + "一次性绑定 API 地址（HTTPS）: "
	if currentEndpoint != "" {
		endpointPrompt = fmt.Sprintf("%s一次性绑定 API 地址（HTTPS）[%s]: ", target, currentEndpoint)
	}
	endpoint, err := c.promptLine(reader, endpointPrompt)
	if endpoint == "" {
		endpoint = currentEndpoint
	}
	if err != nil || endpoint == "" {
		fmt.Fprintln(c.errOut, "绑定 API 地址不能为空")
		return 2
	}
	if endpointErr := c.validateBindingEndpoint(endpoint, monitoring); endpointErr != nil {
		if monitoring {
			fmt.Fprintln(c.errOut, "监控绑定 API 地址无效；未修改本机 PVE 或读取绑定码")
			return 2
		}
		fmt.Fprintln(c.errOut, "官网绑定 API 地址无效；未修改本机 PVE 或读取绑定码")
		return 2
	}
	args := []string{"bind", "--endpoint", endpoint}
	if replace {
		args = append(args, "--replace")
	}
	if monitoring {
		args = append([]string{"monitoring"}, args...)
	} else {
		args = append([]string{"website"}, args...)
	}
	originalPrompt := c.bindingCodePrompt
	c.bindingCodePrompt = func() (string, error) {
		return c.promptLine(reader, "输入一次性绑定码（不会写入 argv、配置或日志）: ")
	}
	defer func() { c.bindingCodePrompt = originalPrompt }()
	if monitoring {
		return c.monitoring(filename, args[1:])
	}
	return c.website(filename, args[1:])
}

func (c *cli) menuRemoveBinding(reader *bufio.Reader, filename string, monitoring bool) int {
	if !c.isRoot() {
		fmt.Fprintln(c.errOut, "删除绑定必须由 PVE root 显式执行")
		return 1
	}
	cfg, ok := c.load(filename)
	if !ok {
		return 1
	}
	domain, target := "website", "PPFlight 官网"
	if monitoring {
		domain, target = "monitoring", "监控站"
	}
	marker, markerFound, markerErr := readUnbindMarker(cfg.Runtime.StateDirectory, domain)
	if markerErr != nil {
		fmt.Fprintf(c.errOut, "%s绑定删除事务不安全或损坏；拒绝继续\n", target)
		return 1
	}
	if markerFound {
		latest, transaction, err := c.acquireStableUnbindTransaction(filename, cfg.Runtime.StateDirectory, domain)
		if err != nil {
			fmt.Fprintln(c.errOut, "绑定删除恢复被拒绝：另一个 Agent 管理事务正在执行，或存在未完成的其它事务")
			return 1
		}
		defer transaction.Close()
		// Re-read under the shared transaction lock. A stale marker must never
		// choose a backup after another root process has completed/restarted the
		// transaction between the optimistic first inspection and lock acquire.
		marker, markerFound, markerErr = readUnbindMarker(latest.Runtime.StateDirectory, domain)
		if markerErr != nil || !markerFound {
			fmt.Fprintf(c.errOut, "%s绑定删除事务在获取锁期间发生变化；拒绝继续\n", target)
			return 1
		}
		return c.resumeUnbindTransaction(filename, latest, domain, target, marker)
	}
	var websiteState bindstate.State
	var monitoringState bindstate.MonitoringState
	var stateErr error
	if monitoring {
		monitoringState, stateErr = bindstate.LoadMonitoring(cfg.Runtime.StateDirectory)
	} else {
		websiteState, stateErr = bindstate.Load(cfg.Runtime.StateDirectory)
	}
	if errors.Is(stateErr, os.ErrNotExist) {
		fmt.Fprintf(c.out, "%s当前没有绑定，无需删除。\n", target)
		return 0
	}
	if stateErr != nil {
		fmt.Fprintf(c.errOut, "%s绑定状态不安全或无效；拒绝删除\n", target)
		return 1
	}
	fmt.Fprintf(c.out, "删除%s绑定会停用本机该信任域的上传、状态查询和命令凭据，并自动重启 Agent。\n", target)
	if monitoring {
		fmt.Fprintln(c.out, "官网绑定、官网配置和所有持久队列不会被删除；监控审计队列会保留，但在重新绑定前无法上传。")
	} else {
		fmt.Fprintln(c.out, "监控绑定、监控配置和所有持久队列不会被删除；PVE 虚拟机、模板、镜像和备份不受影响。")
	}
	confirmed, err := c.promptYesNo(reader, fmt.Sprintf("确认删除%s绑定？", target), false)
	if err != nil {
		fmt.Fprintln(c.errOut, "无法读取删除确认；未执行任何修改")
		return 2
	}
	if !confirmed {
		fmt.Fprintln(c.out, "已取消，绑定保持不变。")
		return 0
	}
	latest, transaction, err := c.acquireStableUnbindTransaction(filename, cfg.Runtime.StateDirectory, domain)
	if err != nil {
		fmt.Fprintln(c.errOut, "绑定保持不变：另一个 Agent 管理事务正在执行，或存在未完成的官网/监控绑定事务")
		return 1
	}
	defer transaction.Close()
	if marker, markerFound, markerErr = readUnbindMarker(latest.Runtime.StateDirectory, domain); markerErr != nil {
		fmt.Fprintf(c.errOut, "%s绑定删除事务不安全或损坏；拒绝继续\n", target)
		return 1
	} else if markerFound {
		return c.resumeUnbindTransaction(filename, latest, domain, target, marker)
	}
	if monitoring {
		current, loadErr := bindstate.LoadMonitoring(latest.Runtime.StateDirectory)
		if loadErr != nil || current.BindingID != monitoringState.BindingID || current.CredentialEpoch != monitoringState.CredentialEpoch {
			fmt.Fprintln(c.errOut, "监控绑定在删除确认期间发生变化；未执行删除")
			return 1
		}
		monitoringState = current
	} else {
		current, loadErr := bindstate.Load(latest.Runtime.StateDirectory)
		if loadErr != nil || current.BindingID != websiteState.BindingID || current.CredentialEpoch != websiteState.CredentialEpoch {
			fmt.Fprintln(c.errOut, "官网绑定在删除确认期间发生变化；未执行删除")
			return 1
		}
		websiteState = current
	}
	cfg = latest
	original := cfg
	if monitoring {
		disableMonitoringBindingConfig(&cfg)
	} else {
		disableWebsiteBindingConfig(&cfg)
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(c.errOut, "删除绑定后的安全配置未通过校验；未修改本机")
		return 1
	}
	if monitoring {
		marker, err = bindstate.BeginMonitoringUnbind(original.Runtime.StateDirectory, monitoringState)
	} else {
		marker, err = bindstate.BeginWebsiteUnbind(original.Runtime.StateDirectory, websiteState)
	}
	if err != nil {
		fmt.Fprintf(c.errOut, "%s绑定删除事务无法建立；未停止 Agent 或修改绑定\n", target)
		return 1
	}
	restartContext, cancelRestart := context.WithTimeout(context.Background(), 30*time.Second)
	restartErr := c.restartAgentForUnbind(restartContext)
	cancelRestart()
	if restartErr != nil {
		rollbackErr := c.rollbackUnbindTransaction(filename, original, domain, marker)
		fmt.Fprintf(c.errOut, "%s绑定删除尚未开始；已尝试恢复原 Agent 运行状态", target)
		if rollbackErr != nil {
			fmt.Fprint(c.errOut, "；自动恢复未完全确认，请重新执行删除绑定以恢复事务")
		}
		fmt.Fprintln(c.errOut)
		return 1
	}
	configBackup, err := c.writeUnbindConfigFile(filename, cfg)
	if err != nil {
		rollbackErr := c.rollbackUnbindTransaction(filename, original, domain, marker)
		fmt.Fprintf(c.errOut, "%s绑定配置保存失败；已尝试恢复原 Agent 运行状态", target)
		if rollbackErr != nil {
			fmt.Fprint(c.errOut, "；自动恢复未完全确认，请重新执行删除绑定以恢复事务")
		}
		fmt.Fprintln(c.errOut)
		return 1
	}
	stateErr = c.removeUnbindTargetState(cfg.Runtime.StateDirectory, domain)
	if stateErr != nil {
		rollbackErr := c.rollbackUnbindTransaction(filename, original, domain, marker)
		fmt.Fprintf(c.errOut, "%s绑定凭据删除失败；已尝试恢复原 Agent 运行状态，原配置备份=%s", target, configBackup)
		if rollbackErr != nil {
			fmt.Fprint(c.errOut, "；自动恢复未完全确认，请重新执行删除绑定以恢复事务")
		}
		fmt.Fprintln(c.errOut)
		return 1
	}
	if err := validateUnboundRemovalState(filename, cfg, domain); err != nil {
		rollbackErr := c.rollbackUnbindTransaction(filename, original, domain, marker)
		fmt.Fprintf(c.errOut, "%s绑定删除后的本地状态未通过校验；已尝试恢复原 Agent 运行状态，原配置备份=%s", target, configBackup)
		if rollbackErr != nil {
			fmt.Fprint(c.errOut, "；自动恢复未完全确认，请重新执行删除绑定以恢复事务")
		}
		fmt.Fprintln(c.errOut)
		return 1
	}
	if err := c.activateUnboundWhileJournalPresent(cfg, domain); err != nil {
		rollbackErr := c.rollbackUnbindTransaction(filename, original, domain, marker)
		fmt.Fprintf(c.errOut, "%s_BINDING_REMOVAL_ACTIVATION_FAILED: 新配置未能由服务确认，已尝试恢复旧绑定；原配置备份=%s", strings.ToUpper(domain), configBackup)
		if rollbackErr != nil {
			fmt.Fprint(c.errOut, "；自动恢复未完全确认，请重新执行删除绑定以恢复事务")
		}
		fmt.Fprintln(c.errOut)
		return 1
	}
	if err := discardUnbindBackup(cfg.Runtime.StateDirectory, domain, marker); err != nil {
		fmt.Fprintf(c.errOut, "%s绑定已停止上传并自动生效，但私有回滚副本清理失败；请重新执行删除绑定完成恢复事务\n", target)
		return 1
	}
	if err := c.finishUnbindTransaction(cfg.Runtime.StateDirectory, domain); err != nil {
		fmt.Fprintf(c.errOut, "%s绑定已停止上传并自动生效，但删除事务标记清理失败；请重新执行删除绑定完成恢复事务\n", target)
		return 1
	}
	other := "监控绑定"
	if monitoring {
		other = "官网绑定"
	}
	fmt.Fprintf(c.out, "%s绑定已从本机安全删除并自动生效；%s保持不变；配置备份=%s。\n", target, other, configBackup)
	return 0
}

func readUnbindMarker(stateDirectory, domain string) (bindstate.UnbindCommit, bool, error) {
	if domain == "website" {
		return bindstate.ReadWebsiteUnbind(stateDirectory)
	}
	if domain == "monitoring" {
		return bindstate.ReadMonitoringUnbind(stateDirectory)
	}
	return bindstate.UnbindCommit{}, false, errors.New("invalid binding removal domain")
}

func (c *cli) writeUnbindConfigFile(filename string, cfg config.Config) (string, error) {
	if c.writeUnbindConfig != nil {
		return c.writeUnbindConfig(filename, cfg)
	}
	return atomicUpdate(filename, cfg)
}

func (c *cli) removeUnbindTargetState(stateDirectory, domain string) error {
	if c.removeUnbindState != nil {
		return c.removeUnbindState(stateDirectory, domain)
	}
	if domain == "website" {
		return bindstate.RemoveWebsite(stateDirectory)
	}
	if domain == "monitoring" {
		return bindstate.RemoveMonitoring(stateDirectory)
	}
	return errors.New("invalid binding removal domain")
}

func (c *cli) finishUnbindTransaction(stateDirectory, domain string) error {
	if c.finishUnbind != nil {
		return c.finishUnbind(stateDirectory, domain)
	}
	if domain == "website" {
		return bindstate.FinishWebsiteUnbind(stateDirectory)
	}
	if domain == "monitoring" {
		return bindstate.FinishMonitoringUnbind(stateDirectory)
	}
	return errors.New("invalid binding removal domain")
}

func discardUnbindBackup(stateDirectory, domain string, marker bindstate.UnbindCommit) error {
	if domain == "website" {
		return bindstate.DiscardWebsiteUnbindBackup(stateDirectory, marker)
	}
	if domain == "monitoring" {
		return bindstate.DiscardMonitoringUnbindBackup(stateDirectory, marker)
	}
	return errors.New("invalid binding removal domain")
}

func websiteRemovalConfigApplied(cfg config.Config) bool {
	return !cfg.Destinations.WebsiteMetering.Enabled && cfg.Destinations.WebsiteMetering.URL == "" &&
		!cfg.Destinations.WebsiteTelemetry.Enabled && cfg.Destinations.WebsiteTelemetry.URL == "" &&
		cfg.Assignments.RefreshURL == "" && !cfg.Control.Enabled && cfg.Control.PollURL == "" && cfg.Control.ResultURL == "" &&
		cfg.Control.Auth.KeyIDEnv == "" && cfg.Control.Auth.SecretEnv == "" && cfg.Control.Auth.BearerTokenEnv == "" &&
		cfg.Control.CommandSecretEnv == "" && cfg.Control.CommandSigningKeyIDEnv == "" && cfg.Control.CommandPublicKeyEnv == "" && !cfg.Control.ProductionExecution
}

func monitoringRemovalConfigApplied(cfg config.Config) bool {
	return !cfg.Destinations.Monitoring.Enabled && cfg.Destinations.Monitoring.URL == "" &&
		!cfg.Destinations.MonitoringAudit.Enabled && cfg.Destinations.MonitoringAudit.URL == "" && !cfg.Control.ProductionExecution
}

func removalConfigApplied(cfg config.Config, domain string) bool {
	if domain == "website" {
		return websiteRemovalConfigApplied(cfg)
	}
	return domain == "monitoring" && monitoringRemovalConfigApplied(cfg)
}

func validateUnboundRemovalState(filename string, expected config.Config, domain string) error {
	cfg, err := config.LoadFile(filename)
	if err != nil || cfg.Runtime.StateDirectory != expected.Runtime.StateDirectory || !removalConfigApplied(cfg, domain) {
		return errors.New("public binding removal configuration is not exact")
	}
	if domain == "website" {
		if _, err := bindstate.Load(cfg.Runtime.StateDirectory); errors.Is(err, os.ErrNotExist) {
			return nil
		} else if err != nil {
			return err
		}
		return errors.New("website binding state remains after removal")
	}
	if domain == "monitoring" {
		if _, err := bindstate.LoadMonitoring(cfg.Runtime.StateDirectory); errors.Is(err, os.ErrNotExist) {
			return nil
		} else if err != nil {
			return err
		}
		return errors.New("monitoring binding state remains after removal")
	}
	return errors.New("invalid binding removal domain")
}

func validateBoundUnbindState(filename string, expected config.Config, domain string, marker bindstate.UnbindCommit) error {
	cfg, err := config.LoadFile(filename)
	if err != nil || cfg.Runtime.StateDirectory != expected.Runtime.StateDirectory || removalConfigApplied(cfg, domain) {
		return errors.New("restored binding removal public configuration is not exact")
	}
	if domain == "website" {
		state, loadErr := bindstate.Load(cfg.Runtime.StateDirectory)
		if loadErr != nil || state.BindingID != marker.BindingID || state.CredentialEpoch != marker.CredentialEpoch {
			return errors.New("restored website binding removal state is not exact")
		}
		return nil
	}
	if domain == "monitoring" {
		state, loadErr := bindstate.LoadMonitoring(cfg.Runtime.StateDirectory)
		if loadErr != nil || state.BindingID != marker.BindingID || state.CredentialEpoch != marker.CredentialEpoch {
			return errors.New("restored monitoring binding removal state is not exact")
		}
		return nil
	}
	return errors.New("invalid binding removal domain")
}

// activateUnboundWhileJournalPresent intentionally runs before the journal is
// removed. The overlay permits this only after the exact target config is
// disabled, so a crash after state removal cannot strand the host offline or
// revive the removed domain's upload credentials.
func (c *cli) activateUnboundWhileJournalPresent(cfg config.Config, domain string) error {
	armContext, cancelArm := context.WithTimeout(context.Background(), 30*time.Second)
	armErr := c.armAgentBinding(armContext)
	cancelArm()
	if armErr != nil {
		return errors.New("arm unbound ppflight-agent service")
	}
	activationContext, cancelActivation := context.WithTimeout(context.Background(), 45*time.Second)
	err := c.activateAgentBinding(activationContext, cfg, bindingActivationExpectation{Domain: domain, Absent: true})
	cancelActivation()
	if err != nil {
		return errors.New("confirm unbound ppflight-agent service")
	}
	return nil
}

// rollbackUnbindTransaction restores the exact preimage while its journal
// blocks credential loading, then arms systemd before exposing the old state
// again. It is used for every ordinary failure after the service restart job
// was created, so a failed unbind never leaves the host intentionally stopped.
func (c *cli) rollbackUnbindTransaction(filename string, original config.Config, domain string, marker bindstate.UnbindCommit) error {
	var restoreErr error
	if domain == "website" {
		restoreErr = bindstate.RestoreWebsiteUnbind(original.Runtime.StateDirectory, marker)
	} else if domain == "monitoring" {
		restoreErr = bindstate.RestoreMonitoringUnbind(original.Runtime.StateDirectory, marker)
	} else {
		return errors.New("invalid binding removal domain")
	}
	if restoreErr != nil {
		return errors.New("restore binding removal private-state preimage")
	}
	if _, err := c.writeUnbindConfigFile(filename, original); err != nil {
		return errors.New("restore binding removal public-config preimage")
	}
	if err := validateBoundUnbindState(filename, original, domain, marker); err != nil {
		return errors.New("restored binding removal preimage is not exact")
	}
	armContext, cancelArm := context.WithTimeout(context.Background(), 30*time.Second)
	armErr := c.armAgentBinding(armContext)
	cancelArm()
	// The journal and its private preimage are the only durable proof that a
	// restart has to keep failing closed until the old binding is safe to load
	// again.  Do not clear either one before systemd has accepted the arm: a
	// crash after a failed arm but before recovery would otherwise strand the
	// host with neither an active service nor a recoverable transaction.
	if armErr != nil {
		return errors.New("arm restored ppflight-agent service")
	}
	if err := c.finishUnbindTransaction(original.Runtime.StateDirectory, domain); err != nil {
		return errors.New("finish restored binding removal transaction")
	}
	recoveryContext, cancelRecovery := context.WithTimeout(context.Background(), 45*time.Second)
	recoveryErr := c.recoverAgentBinding(recoveryContext, original)
	cancelRecovery()
	if recoveryErr != nil {
		return errors.New("confirm restored ppflight-agent service")
	}
	if err := discardUnbindBackup(original.Runtime.StateDirectory, domain, marker); err != nil {
		return errors.New("discard restored binding rollback backup")
	}
	return nil
}

// resumeUnbindTransaction is entered before any new confirmation or binding
// state inspection. A journal with the old public config rolls back; a journal
// with the already-disabled config completes forward. This makes every durable
// crash shape recoverable without reusing or clearing any enrollment code.
func (c *cli) resumeUnbindTransaction(filename string, cfg config.Config, domain, target string, marker bindstate.UnbindCommit) int {
	if !removalConfigApplied(cfg, domain) {
		if err := c.rollbackUnbindTransaction(filename, cfg, domain, marker); err != nil {
			fmt.Fprintf(c.errOut, "%s绑定删除事务尚未完成，且恢复旧运行状态未确认；请检查本机并再次执行删除绑定\n", target)
			return 1
		}
		fmt.Fprintf(c.out, "%s绑定删除事务已安全回滚，原 Agent 运行状态已恢复。\n", target)
		return 0
	}
	removeErr := c.removeUnbindTargetState(cfg.Runtime.StateDirectory, domain)
	if removeErr == nil {
		removeErr = validateUnboundRemovalState(filename, cfg, domain)
	}
	activationErr := c.activateUnboundWhileJournalPresent(cfg, domain)
	if activationErr != nil {
		fmt.Fprintf(c.errOut, "%s绑定删除事务仍在恢复；本机 Agent 未确认 active，请再次执行删除绑定\n", target)
		return 1
	}
	if removeErr != nil {
		fmt.Fprintf(c.errOut, "%s上传已停用且 Agent 已恢复，但私有绑定状态尚未清理；请再次执行删除绑定\n", target)
		return 1
	}
	if err := discardUnbindBackup(cfg.Runtime.StateDirectory, domain, marker); err != nil {
		fmt.Fprintf(c.errOut, "%s上传已停用且 Agent 已恢复，但回滚副本尚未清理；请再次执行删除绑定\n", target)
		return 1
	}
	if err := c.finishUnbindTransaction(cfg.Runtime.StateDirectory, domain); err != nil {
		fmt.Fprintf(c.errOut, "%s上传已停用且 Agent 已恢复，但删除事务标记尚未清理；请再次执行删除绑定\n", target)
		return 1
	}
	fmt.Fprintf(c.out, "%s绑定删除事务已恢复并自动生效。\n", target)
	return 0
}

func disableWebsiteBindingConfig(cfg *config.Config) {
	disableDestination(&cfg.Destinations.WebsiteMetering)
	disableDestination(&cfg.Destinations.WebsiteTelemetry)
	cfg.Assignments.RefreshURL = ""
	cfg.Control.Enabled = false
	cfg.Control.PollURL = ""
	cfg.Control.ResultURL = ""
	cfg.Control.Auth = config.AuthConfig{Mode: "hmac-sha256"}
	cfg.Control.CommandSecretEnv = ""
	cfg.Control.CommandSigningKeyIDEnv = ""
	cfg.Control.CommandPublicKeyEnv = ""
	cfg.Control.ProductionExecution = false
}

func disableMonitoringBindingConfig(cfg *config.Config) {
	disableDestination(&cfg.Destinations.Monitoring)
	disableDestination(&cfg.Destinations.MonitoringAudit)
	// A monitoring audit trust domain is mandatory before real mutations.
	cfg.Control.ProductionExecution = false
}

func disableDestination(destination *config.DestinationConfig) {
	destination.Enabled = false
	destination.URL = ""
	destination.Auth = config.AuthConfig{Mode: "hmac-sha256"}
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

// acquireStableMutationTransaction takes the one process-wide local Agent
// mutation lock used by both binding domains.  It is deliberately separate
// from the bind flow: bind owns its resumable pending/commit markers, while
// every other operation that can replace agent.yaml, remove binding state, or
// purge the installation must refuse to run while either marker exists.
//
// expectedStateDirectory is captured before command parsing.  Reloading after
// acquiring the lock prevents a second root command from swapping the config
// to a different state root between the first read and lock acquisition.
func (c *cli) acquireStableMutationTransaction(filename, expectedStateDirectory string) (config.Config, *fsutil.Lock, error) {
	return c.acquireStableMutationTransactionExceptUnbind(filename, expectedStateDirectory, "")
}

// acquireStableUnbindTransaction is the sole exception to the normal marker
// guard: an unbind command may resume its own durable removal journal, but it
// still refuses all enrollment markers, pending requests and the other
// trust-domain's unbind journal.
func (c *cli) acquireStableUnbindTransaction(filename, expectedStateDirectory, domain string) (config.Config, *fsutil.Lock, error) {
	if domain != "website" && domain != "monitoring" {
		return config.Config{}, nil, errors.New("invalid binding removal domain")
	}
	return c.acquireStableMutationTransactionExceptUnbind(filename, expectedStateDirectory, domain)
}

// acquireCompleteUninstallTransaction serializes complete removal with every
// other root management operation, but deliberately permits incomplete bind
// or unbind journals. A confirmed --purge uninstall is the recovery boundary
// for deleting those journals together with all Agent credentials and state.
func (c *cli) acquireCompleteUninstallTransaction(filename string) (config.Config, *fsutil.Lock, error) {
	initial, err := config.LoadFile(filename)
	if err != nil {
		return config.Config{}, nil, errors.New("load Agent configuration")
	}
	if err := c.requireManagedWriteTarget(filename, initial); err != nil {
		return config.Config{}, nil, err
	}
	transaction, err := bindstate.AcquireTransaction(initial.Runtime.StateDirectory)
	if err != nil {
		return config.Config{}, nil, errors.New("acquire Agent management transaction")
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = transaction.Close()
		}
	}()
	latest, err := config.LoadFile(filename)
	if err != nil {
		return config.Config{}, nil, errors.New("reload Agent configuration under transaction lock")
	}
	if latest.Runtime.StateDirectory != initial.Runtime.StateDirectory {
		return config.Config{}, nil, errors.New("Agent configuration changed during transaction acquisition")
	}
	if err := c.requireManagedWriteTarget(filename, latest); err != nil {
		return config.Config{}, nil, err
	}
	closeOnError = false
	return latest, transaction, nil
}

func (c *cli) acquireStableMutationTransactionExceptUnbind(filename, expectedStateDirectory, allowedUnbindDomain string) (config.Config, *fsutil.Lock, error) {
	initial, err := config.LoadFile(filename)
	if err != nil {
		return config.Config{}, nil, errors.New("load Agent configuration")
	}
	if expectedStateDirectory != "" && initial.Runtime.StateDirectory != expectedStateDirectory {
		return config.Config{}, nil, errors.New("Agent configuration state directory changed before mutation")
	}
	if err := c.requireManagedWriteTarget(filename, initial); err != nil {
		return config.Config{}, nil, err
	}
	transaction, err := bindstate.AcquireTransaction(initial.Runtime.StateDirectory)
	if err != nil {
		return config.Config{}, nil, errors.New("acquire Agent management transaction")
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = transaction.Close()
		}
	}()
	latest, err := config.LoadFile(filename)
	if err != nil {
		return config.Config{}, nil, errors.New("reload Agent configuration under transaction lock")
	}
	if latest.Runtime.StateDirectory != initial.Runtime.StateDirectory || (expectedStateDirectory != "" && latest.Runtime.StateDirectory != expectedStateDirectory) {
		return config.Config{}, nil, errors.New("Agent configuration changed during transaction acquisition")
	}
	if err := c.requireManagedWriteTarget(filename, latest); err != nil {
		return config.Config{}, nil, err
	}
	if err := requireNoIncompleteBindingTransactionExceptUnbind(latest.Runtime.StateDirectory, allowedUnbindDomain); err != nil {
		return config.Config{}, nil, err
	}
	closeOnError = false
	return latest, transaction, nil
}

// requireNoIncompleteBindingTransaction is the shared fail-closed guard for
// non-bind mutations.  A binding code may have been consumed already, so a
// pending request or commit marker may not be deleted, bypassed, or raced by
// set, unbind, PVE preparation, or complete uninstall.
func requireNoIncompleteBindingTransaction(stateDirectory string) error {
	return requireNoIncompleteBindingTransactionExceptUnbind(stateDirectory, "")
}

func requireNoIncompleteBindingTransactionExceptUnbind(stateDirectory, allowedUnbindDomain string) error {
	if allowedUnbindDomain != "" && allowedUnbindDomain != "website" && allowedUnbindDomain != "monitoring" {
		return errors.New("invalid allowed binding removal domain")
	}
	for _, domain := range []string{"website", "monitoring"} {
		var commitPending bool
		var err error
		if domain == "website" {
			_, commitPending, err = bindstate.ReadWebsiteCommit(stateDirectory)
		} else {
			_, commitPending, err = bindstate.ReadMonitoringCommit(stateDirectory)
		}
		if err != nil {
			return fmt.Errorf("%s binding commit marker is unsafe or unreadable", domain)
		}
		if commitPending {
			return fmt.Errorf("%s binding transaction is incomplete", domain)
		}
		requestPending, err := bindstate.PendingRequestExists(stateDirectory, domain)
		if err != nil {
			return fmt.Errorf("%s binding pending request is unsafe or unreadable", domain)
		}
		if requestPending {
			return fmt.Errorf("%s binding request outcome is unresolved", domain)
		}
		var unbindPending bool
		if domain == "website" {
			_, unbindPending, err = bindstate.ReadWebsiteUnbind(stateDirectory)
		} else {
			_, unbindPending, err = bindstate.ReadMonitoringUnbind(stateDirectory)
		}
		if err != nil {
			return fmt.Errorf("%s binding removal transaction is unsafe or unreadable", domain)
		}
		if unbindPending && domain != allowedUnbindDomain {
			return fmt.Errorf("%s binding removal transaction is incomplete", domain)
		}
	}
	return nil
}

// requireNoUnbindTransaction protects either enrollment path from racing a
// durable binding removal. Bind owns its own pending/commit markers and must
// be able to resume those markers, but it must never replace credentials while
// either trust domain has a removal preimage in flight.
func requireNoUnbindTransaction(stateDirectory string) error {
	if _, pending, err := bindstate.ReadWebsiteUnbind(stateDirectory); err != nil {
		return errors.New("website binding removal transaction is unsafe or unreadable")
	} else if pending {
		return errors.New("website binding removal transaction is incomplete")
	}
	if _, pending, err := bindstate.ReadMonitoringUnbind(stateDirectory); err != nil {
		return errors.New("monitoring binding removal transaction is unsafe or unreadable")
	} else if pending {
		return errors.New("monitoring binding removal transaction is incomplete")
	}
	return nil
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

// systemOverview is a human-readable, non-secret operational summary for the
// local PVE administrator. Domain status is derived from the independently
// authenticated binding authorities; payload identity is never trusted as an
// authorization source and no credential material is printed.
func (c *cli) systemOverview(filename string) int {
	cfg, ok := c.load(filename)
	if !ok {
		return 1
	}
	fmt.Fprintln(c.out, "\nPPFlight 系统概况")

	local, localErr := fetchLocalStatus(cfg)
	fmt.Fprintln(c.out, "\n[Agent]")
	fmt.Fprintf(c.out, "  服务：%s\n", systemdUnitState(agentServiceUnit))
	if localErr != nil {
		fmt.Fprintf(c.out, "  本地状态接口：不可达\n  配置模式：%s\n", cfg.Mode)
	} else {
		fmt.Fprintf(c.out, "  版本：%s\n  模式：%s\n  readiness：%s\n", local.Version, local.Mode, yesNo(local.Ready))
		fmt.Fprintf(c.out, "  启动时间：%s\n  最近采集成功：%s\n", displayTime(&local.StartedAt), displayTime(local.Collection.LastSuccess))
		if local.Collection.LastError != "" {
			fmt.Fprintf(c.out, "  采集异常：%s\n", local.Collection.LastError)
		}
	}

	pveStatus, _ := c.inspectLocalPVE(cfg)
	fmt.Fprintln(c.out, "\n[PVE 本地读取]")
	fmt.Fprintf(c.out, "  数据源：%s\n  读取凭据：%s (%s)\n  productionReady：%s\n", pveStatus.PVESource, readyLabel(pveStatus.Read.CredentialReady), pveStatus.Read.Code, yesNo(pveStatus.ProductionReady))
	fmt.Fprintf(c.out, "  写操作：%s；control credential：%s (%s)\n", enabledLabel(pveStatus.ProductionExecution), readyLabel(pveStatus.Control.CredentialReady), pveStatus.Control.Code)
	fmt.Fprintf(c.out, "  网卡/宿主机采集：%s；开机启动：%s\n", systemdUnitState("ppflight-node-exporter.service"), systemdUnitEnabledState("ppflight-node-exporter.service"))
	fmt.Fprintf(c.out, "  SMART 采集：%s；开机启动：%s\n", systemdUnitState("ppflight-smartctl-exporter.service"), systemdUnitEnabledState("ppflight-smartctl-exporter.service"))

	fmt.Fprintln(c.out, "\n[PVE 主机防火墙]")
	firewallTransaction, firewallErr := hostfirewall.InspectTransaction()
	if firewallErr != nil {
		fmt.Fprintln(c.out, "  全新安装事务：状态文件不安全或损坏（禁止推断或修改）")
	} else if !firewallTransaction.Present {
		fmt.Fprintln(c.out, "  全新安装事务：无；现有安装更新保持防火墙原状")
	} else {
		fmt.Fprintf(c.out, "  全新安装事务：%s\n", firewallTransaction.Phase)
		if firewallTransaction.Node != "" {
			fmt.Fprintf(c.out, "  节点：%s；默认路由接口：%s\n", firewallTransaction.Node, strings.Join(firewallTransaction.Interfaces, ","))
		}
		if firewallTransaction.Live.Checked {
			fmt.Fprintf(c.out, "  legacy backend：%s\n", healthyLabel(firewallTransaction.Live.LegacyBackendSelected))
			fmt.Fprintf(c.out, "  优先级守护服务（active/enabled）：%s\n", healthyLabel(firewallTransaction.Live.SupervisorActiveEnabled))
			fmt.Fprintf(c.out, "  原生 IPv4/IPv6 PVE hook 首位：%s\n", healthyLabel(firewallTransaction.Live.NativeHooksFirst))
			fmt.Fprintf(c.out, "  IPv4/IPv6 runtime DROP：%s\n", healthyLabel(firewallTransaction.Live.RuntimeDropsVerified))
			if !firewallTransaction.Live.LegacyBackendSelected || !firewallTransaction.Live.SupervisorActiveEnabled ||
				!firewallTransaction.Live.NativeHooksFirst || !firewallTransaction.Live.RuntimeDropsVerified {
				fmt.Fprintln(c.out, "  运行回验失败：已提交不等于当前防护有效，请立即检查。")
			}
		}
	}

	c.printWebsiteOverview(cfg, local, localErr)
	c.printMonitoringOverview(cfg, local, localErr)

	fmt.Fprintln(c.out, "\n[高可用与升级]")
	fmt.Fprintf(c.out, "  开机启动：%s\n  升级监听：%s\n", systemdUnitEnabledState(agentServiceUnit), systemdUnitState("ppflight-agent-upgrade.path"))
	fmt.Fprintln(c.out)
	return 0
}

func (c *cli) printWebsiteOverview(cfg config.Config, local health.Status, localErr error) {
	fmt.Fprintln(c.out, "\n[PPFlight 官网]")
	state, err := bindstate.Load(cfg.Runtime.StateDirectory)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(c.out, "  绑定：未绑定\n  远端状态：未检查")
		printDomainDeliveryOverview(c.out, "website", local, localErr)
		return
	}
	if err != nil {
		fmt.Fprintln(c.out, "  绑定：状态文件不安全或损坏\n  远端状态：禁止检查")
		printDomainDeliveryOverview(c.out, "website", local, localErr)
		return
	}
	fmt.Fprintf(c.out, "  绑定：已绑定  bindingId=%s  credentialEpoch=%d\n", state.BindingID, state.CredentialEpoch)
	assignmentState, assignmentErr := assignment.LoadState(filepath.Join(cfg.Runtime.StateDirectory, "assignments", "refresh-state.json"))
	if assignmentErr != nil || assignmentState.Revision == 0 {
		fmt.Fprintln(c.out, "  远端状态：本机 assignment revision 尚未就绪")
	} else {
		client, clientErr := enrollment.NewStatusClient(enrollment.StatusClientConfig{BindingEndpoint: state.BindingEndpoint, Credential: state.HMACCredentials.Commands, NetworkPolicy: state.NetworkPolicy, Timeout: 5 * time.Second})
		if clientErr == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			remote, remoteErr := client.Get(ctx, enrollment.StatusExpected{BindingID: state.BindingID, DeviceID: state.DeviceID, AgentRef: state.Identity.AgentRef, CredentialEpoch: state.CredentialEpoch, AssignmentRevision: assignmentState.Revision})
			cancel()
			if remoteErr == nil {
				fmt.Fprintf(c.out, "  远端状态：%s  commandStale=%s  lastVerified=%s\n", remoteStatusLabel(remote.Status), yesNo(remote.CommandChannelStale), displayTime(remote.LastVerifiedAt))
			} else {
				fmt.Fprintln(c.out, "  远端状态：不可达或验签失败")
			}
		} else {
			fmt.Fprintln(c.out, "  远端状态：本机绑定网络策略或凭据状态无效")
		}
	}
	printDomainDeliveryOverview(c.out, "website", local, localErr)
}

func (c *cli) printMonitoringOverview(cfg config.Config, local health.Status, localErr error) {
	fmt.Fprintln(c.out, "\n[监控站]")
	state, err := bindstate.LoadMonitoring(cfg.Runtime.StateDirectory)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(c.out, "  绑定：未绑定\n  远端状态：未检查")
		printDomainDeliveryOverview(c.out, "monitoring", local, localErr)
		return
	}
	if err != nil {
		fmt.Fprintln(c.out, "  绑定：状态文件不安全或损坏\n  远端状态：禁止检查")
		printDomainDeliveryOverview(c.out, "monitoring", local, localErr)
		return
	}
	fmt.Fprintf(c.out, "  绑定：已绑定  bindingId=%s  credentialEpoch=%d\n", state.BindingID, state.CredentialEpoch)
	client, clientErr := monitorenrollment.NewStatusClient(monitorenrollment.StatusClientConfig{BindingEndpoint: state.BindingEndpoint, Credential: state.HMACCredential, NetworkPolicy: state.NetworkPolicy, Timeout: 5 * time.Second})
	if clientErr == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		remote, remoteErr := client.Get(ctx, monitorenrollment.StatusExpected{BindingID: state.BindingID, DeviceID: state.DeviceID, MonitoringAgentRef: state.MonitoringAgentRef, CredentialEpoch: state.CredentialEpoch})
		cancel()
		if remoteErr == nil {
			fmt.Fprintf(c.out, "  远端状态：%s  telemetryStale=%s  auditStale=%s  lastVerified=%s\n", remoteStatusLabel(remote.Status), yesNo(remote.TelemetryStale), yesNo(remote.AuditStale), displayTime(remote.LastVerifiedAt))
		} else {
			fmt.Fprintln(c.out, "  远端状态：不可达或验签失败")
		}
	} else {
		fmt.Fprintln(c.out, "  远端状态：本机绑定网络策略或凭据状态无效")
	}
	printDomainDeliveryOverview(c.out, "monitoring", local, localErr)
}

func printDomainDeliveryOverview(out io.Writer, domain string, local health.Status, localErr error) {
	if localErr != nil {
		fmt.Fprintln(out, "  上传状态：Agent 本地状态接口不可达")
		return
	}
	pendingItems := 0
	pendingBytes := int64(0)
	deadLetters := uint64(0)
	authBlocked := false
	var lastSuccess *time.Time
	for name, state := range local.Deliveries {
		if !deliveryBelongsToDomain(name, domain) {
			continue
		}
		authBlocked = authBlocked || state.AuthBlocked
		if state.LastSuccess != nil && (lastSuccess == nil || state.LastSuccess.After(*lastSuccess)) {
			value := state.LastSuccess.UTC()
			lastSuccess = &value
		}
	}
	for name, stats := range local.Queues {
		if !deliveryBelongsToDomain(name, domain) {
			continue
		}
		pendingItems += stats.PendingItems
		pendingBytes += stats.PendingBytes
		deadLetters += stats.DeadLetterItems
	}
	fmt.Fprintf(out, "  最近上传成功：%s\n  鉴权阻塞：%s\n  队列：pendingItems=%d  pendingBytes=%d  deadLetters=%d\n", displayTime(lastSuccess), yesNo(authBlocked), pendingItems, pendingBytes, deadLetters)
}

func deliveryBelongsToDomain(name, domain string) bool {
	if domain == "website" {
		return strings.HasPrefix(name, "website-") || name == "control-results"
	}
	return strings.HasPrefix(name, "monitoring")
}

func displayTime(value *time.Time) string {
	if value == nil || value.IsZero() {
		return "暂无"
	}
	return value.UTC().Format(time.RFC3339)
}

func yesNo(value bool) string {
	if value {
		return "是"
	}
	return "否"
}

func readyLabel(value bool) string {
	if value {
		return "就绪"
	}
	return "未就绪"
}

func enabledLabel(value bool) string {
	if value {
		return "已启用"
	}
	return "未启用"
}

func healthyLabel(value bool) string {
	if value {
		return "正常"
	}
	return "异常"
}

func remoteStatusLabel(value string) string {
	switch value {
	case "active":
		return "正常(active)"
	case "stale":
		return "过期(stale)"
	case "degraded":
		return "降级(degraded)"
	case "revoked":
		return "已撤销(revoked)"
	default:
		return value
	}
}

func systemdUnitState(unit string) string {
	if runtime.GOOS != "linux" {
		return "当前平台不可检查"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "is-active", unit).Output()
	value := strings.TrimSpace(string(output))
	if err == nil && value == "active" {
		return "运行中(active)"
	}
	if value == "inactive" || value == "failed" || value == "activating" || value == "deactivating" {
		return value
	}
	return "未知或未安装"
}

func systemdUnitEnabledState(unit string) string {
	if runtime.GOOS != "linux" {
		return "当前平台不可检查"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "is-enabled", unit).Output()
	value := strings.TrimSpace(string(output))
	if err == nil && value == "enabled" {
		return "已启用(enabled)"
	}
	if value != "" {
		return value
	}
	return "未知或未安装"
}

// restoreAfterUnsentBinding is called when the request never reached the
// enrollment service or the service returned an exact rejection that is
// contractually guaranteed not to consume the code or issue credentials. The
// pending marker is removed first so the old runtime overlay can load again
// before we restart it. All other HTTP failures remain ambiguous and retain
// the marker and request ID for an idempotent replay.
func (c *cli) restoreAfterUnsentBinding(cfg config.Config, domain string) error {
	if err := bindstate.ClearPending(cfg.Runtime.StateDirectory, domain); err != nil {
		return errors.New("clear rejected binding pending state")
	}
	// An unbound/disabled installation has no old Agent process to restore.
	// Test callers inject activateBinding even for a minimal config, so retain
	// that controlled recovery boundary for the transaction tests.
	if c.activateBinding == nil && cfg.PVE.Source != "api" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	if err := c.recoverAgentBinding(ctx, cfg); err != nil {
		return errors.New("restore previous ppflight-agent service")
	}
	return nil
}

// recoverAfterAmbiguousBinding restarts the last complete local generation
// without clearing its durable requestId. A non-2xx response can be emitted
// by a proxy after the service consumed the one-time code; retaining pending
// makes that request replayable while the old domain and the other domain stay
// available.
func (c *cli) recoverAfterAmbiguousBinding(cfg config.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	if err := c.recoverAgentBinding(ctx, cfg); err != nil {
		return errors.New("restore last complete ppflight-agent service")
	}
	return nil
}

func (c *cli) finalizeWebsiteBindingCommit(filename string, cfg config.Config, expected bindingActivationExpectation) error {
	if err := validateWebsiteBindingDiskFiles(filename, expected); err != nil {
		return errors.New("website binding disk validation failed")
	}
	marker, found, err := bindstate.ReadWebsiteCommit(cfg.Runtime.StateDirectory)
	if err != nil || !found || marker.BindingID != expected.BindingID || marker.CredentialEpoch != expected.CredentialEpoch {
		return errors.New("website binding commit marker does not match disk state")
	}
	armContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = c.armAgentBinding(armContext)
	cancel()
	if err != nil {
		return errors.New("arm website binding activation before clearing commit marker")
	}
	// Leave the marker in place while clearing the retry intent. A crash here
	// remains fail-closed and can be resumed without another code because the
	// marker still carries the exact issued identity. The final marker removal
	// is only reached after systemd has an active/restarting job armed.
	if err := c.clearBindingPendingState(cfg.Runtime.StateDirectory, "website"); err != nil {
		return errors.New("clear website binding pending state")
	}
	if err := c.finishBindingCommitState(cfg.Runtime.StateDirectory, "website"); err != nil {
		return errors.New("finish website binding commit marker")
	}
	if err := validateWebsiteBindingFiles(filename, expected); err != nil {
		// The marker is the fail-closed guard after a post-clear runtime
		// validation failure. It is intentionally restored rather than
		// resurrecting a server-revoked credential generation.
		if markerErr := bindstate.BeginWebsiteCommit(cfg.Runtime.StateDirectory, expected.BindingID, expected.CredentialEpoch); markerErr != nil {
			return errors.New("website runtime validation failed and commit marker could not be restored")
		}
		return errors.New("website runtime binding overlay validation failed")
	}
	return nil
}

func (c *cli) finalizeMonitoringBindingCommit(filename string, cfg config.Config, expected bindingActivationExpectation) error {
	if err := validateMonitoringBindingDiskFiles(filename, expected); err != nil {
		return errors.New("monitoring binding disk validation failed")
	}
	marker, found, err := bindstate.ReadMonitoringCommit(cfg.Runtime.StateDirectory)
	if err != nil || !found || marker.BindingID != expected.BindingID || marker.CredentialEpoch != expected.CredentialEpoch {
		return errors.New("monitoring binding commit marker does not match disk state")
	}
	armContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = c.armAgentBinding(armContext)
	cancel()
	if err != nil {
		return errors.New("arm monitoring binding activation before clearing commit marker")
	}
	// Keep the commit marker until the unit has been armed. See the website
	// equivalent for why pending is cleared first and marker removal is the
	// final durable activation step.
	if err := c.clearBindingPendingState(cfg.Runtime.StateDirectory, "monitoring"); err != nil {
		return errors.New("clear monitoring binding pending state")
	}
	if err := c.finishBindingCommitState(cfg.Runtime.StateDirectory, "monitoring"); err != nil {
		return errors.New("finish monitoring binding commit marker")
	}
	if err := validateMonitoringBindingFiles(filename, expected); err != nil {
		if markerErr := bindstate.BeginMonitoringCommit(cfg.Runtime.StateDirectory, expected.BindingID, expected.CredentialEpoch); markerErr != nil {
			return errors.New("monitoring runtime validation failed and commit marker could not be restored")
		}
		return errors.New("monitoring runtime binding overlay validation failed")
	}
	return nil
}

func (c *cli) clearBindingPendingState(stateDirectory, domain string) error {
	if c.clearBindingPending != nil {
		return c.clearBindingPending(stateDirectory, domain)
	}
	return bindstate.ClearPending(stateDirectory, domain)
}

func (c *cli) finishBindingCommitState(stateDirectory, domain string) error {
	if c.finishBindingCommit != nil {
		return c.finishBindingCommit(stateDirectory, domain)
	}
	if domain == "website" {
		return bindstate.FinishWebsiteCommit(stateDirectory)
	}
	if domain == "monitoring" {
		return bindstate.FinishMonitoringCommit(stateDirectory)
	}
	return errors.New("invalid binding commit domain")
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
	nodeRef := set.String("node-ref", cfg.Identity.NodeRef, "node claim (defaults to identity.nodeRef)")
	host := set.String("hostname", "", "host claim (defaults to local hostname)")
	capabilities := set.String("capabilities", "pve.discovery.v1,pve.telemetry.v1", "comma-separated supported capabilities; pve.control.v1 requires a verified local control token")
	replace := set.Bool("replace", false, "replace an existing local binding after obtaining a new code")
	if err := set.Parse(args); err != nil || set.NArg() != 0 || strings.TrimSpace(*endpoint) == "" {
		if err == nil {
			fmt.Fprintln(c.errOut, "bind 需要 --endpoint，且不接受绑定码或 PVE 版本位置参数")
		}
		return 2
	}
	if err := c.validateBindingEndpoint(strings.TrimSpace(*endpoint), false); err != nil {
		fmt.Fprintln(c.errOut, "官网绑定 API 地址无效；未修改本机 PVE 或读取绑定码")
		return 2
	}
	if err := c.requireManagedWriteTarget(filename, cfg); err != nil {
		fmt.Fprintln(c.errOut, "官网绑定已拒绝：生产管理配置或状态目录不安全")
		return 1
	}
	transaction, err := bindstate.AcquireTransaction(cfg.Runtime.StateDirectory)
	if err != nil {
		fmt.Fprintln(c.errOut, "另一个 Agent 管理事务正在执行；未修改本机")
		return 1
	}
	defer transaction.Close()
	latest, err := config.LoadFile(filename)
	if err != nil || latest.Runtime.StateDirectory != cfg.Runtime.StateDirectory {
		fmt.Fprintln(c.errOut, "配置在绑定开始前发生变化；请重试")
		return 1
	}
	cfg = latest
	if err := requireNoUnbindTransaction(cfg.Runtime.StateDirectory); err != nil {
		fmt.Fprintln(c.errOut, "绑定删除事务尚未完成；请先恢复或完成现有绑定删除")
		return 1
	}
	websiteCommit, resumingWebsiteCommit, err := bindstate.ReadWebsiteCommit(cfg.Runtime.StateDirectory)
	if err != nil {
		fmt.Fprintln(c.errOut, "官网绑定事务标记不安全或损坏；拒绝继续")
		return 1
	}
	if _, pending, markerErr := bindstate.ReadMonitoringCommit(cfg.Runtime.StateDirectory); markerErr != nil || pending {
		fmt.Fprintln(c.errOut, "监控绑定事务尚未完成；请先用原监控绑定码恢复监控绑定")
		return 1
	}
	websitePending, err := bindstate.PendingRequestExists(cfg.Runtime.StateDirectory, "website")
	if err != nil {
		fmt.Fprintln(c.errOut, "官网绑定 pending 状态不安全或损坏；拒绝继续")
		return 1
	}
	if pending, pendingErr := bindstate.PendingRequestExists(cfg.Runtime.StateDirectory, "monitoring"); pendingErr != nil || pending {
		fmt.Fprintln(c.errOut, "监控绑定请求结果尚未确定；请先用原监控绑定码恢复")
		return 1
	}
	// A marker without a request intent can only be safely completed when all
	// local files already exactly match it. New transactions always create the
	// pending request first, so an incomplete legacy marker is never allowed to
	// make a fresh request with a different requestId.
	if resumingWebsiteCommit && !websitePending {
		expected := bindingActivationExpectation{Domain: "website", BindingID: websiteCommit.BindingID, CredentialEpoch: websiteCommit.CredentialEpoch}
		if err := c.finalizeWebsiteBindingCommit(filename, cfg, expected); err != nil {
			fmt.Fprintln(c.errOut, "官网本地提交事务不完整且没有可恢复请求意图；Agent 保持停止，请检查本地绑定文件")
			return 1
		}
		activationContext, cancelActivation := context.WithTimeout(context.Background(), 15*time.Minute)
		activationErr := c.activateAgentBinding(activationContext, cfg, expected)
		cancelActivation()
		if activationErr != nil {
			fmt.Fprintln(c.errOut, "WEBSITE_BIND_ACTIVATION_FAILED: 官网绑定已安全保存，但尚未确认首次真实上传；请检查本机 Agent")
			return 1
		}
		fmt.Fprintf(c.out, "官网绑定恢复并已自动生效：%s active，bindingId=%s，credentialEpoch=%d。\n", agentServiceUnit, expected.BindingID, expected.CredentialEpoch)
		return 0
	}
	resumingWebsite := websitePending
	var requestTemplate bindstate.BindingRequestTemplate
	if resumingWebsite {
		_, requestTemplate, err = bindstate.LoadPendingTemplate(cfg.Runtime.StateDirectory, "website")
		if err != nil {
			fmt.Fprintln(c.errOut, "官网绑定 pending 请求模板不安全或不受支持；拒绝猜测重试")
			return 1
		}
		canonicalEndpoint, canonicalErr := bindstate.CanonicalBindingEndpoint(strings.TrimSpace(*endpoint))
		if canonicalErr != nil || canonicalEndpoint != requestTemplate.Endpoint {
			fmt.Fprintln(c.errOut, "官网绑定重试必须使用原来的 API 地址；未读取绑定码或发送网络请求")
			return 1
		}
	}
	// A malformed or unsafe existing state is never overwritten, even with
	// --replace.  This makes accidental replacement and symlink attacks fail
	// closed before the one-time code is sent to the service.
	var previous bindstate.State
	if existing, err := bindstate.Load(cfg.Runtime.StateDirectory); err == nil && !resumingWebsite {
		if !*replace {
			fmt.Fprintln(c.errOut, "本机已经绑定；如需轮换请使用新的绑定码和 --replace")
			return 1
		}
		previous = existing
	} else if !resumingWebsite && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(c.errOut, "现有绑定状态不安全或无效，未执行替换")
		return 1
	}
	if !resumingWebsite {
		readinessContext, cancelReadiness := context.WithTimeout(context.Background(), 15*time.Minute)
		prepared, readinessErr := c.ensureBindingPVEReady(readinessContext, filename, cfg)
		cancelReadiness()
		if readinessErr != nil {
			fmt.Fprintln(c.errOut, "PVE_REAL_READINESS_FAILED: 未能启用并验证本机真实 PVE 读取；未读取或发送一次性绑定码")
			return 1
		}
		cfg = prepared
		if strings.TrimSpace(*host) == "" {
			localHostname, hostErr := os.Hostname()
			if hostErr != nil {
				fmt.Fprintln(c.errOut, "无法读取本机主机名")
				return 1
			}
			*host = localHostname
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
		versionContext, cancelVersion := context.WithTimeout(context.Background(), 3*time.Second)
		detectedPVEVersion, versionErr := c.localPVEVersion(versionContext)
		cancelVersion()
		if versionErr != nil {
			fmt.Fprintln(c.errOut, "PVE_VERSION_DISCOVERY_FAILED: 无法从本机可信 PVE 环境读取有效版本；请确认 /usr/bin/pveversion 可执行且当前主机为 PVE 8/9")
			return 1
		}
		deviceID, deviceErr := bindstate.LoadOrCreateDeviceID(cfg.Runtime.StateDirectory)
		if deviceErr != nil {
			fmt.Fprintln(c.errOut, "设备状态目录不安全或不可写")
			return 1
		}
		requestTemplate, err = bindstate.NewBindingRequestTemplate("website", strings.TrimSpace(*endpoint), deviceID, c.version, strings.TrimSpace(*host), enrollment.NodeClaim{NodeRef: strings.TrimSpace(*nodeRef), PVEVersion: detectedPVEVersion}, resolvedCapabilities)
		if err != nil {
			fmt.Fprintln(c.errOut, "无法创建安全的官网绑定请求模板")
			return 1
		}
	} else if cfg.PVE.Source != "api" || (cfg.Mode != "production" && c.bindingPVE == nil) {
		fmt.Fprintln(c.errOut, "官网绑定恢复事务缺少已验证的真实 PVE 配置；拒绝继续")
		return 1
	}
	// This is still before the durable request and service-stop boundary. Keep
	// the established PVE readiness-before-code UX so an operator is never
	// prompted for a one-time code on an unready host.
	code, err := c.readBindingCode(*codeFile)
	if err != nil {
		fmt.Fprintln(c.errOut, "读取绑定码失败")
		return 1
	}
	if err := enrollment.ValidateBindingCode(code); err != nil {
		fmt.Fprintln(c.errOut, "绑定码格式无效；未写入绑定事务、未停止 Agent 或发送网络请求")
		return 2
	}

	if cfg.Mode != "test" {
		parsed, parseErr := url.Parse(strings.TrimSpace(*endpoint))
		if parseErr != nil || !strings.EqualFold(parsed.Scheme, "https") {
			fmt.Fprintln(c.errOut, "生产模式下绑定地址必须使用 HTTPS")
			return 2
		}
	}
	client, err := enrollment.NewClient(enrollment.Config{Endpoint: requestTemplate.Endpoint})
	if err != nil {
		fmt.Fprintln(c.errOut, "绑定地址必须是 HTTPS（测试时仅允许 loopback HTTP）")
		return 2
	}
	request := enrollment.Request{SchemaVersion: enrollment.SchemaVersion, BindingCode: code, DeviceID: requestTemplate.DeviceID, AgentVersion: requestTemplate.AgentVersion, Hostname: requestTemplate.Hostname, NodeClaim: requestTemplate.NodeClaim, Capabilities: append([]string(nil), requestTemplate.Capabilities...)}
	fingerprint, err := bindstate.BindingRequestFingerprint("website", requestTemplate.Endpoint, request)
	if err != nil {
		fmt.Fprintln(c.errOut, "无法生成绑定请求指纹")
		return 1
	}
	requestID, storedTemplate, err := bindstate.PreparePendingLocked(cfg.Runtime.StateDirectory, "website", fingerprint, requestTemplate)
	if err != nil {
		if errors.Is(err, bindstate.ErrPendingRequestConflict) {
			fmt.Fprintln(c.errOut, "存在上一次结果未确定的官网绑定请求；本次新绑定码未发送。请使用上一次的原绑定码重试，或先在官网确认并撤销旧请求后再处理本机未决状态")
			return 1
		}
		fmt.Fprintln(c.errOut, "无法持久化绑定请求；未发送绑定码")
		return 1
	}
	if !reflect.DeepEqual(storedTemplate, requestTemplate) {
		fmt.Fprintln(c.errOut, "官网绑定请求模板在重试期间发生变化；拒绝发送网络请求")
		return 1
	}
	request.RequestID = requestID
	quiesceContext, cancelQuiesce := context.WithTimeout(context.Background(), 30*time.Second)
	quiesceErr := c.quiesceAgentForBinding(quiesceContext)
	cancelQuiesce()
	if quiesceErr != nil {
		if recoveryErr := c.restoreAfterUnsentBinding(cfg, "website"); recoveryErr != nil {
			fmt.Fprintln(c.errOut, "官网绑定未发送：无法确认 Agent 已停止，且旧服务恢复未确认；请检查本机 Agent")
			return 1
		}
		fmt.Fprintln(c.errOut, "官网绑定未发送：无法确认 Agent 已停止；已恢复原服务")
		return 1
	}
	response, err := client.Bind(context.Background(), request)
	if err != nil {
		var rejection *enrollment.RejectionError
		if errors.As(err, &rejection) && !resumingWebsiteCommit {
			if recoveryErr := c.restoreAfterUnsentBinding(cfg, "website"); recoveryErr != nil {
				fmt.Fprintln(c.errOut, "官网已明确拒绝本次绑定，但本机未决状态清理或原 Agent 恢复未确认；请检查本机 Agent")
				return 1
			}
			if rejection.Code == "binding_already_active" {
				fmt.Fprintln(c.errOut, "官网拒绝绑定：此 PVE 设备仍有未归档的有效绑定；本次绑定码未消费。请先在官网归档旧设备，再使用该绑定码重新绑定")
				return 1
			}
			if rejection.Code == "invalid_enrollment_code" {
				fmt.Fprintln(c.errOut, "官网拒绝绑定：绑定码无效、已过期或已撤销；本次请求未签发新凭据。请在官网生成新的绑定码后重试")
				return 1
			}
			fmt.Fprintf(c.errOut, "官网拒绝绑定（%s）；本次绑定码未消费，已恢复原 Agent\n", rejection.Code)
			return 1
		}
		// Unrecognized HTTP responses stay ambiguous: an upstream proxy can
		// replace a successful enrollment response with another status/body.
		// Retain pending for idempotent replay while restoring the last complete
		// runtime so either trust domain remains available.
		if resumingWebsiteCommit {
			fmt.Fprintln(c.errOut, "官网绑定请求结果未确定；本地新凭据提交尚未完成，Agent 保持受保护状态，请使用同一绑定码重试")
			return 1
		}
		if recoveryErr := c.recoverAfterAmbiguousBinding(cfg); recoveryErr != nil {
			fmt.Fprintln(c.errOut, "官网绑定请求结果未确定；已保留同一绑定码请求，但旧 Agent 运行状态恢复未确认")
			return 1
		}
		fmt.Fprintln(c.errOut, "官网绑定请求结果未确定；已保留同一绑定码请求并恢复现有 Agent 运行状态，请使用同一绑定码重试")
		return 1
	}
	state := bindstate.FromResponse(requestTemplate.Endpoint, requestTemplate.DeviceID, response)
	if resumingWebsiteCommit && (websiteCommit.BindingID != response.BindingID || websiteCommit.CredentialEpoch != response.CredentialEpoch) {
		fmt.Fprintln(c.errOut, "官网绑定恢复响应与持久事务标记不一致；拒绝覆盖")
		return 1
	}
	if !resumingWebsiteCommit {
		if err := bindstate.BeginWebsiteCommit(cfg.Runtime.StateDirectory, state.BindingID, state.CredentialEpoch); err != nil {
			fmt.Fprintln(c.errOut, "官网绑定已由服务端签发，但无法建立本地提交标记；Agent 保持停止，请使用同一绑定码重试")
			return 1
		}
	}
	if !resumingWebsite && previous.CredentialEpoch != 0 && response.CredentialEpoch <= previous.CredentialEpoch {
		fmt.Fprintln(c.errOut, "官网绑定响应的凭据版本未前进；事务保持冻结，请使用同一绑定码重试")
		return 1
	}
	if _, err := inventory.Parse(response.AssignmentDocument, response.ClusterRef); err != nil {
		fmt.Fprintln(c.errOut, "官网绑定响应中的初始分配无效；事务保持冻结，请使用同一绑定码重试")
		return 1
	}
	applyBinding(&cfg, response)
	autoEnableProductionExecution(&cfg, "website", response.DeviceID)
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(c.errOut, "官网绑定生成的配置未通过严格校验；事务保持冻结，请使用同一绑定码重试")
		return 1
	}
	configBackup := ""
	if err := bindstate.WriteAssignment(cfg.Assignments.File, response.AssignmentDocument); err != nil {
		fmt.Fprintln(c.errOut, "官网初始分配保存失败；新凭据可能已签发，事务保持冻结，请使用同一绑定码重试")
		return 1
	}
	// A refresh authority belongs to the previous website binding/credential
	// epoch. The new enrollment response supplies a new initial assignment, but
	// its first monotonic bundle revision is learned only after the Agent starts.
	// Remove exactly the old cursor/authority file while the service is quiesced;
	// revision zero rejects commands but must not prevent assignment refresh.
	if err := resetAssignmentRefreshAuthority(cfg.Runtime.StateDirectory); err != nil {
		fmt.Fprintln(c.errOut, "官网旧分配授权状态清理失败；新凭据可能已签发，事务保持冻结，请使用同一绑定码重试")
		return 1
	}
	configBackup, err = atomicUpdate(filename, cfg)
	if err != nil {
		fmt.Fprintln(c.errOut, "官网绑定配置保存失败；新凭据可能已签发，事务保持冻结，请使用同一绑定码重试")
		return 1
	}
	expected := bindingActivationExpectation{Domain: "website", BindingID: state.BindingID, CredentialEpoch: state.CredentialEpoch}
	// Commit private credentials last. Until this write completes, an old state
	// cannot be paired with the new public config and assignment as a valid
	// runtime overlay; the durable commit marker makes every crash window fail
	// closed on service startup.
	if err := bindstate.Save(cfg.Runtime.StateDirectory, state); err != nil {
		fmt.Fprintf(c.errOut, "官网绑定密钥保存失败；不会恢复可能已撤销的旧凭据，事务保持冻结，请使用同一绑定码重试；配置备份=%s\n", configBackup)
		return 1
	}
	if err := c.finalizeWebsiteBindingCommit(filename, cfg, expected); err != nil {
		fmt.Fprintf(c.errOut, "官网绑定本地提交回验失败；不会恢复可能已撤销的旧凭据，Agent 保持停止，请使用同一绑定码重试；配置备份=%s\n", configBackup)
		return 1
	}
	activationContext, cancelActivation := context.WithTimeout(context.Background(), 15*time.Minute)
	activationErr := c.activateAgentBinding(activationContext, cfg, expected)
	cancelActivation()
	if activationErr != nil {
		fmt.Fprintf(c.errOut, "WEBSITE_BIND_ACTIVATION_FAILED: 新官网绑定已安全保存但尚未确认首次真实上传；不会恢复服务端已经撤销的旧凭据，请检查 systemctl status ppflight-agent 后重试启动；配置备份=%s\n", configBackup)
		return 1
	}
	fmt.Fprintf(c.out, "官网绑定完成并已自动生效：%s active，bindingId=%s，credentialEpoch=%d；官网采集、上传与任务轮询已启动；VPS写操作=%t；配置备份=%s。监控绑定未被修改。\n", agentServiceUnit, state.BindingID, state.CredentialEpoch, cfg.Control.ProductionExecution, configBackup)
	return 0
}

func resetAssignmentRefreshAuthority(stateDirectory string) error {
	directory := filepath.Join(stateDirectory, "assignments")
	const name = "refresh-state.json"
	file, err := fsutil.OpenRegularInDirectoryNoFollow(directory, name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(directory, name)); err != nil {
		return err
	}
	return fsutil.SyncDir(directory)
}

func (c *cli) readBindingCode(filename string) (string, error) {
	if filename == "" && c.bindingCodePrompt != nil {
		code, err := c.bindingCodePrompt()
		if err != nil || code == "" || len(code) > 128 || strings.ContainsAny(code, "\r\n\x00") {
			return "", errors.New("binding code input is invalid")
		}
		return code, nil
	}
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
	// Website enrollment activates the signed command polling channel. Real PVE
	// mutation remains independently gated by ProductionExecution, assignments,
	// monitoring audit availability, scoped PVE ACLs, and per-command policy.
	cfg.Control.Enabled = true
	cfg.Control.PollURL, cfg.Control.ResultURL = response.Endpoints.Commands, response.Endpoints.Receipts
	cfg.Control.Auth = config.AuthConfig{Mode: "hmac-sha256", KeyIDEnv: bindingoverlay.WebsiteCommandKeyIDEnv, SecretEnv: bindingoverlay.WebsiteCommandSecretEnv}
	cfg.Control.CommandSecretEnv = ""
	cfg.Control.CommandSigningKeyIDEnv = bindingoverlay.WebsiteSigningKeyIDEnv
	cfg.Control.CommandPublicKeyEnv = bindingoverlay.WebsiteCommandPublicKeyEnv
	cfg.Control.AllowedActions = append([]string(nil), response.AllowedActions...)
}

// autoEnableProductionExecution removes the old manual post-install switch.
// It arms real writes only when local PVE preparation, the signed website
// command channel, and the independent monitoring telemetry/audit trust domain
// are all present. A domain currently being committed is accepted because its
// durable commit marker prevents the service from starting before private
// state and public configuration have both been verified.
func autoEnableProductionExecution(cfg *config.Config, completingDomain, completingDeviceID string) bool {
	cfg.Control.ProductionExecution = false
	if cfg.Mode != "production" || cfg.PVE.Source != "api" || cfg.PVE.Endpoint != localPVEEndpoint ||
		cfg.Control.PVETokenIDEnv != config.PVEControlTokenIDEnv || cfg.Control.PVETokenSecretEnv != config.PVEControlTokenSecretEnv ||
		!cfg.Control.Enabled || cfg.Control.PollURL == "" || cfg.Control.ResultURL == "" || len(cfg.Control.AllowedActions) == 0 ||
		!cfg.Destinations.Monitoring.Enabled || !cfg.Destinations.MonitoringAudit.Enabled {
		return false
	}
	if completingDomain != "" && completingDomain != "website" && completingDomain != "monitoring" {
		return false
	}
	if completingDomain != "" && completingDeviceID == "" {
		return false
	}
	if requireNoUnbindTransaction(cfg.Runtime.StateDirectory) != nil {
		return false
	}
	websiteReady := completingDomain == "website"
	monitoringReady := completingDomain == "monitoring"
	var website bindstate.State
	var monitoring bindstate.MonitoringState
	websiteDeviceID := completingDeviceID
	monitoringDeviceID := completingDeviceID
	if !websiteReady {
		var err error
		website, err = bindstate.Load(cfg.Runtime.StateDirectory)
		if err != nil || bindingDomainHasPendingState(cfg.Runtime.StateDirectory, "website") {
			return false
		}
		websiteDeviceID = website.DeviceID
	}
	if !monitoringReady {
		var err error
		monitoring, err = bindstate.LoadMonitoring(cfg.Runtime.StateDirectory)
		if err != nil || bindingDomainHasPendingState(cfg.Runtime.StateDirectory, "monitoring") {
			return false
		}
		monitoringDeviceID = monitoring.DeviceID
	}
	if websiteDeviceID == "" || websiteDeviceID != monitoringDeviceID {
		return false
	}
	cfg.Control.ProductionExecution = true
	return true
}

func bindingDomainHasPendingState(stateDirectory, domain string) bool {
	pending, err := bindstate.PendingRequestExists(stateDirectory, domain)
	if err != nil || pending {
		return true
	}
	if domain == "website" {
		_, found, markerErr := bindstate.ReadWebsiteCommit(stateDirectory)
		return markerErr != nil || found
	}
	_, found, markerErr := bindstate.ReadMonitoringCommit(stateDirectory)
	return markerErr != nil || found
}

func (c *cli) monitoring(filename string, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.errOut, "monitoring 需要 preflight、bind、unbind、status、show、test 或 set")
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
	case "unbind":
		if len(args) != 1 {
			fmt.Fprintln(c.errOut, "monitoring unbind 不接受额外参数")
			return 2
		}
		return c.menuRemoveBinding(bufio.NewReader(io.LimitReader(c.in, 64<<10)), filename, true)
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
		original := cfg
		cfg.Destinations.Monitoring = value
		return c.saveMutation(filename, original, cfg)
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
	SchemaVersion int                        `json:"schemaVersion"`
	Endpoint      string                     `json:"endpoint"`
	Hostname      string                     `json:"hostname"`
	ResolvedAt    time.Time                  `json:"resolvedAt"`
	ResolvedA     []string                   `json:"resolvedA"`
	Checks        []monitoringPreflightCheck `json:"checks"`
}

type monitoringTLSDial func(context.Context, string, string, time.Duration) (tls.ConnectionState, error)
type monitoringResolver interface {
	LookupIP(context.Context, string, string) ([]net.IP, error)
}

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
	return 0
}

// buildMonitoringPreflight is optional DNS/tcp4/TLS diagnostics. It never
// writes binding state, calls an HTTP route, or gates enrollment approval.
func buildMonitoringPreflight(ctx context.Context, raw string, timeout time.Duration, resolver monitoringResolver, dial monitoringTLSDial, now func() time.Time) (monitoringPreflightResult, error) {
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
	if len(addresses) == 0 || len(addresses) > 64 {
		return monitoringPreflightResult{}, errors.New("监控 endpoint 的 A 记录数量无效")
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	if dial == nil {
		dial = dialMonitoringTLS
	}
	result := monitoringPreflightResult{SchemaVersion: 1, Endpoint: parsed.String(), Hostname: hostname, ResolvedAt: now().UTC(), ResolvedA: append([]string(nil), addresses...), Checks: make([]monitoringPreflightCheck, 0, len(addresses))}
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
		result.Checks = append(result.Checks, check)
	}
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
	nodeRef := set.String("node-ref", cfg.Identity.NodeRef, "node claim")
	host := set.String("hostname", "", "host claim")
	capabilities := set.String("capabilities", "telemetry-v1,audit-v1,delivery-state-v1,ipv4-only,mutual-whitelist-v1", "comma-separated monitoring capabilities")
	replace := set.Bool("replace", false, "rotate an existing monitoring binding")
	if err := set.Parse(args); err != nil || set.NArg() != 0 || strings.TrimSpace(*endpoint) == "" {
		if err == nil {
			fmt.Fprintln(c.errOut, "monitoring bind 需要 --endpoint，且不接受绑定码或 PVE 版本位置参数")
		}
		return 2
	}
	if err := c.validateBindingEndpoint(strings.TrimSpace(*endpoint), true); err != nil {
		fmt.Fprintln(c.errOut, "监控绑定 API 地址无效；未修改本机 PVE 或读取绑定码")
		return 2
	}
	if err := c.requireManagedWriteTarget(filename, cfg); err != nil {
		fmt.Fprintln(c.errOut, "监控绑定已拒绝：生产管理配置或状态目录不安全")
		return 1
	}
	transaction, err := bindstate.AcquireTransaction(cfg.Runtime.StateDirectory)
	if err != nil {
		fmt.Fprintln(c.errOut, "另一个 Agent 管理事务正在执行；未修改本机")
		return 1
	}
	defer transaction.Close()
	latest, err := config.LoadFile(filename)
	if err != nil || latest.Runtime.StateDirectory != cfg.Runtime.StateDirectory {
		fmt.Fprintln(c.errOut, "配置在绑定开始前发生变化；请重试")
		return 1
	}
	cfg = latest
	if err := requireNoUnbindTransaction(cfg.Runtime.StateDirectory); err != nil {
		fmt.Fprintln(c.errOut, "绑定删除事务尚未完成；请先恢复或完成现有绑定删除")
		return 1
	}
	monitoringCommit, resumingMonitoringCommit, err := bindstate.ReadMonitoringCommit(cfg.Runtime.StateDirectory)
	if err != nil {
		fmt.Fprintln(c.errOut, "监控绑定事务标记不安全或损坏；拒绝继续")
		return 1
	}
	if _, pending, markerErr := bindstate.ReadWebsiteCommit(cfg.Runtime.StateDirectory); markerErr != nil || pending {
		fmt.Fprintln(c.errOut, "官网绑定事务尚未完成；请先用原官网绑定码恢复官网绑定")
		return 1
	}
	monitoringPending, err := bindstate.PendingRequestExists(cfg.Runtime.StateDirectory, "monitoring")
	if err != nil {
		fmt.Fprintln(c.errOut, "监控绑定 pending 状态不安全或损坏；拒绝继续")
		return 1
	}
	if pending, pendingErr := bindstate.PendingRequestExists(cfg.Runtime.StateDirectory, "website"); pendingErr != nil || pending {
		fmt.Fprintln(c.errOut, "官网绑定请求结果尚未确定；请先用原官网绑定码恢复")
		return 1
	}
	if resumingMonitoringCommit && !monitoringPending {
		expected := bindingActivationExpectation{Domain: "monitoring", BindingID: monitoringCommit.BindingID, CredentialEpoch: monitoringCommit.CredentialEpoch}
		if err := c.finalizeMonitoringBindingCommit(filename, cfg, expected); err != nil {
			fmt.Fprintln(c.errOut, "监控本地提交事务不完整且没有可恢复请求意图；Agent 保持停止，请检查本地绑定文件")
			return 1
		}
		activationContext, cancelActivation := context.WithTimeout(context.Background(), 15*time.Minute)
		activationErr := c.activateAgentBinding(activationContext, cfg, expected)
		cancelActivation()
		if activationErr != nil {
			fmt.Fprintln(c.errOut, "MONITORING_BIND_ACTIVATION_FAILED: 监控绑定已安全保存，但尚未确认首次真实上传；请检查本机 Agent")
			return 1
		}
		fmt.Fprintf(c.out, "监控绑定恢复并已自动生效：%s active，bindingId=%s，credentialEpoch=%d。\n", agentServiceUnit, expected.BindingID, expected.CredentialEpoch)
		return 0
	}
	resumingMonitoring := monitoringPending
	var requestTemplate bindstate.BindingRequestTemplate
	if resumingMonitoring {
		_, requestTemplate, err = bindstate.LoadPendingTemplate(cfg.Runtime.StateDirectory, "monitoring")
		if err != nil {
			fmt.Fprintln(c.errOut, "监控绑定 pending 请求模板不安全或不受支持；拒绝猜测重试")
			return 1
		}
		canonicalEndpoint, canonicalErr := bindstate.CanonicalBindingEndpoint(strings.TrimSpace(*endpoint))
		if canonicalErr != nil || canonicalEndpoint != requestTemplate.Endpoint {
			fmt.Fprintln(c.errOut, "监控绑定重试必须使用原来的 API 地址；未读取绑定码或发送网络请求")
			return 1
		}
	}
	var previous bindstate.MonitoringState
	if existing, err := bindstate.LoadMonitoring(cfg.Runtime.StateDirectory); err == nil && !resumingMonitoring {
		if !*replace {
			fmt.Fprintln(c.errOut, "监控信任域已经绑定；轮换需使用新绑定码和 --replace")
			return 1
		}
		previous = existing
	} else if !resumingMonitoring && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(c.errOut, "现有监控绑定状态不安全或无效，未执行替换")
		return 1
	}
	if !resumingMonitoring {
		readinessContext, cancelReadiness := context.WithTimeout(context.Background(), 15*time.Minute)
		prepared, readinessErr := c.ensureBindingPVEReady(readinessContext, filename, cfg)
		cancelReadiness()
		if readinessErr != nil {
			fmt.Fprintln(c.errOut, "PVE_REAL_READINESS_FAILED: 未能启用并验证本机真实 PVE 读取；未读取或发送监控一次性绑定码")
			return 1
		}
		cfg = prepared
		if strings.TrimSpace(*host) == "" {
			localHostname, hostErr := os.Hostname()
			if hostErr != nil {
				fmt.Fprintln(c.errOut, "无法读取本机主机名")
				return 1
			}
			*host = localHostname
		}
		versionContext, cancelVersion := context.WithTimeout(context.Background(), 3*time.Second)
		detectedPVEVersion, versionErr := c.localPVEVersion(versionContext)
		cancelVersion()
		if versionErr != nil {
			fmt.Fprintln(c.errOut, "PVE_VERSION_DISCOVERY_FAILED: 无法从本机可信 PVE 环境读取有效版本；请确认 /usr/bin/pveversion 可执行且当前主机为 PVE 8/9")
			return 1
		}
		deviceID, deviceErr := bindstate.LoadOrCreateDeviceID(cfg.Runtime.StateDirectory)
		if deviceErr != nil {
			fmt.Fprintln(c.errOut, "设备状态目录不安全或不可写")
			return 1
		}
		requestTemplate, err = bindstate.NewBindingRequestTemplate("monitoring", strings.TrimSpace(*endpoint), deviceID, c.version, strings.TrimSpace(*host), enrollment.NodeClaim{NodeRef: strings.TrimSpace(*nodeRef), PVEVersion: detectedPVEVersion}, splitCapabilities(*capabilities))
		if err != nil {
			fmt.Fprintln(c.errOut, "无法创建安全的监控绑定请求模板")
			return 1
		}
	} else if cfg.PVE.Source != "api" || (cfg.Mode != "production" && c.bindingPVE == nil) {
		fmt.Fprintln(c.errOut, "监控绑定恢复事务缺少已验证的真实 PVE 配置；拒绝继续")
		return 1
	}
	// Validate monitoring syntax after readiness but before durable pending,
	// service stop, or network activity. The independent monitoring grammar is
	// deliberately not delegated to the website domain.
	code, err := c.readBindingCode(*codeFile)
	if err != nil {
		fmt.Fprintln(c.errOut, "读取监控绑定码失败")
		return 1
	}
	if err := monitorenrollment.ValidateBindingCode(code); err != nil {
		fmt.Fprintln(c.errOut, "监控绑定码格式无效；未写入绑定事务、未停止 Agent 或发送网络请求")
		return 2
	}
	if cfg.Mode != "test" {
		parsed, parseErr := url.Parse(strings.TrimSpace(*endpoint))
		if parseErr != nil || !strings.EqualFold(parsed.Scheme, "https") {
			fmt.Fprintln(c.errOut, "生产模式下监控绑定地址必须使用 HTTPS")
			return 2
		}
	}
	client, err := monitorenrollment.NewClient(monitorenrollment.Config{Endpoint: requestTemplate.Endpoint})
	if err != nil {
		fmt.Fprintln(c.errOut, "监控绑定地址必须是 HTTPS（测试时仅允许 loopback HTTP）")
		return 2
	}
	request := monitorenrollment.Request{SchemaVersion: monitorenrollment.SchemaVersion, BindingCode: code, DeviceID: requestTemplate.DeviceID, AgentVersion: requestTemplate.AgentVersion, Hostname: requestTemplate.Hostname, NodeClaim: requestTemplate.NodeClaim, Capabilities: append([]string(nil), requestTemplate.Capabilities...)}
	fingerprint, err := bindstate.BindingRequestFingerprint("monitoring", requestTemplate.Endpoint, request)
	if err != nil {
		fmt.Fprintln(c.errOut, "无法生成监控绑定请求指纹")
		return 1
	}
	requestID, storedTemplate, err := bindstate.PreparePendingLocked(cfg.Runtime.StateDirectory, "monitoring", fingerprint, requestTemplate)
	if err != nil {
		if errors.Is(err, bindstate.ErrPendingRequestConflict) {
			fmt.Fprintln(c.errOut, "存在上一次结果未确定的监控绑定请求；本次新绑定码未发送。请使用上一次的原绑定码重试，或先在监控站确认并撤销旧请求后再处理本机未决状态")
			return 1
		}
		fmt.Fprintln(c.errOut, "无法持久化监控绑定请求；未发送绑定码")
		return 1
	}
	if !reflect.DeepEqual(storedTemplate, requestTemplate) {
		fmt.Fprintln(c.errOut, "监控绑定请求模板在重试期间发生变化；拒绝发送网络请求")
		return 1
	}
	request.RequestID = requestID
	quiesceContext, cancelQuiesce := context.WithTimeout(context.Background(), 30*time.Second)
	quiesceErr := c.quiesceAgentForBinding(quiesceContext)
	cancelQuiesce()
	if quiesceErr != nil {
		if recoveryErr := c.restoreAfterUnsentBinding(cfg, "monitoring"); recoveryErr != nil {
			fmt.Fprintln(c.errOut, "监控绑定未发送：无法确认 Agent 已停止，且旧服务恢复未确认；请检查本机 Agent")
			return 1
		}
		fmt.Fprintln(c.errOut, "监控绑定未发送：无法确认 Agent 已停止；已恢复原服务")
		return 1
	}
	response, err := client.Bind(context.Background(), request)
	if err != nil {
		// Every monitoring HTTP response is ambiguous for a consumed one-time
		// code. Retain the exact durable request ID, then restore the last
		// complete runtime so the independent website domain stays available.
		if resumingMonitoringCommit {
			fmt.Fprintln(c.errOut, "监控绑定请求结果未确定；本地新凭据提交尚未完成，Agent 保持受保护状态，请使用同一绑定码重试")
			return 1
		}
		if recoveryErr := c.recoverAfterAmbiguousBinding(cfg); recoveryErr != nil {
			fmt.Fprintln(c.errOut, "监控绑定请求结果未确定；已保留同一绑定码请求，但旧 Agent 运行状态恢复未确认")
			return 1
		}
		fmt.Fprintln(c.errOut, "监控绑定请求结果未确定；已保留同一绑定码请求并恢复现有 Agent 运行状态，请使用同一绑定码重试")
		return 1
	}
	state := bindstate.MonitoringFromResponse(requestTemplate.Endpoint, requestTemplate.DeviceID, response)
	if resumingMonitoringCommit && (monitoringCommit.BindingID != response.BindingID || monitoringCommit.CredentialEpoch != response.CredentialEpoch) {
		fmt.Fprintln(c.errOut, "监控绑定恢复响应与持久事务标记不一致；拒绝覆盖")
		return 1
	}
	if !resumingMonitoringCommit {
		if err := bindstate.BeginMonitoringCommit(cfg.Runtime.StateDirectory, state.BindingID, state.CredentialEpoch); err != nil {
			fmt.Fprintln(c.errOut, "监控绑定已由服务端签发，但无法建立本地提交标记；Agent 保持停止，请使用同一绑定码重试")
			return 1
		}
	}
	if !resumingMonitoring && previous.CredentialEpoch != 0 && response.CredentialEpoch <= previous.CredentialEpoch {
		fmt.Fprintln(c.errOut, "监控绑定响应的凭据版本未前进；事务保持冻结，请使用同一绑定码重试")
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
		fmt.Fprintln(c.errOut, "监控绑定响应缺少受支持的审计路由；事务保持冻结，请使用同一绑定码重试")
		return 1
	}
	cfg.Destinations.MonitoringAudit.Enabled = true
	cfg.Destinations.MonitoringAudit.URL = auditEndpoint
	cfg.Destinations.MonitoringAudit.Auth = config.AuthConfig{Mode: "hmac-sha256", KeyIDEnv: bindingoverlay.MonitoringKeyIDEnv, SecretEnv: bindingoverlay.MonitoringSecretEnv}
	cfg.Destinations.MonitoringAudit.PayloadFormat = "audit-v1"
	cfg.Destinations.MonitoringAudit.Compression = response.Telemetry.Compression
	cfg.Destinations.MonitoringAudit.MaxCompressedBytes = monitorenrollment.AuditMaxCompressedBytes
	cfg.Destinations.MonitoringAudit.MaxUncompressedBytes = monitorenrollment.AuditMaxUncompressedBytes
	autoEnableProductionExecution(&cfg, "monitoring", response.DeviceID)
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(c.errOut, "监控绑定生成的配置未通过严格校验；事务保持冻结，请使用同一绑定码重试")
		return 1
	}
	configBackup, err := atomicUpdate(filename, cfg)
	if err != nil {
		fmt.Fprintln(c.errOut, "监控绑定配置保存失败；新凭据可能已签发，事务保持冻结，请使用同一绑定码重试")
		return 1
	}
	if err := bindstate.SaveMonitoring(cfg.Runtime.StateDirectory, state); err != nil {
		fmt.Fprintf(c.errOut, "监控绑定密钥保存失败；不会恢复可能已撤销的旧凭据，事务保持冻结，请使用同一绑定码重试；配置备份=%s\n", configBackup)
		return 1
	}
	expected := bindingActivationExpectation{Domain: "monitoring", BindingID: state.BindingID, CredentialEpoch: state.CredentialEpoch}
	if err := c.finalizeMonitoringBindingCommit(filename, cfg, expected); err != nil {
		fmt.Fprintf(c.errOut, "监控绑定本地提交回验失败；不会恢复可能已撤销的旧凭据，Agent 保持停止，请使用同一绑定码重试；配置备份=%s\n", configBackup)
		return 1
	}
	activationContext, cancelActivation := context.WithTimeout(context.Background(), 15*time.Minute)
	activationErr := c.activateAgentBinding(activationContext, cfg, expected)
	cancelActivation()
	if activationErr != nil {
		fmt.Fprintf(c.errOut, "MONITORING_BIND_ACTIVATION_FAILED: 新监控绑定已安全保存但尚未确认首次真实上传；不会恢复服务端已经撤销的旧凭据，请检查 systemctl status ppflight-agent 后重试启动；配置备份=%s\n", configBackup)
		return 1
	}
	fmt.Fprintf(c.out, "监控绑定完成并已自动生效：%s active，bindingId=%s，credentialEpoch=%d；VPS写操作=%t；配置备份=%s。官网绑定未被修改。\n", agentServiceUnit, state.BindingID, state.CredentialEpoch, cfg.Control.ProductionExecution, configBackup)
	return 0
}

func (c *cli) validateBindingEndpoint(endpoint string, monitoring bool) error {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed == nil || (c.bindingPVE == nil && !strings.EqualFold(parsed.Scheme, "https")) {
		return errors.New("binding endpoint is not production-safe")
	}
	if monitoring {
		_, err = monitorenrollment.NewClient(monitorenrollment.Config{Endpoint: endpoint})
	} else {
		_, err = enrollment.NewClient(enrollment.Config{Endpoint: endpoint})
	}
	return err
}

func validateMonitoringBindingFiles(filename string, expected bindingActivationExpectation) error {
	if err := validateMonitoringBindingDiskFiles(filename, expected); err != nil {
		return err
	}
	cfg, err := config.LoadFile(filename)
	if err != nil {
		return err
	}
	lookup, err := config.ResolvePVEEnvironmentLookup(cfg, os.LookupEnv)
	if err != nil {
		return err
	}
	secrets, err := bindingoverlay.Resolve(cfg, lookup)
	if err != nil {
		return err
	}
	if secrets.MonitoringBindingID != expected.BindingID || secrets.Monitoring.CredentialEpoch != expected.CredentialEpoch || secrets.MonitoringAudit.CredentialEpoch != expected.CredentialEpoch {
		return errors.New("monitoring runtime binding overlay does not match the issued response")
	}
	return nil
}

func validateMonitoringBindingDiskFiles(filename string, expected bindingActivationExpectation) error {
	cfg, err := config.LoadFile(filename)
	if err != nil {
		return err
	}
	state, err := bindstate.LoadMonitoring(cfg.Runtime.StateDirectory)
	if err != nil || state.BindingID != expected.BindingID || state.CredentialEpoch != expected.CredentialEpoch {
		return errors.New("monitoring binding state does not match the issued response")
	}
	auditEndpoint, err := monitorenrollment.AuditEndpoint(state.IngestEndpoint)
	if err != nil || !cfg.Destinations.Monitoring.Enabled || cfg.Destinations.Monitoring.URL != state.IngestEndpoint ||
		cfg.Destinations.Monitoring.Auth.Mode != "hmac-sha256" || cfg.Destinations.Monitoring.Auth.KeyIDEnv != bindingoverlay.MonitoringKeyIDEnv || cfg.Destinations.Monitoring.Auth.SecretEnv != bindingoverlay.MonitoringSecretEnv ||
		cfg.Destinations.Monitoring.PayloadFormat != state.Telemetry.PayloadFormat || cfg.Destinations.Monitoring.Compression != state.Telemetry.Compression ||
		cfg.Destinations.Monitoring.MaxCompressedBytes != state.Telemetry.MaxCompressedBytes || cfg.Destinations.Monitoring.MaxUncompressedBytes != state.Telemetry.MaxUncompressedBytes ||
		!cfg.Destinations.MonitoringAudit.Enabled || cfg.Destinations.MonitoringAudit.URL != auditEndpoint || cfg.Destinations.MonitoringAudit.Auth.Mode != "hmac-sha256" ||
		cfg.Destinations.MonitoringAudit.Auth.KeyIDEnv != bindingoverlay.MonitoringKeyIDEnv || cfg.Destinations.MonitoringAudit.Auth.SecretEnv != bindingoverlay.MonitoringSecretEnv ||
		cfg.Destinations.MonitoringAudit.PayloadFormat != "audit-v1" || cfg.Destinations.MonitoringAudit.Compression != state.Telemetry.Compression ||
		cfg.Destinations.MonitoringAudit.MaxCompressedBytes != monitorenrollment.AuditMaxCompressedBytes || cfg.Destinations.MonitoringAudit.MaxUncompressedBytes != monitorenrollment.AuditMaxUncompressedBytes {
		return errors.New("monitoring public configuration does not match the issued response")
	}
	return nil
}

func rollbackMonitoringBinding(filename string, original config.Config, stateDirectory, stateBackup string) error {
	stateErr := bindstate.RestoreMonitoring(stateDirectory, stateBackup)
	_, configErr := atomicUpdate(filename, original)
	return errors.Join(stateErr, configErr)
}

type websiteAssignmentSnapshot struct {
	Exists bool
	Raw    json.RawMessage
}

func captureWebsiteAssignment(filename string) (websiteAssignmentSnapshot, error) {
	file, err := fsutil.OpenRegularInDirectoryNoFollow(filepath.Dir(filename), filepath.Base(filename))
	if errors.Is(err, os.ErrNotExist) {
		return websiteAssignmentSnapshot{}, nil
	}
	if err != nil {
		return websiteAssignmentSnapshot{}, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, enrollment.MaxResponseBytes+1))
	if err != nil || len(raw) > enrollment.MaxResponseBytes || !json.Valid(raw) {
		return websiteAssignmentSnapshot{}, errors.New("website assignment is invalid")
	}
	return websiteAssignmentSnapshot{Exists: true, Raw: append(json.RawMessage(nil), raw...)}, nil
}

func restoreWebsiteAssignment(filename string, snapshot websiteAssignmentSnapshot) error {
	if snapshot.Exists {
		return bindstate.WriteAssignment(filename, snapshot.Raw)
	}
	file, err := fsutil.OpenRegularInDirectoryNoFollow(filepath.Dir(filename), filepath.Base(filename))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Remove(filename); err != nil {
		return err
	}
	return fsutil.SyncDir(filepath.Dir(filename))
}

func validateWebsiteBindingFiles(filename string, expected bindingActivationExpectation) error {
	if err := validateWebsiteBindingDiskFiles(filename, expected); err != nil {
		return err
	}
	cfg, err := config.LoadFile(filename)
	if err != nil {
		return err
	}
	lookup, err := config.ResolvePVEEnvironmentLookup(cfg, os.LookupEnv)
	if err != nil {
		return err
	}
	secrets, err := bindingoverlay.Resolve(cfg, lookup)
	if err != nil {
		return err
	}
	if secrets.WebsiteBindingID != expected.BindingID || secrets.WebsiteCredentialEpoch != expected.CredentialEpoch ||
		secrets.WebsiteMetering.CredentialEpoch != expected.CredentialEpoch || secrets.WebsiteTelemetry.CredentialEpoch != expected.CredentialEpoch ||
		secrets.Assignments.CredentialEpoch != expected.CredentialEpoch {
		return errors.New("website runtime binding overlay does not match the issued response")
	}
	if cfg.Control.Enabled && (secrets.ControlAPI.CredentialEpoch != expected.CredentialEpoch || secrets.ControlReceipts.CredentialEpoch != expected.CredentialEpoch) {
		return errors.New("website control binding overlay does not match the issued response")
	}
	return nil
}

func validateWebsiteBindingDiskFiles(filename string, expected bindingActivationExpectation) error {
	cfg, err := config.LoadFile(filename)
	if err != nil {
		return err
	}
	state, err := bindstate.Load(cfg.Runtime.StateDirectory)
	if err != nil || state.BindingID != expected.BindingID || state.CredentialEpoch != expected.CredentialEpoch {
		return errors.New("website binding state does not match the issued response")
	}
	assignment, err := captureWebsiteAssignment(cfg.Assignments.File)
	assignmentCanonical, assignmentCanonicalErr := compactJSON(assignment.Raw)
	stateCanonical, stateCanonicalErr := compactJSON(state.AssignmentDocument)
	if err != nil || !assignment.Exists || assignmentCanonicalErr != nil || stateCanonicalErr != nil || !bytes.Equal(assignmentCanonical, stateCanonical) {
		return errors.New("website assignment does not match the issued response")
	}
	return nil
}

func compactJSON(raw []byte) ([]byte, error) {
	var result bytes.Buffer
	if err := json.Compact(&result, raw); err != nil {
		return nil, err
	}
	return result.Bytes(), nil
}

func rollbackWebsiteBinding(filename string, original config.Config, stateDirectory, stateBackup, assignmentFile string, assignment websiteAssignmentSnapshot) error {
	stateErr := bindstate.RestoreWebsite(stateDirectory, stateBackup)
	_, configErr := atomicUpdate(filename, original)
	assignmentErr := restoreWebsiteAssignment(assignmentFile, assignment)
	rollbackErr := errors.Join(stateErr, configErr, assignmentErr)
	if rollbackErr == nil {
		rollbackErr = bindstate.FinishWebsiteCommit(stateDirectory)
	}
	return rollbackErr
}

func (c *cli) website(filename string, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.errOut, "website 需要 bind、unbind、status、show、test、metering、telemetry 或 control")
		return 2
	}
	// Preserve the existing top-level binding workflow exactly, including its
	// stdin-only one-time code handling and replacement safeguards.
	if args[0] == "bind" {
		return c.bind(filename, args[1:])
	}
	if args[0] == "unbind" {
		if len(args) != 1 {
			fmt.Fprintln(c.errOut, "website unbind 不接受额外参数")
			return 2
		}
		return c.menuRemoveBinding(bufio.NewReader(io.LimitReader(c.in, 64<<10)), filename, false)
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
		original := cfg
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
		return c.saveMutation(filename, original, cfg)
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
	backupEnabled, err := c.promptYesNo(reader, "模板创建完成后，是否额外生成备份文件？", false)
	if err != nil {
		return 2
	}
	backupPolicy, backupStorage := "required", ""
	if !backupEnabled {
		backupPolicy = "disabled"
	} else {
		fmt.Fprintln(c.out, "备份可用于恢复模板，但会占用所选备份存储的空间。")
		backupStorage, refreshed, err = c.chooseTemplateStorage(ctx, reader, discovery.Storages, "backup", "选择模板备份存储")
		if err != nil {
			fmt.Fprintf(c.errOut, "备份存储选择失败: %v\n", err)
			return 2
		}
		discovery.Storages = refreshed
	}
	externalBridge, err := c.promptLine(reader, "外网网桥（模板 net0）[vmbr0]: ")
	if err != nil {
		return 2
	}
	if externalBridge == "" {
		externalBridge = "vmbr0"
	}
	internalEnabled, err := c.promptYesNo(reader, "是否为模板添加内网网卡 net1？", false)
	if err != nil {
		return 2
	}
	internalBridge := ""
	if internalEnabled {
		for {
			internalBridge, err = c.promptLine(reader, "内网网桥（模板 net1）[vmbr1]: ")
			if err != nil {
				return 2
			}
			if internalBridge == "" {
				internalBridge = "vmbr1"
			}
			if internalBridge == externalBridge {
				fmt.Fprintln(c.out, "内网网桥不能与外网网桥相同，请重新输入。")
				continue
			}
			if !safeTemplateBridgeName(internalBridge) {
				fmt.Fprintln(c.out, "内网网桥名称必须是 1-15 位 ASCII 字母、数字、点、下划线或连字符，且首位必须是字母或数字。")
				continue
			}
			break
		}
	}
	if internalBridge != "" {
		ready, ensureErr := c.ensureTemplateInternalBridge(ctx, reader, internalBridge)
		if ensureErr != nil {
			fmt.Fprintf(c.errOut, "内网网桥准备失败: %v\n", ensureErr)
			fmt.Fprintln(c.out, "未执行任何模板变更。")
			return 1
		}
		if !ready {
			fmt.Fprintln(c.out, "已取消创建内网网桥；未执行任何模板变更。")
			return 0
		}
	}
	fmt.Fprintf(c.out, "网络配置：\n  外网 net0 -> %s\n", externalBridge)
	if internalBridge == "" {
		fmt.Fprintln(c.out, "  内网 net1 -> 不创建")
	} else {
		fmt.Fprintf(c.out, "  内网 net1 -> %s\n", internalBridge)
	}
	requestID, err := protocol.NewID()
	if err != nil {
		return 1
	}
	operationID, err := protocol.NewID()
	if err != nil {
		return 1
	}
	baseArgs := []string{"bootstrap", "--image-storage", imageStorage, "--template-storage", templateStorage, "--backup-policy", backupPolicy, "--items", items, "--bridge", externalBridge, "--request-id", requestID, "--operation-id", operationID}
	if backupPolicy == "required" {
		baseArgs = append(baseArgs, "--backup-storage", backupStorage)
	}
	if internalBridge != "" {
		baseArgs = append(baseArgs, "--internal-bridge", internalBridge)
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
	confirmed, err := c.promptPlanExecution(reader)
	if err != nil || !confirmed {
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
	confirmed, err := c.promptYesNo(reader, "确认配置 storage content 并继续？", false)
	if err != nil || !confirmed {
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

func (c *cli) promptYesNo(reader *bufio.Reader, question string, defaultYes bool) (bool, error) {
	defaultValue := "n"
	if defaultYes {
		defaultValue = "y"
	}
	prompt := fmt.Sprintf("%s [y/n]（回车默认：%s）: ", strings.TrimSpace(question), defaultValue)
	for {
		value, err := c.promptLine(reader, prompt)
		if err != nil {
			return false, err
		}
		switch strings.ToLower(value) {
		case "":
			return defaultYes, nil
		case "y":
			return true, nil
		case "n":
			return false, nil
		default:
			fmt.Fprintln(c.out, "输入无效：只接受 y 或 n；直接回车使用显示的默认值。")
		}
	}
}

func (c *cli) promptPlanExecution(reader *bufio.Reader) (bool, error) {
	return c.promptYesNo(reader, "确认执行以上模板计划？", false)
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
	original := cfg
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
	return c.saveMutation(filename, original, cfg)
}

// saveMutation applies a public configuration change only while holding the
// same bind-state transaction lock as enrollment.  The before snapshot makes
// a stale interactive `set` fail instead of overwriting a concurrent bind,
// unbind, PVE prepare, or another set operation.
func (c *cli) saveMutation(filename string, before, after config.Config) int {
	latest, transaction, err := c.acquireStableMutationTransaction(filename, before.Runtime.StateDirectory)
	if err != nil {
		fmt.Fprintln(c.errOut, "配置未更新：另一个 Agent 管理事务正在执行，或存在未完成绑定事务")
		return 1
	}
	defer transaction.Close()
	if !reflect.DeepEqual(latest, before) {
		fmt.Fprintln(c.errOut, "配置未更新：配置在操作期间发生变化，请重新读取后重试")
		return 1
	}
	if err := after.Validate(); err != nil {
		fmt.Fprintf(c.errOut, "修改无效，未写入: %v\n", err)
		return 1
	}
	backup, err := atomicUpdate(filename, after)
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
