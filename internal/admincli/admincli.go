// Package admincli implements the local ag-pve SSH administration command.
// It never reads or prints secret values; only environment-variable names are
// stored in the Agent configuration.
package admincli

import (
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
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ppflight/ppflight-agent/internal/config"
)

type cli struct {
	out, errOut io.Writer
	version     string
}

func Run(args []string, version string, out, errOut io.Writer) int {
	if out == nil {
		out = os.Stdout
	}
	if errOut == nil {
		errOut = os.Stderr
	}
	return (&cli{out: out, errOut: errOut, version: version}).run(args)
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
	if len(args) == 0 || args[0] == "help" {
		c.usage()
		return 0
	}
	if args[0] == "version" {
		fmt.Fprintln(c.out, c.version)
		return 0
	}
	switch args[0] {
	case "status":
		return c.status(*filename)
	case "validate":
		return c.validate(*filename)
	case "monitor", "monitoring":
		return c.monitoring(*filename, args[1:])
	case "website":
		return c.website(*filename, args[1:])
	default:
		fmt.Fprintf(c.errOut, "未知命令 %q\n", args[0])
		return 2
	}
}

func (c *cli) usage() {
	fmt.Fprintln(c.out, `ag-pve - PPFlight Agent SSH 管理命令

  ag-pve [--config FILE] status
  ag-pve [--config FILE] validate
  ag-pve [--config FILE] monitoring show|test|set [选项]
  ag-pve [--config FILE] monitoring query|modify     # 预留，v0.1 返回未实现
  ag-pve [--config FILE] website show|test
  ag-pve [--config FILE] website metering|telemetry set [选项]
  ag-pve [--config FILE] website control set [选项]
  ag-pve [--config FILE] website query|modify        # 预留，v0.1 返回未实现

show 只显示脱敏配置；test 只做 DNS/TCP/TLS 探测，不发送业务数据；set 原子写入并保留 .bak 备份，不自动重启服务。官网/监控站的远程资产查询修改 API 已预留，待服务端契约完成后补入。`)
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
	if _, err := cfg.ResolveSecrets(os.LookupEnv); err != nil {
		fmt.Fprintf(c.errOut, "环境密钥检查失败: %v\n", err)
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
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Get("http://" + cfg.Runtime.ListenAddress + "/status")
	if err != nil {
		fmt.Fprintf(c.errOut, "Agent 状态查询失败: %v\n", err)
		return 1
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil || response.StatusCode != http.StatusOK {
		fmt.Fprintf(c.errOut, "Agent 状态接口失败: HTTP %d\n", response.StatusCode)
		return 1
	}
	var value any
	if json.Unmarshal(body, &value) != nil {
		fmt.Fprintln(c.errOut, "Agent 状态不是有效 JSON")
		return 1
	}
	return printJSON(c.out, value)
}

func (c *cli) monitoring(filename string, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.errOut, "monitoring 需要 show、test 或 set")
		return 2
	}
	cfg, ok := c.load(filename)
	if !ok {
		return 1
	}
	switch args[0] {
	case "show":
		return printJSON(c.out, cfg.Destinations.Monitoring)
	case "test":
		return c.testURLs(map[string]string{"monitoring": cfg.Destinations.Monitoring.URL})
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

func (c *cli) website(filename string, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.errOut, "website 需要 show、test、metering、telemetry 或 control")
		return 2
	}
	cfg, ok := c.load(filename)
	if !ok {
		return 1
	}
	switch args[0] {
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
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return "", err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	original, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(filename)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("refusing to replace a symlink or non-regular config file")
	}
	backup := filename + ".bak." + time.Now().UTC().Format("20060102T150405.000000000Z")
	if err := os.WriteFile(backup, original, info.Mode().Perm()); err != nil {
		return "", err
	}
	backupHandle, err := os.Open(backup)
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
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(backup, int(stat.Uid), int(stat.Gid))
	}
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
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if err := temporary.Chown(int(stat.Uid), int(stat.Gid)); err != nil {
			_ = temporary.Close()
			return "", err
		}
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
	directory, err := os.Open(filepath.Dir(filename))
	if err != nil {
		return "", err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
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
	if err != nil || parsed.Hostname() == "" {
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
		conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: parsed.Hostname()})
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
	conn, err := dialer.DialContext(context.Background(), "tcp", address)
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
