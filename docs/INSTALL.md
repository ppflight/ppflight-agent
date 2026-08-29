# 安装、测试与运维

本页是 PPFlight PVE Agent 的发布运维清单，目标为 Proxmox VE 8.x/9.x 宿主机。先在测试节点安装和联调；不要直接将首版连接到正在给客户计费的生产账本。

## 0. 前置条件

- Debian 系 Proxmox VE 8.x 或 9.x，root 或可用 sudo 的管理员账户。
- 宿主机时间同步（NTP/chrony）；HMAC 默认只允许约五分钟时钟偏差。
- Agent 到官网/监控站的出站 HTTPS；不需要把 PVE 8006、9100、9633 开放到公网。
- PVE 本机 CA 通常为 /etc/pve/pve-root-ca.pem；安装器会复制公开 CA 到 /etc/ppflight-agent/pve-root-ca.pem，Agent 无需加入 www-data 组。
- 准备两类 PVE API Token：只读采集 token、未来控制执行专用写 token。二者绝不复用。
- PVE 已安装 smartmontools。smartctl_exporter 通常需受限 root 身份读取物理盘；主 Agent 不应一直以 root 身份运行。

## 1. 获取与校验发布包

从 GitHub Release 下载对应架构的二进制、示例配置、systemd 单元和校验文件。验证 SHA-256 后再安装：

~~~bash
sha256sum -c ppflight-agent_<version>_linux_amd64.sha256
sudo install -m 0755 ppflight-agent /usr/local/bin/ppflight-agent
sudo /usr/local/bin/ppflight-agent --version
~~~

从源码构建需要 Go 1.23 或更高版本：

~~~bash
git clone <你的 GitHub 仓库地址> ppflight-agent
cd ppflight-agent
go test ./...
go vet ./...
go build ./...
~~~

发布者应在 Release 中提供实际二进制名称和 SHA-256；不要执行未经校验的远程下载脚本。

安装脚本会将唯一的 Agent 程序放在 /usr/local/bin/ppflight-agent，并创建 /usr/local/bin/ag-pve 软链接。ag-pve 不是第二个服务或第二套配置；它只是同一二进制在 SSH 本机管理模式下的名称。

## 2. 创建只读 PVE Token

在 PVE 管理界面或使用 pveum 创建专用用户，例如 ppflight-read@pve，只授予采集所需的最小读取权限。Agent 要读取节点状态、存储、任务、QEMU/LXC current/config，以及 QEMU Guest Agent 的只读端点。实际 ACL 必须按你的 PVE 资源范围验证。

创建目录及仅 root 可读环境文件：

~~~bash
sudo install -d -m 0750 /etc/ppflight-agent /var/lib/ppflight-agent
sudo editor /etc/ppflight-agent/agent.env
sudo chmod 0600 /etc/ppflight-agent/agent.env
~~~

环境文件示例（不要提交 Git）：

~~~bash
PVE_READ_TOKEN_ID='ppflight-read@pve!agent'
PVE_READ_TOKEN_SECRET='只在此处保存的 PVE token secret'
WEBSITE_METERING_KEY_ID='cluster-key-2026-01'
WEBSITE_METERING_SECRET='官网为本集群签发的 HMAC secret'
WEBSITE_TELEMETRY_KEY_ID='cluster-key-2026-01'
WEBSITE_TELEMETRY_SECRET='官网为本集群签发的 HMAC secret'
CONTROL_COMMAND_SECRET='官网命令签名 secret'
~~~

PVE token secret 只在创建时显示一次。丢失时应撤销并重建，不能将 secret 扩散到聊天记录、工单或 Git。

## 3. node_exporter 与 smartctl_exporter

这两个 exporter 不是 Agent 内置替代品；Agent 会从 loopback 的 Prometheus 文本端点读取并标准化它们的数据。

- node_exporter 必须监听 127.0.0.1:9100，提供 Linux 宿主机 CPU、load、内存、文件系统、网卡、ZFS 等。
- smartctl_exporter 必须监听 127.0.0.1:9633，并使服务账户能读取 smartctl 数据，提供盘健康、温度、错误和 NVMe 寿命。
- 不要绑定 0.0.0.0，不要把 9100/9633 公开到 Internet。

建议把 exporter 做成独立 systemd 服务，使用 ProtectSystem、PrivateTmp、最小 capability 等 hardening。exporter 版本、下载 URL 和 SHA-256 应由正式 Release 固定后再安装；不要在未校验时下载运行。

本机验证：

~~~bash
curl --fail http://127.0.0.1:9100/metrics >/dev/null
curl --fail http://127.0.0.1:9633/metrics >/dev/null
~~~

## 4. 配置 Agent（先 test）

创建 /etc/ppflight-agent/agent.yaml 与 /etc/ppflight-agent/assignments.json。尽管样例扩展名为 yaml，其内容刻意采用严格 JSON（JSON 是 YAML 1.2 的合法子集）；字段名拼错会被拒绝。关键原则：

- mode 必须先为 test：计费全部为 shadow，控制命令验签但不会执行。
- pve.source 为 api，endpoint 指向本机 https://127.0.0.1:8006，使用 CA 与**只读** token。
- identity.clusterRef 使用官网不可变 ID，不能用人可编辑 slug。
- exporter URL 只能是 loopback HTTP。
- 测试期可禁用外发目的地，或使用专用测试 API/HMAC key。
- 控制模块默认启用；没有配置 poll/result URL 不表示官网控制服务已经完成。

完成配置检查与单次采样（命令行参数以最终 Release 为准）：

~~~bash
sudo -u ppflight-agent /usr/local/bin/ppflight-agent --config /etc/ppflight-agent/agent.yaml --check-config
sudo -u ppflight-agent /usr/local/bin/ppflight-agent --config /etc/ppflight-agent/agent.yaml --once
~~~

映射与协议字段见 [API 契约](API.md)。

### 4.1 使用 ag-pve 进行 SSH 本机管理

ag-pve 只对本机 /etc/ppflight-agent/agent.yaml 操作。默认配置路径可在任意命令前以 --config FILE 替换。

~~~bash
# Agent 正在运行时，输出它的本地 /status JSON
sudo ag-pve status

# 读取配置并验证严格 schema 和所引用的环境变量；不发出业务请求
sudo ag-pve validate

# 查看（无 secret 值）或探测监控站目标
sudo ag-pve monitoring show
sudo ag-pve monitoring test

# 设置监控站目标。可选 compression 为 none 或 gzip。
sudo ag-pve monitoring set --enabled=true \
  --url=https://monitor.example/api/ingest \
  --auth-mode=bearer --bearer-token-env=MONITORING_BEARER_TOKEN \
  --payload-format=legacy-ingest-v1 --compression=gzip

# 查看或探测官网目标
sudo ag-pve website show
sudo ag-pve website test

# 分别设置官网计费与业务遥测目标
sudo ag-pve website metering set --enabled=true \
  --url=https://www.example/internal/v1/metering/usage-batches \
  --auth-mode=hmac-sha256 --key-id-env=WEBSITE_METERING_KEY_ID --secret-env=WEBSITE_METERING_SECRET
sudo ag-pve website telemetry set --enabled=true \
  --url=https://www.example/internal/v1/telemetry/batches \
  --auth-mode=hmac-sha256 --key-id-env=WEBSITE_TELEMETRY_KEY_ID --secret-env=WEBSITE_TELEMETRY_SECRET

# 设置官网控制轮询和回执。先保持 production-execution=false。
sudo ag-pve website control set --enabled=true \
  --poll-url=https://www.example/internal/v1/agents/commands \
  --result-url=https://www.example/internal/v1/agents/agent-pve-test-01/command-receipts \
  --auth-mode=hmac-sha256 --key-id-env=CONTROL_API_KEY_ID --secret-env=CONTROL_API_SECRET \
  --command-secret-env=CONTROL_COMMAND_SECRET --production-execution=false
~~~

show 只输出配置和环境变量名称，不会显示 Token、HMAC secret 或密码。test 只做 DNS、TCP 和 HTTPS TLS 握手（HTTP 地址只做 TCP）；它不发送 HTTP 请求、不上传指标，也不会创建或修改远端资产。set 先按配置校验，随后原子写入，并在同目录留下带时间戳的 .bak 备份；**set 不会自动重启服务**。每次 set 后均应执行：

~~~bash
sudo ag-pve validate
sudo systemctl restart ppflight-agent
sudo ag-pve status
~~~

destination 的 set 命令支持 --enabled、--url、--auth-mode、--key-id-env、--secret-env、--bearer-token-env、--compression 和 --payload-format。现有监控 `/api/ingest` 选 `legacy-ingest-v1`；未来 `/internal/v1/monitoring/batches` 选 `telemetry-v1`。website control set 还支持 --poll-url、--result-url、--command-secret-env 和 --production-execution。控制写 PVE Token 的环境变量名称仍在基础配置中设置，且必须与只读采集 Token 分离。

官网/监控站远程资产查询、变更、创建 API 目前只是未来扩展预留；`ag-pve monitoring query|modify` 与 `ag-pve website query|modify` 只会安全返回未实现，不发送请求。不要将 ag-pve 当作远程 PVE/VPS 管理客户端。

## 5. systemd 运行

推荐单元结构如下；正式 Release 的 unit 为准：

~~~ini
[Unit]
Description=PPFlight PVE Agent
After=network-online.target
Wants=network-online.target

[Service]
User=ppflight-agent
Group=ppflight-agent
EnvironmentFile=/etc/ppflight-agent/agent.env
ExecStart=/usr/local/bin/ppflight-agent --config /etc/ppflight-agent/agent.yaml
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ReadWritePaths=/var/lib/ppflight-agent

[Install]
WantedBy=multi-user.target
~~~

~~~bash
sudo systemctl daemon-reload
sudo systemctl enable --now ppflight-agent
sudo systemctl status ppflight-agent
sudo journalctl -u ppflight-agent -f
~~~

Agent health/status 应仅监听 127.0.0.1:9745。如需给本机 Prometheus 抓取，使用 localhost 或受控反向代理；不要直接暴露。

## 6. 官网联调顺序

1. 官网创建不可变 clusterRef，注册 agentRef/collectorRef/sourceRef，并部署 HMAC key。
2. 官网生成映射文件；所有对象先设为 disabled 或 shadow。
3. 验证 PVE 累计流量、QGA/PVE 双视图以及 QGA 缺失语义。
4. 验证网络中断补传、重复批次、乱序、PVE 重启计数器和 VMID 重用 generation 拒绝。
5. 配置 cutoverAt 后只将指定来源切 active，确认旧官网轮询采集器不再对同一服务计费。
6. 仅在 test 完成控制命令 dry-run、审批和回执验证后，才建立独立写 token 并申请生产执行；v0.1 生产只开放 start/shutdown/reboot。

## 7. 切换 production 控制执行

这是高风险变更，建议使用变更单并在维护窗口实施：

1. 确认官网命令 API 已实现 HMAC、命令二次签名、审批、nonce 防重放、审计和回执幂等。
2. 创建最小权限**写** token，只授予批准的 VM/节点操作范围；`create-pve-tokens.sh --create-control-token` 默认创建无 ACL 的 privsep Token，必须分别给 backing user 与 Token 配置经审阅的 ACL。`--control-global-acl` 只允许隔离测试集群使用。不要用 root@pam token，也不要复用读取 token。
3. 在 agent.env 添加写 token；在配置填入它们的环境变量名称。
4. 配置 control.pollUrl、control.resultUrl、control.auth、control.commandSecretEnv，均使用生产 HTTPS。
5. 将 mode 改为 production 且 control.productionExecution 改为 true；v0.1 的 allowedActions 只能包含 vm.start、vm.shutdown、vm.reboot，然后重载服务。
6. 先发送一条低风险测试 VM 命令，核对 PVE task UPID、官网回执与审计。

失败时先把 productionExecution 改回 false；不要删除计费队列或关闭审计。

## 8. 常见问题

| 现象 | 检查方向 |
| --- | --- |
| PVE 采样 401/403 | token ID/secret、ACL、CA、时间和 endpoint；不要跳过 TLS。 |
| QGA 数据为空 | 客体是否安装/启动 QEMU Guest Agent、PVE 是否允许调用；PVE 指标仍可正常。 |
| SMART 为空 | smartctl_exporter、设备权限、smartctl -a 本机结果；不能把缺失说成健康。 |
| 计费被拒绝 | 映射 serviceRef/clusterRef/vmid/generation/instanceUuid、billingState、cutoverAt、sourceRef、HMAC 与服务端错误码。 |
| 队列持续增长 | 出站 DNS/TLS/防火墙、官网响应、HMAC 时钟、队列磁盘；计费队列不能直接删除。 |
| 控制命令只 dry-run | test 的预期行为；v0.1 生产只允许 start/shutdown/reboot，并要求 mode=production、productionExecution=true 与独立写 token。 |

## 升级与卸载

升级前备份配置和队列目录，停服务后替换二进制，再运行 --check-config 和一次 --once，最后启动服务。官网未确认所有计费队列都已接收前，不能删除 /var/lib/ppflight-agent。

卸载服务时可保留 /etc/ppflight-agent 和 /var/lib/ppflight-agent 以便回滚；只有官网确认账本与补传完成后，才按变更流程清理目录并撤销 Token。
