# PPFlight PVE Agent

ppflight-agent 是部署在每台 Proxmox VE 宿主机上的全功能采集与受控执行 Agent。它统一采集客户 VPS、PVE 节点/集群、宿主机和物理磁盘健康，并将数据主动推送至官网业务 API 与本机监控站 API。

首版目标平台为 **Proxmox VE 8.x / 9.x（Debian 系）**。它不会替换官网当前通过 PVE API 创建、重装、改密码的流程；控制通道是额外且可审计的路径，可逐步接入。

> 边界说明：Agent 端采集、队列、签名协议与控制执行器在本仓库开发；官网接收 API、不可变 clusterRef、映射下发与最终流量账本仍需官网端实现。本文的“建议端点”不表示官网已上线服务。

## 架构

~~~text
PVE API / 本机 PVE 数据 ──┐
QEMU Guest Agent（可选） ─┼─> PPFlight Agent ─> 官网计费 API
node_exporter :9100 ─────┼─>                 ─> 官网业务遥测 API
smartctl_exporter :9633 ─┘                    └> 监控站 API
                                                    ↑
官网控制 API（轮询） ──> 已签名命令 ─> Agent（默认启用）
~~~

每个目的地有独立持久化队列、重试和幂等批次。PVE 不必向公网暴露 8006、9100、9633；官网和监控站不需要反向连入宿主机。

## 采集范围与来源

| 范围 | 指标 | 来源 | 使用方式 |
| --- | --- | --- | --- |
| VPS/PVE 视图 | 开关机、CPU、内存、虚拟盘、I/O、累计网卡字节、运行时间 | PVE API | 每台 QEMU/LXC 的平台主视图。 |
| 客体增强视图 | OS、文件系统已用、客体网卡/IP、QGA 信息 | QEMU Guest Agent | 仅 QEMU 且 Agent 可用；缺失不等于 0。 |
| 流量计费 | ingress / egress 64 位累计计数 | **PVE API** | 官网计算差值与最终账本。QGA 永不参与计费。 |
| PVE 节点/集群 | 版本、CPU/内存、存储池、任务、集群状态 | PVE API | 可配置本机或集群范围。 |
| Linux 宿主机 | CPU、load、内存、swap、FS、网卡、PSI、ZFS | node_exporter :9100 | Agent 仅从 loopback 拉取。 |
| 物理磁盘 | SMART、温度、介质错误、NVMe 寿命 | smartctl_exporter :9633 | HDD/SSD/NVMe 硬件健康。 |

### PVE 与 QGA 双视图

PVE 是虚拟化平台外部视图，适合平台监控、资源管理和计费；QGA 是客户系统内部视图，适合文件系统、IP 和 OS 详情。二者不同是正常的：虚拟盘容量不等于客体文件系统已用，PVE 内存也不等于客体 OS 报告值。

官网和监控站必须分别存储/展示 guest.pve.* 与 guest.qga.*，并保存来源、可用性和采样时间。QGA 不可用时不能以 0 覆盖 PVE 指标。

### 流量计费的硬规则

- 上报 PVE 的原始累计 ingressBytes、egressBytes；JSON 采用十进制字符串，避免 JavaScript 丢失 uint64 精度。
- 官网是账本权威方：负责差值、账期、计费方向、去重、乱序和最终 usedBytes。Agent 不计算客户欠费或超额。
- 当前 500G 应明确为 500,000,000,000 bytes（500 GB 十进制），不是 500 GiB。
- 当前方向是 ingress + egress；严格 usedBytes > 500000000000 才触发限速，等于不触发。
- 未映射、disabled、身份不匹配或 PVE 计数缺失的 VPS 不能进入计费事件；不是“0 流量”。

## 身份、重装与来源切换

VMID 不是客户身份。官网映射并由 Agent 校验的主键是：

~~~text
clusterRef + guestType + VMID + generation
~~~

每条记录还必须有 serviceRef（当前官网事实为 billing_subscriptions.uuid）和 instanceUuid。重装或 VMID 重用时，官网必须让 generation + 1；旧 generation 的计费事件和控制命令必须拒绝。

clusterRef 必须是官网创建的不可变 UUID/安全标识，不能是可改的 cluster slug 或自增 ID。新 Agent 替换官网旧轮询采集器时，官网需下发 sourceRef 与 cutoverAt，保证任一时刻仅一个来源成为 active，防止双计费。

映射文件及完整字段见 [API 契约](docs/API.md#映射文件)。

## 控制模块：默认启用，默认 dry-run

控制模块默认开启，但默认全局模式是：

~~~json
{"mode":"test","control":{"enabled":true,"productionExecution":false}}
~~~

在该状态下 Agent 可以轮询、验签、校验映射并回传回执，但只回传 dry-run，不会改变 PVE。代码保留固定动作 schema：启动、优雅关机、停止、重启、创建、克隆、受限更新、只增不减扩盘、保护式删除、限速、QGA 密码重置；它不接受任意 PVE URL、shell 或脚本。v0.1 的默认 allowlist 只有 `vm.start`、`vm.shutdown`、`vm.reboot`，且生产校验也只允许这三项；其余高风险动作当前只能用于 test/dry-run 契约联调，待资源 allowlist、任务终态跟踪和审批闭环完成后再开放。

真实执行必须同时完成：

1. mode 改为 production。
2. control.productionExecution 改为 true。
3. HTTPS 控制轮询/回执 URL、API HMAC 凭据、命令签名密钥均已配置。
4. 创建独立的**写 PVE Token**，填入 control.pveTokenIdEnv 和 control.pveTokenSecretEnv；绝不复用采集 Token。
5. action 必须属于 v0.1 生产白名单，且 serviceRef/instanceUuid/generation 与当前映射完全匹配。
6. 先在测试节点验证 dry-run、签名、幂等回放与回执。

即使 Agent 运行在 PVE 本机，采集也始终使用独立的**只读 PVE Token**，而不是 root shell 权限；这样可最小授权、撤销和审计。

## 安装与联调

完整步骤在 [安装与运维](docs/INSTALL.md)。生产前建议在一台测试 PVE 完成：

1. 验证 PVE 8.x/9.x、本机 CA、NTP 和只读 Token。
2. 验证 QGA 缺失的 VM 仍正确上报 PVE 视图。
3. 验证 127.0.0.1:9100/metrics 与 127.0.0.1:9633/metrics。
4. 先让官网接收 shadow 计费事件，核对累计字节、epoch、幂等和 cutoverAt。
5. 控制命令先只做 test/dry-run，最后才批准生产执行。

配置为严格 JSON，未知字段会报错。密钥只放在权限 0600 的 systemd 环境文件或密钥系统，不能写入 JSON、Git、日志或回执。

### SSH 本机管理命令：ag-pve

安装器只安装一份 Agent 二进制，并创建 /usr/local/bin/ag-pve 到 /usr/local/bin/ppflight-agent 的软链接。通过 SSH 登录 PVE 后，可用 ag-pve 管理本机 Agent 配置；它不需要、也不会调用官网或监控站的资产管理 API。

~~~bash
# 查看本机 Agent 的 /status JSON；Agent 没启动时会失败，不会启动服务
ag-pve status

# 严格校验配置和所引用的环境变量是否存在，不发送网络业务数据
ag-pve validate

# 查看或连通性检测监控站配置
ag-pve monitoring show
ag-pve monitoring test
ag-pve monitoring set --enabled=true --url=https://monitor.example/api/ingest \
  --auth-mode=bearer --bearer-token-env=MONITORING_BEARER_TOKEN \
  --payload-format=legacy-ingest-v1 --compression=gzip

# 查看或连通性检测官网目标
ag-pve website show
ag-pve website test

# 配置官网计费与遥测目标
ag-pve website metering set --enabled=true --url=https://www.example/internal/v1/metering/usage-batches \
  --auth-mode=hmac-sha256 --key-id-env=WEBSITE_METERING_KEY_ID --secret-env=WEBSITE_METERING_SECRET
ag-pve website telemetry set --enabled=true --url=https://www.example/internal/v1/telemetry/batches \
  --auth-mode=hmac-sha256 --key-id-env=WEBSITE_TELEMETRY_KEY_ID --secret-env=WEBSITE_TELEMETRY_SECRET

# 配置控制轮询和回执；默认仍只 dry-run，除非显式 production-execution=true
ag-pve website control set --enabled=true \
  --poll-url=https://www.example/internal/v1/agents/commands \
  --result-url=https://www.example/internal/v1/agents/agent-pve-test-01/command-receipts \
  --auth-mode=hmac-sha256 --key-id-env=CONTROL_API_KEY_ID --secret-env=CONTROL_API_SECRET \
  --command-secret-env=CONTROL_COMMAND_SECRET --production-execution=false
~~~

show 只展示配置与密钥的环境变量名，不会输出 secret。test 只做 DNS 解析、TCP 建连和 HTTPS TLS 握手（HTTP 地址只做 TCP），不发送 HTTP 请求、不上传任何监控或计费数据。每个 set 都会先校验、以原子方式写入配置，并创建带时间戳的 .bak 备份；它不会重启 Agent。完成后执行 ag-pve validate，确认后由管理员手动执行 systemctl restart ppflight-agent。当前监控站 `/api/ingest` 使用 `legacy-ingest-v1`；未来新监控 API 使用 `telemetry-v1`，两者不能配错。

可在任意命令前加 --config FILE 指定另一份配置。destination 的 set 命令都支持 --enabled、--url、--auth-mode、--key-id-env、--secret-env、--bearer-token-env、--compression（none 或 gzip）和 --payload-format；控制 set 支持 --enabled、--poll-url、--result-url、--auth-mode、--key-id-env、--secret-env、--bearer-token-env、--command-secret-env、--production-execution。

官网/监控站的远程资产查询、修改或创建接口目前仅预留；`ag-pve monitoring query|modify` 与 `ag-pve website query|modify` 会明确返回“未实现”且不发请求。代码已保留 typed `remote.AssetClient` 边界，后续可在不改变 SSH 命令分组的前提下接入正式 API；不能把上述本机配置命令理解为远程资产管理已可用。

关键测试配置：

~~~json
{
  "schemaVersion": 1,
  "mode": "test",
  "identity": {
    "agentRef": "agent-pve-test-01",
    "collectorRef": "collector-pve-test-01",
    "sourceRef": "pve-agent-v1",
    "clusterRef": "cluster-immutable-uuid-01",
    "nodeRef": "auto",
    "site": "primary"
  },
  "pve": {
    "source": "api",
    "endpoint": "https://127.0.0.1:8006",
    "tokenIdEnv": "PVE_READ_TOKEN_ID",
    "tokenSecretEnv": "PVE_READ_TOKEN_SECRET",
    "caFile": "/etc/ppflight-agent/pve-root-ca.pem",
    "localNode": "pve01"
  },
  "exporters": {
    "node": {"enabled": true, "url": "http://127.0.0.1:9100/metrics"},
    "smart": {"enabled": true, "url": "http://127.0.0.1:9633/metrics"}
  },
  "control": {"enabled": true, "productionExecution": false}
}
~~~

## API 对接与官网待实现项

建议目标端点：

- POST /internal/v1/metering/usage-batches：精确计费累计值（不可丢弃）。
- POST /internal/v1/telemetry/batches：官网 VPS/PVE 双视图业务遥测。
- POST /internal/v1/monitoring/batches：监控站新遥测（配置 `payloadFormat=telemetry-v1`）；现有 `/api/ingest` 兼容桥使用 `legacy-ingest-v1`。
- GET /internal/v1/agents/commands?agentRef={agentRef}&after=...&limit=...：控制轮询。
- POST /internal/v1/agents/{agentRef}/command-receipts：控制回执。

这是**建议契约，不表示官网已实现**；完整 JSON、HMAC、响应语义、映射和命令格式见 [API 契约](docs/API.md)。

官网端仍必须实现：

1. 不可变 clusterRef、Agent 注册及每集群 HMAC key。
2. 映射文件和 serviceRef + instanceUuid + VMID + generation 生命周期；重装增加 generation。
3. 计费批次验证、nonce 防重放、幂等、来源切换、累计计数差值与权威 traffic_usage_periods.billable_bytes。
4. PVE/QGA 分离的遥测存储和访问控制。
5. 控制命令的审批、二次签名、审计、轮询和回执。
6. 限速/恢复策略队列。Agent 只提供数据和受控执行，不自行改账期或套餐。

旧监控接口 /api/ingest 只能作为经过确认的兼容桥。若它仍会把 networkRxBytes/networkTxBytes 写入旧流量计费器，禁止与新计费 API 同时启用，避免重复计费。

## GitHub 发布

发布前至少运行：

~~~bash
go test ./...
go vet ./...
go build ./...
~~~

GitHub Release 应包含 Linux amd64/arm64 二进制、SHA-256、示例配置、systemd 单元和安装脚本。不得发布真实 token、环境文件、PVE 备份、映射文件或队列目录。建议先标记 v0.1.0；只有官网 API、断网补传和生产切换都完成联调后，才宣称可用于生产计费。

## 安全与故障处理

- health/status 默认仅监听 127.0.0.1，不能直接公开。
- PVE/QGA/exporter 故障要保留“不可用原因 + 采样时间”，不能伪造 0。
- 计费队列不可静默淘汰；遥测队列可有界淘汰，但必须告警。
- 生产禁用 insecureSkipTls；exporter 只允许 loopback HTTP。
- HMAC 覆盖 method、path/query、key ID、Unix 时间戳、nonce、body SHA-256。
- 日志和控制 journal 不得记录 Token、HMAC secret、密码或完整敏感参数。
- 本项目不是 BGP 路由/会话控制器；它提供 PVE/VPS/硬件观测与受控 PVE 操作。

## 文档

- [安装与运维](docs/INSTALL.md)
- [官网与监控 API 契约](docs/API.md)
- [历史协议审阅记录（非规范）](docs/CONTRACT-REVIEW.md)
