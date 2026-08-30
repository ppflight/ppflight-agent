# PPFlight PVE Agent

ppflight-agent 部署在 Proxmox VE 8.x/9.x 节点上，由 Agent 主动连接 PPFlight 服务，并仅在本机访问 PVE API。迁移的目标状态是：**官网不保存 PVE 地址或 PVE API Token，也不连接客户 PVE 的 8006 端口**；Agent 使用 `https://127.0.0.1:8006` 和本地专用最小权限 Token 完成读取与受控写入。

```text
PPFlight 官网  <── Agent 主动出站 HTTPS ──>  ppflight-agent  ──> 127.0.0.1:8006
                                                     ├──> 127.0.0.1:9100
                                                     └──> 127.0.0.1:9633
```

PVE 8006、node_exporter 9100 和 smartctl_exporter 9633 都不需要向公网开放。官网持有业务资产、IPAM、套餐、审批、`generation` 和操作线程；Agent 持有本地 PVE 凭据并执行固定 schema 的 PVE 原语。两侧都不能只用 VMID 代表客户资产。

## 全新 PVE 一键安装（联调测试）

在 PVE 8.x/9.x 的 **root 终端**执行这一行：

```bash
curl -4fsSL https://raw.githubusercontent.com/ppflight/ppflight-agent/main/scripts/quick-install.sh | bash
```

`quick-install.sh` 会自动识别 `amd64`/`arm64`，固定 IPv4/HTTPS 下载 `v0.1.0-rc.6`，校验内置 SHA-256 后才解压并运行包内安装器。它只安装并启用开机启动，不会启动 Agent、创建 PVE Token、授予 control ACL 或绑定官网/监控站。

安装完成后只输入：

```bash
AG
```

先从 `AG` 菜单查看和调整；在完成本地 PVE Token、API source、双绑定、IPv4 白名单及配置校验前，不要手工启动服务。该一行命令用于当前 `main` 联调分支；生产环境仍应采用安装文档中的离线校验流程。

官网、监控站和 PVE 外连的目标合同是 IPv4-only：dial 固定 `tcp4`，禁止 IPv6 literal/fallback；PVE 固定 `127.0.0.1:8006`。官网和 monitoring bind response 分别返回 exact `networkPolicy={agentObservedIPv4}`；该值是对应服务端从可信连接元数据观察并冻结的 Agent 公网出口 canonical IPv4，只用于服务端 `/32` 来源白名单，不是 Agent 自报值或拨号目的地。Agent 不再固定 Cloudflare DNS A/Anycast 地址，始终保留 endpoint hostname 作 HTTP Host、TLS SNI 和系统 CA 证书校验，并禁环境代理、redirect 与跨 origin credential。来源 IP 命中不能替代绑定 identity、key scope/epoch、HMAC/Ed25519、assignment generation、nonce/time、action allowlist 和审计校验。

> 上线状态：Agent 侧绑定、发现、assignment、受控执行和 UPID 恢复所需的代码与资源原语已在本仓接线，但外部服务和真实 PVE 端到端验收尚未完成；这不等于官网新 Agent 升级业务路由已经上线。官网的 Agent upgrade route feature flag 必须默认关闭。迁移期间旧客户的升级路由继续使用既有路径，直到按资产完成 shadow/read-back、互斥和显式切换；目标切换完成后官网才停止该资产的旧 PVE 直连。

发布物由 tag `vX.Y.Z` workflow 分别构建 Linux `amd64`/`arm64`、离线可复现打包并发布 tarball 与 `SHA256SUMS`；手动触发只生成 artifact，不发布。上面的 `curl | bash` 仅是 `main` 联调测试入口，脚本仍会校验固定发布包摘要；正式生产节点必须按安装文档先独立校验 checksum、再解压并运行包内 installer。发布脚本不会下载代码或把运行时凭据/队列打入包；具体校验和本地重建方式见[安装文档](docs/INSTALL.md#2-安装已校验发布物)。

## 安全绑定与本地凭据

官网管理员创建一次性绑定码，操作者在 PVE 本机执行：

```bash
# 自动创建相互隔离的只读/受控写 PVE Token，并只写入本机 root-only 环境文件。
sudo /usr/local/lib/ppflight-agent/create-pve-tokens.sh \
  --write-env /etc/ppflight-agent/agent.env

# 绑定码从标准输入读取，不得放在 argv、URL、日志或 shell history 中。
sudo ag-pve bind \
  --endpoint https://www.example/internal/v1/agents/bind \
  --pve-version "$(pveversion | sed -n 's/^pve-manager\/\([^/]*\).*/\1/p')"
```

这不是一键 onboarding。安装器默认复制的样例仍是 `mode=test`、`pve.source=simulator`；Token bootstrap 只创建本地身份/环境文件，官网 bind 只写官网 identity、endpoint/credential、assignment 和授权，不会把 source 改成 `api`、切换 `mode`/`productionExecution`、授予 control ACL 或启动/重启服务。操作者必须按安装文档显式编辑并校验配置。五项 `AG` 菜单同样不包含 Token bootstrap、source/mode 切换或服务启停。

完成 bootstrap 后，root 可用 `ag-pve pve prepare --tls-server-name <PVE证书DNS名>` 将仍为 test 的本机配置安全准备为 API 采集：它固定 TCP 为 `https://127.0.0.1:8006`/`tcp4`，并单独使用 `pve.tlsServerName` 做 TLS SNI/证书校验。后者必须是证书中的 DNS 名，不能是 `127.0.0.1`、`localhost`、IPv6 或通配符。prepare 先探测只读 Token 的 PVE version/有效权限，控制 Token 仅作 readiness 探测；不会授予 ACL、打开 production 或启动服务。`ag-pve pve status` 只输出脱敏的本地 read/control 探测与 readiness，不能证明官网、监控站或任一生产写路由已上线。

也可用 `--code-file FILE` 读取仅 owner 可读、非符号链接的私密文件；CLI 拒绝额外位置参数，也没有接收 code 值的命令行选项。Agent 在发送前持久化 UUID `requestId` 与 canonical 请求指纹以便安全重试，绑定码参与 hash 但原文不落盘。绑定成功后，官网必须返回 `bindingId`、匹配的 `deviceId`、身份、同源 HTTPS 端点、分用途 HMAC 凭据、Ed25519 命令验签公钥、初始 assignment、`networkPolicy` 和 `credentialEpoch`，并保存到 `<stateDirectory>/bindings/binding-state.json`；稳定 device ID 和 pending 幂等状态也在该私有子目录，PVE Token 永不上传官网。

监控站采用另一套一次性绑定码和独立信任域。Agent 已提供严格客户端、独立 `<stateDirectory>/bindings/monitoring-binding-state.json`、运行时 private-state credential overlay 和 `ag-pve monitoring bind`；响应只签发 monitoring `bindingId/deviceId/monitoringAgentRef`、ingest endpoint、`hmac-sha256` credential、`telemetry-v1` 传输上限、独立 `networkPolicy` 和 `credentialEpoch`。该 key 只能按服务端逐路由 scope 用于 `monitoring:telemetry.write`、`monitoring:audit.write` 和固定同源的 `monitoring:status.read`，不能授权官网 API 或 PVE mutation。官网 bind/replace 不得创建、覆盖、轮换或复用监控站凭据/`networkPolicy`。监控服务端路由和其 networkPolicy 发放/持久化由另一交付任务实现；没有已部署 endpoint 时样例保持 `enabled=false`，不能据此宣称监控站服务已经上线。

`sudo ag-pve monitoring preflight --endpoint https://<监控域名>/internal/v1/monitoring/agents/bind` 现在只是可选诊断：它输出当前 `resolvedA` 和逐地址 tcp4/TLS 检查，不再输出 `eligibleServerIPv4Allowlist` 或 `readyForOperatorApproval`，也不是绑定前置条件。命令不会访问 HTTP 路由、写配置、读取绑定码或执行绑定。

生产安装将 `<stateDirectory>/bindings` 建为 `root:ppflight-agent`、`0750`，状态文件为 `0640`；root 管理命令原子更新，systemd 服务只有组读取权限，并通过 `ReadOnlyPaths` 禁止写入。远端 assignment 则写入独立的 `<stateDirectory>/assignments/assignments.json`，目录/文件为 `ppflight-agent:ppflight-agent`、`0750/0640`，不能通过放宽 binding 目录权限来实现 refresh。

完整步骤见 [安装与迁移](docs/INSTALL.md)，严格接口见 [Agent API v1 目标契约](docs/AGENT-API-V1.md)。

`ag-pve website status` 与 `ag-pve monitoring status` 会分别读取本地 binding/Agent 健康，并用各自 trust domain 的 HMAC 查询固定同源只读状态端点；响应必须逐项匹配本机 binding/device/agent/epoch（官网还匹配 assignment revision）。Agent 客户端已实现，外部 website/monitoring status 服务端仍待各自任务交付。

## 多轮发现与操作线程

添加 PVE 不是一次扫描。官网以持久 `operationId` 下发只读 `pve.discover`，分轮执行 `version`、`permissions`、`nodes`、`storage`、`templates`、`networks`、`capacity`、`firewall`、`readiness`。`limit` 省略时为 20，合法范围为 1..50；通过 `cursor` 继续分页。发现不得夹带 firewall 或其他写操作。

绑定后的 assignment 客户端支持最长 25 秒的长轮询。命令通道也以持久 cursor/operation 设计；PVE 返回 UPID 只表示任务已提交。Agent journal 保存 UPID，重启后通过 `task.status` 对应的 PVE task status 读取继续对账，不重新提交原 mutation。当前接线状态与服务端仍需实现的部分见契约中的[实现状态](docs/AGENT-API-V1.md#11-实现状态与上线门槛)。

模板初始化是另一条仅限 PVE 本机 root 管理员的流程，不是官网远程 command。cloud-init helper bundle 作为同一 Agent 发布/安装包内的 `bundles/ppflight-cloudinit` 交付，不在安装时从任意 URL 拉代码；缺失或摘要不符时安装失败。安装后的 `AG`/`ag`/`ag-pve` 不带参数会显示五项交互菜单，其中模板向导会依次选择模板、镜像缓存 storage、模板磁盘 storage、备份策略与备份 storage、bridge。若 active/enabled 存储仅缺受支持的 content 类型，向导会用中文分块显示当前能力、需要新增的能力、完成后的能力和固定 `pvesm set` 命令；只有操作者输入 `Y` 才执行，并在继续前重新 discovery 验证。随后先输出无副作用 plan，只有操作者输入完整单词 `YES` 才按该 plan 的 `requestId/operationId/catalogRevision/catalogSha256` 执行；输入 `no` 或直接回车会取消。安装器已校验 bundle、运行依赖、逐文件摘要和 `networkRedirectPolicy.addressFamily=ipv4-only`，以版本目录加原子 managed symlink 提供 `/usr/local/lib/ppflight-agent/template-bootstrap`；helper 的镜像连接固定 `curl --disable --ipv4`、HTTPS-only redirect 和 catalog/official-checksum 完整性链。Agent 每次调用前再次校验，再以 `/usr/bin/python3 -I` 和受限环境执行唯一入口。真实 PVE 上会创建模板/备份的 plan/execute 尚未完成破坏性发布验收；它不新增 control action，更不表示 `vm.reinstall` 或远程 Agent 自升级已经实现。

## 连续性与离线边界

生产 unit 已使用 `Type=notify`、`WatchdogSec=60s`、`Restart=always` 和 `RestartSec=3s`。Agent 只在本地 health listener 可访问后发送 `READY=1`，并且只有采集循环仍在产生请求级 progress 时才继续发送 watchdog heartbeat；卡死后返回错误、保留未清理的 lifecycle session，由 systemd 重启。正常停止发送 `STOPPING=1` 并写入 clean marker。watchdog 只是本机进程监督，不会绕过 command/audit gate 或自行执行 PVE mutation，也不能被描述成远端服务 SLA。

下一次启动会在访问 PVE 前把上一进程未正常退出转换为 `agent.previousExit.<eventId>` / `previous_unclean_exit` 可用性事件，并为已启用的 website 与 monitoring telemetry 分别写入不可淘汰的 lifecycle 队列；未启用的一域继续留在 lifecycle state 等待以后启用。两个 trust domain 的 queued 状态独立，一个成功不能清掉另一个。Agent 侧持久化与双域入队已实现，外部接收、展示和告警仍须官网/监控站部署验证。

Agent 或官网离线时都不得回退为官网直连 PVE。目标官网服务应持久排队尚未过期的已签命令，Agent 恢复后继续主动轮询；Agent 一旦领取命令，则由本地 journal、UPID reconcile 和 receipt queue 保证恢复。服务端离线队列与 command `wait` 尚待官网实现/联调，旧客户兼容写路径也只能按资产显式 cutover，不能因 Agent 暂时不可达而自动启用。

## 固定动作面

Executor 不接受任意 URL、PVE path、shell、`qm`、`pct` 或 `pvesh`。代码中的动作名是：

- 生命周期/资源：`vm.start`、`vm.shutdown`、`vm.stop`、`vm.reboot`、`vm.create`、`vm.clone`、`vm.set-resources`、`vm.resize`、`vm.set-network`、`vm.set-rate`、`vm.delete`、`vm.reset-password`。
- 快照/备份：`snapshot.create`、`snapshot.delete`、`snapshot.rollback`、`backup.create`、`backup.delete`、`backup.restore`。
- PVE 任务：`task.status`。
- 防火墙：`firewall.cluster.set-options`、`firewall.node.set-options`、`firewall.guest.set-options`、`firewall.rule.create`、`firewall.rule.update`、`firewall.rule.delete`、`firewall.ipset.create`、`firewall.ipset.update`、`firewall.ipset.delete`、`firewall.ipset.entry.create`、`firewall.ipset.entry.update`、`firewall.ipset.entry.delete`、`firewall.guest.set-ipfilter`。
- 只读发现：`pve.discover`。

当前 33 个 known actions 已由一致性测试锁住 registry、strict validator 和 Executor 分派。动作存在也不代表官网已批准生产路由；production 仍受签名、assignment、allowlist、审批、资源锁、产品 rollout 和 `productionExecution` 共同限制。`vm.reinstall` 和远程 Agent 自升级不在当前动作表中，不能用 create/upgrade 原语推断它们已经实现；尤其 `vm.reinstall` 仍因 PVE 恢复流程非事务性，且没有可被命令签名/校验的安装介质 allowlist，而刻意不实现。

所有已验签的官网修改类 command（包括 dry-run、策略拒绝和终态）还必须生成脱敏审计事件，使用监控站独立绑定的 HMAC 上传到 `/internal/v1/monitoring/audit-events/batches`。审计使用独立 durable outbox、幂等 event ID、跨重启单调 sequence、`observedAt/sentAt`；只允许冻结的 command/action/scope/typed target/outcome 元数据和 SHA-256 digest，严禁 secret、root 密码、Token、完整 command parameters/result 或原始 UPID。monitoring audit schema 不含 `operationId`/`executionMode`；精确字段见目标契约。Agent wire/journal/outbox、runtime sink 和 monitoring HMAC uploader 已接线；监控服务端存储和可查询 UI 仍由另一任务交付。官网不得向未具备 audit route 的 Agent 下发修改命令，完成端到端验收前 production 修改动作不得开放。

## NIC 角色、IP、网络与防盗用

`vm.set-network` 只更新既有 `net0`..`net31`，支持固定 MAC、bridge、VLAN tag、MTU、NIC firewall、rate、IPv4/IPv6 和 gateway。QEMU 的 IP 字段写入对应 `ipconfigN`；LXC 写入 `netN`。QEMU Cloud-Init 配置写入不等于客户系统已经实时换 IP，官网必须在同一 `operationId` 中完成状态等待和回读后再提交 IPAM。

向导的 `networks` phase 后必须显式保存每张 NIC 的 `interface=netN`、`role=public|private`、`primary`、`metered`、`monitoring`、expected MAC、bridge/vnet、VLAN、MTU 和 IPFilter policy，不能依赖 NIC 顺序。Agent 的 strict assignment 已验证 interface 唯一、恰有一个 primary public NIC 和一个 monitoring NIC、canonical unicast MAC、bridge xor vnet 和范围；telemetry 会把 observed `netN` 与 binding 关联并返回 policy match/mismatch reason。

当前 PVE status 只有 guest aggregate `netin/netout`。Agent meter 对无 binding、单 NIC 不计费或 mixed metering 多 NIC 强制 shadow；只有每张绑定 NIC 都显式 `metered=true` 才可能 active，禁止把 private 流量算作 public。QGA per-interface stats 只用于观测，不能用于权威计费。

IP 切换应先保留新地址，再按操作线程更新 NIC/`ipconfigN`、`ipfilter-netN` 和防火墙，验证成功后才释放旧地址。防盗用需要组合：

1. `vm.set-network` 设置受管固定 MAC 并启用 NIC firewall；
2. 创建 PVE 约定名称 `ipfilter-netN` 的 guest IPSet；用 `firewall.ipset.entry.create` 先加入新 CIDR，`entry.update` 只改该 CIDR 的 comment/`noSubnet`，验证切换后才用 `entry.delete` 移除旧 CIDR；
3. 用 `firewall.guest.set-options` 和 `firewall.guest.set-ipfilter` 启用 guest firewall/IPFilter；
4. 必要时单独审批 cluster/node firewall options，并回读验证。

这些是可编排原语，不是“一次调用即可无缝切换”的承诺。官网必须负责 IPAM 预留、顺序、补偿、digest/read-back、审批和防自锁。

website telemetry 已输出 `lifecycle/rootPasswordReset/guestNetworkVerify/metering` capabilities；原始 QGA availability 含 `available/observedAt/freshUntil/unavailableReason`，依赖动作 capability 含 `available/observedAt/freshUntil/reason/executionPreflight`。QEMU Guest Agent 被卸载、停止或数据过期时，password reset/guest-network verify capability 会冻结，纯 PVE lifecycle 保持可用；Executor 还会在 `vm.reset-password` 前读取并检查具体 QGA 命令，缺少 `guest-set-user-password` 时拒绝执行。APP 对这些字段的展示与 guest-network verify 编排仍待远端官网合并，不能从 Agent 字段推断 UI 已上线。

## 采集与计费边界

- 流量计费只使用 PVE 的 ingress/egress 64 位累计计数；JSON 用十进制字符串，QGA 永不参与计费。
- 官网是账本权威方，负责差值、重放、乱序、counter reset、账期和最终 `usedBytes`；Agent 不计算欠费。
- 资产键至少包含 `clusterRef + guestType + vmid + generation`，并校验 `serviceRef` 与 `instanceUuid`。VMID 重用或重装必须推进 generation。
- PVE 与 QGA 是不同来源。QGA 缺失不能以 0 覆盖 PVE 视图，未映射或身份不匹配的 VPS 不能进入计费。

## 开发与发布

```bash
go test ./...
go vet ./...
go build ./...
```

配置使用严格 JSON（示例保留 `.yaml` 文件名），未知字段会被拒绝。真实 Token、绑定码、HMAC secret、assignment、控制 journal 和队列不得提交 Git 或出现在工单/日志中。

更多文档：

- [安装与迁移](docs/INSTALL.md)
- [Agent API v1 目标契约](docs/AGENT-API-V1.md)
- [现有数据面 API 与兼容说明](docs/API.md)
- [历史审阅输入（非规范）](docs/CONTRACT-REVIEW.md)
