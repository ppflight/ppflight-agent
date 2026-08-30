# 配置样例

`agent.example.yaml` 与 `assignments.example.yaml` 刻意使用严格 JSON。当前 Agent 拒绝未知字段和 YAML 隐式类型；`.yaml` 只是部署侧保留的文件名。

安装后对应：

- `/etc/ppflight-agent/agent.yaml`
- `/var/lib/ppflight-agent/assignments/assignments.json`
- `/etc/ppflight-agent/agent.env`

样例默认 `mode=production`、`pve.source=disabled`、所有外发 destination disabled、`control.enabled=false`、`control.productionExecution=false`。disabled 是安装/准备专用状态：服务进程会拒绝启动，因而不会生成、缓存或上传任何 PVE observation。未绑定样例中的 HMAC/Ed25519 environment label 刻意留空；`ag-pve bind` 验证响应后才写入保留 label，运行时从 private binding state 解析真实 credential，而不是从环境变量取同名 secret。

安装器默认原样复制这份 disabled 样例。旧版遗留的 `mode=test` 或 `pve.source=simulator` 会在安装升级时自动迁移为 `production+disabled`；发布版 Agent 不包含模拟采集实现，运行态也只接受 `mode=production`/`pve.source=api`。官网与监控 bind 在读取一次性码之前都会执行同一 root-only 真实 PVE 准备：先预检固定 service-readable CA/SNI/本机信息，再安全创建或读取隔离 Token，固定 `127.0.0.1:8006/tcp4`，要求完整 read audit 权限并实际读取本机 node status/storage，原子切到 `mode=production`/`pve.source=api`，受控启动或重启并等待真实采集及已绑定 telemetry 成功。readiness 阶段失败不会读取绑定码、创建 pending 或发送请求。

样例的 `allowedActions` 只列 `vm.start/vm.shutdown/vm.reboot`，表示本机部署层刻意缩小授权面，不是协议只实现这三项。配置只能从代码 known-action registry 中选择，且还必须是绑定响应 `allowedActions` 的子集；增加本机列表不能绕过绑定授权、scope、approval、`productionExecution`、assignment 或 audit gate。完整动作名以 [Agent API v1 第 7 节](../docs/AGENT-API-V1.md#7-executor-动作和参数事实) 为准。

推荐配置顺序：

1. root 直接执行 `ag-pve bind --endpoint ...` 或 `ag-pve monitoring bind --endpoint ...`。如果 root-only PVE 环境尚未生成，CLI 只调用安装包内固定路径的 Token helper；read/control Token 互相隔离，control 默认无 ACL，Token 永不上传远端。
2. CLI 自动固定本地 PVE API、验证真实读取并切换到 production/api；如证书 DNS 无法从本机 FQDN确定，先运行 `ag-pve pve prepare --tls-server-name <PVE-证书中的DNS名>`。该名称不能是 IP、`localhost`、IPv6 或通配符。
3. 两种 bind 都不接受 `--pve-version`；PVE 版本只从固定 `/usr/bin/pveversion` 自动读取。绑定码只从 stdin 或 owner-only `--code-file` 读取，不能放入 argv。
4. Agent 先持久化 UUID `requestId` 和 canonical request hash（code 参与 hash、原文不落盘）；官网响应返回 UUID `bindingId`、匹配的 `deviceId`、identity、初始 assignment 和本地私有 credential state。不要手工把官网 HMAC secret 写进示例配置或 Git。
5. 未绑定样例的 `assignments.refreshUrl` 保持空字符串；官网绑定成功后 CLI 会写入服务端签发的同源 assignment endpoint，runtime 主循环使用最长 25 秒长轮询、Ed25519 bundle 验签和防回滚状态。不得手工填入其他 URL；生产 assignment 使用 `<stateDirectory>/assignments/assignments.json`，目录/文件为 `ppflight-agent:ppflight-agent`、`0750/0640`，binding credential 子目录继续只读。
6. 保持 `control.productionExecution=false`，直到为审核过的资源范围显式执行 helper 的 `--acl-only --control-pool NAME`/`--control-scope PATH`，并完成官网 Ed25519、approval、UPID 恢复、资源锁、IPv4 whitelist 和独立 monitoring audit 验收。真实数据采集不依赖该写权限开关。

监控站使用第二枚一次性绑定码和 `ag-pve monitoring bind --endpoint ...`，不接受 `--pve-version` 或版本位置参数。CLI 在读取 code 前以固定 `/usr/bin/pveversion` 自动发现本机可信 PVE 8/9 版本；命令失败、超时、非 PVE 或异常输出均 fail closed。code 仍只从 stdin 或 owner-only `--code-file` 读取。响应严格包含独立 `bindingId/deviceId/monitoringAgentRef`、ingest endpoint、`hmac-sha256`/base64 credential、`telemetry-v1` compression/大小上限、`credentialEpoch/issuedAt`，并写入独立 `<stateDirectory>/bindings/monitoring-binding-state.json`；官网 bind/replace 不得覆盖它。CLI 在首次网络请求前持久化同码可重试的 pending request。服务端一旦签发凭据，任何本地写入、重启或加载回验失败都会保留 pending/commit marker、停止服务并拒绝退回旧凭据；操作者以同一 code 重试会复用 requestId 并完成严格回读、自动重启与本地 binding ID/epoch 核对。样例因没有真实 endpoint/credential 而将 `monitoring` 与 `monitoringAudit` 都设为 `enabled=false`、`url=""`；绑定成功后 CLI 启用 telemetry endpoint，并从同 origin 固定派生 audit/status 路径，服务端分别校验 `monitoring:telemetry.write`、`monitoring:audit.write`、`monitoring:status.read`。不得复制官网凭据绕过独立绑定。

生产安装的 `<stateDirectory>/bindings` 为 `root:ppflight-agent`、`0750`，其中 website/monitoring/device/pending 文件为 `0640`；root 管理 CLI 写入，systemd service 组读且通过 `ReadOnlyPaths` 禁止写入。assignment 文件位于独立 `<stateDirectory>/assignments/assignments.json`，目录/文件为 `ppflight-agent:ppflight-agent`、`0750/0640`；原子替换保留已有 owner/group/mode，不能把 credential 和 assignment 的写权限混在一起。

两种绑定的服务端都必须按 `requestId + deviceId + canonical hash` 幂等、以事务消费一次性 code，并保证同 code 并发最多签发一个 binding。服务端不得保存 code 原文；为重放同一幂等响应，credential 必须加密保存。

当前 strict assignment 已支持每个 `netN` 的 typed `nicBindings`（public/private、primary、metered/monitoring、canonical unicast expected MAC、bridge xor vnet、VLAN、MTU、`ipFilterPolicy`）。非空列表必须恰有一个 primary public NIC 和一个 monitoring NIC；`config/assignments.example.yaml` 已给出 public/private 双 NIC 的 shadow 示例。Agent 只有在每张已绑定 NIC 都显式 `metered=true` 时才允许 PVE guest aggregate 进入 active，未绑定、单 NIC 不计费或 mixed metering 都强制 shadow；QGA per-interface counter 不能替代 PVE 权威计费。

website telemetry 会把 observed `netN` 与 binding 关联，输出 `policyMatch`/稳定 mismatch reason，并给每个 guest 输出 `lifecycle/rootPasswordReset/guestNetworkVerify/metering` capabilities。APP/官网消费与展示不在本配置样例中，仍需远端项目合并。

配置中的 PVE endpoint、Token 环境变量名属于节点本地。官网数据库、绑定响应、assignment 和 telemetry payload 都不能出现 PVE endpoint/Token。示例 ID 和空值都不是生产凭据。

生产网络合同要求 Agent 到官网、监控站和 PVE 全部 `tcp4`，拒绝 AAAA、IPv6 literal/fallback；因此 PVE TCP endpoint 必须精确为 `https://127.0.0.1:8006`，不能改成 `localhost`/`::1`，而 `pve.tlsServerName` 单独填写证书 DNS SAN/CN 名称。示例的 `pve01.example.invalid` 只是占位符，切换 `source=api` 前必须替换为本机 PVE 证书实际覆盖的 DNS 名。`internal/netpolicy` 已接 Agent 外连和管理探测；website 与 monitoring 仍须分别实现服务端 source-IP allow set 和 Agent 目标 IPv4 pin/轮换。IP 只作加密身份之外的附加门槛。不要通过环境变量注入代理，不能从 Agent tcp4 或 capability 字符串推断 mutual whitelist 已上线。
