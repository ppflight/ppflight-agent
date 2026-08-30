# 配置样例

`agent.example.yaml` 与 `assignments.example.yaml` 刻意使用严格 JSON。当前 Agent 拒绝未知字段和 YAML 隐式类型；`.yaml` 只是部署侧保留的文件名。

安装后对应：

- `/etc/ppflight-agent/agent.yaml`
- `/var/lib/ppflight-agent/assignments/assignments.json`
- `/etc/ppflight-agent/agent.env`

样例默认 `mode=test`、`pve.source=simulator`、所有外发 destination disabled、`control.productionExecution=false`。未绑定样例中的 HMAC/Ed25519 environment label 刻意留空；`ag-pve bind` 验证响应后才写入保留 label，运行时从 private binding state 解析真实 credential，而不是从环境变量取同名 secret。

安装器默认原样复制这份 simulator/test 样例。`AG` 五项菜单只包含模板向导、官网/监控绑定和两个通信状态，不会运行 Token bootstrap、把 `pve.source` 切为 `api` 或修改 mode/production gate。官网 bind 不改变 service；监控 bind 在安全写入并回验独立状态后会受控重启 `ppflight-agent.service`，并确认新 monitoring binding 已由进程加载，除此之外不改变本地 PVE 接入设置。生产 onboarding 必须按下列顺序逐步完成，不能把 binding 成功当作本地 PVE API 已接通。

样例的 `allowedActions` 只列 `vm.start/vm.shutdown/vm.reboot`，表示本机部署层刻意缩小授权面，不是协议只实现这三项。配置只能从代码 known-action registry 中选择，且还必须是绑定响应 `allowedActions` 的子集；增加本机列表不能绕过绑定授权、scope、approval、`productionExecution`、assignment 或 audit gate。完整动作名以 [Agent API v1 第 7 节](../docs/AGENT-API-V1.md#7-executor-动作和参数事实) 为准。

推荐配置顺序：

1. 用安装器落盘的 root-only `/usr/local/lib/ppflight-agent/create-pve-tokens.sh --write-env /etc/ppflight-agent/agent.env` 自动创建本地 read/control PVE Token；Token 不上传官网。control 默认无 ACL，审核资源后用同一 helper 的 `--acl-only --control-pool NAME` 或重复 `--control-scope PATH` 补最小权限，不得二次创建 Token。
2. 以 root 运行 `ag-pve pve prepare --tls-server-name <PVE-证书中的DNS名>`（或显式编辑等价字段）。它只在 `mode=test`、`productionExecution=false` 时运行，会安全读取 root-only Token 文件，先探测只读 Token 的 `/version` 与有效权限，再把本机配置写为 `pve.source=api`、精确 endpoint `https://127.0.0.1:8006`、固定 Token environment label、CA 和 `pve.tlsServerName`；它不会授予 control ACL、开启 production 或启动服务。TCP 目的地始终是 `127.0.0.1:8006`/`tcp4`，`pve.tlsServerName` 只能是 PVE API 证书中的 DNS 名称，不能填 `127.0.0.1`、`localhost`、IPv6 或通配符。随后以 root 运行 `ag-pve pve status` 输出脱敏 read/control 探测与 readiness；它不是官网、监控站或生产动作已经上线的证明。
3. 使用 `ag-pve bind --endpoint ... --pve-version ...` 完成官网一次性绑定；绑定码只从 stdin 或 owner-only `--code-file` 读取，不能放入 argv。
4. Agent 先持久化 UUID `requestId` 和 canonical request hash（code 参与 hash、原文不落盘）；官网响应返回 UUID `bindingId`、匹配的 `deviceId`、identity、初始 assignment 和本地私有 credential state。不要手工把官网 HMAC secret 写进示例配置或 Git。
5. 未绑定样例的 `assignments.refreshUrl` 保持空字符串；官网绑定成功后 CLI 会写入服务端签发的同源 assignment endpoint，runtime 主循环使用最长 25 秒长轮询、Ed25519 bundle 验签和防回滚状态。不得手工填入其他 URL；生产 assignment 使用 `<stateDirectory>/assignments/assignments.json`，目录/文件为 `ppflight-agent:ppflight-agent`、`0750/0640`，binding credential 子目录继续只读。
6. 保持 `control.productionExecution=false`，直到官网 API、Ed25519、approval、UPID 恢复、资源锁、IPv4 whitelist 和独立 monitoring audit outbox/UI 均完成验收；官网 Agent upgrade route feature flag 另行保持默认关闭。

监控站使用第二枚一次性绑定码和 `ag-pve monitoring bind --endpoint ...`，不接受 `--pve-version` 或版本位置参数。CLI 在读取 code 前以固定 `/usr/bin/pveversion` 自动发现本机可信 PVE 8/9 版本；命令失败、超时、非 PVE 或异常输出均 fail closed。code 仍只从 stdin 或 owner-only `--code-file` 读取。响应严格包含独立 `bindingId/deviceId/monitoringAgentRef`、ingest endpoint、`hmac-sha256`/base64 credential、`telemetry-v1` compression/大小上限、`credentialEpoch/issuedAt`，并写入独立 `<stateDirectory>/bindings/monitoring-binding-state.json`；官网 bind/replace 不得覆盖它。绑定后 CLI 严格回验 config/state/runtime overlay，自动重启 unit 并从本地 `/status` 核对新 binding ID/epoch；失败原子回滚并保留可重试 request，成功后无需手工 restart。样例因没有真实 endpoint/credential 而将 `monitoring` 与 `monitoringAudit` 都设为 `enabled=false`、`url=""`；绑定成功后 CLI 启用 telemetry endpoint，并从同 origin 固定派生 audit/status 路径，服务端分别校验 `monitoring:telemetry.write`、`monitoring:audit.write`、`monitoring:status.read`。不得复制官网凭据绕过独立绑定。

生产安装的 `<stateDirectory>/bindings` 为 `root:ppflight-agent`、`0750`，其中 website/monitoring/device/pending 文件为 `0640`；root 管理 CLI 写入，systemd service 组读且通过 `ReadOnlyPaths` 禁止写入。assignment 文件位于独立 `<stateDirectory>/assignments/assignments.json`，目录/文件为 `ppflight-agent:ppflight-agent`、`0750/0640`；原子替换保留已有 owner/group/mode，不能把 credential 和 assignment 的写权限混在一起。

两种绑定的服务端都必须按 `requestId + deviceId + canonical hash` 幂等、以事务消费一次性 code，并保证同 code 并发最多签发一个 binding。服务端不得保存 code 原文；为重放同一幂等响应，credential 必须加密保存。

当前 strict assignment 已支持每个 `netN` 的 typed `nicBindings`（public/private、primary、metered/monitoring、canonical unicast expected MAC、bridge xor vnet、VLAN、MTU、`ipFilterPolicy`）。非空列表必须恰有一个 primary public NIC 和一个 monitoring NIC；`config/assignments.example.yaml` 已给出 public/private 双 NIC 的 shadow 示例。Agent 只有在每张已绑定 NIC 都显式 `metered=true` 时才允许 PVE guest aggregate 进入 active，未绑定、单 NIC 不计费或 mixed metering 都强制 shadow；QGA per-interface counter 不能替代 PVE 权威计费。

website telemetry 会把 observed `netN` 与 binding 关联，输出 `policyMatch`/稳定 mismatch reason，并给每个 guest 输出 `lifecycle/rootPasswordReset/guestNetworkVerify/metering` capabilities。APP/官网消费与展示不在本配置样例中，仍需远端项目合并。

配置中的 PVE endpoint、Token 环境变量名属于节点本地。官网数据库、绑定响应、assignment 和 telemetry payload 都不能出现 PVE endpoint/Token。示例 ID 和空值都不是生产凭据。

生产网络合同要求 Agent 到官网、监控站和 PVE 全部 `tcp4`，拒绝 AAAA、IPv6 literal/fallback；因此 PVE TCP endpoint 必须精确为 `https://127.0.0.1:8006`，不能改成 `localhost`/`::1`，而 `pve.tlsServerName` 单独填写证书 DNS SAN/CN 名称。示例的 `pve01.example.invalid` 只是占位符，切换 `source=api` 前必须替换为本机 PVE 证书实际覆盖的 DNS 名。`internal/netpolicy` 已接 Agent 外连和管理探测；website 与 monitoring 仍须分别实现服务端 source-IP allow set 和 Agent 目标 IPv4 pin/轮换。IP 只作加密身份之外的附加门槛。不要通过环境变量注入代理，不能从 Agent tcp4 或 capability 字符串推断 mutual whitelist 已上线。
