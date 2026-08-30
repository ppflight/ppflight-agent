# PPFlight Agent 数据面 API 与兼容说明

绑定、assignment、discovery、控制动作、IPFilter 和迁移规则以 [Agent API v1](AGENT-API-V1.md) 为规范。本页只保留 Agent 已有数据类型对应的数据面约束。列出的 URL 是目标契约；服务端完成并通过联调前，不表示 API 已上线。

目标架构中，官网不保存 PVE URL/Token，也不访问 8006。Agent 只在本机连接 `https://127.0.0.1:8006`，然后主动向以下服务出站。

## 1. Endpoint-specific HMAC

官网绑定分别签发 metering、website telemetry、assignments、commands、receipts 凭据；不得跨 endpoint 复用。Commands HMAC 唯一附加用途是固定同源 website status GET，并由服务端单独校验 `website:status.read`。监控站通过独立一次性绑定签发自己的 monitoring credential，只能按逐路由 scope 用于 telemetry ingest、固定同源的脱敏 audit batches 和只读 status，不是官网凭据的一部分。

官网和监控绑定请求都必须携带 Agent 在首次发送前持久化的 UUID `requestId` 与稳定 `deviceId`；响应都返回 UUID `bindingId`、匹配的 `deviceId` 和必填 `networkPolicy`。服务端以 `requestId + deviceId + canonical request hash` 幂等，同请求重放第一次响应，不同 body 返回冲突；同一一次性 code 的并发请求最多签发一个 binding。code 原文不得持久化，已签发 credential 则必须在服务端加密保存为可安全重放的幂等结果。Agent pending 文件位于 `<stateDirectory>/bindings`，仅保存 request ID 和包含 code 的 hash，不保存 code 原文。

签名请求头与 `internal/protocol` 一致：

```text
X-PPFlight-Key-Id: <keyId>
X-PPFlight-Timestamp: <Unix seconds>
X-PPFlight-Nonce: <至少16字符随机值>
X-PPFlight-Content-SHA256: <lowercase SHA-256 hex of exact body>
X-PPFlight-Signature: <lowercase HMAC-SHA256 hex>
```

canonical input 是六行 UTF-8 文本：

```text
UPPERCASE_METHOD
escaped-path[?raw-query]
x-ppflight-key-id:<keyId>
x-ppflight-timestamp:<timestamp>
x-ppflight-nonce:<nonce>
x-ppflight-content-sha256:<bodySha256>
```

服务端必须验证 exact raw body/path/query，使用 constant-time compare，并事务性消费 nonce。默认允许的时间偏差为 ±300 秒。重试可生成新 nonce，但业务 `batchId`、`eventId`、`commandId`、`receiptId` 不变。

生产端点仅允许 HTTPS/TLS 1.2+，禁环境代理、跨 host 重定向和 URL 中的 credential。PVE Token、绑定码、密码和命令敏感参数不得出现在请求 URL、错误、日志或 dead letter。

每个 website/monitoring bind response 的 exact `networkPolicy` 是：

```json
{
  "agentObservedIPv4": "198.51.100.24",
  "serverIPv4Allowlist": ["203.0.113.10", "203.0.113.11"]
}
```

两个字段都使用 canonical IPv4 字符串；`serverIPv4Allowlist` 必须有 1..16 个无重复项，且不得为 unspecified、multicast 或 broadcast 地址。`agentObservedIPv4` 由对应服务端观察并签发，只是该 binding 的服务端 source-IP metadata，Agent 不从本地网络学习它，也绝不把它作为拨号目的地。website 与 monitoring 分别签发、保存和轮换自己的 policy，不能合并、复制或在另一域 bind/replace 时覆盖。

官网、监控站和 PVE transport 必须固定 `tcp4`，拒绝 AAAA、IPv6 literal 和 IPv6 fallback；PVE 只访问 `127.0.0.1:8006`。对 DNS endpoint，Agent 只查询 A 记录、取 `A ∩ allowlist`（即 `A ∩ serverIPv4Allowlist`）并向选中的 IPv4 直接拨号；为空即 fail closed。HTTP URL hostname 保持不变，继续作为 Host、TLS SNI 与证书 hostname 校验，不能用 IP 绕过 TLS identity。所有绑定/上报/status client 禁 ambient proxy、拒绝 redirect 和跨 origin credential；未来代理只能是显式受控 CA/认证/固定链路，且不能代理解析绕过最终目标检查。IP allowlist 仅作附加条件，不能替代 TLS、`bindingId/deviceId/agentRef` 关系、key scope/epoch、HMAC/Ed25519、nonce/time、assignment generation 或 action allowlist。Agent 的 strict response 校验、private-state 保存和 tcp4 pinning 已接线；服务端 source-IP 记录、policy 发放/轮换与真实部署仍需官网、监控站各自实现/联调。

## 2. Assignment 身份

每个可计费/控制的 VM assignment 至少包含：

```json
{
  "serviceRef": "subscription-uuid",
  "clusterRef": "immutable-cluster-id",
  "nodeRef": "pve01",
  "vmid": 101,
  "generation": 3,
  "instanceUuid": "instance-uuid",
  "guestType": "qemu",
  "billingState": "shadow",
  "nicBindings": [
    {
      "interface": "net0",
      "role": "public",
      "primary": true,
      "metered": true,
      "monitoring": true,
      "expectedMac": "02:00:00:00:01:01",
      "bridge": "vmbr0",
      "vlan": 100,
      "mtu": 1500,
      "ipFilterPolicy": "required"
    }
  ]
}
```

资产键是 `clusterRef + guestType + vmid + generation`，并校验 `serviceRef`、`instanceUuid` 和可选 node。VMID 删除重用或重装必须推进 generation。旧 generation 的计量事件和控制命令都要拒绝。

`networks` discovery 后，官网必须保存每张 NIC 的 `nicBindings`：`interface=netN`、`role=public|private`、`primary`、`metered`、`monitoring`、expected MAC、bridge/vnet、VLAN、MTU 和 `ipFilterPolicy=required|disabled`。当前 `internal/inventory.Assignment` strict schema 已包含这些字段并拒绝 unknown fields；非空列表要求 interface 唯一、恰有一个 primary public NIC 和一个 monitoring NIC、canonical unicast MAC、bridge/vnet 恰选一个，并校验 VLAN 0..4094、MTU 576..9216。字段进入 signed assignment，PVE/QGA 数组顺序永远不是身份。

assignment refresh 使用官网绑定中的独立 credential：

```text
GET <binding response.endpoints.assignments>
    ?agentRef=...&deviceId=...&clusterRef=...
    &cursor=...&version=...&afterRevision=...&wait=25
```

Agent 客户端接受 `wait<=25s`，验证 Ed25519 signature、exact assignment JSON SHA-256、签发/过期时间、cursor 与单调 revision，并拒绝防回滚失败；runtime 主循环已接入 refresh，使用原子替换保存 assignment 和 cursor，安装器已接 service-owned `<stateDirectory>/assignments/assignments.json` 及 legacy 首次迁移。官网服务仍需联调，不能据此宣称服务已上线。

## 3. 官网 metering

目标端点：

```text
POST /internal/v1/metering/usage-batches
```

`internal/protocol.UsageBatch` 包含 `schemaVersion`、`batchId`、Agent/collector/source/cluster identity、`mode`、十进制字符串 `sequence`、`observedAt` 和 events。每个 event 包含当前 assignment identity、`eventId`、`counterEpoch`、十进制字符串 sequence、source/billing state/cutoverAt，以及 PVE 原始累计 `ingressBytes`/`egressBytes`。

硬规则：

- 所有 uint64 counter 用 JSON 十进制字符串，避免 JavaScript 精度丢失；
- 只上报 PVE 累计 ingress/egress，QGA 永不参与计费；
- 官网负责差值、乱序、重复、counter reset、账期和最终账本；Agent 不计算欠费；
- 非 production batch 不能含 active event；未映射、generation 不匹配或计数缺失不能伪造成 0；
- PVE `netin/netout` 当前是 guest aggregate。Agent 已实现 typed metering capability：没有 `nicBindings`、单 NIC 明确不计费、或多 NIC mixed metering 都强制 usage event 为 shadow；只有每张绑定 NIC 都显式 `metered=true` 才可能进入 active。不能把 private 流量并入公网账单；
- QGA per-interface rx/tx 只作观测/诊断，永远不是权威计费来源；
- `batchId`/`eventId` 幂等，服务端在响应前必须 durable commit。

上传器以任意 `2xx` 作为 ACK，成功响应 body 只作 advisory；已提交批次也可用 HTTP 409 和无歧义机器码 `DUPLICATE` 确认。其他 4xx schema/identity 错误进入 quarantine/人工处理；401/403 打开认证断路器；408/425/429/5xx/网络错误带抖动退避且保留原 body/idempotency ID。

## 4. 官网 telemetry

目标端点：

```text
POST /internal/v1/telemetry/batches
```

官网 telemetry 使用 website telemetry binding credential。PVE 与 QGA 字段必须保留 source、availability 与 sampled time；QGA 不可用时不能以 0 覆盖 PVE 视图。website identity 是该 endpoint 的授权主体。

website guest telemetry 已输出 `capabilities.lifecycle/rootPasswordReset/guestNetworkVerify/metering`。QGA availability/freshness 决定两个 QEMU 依赖 capability，lifecycle 始终可用；Executor 还会在 QEMU password reset 前重新读取 `agent/info` 并检查 `guest-set-user-password`。APP 必须展示 `available/observedAt/freshUntil/reason/executionPreflight`，不能只显示缓存的最后成功数据。APP 消费/展示与组合升级中的 guest-network verify 尚待远端官网合并，不能因 Agent 已给出字段而宣称 UI 已完成。

每个 `netN` telemetry 还会关联 signed `binding` 并输出 `policyMatch{supported,reason,source}`。当前稳定 reason 包括 `binding_missing`、`interface_missing`、`mac_mismatch`、`attachment_mismatch`、`vlan_mismatch`、`mtu_mismatch`、`nic_firewall_disabled`；这是 PVE config 的一致性信号，不能替代对 `ipfilter-netN` 条目和 firewall rule 的操作级回读。

Telemetry 队列可按显式策略淘汰旧快照，但不能影响 metering、control receipt 或 binding state。

## 5. 监控站 telemetry

监控站先独立调用目标绑定接口：

```text
POST /internal/v1/monitoring/agents/bind
```

请求严格字段是 `schemaVersion`、UUID `requestId`、`bindingCode`、`deviceId`、`agentVersion`、`hostname`、`nodeClaim{nodeRef,pveVersion}` 和 `capabilities`，不要求官网先绑定。响应严格字段是：

```json
{
  "schemaVersion": 1,
  "bindingId": "123e4567-e89b-42d3-a456-426614174011",
  "deviceId": "device-node-01",
  "monitoringAgentRef": "monitor-agent-01",
  "ingestEndpoint": "https://monitor.example/internal/v1/monitoring/telemetry/batches",
  "hmacCredential": {
    "algorithm": "hmac-sha256",
    "keyId": "monitor-key-01",
    "secretEncoding": "base64",
    "secret": "MDEyMzQ1Njc4OWFiY2RlZg=="
  },
  "telemetry": {
    "payloadFormat": "telemetry-v1",
    "compression": "gzip",
    "maxCompressedBytes": 8388608,
    "maxUncompressedBytes": 33554432
  },
  "credentialEpoch": 1,
  "issuedAt": "2026-08-30T00:00:00Z"
}
```

状态写入独立 `<stateDirectory>/bindings/monitoring-binding-state.json`。响应不含 website identity、metering、assignment、commands、receipts 或 Ed25519 key。该目录的生产权限为 `root:ppflight-agent`、`0750`，状态文件为 `0640`；root 管理 CLI 写、service 只读。

`telemetry-v1` ingest 使用监控绑定 HMAC key 所绑定的 `monitoringAgentRef` 鉴权；payload 自报的 website identity 只能作为数据标签，不能授予权限。当前 envelope 已含 binding/device/epoch、`observedAt/sentAt`，monitoring sequence 在 run state 中跨重启单调递增；`bootId` 只作进程/legacy correlation，不能替代 sequence。`agentHealth.auditQueue` 另暴露 pending items/bytes、dead-letter/drop 计数、auth-blocked 状态和受限 delivery error/oldest time，供监控站显示审计链路健康，不能携带自由错误文本。官网 bind/replace 与监控 bind/replace 互不覆盖。

Agent 已有严格类型、pending/state、运行时 private-state credential overlay 和 `ag-pve monitoring bind`；成功绑定才会启用 telemetry destination，并固定派生同源 audit destination。uploader 已执行响应中的 telemetry 压缩/非压缩大小上限，audit 使用 Agent 固定的 4 MiB/16 MiB 上限；ingest 联调与外部监控服务端路由仍须分别验收。没有真实 endpoint/credential 的样例默认 disabled；旧 `/api/ingest`/`legacy-ingest-v1` 只能视为历史兼容，不得复用官网 credential，也不能作为新双绑定已上线的证据。

### 5.1 双绑定只读状态

Agent 从各自 `bindingEndpoint` 固定派生无 query/body 的 HMAC GET，不从 bind response 接收 status URL：

```text
GET /internal/v1/agents/status
GET /internal/v1/monitoring/agents/status
```

website 使用 Commands HMAC 的 `website:status.read`，响应回钉 `bindingId/deviceId/agentRef/credentialEpoch/assignmentRevision`；monitoring 使用独立 HMAC 的 `monitoring:status.read`，回钉 `bindingId/deviceId/monitoringAgentRef/credentialEpoch`。counter 是大于 0 的十进制字符串；状态只允许 `active|stale|revoked|degraded`；server time 必须在 ±5 分钟内。两端都 strict 拒绝 unknown/duplicate/超限响应、重定向、IPv6 和 identity/epoch 不匹配。完整 exact keys 和 CLI 行为见 [Agent API v1 第 3.1 节](AGENT-API-V1.md#31-双绑定只读状态合同)。Agent client/CLI 已有，外部两个 status 服务端仍待交付。

### 5.2 修改命令审计

所有通过官网身份/签名校验的修改类 command，不论 dry-run、拒绝、submitted/waiting、成功、失败或 indeterminate，都必须向监控站生成脱敏事件。固定目标端点是与 monitoring bind/ingest 同 origin 的：

```text
POST /internal/v1/monitoring/audit-events/batches
```

transport 使用 monitoring 独立绑定 HMAC，授权主体是该 key 绑定的 `monitoringAgentRef`。audit 使用独立于 telemetry/receipts 的 durable outbox、稳定 event ID、跨重启单调 sequence，以及 batch `observedAt/sentAt`；`bootId` 只作进程关联，不能取代 sequence。服务端按 event ID 幂等 durable commit 后才能 ACK。retry 或 credential epoch 前进不能删除或重写未确认事件，也不能触发 PVE mutation 重放。

`audit-v1` Batch 的固定字段为 `schemaVersion/batchId/monitoringAgentRef/deviceId/credentialEpoch/sequence/bootId/observedAt/sentAt/deliveryState/events`；`events` 为 1..500 项。DeliveryState 必填 `pendingItems/pendingBytes/lastDeliveryError/authBlocked`，可选 `authBlockedSince/oldestObservedAt`。Event 必填 `eventId/assignmentRevision/commandId/idempotencyKey/action/scope/targetRef/websiteCommandKeyId/receivedAt/outcome/payloadDigest/policyDecision/agentVersion`，可选 `acceptedAt/startedAt/finishedAt/errorCode/upid/approvalRef/requestedByRef/resultDigest`。所有 counter 都是十进制字符串；`assignmentRevision` 是 remote Bundle/command authority 的 uint64，不是 assignment document 的文本 revision。

`targetRef` 由 Agent 从验签 identity 构造为 `cluster:<clusterRef>`、`node:<clusterRef>:<nodeRef>` 或 `vm:<clusterRef>:<guestType>:<instanceUuid>:<generation>`，调用者不能自由传。该 audit schema 不含 `operationId` 或 `executionMode`。不得包含 `parameters`、`result`、完整 payload、原始 PVE response/error/UPID、secret、root/其他密码、PVE/API token 或签名/HMAC material；`resultDigest` 只覆盖不含 `result` 的 canonical safe receipt projection，`upid` 若出现只能是原始值的 `sha256:<lowercase hex>`。`lastDeliveryError` 的 exact allowlist 是空字符串、`AUTH_BLOCKED`、`DELIVERY_FAILED`、`QUEUE_CAPACITY`。outbox、dead letter、日志和指标同样适用。监控 UI 目标是按 event/command/action/target/time/outcome 查询。精确 JSON shape、枚举和可选性见 [Agent API v1 第 6.1 节](AGENT-API-V1.md#61-修改命令的独立-monitoring-审计)。Agent 的 strict wire/builder、control journal 投影、不可淘汰 `store.Audit`、runtime sink 和独立 uploader 已接线；启动 delivery worker 前会先 reconcile journal pending event。外部监控存储/UI 未因 Agent 代码而自动上线，仍是 production 修改动作的验收门槛。

### 5.3 previousExit 双域补报

Agent 用 `<stateDirectory>/lifecycle-state.json` 区分 clean exit 和上一进程未完成退出。重启后、访问 PVE 前，会把每个 incident 投影为 component-only telemetry：key 为 `agent.previousExit.<eventId>`，`available=false`，`unavailableReason=previous_unclean_exit`，时间为本次观察时间。它不携带 crash dump、自由错误文本、secret 或上一轮 guest 快照，因此也不能被远端解释为已知的具体崩溃原因。

相应 telemetry destination 启用时，同一 incident 分别进入不可淘汰的 `website-lifecycle` 与 `monitoring-lifecycle` durable queue，使用各自 telemetry identity/HMAC；未启用的一域继续作为 pending incident 保存在本地 state。state 分开记录两域是否已经成功入队，一域不能确认或删除另一域的数据。Agent 侧 session 检测与双域入队已实现；外部官网/监控站的 durable receive、展示和告警尚待各自部署验收。该 telemetry 不是第 5.2 节的 command audit event，也不能替代 audit availability gate。

## 6. Commands 与 receipts

目标端点：

```text
GET  /internal/v1/agents/commands?agentRef=...&after=...&limit=20&wait=25
POST /internal/v1/agents/{agentRef}/command-receipts
```

transport 使用 commands/receipts 各自 HMAC；命令内容在生产环境另用官网 Ed25519 私钥签名，Agent 只持公钥。生产 command authority 还必须签入匹配本机状态的 `bindingId/deviceId/credentialEpoch`、remote Bundle 的 uint64 decimal `assignmentRevision` 和稳定 `idempotencyKey`；该 revision 不是 assignment document 的文本 revision。当前 command client 已发送 `agentRef/after/limit`，尚未发送 `wait`；不要把目标长轮询写成已接线。

Agent 离线时，官网必须把尚未过期的命令持久排队，恢复后仍通过上述主动 poll 交付；官网自身不可达时，Agent 只重试轮询。两种离线场景都禁止自动回退为官网直连 PVE 8006。命令被 Agent 领取后，才由本地 journal、UPID reconcile 和 receipt queue 负责恢复。官网离线队列和 command `wait` 都属于远端待实现/联调能力，本仓不能证明服务端已经部署；旧客户兼容写路径也只能经逐资产 feature flag/cutover 显式选择，不能作为故障 fallback。

修改任务执行门槛是合取而不是任选：website 服务端 IPv4 whitelist、本机 `bindingId+deviceId+agentRef` 关系、commands key scope/epoch/HMAC、Ed25519 key/signature、assignment generation、issued/expiry time、协议/绑定/部署 action allowlist、approval/resource lock，以及 monitoring audit availability 全部通过才可执行。IPv4 whitelist 不能让其他校验 fail-open，monitoring key 也不能授权 commands。

动作名必须采用代码值，例如 `snapshot.create`、`backup.create`、`firewall.rule.create`、`firewall.guest.set-ipfilter`、`task.status`。完整 allowlist、scope、参数和 UPID 重启恢复见 [Agent API v1 第 5–7 节](AGENT-API-V1.md#5-长轮询操作线程和-upid-恢复)。

## 7. HTTP/幂等处理

- `2xx`：按 HTTP status 确认本地队列；成功 body 是 advisory，空、非 JSON 或过大都不能把已接受批次变回 retry；
- `400/404/409/422`：协议、identity 或冲突进入 quarantine 并告警；唯一例外是 HTTP 409 且平铺/嵌套机器码无冲突地等于 `DUPLICATE`，此时 ACK；
- `401/403`：打开对应 destination 的认证断路器，队列 head 不 Nack、不 quarantine；只有同 trust domain 严格递增的 `credentialEpoch` 安装新 credential 才可恢复，不能跨 endpoint 借 key；
- `408/425/429/5xx`：遵循合理的 `Retry-After`，否则指数退避加抖动；
- timeout/断线：GET/上报按同一业务 ID 重试；PVE mutation 提交结果不明时返回 indeterminate，不能自动重提。

需要解析的错误响应默认最多读取 2 MiB，配置硬上限 8 MiB；非 retryable 的超限/歧义响应进入 quarantine，不能因错误 body 伪造 `DUPLICATE`。

monitoring telemetry、monitoring audit、官网 telemetry、metering、assignment、commands 和 receipts 必须使用相互隔离的状态/队列；确认一个 endpoint 不能删除另一个 endpoint 的数据。monitoring 可使用独立绑定签发的同一 key，但服务端必须按路由分别校验 exact `monitoring:telemetry.write`、`monitoring:audit.write`、`monitoring:status.read` scope；website Commands key 的 status 路由则校验 `website:status.read`。这些 scope 不出现在 bind 响应里，Agent 不解析或信任服务端自报 scope；任一 key 都不能跨 trust domain。
