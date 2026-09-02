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
  "agentObservedIPv4": "198.51.100.24"
}
```

`agentObservedIPv4` 必须是 canonical IPv4，由对应服务端从可信连接元数据观察并签发，只是该 binding 的服务端 source-IP metadata。Agent 不从 payload 或本地网络学习它，也绝不把它作为拨号目的地。website 与 monitoring 分别保存自己的来源白名单，不能在另一域 bind/replace 时覆盖。`serverIPv4Allowlist` 已从 strict response 删除，服务端继续返回该字段会被 Agent 当作 unknown field 拒绝。

官网、监控站和 PVE transport 必须固定 `tcp4`，拒绝 IPv6 literal 和 IPv6 fallback；PVE 只访问 `127.0.0.1:8006`。DNS endpoint 使用系统 A 解析并直接 tcp4 连接，不固定 Cloudflare A/Anycast 集合；HTTP URL hostname 保持不变，继续作为 Host、TLS SNI 与系统 CA 证书 hostname 校验。所有绑定/上报/status client 禁 ambient proxy、拒绝 redirect 和跨 origin credential。服务端继续以可信来源头、`agentObservedIPv4/32`、TLS、`bindingId/deviceId/agentRef`、key scope/epoch、HMAC/Ed25519、nonce/time、assignment generation 和 action allowlist 联合授权。

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

Agent 客户端接受 `wait<=25s`，验证 Ed25519 signature、exact assignment JSON SHA-256、签发/过期时间、cursor 与单调 revision，并拒绝防回滚失败。新 authority 文档在 assignment document 顶层携带 `allowedActions`：

```json
{
  "schemaVersion": 1,
  "revision": "assignment-4",
  "issuedAt": "2026-09-01T04:00:00Z",
  "allowedActions": [
    "pve.discover",
    "vm.clone",
    "vm.set-cloud-init",
    "vm.set-timezone",
    "vm.verify-delivery"
  ],
  "assignments": []
}
```

`allowedActions` 存在时必须是 1..64 个不重复、符合 action grammar 且属于 Agent 本地 known-action registry 的名称；unknown/duplicate/空数组均 fail closed。该数组位于 `assignmentDocument` 内，因此由 bundle 的 exact `contentSha256` 和 Ed25519 signature 覆盖。Agent 将当前 `bindingId/deviceId/credentialEpoch`、bundle 的 uint64 revision/cursor、exact document、document SHA-256 原子写入 `<stateDirectory>/assignments/refresh-state.json` version 2，然后在一个控制锁内同时切换 inventory、revision 与 action set；重启时 scope 必须逐项匹配当前 binding，崩溃或并发 command poll 不能观察到混合 authority。首次收到 version-2 authority 后，后续文档省略 `allowedActions` 会被拒绝。旧文档仍可沿用绑定时的静态 allowlist，直到第一次安全升级为动态 authority。

跨语言固定向量位于 `internal/assignment/testdata/allowed-actions-v2.json`，包含 exact assignment bytes、SHA-256、canonical payload、测试专用 Ed25519 seed/public key 和 signature；测试 seed 仅用于 fixture，绝不是生产 credential。Go 测试会重新计算所有值并执行完整 bundle verify，官网实现必须使用同一向量得到逐字节相同结果。

`<stateDirectory>/assignments/assignments.json` 继续作为工具和旧 reader 的兼容投影；version-2 runtime 重启只信任上述原子 authority 文件，不会把兼容文件与另一 revision 拼接。安装器已接 service-owned assignment 路径及 legacy 首次迁移。官网服务仍需按该 shape 联调，不能据此宣称服务已上线。

官网重新绑定/替换 credential epoch 时，旧 `refresh-state.json` 不得跨 binding 继续生效。Agent 管理事务在服务停止且新绑定响应已签发后精确移除旧 refresh authority，保留新响应的初始 assignment，并以 revision 0 启动刷新；此时所有 command authority 校验均拒绝，直到新绑定 credential 验证的首个单调 bundle 原子落盘。该清理只针对 refresh authority 文件，不触碰 telemetry/control queue、journal 或 dead-letter。

仅删除官网绑定时，为了让独立监控域继续展示最后一份 inventory，旧 authority 文件可以留作只读 inventory 投影，但 website control/refresh 已从配置和私有状态中禁用，不能执行命令。以后重新绑定时必须先按上一段精确移除它，再接受新 binding scope。

## 3. 官网 metering

目标端点：

```text
POST /internal/v1/metering/usage-batches
```

`internal/protocol.UsageBatch` 包含 `schemaVersion`、`batchId`、Agent/collector/source/cluster identity、`mode`、十进制字符串 `sequence`、`observedAt` 和 events。每个 event 包含当前 assignment identity、`eventId`、`counterEpoch`、十进制字符串 sequence、source/billing state/cutoverAt，以及 PVE 原始累计 `ingressBytes`/`egressBytes`。逐 NIC 事件另带 `interfaceRef/canonicalMac/networkRole/metered`。

硬规则：

- 所有 uint64 counter 用 JSON 十进制字符串，避免 JavaScript 精度丢失；
- 只上报 PVE 累计 ingress/egress，QGA 永不参与计费；
- 官网负责差值、乱序、重复、counter reset、账期和最终账本；Agent 不计算欠费；
- 非 production batch 不能含 active event；未映射、generation 不匹配或计数缺失不能伪造成 0；
- 正式逐 NIC 计量使用 PVE 宿主 `tap/veth` netdev counter，按 signed `netN + canonical MAC + generation` 关联；public 必须 metered，private 必须不计费；多 NIC 的 guest aggregate 永远不能 active，只有恰好一张 public NIC 时才保留安全 aggregate fallback；
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

动作名必须采用代码值，例如 `snapshot.create`、`backup.create`、`firewall.rule.create`、`firewall.guest.verify-ipfilter-sets`、`task.status`。完整 allowlist、scope、参数和 UPID 重启恢复见 [Agent API v1 第 5–7 节](AGENT-API-V1.md#5-长轮询操作线程和-upid-恢复)。

## 7. HTTP/幂等处理

- `2xx`：按 HTTP status 确认本地队列；成功 body 是 advisory，空、非 JSON 或过大都不能把已接受批次变回 retry；
- `400/404/409/422`：协议、identity 或冲突进入 quarantine 并告警；唯一例外是 HTTP 409 且平铺/嵌套机器码无冲突地等于 `DUPLICATE`，此时 ACK；
- `401/403`：打开对应 destination 的认证断路器，队列 head 不 Nack、不 quarantine；只有同 trust domain 严格递增的 `credentialEpoch` 安装新 credential 才可恢复，不能跨 endpoint 借 key；
- `408/425/429/5xx`：遵循合理的 `Retry-After`，否则指数退避加抖动；
- timeout/断线：GET/上报按同一业务 ID 重试；PVE mutation 提交结果不明时返回 indeterminate，不能自动重提。

需要解析的错误响应默认最多读取 2 MiB，配置硬上限 8 MiB；非 retryable 的超限/歧义响应进入 quarantine，不能因错误 body 伪造 `DUPLICATE`。

monitoring telemetry、monitoring audit、官网 telemetry、metering、assignment、commands 和 receipts 必须使用相互隔离的状态/队列；确认一个 endpoint 不能删除另一个 endpoint 的数据。monitoring 可使用独立绑定签发的同一 key，但服务端必须按路由分别校验 exact `monitoring:telemetry.write`、`monitoring:audit.write`、`monitoring:status.read` scope；website Commands key 的 status 路由则校验 `website:status.read`。这些 scope 不出现在 bind 响应里，Agent 不解析或信任服务端自报 scope；任一 key 都不能跨 trust domain。
