# PPFlight Agent API v1（目标契约与迁移边界）

本文是官网、监控站与 PVE Agent 对接的规范入口。文中的“必须”描述目标契约；是否已经可用以第 11 节实现状态为准。存在 Go 类型、Executor 分支或 runtime 接线只证明相应 Agent 代码事实，不能据此宣称服务端 API、官网路由或生产能力已经上线。

## 1. 目标边界与迁移现状

目标架构不再让官网保存 PVE URL、PVE 用户或 PVE API Token，也不让官网连接客户 PVE 的 8006：

```text
官网业务控制面 <── Agent 主动出站 HTTPS ──> PVE 节点上的 Agent
                                             └──> https://127.0.0.1:8006
```

PVE Token 由节点上的凭据 bootstrap 自动创建并保存在 root-only 本地环境文件。只读采集身份和受控写身份必须分离。绑定请求和任何上报都不得包含 PVE endpoint/Token。安装后的 helper 是 `/usr/local/lib/ppflight-agent/create-pve-tokens.sh`（root-only `0700`）；一键准备创建 read/control Token，并为 dedicated control role 在 `/` 同时授予固定 VPS 管理权限。该角色不含用户/RBAC、主机电源或主机控制台权限；`--acl-only --control-global-acl` 可为早期已存在的专用 control identity 完成同一迁移且不读取、重写或重新创建 secret。`--control-pool NAME`/重复 `--control-scope PATH` 仍可用于显式缩小的人工部署。

节点 root 可用 `ag-pve pve prepare --tls-server-name <证书DNS名>` 完成本地 readiness；一键安装会自动调用它。命令在任何 PVE RBAC 修改前先验证固定 `/etc/ppflight-agent/pve-root-ca.pem`、严格 SNI、本机节点和本机版本；缺少凭据时调用固定 helper 创建隔离 read/control Token，已有 dedicated identity 缺少固定权限时以 ACL-only 模式补齐并再次回读验证。TCP endpoint 始终精确为 `https://127.0.0.1:8006`（`tcp4`）；`pve.tlsServerName` 必须是证书覆盖的 DNS 名，不能是 IP、`localhost`、IPv6 或通配符。read Token 必须在 `/` 具备 `Sys.Audit VM.Audit VM.Monitor Datastore.Audit SDN.Audit` 并成功读取本机 node status/storage；control Token 必须在 `/` 精确具备 Agent 固定 VPS control role。prepare 同时把旧配置的 node/smart exporter 迁移到启用的固定 loopback URL，切到 production/api、受控重启并等待真实采集及已绑定 telemetry 通道成功。官网与 monitoring 两个绑定均稳定且 device identity 一致后自动打开 `productionExecution`；缺少任一信任域、pending/commit/解绑事务或权限回读失败都保持关闭。

官网 Agent upgrade route 的 feature flag **必须默认关闭**。迁移期间，旧客户升级继续走既有升级路由；它是待迁移的兼容路径，不是目标架构。只有某资产完成 shadow/read-back、幂等、资源互斥和显式 cutover 后，才能开启该资产的 Agent upgrade route 并关闭其旧 PVE 直连。任何时刻不得让新旧升级路径并发写同一资源。

官网是业务资产、IPAM、套餐、容量、审批、`generation` 和操作线程的权威方；Agent 是 PVE 读取与受控执行方。VMID 不能单独作为客户资产身份。

### 1.1 IPv4-only 外连与服务端来源白名单

Agent 到官网、监控站和 PVE 的所有连接必须显式使用 IPv4：dial network 固定为 `tcp4`，不得尝试 IPv4 失败后的 IPv6 fallback 或 IPv6 literal。PVE 固定访问 `https://127.0.0.1:8006`；`localhost`、`::1` 或节点对外地址不能代替。IPv4-only 是部署安全策略，不影响 guest 的 IPv6 网络配置能力。

官网绑定成功后，website trust domain 从可信连接元数据冻结该 Agent 的公网出口 IPv4/32；monitoring 绑定独立冻结另一份来源白名单，不能由 website bind/replace 覆盖。Agent 不固定 Cloudflare DNS A/Anycast 地址，只连接绑定 origin hostname。来源 IP 只是附加门槛，绝不能取代 TLS、绑定身份、HMAC/Ed25519、epoch 或 nonce/time 校验。

两种 bind response 都必须包含且只能以严格 schema 解码以下 `networkPolicy`：

```json
{
  "agentObservedIPv4": "198.51.100.24"
}
```

`agentObservedIPv4` 是**对应服务端**在该 bind 请求上从可信连接元数据观察并签发的 canonical IPv4；它不是 Agent 本地自报/探测值，也不是 destination。`serverIPv4Allowlist` 已删除，继续返回会触发 strict unknown-field 拒绝。Agent 对 endpoint hostname 使用系统 A 解析并固定 `tcp4`，保留 URL hostname 执行 Host、TLS SNI 和系统 CA 证书校验；ambient proxy、redirect、跨 origin credential、IPv6 literal/fallback 一律拒绝。该来源 policy 与 binding state 原子保存，两域有各自 credential epoch 与 policy，不能共享。

`ag-pve monitoring preflight --endpoint HTTPS_URL` 是可选只读诊断。它对一次 DNS A 快照逐个进行 tcp4 与原 hostname/SNI 的系统 CA TLS 检查，只输出 `resolvedAt`、`resolvedA` 和 `checks`；不再输出 `eligibleServerIPv4Allowlist`/`readyForOperatorApproval`，也不作为绑定前置。它不发送 HTTP 请求、不持久化 policy、不读取/消费绑定码。

默认忽略 `HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY` 等环境代理。若未来支持代理，只能使用显式配置、受控 CA/认证和固定链路的代理，并继续在最终 origin、目标 IPv4、证书、重定向与 credential scope 上 fail closed；不能因代理解析 DNS 而绕过 IPv4 whitelist。

## 2. 官网一次性绑定

### 2.1 服务端创建绑定码

官网管理员创建一次性绑定码。服务端至少应使用 128 bit 随机熵、只展示一次、仅保存慢哈希，并设置短有效期、失败次数上限和撤销状态。绑定码的消费、Agent 身份创建和凭据签发必须在同一事务中完成；已消费、过期、撤销或错误的 code 返回同一种通用失败，不能泄露绑定对象。

管理员不填写 PVE URL、PVE 用户或 Token。官网不得以“联通性检测”为由访问 PVE 8006。

### 2.2 Agent 主动绑定

```http
POST /internal/v1/agents/bind
Content-Type: application/json
```

请求与 `internal/enrollment.Request` 一致：

```json
{
  "schemaVersion": 1,
  "requestId": "123e4567-e89b-42d3-a456-426614174000",
  "bindingCode": "一次性高熵绑定码",
  "deviceId": "device-node-01",
  "agentVersion": "1.0.0",
  "hostname": "pve01.example",
  "nodeClaim": {"nodeRef": "pve01", "pveVersion": "9.0.8"},
  "capabilities": ["pve.discovery.v1", "pve.control.v1", "pve.telemetry.v1"]
}
```

`agentVersion` 只是一项可选、非权威的观测信息，绝不是官网绑定准入条件。官网绑定处理器不得要求或语义校验它，也不得按版本格式、新旧、最低版本、release manifest、Agent/installer commit、wire identity、binary hash、build ID 或 User-Agent 允许或拒绝绑定；字段缺失、空值、未知值或非 semver 值都不能导致绑定失败。首次绑定只以正确的绑定 API 合同和有效的一次性绑定码为准，并保留 `requestId/deviceId` 的幂等与并发消费规则。版本类信息即使被保存，也只能用于非权威展示或后续升级规划；绑定成功后签发的凭据、可信观测 IPv4 白名单以及后续 HMAC/Ed25519、ACTIVE/epoch/device/key/scope/assignment 校验不因此放宽。

成功响应与 `internal/enrollment.Response` 一致，包含：

- UUID `bindingId`，以及必须与请求完全一致的 `deviceId`；
- `agentRef`、`collectorRef`、`sourceRef`、`clusterRef`、`nodeRef`、`site`；
- metering、telemetry、assignments、commands、receipts 五个与 bind URL 同源的安全端点；
- 五组 endpoint-specific HMAC `keyId`/`secret`；
- `algorithm=ed25519` 的命令验签公钥与 key ID；
- `allowedActions`、初始 `assignmentDocument`、必填 `networkPolicy`、单调递增的 `credentialEpoch` 和 `issuedAt`。

`allowedActions` 必须包含 1..64 个不重复动作。它是服务端按资产签发的授权子集，不是让服务端扩展协议动作面的入口：Agent 配置与运行时仍只接受本地 known-action registry 中的名称，并可在绑定授权之上继续缩小部署 allowlist；样例默认仅开放三个生命周期动作。

Agent 严格拒绝未知响应字段、缺失/非法 `networkPolicy`、跨 origin 端点、重定向、无效 assignment 和不安全凭据。官网状态固定为 `<stateDirectory>/bindings/binding-state.json`，稳定 device ID 为同目录 `device-id`；替换绑定要求新 code、显式 `--replace`，且新的 `credentialEpoch` 必须前进。

绑定前包含一个共享、本机 root-only readiness 阶段：安装器默认的 `mode=production`/`pve.source=disabled` 不能启动、采集或外发；发布版运行态只有 `mode=production`/`pve.source=api`，不含 simulator 或测试数据上报路径。CLI 在读取 code 前先完成无凭据 CA/SNI/本机预检，再安全创建或读取隔离 PVE Token；固定 `127.0.0.1:8006/tcp4`，校验 API version、`/` 完整 read audit 权限、本机 node status/storage、固定 control role 权限和 `/usr/bin/pveversion` 一致性，并强制启用固定 loopback exporter，切到 `mode=production`/`source=api`，受控重启并等待真实采集及已有 telemetry 通道成功。readiness 失败不读取 code、不创建 pending、不发 bind 请求。两域 binding 事务随后各自回读 config/state/overlay、重启并确认对应 binding ID/epoch 与首次 telemetry 成功；website 以 fail-closed commit marker 关联 config/state/initial assignment。第二个信任域完成且两域 device identity 一致时，CLI 在同一原子配置事务中自动启用 `productionExecution`，无需人工 ACL/配置命令。服务端一旦签发新 binding，任何后续本地失败都不得恢复旧凭据、旧配置或旧 assignment，而必须保留 marker/pending、停止服务并通过同码幂等重试恢复；两个 trust domain 互不覆盖。

`requestId` 是 Agent 在第一次网络请求前生成并持久化的 UUID。相同 `deviceId` 和相同 canonical 请求内容重试时必须复用同一个 `requestId`；未清除的 pending 不允许换输入或生成新 ID。本地 `<stateDirectory>/bindings/.website-binding-pending.json` 只保存 `requestId` 与 canonical 请求 SHA-256 指纹：绑定码参与指纹计算，但原文绝不能持久化。pending 或 commit marker 存在时 runtime 必须 fail closed；操作者以同一 code 重试，服务端回放同一幂等响应，Agent 验证并完成中断的本地事务后才清除它们。

生产安装中，`<stateDirectory>/bindings` 必须为 `root:ppflight-agent`、`0750`，其中 website/monitoring/device/pending 文件为 `0640`。root 运行的管理 CLI 负责原子更新；systemd Agent 只通过组权限读取，并以 `ReadOnlyPaths=<stateDirectory>/bindings` 进一步禁止服务写入凭据目录。assignment 文件不属于该目录：远端 refresh 写入 `<stateDirectory>/assignments/assignments.json`，目录/文件为 `ppflight-agent:ppflight-agent`、`0750/0640`；原子替换已有文件时保留 owner/group/mode。安装器首次迁移旧 `/etc/ppflight-agent/assignments.json` 时必须保留内容，不得用空文档覆盖。

绑定码只能从标准输入或 owner-only、非符号链接的 `--code-file` 读取：

```bash
sudo ag-pve bind \
  --endpoint https://www.example/internal/v1/agents/bind

sudo ag-pve bind \
  --endpoint https://www.example/internal/v1/agents/bind \
  --code-file /run/ppflight-binding-code
```

CLI 必须拒绝额外位置参数和任何接收 code 值的命令行选项；bind URL 不能含 query。绑定码、HMAC secret、PVE Token 和密码不得出现在 argv、shell history、日志、回执或 dead-letter 元数据中。

### 2.3 服务端幂等与并发消费

官网和监控站绑定服务必须采用相同的事务语义：

- 以 `requestId + deviceId` 定位幂等请求，并保存 canonical 请求 hash；同 ID、同 device、同 hash 的重试返回第一次签发的同一 `bindingId`、identity 与 credential，不能再生成一套凭据；
- 同一 `requestId` 携带不同 device 或 canonical body 必须返回冲突，不能覆盖第一次结果；
- 一次性 code 的校验、消费、binding 创建、credential 签发和幂等结果写入必须属于同一事务；同一 code 的并发请求最多只有一个能签发 binding；
- 服务端只能保存绑定码的慢哈希/消费状态，不能持久化绑定码原文。为安全重放相同幂等响应，已签发 credential 必须以服务端加密存储的可重放形式保存，并受密钥轮换、最小访问权限和审计保护；日志、指标和错误不得包含 secret。

## 3. 监控站独立绑定

监控站不是官网 enrollment 的第六个 endpoint，而是独立 trust domain：使用另一枚一次性绑定码，只签发 monitoring plane 所需的 endpoint/HMAC，并拥有独立本地状态、设备绑定关系、轮换规则和 `credentialEpoch`。严格响应仍只返回 telemetry `ingestEndpoint`；同一 monitoring key 的附加用途只限第 6.1 节固定同 origin audit POST 和第 3.1 节固定同 origin status GET，不能由响应增加任意 URL。目标接口是：

```http
POST /internal/v1/monitoring/agents/bind
Content-Type: application/json
```

请求复用官网绑定的安全基础字段并要求独立的 UUID `requestId`；它不要求先完成官网绑定：

`nodeClaim.pveVersion` 不是用户输入。官网与监控 CLI 都不提供 `--pve-version`，在读取绑定码前使用固定绝对路径 `/usr/bin/pveversion`（不经 shell）自动发现本机 PVE 8/9，并只接受规范化版本文本。命令失败、3 秒超时、非 PVE 环境、多行/NUL/异常输出或不受支持版本时返回 `PVE_VERSION_DISCOVERY_FAILED`，不发送绑定请求、不得以空值、`unknown` 或旧缓存继续。服务端可将该字段作为非权威观测信息，但不得用它或 Agent version/commit/hash 作为一次性码绑定准入条件。

```json
{
  "schemaVersion": 1,
  "requestId": "123e4567-e89b-42d3-a456-426614174010",
  "bindingCode": "另一枚一次性高熵绑定码",
  "deviceId": "device-node-01",
  "agentVersion": "1.0.0",
  "hostname": "pve01.example",
  "nodeClaim": {"nodeRef": "pve01", "pveVersion": "9.0.8"},
  "capabilities": ["telemetry-v1", "audit-v1", "delivery-state-v1", "ipv4-only", "mutual-whitelist-v1"]
}
```

成功响应严格限制为：

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
  "networkPolicy": {
    "agentObservedIPv4": "198.51.100.24"
  },
  "credentialEpoch": 1,
  "issuedAt": "2026-08-30T00:00:00Z"
}
```

响应只能包含上列字段，不含 assignments、commands、receipts、metering、Ed25519 key 或 website identity；`deviceId` 必须与请求一致。`algorithm` 固定为 `hmac-sha256`，`secretEncoding` 固定为 `base64`，解码 secret 为 16..4096 bytes；`compression` 只允许 `none|gzip`，`maxCompressedBytes` 为 1..64 MiB，`maxUncompressedBytes` 不小于压缩上限且不超过 256 MiB。`networkPolicy` 使用第 1.1 节同一严格规则，但只能是 monitoring authority 签发的独立 policy，不能接受 website 值或让 website bind/replace 覆盖。Agent 将响应原子保存在独立 `<stateDirectory>/bindings/monitoring-binding-state.json`，其 pending 文件为同目录 `.monitoring-binding-pending.json`。`telemetry-v1` 使用该 key 绑定的 `monitoringAgentRef` 作为授权主体；payload 中自报的 website identity 只是数据标签，不能参与鉴权。当前 telemetry builder 已包含 binding/device/epoch、`observedAt/sentAt` 和跨重启单调 sequence；`bootId` 仍保留作进程/legacy correlation，但不能作为幂等或排序权威。

监控绑定沿用第 2.3 节的 `requestId + deviceId + canonical hash` 幂等和 code 并发消费规则。官网和监控绑定可复用同一个本机持久 `deviceId` 来表示物理安装，但 `bindingId`、授权主体、credential 和 epoch 始终属于不同 trust domain。

必须满足以下隔离不变量：

- 官网 bind/replace 不创建、不返回、不覆盖、不轮换监控站凭据；监控站 bind/replace 也不能改官网身份或五组官网凭据。
- 两套绑定状态分别使用 `<stateDirectory>/bindings/binding-state.json` 与 `<stateDirectory>/bindings/monitoring-binding-state.json`、不同原子替换事务、credential epoch 和 `networkPolicy`；失败时不能半覆盖另一套状态。
- monitoring bind/ingest 使用 HTTPS（仅测试可用 loopback HTTP），拒绝重定向；`ingestEndpoint` 必须与 bind endpoint 同 origin，不能由响应把 credential 引向第三方。
- 监控站凭据只能按逐路由 scope 写 monitoring telemetry/audit 或读取固定 monitoring status，不能调用 website metering、assignment、commands 或 receipts，也不能授权 PVE mutation。
- 监控站绑定码同样不得进入 argv、URL 或日志。

Agent 侧已有严格 request/response 类型、pending 幂等状态、独立私有状态、运行时 private-state credential overlay 和 `ag-pve monitoring bind` CLI；在首次请求前持久化 pending 后，成功响应立即建立 fail-closed commit marker，再原子写入 monitoring state/config、严格回读 config/state/overlay，受控 `systemctl restart ppflight-agent.service`，轮询 `is-active` 和 loopback `/status`，只有运行进程报告相同 monitoring `bindingId` 与十进制 `credentialEpoch` 才清除 marker/pending 并报告成功。服务端已签发时，写入、重启或加载确认失败绝不恢复旧 monitoring config/state（旧凭据可能已撤销）；marker/pending 和停止的服务保留，操作者使用同一 code 重试以复用 requestId 和服务端原响应完成恢复。日志/输出不得含 secret。该流程不清理 durable audit/HA queue，也不触碰 website state。监控服务端路由属于另一交付任务，本仓代码不能证明它已部署。

### 3.1 双绑定只读状态合同

状态端点不扩展两种 bind 响应，也不接受服务端返回的任意 URL。Agent 从各自已验证的 `bindingEndpoint` 固定派生同 origin/path，发送无 query、无 body 的 HMAC-signed GET：

```text
GET /internal/v1/agents/status
GET /internal/v1/monitoring/agents/status
```

website 请求复用 Commands HMAC，但服务端必须在该路由单独校验 `website:status.read`；monitoring 请求使用独立 monitoring HMAC 并校验 `monitoring:status.read`。同一 monitoring key 的另外两个 exact scope 是 `monitoring:telemetry.write` 与 `monitoring:audit.write`。scope 不新增到 bind response，Agent 不解析或信任服务端自报 scope；路由授权由服务端绑定记录决定，两个 trust domain 不能互借 key。

website status 响应的 exact keys 是：

```json
{
  "schemaVersion": 1,
  "bindingId": "123e4567-e89b-42d3-a456-426614174000",
  "deviceId": "device-node-01",
  "agentRef": "agent-01",
  "status": "active",
  "credentialEpoch": "3",
  "assignmentRevision": "17",
  "lastVerifiedAt": "2026-08-30T00:00:00Z",
  "lastAssignmentIssuedAt": "2026-08-30T00:00:01Z",
  "lastCommandIssuedAt": "2026-08-30T00:00:02Z",
  "lastReceiptReceivedAt": "2026-08-30T00:00:03Z",
  "lastReceiptCommandId": "command-2026-0001",
  "commandChannelStale": false,
  "serverTime": "2026-08-30T00:00:04Z"
}
```

website 响应中的四个 last-* 时间和 `lastReceiptCommandId` key 也固定存在；未知值编码为 JSON `null`，不得省略或使用空字符串。`credentialEpoch` 与 `assignmentRevision` 是大于 0 的 canonical 十进制字符串，且必须分别与本机 website binding 和 `<stateDirectory>/assignments/refresh-state.json` 精确匹配；后者不是 inventory document 的文本 revision。

monitoring status 响应的 exact keys 是：

```json
{
  "schemaVersion": 1,
  "bindingId": "123e4567-e89b-42d3-a456-426614174011",
  "deviceId": "device-node-01",
  "monitoringAgentRef": "monitor-agent-01",
  "status": "active",
  "credentialEpoch": "2",
  "lastVerifiedAt": "2026-08-30T00:00:00Z",
  "lastTelemetryReceivedAt": "2026-08-30T00:00:01Z",
  "lastTelemetryBatchId": "123e4567-e89b-42d3-a456-426614174031",
  "telemetryStale": false,
  "lastAuditReceivedAt": "2026-08-30T00:00:02Z",
  "lastAuditBatchId": "123e4567-e89b-42d3-a456-426614174032",
  "auditStale": false,
  "serverTime": "2026-08-30T00:00:03Z"
}
```

monitoring 响应中的三个 last-verified/received 时间和两个 batch ID key 固定存在，未知值编码为 JSON `null`，不得用空字符串；非空 batch ID 必须为 UUID。两种响应的 `status` 都只允许 `active|stale|revoked|degraded`；strict decoder 拒绝 unknown/duplicate/trailing 数据和超过 1 MiB 的响应。响应 identity、credential epoch（website 另含 assignment revision）必须逐项等于本机 state，`serverTime` 与本机相差不超过 ±5 分钟，所有非空时间必须是非零 UTC。transport 继续执行 IPv4-only、TLS 1.2+、no ambient proxy、no redirect。

`ag-pve website status` 和 `ag-pve monitoring status` 都输出脱敏的 local binding、local Agent `/status` 与对应 remote status；本地 state 缺失、website assignment revision 为 0、远端不可达或任何回钉失败都以安全码 fail closed，不能打印 credential 或上游 body。Agent 客户端/CLI 已实现；外部 website/monitoring status 服务端仍由相应任务交付，不能因本地命令存在而宣称已上线。

## 4. 多轮只读 discovery

添加 PVE 的向导通过签名动作 `pve.discover` 分轮读取：

1. `version`、`permissions`：版本、有效权限和本机连通性；
2. `nodes`、`storage`、`templates`：节点、存储和模板；
3. `networks`：无 `nodeRef` 时读取 cluster SDN，有 `nodeRef` 时读取节点网络；
4. `capacity`：指定节点的 node status 与 storage；
5. `firewall`：cluster，以及指定节点时的 node/guest options、rules、IPSet 名称；
6. `readiness`：节点在线状态的最终只读检查。

参数与 `internal/discovery.Request` 一致：

```json
{
  "operationId": "operation-2026-0001",
  "phase": "templates",
  "nodeRef": "pve01",
  "cursor": "0",
  "limit": 20
}
```

`limit=0` 或省略使用默认值 20，合法范围是 **1..50**；50 是实现硬上限。`cursor` 是当前实现的非负十进制 offset，调用方仍应把它视为 opaque string。`version/permissions` 只允许 cluster scope；`storage/capacity` 只允许 node scope。其余 phase 可用 cluster 或 node scope，但 node scope 命令的 `nodeRef` 必须等于签名 identity 的 node，cluster scope 命令不得在 body 偷带 node selector；节点网络使用 node scope。

结果与 `internal/discovery.Result` 一致：`operationId`、`phase`、`observedAt`、`complete`、可选 `nextCursor`、typed `data` 和安全 `errorCode`。固定错误码包括 `INVALID_REQUEST`、`PVE_FORBIDDEN`、`PVE_NOT_FOUND`、`PVE_ERROR`、`PVE_UNAVAILABLE`。原始 PVE 错误文本不得回传。

`pve.discover` 只能调用固定 GET 读取。启用 firewall 或修改任何资源必须创建独立、签名、审批的写命令，不能藏在 discovery 中。

`networks` phase 完成后，向导不能依靠 PVE 返回顺序猜测“第一张网卡是公网”。管理员必须为每个受管 guest/NIC 保存第 8 节的 typed NIC binding，并在 readiness 前完成 MAC、attachment、VLAN、MTU 和 IPFilter policy 校验。发现数据只是候选值，官网保存的显式 role/policy 才是业务配置。

### 4.1 本地模板 bootstrap（非远程 action）

模板 catalog/storage 发现和首次创建模板属于 PVE 节点上的 root 管理流程，不进入第 7 节的远程 command registry。固定命令是 `ag-pve template catalog|discover|bootstrap`；推荐入口 `ag-pve template init` 会交互选择 catalog item、image/template/backup storage、backup policy、外网桥和可选内网桥。所有普通确认统一显示 `[y/n]` 与回车默认值并接受大小写字母；添加内网 `net1` 默认 `y`，模板备份默认 `n`，最终 plan 执行确认默认 `y`。外网桥映射模板 `net0/public`，可选内网桥映射 `net1/private`，二者不得相同；明确输入 `n` 时不创建 `net1`。交互向导可在明确输入 `y` 后创建缺失的安全隔离 Linux bridge（无 ports/IP/gateway，STP off，autostart），但会拒绝已有 pending network、错误类型或不安全的同名接口，并在 reload task、PVE 配置和内核接口严格回读前阻断模板 plan；已有安全桥只读复用，直接 `template bootstrap` 不创建网络。向导随后生成 plan，直接回车或输入 `y` 会执行，输入 `n` 才取消。`backupPolicy=required` 必须选择支持 `backup` content 的 storage；不备份必须显式选择 `disabled`，不能从空值推断。

受信 bundle 与 Agent 使用同一发布/安装包交付，仓内固定源为 `bundles/ppflight-cloudinit`；安装器不从网络下载 helper 代码，bundle 缺失、多文件或摘要不符都会 fail closed。安装后的默认根目录是 root-owned managed symlink `/usr/local/lib/ppflight-agent/template-bootstrap`；它只能解析到 `/usr/local/lib/ppflight-agent/template-bundles/<manifest-derived-id>` 的单层受管版本目录。自定义 root 不允许 symlink，受管 target 与内部组件也不得可被 group/other 写入或再含 symlink。入口固定为 `tools/ppflight-template-bootstrap.py`。Runner 每次特权调用前严格解析 `agent-vendor-manifest.v1.json`，拒绝 unknown/版本混装/摘要不符，校验 catalog revision/SHA-256，再用 `/usr/bin/python3 -I`、固定 PATH、无 stdin、受限环境和有界 stdout 调用唯一入口；不能下载或执行官网传来的脚本、URL、catalog 路径或 shell 片段。

manifest 的 `networkRedirectPolicy` 也是 strict 合同：只能是 `allowed=true`、`schemes=["https"]`、`addressFamily=ipv4-only`、`hostPolicy=upstream-selected`、`integrityPolicy=catalog-sha256-and-official-checksum`。因此上游可以选择 HTTPS redirect host，但 helper 的每次下载都必须使用 `curl --disable --ipv4`、最多五次 HTTPS-only redirect，并继续通过 catalog SHA-256 与官方 checksum 链验证内容；不得把“redirect 可用”解释为可执行任意远程代码。

`bootstrap` 默认只做 plan。`--bridge` 是外网 `net0`，`--internal-bridge` 是可选内网 `net1`。显式 `--execute` 必须使用与已确认 plan 相同的 storage/items/两个 bridge，并原样带回 plan 的 UUID `requestId`、UUID `operationId`、`catalogRevision` 和 `catalogSha256`；任一 catalog 漂移都必须在 PVE mutation 前拒绝。helper 退出码固定为：0 表示 catalog/discovery 成功、plan ready 或 execute 全部成功；1 表示已进入执行后 builder/template/backup 失败；2 表示参数、catalog、storage、PVE preflight 或 VMID 冲突拒绝。调用方优先读取 strict JSON `state/errorCode`，不得解析 stderr 人类日志。

storage discovery 若给出 content remediation，管理 CLI 只在 `program=pvesm`，且 `argv/storageId/current/required/proposed content` 全部通过 strict 交叉校验，存储 active/enabled，角色失败原因仅为缺 content 时允许选择。CLI 用中文分块显示当前/新增/完成后能力和精确命令；操作者选中该存储后自动以固定绝对路径执行且不经 shell，不再追加一次 `Y` 确认；完成后必须重新 discovery 并确认该角色 `allowed=true` 才继续。执行失败或回读不一致均 fail closed。

这条本地流程仅说明 Agent runner/CLI 与 vendored helper 的合同。安装器已强制验证 vendored bundle、Python/Bash 版本、manifest command/Perl module 依赖，复制到 manifest 派生的不可变版本目录，二次验证 staged 内容，再原子切换 managed symlink；旧版本保留，避免 in-flight runner 在切换时观察到混合文件。它不是 `vm.reinstall`、不是远程模板创建 action，也不授权网站执行 PVE mutation；真实 PVE 8/9 plan/execute 仍须随发布物验收。

## 5. 长轮询、操作线程和 UPID 恢复

目标端点全部由 Agent 主动出站：

```text
GET  /internal/v1/agents/commands?agentRef=...&after=...&limit=...&wait=25
POST /internal/v1/agents/{agentRef}/command-receipts
GET  /internal/v1/agents/{agentRef}/assignments?afterRevision=...&wait=25
```

`wait` 最大 25 秒。assignment 客户端当前已实现该上限；command 客户端当前只发送 `agentRef + after + limit`，尚未发送 `wait`，因此命令长轮询仍是目标契约，不能写成已接线。

新 assignment authority 的 `assignmentDocument` 顶层 exact shape 为 `schemaVersion/revision/issuedAt/allowedActions/assignments`。`allowedActions` 是 1..64 个不重复 action name，并与 inventory 一起被 bundle 的 exact content SHA-256 和 Ed25519 signature 覆盖。Agent 只接受本地 compiled known-action registry 中的名称；远端不能借此发明任意 action。

跨语言 golden 为 `internal/assignment/testdata/allowed-actions-v2.json`。它冻结 exact document UTF-8、content SHA-256、canonical payload、测试专用 Ed25519 key material 和 signature；生产端只能把测试 seed 用于 fixture 测试，不能把它安装为真实签名 key。

验签成功后，Agent 把当前 `bindingId/deviceId/credentialEpoch`、bundle uint64 `revision`、opaque `cursor`、exact `assignmentDocument` 和 document SHA-256 作为 version-2 authority 原子持久化；重启加载时三项 binding scope 必须逐项匹配。随后在 command poll 共用的控制锁内同时替换 inventory、revision 和 allowed action set。命令只能看到完整旧 authority 或完整新 authority。首次接受含 `allowedActions` 的动态 authority 后，后续刷新省略该字段会 fail closed；legacy 文档在升级前仍使用绑定时 allowlist 和动态 revision callback，避免破坏旧服务端。`assignmentDocument.revision` 仍只是文档标签，命令签入的是 bundle 的单调 uint64 revision。

重新绑定或 credential epoch 替换时，旧 refresh authority 不得跨 binding 复用。root 管理事务在新响应签发且服务已停止后只移除旧 `assignments/refresh-state.json`，保留新响应的初始 assignment；Agent 可以在 revision 0 启动 assignment refresh，但 command verification 一律 fail closed，直至新 credential 验证的首个 bundle 成功落盘。队列、control journal 和 dead-letter 不属于该重置范围。

删除 website binding 但保留 monitoring binding 时，旧 authority 仅可作为监控 inventory 的最后已知只读投影；website control/refresh 已禁用，不存在可执行命令的 authority。下一次 website rebind 必须在新响应签发后精确移除该文件并从新 scope 的 revision 0 开始。

官网为一次向导、VPS 操作、IP 切换或升级创建持久 `operationId`。其中每个不可分步骤有自己的 `commandId`；同一 command 的重试保留 command ID 和 canonical body。Agent 只有在所有回执已进入持久队列后才推进 cursor。同一 ID 配不同 body 返回 `COMMAND_ID_CONFLICT`。

实际回执状态是 `dry_run`、`submitted`、`waiting`、`succeeded`、`failed`、`indeterminate`、`rejected`。PVE 返回 UPID 时只生成 `submitted/PVE_TASK_SUBMITTED`，不代表成功。Agent 必须把 UPID 写入 journal；后续通过 node scope 的 `task.status` 或内部等价 resolver 读取：

```text
GET /api2/json/nodes/{node}/tasks/{UPID}/status
```

`queued/running` 对应 `waiting/PVE_TASK_WAITING`；终态 `exitstatus=OK` 对应 `succeeded`，其他终态对应 `failed/PVE_TASK_FAILED`。Agent 重启后继续查询同一 UPID，绝不能重新提交原 mutation。若崩溃发生在 durable claim 之后、UPID 持久化之前，只能返回 `indeterminate/EXECUTION_INDETERMINATE`，不得猜测失败后重试。

`vm.cloud-init-snippet.delete` 在通用 command state 之外保存严格单调的安全阶段：`validated`、`reference_proven`、`detached`、`delete_submitted`、`deleted`、`verified`、`succeeded`。记录只含签名 identity、storage identifier 和 exact volume 的 SHA-256；原始 volume、`cicustom`、路径与 PVE response 不可表示。detach 后重启可凭同一 command digest、先前 reference proof 与当前 absent 回读继续；delete UPID 在返回 submitted receipt 前先落盘。UPID `stopped/OK` 之后仍必须读取 target config 和 `content=snippets` 清单并按 volume digest 证明两处 absent，才从 `deleted` 推进到 `verified/succeeded`。状态读取失败保留 waiting/indeterminate，非 OK 终态失败，均不得重新提交 DELETE。最终网站 receipt 不公开原始 UPID。

### 5.1 systemd watchdog、previousExit 与离线命令

生产 unit 当前固定 `Type=notify`、`NotifyAccess=main`、`WatchdogSec=60s`、`Restart=always`、`RestartSec=3s` 和 `StartLimitIntervalSec=0`；显式 `systemctl stop/disable` 仍是管理员的权威操作。Agent 在 tcp4 health listener 已成功监听后才发送 `READY=1`，正常退出发送 `STOPPING=1`。watchdog 心跳不是无条件定时器：采集器会报告请求级 progress，活动采集在完整 watchdog timeout 内无进展、或空闲循环超过下一次 `sampleInterval + watchdog timeout` 仍无进展时，Agent 停止 heartbeat 并返回错误，让 systemd 重启。该机制只监督本机进程，不执行 PVE mutation，也不证明官网/监控站可用。

`<stateDirectory>/lifecycle-state.json` 原子记录当前 session。正常退出写 clean marker；watchdog、SIGKILL、启动失败或其他未完成退出会让 session 保持 `running`。下一进程在任何 PVE collection/control 之前生成稳定 incident ID，并在相应 telemetry destination 已启用时，把 component-only 的 `agent.previousExit.<eventId>`、`unavailableReason=previous_unclean_exit` 分别写入不可淘汰的 `website-lifecycle` 与 `monitoring-lifecycle` durable queue；未启用的一域保持 pending，供以后启用后补入队。两个 domain 独立记 queued 状态，任一入队成功不能清除另一域待补报；payload 不带 crash dump、自由错误文本、secret 或旧 guest 快照。Agent 侧检测、持久化和双域入队已实现，但只有外部 telemetry 服务 durable ACK、展示/告警完成后才能称用户可见闭环。

Agent 离线时，官网目标合同必须把未过期命令持久排队，而不是直接连接 PVE；Agent 恢复后继续主动轮询并重新执行全部签名/authority/time/audit gate。Agent 已领取的命令由本地 journal、UPID reconcile 和 receipt queue 恢复。官网不可达时 Agent 只重试出站轮询/上传，也绝不触发官网旧 PVE 直连作为 fallback。服务端离线任务队列不在本仓，command client 也尚未发送 `wait`；这两项都必须标为远端待实现/联调。旧客户兼容路径只能按资产显式 cutover，不能以 Agent 暂时不可达作为自动回退条件。

## 6. 命令身份、签名、审批和锁

命令 envelope 与 `internal/control.Command` 一致。生产签名使用官网私钥生成的 Ed25519 签名；Agent 只持有绑定响应中的公钥。生产命令必须携带 UUID `bindingId`、稳定 `deviceId`、十进制字符串 `credentialEpoch`、十进制字符串 `assignmentRevision` 和稳定 `idempotencyKey`，并逐项匹配本机 active website binding 与已持久化 remote assignment authority。这里的 `assignmentRevision` 是 assignment Bundle 的单调 uint64，不是 assignment document 内的人类可读 `revision` 字符串。签名覆盖 schema、command/operation/idempotency/agent/binding/device/epoch/assignment ID、`signingKeyId`、scope、时间、完整 identity、action、parameters、operator/approval 和 `bodySha256`。测试模式在未配置 authority 时可使用旧 helper，但不能作为生产回退。

scope 与 identity 必须匹配：

- `cluster`：仅 `clusterRef`，用于 cluster discovery 和 `firewall.cluster.set-options`；
- `node`：`clusterRef + nodeRef`，用于 node discovery、`task.status` 和 `firewall.node.set-options`；
- `vm`：`serviceRef + clusterRef + nodeRef + guestType + vmid + generation + instanceUuid`。

VM 命令必须与当前 signed assignment 完全一致。绑定时 allowlist 是初始授权；后续只有由同一 assignment trust domain 签名的 `assignmentDocument.allowedActions` 才能按 revision 原子缩小或扩展该集合，并且永远受 Agent compiled known-action registry 上限约束。未签名配置、数据库手工改值或 command 自报 action 都不能扩权。除 `pve.discover` 与 `task.status` 外，所有当前协议动作都要求非空 `approvalRef`。mutation 以 scope/资源键互斥；只读 discovery/status 不应占用 mutation 锁。

修改任务执行前必须同时满足：服务端记录的 website 出口 IPv4 whitelist；本机 website state 中同一 `bindingId + deviceId + agentRef`；commands HMAC key 的 endpoint scope 与未回滚 `credentialEpoch`；命令 Ed25519 key ID/signature；remote assignment revision 及 VM assignment identity/generation；issued/expiry time；协议 known-action、绑定授权和部署 allowlist；approval/资源锁；以及第 6.1 节 monitoring audit availability。任一项失败都拒绝执行。IP 命中不能为错误 key、过期 epoch、旧 assignment/generation 或缺失审计开绿灯；monitoring HMAC 也不能授权 website command。

### 6.1 修改命令的独立 monitoring 审计

所有已通过官网身份/签名校验、且 action registry 标记为修改类的 command 都必须产生脱敏审计事件；这包括 dry-run、业务校验拒绝、PVE 提交、waiting、终态成功/失败和 `indeterminate`。`pve.discover`、`task.status` 不属于修改类。无法通过签名或 strict decode 的不可信输入不能照抄其字段进入审计记录，可只计入本地聚合安全指标。

审计批次使用 monitoring 独立绑定的 `monitoringAgentRef` 与 HMAC，而不是 website commands/receipts credential，固定上传到与 monitoring bind/ingest 同 origin 的：

```text
POST /internal/v1/monitoring/audit-events/batches
```

这是与 monitoring telemetry、官网 receipt 和 metering 分离的 durable outbox。每个不可变状态事件有稳定 event ID；重试必须复用同一 ID 和 exact body。audit stream 维护自己的跨重启单调 `sequence`，不能借用 telemetry sequence；`bootId` 只关联产生 batch 的 Agent 进程，不能取代 sequence。batch 必须同时携带事件观察时间 `observedAt` 和实际构造/发送时间 `sentAt`，event 另保留受限的 received/accepted/started/finished 时间。只有监控站 durable commit 后才能 ACK 并删除 outbox item；网络失败、Agent 重启或服务端重复接收都不得丢失、重排为新事件或触发原 PVE mutation 重放。Agent 在启动任何 delivery worker 前先同步 reconcile control journal，使“outbox 已落盘、journal queued marker 尚未来得及更新”的崩溃窗口也按原 event ID恢复，而不是生成新事件。

冻结的 `audit-v1` wire shape 如下。所有 counter 都是 JSON 十进制字符串；`assignmentRevision` 必须大于 0，来源是已认证 command 的 remote Bundle authority，不是 inventory 文档的自由文本 `revision`。所有时间都是 canonical RFC3339 UTC `Z`；`events` 允许 1..500 项且 event ID 不得重复。当前 Agent 每批只放一个 event 并复用其 UUID 作为 `batchId`，但接收端不得把二者相等写成协议不变量。

```json
{
  "schemaVersion": 1,
  "batchId": "123e4567-e89b-42d3-a456-426614174021",
  "monitoringAgentRef": "monitor-agent-01",
  "deviceId": "device-node-01",
  "credentialEpoch": "2",
  "sequence": "42",
  "bootId": "123e4567-e89b-42d3-a456-426614174022",
  "observedAt": "2026-08-30T00:00:02Z",
  "sentAt": "2026-08-30T00:00:03Z",
  "deliveryState": {
    "pendingItems": "3",
    "pendingBytes": "4096",
    "lastDeliveryError": "",
    "authBlocked": false,
    "oldestObservedAt": "2026-08-30T00:00:01Z"
  },
  "events": [
    {
      "eventId": "123e4567-e89b-42d3-a456-426614174021",
      "assignmentRevision": "17",
      "commandId": "command-2026-0001",
      "idempotencyKey": "idempotency-2026-0001",
      "action": "vm.set-network",
      "scope": "vm",
      "targetRef": "vm:cluster-01:qemu:instance-01:3",
      "websiteCommandKeyId": "website-command-key-01",
      "receivedAt": "2026-08-30T00:00:00Z",
      "acceptedAt": "2026-08-30T00:00:00Z",
      "startedAt": "2026-08-30T00:00:01Z",
      "finishedAt": "2026-08-30T00:00:02Z",
      "outcome": "succeeded",
      "upid": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      "approvalRef": "approval-01",
      "requestedByRef": "operator-01",
      "payloadDigest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      "resultDigest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
      "policyDecision": "allowed",
      "agentVersion": "1.0.0"
    }
  ]
}
```

`deliveryState` 的必填键是 `pendingItems`、`pendingBytes`、`lastDeliveryError` 和 `authBlocked`；`authBlockedSince` 与 `oldestObservedAt` 可选，且前者只有在 `authBlocked=true` 时出现并固定为本轮首次认证阻断时间。`lastDeliveryError` 的 exact allowlist 是空字符串、`AUTH_BLOCKED`、`DELIVERY_FAILED`、`QUEUE_CAPACITY`。Event 必填 `eventId/assignmentRevision/commandId/idempotencyKey/action/scope/targetRef/websiteCommandKeyId/receivedAt/outcome/payloadDigest/policyDecision/agentVersion`；`acceptedAt/startedAt/finishedAt/errorCode/upid/approvalRef/requestedByRef/resultDigest` 可选。`requestedByRef` 只能是受限的不透明引用，不能是邮箱或自由文本身份。通用 `outcome` 是 `dry_run|submitted|waiting|succeeded|failed|rolled_back|indeterminate|rejected`；`rolled_back` 只由 `agent.upgrade` 的回滚终态 builder 产生。升级 receipt 的 `waiting` 在 audit 中规范映射为 `submitted`，不会输出升级专用 `waiting`。`policyDecision` 只能是 `allowed|denied`，且 `rejected` 必须对应 `denied`。

`targetRef` 只能由已验签的 typed identity 在 Agent 内部构造，调用者不能自由填写：cluster 为 `cluster:<clusterRef>`，node 为 `node:<clusterRef>:<nodeRef>`，VM 为 `vm:<clusterRef>:<guestType>:<instanceUuid>:<generation>`。审计 schema 故意不含 `operationId` 或 `executionMode`；它们可以保留在 website command/receipt，但不能被额外塞入 monitoring audit payload。

威胁模型包括：command 参数主动携带密码/Token，PVE error/result 回显敏感数据，跨 trust-domain credential 混用，telemetry ACK 误删 audit，崩溃造成审计缺口，以及重试重复执行 mutation。实现必须从 typed command/receipt 投影上列固定字段，不能先序列化完整对象再做字符串替换。严禁上传 command `parameters`、receipt `result`、完整 command/receipt payload、原始 PVE response/error/UPID，以及 secret、root/其他密码、PVE/API token、HMAC/Ed25519 material。`payloadDigest` 绑定已签 command body；`resultDigest` 只散列不含 `result` 的 canonical safe receipt projection，绝不能先对原始 PVE/result body 求 hash 再借该字段外传。`upid` 字段若出现，只能是原始 UPID 的 `sha256:<lowercase hex>`；原始值只可保留在本地 journal 和 website receipt。相同禁令适用于 outbox 文件名/元数据、dead letter、日志、指标和错误。digest 只能用于一致性证明，不能代替敏感原文进入监控站。监控服务端须以 event ID 幂等落库，并让 UI 至少可按 event/command/action/target/time/outcome 查询；UI 和服务端由监控站交付，不能因本文目标契约而宣称已上线。

修改类 command 的 fail-closed 门槛是：官网在 dispatch 前确认有效 monitoring binding/audit route，Agent 本地确认独立 audit outbox 可持久化。该门槛同样适用于 dry-run，不能用 test mode 绕过审计。监控站暂时不可达时，已持久化事件可后台重试且不能重提 mutation；若在执行前无法持久化该命令的审计起始事件，则不得接受/执行该修改命令。credential epoch 前进不得清空旧 outbox。production 还必须完成审计 endpoint 与 UI 查询联调。

## 7. Executor 动作和参数事实

以下名称是当前代码接受的完整动作名，不得使用旧草案别名。

| scope | action | 关键参数/约束 |
| --- | --- | --- |
| cluster/node | `pve.discover` | 第 4 节 `operationId/phase/nodeRef/cursor/limit`。 |
| node | `task.status` | `upid`，格式必须以 `UPID:<identity.nodeRef>:` 开头。 |
| node | `agent.upgrade` | strict 固定 manifest 制品参数；需要 approval、独立 root helper、重启回验与回滚，详见 `SELF-UPGRADE-V1.md`。 |
| vm | `vm.start`, `vm.shutdown`, `vm.stop`, `vm.reboot` | `parameters` 必须是空对象。 |
| vm | `vm.suspend`, `vm.resume` | QEMU only；空对象；Agent 等待 UPID 并回读 `qmpstatus=paused` 或 running，LXC 明确拒绝。 |
| vm | `vm.create` | `name`, `cores`, `memoryMiB`, `storage`, `diskGiB` 和必填 bool `start`；LXC 必须有 `template`，QEMU 禁止 `template`。 |
| vm | `vm.clone` | `sourceVmid`, `templateRef`, `name`, `target`, `storage`, `sourceConfigSha256` 和必填且只能为 true 的 `full`；执行前重新读取模板基线并校验 SHA-256，Journal 固化 templateRef/sourceVmid 供后续 lineage 使用。 |
| vm | `vm.set-resources` | 可选 `cores/sockets/memoryMiB`，至少一项；实现会读取现值且只允许增加。 |
| vm | `vm.set-initial-resources` | 仅新 clone 首次定型；精确 `cores/sockets/memoryMiB` 加 `cloneOperationId/templateRef/sourceVmid/vmGeneration/templateConfigSha256`，其中 `vmGeneration` 是十进制字符串。当前命令使用独立 operationId，`cloneOperationId` 引用此前成功终态的 clone；本机 durable journal 精确核对 authority、VM identity、generation、template identity 与 SHA，并证明目标从未启动/交付/重装或进入其他代次。PVE 当前须为 stopped non-template；允许低于模板基线，但不构成存量降级入口。等待 UPID 并精确回读。 |
| vm | `vm.migrate-legacy-journal` | 修改类、必须由当前有效 revision 签名审批。常规变体是每个 clone lineage 仅能消费一次的本地恢复动作：只接受一个严格小于当前 revision 且与目标记录 audit 完全一致的 `legacyAssignmentRevision`、一个精确 legacy clone command/operation/digest、固定 templateRef/sourceVmid/source config SHA，以及显式排序的无 UPID indeterminate command ID 列表；命令 envelope 锁定当前 binding/device/epoch/VMID/generation，旧记录的 Agent/audit target/signing key/legacy assignment/resource key 及任何已存在 authority 字段必须一致。另有 `0.1.1-rc.7` 的互斥单事件变体 `recoveryKind=pve-delete-form-body-501-v1`，它硬编码 rc.4 的唯一 DELETE 501 command/operation/digest 与 qemu/100/generation=1，只在 PVE 8.4.0 回读证明 VM 存在且 stopped 后追加退休 marker；不会发送 PVE mutation，也不会扩大可退休错误码。两种变体都绝不删除旧文件；只有 `RetiredByCommandID/RetiredAt` 完整合法、同资源同 authority 的迁移 Journal 已成功终态，且 durable typed result 精确引用旧记录时才释放锁。部分 marker、未完成迁移或结果不匹配继续 fail closed。 |
| vm | `vm.reinstall` | Linux QEMU only；固定 template identity/version/VMID/config SHA-256、独占 temporary VMID、完整最终资源/磁盘 IO/网络/IPFilter/Cloud-Init/OS identity 合同。先建本机完整补偿 clone，再替换并逐项回读；失败恢复或进入 indeterminate。禁止 URL/ISO/shell/任意 guest-exec 参数。 |
| vm | `vm.resize` | `disk`，以及互斥的 grow-only `size`（例如 `+20G`）或绝对 `targetGiB`；绝对目标会先回读当前 `size=`，相等幂等成功、缩容拒绝。 |
| vm | `vm.set-disk-io` | QEMU only；`disk` 与 `limits`。limits 的 10 个 IOPS/MBPS base/max/burst length 键必须全部出现，值为 typed 整数或 null；null 会移除对应受管键，保留 volume/size/cache 等其余配置并使用 PVE digest。 |
| vm | `vm.set-network` | `interface` 及 bridge/model/MAC/VLAN/MTU/firewall/rate/IP/gateway typed 字段。 |
| vm | `vm.set-rate` | `interface`, `rateMbps`；`0` 移除 rate。 |
| vm | `vm.set-cloud-init` | QEMU only；`hostname/username/password/passwordFormat/sshAuthorizedKeys/qgaEnabled`，且 `qgaEnabled=true`。secret 不进入 result/receipt/audit。 |
| vm | `vm.cloud-init-snippet.delete` | Linux QEMU only、修改类且必须审批。exact 参数为 `volume/attachment/deleteUnreferenced`；attachment 只能是 `network`，bool 只能为 true，volume 只能是 `<storage>:snippets/<filename>`。执行前精确证明目标 `cicustom.network` 引用并无任何其他 QEMU/LXC 引用，使用 config digest 只解除 network，再删除一个 URL-encoded storage content；同步或 UPID 终态后均回读目标 config 与 storage。Journal 只保存 storage ID、volume SHA-256 和 `validated → reference_proven → detached → delete_submitted → deleted → verified → succeeded` 阶段，不保存 volume/config/PVE response。成功 result 固定为 `detached/deleted/alreadyAbsent` 三个 bool。 |
| vm | `vm.set-timezone` | QEMU only；IANA `timezone`，固定执行 QGA `timedatectl set-timezone`、兼容解码 PVE 8/9 的 direct 或 `{result:...}` guest-exec/exec-status 数据、等待 exit code 0，并用固定只读 `guest-get-timezone` 回验。未知/null 响应仍失败关闭。 |
| vm | `vm.verify-delivery` | QEMU read-only；`notBefore` 与完整 `expected` 资源/磁盘 IO/多网卡/IPFilter/时区合同。重新读取 PVE config、QGA interfaces/timezone 和 guest firewall；全部匹配才返回 ready。失败时仍只返回固定安全诊断 `{ready:false,observedAt,failedCheck}`；`failedCheck` 是 power/config/disk/QGA/network/firewall/timezone/provider_read 等冻结枚举，不返回原始 PVE/QGA 错误、配置或来宾数据。 |
| vm | `vm.delete` | 必须显式提供 `purge` 与 `destroyUnreferencedDisks`。 |
| vm | `vm.reset-password` | `username/password/crypted/osFamily`；QEMU Linux/Windows/非 root 账户在提交前检查 QGA `guest-set-user-password`；LXC 仅 Linux、`crypted=false`，通过固定 config password 字段重置 root。secret 不进入 receipt/audit/log。 |
| vm | `vm.console.create-session`, `vm.console.revoke-session` | QEMU only；create 仅接受 `ttlSeconds=30..300,webSocket=true`。Agent 在 `tcp4 127.0.0.1:<PVE temporary port>` 内存认证后主动接入固定同源 HMAC WSS broker；secret-free registration 绑定完整 authority/VM generation，receipt 只返回 `sessionRef/state/expiresAt/browserPath`。revoke 只接受 opaque `sessionRef` 并立即关闭本地 socket/WSS。 |
| vm | `snapshot.create` | `name`、必填 bool `includeRam`，可选 `description`；LXC 的 `includeRam` 只能为 false。 |
| vm | `snapshot.delete`, `snapshot.rollback` | `name`。 |
| vm | `snapshot.list`, `snapshot.get` | 只读；list 接受 `limit=1..100`，get 接受 `name`；返回 stable snapshot ID/name/time/state/parent/RAM state 与 decimal-string VM generation。 |
| vm | `backup.create` | `storage`, `mode=snapshot|suspend|stop`, 可选 `compress`。 |
| vm | `backup.delete`, `backup.restore` | `storage`, `volume`；restore 另要求必填 bool `force`。 |
| vm | `backup.list`, `backup.get` | 只读；固定查询签名 `storage` 的 backup content 和当前 VMID；返回 storage/volume/time/decimal-string size/state/guest identity/generation/restorable，不返回路径或凭据。 |
| cluster/node | `firewall.cluster.set-options`, `firewall.node.set-options` | typed 参数仅 `enable`。 |
| vm | `firewall.guest.set-options` | `enable` 必填；可选 `policyIn`/`policyOut`（`ACCEPT`/`DROP`/`REJECT`）与 `macFilter`。旧 `{enable}` payload 保持兼容，未知字段仍拒绝。 |
| vm | `firewall.guest.verify-ipfilter` | 只读；精确回验 cluster、目标 node 与 guest firewall 已启用、cluster 未显式关闭 PVE 8 二层 `ebtables`、guest 策略为 `ACCEPT/ACCEPT`、MACFilter 有效、目标 `netN firewall=1`，并且每个 `ipfilter-netN` 仅包含签名命令声明的正向 `/32`、`/128` host CIDR。`networks[].macAddress` 可选以兼容旧调用；新流程必须提供规范大写、非零单播 MAC，Agent 会同时证明 PVE 当前 QEMU `virtio=<MAC>` 或 LXC `hwaddr=<MAC>` 与签名分配一致。成功结果显式返回 `guestFirewallEnabled`、`policyIn`、`policyOut`、`macFilterEnabled`，以及每张网卡的 `macAddress`、`firewallEnabled`、`ipFilterEnabled`、`ipSet`、`ipFilterCidrs`。可在 guest 停机时执行。 |
| vm | `firewall.guest.verify-ipfilter-sets` | 只读；创建/重装的中间预配置阶段精确回验 guest firewall 与目标全部 `netN firewall` 均关闭，按新请求同时证明每张 `netN` 的规范 MAC，并确认每个 `ipfilter-netN` 仅含签名命令声明的正向 `/32`、`/128` host CIDR。成功结果固定返回 `enforcementState=preconfigured-not-enforcing`，不得解释为防冒用已生效，也不得作为创建/重装最终成功条件。 |
| vm | `firewall.guest.rules.list`, `firewall.guest.rules.get`, `firewall.guest.rules.verify` | 只读。list 仅接受 `{}`；get 接受 `position=0..999`；verify 接受按 position 严格递增的完整 canonical rules 和对应 SHA-256。返回 PVE position/type/action/macro/protocol/ICMP/source/destination/ports/interface/IP version/log/enabled/comment 字段与确定性摘要；未知上游字段、重复位置或摘要/内容不一致均 fail closed。 |
| vm | `firewall.rule.create`, `firewall.rule.update`, `firewall.rule.delete` | typed direction/action/protocol/source/destination/port/position 等；不接受规则文本。 |
| vm | `firewall.ipset.create`, `firewall.ipset.update`, `firewall.ipset.delete` | `name` 与可选 `comment`。 |
| vm | `firewall.ipset.entry.create` | `name`, `cidr`、必填 bool `noSubnet`，可选 `comment`。 |
| vm | `firewall.ipset.entry.update` | `name`, `cidr`，以及可选 `comment/noSubnet`；后两者至少提供一项，固定 PUT 到该 guest IPSet entry。 |
| vm | `firewall.ipset.entry.delete` | `name`, `cidr`，固定 DELETE 该 guest IPSet entry。 |

### 7.1 安全删除 legacy Cloud-Init network snippet

`vm.cloud-init-snippet.delete` 的 parameters 是 exact object；未知字段、重复字段、缺字段、false 或其他 attachment 全部拒绝：

```json
{
  "volume": "local:snippets/example.yaml",
  "attachment": "network",
  "deleteUnreferenced": true
}
```

volume 只接受 canonical `<storage>:snippets/<filename>`；filename 不能为空、`.`、`..`、隐藏/绝对/分层路径，不能含反斜线、重复斜线、percent、NUL、控制字符或非受限文件名字节。node、VMID、guest type、generation 和全部 authority 只取自签名 envelope。目标必须是明确的 Linux QEMU（当前 PVE `ostype=l24|l26`）；LXC 与 Windows 拒绝，但全 cluster 引用证明仍逐个读取 QEMU/LXC config，任何读取错误、未知 guest 行、重复资源、畸形 `cicustom` 或未找到目标都会 fail closed。

成功 result 也是 exact object：

```json
{
  "detached": true,
  "deleted": true,
  "alreadyAbsent": false
}
```

首次完整执行固定 `alreadyAbsent=false`。只有同一 durable command 已推进到 detach/delete 恢复点，且当前 config 与 storage 双回读均 absent 时才可为 true。同步和异步路径都不把 volume、路径、`cicustom`、PVE response 或原始 UPID返回给官网；监控审计仍只含既有 action/typed target/outcome/digest 白名单。跨语言字节向量固定在 `internal/control/testdata/agent-v1-vm-cloud-init-snippet-delete.json` 和 `internal/control/testdata/agent-v1-vm-cloud-init-snippet-delete-result.json`。

稳定失败分类为 `CLOUD_INIT_SNIPPET_VOLUME_INVALID`、`CLOUD_INIT_SNIPPET_REFERENCE_MISMATCH`、`CLOUD_INIT_SNIPPET_SHARED`、`CLOUD_INIT_SNIPPET_SCAN_INCOMPLETE`、`CLOUD_INIT_SNIPPET_CONFIG_CONFLICT`、`CLOUD_INIT_SNIPPET_DELETE_FAILED`、`CLOUD_INIT_SNIPPET_DELETE_INDETERMINATE` 与 `CLOUD_INIT_SNIPPET_VERIFY_FAILED`。错误正文不投影上游响应、volume 或配置。

`firewall.guest.verify-ipfilter-sets` 的请求与成功结果由
`internal/control/testdata/agent-v1-firewall-verify-ipfilter-sets.json` 和
`internal/control/testdata/agent-v1-firewall-verify-ipfilter-sets-result.json`
锁定。每张 NIC 都必须出现且 `interface` 唯一；CIDR 必须是 canonical `/32` 或 `/128` host，未知字段、缺失/额外/negative IPSet entry、guest firewall 已开或任一 NIC firewall 已开都会失败。该动作不读取 cluster firewall，也不执行写操作。

创建/重装最终启用宿主商 IP/MAC 反冒用基线后的 `firewall.guest.verify-ipfilter` 请求与成功结果另由
`internal/control/testdata/agent-v1-firewall-verify-ipfilter.json` 和
`internal/control/testdata/agent-v1-firewall-verify-ipfilter-result.json`
锁定。新官网流程的两种回验都必须携带每张 NIC 的 `macAddress`；旧调用省略该字段时，Agent 为协议兼容不会在结果中添加该字段。

当前共有 54 个 known actions，一致性测试会枚举并锁住 registry、strict parameter validator、Executor dispatch 与 fixture，避免出现“协议允许但执行分支缺失”。动作原语存在也不表示 storage/template/archive/snapshot/snippet 的业务授权集合、审批 UI 或官网路由已经完成。`agent.upgrade` 是 node scope mutation，严格参数、manifest、root helper、回验/回滚合同见 `SELF-UPGRADE-V1.md`；它不能接收任意 URL/命令，也不能复用本地模板 helper。新增 provisioning action 与安全 snippet 删除的 exact JSON shape、回执及服务端接入边界见本节和 `PROVISIONING-ACTIONS-V1.md`。

## 8. NIC 角色、IP 切换、防盗用与 QGA capability

### 8.1 typed NIC binding

每个受管 NIC 必须用 `interface=netN` 作稳定键，不能只保存数组下标或依赖排序。向导支持 `public`、`private` 两种 role；`monitoring` 可独立选择，但计费规则固定为 public `metered=true`、private `metered=false`。当前 strict assignment 的持久产物如下：

```json
{
  "interface": "net0",
  "role": "public",
  "primary": true,
  "metered": true,
  "monitoring": true,
  "expectedMac": "02:00:00:00:01:01",
  "bridge": "vmbr0",
  "vnet": "",
  "vlan": 100,
  "mtu": 1500,
  "ipFilterPolicy": "required"
}
```

约束：

- `interface` 必须是 `net0`..`net31`；`role` 为 `public|private`；public 必须 `metered=true`、private 必须 `metered=false`；同一 guest 的 `interface` 唯一；非空列表必须恰有一个 primary public NIC 和一个 monitoring NIC；
- `bridge`/`vnet` 必须恰有一个非空，并且来自已确认的 node network/cluster SDN 候选；
- `expectedMac` 必须是 canonical、非零、unicast 48-bit MAC；可选 VLAN 为 0..4094，可选 MTU 为 576..9216，并与实际 PVE config 回读一致；
- `ipFilterPolicy` 至少明确 `required|disabled`，不能以字段缺失表示策略；公网/计费 NIC 的 disabled 必须由显式审批决定；
- website inventory 是 role/policy 权威，Agent assignment 应签发同一 `nicBindings`，防止命令和计量使用过期映射。

`internal/inventory.Assignment` 已包含并严格验证 `nicBindings`；`observation.Network` 也为 PVE config 提供稳定 `interface=netN`、MAC、attachment、VLAN、MTU 和 NIC firewall 等回读字段。website telemetry 按 interface 关联 observed network 与 signed binding，输出 `policyMatch{supported,reason,source}`；稳定 mismatch reason 包括 `binding_missing`、`interface_missing`、`mac_mismatch`、`attachment_mismatch`、`vlan_mismatch`、`mtu_mismatch`、`nic_firewall_disabled`。这只证明 Agent schema/回读信号已实现；官网向导的编辑、签发和 APP 呈现仍待远端合并。`policyMatch` 也不能替代对 `ipfilter-netN` 条目和 firewall rule 的操作级回读。

PVE status 的 guest `netin/netout` 不再用于 mixed-NIC 正式计费。Agent 按 signed assignment 的稳定 `netN + canonical MAC + VM generation` 关联 PVE config，再从宿主机 `tap<vmid>i<n>`（QEMU）或 `veth<vmid>i<n>`（LXC）的 node exporter uint64 累计计数生成 `source=pve-host-netdev` 事件。仅 `role=public,metered=true` 的 NIC 会产生逐网卡计量事件；`role=private` 必须 `metered=false` 且完全不进入客户流量。缺失/错配 NIC、MAC 或 host counter 时不伪造逐网卡数据；旧 aggregate 仅保留 source-labelled shadow fallback。counter 下降、generation/MAC/source 改变会生成新 `counterEpoch`，服务端据此处理重启、热插拔、回绕和跨月账期。QGA per-interface stats 仍只供观测和诊断，永远不能升级为权威计费来源。

### 8.2 IP 切换与 IPFilter

`vm.set-network` 只修改已存在的 `net0`..`net31`。支持：

- QEMU model `virtio/e1000/e1000e/vmxnet3/rtl8139`，QEMU/LXC 固定 MAC；
- bridge、VLAN tag 0..4094、MTU 576..9216、NIC firewall 和 rate；
- IPv4 static CIDR/`dhcp`/`manual`，IPv6 static CIDR/`auto`/`dhcp`/`manual`，以及 gateway。

QEMU 的 IP/gateway 写入与 `netN` 对应的 `ipconfigN`；LXC 写入 `netN` 的 `ip/ip6/gw/gw6`。代码会保留未被本次 typed 参数替换的 NIC 字段，并在可用时提交 PVE config digest。QEMU `ipconfigN` 是 Cloud-Init 配置，不保证客户 OS 热更新；网站不能在 PUT 返回后立即声称换 IP 成功。

一次 IP 切换必须共用一个 `operationId`：IPAM 预留新 IP → 更新固定 MAC/VLAN/MTU/NIC/`ipconfigN` → 更新 `ipfilter-netN` → 启用 guest/NIC firewall 与 IPFilter → 等待必要的 reboot/guest 网络就绪 → 回读/探测 → 提交 IPAM 并释放旧 IP。失败时保留旧租约并进入补偿/人工处理，不能静默释放。

PVE 的 anti-spoof/IPFilter 组合契约是：guest IPSet 使用精确名称 `ipfilter-netN`；IP 切换先用 `firewall.ipset.entry.create` 加入新 CIDR，`entry.update` 只更新同一 CIDR 的 comment/`noSubnet`，验证成功后才用 `entry.delete` 删除旧 CIDR。`ipfilter-netN` 是 PVE 标准命名约定，不是 `/firewall/options` 的可写字段。创建/重装过程中可以用只读 `firewall.guest.verify-ipfilter-sets` 证明集合精确但 enforcement 尚未启用；它只是中间态。最终交付前，NIC 自身必须 `firewall=true`，guest firewall 用 `firewall.guest.set-options` 启用并固定 `policyIn=ACCEPT`、`policyOut=ACCEPT`、`macFilter=true`；这样默认启用宿主商 IP/MAC 防伪造，但不添加任何端口 `DROP`/`REJECT` 规则，不限制客户业务端口。启动 guest 前必须用只读 `firewall.guest.verify-ipfilter` 精确回验以上策略、签名 MAC 和集合，相关 cluster/node firewall 仍按审批启用。客户控制台的端口规则防火墙状态必须与此宿主商反冒用基线分别存储和展示；关闭客户规则不得关闭反冒用基线。官网必须计算期望 digest、防止自锁并回读；Agent 没有一个可绕过逐步持久化编排的“防盗用”复合写动作。

Firewall discovery 始终显式投影有效 `options.enable`。PVE API 对仍处于默认值的 option 可能省略字段，而各 scope 的缺省值并不相同：cluster master=`0`、node host firewall=`1`、guest=`0`。Agent 必须按 scope 补齐该有效值；显式值若不是 `0|1` 则以读取错误拒绝，官网不得把缺失值统一解释为关闭。启用 cluster master 前必须单独证明 node host firewall 不会阻断 SSH/API/Agent 管理通道。

### 8.3 QGA availability 与依赖动作

Agent telemetry 已区分 `qga.availability.available`、`observedAt`、`freshUntil` 和 `unavailableReason`，并列出各 QGA read capability。APP 必须展示 availability 和 freshness，不能只显示最后一次成功结果，也不能把“已安装但已停止”和新鲜可用混为一谈。

QEMU 的 `vm.reset-password`、`vm.set-timezone`、`vm.verify-delivery` 与重装最终回验依赖 QGA。新启动来宾的 `vm.set-timezone` 在首次 capability unavailable 后有固定 60 秒、每 2 秒一次的有界启动宽限期，并为 90 秒命令租约保留回执余量；宽限期结束仍不可用、QGA 被卸载/停止、对应命令未支持或 freshness 过期时，这些步骤必须冻结/拒绝并显示 capability unavailable，不得把 PVE/QGA 错误伪装成成功。`vm.start`、`vm.shutdown`、`vm.stop`、`vm.reboot` 等纯 PVE 生命周期动作不依赖 QGA，应继续可用。LXC root password 使用 PVE 固定 config password 字段，不经过 QGA；Windows 和 QEMU 非 root 账户仍走 typed QGA password API。

website guest telemetry 已携带 QGA availability/freshness，并输出 `capabilities.lifecycle/rootPasswordReset/guestNetworkVerify/metering`。QGA 缺失或过期会让依赖 capability unavailable，lifecycle 保持 available；capability 带 `observedAt/freshUntil/reason/executionPreflight`。Executor 已在 `vm.reset-password` 提交前只读查询 PVE QGA `agent/info` 并检查 `guest-set-user-password`；APP 消费/展示和 operation 中的 guest-network verify 仍属于远端待合并项。

## 9. VPS 升级接口的准确状态

Agent 已实现可组成升级的资源原语：`vm.set-resources`（CPU/socket/内存只增）、`vm.resize`（磁盘只增）、`vm.set-rate` 和 `vm.set-network`，且 registry/validator/Executor 的逐动作一致性测试已覆盖。生产开放仍须逐产品动作完成服务端编排、审批、回读和 rollout；这些原语是独立命令，不是已上线的“VPS 无缝升级 API”。当前没有单一 action 可以原子完成付款、套餐变更、磁盘 I/O 策略、带宽、回读和订阅结算。

官网新 Agent 升级路由的 feature flag 必须默认关闭。旧客户升级路由继续运行，直到新流程完成端到端验收；文档、UI 和发布说明不得宣称 Agent 升级已上线。目标 Saga 应由官网持久化，例如：

```text
payment_authorized
  -> vm.set-resources
  -> vm.resize（需要时）
  -> vm.set-rate / vm.set-network（需要时）
  -> read_back_and_verify
  -> website_finalize_subscription
```

每一步使用独立 `commandId`、共享 `operationId`。只有全部 PVE 终态成功且回读一致后才能提交套餐；失败不得提前改账。磁盘不支持缩容，当前 `vm.set-resources` 也拒绝 CPU/socket/内存减少。

## 10. 迁移顺序

1. 官网实现并验收一次性 bind、五组 endpoint-specific 凭据、assignment 签名/防回滚和 Ed25519 command signing；upgrade route feature flag 保持关闭。
2. 节点运行本地 Token bootstrap 和官网绑定；官网不接收任何 PVE endpoint/Token。
3. 接通多轮 discovery，仅做读取；networks 后保存 typed NIC binding，完成多 NIC metering capability 与 QGA capability 检查，再进入 readiness。firewall bootstrap 使用独立审批命令。
4. 接通 inventory/runtime/traffic 的 shadow 与 read-back，对账旧来源。
5. 修改命令 cutover 前完成 monitoring 独立绑定、audit durable outbox 和服务端/UI 验收；官网同时实现 Agent 离线命令持久队列，且明确禁止因 Agent/官网离线回退直连 PVE。随后先按资产迁移低风险生命周期，再迁移 create/upgrade/IP/password/firewall/snapshot/backup。每次 cutover 保证新旧写路径互斥。
6. 所有资产完成显式 cutover 后，关闭其旧官网 PVE 直连。最后才移除旧客户升级兼容路由。
7. monitoring telemetry 可按独立里程碑上线且不得借官网 credential；但 monitoring audit availability 是所有修改命令（含 dry-run）的强制门槛。它不阻止官网绑定、只读 discovery 或 shadow 对账，却必须阻止尚未具备审计闭环的 mutation cutover。

## 11. 实现状态与上线门槛

| 能力 | 当前代码事实 | 对外状态 |
| --- | --- | --- |
| PVE 本地专用 Token / prepare | installer 以 root-only `0700` 安装固定 helper；bind/`ag-pve pve prepare` 在读取 code 前创建或读取独立 read/control Token，自动授予并回读 dedicated VPS-control role 的 `/` 固定权限、启用固定 loopback exporter，验证 version/permissions/node，切换 production/api，受控重启并等待真实采集成功。 | 已实现真实数据 readiness、旧 exporter 配置迁移和 control ACL 自动准备；官网+monitoring 双绑定稳定且 device identity 一致后自动打开 `productionExecution`。已绑定旧节点可单独运行 prepare，无需重新绑定。完全卸载会撤销专用 identity/ACL。 |
| 安装发布物 | tag `vX.Y.Z` release workflow 已分别构建 Linux amd64/arm64、运行 Go/packaging 测试，并用 `scripts/package-release.sh` 生成离线、可复现 tarball 和 `SHA256SUMS`；脚本只打包已构建 binary 与显式 allowlist 内容、二次验证 bundle，拒绝网络下载、symlink、secret/queue material 和输出覆盖。manual dispatch 只生成 artifact，不发布。installer 继续校验包内 binary SHA-256、cloud-init bundle、依赖、权限、systemd unit 和 assignment 迁移。 | 发布物应先离线校验 `SHA256SUMS` 再解压，不能 `curl | bash`。当前 workflow 的完整性机制是 SHA-256；如需发布签名/来源审批，仍须由组织发布流程另行完成。 |
| 官网 bind / networkPolicy | `internal/enrollment`、`internal/bindstate`、运行时 private-state credential overlay、exact `networkPolicy={agentObservedIPv4}` strict decoder/persistence 及 `ag-pve bind` 已有实现；绑定码不进 argv，Agent 使用 hostname + tcp4 direct dial。绑定前完成真实 PVE prepare；签发后使用 pending/commit marker 恢复，绝不退回可能已撤销的旧凭据。 | 真实 PVE read readiness 与绑定自动生效已接线；官网可信来源 IPv4/32 冻结、轮换与 endpoint 部署仍需官网任务完成，不能仅凭 Agent 代码称已上线。 |
| assignment | `internal/assignment` 已有 HMAC `wait<=25s`、Ed25519 bundle 验签、revision/cursor 防回滚；runtime 主循环已接客户端并原子保存 assignment/cursor，安装器已接 service-owned 路径与 legacy 首次迁移。 | Agent 侧读写/权限闭环已接；官网服务仍需联调，不能据此宣称服务已上线。 |
| discovery | `internal/discovery` 和 `pve.discover` Executor 分支已有 typed phase、分页与安全错误码；API 模式 runtime 已注入本地 PVE read client/Discovery。 | 仍须在 PVE 8/9 fixture 和真实非生产节点验收，不等于官网向导已上线。 |
| 本地模板 bootstrap | cloud-init bundle 已在同一 Agent 包的 `bundles/ppflight-cloudinit` 落仓；installer 验证依赖/两次校验 bundle、strict IPv4/HTTPS redirect policy 并原子切换版本 symlink；`internal/templatebootstrap` 每次调用复验 manifest/运行文件摘要并用隔离 Python 入口执行，`ag-pve template init|catalog|discover|bootstrap` 已接本地 plan/显式确认流程。 | 不在远程 action registry；真实 PVE 上创建模板/备份的 plan/execute 破坏性验收完成前不可称模板业务上线，更不等于 `vm.reinstall`。 |
| command 长轮询 | control client 支持 signed `after+limit` 轮询。 | `wait` 尚未发送；长轮询是目标而非现状。 |
| 操作线程/UPID | command/receipt 含 `operationId`；journal 保存 submitted/waiting UPID，runtime 在 command cycle 前后调用 reconcile 并查询原 UPID。 | Agent 与官网端到端恢复矩阵通过前不得称生产就绪。 |
| watchdog/previousExit | systemd notify/watchdog、请求级采集 progress deadline、自动重启所需 unit 设置、`lifecycle-state.json` 和按 destination 启用的 website/monitoring 不可淘汰 lifecycle outbox 已实现并有 Linux/重启测试；未启用域保持 pending。 | 这是本地恢复与补报原语，不是远端 SLA；官网/监控接收、展示/告警以及真实故障演练仍需验收。 |
| Agent 离线命令 | Agent 主动 poll、领取后的 journal/UPID/receipt durable recovery 已实现。 | 官网持久离线命令队列与 command `wait` 尚待实现/联调；任何离线场景都禁止自动回退官网直连 PVE。 |
| 固定动作 Executor | 第 7 节 54 个 known actions 的 registry/validator/dispatch/fixture 已有 AST 一致性测试，生产 mutation 要求 approval；新增合同见 `PROVISIONING-ACTIONS-V1.md`。 | 只是 Agent 原语；`agent.upgrade`、重装、console、snippet 删除等仍需独立产品 rollout 与真实 PVE 验收，业务 flag 默认关闭。 |
| VPS 升级/IP Saga | 资源、网络、IPFilter/firewall 原语存在。 | 复合编排、回读、IPAM/账务提交未因这些原语自动完成。 |
| NIC role/多 NIC 计费 | strict `nicBindings`、PVE config policy matching 与 signed netN/MAC/generation 到宿主 tap/veth counter 的逐公网 NIC 计量已实现；private NIC 不计费。 | 官网向导/assignment 签发与账本消费仍待远端合并；多 NIC guest aggregate 永远不能 active。 |
| QGA 展示/门禁 | telemetry 已输出 availability/freshness 和四类 guest capability；Executor 在 QEMU password reset 前做 QGA command capability 读取。 | APP freshness/capability 展示与组合流程的 guest-network verify 仍待远端合并；QGA stats 不作计费。 |
| 监控站绑定 / networkPolicy | `internal/monitorenrollment`、独立 pending/state/`networkPolicy`、运行时 credential overlay、自动可信 PVE 版本发现、写后严格回验、systemd 自动重启与本地 binding ID/epoch 加载确认、签发后 fail-closed 同码恢复、`sentAt`、持久 monitoring sequence 和 uploader tcp4 pinning 已实现；官网 bind/replace 不触碰它。 | 仍需在真实 PVE 8/9 对新绑定/轮换及服务端 ingest 做联调；不可仅凭本仓 Agent 能力宣称全部生产链路已验收。 |
| 双绑定状态 | website/monitoring strict status clients 与 `ag-pve ... status` 已实现固定同源 HMAC GET、identity/epoch/revision/time 回钉、IPv4/no-proxy/no-redirect；scope 由服务端逐路由固定。 | 外部 `/internal/v1/agents/status` 与 `/internal/v1/monitoring/agents/status` 服务仍待交付；本地 CLI 存在不等于远端状态服务已上线。 |
| 修改命令审计 | `internal/auditlog` 已有严格 wire/builder，control journal 持久化脱敏 context/event，`store.Audit` 是独立、不可淘汰 outbox；runtime 已把 monitoring binding、audit queue/sink、独立 sequence 与 HMAC uploader 接通，并在 monitoring telemetry 暴露 bounded `agentHealth.auditQueue`。正反/golden 测试覆盖最终字段。 | Agent 侧已接线；监控服务端 durable 存储、幂等与可查询 UI 由另一任务实现。端到端验收前 production 修改动作不得开放。 |
| IPv4/mutual whitelist | `internal/netpolicy` 已把 enrollment、assignment、control、uploader、PVE、exporter 与管理探测统一为 `tcp4`，拒绝 IPv6 literal；clients 禁 ambient proxy/重定向并校验绑定 origin，PVE 配置目标为 `127.0.0.1`。 | IPv4-only 已接；website/monitoring 各自的服务端 source-IP allow set、Agent 目标 IPv4 pin/轮换和端到端任务门槛仍需实现/联调。`mutual-whitelist-v1` capability 不能当作已上线证据。 |

上线前至少需要：官网 API 与事务语义完成；command `wait` 接线；assignment refresh 官网服务联调完成；discovery/UPID 恢复在 PVE 8/9 fixture 和真实非生产节点通过；修改动作的独立 monitoring audit outbox、审批、互斥、read-back、审计查询和回滚全部验收。当前尚未完成真实 PVE 上 mutation 与模板 execute 的破坏性发布验收。升级业务还必须按资源验收并显式开启 upgrade route feature flag。
