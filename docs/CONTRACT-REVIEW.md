# PPFlight Agent v0.1 — 架构、安全与接口契约审查（历史设计输入）

> **非规范文档：** 本文件保留早期独立审查思路，其中的 `sample` 模式、`assetRef`、`pveClusterRef`、`/api/agent/v1/*` 路径、RFC3339 请求签名时间戳和 `guest.*` 动作名没有被最终 v0.1 采用。实现与联调唯一规范是 [API.md](API.md)：仅有 `test|production`，身份字段为 `serviceRef|clusterRef`，端点为 `/internal/v1/*`，请求签名时间戳为 Unix 秒，动作名为 `vm.*`。出现冲突时一律以 API.md、配置校验和协议测试向量为准。

状态：**开发前冻结建议**（2026-08-29）。本文是给 Agent、官网和监控
Control Plane 实现者共同使用的契约；没有在现有代码中实现的端点会明确标为
`待实现`，不能被 README 写成“已经可用”。

## 1. 已核实的当前事实

1. 现有监控 Control Plane 的 `POST /api/ingest` 已可用，认证是
   `Authorization: Bearer <COLLECTOR_TOKEN>`。它接收 `schemaVersion: 1` 的
   Collector envelope，并以 `(collector.id, bootId, sequence)` 和 `batchId`
   做批次幂等。
2. 该端点返回 `202`（成功、重复、序列冲突或过期快照），处理中返回
   `503` + `Retry-After: 5`，认证失败为 `401`，无效输入为 `400`。单个
   envelope 最大 5,000 条记录；未来时间最多允许 2 分钟并会被归一化。
3. 现有 Control Plane 在 ingest 时会调用 `updateTrafficPeriods()`，但它只有
   通用的 PVE VM 累计 `networkRxBytes/networkTxBytes`，没有来源字段、切换点、
   VMID generation 或单独的计费 API。因此它**不能**在没有后端改造前成为
   Agent 的计费权威写入通道。
4. 现有 Collector 的 Proxmox 采集使用 `/api2/json/cluster/resources`，再尽力
   读取 `/nodes/{node}/status`；它的默认周期是 30 秒，并把 PVE 的 `netin`
   / `netout` 当 VM 累计字节数。它不采集 QGA。
5. 官网目前仍直接调用 Proxmox API 完成创建、重装、密码和配置类管理。v0.1
   必须保持这个路径可用；Agent 控制器是并行能力，不得暗中接管官网的动作。

以上结论来自本仓库的
`control-plane/app/api/ingest/route.ts`、`control-plane/lib/contracts.ts`、
`control-plane/lib/traffic-engine.ts`、`collector/lib/proxmox.mjs` 和
`collector/server.mjs`。

## 2. 责任边界与运行模式

```text
PVE 8/9 节点
  ppflight-agent
    ├─ PVE 只读采集：库存、状态、资源、PVE VM 网络累计计数
    ├─ QGA 增强采集：来宾 OS / 文件系统 / IP（仅可用时）
    ├─ exporter 采集：127.0.0.1:9100、127.0.0.1:9633（可选）
    ├─ Meter spool -> 官网计费 API（待实现）
    ├─ Monitor spool -> 监控 ingest API
    └─ Executor <- 官网签名命令（默认启用；sample/test 一律 dry-run）

官网
  ├─ 业务/库存/客户授权/账期与计费权威
  ├─ 现有直连 PVE API 控制路径（v0.1 保留）
  └─ 未来可选择向 Agent 发控制命令，而不是由 Agent 自行决定动作
```

`control.enabled` 的默认值为 `true`，以符合“全功能 Agent”的部署预期；这
**不等于**默认对生产 PVE 执行写操作。默认安装配置必须是
`execution.mode: sample`，其中 Executor 验证、审计并回执命令，但绝不建立到
PVE 的变更请求。只有操作者把模式显式切换为 `production`，并配置单独的
Executor 凭据后，才可真正执行。

模式是全局的、持久化的，并且每条命令回执必须包含 `executionMode` 与
`dryRun`，以免测试结果被误当作实际完成。

| 模式 | 采集/上报 | 接收控制命令 | PVE 写操作 | 计费写入 |
| --- | --- | --- | --- | --- |
| `sample`（默认） | 模拟或真实采集均可，标记 `sample` | 是 | **禁止，回 `DRY_RUN`** | **禁止** |
| `test` | 真实端点可连通，但所有业务资产须为 allowlist | **禁止，回 `TEST_MODE_BLOCKED`** | 禁止 | 只允许 `shadow` |
| `production` | 是 | 是 | 仅已授权、已签名、未过期、未执行过的白名单命令 | 仅已切换到 `active` 的资产 |

`sample` 和 `test` 都不能以“下游忽略”为理由发送可计费数据。Agent 本身要
阻断；官网仍必须二次阻断，形成双保险。

## 3. 身份、来源与数据字段

### 3.1 不能只用 VMID

VMID 可在删除后被复用，且不同集群可重复。计费或控制对象的不可变键必须是：

```json
{
  "assetRef": "官网业务资产的 UUID",
  "pveClusterRef": "官网登记的 PVE/集群 UUID",
  "vmid": 101,
  "generation": 3,
  "guestType": "qemu"
}
```

`assetRef + generation` 是官网颁发的生命周期身份：创建/克隆时官网递增或新建
generation，删除后永不重新绑定；迁移节点不改变 generation。Agent 只能从已签名
库存映射读取它，不能用“同 VMID 又出现”自行推断同一客户或同一账单。若 PVE
可见资源没有对应映射，仍可监控为 `unmanaged`，但不得发 Metering 样本或执行
客户命令。VMID 复用、映射变更、集群/guestType 不符均产生 `VM_GENERATION_MISMATCH`
告警并停止此资产的计费。

### 3.2 PVE 与 QGA 的双来源规则

每个字段带 `source`、`observedAt`、`freshUntil`、`available` 和可选
`unavailableReason`；不使用零值冒充“没有数据”。

| 字段组 | 权威来源 | QGA 的作用 | 规则 |
| --- | --- | --- | --- |
| `vmid`、guest 类型、节点、运行状态、vCPU/内存限制、PVE 网络累计字节、宿主 CPU/内存 | `pve` | 无 | QGA 永远不得覆盖。PVE 网络计数是 v0.1 VM 计费的唯一候选。 |
| guest OS、hostname、guest IP、文件系统容量/使用量 | `qga`（若可用） | 提供增强显示 | QGA 不可用时字段为 unavailable，监控不降级为“0”。 |
| guest 内存 | `pve` 用于资源使用；`qga` 仅作 guest 视角补充 | 可同时显示 | 两者字段名必须不同，例如 `pveMemoryUsedBytes`、`guestMemoryUsedBytes`。 |
| 宿主 CPU/内存/磁盘/S.M.A.R.T. | PVE 或本地 exporter | 无 | 不参与客户流量计费。 |

QGA 仅对 QEMU VM 尝试；LXC 不应被标记为“QGA 故障”。对 QEMU，先探测 agent
状态，再按能力读取 `info`、`get-osinfo`、`get-fsinfo`、`network-get-interfaces`。
禁止使用 QGA 的 guest exec/密码/文件读写接口做“采集”。`403/404/501` 是该能力
不可用或权限不足，不是 VM 下线；记录 reason 后指数退避重试。

### 3.3 时间、计数器与顺序

* `observedAt` 是采集完成时的 UTC RFC3339 时间；`sentAt` 是发送时间。两者都
  不能由服务端时钟替代保存。
* PVE `netin/netout` 等累计计数用十进制字符串，不能先转 JavaScript/JSON 浮点数。
  字段分别是 `rxBytesTotal`、`txBytesTotal`，绝不上传 Agent 自算的“累计计费值”。
* `bootId` 在 Agent 进程启动时生成并持久化到当前运行世代；`sequence` 每个
  `bootId` 单调递增，未发送 batch 重启后仍保留原 batchId/sequence。每条样本另有
  `sampleId`（UUID）和严格递增 `sampleSequence`。
* Server 按 `assetRef + generation + source + observedAt/sampleSequence` 去重并按
  观测时间处理。乱序旧样本只可用于监控历史，不得回滚最新快照或重新结算账期。

## 4. 官网 API 契约

### 4.1 现有监控 ingest（已实现，兼容桥）

`POST /api/ingest` 可继续承载 v0.1 监控 bridge，但只使用其现有的 Bearer Token
认证和 `CollectorEnvelope schemaVersion: 1` 字段。Agent 必须按现有 5,000 记录
限制分批，且**不能**把一个有 reconciliation 语义的完整 PVE 快照拆成不完整快照。
成功或重复的 `202` 才能确认删除本地 spool 文件；`503` 与网络错误保留原 batch
并退避重试。该路径不被视为 Metering API。

为支持 PVE/QGA 新字段，建议新建下列 API，待官网实现后改为主路径：

```text
POST /api/agent/v1/monitoring/ingest       # 待实现
POST /api/agent/v1/metering/batches        # 待实现，独立账务事务
GET  /api/agent/v1/control/commands?after= # 待实现，长轮询/短轮询均可
POST /api/agent/v1/control/receipts        # 待实现
GET  /api/agent/v1/inventory               # 待实现，返回受签名保护的 asset 映射
```

新 `/v1` 端点不可复用单一 `COLLECTOR_TOKEN` 作为万能权限。每个 Agent 发放独立
`keyId` 和密钥，密钥角色至少分为 `monitor.write`、`metering.write`、
`control.read`、`control.receipt`、`inventory.read`；权限应按 PVE/站点范围约束。

### 4.2 所有新 v1 请求的 HMAC 与 TLS

TLS 1.2+、证书链/SAN 验证为强制要求；生产配置不允许明文 HTTP，也不允许
`InsecureSkipVerify`。首次安装通过受控配置/固定 CA 完成信任根分发，不允许 Agent
接受网页任意下发的 CA 或 URL。请求最多 10 MiB（monitor 可再设更低），响应最多
1 MiB，连接/总超时应为 5 秒/15 秒并禁用跨主机重定向。

每个 v1 请求必须有：

```text
X-PPFlight-Key-Id: agent-pve-01
X-PPFlight-Timestamp: 2026-08-29T15:04:05Z
X-PPFlight-Nonce: UUID
X-PPFlight-Content-SHA256: lowercase-hex(sha256(raw-body))
X-PPFlight-Signature: lowercase-hex(hmac-sha256(secret, canonical-request))
```

`canonical-request` 是严格 UTF-8 的：

```text
METHOD + "\n" + PATH_WITH_QUERY + "\n" + KEY_ID + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + CONTENT_SHA256
```

服务端允许 ±300 秒时钟漂移，并对 `(keyId, nonce)` 保留至少 10 分钟以拒绝重放。
签名覆盖原始 body，而不是重新序列化 JSON。签名/时间/nonce 失败时不得泄露“哪一项
正确”。Meter、Monitor、命令回执和库存响应均使用该格式；控制命令本体还需要官网
命令签名（见第 6 节），两层签名不能互相替代。

### 4.3 监控 ingest v1（待实现）

最小请求：

```json
{
  "schemaVersion": 1,
  "batchId": "018...",
  "agentId": "pve-01-agent",
  "bootId": "018...",
  "sequence": 42,
  "observedAt": "2026-08-29T15:04:05.123Z",
  "mode": "production",
  "snapshots": [{
    "identity": {"assetRef":"...","pveClusterRef":"...","vmid":101,"generation":3,"guestType":"qemu"},
    "pve": {"available":true,"observedAt":"...","status":"running","node":"pve-01","rxBytesTotal":"123","txBytesTotal":"456"},
    "qga": {"available":false,"unavailableReason":"guest-agent-not-running"}
  }]
}
```

默认周期：PVE inventory/resource 每 30 秒；QGA 成功数据每 60 秒（失败退避至 5
分钟）；node exporter 每 15 秒；SMART 每 5 分钟。发送可批量（每 10 秒或累积
100 条），但每个原始 sample 保留其 `observedAt`。这类周期是监控目标，不能用来
提高客户流量账单精度的承诺。

### 4.4 Metering batches v1（待实现，权威边界）

Metering 与监控批次使用**不同 endpoint、spool、密钥、幂等表和保留策略**。只接受
`mode: production`、`billingState: active` 的映射资产。请求包含：

```json
{
  "schemaVersion": 1,
  "batchId": "018...",
  "agentId": "pve-01-agent",
  "bootId": "018...",
  "sequence": 42,
  "billingState": "shadow|active",
  "samples": [{
    "sampleId":"018...",
    "identity":{"assetRef":"...","pveClusterRef":"...","vmid":101,"generation":3,"guestType":"qemu"},
    "source":"pve-cluster-resources",
    "observedAt":"2026-08-29T15:04:05.123Z",
    "rxBytesTotal":"123456789012",
    "txBytesTotal":"987654321098",
    "counterEpoch":"pve-boot-or-agent-observed-epoch"
  }]
}
```

Agent 发送绝对 PVE 计数；官网以持久的上一个已接受基线计算增量。负差、VM
generation 改变或 `counterEpoch` 改变均创建新基线，增量为零，绝不把回绕/重启值
当作客户使用量。官网响应必须对每个 `sampleId` 标注 `accepted`、`duplicate`、
`baseline`、`shadow`、`rejected`，Agent 只有全部终态成功才删除 batch。

**切换（cutover）流程：**

1. `shadow` 至少运行一个完整账期边界前的对比窗口；官网仅展示与旧计量源的差异，
   不计费、不限速。
2. 运营者为每个 `assetRef + generation` 设置不可回退的 `cutoverAt` 和
   `meteringAuthority: agent`，官网以签名库存映射发给 Agent。
3. `cutoverAt` 后 Agent 的**第一条**样本只能建立基线，不能结算历史差额；第二条
   且后续单调计数才产生计费用量。旧来源在同一精确时刻停止写该资产。
4. 若资产、generation、来源或时间窗重叠，官网返回 `METER_SOURCE_CONFLICT`；
   Agent 停止 active 上报并告警，不自行选择胜者。

### 4.5 标准错误语义

所有 v1 错误 body 使用：

```json
{"error":{"code":"METER_SOURCE_CONFLICT","message":"safe operator message","retryable":false,"requestId":"..."}}
```

| HTTP | code 示例 | Agent 行为 |
| --- | --- | --- |
| 200/202 | `ACCEPTED`、`DUPLICATE`、`BASELINE_RECORDED`、`DRY_RUN` | 终态；删除对应 spool（`DRY_RUN` 只删控制命令，不删计费数据）。 |
| 400/422 | `INVALID_SCHEMA`、`INVALID_COUNTER`、`VM_GENERATION_MISMATCH` | 不重试原消息；隔离并告警。 |
| 401/403 | `AUTH_FAILED`、`SCOPE_DENIED`、`SIGNATURE_INVALID` | 停止该通道、告警；不得快速重试。 |
| 408/425/429 | `RETRY_LATER` | 保留原 body，遵守 `Retry-After`，指数退避加抖动。 |
| 409 | `BATCH_CONFLICT`、`METER_SOURCE_CONFLICT`、`COMMAND_ID_CONFLICT` | 不重试；需要人工/官网修复。 |
| 5xx/网络/TLS 临时失败 | `UPSTREAM_UNAVAILABLE` | 保留原 batch，指数退避；TLS 证书失败视为安全故障而非普通重试。 |
| 507 | `QUEUE_FULL` | Agent 保留数据、提高告警；官网不得要求丢弃账务 batch。 |

未知 2xx 不是成功；未知 4xx 不是可重试；未知 5xx 按短暂错误处理但设置重试预算。

## 5. 本地持久化、排队与可观察性

* Metering spool 是加密或至少 `0600`、专属 Unix 用户、原子 rename 写入的持久
  目录；与普通 Monitoring spool 分离。密钥、Token、密码、Authorization、命令
  敏感参数、QGA 内容不得写入日志或 spool。
* Metering 队列达到容量时进入 `METER_QUEUE_FULL`，停止接收新的 active 计费
  样本而非淘汰最旧样本；明确暴露最大容量、最旧样本年龄、积压数和剩余磁盘。若
  磁盘耗尽，告警且操作员决定扩容/导出，禁止静默丢账。
* Monitoring 队列可按明确的容量策略淘汰非关键遥测，但不得淘汰审计回执、控制
  结果或 active Meter 数据。
* 健康端点必须单独报告 `pveRead`, `qga`, `metering`, `monitoring`, `control`,
  `spool` 及每个通道的最后成功/失败原因；“PVE 可读”不等于“账务已送达”。

## 6. 控制命令契约（默认启用的安全边界）

官网拉取/推送的命令必须是不可变对象：

```json
{
  "schemaVersion": 1,
  "commandId": "018...",
  "issuedAt": "2026-08-29T15:04:05Z",
  "expiresAt": "2026-08-29T15:09:05Z",
  "agentId": "pve-01-agent",
  "identity": {"assetRef":"...","pveClusterRef":"...","vmid":101,"generation":3,"guestType":"qemu"},
  "action": "guest.start",
  "parameters": {},
  "operatorRef": "官网审计用户 UUID",
  "approvalRef": "需要双人审批时的批准 UUID",
  "bodySha256": "...",
  "signature": "官网命令签名"
}
```

* Executor 默认启动并验证命令；`sample`/`test` 模式无条件回执
  `DRY_RUN`/`TEST_MODE_BLOCKED`，且不向 PVE 发任何写请求。
* 生产模式只接受目标为本 Agent、签名正确、发布时间未超过 5 分钟、未过期、
  身份映射一致的白名单动作。任何验签/时钟/映射错误都不执行。
* v0.1 白名单必须逐项实现，不存在“透传任意 PVE API”：
  `guest.start`、`guest.shutdown`、`guest.stop`、`guest.reboot`、
  `guest.set-resources`、`guest.resize-disk`、`guest.set-network`、
  `guest.reinstall`、`guest.reset-login-credential`、`guest.create`、
  `guest.clone`。每项再按 QEMU/LXC、参数 schema、可允许存储/模板/网络和
  官网资产授权检查。未实现项回 `ACTION_UNSUPPORTED`，绝不降级为 shell。
* `guest.create`/`clone`/`reinstall`/`reset-login-credential`/资源缩减、删除、
  防火墙和网络变更为高风险命令，生产必须有 `approvalRef`、资产锁和 PVE task
  追踪。删除 PVE guest、修改 PVE 宿主机 root 密码、读取 `/etc/pve/priv/token.cfg`、
  任意 shell/`pvesh` 透传均不在 v0.1 白名单内。
* `(agentId, commandId)` 和 `bodySha256` 记录到持久 command journal 至少 30 天。
  相同 ID+同 body 只返回原始回执；相同 ID+不同 body 回
  `COMMAND_ID_CONFLICT`。进程重启、网络超时、PVE task 查询超时都不得让命令
  再执行一次。
* 回执至少包含 `commandId`、`state`（`received|dry_run|running|succeeded|failed|
  rejected|expired`）、`startedAt`、`finishedAt`、`pveTaskUPID`（若有）、
  `executionMode`、安全的错误码、`operatorRef`。密码、SSH 私钥、Token、命令
  完整敏感参数绝不回显或写审计日志。

采集 Token 和 Executor Token 必须为不同 PVE user/token。监控 Token 只给
`PVEAuditor` 所需范围；执行 Token 只给已托管资源池/路径所需最小权限，并按
action 做应用层二次限制。Proxmox 的 token 权限可以独立于其用户进一步缩小，正
适合此分离设计；不要运行一个联网 root Agent 或读取 PVE 的 token 密钥文件。

## 7. Proxmox VE 8.0 / 9.0 兼容策略

不得仅通过 `major >= 9` 分支。连接建立和每次版本/配置变更后必须能力探测，并把
`pveVersion`、`apiVersion`、`capabilities` 放入监控元数据：

1. `GET /api2/json/version`：记录版本，确认 JSON API 可用。
2. `GET /api2/json/cluster/resources`：这是所有 8/9 都必须具备的最小 PVE
   库存/VM 计数能力；没有它则整个 PVE source 为不可用。
3. 对发现的节点探测 `GET /api2/json/nodes/{node}/status`。`403` 表示 Token
   权限不足，回退为 cluster resource 的字段；不能把它误判成 PVE 8/9 差异。
4. 对 QEMU 的 QGA 按 VM 逐个、低频探测 info/osinfo/fsinfo/network interfaces；
   `404/501` 记为未支持，`500` 只有在确认 agent 已运行时才做有限退避。禁止对
   LXC 探测 QGA。
5. 写功能在 `production` 中在真正执行前，以 endpoint + action + guestType
   capability 验证；`401/403` 是权限配置错误，`404/501` 是不支持，均不得改用
   未文档化命令或 shell fallback。

PVE 8 和 9 应共同使用 `/api2/json` 的公开 REST API、API Token 和异步任务
UPID；字段可能随补丁级版本增减，所以解析器必须 tolerate unknown fields、对
缺失 optional 字段输出 unavailable，并对需要的字段做显式 presence check。API
守护进程 `pvedaemon` 在本地以 root 运行；Agent 不应调用其 127.0.0.1:85 私有接口
来绕过授权。官方文档说明 API token 权限只能是所属用户权限的子集，并给出
`-privsep 1` + `PVEAuditor` 的监控 Token 示例；这应成为安装器默认策略。

## 8. 上线前必须自动化测试的场景

| 场景 | 必须断言 |
| --- | --- |
| Agent 重启 | 未确认的 meter/monitor batch 以原 `batchId`、body、sequence 重放；控制 journal 不重复执行。 |
| 服务端在收到后断线 | 重试得到 `DUPLICATE` 或原回执；账单增量只记一次。 |
| 乱序/重复/时钟漂移 | 旧监控样本不覆盖新快照；旧计量样本不结算；±300 秒外 HMAC 拒绝。 |
| counter reset/回绕/PVE 重启 | 负差只建立新基线、不产生巨额流量；告警记录 reset。 |
| VMID 删除并复用 | generation 不匹配时停止计费/控制；新官网映射+新 generation 才可恢复。 |
| Agent 离线期间 VMID 被复用 | Agent 不能靠缓存自动继续对旧资产计费。 |
| 官网/PVE/outage | TLS、DNS、timeout、5xx、429 均不丢 active Meter 数据；退避有抖动且队列状态可见。 |
| queue full/磁盘满 | Meter 不淘汰、不默默覆盖；Monitor 的淘汰不影响 Meter 或 command audit。 |
| TLS | 过期证书、错误 SAN、未知 CA、降级 HTTP、重定向到其他 host 全部失败且不泄密。 |
| HMAC/replay | 篡改 body、签名、path、timestamp、nonce、重复 nonce、key 轮换都覆盖。 |
| QGA | agent 未安装、未运行、无权限、超时、LXC、返回不完整数据均不会产生“0 使用量”或 VM down。 |
| PVE 8/9 matrix | 对每个受支持的 8.x/9.x fixture 验证版本探测、resource 解析、可选 node status/QGA capability。 |
| sample/test 防误计费 | 所有 sample/test payload 被 Agent 和官网拒绝计费；全部控制命令无 PVE 写请求并留下 dry-run 回执。 |
| command 安全 | 过期、错误 agent、错误 generation、重复 ID、同 ID 不同 body、未白名单、未审批高风险命令均不可执行。 |
| PVE task 恢复 | 进程在提交 PVE 动作前/后崩溃；恢复时按 UPID 查询原任务，不重新提交。 |
| cutover | 切换第一样本仅 baseline；旧/新来源重叠拒绝；账期边界、重启和 counter reset 不重复/漏计。 |

建议提供 PVE 8、PVE 9、QGA 成功/失败、计数复位、乱序回放和命令回执的脱敏 JSON
fixture，全部在 CI 离线运行；不得依赖真实生产 PVE。

## 9. 实施阻断项与验收

在 README 宣称“可用于计费/控制”前，以下必须完成：

1. 官网实现并发布第 4.3/4.4/4.5/6 所列 v1 API、HMAC 验证、库存 generation 映射、
   Meter 幂等与 cutover 状态机；仅有现有 `/api/ingest` 时，Agent 只能做监控和
   shadow 对比。
2. Agent 实现互相独立的 monitoring/metering/command journal、生产 TLS 约束、
   PVE capability probe 和第 8 节测试矩阵。
3. 官网现有直连 PVE 控制与 Agent Executor 对同一 `assetRef + generation` 做互斥
   锁；v0.1 上线阶段官网直连仍是权威执行者，除非运营者针对资产显式切换。
4. 至少完成一个非生产 PVE 8 和一个 PVE 9 的 dry-run 端到端验收；真实控制先从
   start/shutdown/reboot 低风险动作、独立权限 Token 和完整审计开始。

参考：Proxmox 官方 [PVE 8 管理指南](https://pve.proxmox.com/pve-docs-8/pve-admin-guide.pdf)
和 [当前 PVE 管理指南](https://pve.proxmox.com/pve-docs/pve-admin-guide.pdf) 的 API
Token 权限分离/监控示例；[pvedaemon 文档](https://pve.proxmox.com/pve-docs/pvedaemon.8.html)
说明本地 API daemon 以 root 运行，不能作为 Agent 绕权路径。
