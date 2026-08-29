# PPFlight Agent API 契约（官网与监控站待实现）

本文定义 Agent 与官网/监控站之间的目标协议。除非服务端已经实现并完成联调，不能把其中 URL 当作可直接调用的已上线 API。

本文也不定义官网/监控站的远程资产查询、创建或修改 API：该类接口目前仅预留为未来扩展，尚未由 Agent 或 ag-pve 实现。ag-pve 只管理其所在 PVE 宿主机上的本地配置。

所有时间为 RFC 3339 UTC；所有可能超过 JavaScript 安全整数的计数器均为十进制 JSON 字符串。所有接口只接受 HTTPS（测试模式可使用 loopback HTTP），内容类型为 application/json。

## 统一 HMAC-SHA256 请求签名

计费、业务遥测、监控遥测、控制轮询与控制回执应使用每个集群独立的 HMAC 凭据。不得使用 ADMIN Cookie、CSRF Token 或 PVE Token 代替。

必填请求头：

~~~text
X-PPFlight-Key-Id: key-2026-01
X-PPFlight-Timestamp: 1788048000
X-PPFlight-Nonce: 32+ 个随机十六进制字符
X-PPFlight-Content-SHA256: <请求原始字节的 sha256 十六进制>
X-PPFlight-Signature: <HMAC-SHA256 十六进制>
~~~

签名输入（末尾没有额外换行）：

~~~text
<UPPERCASE_METHOD>
<escaped-path[?raw-query]>
x-ppflight-key-id:<key-id>
x-ppflight-timestamp:<unix-seconds>
x-ppflight-nonce:<nonce>
x-ppflight-content-sha256:<lowercase-body-sha256>
~~~

签名为 hex(HMAC-SHA256(secret, canonical-input))。GET 的 raw query 必须按实际发送的原样参与签名。

服务端必须校验 key ID 所属集群、签名、内容 hash、五分钟（或更小）时钟偏差，并持久化 nonce 到偏差窗口结束以防重放。任何代理重写 path/query 都会使签名失效，应在网关保留原始请求目标。

## 映射文件

官网下发的映射是采集与控制的许可清单。建议 HTTPS 认证下载或在 Agent 配置目录中原子写入；不得让客户 VPS 生成。

~~~json
{
  "schemaVersion": 1,
  "revision": "mapping-2026-08-29-001",
  "issuedAt": "2026-08-29T12:00:00Z",
  "assignments": [
    {
      "serviceRef": "c144b1a9-8e82-4b4f-967d-1bd36a0c11fd",
      "clusterRef": "cluster-immutable-uuid-01",
      "nodeRef": "pve01",
      "vmid": 101,
      "generation": 3,
      "instanceUuid": "f955bbd2-d8af-4a4c-bae3-b9febd4c2dd5",
      "guestType": "qemu",
      "billingState": "shadow",
      "cutoverAt": "2026-08-30T00:00:00Z"
    }
  ]
}
~~~

serviceRef 当前为 billing_subscriptions.uuid。clusterRef 必须由官网保存为不可变值；不要传可修改 slug。身份匹配条件为 clusterRef + guestType + vmid + generation，并核验 serviceRef 与 instanceUuid。重装/VMID 重用必须提高 generation。

billingState 只能是 disabled、shadow、active。active 必须有 cutoverAt。切换时官网必须按 sourceRef/cutoverAt 确保同时只有一个来源进入真实账本。

## 1. 流量计费批次

建议端点：POST /internal/v1/metering/usage-batches

这是不可丢弃的精确计费输入。Agent 仅提交 PVE 累计计数，官网决定差值和最终账本。

~~~json
{
  "schemaVersion": 1,
  "batchId": "f4f2203b-4d61-4f99-a3bf-4b2d444d7f5d",
  "agentRef": "agent-pve-test-01",
  "collectorRef": "collector-pve-test-01",
  "sourceRef": "pve-agent-v1",
  "clusterRef": "cluster-immutable-uuid-01",
  "mode": "test",
  "sequence": "42",
  "observedAt": "2026-08-29T12:00:00Z",
  "events": [
    {
      "serviceRef": "c144b1a9-8e82-4b4f-967d-1bd36a0c11fd",
      "clusterRef": "cluster-immutable-uuid-01",
      "nodeRef": "pve01",
      "vmid": 101,
      "generation": "3",
      "instanceUuid": "f955bbd2-d8af-4a4c-bae3-b9febd4c2dd5",
      "guestType": "qemu",
      "eventId": "ba794d21-4926-49b5-9c01-dabd283651f2",
      "counterEpoch": "9b2d39b1-3df6-4d8a-9d8d-ce282af1c808",
      "sequence": "42",
      "source": "pve-cluster-resources",
      "billingState": "shadow",
      "cutoverAt": "2026-08-30T00:00:00Z",
      "observedAt": "2026-08-29T12:00:00Z",
      "ingressBytes": "103441234567",
      "egressBytes": "61234567890"
    }
  ]
}
~~~

规则：

- ingressBytes、egressBytes 是 PVE netin/netout 的 uint64 累计值；不可使用 QGA 或 Agent 自算差值。
- counterEpoch 在 Agent 发现累计值回退/重置时变化；官网仍需独立保护账本。
- eventId 用于事件幂等，batchId 用于批次幂等，sequence 用于每个来源的乱序检查。建议唯一索引为 (collectorRef,batchId) 和 (serviceRef,generation,eventId)。
- mode=test 的事件只能为 shadow，不得写入真实账本。只有 mode=production 且来源切换已生效的 active 才能入账。

建议服务端响应：

~~~json
{
  "accepted": true,
  "batchId": "f4f2203b-4d61-4f99-a3bf-4b2d444d7f5d",
  "results": [
    {"eventId": "ba794d21-4926-49b5-9c01-dabd283651f2", "status": "accepted"}
  ]
}
~~~

成功仅限 2xx，或明确且同一内容的 duplicate 确认。建议机器可读拒绝码：duplicate、stale_generation、identity_mismatch、out_of_order、idempotency_conflict、source_not_active。不要把含糊 200 当作已入账。

计费字段约束：

| 字段 | 约束 |
| --- | --- |
| schemaVersion | 固定 1。 |
| batchId | UUID；同一 collectorRef 内必须幂等。 |
| agentRef / collectorRef / sourceRef / clusterRef | 官网注册的安全标识，必须属于同一集群。 |
| sequence | 批次单调序号，十进制字符串。它用于检测乱序，不取代幂等键。 |
| vmid / guestType | PVE VMID 与 qemu 或 lxc。 |
| generation / ingressBytes / egressBytes | 十进制 uint64 字符串。 |
| billingState | disabled 对象不应出现在事件中；test 模式只能 shadow。 |
| observedAt / cutoverAt | UTC 时间。cutoverAt 是官网切换边界，不是 Agent 自行决定的时间。 |

## 2. 官网业务遥测与监控遥测

建议端点：

- POST /internal/v1/telemetry/batches
- POST /internal/v1/monitoring/batches

官网遥测使用下列 envelope。监控目的地只有在 `payloadFormat=telemetry-v1` 时使用同一 envelope；现有监控站 `/api/ingest` 必须配置 `legacy-ingest-v1`，由 Agent 生成旧 `CollectorEnvelope schemaVersion=1` 兼容格式：

~~~json
{
  "schemaVersion": 1,
  "batchId": "2a2c09c9-b0dd-4f3d-882e-ed55fdbf42c9",
  "agentRef": "agent-pve-test-01",
  "collectorRef": "collector-pve-test-01",
  "sourceRef": "pve-agent-v1",
  "clusterRef": "cluster-immutable-uuid-01",
  "mode": "test",
  "sequence": "43",
  "observedAt": "2026-08-29T12:00:10Z",
  "components": {"pve": {"available": true}, "qga": {"available": true}},
  "guests": [
    {
      "managed": true,
      "identity": {
        "serviceRef": "c144b1a9-8e82-4b4f-967d-1bd36a0c11fd",
        "generation": 3,
        "instanceUuid": "f955bbd2-d8af-4a4c-bae3-b9febd4c2dd5"
      },
      "vmid": 101,
      "guestType": "qemu",
      "pveObserved": {
        "memoryUsedBytes": 805306368,
        "memoryTotalBytes": 2147483648,
        "ingressBytesTotal": "103441234567",
        "egressBytesTotal": "61234567890"
      },
      "guestObserved": {
        "availability": {"available": true},
        "filesystems": [{"mountpoint": "/", "usedBytes": 4294967296}]
      }
    }
  ]
}
~~~

PVE/QGA 必须保持分离并带可用性；QGA 缺失表示未知/不可用，不代表 0。QGA IP 和文件系统可能涉及客户隐私，官网需执行角色授权、脱敏和保留期控制。

遥测最小字段语义：

| 区域 | 必需/推荐内容 |
| --- | --- |
| 顶层 | schemaVersion、batchId、agentRef、collectorRef、sourceRef、clusterRef、mode、sequence、observedAt、components。 |
| nodes | 节点名称、状态、CPU 比例/核数、内存、swap、rootfs、load、uptime、PVE 版本、采样时间。 |
| storages | 节点、存储名/类型/内容、shared、状态、used/free/total、采样时间。 |
| tasks | 节点、任务类型、资源 ID、状态、开始/结束时间。 |
| guests | VMID、guestType、节点、模板标识、managed/identity、pveObserved、guestObserved、虚拟网卡配置。 |
| host | node_exporter 标准化结果：CPU、内存、FS、网卡、PSI、ZFS 等。 |
| smart | smartctl_exporter 标准化结果：盘路径/序列号/型号、健康、温度、错误、寿命/容量。 |

旧监控接口 /api/ingest 只能作为经过确认的兼容桥。test 模式下 Agent 会从该兼容 payload 中移除 VPS 网络累计计数，防止测试误计费；production 若旧接口仍将网卡累计值输入旧计费逻辑，禁止与新计费 API 同时启用。

## 3. 控制命令轮询与回执

建议轮询：GET /internal/v1/agents/commands?agentRef={agentRef}&after=<cursor>&limit=20

请求仍按统一 HMAC 签名。空 body SHA-256 是：

~~~text
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
~~~

官网返回：

~~~json
{
  "schemaVersion": 1,
  "cursor": "cmd-000042",
  "commands": [
    {
      "schemaVersion": 1,
      "commandId": "ea6575cb-8a0f-4a5b-adc5-765889e244d3",
      "agentRef": "agent-pve-test-01",
      "issuedAt": "2026-08-29T12:00:00Z",
      "expiresAt": "2026-08-29T12:10:00Z",
      "identity": {
        "serviceRef": "c144b1a9-8e82-4b4f-967d-1bd36a0c11fd",
        "clusterRef": "cluster-immutable-uuid-01",
        "nodeRef": "pve01",
        "vmid": 101,
        "generation": 3,
        "instanceUuid": "f955bbd2-d8af-4a4c-bae3-b9febd4c2dd5",
        "guestType": "qemu"
      },
      "action": "vm.start",
      "parameters": {},
      "operatorRef": "admin-uuid",
      "bodySha256": "<sha256(parameters 原始 JSON)>",
      "signature": "<命令 HMAC 签名>"
    }
  ]
}
~~~

命令使用独立命令签名密钥。签名输入依下列顺序以换行连接：

~~~text
schemaVersion
commandId
agentRef
issuedAt（RFC3339Nano UTC）
expiresAt（RFC3339Nano UTC）
serviceRef
clusterRef
nodeRef
vmid
generation
instanceUuid
guestType
action
operatorRef
approvalRef
lowercase(bodySha256)
~~~

签名为 hex(HMAC-SHA256(command-secret, canonical-input))。Agent 必须校验命令 ID、映射身份、允许 action、15 分钟最大生命周期、时钟窗口、参数 body hash 和签名。vm.stop/create/clone/resize/delete/set-rate/reset-password 必须有 approvalRef。

建议回执：POST /internal/v1/agents/{agentRef}/command-receipts

~~~json
{
  "schemaVersion": 1,
  "receiptId": "b78eb14e-f558-4f36-bb1b-e07402f17155",
  "commandId": "ea6575cb-8a0f-4a5b-adc5-765889e244d3",
  "agentRef": "agent-pve-test-01",
  "state": "dry_run",
  "code": "DRY_RUN",
  "executionMode": "test",
  "dryRun": true,
  "startedAt": "2026-08-29T12:00:01Z",
  "finishedAt": "2026-08-29T12:00:01Z",
  "operatorRef": "admin-uuid"
}
~~~

回执状态可为 dry_run、submitted、succeeded、failed、indeterminate、rejected。PVE 返回 UPID 时 v0.1 只回 `submitted/PVE_TASK_SUBMITTED`，绝不把“任务已排队”误报成成功；任务终态追踪接口后续补齐。传输中断导致无法判断 PVE 是否已接受时回 `indeterminate/PVE_RESULT_INDETERMINATE`，不得自动重发同一业务动作。服务端应以 (agentRef,receiptId) 幂等，并保存命令摘要、操作者、审批号、时间与 PVE task UPID；绝不要求 Agent 上传密码或敏感参数明文。

## HTTP 重试

- 2xx 或同一内容的显式 duplicate：确认并删除本地队列项目。
- 网络错误、408、425、429、5xx：保留项目，指数退避并带抖动重试。
- 身份/签名/模式/参数类 4xx、以及冲突：隔离到 dead-letter 并告警，不得无限重试或静默丢弃。
- 拒绝重定向，防止数据/签名被转发到非预期地址。
- 官网计费、官网遥测、监控遥测、控制回执必须使用独立队列。
