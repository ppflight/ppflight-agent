# Agent provisioning actions v1

本文冻结新增 Agent action 的 `parameters` 与成功 `receipt.result`。它们继续使用
`AGENT-API-V1.md` 的 control command envelope、Ed25519 签名、binding/device/epoch、
assignment revision、VM identity/generation、approval、resource lock、durable journal、
HMAC receipt 和 monitoring audit 规则。JSON decoder 拒绝 unknown/duplicate/trailing 字段。

首个包含这些 action 的 Agent 版本是 `0.1.0-rc.27`；clone lineage 修正与可用的反向
WSS console 合同从 `0.1.0-rc.28` 开始；VM 级 legacy Journal 恢复和 guest firewall rules
严格回验从 `0.1.0-rc.29` 开始；跨 assignment revision 的精确 legacy 恢复合同从
`0.1.0-rc.30` 开始；旧版 `PVE_RESULT_INDETERMINATE` 精确恢复兼容从 `0.1.0-rc.31`
开始；旧生产 Journal 缺失 record-level action 与 clone source identity 的签名审计恢复从
`0.1.1-rc.2` 开始；已由成功迁移完整退休的 indeterminate 记录从 `0.1.1-rc.3` 开始不再
占用资源锁。释放锁前必须同时验证合法 `RetiredByCommandID/RetiredAt`、同资源同 authority
的成功迁移 Journal，以及明确列出该旧 command 的严格迁移结果；部分标记或未完成迁移继续
fail closed。`0.1.1-rc.7` 增加固定到单条已审计生产事件的 DELETE-body 501 恢复变体。
协议版本仍为 `schemaVersion: 1`，这些 action
是 additive 扩展。密码、SSH key、PVE
ticket/certificate、完整 parameters 和原始 PVE response 不进入 receipt、audit 或日志。

## VM 级 legacy Journal 恢复

`vm.migrate-legacy-journal` 是 mutation，必须通过现有 command Ed25519、当前
`bindingId/deviceId/credentialEpoch/assignmentRevision`、VM identity/generation、action
allowlist、`approvalRef`、资源锁和 monitoring audit 门禁。它不是运维清理接口，也不能列举、
删除或清空 Journal。

exact parameters：

```json
{
  "legacyAssignmentRevision": "3",
  "legacyCloneCommandId": "legacy-clone-command-01",
  "legacyCloneOperationId": "legacy-clone-operation-01",
  "legacyCloneDigest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "templateRef": "ubuntu-24.04",
  "sourceVmid": 9001,
  "sourceConfigSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "retireIndeterminateCommandIds": ["legacy-indeterminate-command-01"]
}
```

`retireIndeterminateCommandIds` 必须显式出现、按字典序严格递增、无重复，最多 64 项；可为
空数组。`legacyAssignmentRevision` 必须显式给出、非零且严格小于当前已验签 command envelope
的 `assignmentRevision`；它不是范围或查询条件，而必须与目标 clone 及每条退休记录中持久化的
audit assignment 完全一致。因此当前 revision 只能精确批准一组已知旧 revision 记录，不能访问
“任意历史 revision”。目标 clone 必须是参数逐项引用的成功终态 `vm.clone`，保有相同 Agent、node、
VM resource key、audit signing key/target，且任何已存在的 binding/device/epoch/assignment/VMID/
generation 字段必须分别与当前 authority 或显式 legacy revision 一致。RC.27 缺失的 authority 字段
只能由当前已验签并获批的恢复命令补齐，不能由本地 CLI 或自报 payload 补齐；原始 audit context
继续保留 `legacyAssignmentRevision`，迁移后的 lineage authority 则提升到当前 revision，以允许当前
revision 的后续定型命令。旧记录缺失 record-level `action` 时，只能从该记录自身已经持久化且通过
校验的 signed audit action 恢复，并且必须是 known、mutating、VM-scope action；clone 必须精确恢复为
`vm.clone`。缺失的 clone source identity 只能在 Agent 重新读取当前 PVE 模板并核对签名参数中的
source config SHA-256 后补齐。Agent 执行前还会重新读取
`sourceVmid`，确认它仍是当前 node 上的同 guest type 模板，并重算 `sourceConfigSha256`。

只允许把所列、同 VM generation、状态恰为
`state=indeterminate` 且 code 精确为 `EXECUTION_INDETERMINATE` 或旧版
`PVE_RESULT_INDETERMINATE`、Journal 与 receipt 都没有 UPID/upgrade ID 的旧记录
标记为 retired。记录文件和审计证据保留；未列出的活动 mutation、带 UPID、身份冲突或损坏记录
都会使整个动作 fail closed。clone 的 migration marker 使不同 command 无法二次消费；同一
command/idempotency digest 可在进程崩溃后继续未完成的本地迁移，并在完成后只返回第一次结果。

历史记录可以是缺少新增 authority 列的早期 schema，也可以已经带有完整 authority；后者必须与
显式 `legacyAssignmentRevision` 及当前命令的 binding、device、epoch、signing key、VM 身份和
generation 逐项精确匹配。迁移资格不再以“必须缺字段”判断。Claim 前拒绝会返回脱敏细分码：
存在未列出的活动 mutation 为 `UNLISTED_ACTIVE_MUTATION`，列出记录不满足无 UPID、终态或身份
限制为 `LISTED_RECORD_NOT_ELIGIBLE`。clone 分别使用 `CLONE_JOURNAL_NOT_FOUND`、
`CLONE_DIGEST_MISMATCH`、`CLONE_RESOURCE_IDENTITY_MISMATCH`、
`CLONE_TERMINAL_RECEIPT_INVALID`、`CLONE_LEGACY_AUTHORITY_MISMATCH` 和
`CLONE_ALREADY_MIGRATED`；这些分类只暴露拒绝类别，不输出 Journal 内容、参数或密钥，也不会放宽成
通用 Journal 清理接口。

成功 result：

```json
{
  "migrated": true,
  "legacyAssignmentRevision": "3",
  "legacyCloneCommandId": "legacy-clone-command-01",
  "legacyCloneOperationId": "legacy-clone-operation-01",
  "templateRef": "ubuntu-24.04",
  "sourceVmid": 9001,
  "sourceConfigSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "retiredIndeterminateCommandIds": ["legacy-indeterminate-command-01"]
}
```

请求与结果 golden 分别为
`internal/control/testdata/agent-v1-vm-migrate-legacy-journal.json` 和
`internal/control/testdata/agent-v1-vm-migrate-legacy-journal-result.json`。

### rc.4 DELETE-body 501 单事件恢复变体

同一个 action 另有一个互斥的 exact parameters 变体：

```json
{
  "recoveryKind": "pve-delete-form-body-501-v1",
  "failedCommandId": "c864ed6d-3d43-4fc9-b966-edaf7066cbb0",
  "failedOperationId": "f967235b-a593-42fa-ae2d-f42219204d59",
  "failedCommandDigest": "c1ed3db0b581f7891f3f917fbf9b42d2ffb86251d0cdf4b2a00cb0c6d48ab830"
}
```

它不是按错误码工作的通用恢复能力。Agent 常量同时锁定 `qemu/100/generation=1`、旧记录的
`agentVersion=0.1.1-rc.4`、`state=indeterminate`、`code=PVE_ACTION_INDETERMINATE`、
`accepted=false`、`asynchronous=false`、`mutationMayHaveSucceeded=true`，并要求 Journal/receipt/
audit 的 command、operation、authority、target、signing key 与当前已验签恢复命令逐项一致。
旧记录或 receipt 不得有 UPID/upgrade ID，且相同资源不能存在其他活动 mutation。

执行阶段只使用 PVE GET：`/version` 必须精确返回 `8.4.0`，VM100 config 必须存在，current
status 必须精确为 `stopped`。它不会在恢复动作内发送 DELETE 或其他 PVE mutation。成功时只向
旧文件追加 `RetiredByCommandID/RetiredAt`，原 command、operation、digest、state、receipt、audit
和 authority 原样保留；成功 typed result 为：

```json
{
  "reconciled": true,
  "recoveryKind": "pve-delete-form-body-501-v1",
  "failedCommandId": "c864ed6d-3d43-4fc9-b966-edaf7066cbb0",
  "failedOperationId": "f967235b-a593-42fa-ae2d-f42219204d59",
  "failedCommandDigest": "c1ed3db0b581f7891f3f917fbf9b42d2ffb86251d0cdf4b2a00cb0c6d48ab830",
  "failedReceiptCode": "PVE_ACTION_INDETERMINATE",
  "affectedAgentVersion": "0.1.1-rc.4",
  "pveVersion": "8.4.0",
  "guestType": "qemu",
  "vmid": 100,
  "generation": 1,
  "guestPresent": true,
  "guestStatus": "stopped"
}
```

只有恢复 Journal 已成功终态且保存的 typed result 与上述所有字段完全一致，旧 VM 锁才释放；
部分 marker、结果缺失或字段不匹配继续 fail closed。随后删除必须使用新的 command/operation，
由 rc.5+ 的无 body、query-only `vm.delete` 正常提交。请求与结果 golden 为
`agent-v1-vm-migrate-delete-501.json` 和 `agent-v1-vm-migrate-delete-501-result.json`。

## 初次资源定型

`vm.set-initial-resources`：

```json
{
  "cores": 1,
  "sockets": 1,
  "memoryMiB": 1024,
  "cloneOperationId": "operation-clone-01",
  "templateRef": "ubuntu-24.04",
  "sourceVmid": 9001,
  "vmGeneration": "1",
  "templateConfigSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}
```

成功 result：

```json
{
  "configured": true,
  "cores": 1,
  "memoryMiB": 1024,
  "sockets": 1,
  "templateRef": "ubuntu-24.04",
  "sourceVmid": 9001,
  "templateConfigSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "verified": true,
  "vmGeneration": "1"
}
```

当前 command 使用独立的新 `operationId`；`cloneOperationId` 必须引用此前已经成功终态的
`vm.clone`，两者不得相同。本机 durable journal 会精确核对 clone 与当前命令的 binding、
device、agent/cluster/node、service/instance、guest/VMID/generation、assignment revision、
credential epoch、templateRef/sourceVmid 和 template SHA。clone 未完成、失败、回滚、身份不符或不存在时均拒绝。
同 generation 只允许成功一次；目标已经启动、交付、重装或进入其他代次后拒绝。PVE 回读
必须为 stopped、non-template。该一次性动作可把模板基线降到最终套餐值；普通
`vm.set-resources` 仍只扩容，磁盘仍只允许扩容。

## 固定模板重装

`vm.reinstall` v1 目前仅支持 Linux QEMU（固定 Cloud-Init 与 `timedatectl` 回验）；Windows
Administrator 密码重置是独立能力，不表示 Windows 重装已开放。exact parameters：

```json
{
  "templateRef": "ubuntu-24.04",
  "templateVersion": "24.04",
  "templateNode": "pve1",
  "templateGuestType": "qemu",
  "templateVmid": 9001,
  "templateConfigSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "vmGeneration": 3,
  "temporaryVmid": 800101,
  "storage": "local-zfs",
  "notBefore": "2026-09-02T00:00:00Z",
  "expected": {
    "cores": 2,
    "sockets": 1,
    "memoryMiB": 2048,
    "disk": {
      "interface": "scsi0",
      "minimumGiB": 40,
      "limits": {
        "iopsRead": 1000,
        "iopsWrite": 1000,
        "iopsReadMax": null,
        "iopsWriteMax": null,
        "iopsReadMaxLength": null,
        "iopsWriteMaxLength": null,
        "mbpsRead": 100,
        "mbpsWrite": 100,
        "mbpsReadMax": null,
        "mbpsWriteMax": null
      }
    },
    "networks": [{
      "interface": "net0",
      "bridge": "vmbr0",
      "mac": "02:00:00:00:01:01",
      "vlan": null,
      "mtu": 1500,
      "firewall": true,
      "rateMbps": "100",
      "ipv4": "192.0.2.10/24",
      "ipv6": "2001:db8::10/64",
      "ipFilterCidrs": ["192.0.2.10/32", "2001:db8::10/128"]
    }],
    "timezone": "UTC"
  },
  "expectedOs": {"family": "linux", "name": "ubuntu", "versionId": "24.04"},
  "networks": [{
    "interface": "net0",
    "bridge": "vmbr0",
    "mac": "02:00:00:00:01:01",
    "vlan": null,
    "mtu": 1500,
    "firewall": true,
    "rateMbps": "100",
    "ipv4": "192.0.2.10/24",
    "ipv6": "2001:db8::10/64",
    "gateway4": "192.0.2.1",
    "gateway6": "2001:db8::1"
  }],
  "cloudInit": {
    "hostname": "vps-101",
    "username": "root",
    "password": "<secret>",
    "passwordFormat": "plain",
    "sshAuthorizedKeys": [],
    "qgaEnabled": true
  },
  "start": true
}
```

`networks` 必须逐项等于 `expected.networks` 的 identity/config；`expected` 同时承担最终
delivery proof。Agent 先证明目标 stopped/non-template 和 template current config SHA，证明
temporary VMID 未占用，再完整 clone 当前 VM 作补偿边界。新 VM 使用相同业务 VMID，恢复
资源、磁盘、IO、Cloud-Init、网络/MAC/IP/rate、guest firewall、MACFilter 和精确
`ipfilter-netN`，启动后回读 QGA 地址、时区、OS name/version。任何步骤失败都会恢复原 clone；
无法证明恢复结果时 journal 保留 `indeterminate`，不得自动重放 mutation。

若 replacement 步骤失败但原 VM 已完整恢复，receipt 为 `failed/REINSTALL_ROLLED_BACK`；
若恢复或最终补偿 clone 清理结果无法证明，receipt 为
`indeterminate/REINSTALL_INDETERMINATE`，必须人工处置，不能重放同一 mutation。

成功 result 只含：

```json
{"reinstalled":true,"templateConfigSha256":"<64-lower-hex>","templateRef":"ubuntu-24.04","templateVersion":"24.04","verified":true,"vmGeneration":"3"}
```

不接受 ISO、URL、shell、guest-exec、任意 volume 或 PVE endpoint。LXC reinstall 在 v1
fail closed。

## noVNC 短时会话

create parameters：

```json
{"ttlSeconds":60,"webSocket":true}
```

成功 result：

```json
{"sessionRef":"<uuid>","state":"ready","expiresAt":"2026-09-02T00:01:00Z","browserPath":"/api/pve-agent/v1/console/<opaque>"}
```

Agent 使用 control token 向固定 QEMU VM `vncproxy` 请求 `websocket=1`，只通过 IPv4
`127.0.0.1:<temporary-port>` 连接该本地端口，并在内存中完成 PVE VNC ticket/RFB 认证。
随后 Agent 先向由 receipt URL 同源推导的固定 `/console-sessions` 注册不含 secret 的 session，
再主动连接固定 `wss://<same-origin>/console-sessions/<sessionRef>/agent-tunnel`。两个请求均使用
现有 control-receipts HMAC；原始 create command 仍须先通过 Ed25519、binding、epoch 和
assignment 校验。浏览器只获得 opaque `browserPath`，不接收 PVE 地址、端口、user、ticket、
certificate 或 API token。Agent 对浏览器呈现一次性无密码 RFB 握手，随后只转发内存字节流。

broker registration request 的 exact shape（完全不含 PVE secret 或本地端口）：

```json
{
  "schemaVersion": 1,
  "transport": "agent-reverse-wss-v1",
  "sessionRef": "<uuid>",
  "commandId": "command-01",
  "idempotencyKey": "provision-console-01",
  "operationId": "operation-01",
  "bindingId": "<uuid>",
  "deviceId": "device-01",
  "credentialEpoch": "2",
  "assignmentRevision": "7",
  "agentRef": "agent-01",
  "clusterRef": "cluster-01",
  "serviceRef": "service-01",
  "instanceUuid": "instance-01",
  "generation": "3",
  "nodeRef": "pve1",
  "guestType": "qemu",
  "vmid": 101,
  "expiresAt": "2026-09-02T00:01:00Z",
  "oneTime": true
}
```

成功 result：

```json
{"sessionRef":"<uuid>","state":"ready","expiresAt":"2026-09-02T00:01:00Z","browserPath":"/api/pve-agent/v1/console/<opaque>"}
```

WSS 连接只允许系统 CA、正确 Host/SNI、IPv4，transport 明确禁用代理和重定向。TTL 为
30–300 秒且只能领取一次；本地或浏览器断开、TTL 到期、revoke、assignment authority 更新、
binding/credential 重载或 Agent 退出都会关闭本地 PVE socket 与 WSS。所有帧、ticket 和临时
连接元数据均不写 journal、receipt、audit、telemetry 或日志。

PVE 8/9 的 `vncproxy` 成功响应可能把端口编码为 JSON 数字或十进制字符串；
`0.1.1-rc.35` 对这两种受限编码作等价解析，并继续拒绝空值、布尔值、小数、符号、
非十进制文本与 1–65535 之外的端口。
`0.1.1-rc.36` 把注册 `expiresAt` 规范为 UTC 整秒；broker 非 2xx 响应只回传 HTTP 状态和
最多 64 字节的安全协议错误码，绝不回传自由文本 message 或原始响应。

revoke parameters/result：

```json
{"sessionRef":"<uuid>"}
```

```json
{"revoked":true,"sessionRef":"<uuid>"}
```

broker revoke 固定 POST `/console-sessions/{sessionRef}/revoke`，request exact shape 为
`schemaVersion/sessionRef/commandId/idempotencyKey/operationId/bindingId/deviceId/assignmentRevision/serviceRef/instanceUuid/generation/nodeRef/guestType/vmid`；
成功可返回空 2xx body。broker 禁止 redirect；create response 必须是 strict JSON。

## Guest firewall rules 严格回验

以下三个 VM scope action 都是只读操作，不占用 mutation lock，也不需要审批；command 仍须
通过 binding/device/epoch、assignment、VM identity/generation、Ed25519 和 action allowlist：

- `firewall.guest.rules.list` parameters 固定为 `{}`。
- `firewall.guest.rules.get` parameters 固定为 `{"position":0}`，position 范围 0..999。
- `firewall.guest.rules.verify` parameters 固定为 `expectedDigest/rules`，rules 必须按 position
  严格递增、无重复、最多 1000 条，且 SHA-256 必须等于 canonical JSON rules 的摘要。

canonical rule 的 exact 字段为：

```json
{
  "position": 0,
  "type": "in",
  "action": "ACCEPT",
  "macro": "HTTPS",
  "protocol": "tcp",
  "icmpType": "echo-request",
  "source": "192.0.2.0/24",
  "destination": "198.51.100.10/32",
  "sourcePort": "1024-65535",
  "destinationPort": "443",
  "interface": "net0",
  "ipVersion": "4",
  "logLevel": "info",
  "enabled": true,
  "comment": "managed rule"
}
```

除 `position/type/action/enabled` 外的空字段省略。`type` 支持 PVE 官方返回的
`in|out|group`；macro 和 security group 保持为受限 typed 名称。Agent 对 PVE 官方 rules
返回字段执行 unknown-field fail-closed，拒绝重复位置、非法 enable/IP version、控制字符和
不受支持的组合，然后按 position 排序再计算摘要。`verify` 同时比较摘要和 canonical JSON，
所以新增、修改、删除、启用或关闭任一规则后都必须读取到完全一致状态才成功。

list result 固定为 `{"rules":[...],"digest":"<64-lower-hex>"}`；get result 固定为
`{"rule":{...},"digest":"<single-rule-64-lower-hex>"}`；verify result 固定为
`{"verified":true,"rules":[...],"digest":"<64-lower-hex>"}`。上游 PVE 自带的共享 SHA-1
digest 只用于验证返回格式，不进入本合同的 rule 字段或摘要算法。

golden 位于
`internal/control/testdata/agent-v1-firewall-guest-rules-list-result.json` 和
`internal/control/testdata/agent-v1-firewall-guest-rules-verify.json`。

## 只读 snapshot / backup

- `snapshot.list`: `{"limit":50}`；`snapshot.get`: `{"name":"before-upgrade"}`。
- `backup.list`: `{"storage":"backup1","limit":50}`；`backup.get`:
  `{"storage":"backup1","volume":"backup1:backup/vzdump-qemu-101.vma.zst"}`。
- list 上限 100；get 找不到即失败。所有 uint64/generation 均为十进制 JSON string。
- result 顶层固定为 `vmid/guestType/vmGeneration/items`。snapshot item 固定
  `snapshotId/name/state/hasRamState/vmGeneration`，可选 `createdAt/parentId`；backup item 固定
  `storage/volume/sizeBytes/state/guestType/vmid/vmGeneration/restorable`，可选
  `createdAt/compression`。

## suspend / resume 与密码

- `vm.suspend` / `vm.resume` parameters 均为 `{}`，仅 QEMU；Agent 等待 UPID 并回读
  qmpstatus，成功 result 为 `{"powerState":"suspended|running","verified":true}`。
- `vm.reset-password` parameters 为
  `{"username":"root","password":"<secret>","crypted":false,"osFamily":"linux"}`。
  QEMU 支持 `linux|windows` 和受限账户名，经 QGA fixed password endpoint；LXC 只允许
  `username=root,osFamily=linux,crypted=false`，经 PVE config password 字段。为兼容既有 QEMU
  command，`osFamily` 可省略并按原 QGA 行为处理；新调用必须显式发送。成功 result 为空。

## 逐 NIC 计量扩展

`UsageRecord` schemaVersion 仍为 1。host-netdev 事件新增固定字段：

```json
{
  "source": "pve-host-netdev",
  "interfaceRef": "net0",
  "canonicalMac": "02:00:00:00:01:01",
  "networkRole": "public",
  "metered": true,
  "generation": "3",
  "counterEpoch": "<uuid>",
  "ingressBytes": "18446744073709551614",
  "egressBytes": "18446744073709551613"
}
```

身份来自 signed assignment 与当前 PVE config 的精确 netN/MAC 交集；数值来自 node
exporter 的宿主 tap/veth netdev uint64。Linux host TX 对应 guest ingress，host RX 对应 guest
egress。private binding 必须 `metered=false` 且不生成用量事件。counter 下降、MAC、generation
或 source 变化都会轮换 `counterEpoch`；服务端以 `eventId/sequence/epoch` 幂等计算差值、月度
结算与跨月解除限速，达量后继续使用既有 typed `vm.set-rate`。QGA counter 只作诊断。
