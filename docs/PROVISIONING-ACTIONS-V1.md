# Agent provisioning actions v1

本文冻结新增 Agent action 的 `parameters` 与成功 `receipt.result`。它们继续使用
`AGENT-API-V1.md` 的 control command envelope、Ed25519 签名、binding/device/epoch、
assignment revision、VM identity/generation、approval、resource lock、durable journal、
HMAC receipt 和 monitoring audit 规则。JSON decoder 拒绝 unknown/duplicate/trailing 字段。

首个包含这些合同的 Agent 版本是 `0.1.0-rc.27`；协议版本仍为 `schemaVersion: 1`，
这些 action 是 additive 扩展。密码、SSH key、PVE
ticket/certificate、完整 parameters 和原始 PVE response 不进入 receipt、audit 或日志。

## 初次资源定型

`vm.set-initial-resources`：

```json
{
  "cores": 1,
  "sockets": 1,
  "memoryMiB": 1024,
  "cloneOperationId": "operation-01",
  "vmGeneration": 1,
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
  "templateConfigSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "verified": true,
  "vmGeneration": "1"
}
```

`cloneOperationId` 必须等于 command `operationId`。本机 journal 还必须存在同 target、
generation、operation、template SHA 的已成功 `vm.clone`，且同 generation 不得已有成功或
未决的 `vm.start`、`vm.verify-delivery`、`vm.reinstall`。PVE 回读必须为 stopped、
non-template。该一次性动作可把模板基线降到最终套餐值；普通 `vm.set-resources` 仍只扩容。

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
{"sessionRef":"<uuid>","path":"/console/session/<uuid>","expiresAt":"2026-09-02T00:01:00Z","oneTime":true}
```

Agent 使用 control token 向固定 VM `vncproxy` 获取临时材料，并立即 POST 到由 receipt URL
同源推导的固定 `/console-sessions` broker；请求使用 control-receipts HMAC。secret 只存在于
该 HTTPS 请求内存，普通 receipt/outbox/audit 不持有它。broker 返回的 path、sessionRef、TTL
必须与请求一致。官网不得持有长期 PVE credential，也不得自行请求 PVE ticket。

broker create request 的 exact shape（这是唯一包含临时 secret 的边界）：

```json
{
  "schemaVersion": 1,
  "sessionRef": "<uuid>",
  "commandId": "command-01",
  "idempotencyKey": "provision-console-01",
  "operationId": "operation-01",
  "bindingId": "<uuid>",
  "deviceId": "device-01",
  "assignmentRevision": "7",
  "serviceRef": "service-01",
  "instanceUuid": "instance-01",
  "generation": "3",
  "nodeRef": "pve1",
  "guestType": "qemu",
  "vmid": 101,
  "pveUser": "ppflight-control@pve",
  "pveTicket": "<ephemeral-secret>",
  "pveCertificate": "<ephemeral-cert>",
  "pvePort": 5901,
  "expiresAt": "2026-09-02T00:01:00Z",
  "oneTime": true
}
```

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
