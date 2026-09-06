# Agent 安全自升级合同 v1

`agent.upgrade` 是 node scope、需要审批的写操作。它沿用官网控制通道已有的 Ed25519、`bindingId`、`deviceId`、`credentialEpoch`、`assignmentRevision`、`idempotencyKey`、目标身份、有效期、本地 `allowedActions` 和独立监控审计门禁。官网不得从浏览器接收或透传下载 URL、大小或 SHA。

从 `0.1.1-rc.30` 起，命令接收、策略拒绝、执行开始、终态、耗时和自升级各复验阶段都会写入结构化 journal 日志。从 `0.1.1-rc.31` 起，root helper 的失败阶段与原因也会持久化并进入官网签名回执，且发布打包器生成的每个文件都会由自动测试逐项通过 helper 白名单。从 `0.1.1-rc.32` 起，特权 helper 与主 Agent 统一使用 JSON journal 格式。从 `0.1.1-rc.33` 起，同一受限诊断也进入 monitoring audit，并附带 `operationId` 与可读 VM 目标供监控端聚合。日志与回执只包含合同允许的 `source/stage/method/path/httpStatus/reason`，不记录参数、凭据、请求体、PVE 原始响应或 guest 输出。

严格参数如下，未知字段拒绝：

```json
{
  "schemaVersion": 1,
  "releaseTag": "v0.1.0-rc.9",
  "agentCommitSha": "64位小写十六进制",
  "artifact": {
    "architecture": "amd64",
    "assetName": "ppflight-agent-0.1.0-rc.9-linux-amd64.tar.gz",
    "sizeBytes": "十进制uint64字符串",
    "sha256": "64位小写十六进制",
    "downloadUrl": "https://www.ppflight.com/api/pve-agent/v1/releases/artifacts/v0.1.0-rc.9/amd64"
  }
}
```

Agent 固定读取同一官网 origin 的 `GET /api/pve-agent/v1/releases/current`。只有 `upgradeDeliveryEnabled=true` 且签名参数与当前 manifest 的 release、commit、arch、assetName、size、SHA、URL 全部逐项一致时才暂存。manifest 和制品路由都必须 IPv4、HTTPS、系统 CA、正确 Host/SNI、无代理、无重定向并直接返回 200；GitHub 的 302 release URL 不能直接进入本合同。

长期运行进程以 `ppflight-agent` 用户运行，只能写私有 state 目录。它完成首次校验、下载、长度/SHA 校验并持久化已签名请求，返回独立 `agentUpgradeId`。root systemd oneshot helper 随后重新加载当前 config、官网 binding、assignment revision、Ed25519 key 和本地 allowlist，再次验签，并要求 control journal 已把相同 digest/upgradeId 记为 `submitted`。helper 从 no-follow 文件描述符重新校验制品，拒绝路径穿越、链接、特殊文件、重复/超量条目，验证包内 VERSION 和二进制 SHA 后才在 `/usr/local/bin` 同目录原子替换。

helper 重启 `ppflight-agent.service` 后，必须从 loopback `/status` 同时核对目标版本和原 `bindingId/deviceId/credentialEpoch`。失败会用 root-only 备份原子回滚、重启旧版并再次核对；回滚本身失败时只能报告真实 `failed`，不能伪报 `rolled_back`。升级不删除或迁移官网、监控、audit、receipt、telemetry durable queue。

候选版本健康后，helper 通过唯一命名、root-only、受限的 transient unit 执行候选版本自身的 `host-firewall reconcile`。该 postflight 必须完成 PVE 替代保护、UFW 删除以及严格回读，才可产生 `AGENT_UPGRADE_SUCCEEDED_HOST_FIREWALL_V1`。postflight 失败不会把已通过健康检查的新二进制回退到不具备该修复的旧版本，但必须返回真实失败阶段；官网不得据此提升升级 authority。

命令签名公钥轮换只能发生在 firewall postflight 成功之后。本机切换新公钥后，在成功 result 已持久化、可由 control reconcile 生成官网回执之前的任一失败，都必须恢复旧 binding、公钥和运行进程并严格回验，避免官网仍持有旧私钥而 Agent 只接受新公钥。官网也只有收到并验证 `AGENT_UPGRADE_SUCCEEDED_HOST_FIREWALL_V1` 后才可激活预备私钥。

## 旧版本两阶段升级

已经安装的 `0.1.5` helper 不认识新的 firewall postflight，因此第一次升级到新版本可能只返回旧码 `AGENT_UPGRADE_SUCCEEDED`。该回执仅证明旧 helper 完成了二进制替换，不能证明本合同新增的 PVE/UFW 收尾，也不能提升官网 authority。官网在观察到目标版本 telemetry 后，必须以唯一幂等键自动下发一次不轮换公钥的同版本升级；新 helper 会重新校验相同固定制品并完成 postflight。只有第二次返回 `AGENT_UPGRADE_SUCCEEDED_HOST_FIREWALL_V1` 才算最终成功。重复 telemetry 不得创建重复二阶段任务。

同版本重跑仅用于上述 postflight、恢复或显式强制校验；降级（包括 stable 到 prerelease 或更低 prerelease）在制品下载前拒绝。新 helper 的前向工作有小于旧 `ppflight-agent-upgrade.service` 180 秒上限的硬预算，各子阶段使用同一可取消 context；必要的独立回滚另有短预算。发布包可提高后续节点的 unit 上限，但绝不能依赖先更新 unit 才避免第一跳被 PID 1 强杀。

`0.1.7` 起，host-firewall transient worker 使用 110 秒预算，外层 postflight 使用 115 秒预算，总 helper 仍为 140 秒并为旧 180 秒 unit 保留独立回滚空间。受控 helper 诊断最多 512 字节，并同时保留开头与结尾，避免阶段日志遮蔽最终 systemd、dpkg 或 netfilter 错误。官网仍接收每次升级等待状态用于刷新进度，但 monitoring audit 只记录一次已提交阶段与最终成功、失败或回滚，不再随每轮轮询重复上传相同日志。

## Bootstrap 边界

RC.8 及更早版本没有 `agent.upgrade` 和 root helper，因此不能被官网安全地远程升级。部署首个支持自升级的版本需要一次人工执行 README 的固定 SHA 一键安装。该版本安装、服务回验、官网重新绑定/授权 `agent.upgrade` 完成之前，官网必须保持 `upgradeDeliveryEnabled=false`，不得显示“已下发”或“升级成功”。
