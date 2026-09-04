# Agent 安全自升级合同 v1

`agent.upgrade` 是 node scope、需要审批的写操作。它沿用官网控制通道已有的 Ed25519、`bindingId`、`deviceId`、`credentialEpoch`、`assignmentRevision`、`idempotencyKey`、目标身份、有效期、本地 `allowedActions` 和独立监控审计门禁。官网不得从浏览器接收或透传下载 URL、大小或 SHA。

从 `0.1.1-rc.30` 起，命令接收、策略拒绝、执行开始、终态、耗时和自升级各复验阶段都会写入结构化 journal 日志。失败日志只包含回执合同允许的 `source/stage/method/path/httpStatus/reason`，不记录参数、凭据、请求体、PVE 原始响应或 guest 输出。

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

helper 重启 `ppflight-agent.service` 后，必须从 loopback `/status` 同时核对目标版本和原 `bindingId/deviceId/credentialEpoch`。失败会用 root-only 备份原子回滚、重启旧版并再次核对；终态写入私有 result，由 control reconcile 生成官网 receipt，并通过独立 monitoring audit 队列上传。升级不删除或迁移官网、监控、audit、receipt、telemetry durable queue。

## Bootstrap 边界

RC.8 及更早版本没有 `agent.upgrade` 和 root helper，因此不能被官网安全地远程升级。部署首个支持自升级的版本需要一次人工执行 README 的固定 SHA 一键安装。该版本安装、服务回验、官网重新绑定/授权 `agent.upgrade` 完成之前，官网必须保持 `upgradeDeliveryEnabled=false`，不得显示“已下发”或“升级成功”。
