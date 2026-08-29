# 配置样例

`agent.example.yaml` 与 `assignments.example.yaml` 的内容刻意使用严格 JSON。JSON 是 YAML 1.2 的合法子集，但当前 Agent 为了拒绝未知字段、避免 YAML 隐式类型转换，只接受 JSON 语法；文件名保留 `.yaml` 是为了部署侧的常见习惯。

安装脚本会将它们复制为：

- `/etc/ppflight-agent/agent.yaml`
- `/etc/ppflight-agent/assignments.json`
- `/etc/ppflight-agent/agent.env`

先用默认 `mode: "test"`、`pve.source: "simulator"` 检查进程、队列和本地状态端点。投入生产前必须至少完成以下变更：

1. 用官网分配的不可变 `agentRef`、`collectorRef`、`sourceRef`、`clusterRef` 替换样例值。
2. 设置 `mode: "production"` 与 `pve.source: "api"`，并在 `agent.env` 提供只读 PVE Token。
3. 将已安装的两个 exporter 设为 `enabled: true`；两者只能使用 `127.0.0.1`/`::1` URL。
4. 为每个已映射 VPS 填写 `serviceRef + clusterRef + vmid + generation + instanceUuid`。未映射 VPS 永远不会进入计费。
5. 设置官网 HTTPS API 与 HMAC 环境变量，再分别启用网站计量、官网遥测和监控站目标。
6. 即使控制轮询已启用，仍保持 `productionExecution: false`，直到单独审计和批准写操作 Token。

`assignments.refreshUrl` 在 v0.1 是明确的预留字段，必须保持空字符串；映射由官网侧工具原子替换本地 `assignments.json`。远程拉取、响应签名与防回滚完成前，Agent 会拒绝非空 refreshUrl，避免出现“看似配置了但实际上没有刷新”的假象。

示例值不是凭据、不是生产 ID，也不应在生产环境保留。
