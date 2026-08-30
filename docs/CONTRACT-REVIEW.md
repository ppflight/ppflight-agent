# PPFlight Agent v0.1 历史审阅摘要（非规范）

本文件只记录 2026-08-29 早期审阅中仍有解释价值的背景。旧草案中的模式名、identity、URL、签名时间、动作名、共享监控信任域和“官网长期直连 PVE”方案均已归档，不应用于实现、部署或验收。

当前规范：

- [Agent API v1 目标契约与迁移边界](AGENT-API-V1.md)
- [数据面 API 与兼容说明](API.md)
- [安装、绑定与迁移](INSTALL.md)

出现冲突时，以当前 Go 类型、协议测试和上述规范为准。尤其是：discovery `limit` 默认 20、最大 50；动作使用 `snapshot.*`、`backup.*`、`firewall.*`、`task.status` 等代码中的完整名称。

control 当前 33 个 known actions 已用一致性测试锁住 registry/validator/executor；`firewall.ipset.entry.update/delete` 已实现，`vm.reinstall` 和远程 Agent 自升级未实现。`vm.reinstall` 不能以本地 template helper、任意 URL、storage volume 或 `vm.create` 替代：PVE 恢复/介质切换是非事务性流程，缺少安全回滚保证，且尚无签名命令可验证的安装介质 allowlist、摘要/来源约束和审批模型。

## 仍然有效的审阅结论

1. VMID 可重用，计量和控制必须校验 `clusterRef + guestType + vmid + generation`，以及 `serviceRef`、`instanceUuid`。
2. PVE 是平台外部视图，QGA 是客户系统内部增强视图；QGA 缺失不能伪造成 0，也不能参与流量计费。
3. 流量使用 PVE ingress/egress 原始累计 uint64，官网负责差值、counter reset、乱序、账期和最终账本。
4. metering、telemetry、commands、receipts 使用独立队列和幂等 ID；确认一个通道不能删除另一个通道的数据。
5. mutation 必须固定 schema、签名、审批、assignment 校验和持久 journal；不允许任意 PVE path、shell 或脚本透传。
6. PVE 返回 UPID 只是提交成功。Agent 必须持久化并在重启后继续对账，不能重新提交原 mutation。
7. PVE 8/9、QGA 成功/失败、VMID 重用、counter reset、断网重放、command conflict、UPID 崩溃窗口都需要自动化 fixture 和非生产端到端验证。
8. NIC 业务角色必须按 `netN` 显式保存，不能依赖顺序；多 NIC aggregate 无法拆分时停止 active 计费，QGA per-interface 只作观测。
9. QGA availability/freshness 必须展示并作为依赖动作 gate；QGA 故障不能阻断纯 PVE lifecycle。
10. Agent/官网离线只能触发持久排队与主动重连，不能回退官网直连 PVE；systemd watchdog/自动重启也不能扩大执行权限。

## 已替换的架构决定

- 目标状态是官网不保存 PVE URL/Token、不访问 8006；Agent 只在节点本地使用 `https://127.0.0.1:8006` 和自动创建的专用 Token。
- `ag-pve pve prepare/status` 是已接线的 root 本地 readiness 工具：prepare 在 test/productionExecution=false 时验证 root-only Token 文件并将 TCP endpoint 固定为 `127.0.0.1:8006`，TLS 证书验证另用严格 DNS `pve.tlsServerName`；它不会增授 ACL、开启 production 或启动服务。read/control 探测成功也不表示远端官网/监控路由、production mutation 或真实 PVE 破坏性验收已完成。
- 官网使用一次性绑定签发 `bindingId/deviceId`、五组业务端点凭据、Ed25519 命令公钥、assignment 和 credential epoch。
- website/monitoring 每个 bind response 都必须有各自 exact `networkPolicy={agentObservedIPv4}`；`serverIPv4Allowlist` 已删除并会被 strict decoder 拒绝。Agent 对 endpoint hostname 使用 tcp4，保留 hostname 做 Host/TLS SNI/系统 CA 证书校验，并拒绝 proxy、redirect 与 IPv6 fallback。两端服务分别从可信连接元数据冻结 Agent 公网出口 IPv4/32，并与 binding/HMAC/epoch/scopes 联合授权；两个 trust domain 不得共享 policy。
- 监控站使用第二枚一次性绑定码、独立 `bindingId/deviceId/monitoringAgentRef`、monitoring telemetry/固定同源 audit/status HMAC 合同、独立 `<stateDirectory>/bindings/monitoring-binding-state.json` 和 credential epoch；官网绑定不能覆盖它。服务端按路由分别校验 `monitoring:telemetry.write`、`monitoring:audit.write`、`monitoring:status.read`，website Commands key 另有固定 `website:status.read`，均不得跨 trust domain。
- 官网修改类 command 还需要通过 monitoring 独立 HMAC 投递脱敏 audit event，使用独立 durable outbox/idempotency/sequence/timestamps；只允许冻结字段与 SHA-256 digest，不能保存或上传 secret、密码、Token、完整 parameters/result 或原始 UPID。wire schema 故意不含 `operationId/executionMode`，UPID 若出现只能是 digest。Agent wire/journal/outbox/runtime sink/uploader 已接线；监控存储/UI 仍由外部任务交付，是 production 修改动作的验收项。
- Agent 到官网、监控站和 PVE 必须 IPv4-only，无 AAAA/IPv6 fallback；两套绑定分别建立 mutual IPv4 whitelist。IP 只是 TLS、绑定/key/epoch/签名/assignment/time/action/audit 之外的附加门槛，环境代理不可信，仅允许未来显式受控代理链。Agent tcp4 已接；服务端两套 source-IP whitelist 仍待外部实现/联调。
- 两种绑定均使用 UUID `requestId`、稳定 `deviceId` 与 canonical hash 幂等；code 原文不落盘，同 code 并发只签发一个 binding，服务端加密保存可重放 credential。
- 官网 Agent upgrade route feature flag 默认关闭。旧客户升级路由在逐资产 cutover 前继续，但不再作为新接入方案。
- 资源、网络、IPFilter、防火墙、快照和备份的 Executor 分支只是 Agent 原语；官网编排、回读和 feature flag 完成前不能宣称相关产品能力已上线。
- systemd notify/watchdog、请求级采集 progress deadline、`Restart=always` 和 clean/unclean lifecycle state 已接线；重启后 `agent.previousExit.*` 会分别进入不可淘汰的 website/monitoring lifecycle 队列。外部接收/展示与真实故障演练仍待验收，这只是本地恢复原语而非远端 HA SLA。
- 官网目标服务必须在 Agent 离线时持久排队未过期命令；本仓已实现领取后的 journal/UPID/receipt 恢复，但官网队列与 command `wait` 仍待远端交付。任何离线场景都禁止自动启用官网直连 PVE。
- `ag-pve template init|catalog|discover|bootstrap` 是校验同一 Agent 发布包内 `bundles/ppflight-cloudinit` 后执行的本机 root 管理流程；installer 已验证依赖、strict IPv4/HTTPS redirect policy，并用不可变版本目录/原子 managed symlink 安装。真实 PVE 上创建模板/备份的 plan/execute 破坏性验收仍待完成。它不进入远程 control action registry，也不能当作 `vm.reinstall` 或远程 Agent 自升级已经实现。
- `vX.Y.Z` tag release workflow 已构建 Linux amd64/arm64，测试并用 `scripts/package-release.sh` 输出可复现、离线 tarball 与 `SHA256SUMS`；手动 dispatch 只留 artifact，不发布。应先校验 checksum 再解压，不能 `curl | bash`；SHA-256 不替代组织另行要求的发布签名/来源审批。

本历史摘要不再列出旧 JSON 或旧 endpoint，以免示例被复制到新实现。
