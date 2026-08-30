# 安装、绑定与迁移

本页用于 Proxmox VE 8.x/9.x 节点。目标架构只允许 Agent 在本机连接 `https://127.0.0.1:8006`；官网不保存 PVE 地址或 Token，也不需要访问 PVE 8006。

当前 Agent 侧已经包含安装、PVE Token bootstrap 和官网绑定原语，但它们是需要管理员逐步执行/验收的独立步骤，不是一键 onboarding。官网 Agent upgrade route feature flag 必须默认关闭。旧客户升级继续走既有路由，直到按资产完成对账和 cutover；不要把安装成功等同于官网控制/升级已上线。

## 1. 前置条件

- Debian 系 PVE 8.x 或 9.x，root 管理权限；
- NTP/chrony 正常，生产请求默认只容忍约五分钟时钟偏差；
- Agent 到官网和监控站的出站 HTTPS 只能走 IPv4；DNS 必须有经审批的 A 记录，不能依赖 AAAA 或 IPv6 fallback；无需开放入站 8006/9100/9633；
- 为 website 与 monitoring trust domain 分别准备稳定的 NAT/出口 IPv4；每次 bind response 的 exact `networkPolicy` 只含对应服务端从可信连接元数据观察到的 canonical `agentObservedIPv4`，两端分别冻结该地址/32，地址变化走显式 rebind/轮换；
- `/etc/pve/pve-root-ca.pem` 可读，安装器会复制公开 CA；
- 已校验的 Agent 二进制和 SHA-256；
- Python 3.9+、Bash 5+，以及 vendored template manifest 列出的本机命令与 Perl modules；安装器会逐项检查并在缺失时中止；
- 如启用宿主机/磁盘采集，使用仅监听 loopback 的 node_exporter/smartctl_exporter。

监控站使用独立一次性绑定和独立信任域，不复用官网凭据。样例没有真实监控 endpoint/credential，所以默认 `destinations.monitoring.enabled=false`；已部署监控服务端后，成功执行第 6 节的独立绑定才会启用该 destination。

安装前可用 `getent ahostsv4 <官网域名>`、`getent ahostsv4 <监控域名>` 和 `curl -4` 诊断 IPv4 路径，但不再审批或固定 Cloudflare A/Anycast 集合。Agent 对 hostname 使用系统 A 解析和 `tcp4` 直拨，并保留 URL hostname 完成 Host/TLS SNI/系统 CA 证书校验；redirect、跨 origin、环境代理或 IPv6 fallback 都 fail closed。PVE endpoint 必须精确为 `https://127.0.0.1:8006`，不能写 `localhost`、`::1` 或节点公网地址。

## 2. 安装已校验发布物

不要执行未经校验的远程脚本，更不要使用 `curl | bash`。发布 workflow 在 `vX.Y.Z` tag push 时分别构建 Linux `amd64` 和 `arm64` 静态二进制，运行 Go/打包测试，再用 `scripts/package-release.sh` 生成 GitHub Release 的两个离线 tarball 与合并 `SHA256SUMS`；手动 dispatch 只保留 Actions artifact，绝不发布 release。包脚本不下载代码或依赖，只接受已构建的常规二进制，显式白名单 installer/config/systemd/docs/verifier/cloud-init bundle，二次验证 bundle，拒绝 symlink、secret/queue material 和覆盖既有输出；固定 archive 排序、owner、mtime 与 gzip metadata，使相同输入可复现。该流程提供 SHA-256 完整性校验，不替代组织另行要求的发布签名/来源审批。

从 Release 或受控 artifact 下载完整包与同一版本 `SHA256SUMS` 后，先离线校验再解压；该包必须同时含 installer/config/systemd/verifier 和 `bundles/ppflight-cloudinit`：

```bash
sha256sum --check SHA256SUMS
tar -xzf ppflight-agent-X.Y.Z-linux-amd64.tar.gz
cd ppflight-agent
sha256sum --check ppflight-agent.sha256
```

维护者可在已检出的受控源码和已构建二进制上离线重建单架构包（不应在目标 PVE 用它拉取源码）：

```bash
scripts/package-release.sh \
  --binary ./ppflight-agent \
  --version X.Y.Z \
  --arch amd64 \
  --output-dir ./dist/release
```

使用解压包内的本地二进制时：

```bash
sha256sum ppflight-agent
sudo scripts/install.sh \
  --binary ./ppflight-agent \
  --binary-sha256 '<发布页给出的64位SHA-256>' \
  --enable
```

安装器会创建专用系统用户和目录、安装 `/usr/local/bin/ppflight-agent`，并创建 `/usr/local/bin/ag-pve`、`/usr/local/bin/ag`、`/usr/local/bin/AG` 软链接。它保留已有 `/etc/ppflight-agent/agent.yaml`、`agent.env` 和 assignment 数据，且没有 `--start` 时不会启动服务。生产 assignment 的目标路径是 `/var/lib/ppflight-agent/assignments/assignments.json`；从旧 `/etc/ppflight-agent/assignments.json` 迁移时必须保留现有内容、再按目标 `ppflight-agent:ppflight-agent/0640` 元数据落盘，不能用空文件覆盖。

cloud-init helper 不是安装时另行下载的插件：同一 Agent 发布/安装包必须携带仓内 `bundles/ppflight-cloudinit`、manifest 和 verifier。安装器在安装二进制前先验证 bundle 精确文件集、摘要、依赖和 IPv4/HTTPS redirect policy；缺失、混装或校验失败会中止整次安装。当前自动化已覆盖打包/安装合同，但发布物仍须在 PVE 8/9 非生产节点完成会创建模板/备份的真实 plan/execute 破坏性验收。

installer 也支持 `--release-url HTTPS_URL --release-sha256 HEX` 只下载 Agent 二进制；该下载固定 IPv4、HTTPS/TLS 1.2+，并在安装前校验 SHA-256。它不会下载缺失的 scripts/config/cloud-init bundle，所以仍必须从已经解压并校验的完整发布包内运行；`--release-url` 不是远程脚本或整包 bootstrap。

## 3. 自动创建本地专用 PVE Token

在目标节点以 root 执行凭据 bootstrap：

```bash
sudo /usr/local/lib/ppflight-agent/create-pve-tokens.sh \
  --write-env /etc/ppflight-agent/agent.env
```

脚本会自动创建两套 privilege-separated PVE 身份：

- `PVE_READ_TOKEN_*`：只读采集，使用固定审计角色；
- `PVE_CONTROL_TOKEN_*`：受控写入，默认创建但**不授予 ACL**。

Token secret 只进入 mode 0600、root-owned 的本地环境文件，不输出到终端，也不上传官网。脚本发现同名 Token 已存在时会 fail closed，因为 PVE 无法再次读取旧 secret；它不会删除或重建现有 Token。

如果首次 bootstrap 就要在隔离测试池授予 control ACL，应**改用**下面的命令，而不是先执行上面的命令后再执行一次：

```bash
sudo /usr/local/lib/ppflight-agent/create-pve-tokens.sh \
  --write-env /etc/ppflight-agent/agent.env \
  --control-pool lab
```

`--control-global-acl` 仅允许隔离测试集群，不能作为生产安装示例。read/control Token 不得相同，官网也不得接收这四个环境变量的值。

若 fresh-PVE bootstrap 时先按默认值创建了无 ACL 的 control Token，完成资源审查后使用显式 ACL-only 模式补授权；它只验证既有 dedicated role/user/token 并同时给 backing user 与 privsep token 增加所列 scope，不创建、读取或重写 secret：

```bash
sudo /usr/local/lib/ppflight-agent/create-pve-tokens.sh \
  --acl-only \
  --control-pool lab

# 也可以重复 --control-scope，为已经审核的非根 PVE ACL path 逐项授权。
sudo /usr/local/lib/ppflight-agent/create-pve-tokens.sh \
  --acl-only \
  --control-scope /pool/lab \
  --control-scope /vms/101
```

ACL-only 禁止 `/` 和 `--control-global-acl`，也不能与 `--write-env` 混用。它不代替 assignment/action/approval gate；后续缩小或撤销 ACL 仍须作为独立、经审计的 PVE 管理操作完成。

## 4. 本地配置

安装器默认复制的示例是 `mode=test`、`pve.source=simulator`；即使启动也只产生模拟采集。Token bootstrap 不编辑配置，`AG` 菜单和两种 bind 也不会切换 PVE source/mode。官网 bind 不改变 service；监控 bind 仅在独立状态写入并严格回验后自动重启 unit、确认新 binding 已加载，失败则回滚。创建 Token 后，管理员可先以 root 执行下面的本地准备命令；它只允许在 `mode=test`、`control.productionExecution=false` 下运行，安全读取 root-only 环境文件，先验证只读 Token 的 PVE version/有效权限，再原子写入 API 采集所需字段。它不创建或扩大 control ACL、不打开 production、也不启动服务：

```bash
sudo ag-pve pve prepare \
  --tls-server-name pve01.example.com \
  --ca-file /etc/ppflight-agent/pve-root-ca.pem
```

`--tls-server-name` 必须是本机 PVE API 证书覆盖的严格 DNS 名称（不能是 IP、`localhost`、IPv6 或通配符）。它只用于 TLS SNI/证书校验；TCP 仍严格连接 `https://127.0.0.1:8006` 且 dial 为 `tcp4`。若不传且现有配置为空，命令只会尝试本机 FQDN；无法得到受信 DNS 名就拒绝写配置。管理员也可以显式编辑 `/etc/ppflight-agent/agent.yaml`，但必须得到同一结果：将 `pve.source` 改为 `api` 并保持 `mode=test`、`control.productionExecution=false` 做首轮真实只读验证：

```json
{
  "mode": "test",
  "pve": {
    "source": "api",
    "endpoint": "https://127.0.0.1:8006",
    "tlsServerName": "pve01.example.com",
    "tokenIdEnv": "PVE_READ_TOKEN_ID",
    "tokenSecretEnv": "PVE_READ_TOKEN_SECRET",
    "caFile": "/etc/ppflight-agent/pve-root-ca.pem"
  },
  "destinations": {
    "monitoring": {"enabled": false, "url": ""}
  },
  "control": {
    "enabled": true,
    "productionExecution": false,
    "pveTokenIdEnv": "PVE_CONTROL_TOKEN_ID",
    "pveTokenSecretEnv": "PVE_CONTROL_TOKEN_SECRET"
  }
}
```

以上是字段摘要，不是可单独加载的完整配置；请从 [config/agent.example.yaml](../config/agent.example.yaml) 开始修改持久文件。`mode=test` 或 `productionExecution=false` 时 mutation 最多只能产生 dry-run，但 dry-run 仍要求 monitoring 独立绑定和可持久化的 audit sink；缺少审计时必须返回 `AUDIT_UNAVAILABLE`，不能执行或用测试模式绕过。不得将 endpoint 改成官网可访问的 PVE 地址。

## 5. 使用一次性代码绑定官网

先在官网创建一次性绑定码。绑定码不能出现在 argv、URL、环境变量或 shell history。交互式执行命令，再在提示/标准输入中粘贴 code：

```bash
sudo ag-pve bind \
  --endpoint https://www.example/internal/v1/agents/bind \
  --pve-version 9.0.8 \
  --node-ref pve01
```

非交互安装使用 owner-only 临时文件：

```bash
sudo install -m 0600 /dev/null /run/ppflight-binding-code
sudo editor /run/ppflight-binding-code
sudo ag-pve bind \
  --endpoint https://www.example/internal/v1/agents/bind \
  --pve-version 9.0.8 \
  --node-ref pve01 \
  --code-file /run/ppflight-binding-code
sudo shred -u /run/ppflight-binding-code
```

CLI 拒绝额外位置参数，也没有接收 code 值的命令行选项；绑定 endpoint 也不得含 query。只能使用 stdin 或 `--code-file`。

`--code-file` 必须是 regular file、非 symlink，Unix 上 group/other 不得有权限。Agent 在首次请求前将 UUID `requestId` 和 canonical 请求指纹保存到 `<stateDirectory>/bindings/.website-binding-pending.json`，网络失败时相同输入复用该 ID；指纹包含 code，但 code 原文不落盘。绑定成功后，`<stateDirectory>/bindings/binding-state.json` 保存响应的 UUID `bindingId`、匹配的 `deviceId`、官网 identity、五组 endpoint-specific HMAC、Ed25519 验签公钥、initial assignment、exact `networkPolicy={agentObservedIPv4}` 和 `credentialEpoch`；输出不会显示 secret。Agent 保留 hostname 作 Host/TLS SNI/系统 CA 验证，使用 tcp4 并拒绝代理、redirect/跨 origin 与 IPv6 fallback。website policy 不能被 monitoring binding 读取或覆盖。重复绑定需要官网新 code 和显式 `--replace`，响应 epoch 必须单调前进。

安装脚本创建 `/var/lib/ppflight-agent/bindings` 为 `root:ppflight-agent`、`0750`，状态/device/pending 文件为 `0640`。绑定命令由 root 执行；systemd 服务只有组读权限，并以 `ReadOnlyPaths=/var/lib/ppflight-agent/bindings` 禁止写入。远端 assignment 使用独立的 `/var/lib/ppflight-agent/assignments/assignments.json`，目录/文件为 `ppflight-agent:ppflight-agent`、`0750/0640`；不要把 binding 目录改成 service 可写来实现 refresh。

完成后检查：

```bash
sudo ag-pve website show
```

服务启动后可运行第 7 节的 `website status`；它同时汇总脱敏本地 binding、Agent `/status` 和固定同源 `/internal/v1/agents/status`。远端 GET 只使用 Commands HMAC 的 `website:status.read`，还必须回钉本机 binding/device/agent/epoch 和数字 assignment revision。外部 website status 服务未部署时会安全返回不可用并以非零码退出，不表示本地绑定被删除。

官网 bind/replace 不得修改本地 PVE Token，也不得修改独立的监控站绑定状态；它同样不会修改 `pve.source`、`mode`、`productionExecution`、PVE ACL 或 systemd 服务状态。

官网绑定完成后，服务端以可信连接元数据观察并冻结 `agentObservedIPv4/32`，作用域绑定到 `bindingId/deviceId/agentRef`；来源 IP 命中不能替代 TLS、HMAC、Ed25519、epoch、assignment 或时间窗校验。出口地址变化不能静默自动学习，必须显式 rebind/轮换。

## 6. 监控站独立绑定的部署边界

监控站接口为 `POST /internal/v1/monitoring/agents/bind`，使用与官网不同的一次性 code，不要求官网先绑定。请求必须包含 UUID `requestId`、稳定 `deviceId` 和 node/capability 基础字段；响应只含 `bindingId`、匹配的 `deviceId`、`monitoringAgentRef`、ingest endpoint、`hmac-sha256`/base64 credential、`telemetry-v1` compression/大小上限、exact `networkPolicy={agentObservedIPv4}`、`credentialEpoch` 和 `issuedAt`。监控端从可信 `CF-Connecting-IP` 冻结该出口 IPv4/32；Agent 对 ingest/status hostname 使用 tcp4，保留 TLS hostname，并拒绝 proxy/redirect/IPv6 fallback。状态写入 `<stateDirectory>/bindings/monitoring-binding-state.json`；website bind/replace 不能读取、复用或覆盖该 policy。

绑定前必须在将要运行 Agent 的同一台 PVE 上生成可审批的网络证据：

```bash
sudo ag-pve monitoring preflight \
  --endpoint https://moniter.example/internal/v1/monitoring/agents/bind
```

命令只解析 A，并对每个 A 直接执行 tcp4 + 原 hostname/SNI 的系统 CA TLS 检查；不发送 HTTP、不读取绑定码、不写 state/config。输出仅含 `resolvedAt/resolvedA/checks`，不再生成 `eligibleServerIPv4Allowlist` 或 `readyForOperatorApproval`，也不是 bind 前置条件。

本仓 Agent 已提供独立绑定 CLI。确认监控服务端路由已经部署后，交互式执行并在标准输入提示中粘贴 monitoring code：

```bash
sudo ag-pve monitoring bind \
  --endpoint https://monitor.example/internal/v1/monitoring/agents/bind \
  --node-ref pve01
```

非交互安装仍只能使用 owner-only、非 symlink 文件：

```bash
sudo install -m 0600 /dev/null /run/ppflight-monitoring-binding-code
sudo editor /run/ppflight-monitoring-binding-code
sudo ag-pve monitoring bind \
  --endpoint https://monitor.example/internal/v1/monitoring/agents/bind \
  --node-ref pve01 \
  --code-file /run/ppflight-monitoring-binding-code
sudo shred -u /run/ppflight-monitoring-binding-code
```

不要将 code 值作为位置参数或任何 argv 选项，也不要提供 `--pve-version`：CLI 在读取 code 前只调用固定 `/usr/bin/pveversion`，自动规范化可信本机 PVE 8/9 版本；失败、超时、异常输出或非 PVE 主机都会停止且不发送绑定码。成功响应验证通过后，CLI 只更新 monitoring telemetry/audit destinations 并保存独立状态；随后严格回读 config/state/runtime overlay，受控重启 `ppflight-agent.service`，并从本地 `/status` 确认新 `bindingId/credentialEpoch` 已由运行进程加载后才报告成功。失败会恢复旧 config/state、保留私有备份与可重试 pending request，并重新确认旧服务，不打印 secret。audit/status URL 都不是新增响应字段，而是从同 origin 固定派生 `/internal/v1/monitoring/audit-events/batches` 与 `/internal/v1/monitoring/agents/status`。官网 identity/credential 不变。轮换需要新 monitoring code 和 `--replace`。

完成后可运行：

```bash
sudo ag-pve monitoring show
```

服务启动后可运行第 7 节的 `monitoring status`，汇总脱敏 monitoring binding、本地 Agent health/audit queue 和远端只读状态。服务端按路由校验 exact `monitoring:status.read`；相同 key 的写权限仅为 `monitoring:telemetry.write` 与 `monitoring:audit.write`。identity/epoch/time 回钉失败或远端路由尚未部署时命令以安全码和非零状态退出，不打印 HMAC 或上游 body。

monitoring bind 需要单独确认监控服务端观察到的 Agent 出口 IPv4 和 Agent 侧监控 origin/A 记录集合；它不能继承 website whitelist。两套绑定即使当前经同一 NAT 出口，也必须是两个独立授权记录。

两种绑定都要求服务端以 `requestId + deviceId + canonical request hash` 幂等：同请求重放第一次响应，不同 body 冲突；同一 code 并发最多签发一个 binding。服务端不保存 code 原文，但必须加密保存已签发的可重放 credential。完整字段和事务规则见 [Agent API v1 第 2–3 节](AGENT-API-V1.md#2-官网一次性绑定)。

## 7. 启动前验证与多轮 discovery

```bash
sudo systemd-run --wait --pipe --collect \
  --property=User=ppflight-agent \
  --property=EnvironmentFile=/etc/ppflight-agent/agent.env \
  /usr/local/bin/ppflight-agent \
    --config /etc/ppflight-agent/agent.yaml \
    --check-config
sudo systemctl start ppflight-agent
sudo ag-pve pve status
```

root 直接运行 `/usr/local/bin/ppflight-agent --config /etc/ppflight-agent/agent.yaml --check-config` 时，会优先通过 no-follow、owner/mode/link-count 校验读取 root-only `/etc/ppflight-agent/agent.env`，并仅为四个固定 `PVE_*` 名称创建进程内 overlay；sudo 遗留的 ambient PVE 变量不能混入或覆盖该值，Token 不会写回配置、日志、argv 或子进程。非 root 的 service account 无法读取该 0600 文件，必须由 systemd manager 的 `EnvironmentFile=` 提供一套完整凭据；缺少任一所需值会 fail closed，绝不混合环境和文件来源。上面的 transient service 因此是验证实际 service 运行条件的推荐方式。不要用 `env KEY=secret ...` 或命令替换把 Token 值放进 argv。`ag-pve validate` 不替代这项 secret-aware 校验。安装、Token bootstrap、PVE prepare/手工切换 source、双绑定、config check 和 `systemctl start` 必须逐步完成，四项 `AG` 主菜单不会代替这些步骤。

本地 Agent ready 后可分别检查远端状态；外部 status 服务未部署时以下命令按设计非零退出，不影响本地 `/healthz` 事实：

```bash
sudo ag-pve website status
sudo ag-pve monitoring status
```

本机检查：

```bash
curl -4 --fail --cacert /etc/ppflight-agent/pve-root-ca.pem \
  https://127.0.0.1:8006/api2/json/version >/dev/null
curl -4 --fail http://127.0.0.1:9100/metrics >/dev/null
curl -4 --fail http://127.0.0.1:9633/metrics >/dev/null
```

添加 PVE 向导必须用多个只读 `pve.discover` 操作，依次覆盖 `version/permissions`、`nodes/storage/templates`、`networks`、`capacity`、`firewall`、`readiness`。分页 `limit` 省略时为 20，合法范围 1..50。discovery 中不得顺便启用 firewall 或修改资源。

`networks` 后必须让管理员按 `netN` 保存 typed NIC binding：public/private role、primary、metered/monitoring、expected MAC、bridge/vnet、VLAN、MTU 和 IPFilter policy，不能依赖网卡顺序。当前 strict assignment 已验证 interface 唯一、恰有一个 primary public NIC 和一个 monitoring NIC、canonical unicast MAC、bridge xor vnet 和范围。Agent meter 对无 binding、单 NIC 不计费或 mixed metering 多 NIC 强制 shadow；只有所有绑定 NIC 都明确 metered 才可能 active。QGA per-interface counter 只能展示，不能补作账单来源。

Agent website telemetry 已输出 network binding/policy match reason，以及 `lifecycle/rootPasswordReset/guestNetworkVerify/metering` capabilities。APP 还要展示原始 QGA `available/observedAt/freshUntil/unavailableReason` 和依赖动作 `available/observedAt/freshUntil/reason/executionPreflight`；QGA 不可用或过期时，QEMU password reset 和 guest-network verify 必须冻结，纯 PVE lifecycle 不受影响。Executor 已在 QEMU password reset 前读取 QGA command capability；APP 展示、官网向导消费和 guest-network verify 组合编排仍待远端合并。

### 7.1 本机模板初始化

模板 bootstrap 是 PVE 节点 root 管理员主动发起的本地工具，不是官网远程 action。安装器已强制验证同包 vendored bundle、Python 3.9+/Bash 5+、manifest command 和 Perl module 依赖；文件先复制到 `/usr/local/lib/ppflight-agent/template-bundles/<manifest-derived-id>` 的同文件系统 staging 目录并二次校验，再通过 root-owned `/usr/local/lib/ppflight-agent/template-bootstrap` symlink 原子切换。版本目录为 `root:root/0755`，数据/schema 为 `0644`、固定 `.sh/.py` 为 `0755`，group/other 不可写；旧版本保留以保护已解析路径的 in-flight 操作。Agent 每次调用仍会复验 `agent-vendor-manifest.v1.json`、catalog 和全部 manifest 文件的 SHA-256，拒绝内部 symlink、可写组件或摘要不符，再固定执行：

```text
/usr/bin/python3 -I /usr/local/lib/ppflight-agent/template-bootstrap/tools/ppflight-template-bootstrap.py
```

推荐使用交互向导：

```bash
sudo ag
# 选择 1；也可直接运行：
sudo ag-pve template init
```

安装后的 `AG`、`ag`、`ag-pve` 不带参数都会显示同一四项主菜单：模板初始化、官网绑定设置、监控绑定设置、完全卸载。原官网/监控通信状态分别移入对应绑定设置子菜单；未绑定时显示“添加绑定”，已有有效绑定时显示“重新绑定”和“删除绑定”。两个绑定选项仍只在交互提示中读取一次性 code，不会把 code 转成 argv。域级删除分别要求完整输入 `DELETE WEBSITE`/`DELETE MONITORING`，只删除该域本机凭据与派生配置并自动重启回验；另一信任域、稳定 device ID 和持久队列不删除。完全卸载另需输入 `UNINSTALL`。

向导会读取本地 catalog 和 PVE storage discovery，让管理员依次选择模板、镜像缓存 storage、模板磁盘 storage、显式 `required|disabled` 备份策略、备份 storage（required 时）、外网桥和可选内网桥。外网桥用于 `net0`，启用内网时另建 `net1`；二者必须是不同的现有 PVE bridge。选择 `all` 也不会跳过任一 storage 或网络选择。它先输出无副作用 plan；只有核对 VMID/storage/摘要/备份策略/网络角色后输入完整单词 `YES` 才执行，输入 `no` 或直接回车不创建模板。

若 discovery 返回 storage content remediation，`ag` 只会在 `program=pvesm` 且 argv、storage ID、current/required/proposed content 全部严格匹配，存储 active/enabled，且该角色没有其他阻断原因时把它列为“选择后新增”的候选项。选中后会用中文分块显示当前能力、需要新增的能力、完成后的能力和固定命令；只有输入 `Y` 才以固定绝对路径执行，不经 shell，并立即重新 discovery。取消、命令失败或重新检测仍不合格都会停止向导，不会进入模板 plan/execute。

自动化可调用以下固定子命令；不能传 URL、catalog 路径、cache 路径、shell 片段或 replace 选项：

```bash
sudo ag-pve template catalog
sudo ag-pve template discover
sudo ag-pve template bootstrap \
  --image-storage local \
  --template-storage local-lvm \
  --backup-policy required \
  --backup-storage pbs-backup \
  --items all \
  --bridge vmbr0 \
  --internal-bridge vmbr1
```

`bootstrap` 默认为 plan。自动化执行时必须使用相同选择，加 `--execute`，并原样带回 plan 的 `--request-id`、`--operation-id`、`--expected-catalog-revision`、`--expected-catalog-sha256`；缺失或 catalog 漂移应在修改 PVE 前以 exit 2 拒绝。exit 0 表示 catalog/discovery 成功、plan ready 或 execute 全部成功；exit 1 仅表示已进入执行后的 builder/template/backup 失败；业务判断优先使用 stdout strict JSON 的 `state/errorCode`，不能解析 stderr。

helper 只调用本机 `pvesh/pvesm/qm/vzdump` 等固定程序，不读取官网凭据或 PVE API Token。manifest strict 固定 `networkRedirectPolicy` 为 HTTPS-only、`addressFamily=ipv4-only`、`hostPolicy=upstream-selected` 和 catalog/official-checksum 完整性链；实际 curl 固定 `--disable --ipv4`、最多五次 HTTPS redirect。上游可选择 redirect host，但下载内容仍必须通过 catalog SHA-256 与官方 checksum，不能把 redirect 当作任意 URL/代码执行入口。该模板 CLI 不进入 control 的 34 个远程动作，也不表示 `vm.reinstall` 或远程模板创建已经上线；远程 Agent 自升级是独立的 `agent.upgrade` 合同，不能调用此模板 helper，详见 `SELF-UPGRADE-V1.md`。`vm.reinstall` 仍不实现：PVE 恢复/介质切换是非事务性流程，缺少可安全回滚保证，且目前没有可纳入签名命令的安装 ISO/template 介质 allowlist、摘要/来源约束与审批模型；不能把本地 template helper 或任意 URL/storage volume 当作替代。安装与依赖检查已有自动化；发布前仍要在 PVE 8/9 非生产节点验收实际 plan/execute。

### 7.2 systemd watchdog 与重启补报

生产 unit 已透明启用：`Type=notify`、`WatchdogSec=60s`、`Restart=always`、`RestartSec=3s`、`StartLimitIntervalSec=0`。Agent 只有在 tcp4 本地 health listener 已可访问后才发送 `READY=1`；正常停止发送 `STOPPING=1` 并写 clean lifecycle marker。watchdog 依据采集请求级 progress，而不是盲目续租：活动采集超过完整 timeout 没有进展，或空闲循环超过下一次 sample interval 加 timeout 仍无进展，就停止 heartbeat、返回错误并由 systemd 重启。显式 `systemctl stop/disable` 仍保持权威，不会被 restart policy 抵消。

```bash
systemctl show ppflight-agent \
  -p Type -p WatchdogUSec -p Restart -p RestartUSec
systemctl status ppflight-agent
curl -4 --fail http://127.0.0.1:9745/healthz
```

`/var/lib/ppflight-agent/agent/lifecycle-state.json` 会保留未 clean 的上一 session。下次启动在访问 PVE 前把它投影为 `agent.previousExit.<eventId>` / `previous_unclean_exit`；相应 telemetry destination 已启用时，分别持久写入不可淘汰的 website/monitoring lifecycle 队列，未启用的一域继续保持 pending。两域的 queued 标记独立。payload 不上传 crash dump、自由错误文本或旧 guest 快照。Agent 本地检测与双域入队已有 Linux/重启测试，外部接收、展示/告警和真实 kill/hang 演练仍须验收，因此不能把 watchdog 写成远端 HA SLA。

## 8. 官网迁移与 feature flag

推荐顺序：

1. 官网先实现 bind、assignment、commands、receipts 及签名/事务语义；
2. Agent bind 后先做 discovery 和 shadow 上报，upgrade route flag 保持 false；
3. 对账 inventory、typed NIC roles、multi-NIC metering capability、QGA freshness、traffic、generation、sourceRef 与 cutoverAt；
4. 用非生产 PVE 验证 command approval、幂等、资源锁、UPID 重启恢复和回读；
5. 修改动作 cutover 前完成 monitoring 独立绑定、audit outbox、服务端 durable commit 和查询 UI 验收；官网还必须提供 Agent 离线命令持久队列，且任何离线场景都不得回退官网直连 PVE；这不阻止此前的官网绑定、只读 discovery 或 shadow 对账；
6. 按资产开启低风险动作，再迁移 upgrade/IP/firewall/snapshot/backup；
7. 单个资产切换成功后关闭其旧写路径，最后才停止旧客户升级路由。

若 PVE 返回 UPID，`submitted` 只表示接受。Agent 必须持久化 UPID，重启后继续查询同一任务，不能重提 mutation。官网也不能在 `submitted/waiting` 阶段提前提交账务、套餐或 IPAM。

升级所需的 `vm.set-resources`、`vm.resize`、`vm.set-rate`、`vm.set-network` 已在 Agent Executor 实现，并有 registry/validator/dispatch 的逐动作一致性测试；生产开放仍须完成官网编排、审批、回读和逐产品 rollout。官网新 Agent 升级 route 尚未因这些原语自动上线，feature flag 默认关闭；旧客户升级路由继续。

Agent 不可达时，官网目标服务保留尚未过期的签名命令，待 Agent 恢复后由它主动轮询；官网不可达时 Agent 只重试出站连接。命令领取后才进入本地 journal/UPID/receipt 恢复链。服务端离线队列与 command `wait` 仍待官网实现/联调；旧客户升级兼容路径只能按资产显式选择，不能因故障自动变成 PVE 直连 fallback。

## 9. production 执行门槛

只有同时满足以下条件，才可针对已 cutover 资产开启生产写入：

1. `mode=production` 且 `control.productionExecution=true`；
2. website 双向 IPv4 whitelist 已批准，连接无 IPv6 fallback；本机 `bindingId/deviceId/agentRef`、key scope/epoch、HMAC transport、nonce 均匹配；
3. 官网命令为 Ed25519 签名，时间窗、assignment/generation 全部校验；
4. action 在协议、绑定授权与部署 allowlist 中，所有 mutation 有 `approvalRef`；
5. control Token 与 read Token 不同，且 ACL 只覆盖已审批资源；
6. resource lock、command ID conflict、receipt 幂等、UPID reconcile 和 PVE 8/9 测试已通过；
7. monitoring 独立 binding/whitelist 有效，修改命令的脱敏审计能先写入独立 durable outbox，再用 monitoring HMAC 上传 `/internal/v1/monitoring/audit-events/batches`；监控 UI 可按白名单元数据查询；
8. NIC role/IPFilter 已回读；不同策略的多 NIC 不使用 aggregate 计费；QGA-dependent action 有 freshness gate；
9. 官网按资产的 upgrade route feature flag 已显式打开，旧升级写路径已互斥关闭。

Executor 的动作全集和网络/IPFilter 编排见 [Agent API v1](AGENT-API-V1.md)。

## 10. 升级、回滚与卸载 Agent 软件

这里的“升级”指 Agent 二进制，不是客户 VPS 套餐升级。发布流程尚未提供远程自升级 API；管理员应使用已签名/校验的发布物，备份配置与状态，停服务后原子替换二进制，运行 `--check-config`，再启动并检查 `/status`。

不要删除 `/var/lib/ppflight-agent` 中的 queue、control journal、assignment refresh state，或 `/var/lib/ppflight-agent/bindings` 中的 binding state、device ID/pending state。它们用于幂等、UPID 恢复和凭据防回滚。卸载前先确认官网已经接收所有关键队列，并明确是否保留绑定状态。

卸载器会删除 Agent 自带的 `/usr/local/lib/ppflight-agent/create-pve-tokens.sh`、`template-bootstrap` managed link 和 `template-bundles` helper 版本目录；它不会删除已经创建的 PVE user/token/role/ACL，也不会删除 PVE 中已经创建的模板、镜像缓存或备份。是否撤销身份/ACL或清理这些 PVE 资产必须另做清单、审批和显式操作。

## 11. 故障检查

| 现象 | 检查 |
| --- | --- |
| PVE TLS/401/403 | endpoint 必须是 `127.0.0.1:8006`、CA、read Token ID/secret、本地 ACL。 |
| bind 失败 | HTTPS origin、时钟、code 是否过期/已消费；错误故意不回显 code 细节。 |
| bind 后 validate 失败 | 私有 binding state 权限、环境文件权限、官网响应字段/endpoint 同源性。 |
| discovery `INVALID_REQUEST` | phase、scope/nodeRef、cursor；limit 必须为 1..50。 |
| command `rejected` | action/scope、assignment identity、generation、签名、时间窗、approvalRef、allowlist。 |
| task 长时间 waiting | 使用原 UPID 查询 PVE task status；不要重新提交。 |
| Agent/systemd 反复重启 | 检查 `systemctl status/show`、journal 和本地 `/healthz`；watchdog 只在采集有请求级进展时续租。下次启动应把 `agent.previousExit.*` 放入已启用的 website/monitoring lifecycle 队列，未启用域继续保留 pending。 |
| Agent 离线期间有任务 | 官网应保留未过期命令，恢复后由 Agent 主动 poll；不得临时改为官网直连 8006。服务端队列未部署前不要宣称离线控制可用。 |
| audit outbox 增长 | monitoring 独立 binding/epoch、audit endpoint、磁盘和 HMAC；不得删除未 ACK 事件，也不得改用 website credential。 |
| 队列增长 | 出站 DNS/TLS、官网响应、时钟/签名和磁盘；不要直接删除计费/回执队列。 |
| monitoring 无数据 | 独立 monitoring binding 是否成功、`monitoring-binding-state.json`/endpoint/epoch 是否匹配、外部监控服务端路由是否已部署；不要借用官网 credential 绕过。 |
