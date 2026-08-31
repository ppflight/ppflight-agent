#!/usr/bin/env bash
# PPFlight Agent integration-test bootstrap for a fresh PVE 8/9 node.
# Installation is complete only after authoritative local PVE collection is
# prepared, enabled for boot and active. No simulator/test source is available.
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly RELEASE_TAG='v0.1.0-rc.18'
readonly RELEASE_VERSION='0.1.0-rc.18'
readonly RELEASE_BASE="https://github.com/ppflight/ppflight-agent/releases/download/$RELEASE_TAG"
readonly NODE_EXPORTER_VERSION='1.12.1'
readonly NODE_EXPORTER_BASE="https://github.com/prometheus/node_exporter/releases/download/v$NODE_EXPORTER_VERSION"
readonly SMARTCTL_EXPORTER_VERSION='0.14.0'
readonly SMARTCTL_EXPORTER_BASE="https://github.com/prometheus-community/smartctl_exporter/releases/download/v$SMARTCTL_EXPORTER_VERSION"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

[[ ${EUID:-$(id -u)} -eq 0 ]] || die '请在 PVE root 终端执行'

for required_command in curl sha256sum tar mktemp uname cut; do
  command -v "$required_command" >/dev/null 2>&1 || die "缺少命令: $required_command"
done

case "$(uname -m)" in
  x86_64|amd64)
    readonly RELEASE_ARCH='amd64'
    readonly RELEASE_SHA256='4836b8508776173a18b5659dc87321b3893f1a812cab154a346f1c61967cf73d'
    readonly NODE_EXPORTER_SHA256='b51d8a76aa2a9156a55d501aca6276fae09e262259a5e4e831d2c2222f084e63'
    readonly SMARTCTL_EXPORTER_SHA256='875983cd27affc5a682401930e5a8eea3f06c325fe6d6a7228c5547d882685b3'
    ;;
  aarch64|arm64)
    readonly RELEASE_ARCH='arm64'
    readonly RELEASE_SHA256='284805c5218d7f89aa32bad71462c84ba528e899637200b196acb99a6717d6d4'
    readonly NODE_EXPORTER_SHA256='ad35b605f9954b9f1ffddf5ba054bdc5a98d790b9eae5291e1eeb83f1ecbd0e7'
    readonly SMARTCTL_EXPORTER_SHA256='27353b3adca7f54dd486417412041a17260709c724ea63f5138df2612ecf4299'
    ;;
  *)
    die "不支持的 CPU 架构: $(uname -m)"
    ;;
esac

readonly ARCHIVE="ppflight-agent-${RELEASE_VERSION}-linux-${RELEASE_ARCH}.tar.gz"
readonly NODE_EXPORTER_ARCHIVE="node_exporter-${NODE_EXPORTER_VERSION}.linux-${RELEASE_ARCH}.tar.gz"
readonly SMARTCTL_EXPORTER_ARCHIVE="smartctl_exporter-${SMARTCTL_EXPORTER_VERSION}.linux-${RELEASE_ARCH}.tar.gz"
INSTALL_TEMP_DIR="$(mktemp -d /tmp/ppflight-agent-install.XXXXXX)"
readonly INSTALL_TEMP_DIR

cleanup() {
  rm -rf -- "$INSTALL_TEMP_DIR"
}
trap cleanup EXIT

cd -- "$INSTALL_TEMP_DIR"
printf '正在下载 PPFlight Agent %s (%s)...\n' "$RELEASE_TAG" "$RELEASE_ARCH"
curl \
  --disable \
  --ipv4 \
  --fail \
  --show-error \
  --silent \
  --location \
  --max-redirs 5 \
  --proto '=https' \
  --proto-redir '=https' \
  --tlsv1.2 \
  --connect-timeout 15 \
  --max-time 180 \
  --retry 3 \
  --retry-all-errors \
  "$RELEASE_BASE/$ARCHIVE" \
  --output "$ARCHIVE"

printf '%s  %s\n' "$RELEASE_SHA256" "$ARCHIVE" | sha256sum --check --status - \
  || die '发布包 SHA-256 校验失败'

tar -xzf "$ARCHIVE"
cd ppflight-agent
sha256sum --check --status ppflight-agent.sha256 \
  || die '包内 Agent 二进制 SHA-256 校验失败'

download_verified() {
  local url=$1 output=$2 expected=$3 label=$4
  curl \
    --disable \
    --ipv4 \
    --fail \
    --show-error \
    --silent \
    --location \
    --max-redirs 5 \
    --proto '=https' \
    --proto-redir '=https' \
    --tlsv1.2 \
    --connect-timeout 15 \
    --max-time 180 \
    --retry 3 \
    --retry-all-errors \
    "$url" \
    --output "$output"
  printf '%s  %s\n' "$expected" "$output" | sha256sum --check --status - \
    || die "$label SHA-256 校验失败"
}

readonly NODE_EXPORTER_PATH="$INSTALL_TEMP_DIR/$NODE_EXPORTER_ARCHIVE"
readonly SMARTCTL_EXPORTER_PATH="$INSTALL_TEMP_DIR/$SMARTCTL_EXPORTER_ARCHIVE"
printf '正在下载固定版本 node_exporter %s 和 smartctl_exporter %s...\n' "$NODE_EXPORTER_VERSION" "$SMARTCTL_EXPORTER_VERSION"
download_verified "$NODE_EXPORTER_BASE/$NODE_EXPORTER_ARCHIVE" "$NODE_EXPORTER_PATH" "$NODE_EXPORTER_SHA256" 'node_exporter'
download_verified "$SMARTCTL_EXPORTER_BASE/$SMARTCTL_EXPORTER_ARCHIVE" "$SMARTCTL_EXPORTER_PATH" "$SMARTCTL_EXPORTER_SHA256" 'smartctl_exporter'

binary_sha256="$(cut -d ' ' -f 1 ppflight-agent.sha256)"
scripts/install.sh \
  --binary ./ppflight-agent \
  --binary-sha256 "$binary_sha256" \
  --install-exporters \
  --node-exporter-archive "$NODE_EXPORTER_PATH" \
  --node-exporter-sha256 "$NODE_EXPORTER_SHA256" \
  --smartctl-exporter-archive "$SMARTCTL_EXPORTER_PATH" \
  --smartctl-exporter-sha256 "$SMARTCTL_EXPORTER_SHA256" \
  --install-smartmontools \
  --enable

systemctl start ppflight-node-exporter.service ppflight-smartctl-exporter.service \
  || die '启动本机指标采集服务失败'
systemctl is-active --quiet ppflight-node-exporter.service \
  || die 'ppflight-node-exporter.service 未成功启动'
systemctl is-active --quiet ppflight-smartctl-exporter.service \
  || die 'ppflight-smartctl-exporter.service 未成功启动'

node_metrics="$INSTALL_TEMP_DIR/node-exporter.metrics"
node_network_ready=0
for ((attempt = 0; attempt < 15; attempt++)); do
  if curl --disable --ipv4 --fail --silent --show-error --max-time 5 \
      http://127.0.0.1:9100/metrics --output "$node_metrics" \
      && grep -q '^node_network_receive_bytes_total{' "$node_metrics" \
      && grep -q '^node_network_transmit_bytes_total{' "$node_metrics" \
      && grep -q '^node_disk_read_bytes_total{' "$node_metrics" \
      && grep -q '^node_disk_written_bytes_total{' "$node_metrics"; then
    node_network_ready=1
    break
  fi
  sleep 1
done
[[ $node_network_ready -eq 1 ]] \
  || die 'node_exporter 未提供网卡与硬盘累计字节指标，Agent 不能报告真实带宽或硬盘 IO'

smart_metrics="$INSTALL_TEMP_DIR/smartctl-exporter.metrics"
smart_ready=0
for ((attempt = 0; attempt < 15; attempt++)); do
  if curl --disable --ipv4 --fail --silent --show-error --max-time 10 \
      http://127.0.0.1:9633/metrics --output "$smart_metrics" \
      && grep -Eq '^smartctl_device_(info|smart_status)\{' "$smart_metrics"; then
    smart_ready=1
    break
  fi
  sleep 1
done
[[ $smart_ready -eq 1 ]] \
  || die 'smartctl_exporter 未发现任何可读硬盘；请先确认 smartctl --scan-open 能识别物理磁盘，然后重新安装'

printf '\n正在自动准备本机真实 PVE 读取、启动服务并校验首次采集...\n'
/usr/local/bin/ag-pve pve prepare --local-only \
  || die '真实 PVE 自动准备失败；Agent 未被报告为就绪，请根据上方安全错误修复后重试安装'

systemctl start ppflight-agent-upgrade.path \
  || die '启动 PPFlight 签名升级监听失败'
systemctl is-enabled --quiet ppflight-agent.service \
  || die 'ppflight-agent.service 未加入开机启动'
systemctl is-enabled --quiet ppflight-agent-upgrade.path \
  || die 'ppflight-agent-upgrade.path 未加入开机启动'
systemctl is-enabled --quiet ppflight-node-exporter.service \
  || die 'ppflight-node-exporter.service 未加入开机启动'
systemctl is-enabled --quiet ppflight-smartctl-exporter.service \
  || die 'ppflight-smartctl-exporter.service 未加入开机启动'
systemctl is-active --quiet ppflight-agent.service \
  || die 'ppflight-agent.service 未成功启动'
systemctl is-active --quiet ppflight-agent-upgrade.path \
  || die 'ppflight-agent-upgrade.path 未成功启动'
systemctl is-active --quiet ppflight-node-exporter.service \
  || die 'ppflight-node-exporter.service 未成功启动'
systemctl is-active --quiet ppflight-smartctl-exporter.service \
  || die 'ppflight-smartctl-exporter.service 未成功启动'

printf '\n安装或更新完成：真实 PVE 读取已就绪，Agent 已启动并加入开机启动。现在输入 AG 进入 PPFlight 菜单。\n'
