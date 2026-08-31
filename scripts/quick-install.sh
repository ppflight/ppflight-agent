#!/usr/bin/env bash
# PPFlight Agent integration-test bootstrap for a fresh PVE 8/9 node.
# Installation is complete only after authoritative local PVE collection is
# prepared, enabled for boot and active. No simulator/test source is available.
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly RELEASE_TAG='v0.1.0-rc.16'
readonly RELEASE_VERSION='0.1.0-rc.16'
readonly RELEASE_BASE="https://github.com/ppflight/ppflight-agent/releases/download/$RELEASE_TAG"

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
    readonly RELEASE_SHA256='ac60196c28e5713e113eea874ebb61d83dac933a8ed16fc1341b410e915d02d7'
    ;;
  aarch64|arm64)
    readonly RELEASE_ARCH='arm64'
    readonly RELEASE_SHA256='8fedd724818dc0d746ea5e1cf381238211ab39f9d9804e0025aa59c2190c8b53'
    ;;
  *)
    die "不支持的 CPU 架构: $(uname -m)"
    ;;
esac

readonly ARCHIVE="ppflight-agent-${RELEASE_VERSION}-linux-${RELEASE_ARCH}.tar.gz"
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

binary_sha256="$(cut -d ' ' -f 1 ppflight-agent.sha256)"
scripts/install.sh \
  --binary ./ppflight-agent \
  --binary-sha256 "$binary_sha256" \
  --enable

printf '\n正在自动准备本机真实 PVE 读取、启动服务并校验首次采集...\n'
/usr/local/bin/ag-pve pve prepare --local-only \
  || die '真实 PVE 自动准备失败；Agent 未被报告为就绪，请根据上方安全错误修复后重试安装'

systemctl start ppflight-agent-upgrade.path \
  || die '启动 PPFlight 签名升级监听失败'
systemctl is-enabled --quiet ppflight-agent.service \
  || die 'ppflight-agent.service 未加入开机启动'
systemctl is-enabled --quiet ppflight-agent-upgrade.path \
  || die 'ppflight-agent-upgrade.path 未加入开机启动'
systemctl is-active --quiet ppflight-agent.service \
  || die 'ppflight-agent.service 未成功启动'
systemctl is-active --quiet ppflight-agent-upgrade.path \
  || die 'ppflight-agent-upgrade.path 未成功启动'

printf '\n安装或更新完成：真实 PVE 读取已就绪，Agent 已启动并加入开机启动。现在输入 AG 进入 PPFlight 菜单。\n'
