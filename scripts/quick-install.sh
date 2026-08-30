#!/usr/bin/env bash
# PPFlight Agent integration-test bootstrap for a fresh PVE 8/9 node.
# This script installs and enables the service but deliberately does not start it.
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly RELEASE_TAG='v0.1.0-rc.11'
readonly RELEASE_VERSION='0.1.0-rc.11'
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
    readonly RELEASE_SHA256='19ed933f5d2c71b75ddc3f32ddd58373dfbe217ea86d6d0376be78c76b0fd0ec'
    ;;
  aarch64|arm64)
    readonly RELEASE_ARCH='arm64'
    readonly RELEASE_SHA256='4422880dd5d96fec4d85de9a3c16e9047a33683118ceddc296e3347d71ca3151'
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

printf '\n安装完成，服务尚未启动。现在输入 AG 进入 PPFlight 菜单。\n'
