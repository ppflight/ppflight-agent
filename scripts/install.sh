#!/usr/bin/env bash
# Installs a released PPFlight agent on one PVE 8/9 node. It deliberately does
# not start services unless --start is passed. Run only on the target PVE host.
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly APP='ppflight-agent'
readonly ETC_DIR='/etc/ppflight-agent'
readonly STATE_DIR='/var/lib/ppflight-agent'
readonly LIB_DIR='/usr/local/lib/ppflight-agent'
readonly BIN_PATH='/usr/local/bin/ppflight-agent'
readonly SYSTEMD_DIR='/etc/systemd/system'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
TMP_DIR=''
ENABLE=0
START=0
INSTALL_EXPORTERS=0
INSTALL_SMARTMONTOOLS=0
BINARY=''
BINARY_SHA256=''
RELEASE_URL=''
RELEASE_SHA256=''
CONFIG_FILE="$REPO_DIR/config/agent.example.yaml"
ASSIGNMENTS_FILE="$REPO_DIR/config/assignments.example.yaml"
ENV_FILE="$REPO_DIR/config/agent.env.example"
NODE_ARCHIVE=''
NODE_SHA256=''
SMART_ARCHIVE=''
SMART_SHA256=''

usage() {
  cat <<'EOF'
Usage: sudo scripts/install.sh [options]

Required (choose one):
  --binary FILE                 Pre-built ppflight-agent binary.
  --binary-sha256 HEX           SHA-256 for --binary (required with it).
  --release-url HTTPS_URL       HTTPS URL of a release binary.
  --release-sha256 HEX          SHA-256 for --release-url (required with it).

Optional files:
  --config FILE                 Agent config; default config/agent.example.yaml.
  --assignments FILE            Assignment file; default config/assignments.example.yaml.
  --env-file FILE               Environment-file template; default config/agent.env.example.

Optional exporters (all four archive/checksum arguments are required):
  --install-exporters
  --node-exporter-archive FILE  Verified node_exporter linux archive.
  --node-exporter-sha256 HEX    SHA-256 for node archive.
  --smartctl-exporter-archive FILE
  --smartctl-exporter-sha256 HEX
  --install-smartmontools       Install smartmontools using apt before smartctl exporter.

Activation:
  --enable                      Enable units for boot, but do not start them.
  --start                       Start units now (implies --enable).

The installer never accepts an unverified network download and never replaces
an existing /etc/ppflight-agent/{agent.yaml,assignments.json,agent.env}.
EOF
}

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
note() { printf '%s\n' "$*"; }

cleanup() {
  if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
    rm -rf -- "$TMP_DIR"
  fi
}
trap cleanup EXIT

need_value() {
  [[ $# -ge 2 && -n "$2" ]] || die "missing value for $1"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary) need_value "$@"; BINARY=$2; shift 2 ;;
    --binary-sha256) need_value "$@"; BINARY_SHA256=$2; shift 2 ;;
    --release-url) need_value "$@"; RELEASE_URL=$2; shift 2 ;;
    --release-sha256) need_value "$@"; RELEASE_SHA256=$2; shift 2 ;;
    --config) need_value "$@"; CONFIG_FILE=$2; shift 2 ;;
    --assignments) need_value "$@"; ASSIGNMENTS_FILE=$2; shift 2 ;;
    --env-file) need_value "$@"; ENV_FILE=$2; shift 2 ;;
    --install-exporters) INSTALL_EXPORTERS=1; shift ;;
    --node-exporter-archive) need_value "$@"; NODE_ARCHIVE=$2; shift 2 ;;
    --node-exporter-sha256) need_value "$@"; NODE_SHA256=$2; shift 2 ;;
    --smartctl-exporter-archive) need_value "$@"; SMART_ARCHIVE=$2; shift 2 ;;
    --smartctl-exporter-sha256) need_value "$@"; SMART_SHA256=$2; shift 2 ;;
    --install-smartmontools) INSTALL_SMARTMONTOOLS=1; shift ;;
    --enable) ENABLE=1; shift ;;
    --start) START=1; ENABLE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die 'run as root on the target PVE host'
command -v systemctl >/dev/null || die 'systemd is required'
command -v install >/dev/null || die 'install command is required'
command -v sha256sum >/dev/null || die 'sha256sum is required'
command -v tar >/dev/null || die 'tar is required'
command -v pveversion >/dev/null || die 'this installer must run on Proxmox VE 8 or 9'

pve_version="$(pveversion | sed -n 's/^pve-manager\/\([0-9]\+\).*/\1/p')"
[[ "$pve_version" == '8' || "$pve_version" == '9' ]] || die "unsupported PVE major version ${pve_version:-unknown}; expected 8 or 9"

[[ -f "$CONFIG_FILE" ]] || die "config file not found: $CONFIG_FILE"
[[ -f "$ASSIGNMENTS_FILE" ]] || die "assignments file not found: $ASSIGNMENTS_FILE"
[[ -f "$ENV_FILE" ]] || die "environment template not found: $ENV_FILE"
[[ -z "$BINARY" || -z "$RELEASE_URL" ]] || die 'use either --binary or --release-url, not both'
[[ -n "$BINARY" || -n "$RELEASE_URL" ]] || die 'supply --binary with --binary-sha256, or --release-url with --release-sha256'

valid_sha256() { [[ "$1" =~ ^[A-Fa-f0-9]{64}$ ]]; }
verify_sha256() {
  local file=$1 expected=$2 actual
  valid_sha256 "$expected" || die "invalid SHA-256 value for $file"
  actual="$(sha256sum -- "$file" | awk '{print $1}')"
  [[ "${actual,,}" == "${expected,,}" ]] || die "SHA-256 mismatch for $file"
}

TMP_DIR="$(mktemp -d /tmp/ppflight-agent-install.XXXXXX)"
if [[ -n "$RELEASE_URL" ]]; then
  [[ "$RELEASE_URL" =~ ^https:// ]] || die '--release-url must use HTTPS'
  [[ -n "$RELEASE_SHA256" ]] || die '--release-sha256 is required with --release-url'
  command -v curl >/dev/null || die 'curl is required for --release-url'
  BINARY="$TMP_DIR/$APP"
  curl --fail --location --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 300 --output "$BINARY" "$RELEASE_URL"
  verify_sha256 "$BINARY" "$RELEASE_SHA256"
else
  [[ -n "$BINARY_SHA256" ]] || die '--binary-sha256 is required with --binary'
  [[ -f "$BINARY" ]] || die "agent binary is missing: $BINARY"
  verify_sha256 "$BINARY" "$BINARY_SHA256"
fi
[[ -f "$BINARY" && -x "$BINARY" ]] || die "agent binary is not executable: $BINARY"

if [[ $INSTALL_EXPORTERS -eq 1 ]]; then
  [[ -n "$NODE_ARCHIVE" && -n "$NODE_SHA256" && -n "$SMART_ARCHIVE" && -n "$SMART_SHA256" ]] || die '--install-exporters requires both local exporter archives and their SHA-256 values'
  [[ -f "$NODE_ARCHIVE" && -f "$SMART_ARCHIVE" ]] || die 'an exporter archive is missing'
  verify_sha256 "$NODE_ARCHIVE" "$NODE_SHA256"
  verify_sha256 "$SMART_ARCHIVE" "$SMART_SHA256"
fi

if [[ $INSTALL_SMARTMONTOOLS -eq 1 ]]; then
  command -v apt-get >/dev/null || die '--install-smartmontools currently requires apt-get (Debian-based PVE)'
  DEBIAN_FRONTEND=noninteractive apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends smartmontools
fi

getent group ppflight-agent >/dev/null || groupadd --system ppflight-agent
getent passwd ppflight-agent >/dev/null || useradd --system --gid ppflight-agent --home-dir "$STATE_DIR" --shell /usr/sbin/nologin ppflight-agent
getent group ppflight-nodeexp >/dev/null || groupadd --system ppflight-nodeexp
getent passwd ppflight-nodeexp >/dev/null || useradd --system --gid ppflight-nodeexp --no-create-home --shell /usr/sbin/nologin ppflight-nodeexp

install -d -o root -g ppflight-agent -m 0750 "$ETC_DIR"
install -d -o ppflight-agent -g ppflight-agent -m 0750 "$STATE_DIR"
install -d -o root -g root -m 0755 "$LIB_DIR"
install -m 0755 "$BINARY" "$BIN_PATH"
ln -sfn -- "$BIN_PATH" /usr/local/bin/ag-pve

install_if_absent() {
  local source=$1 target=$2 mode=$3 owner=$4 group=$5
  if [[ -e "$target" ]]; then
    note "preserved existing $target"
  else
    install -o "$owner" -g "$group" -m "$mode" "$source" "$target"
  fi
}
install_if_absent "$CONFIG_FILE" "$ETC_DIR/agent.yaml" 0640 root ppflight-agent
install_if_absent "$ASSIGNMENTS_FILE" "$ETC_DIR/assignments.json" 0640 root ppflight-agent
install_if_absent "$ENV_FILE" "$ETC_DIR/agent.env" 0600 root root
install_if_absent /etc/pve/pve-root-ca.pem "$ETC_DIR/pve-root-ca.pem" 0644 root root

install -m 0644 "$REPO_DIR/packaging/systemd/ppflight-agent.service" "$SYSTEMD_DIR/ppflight-agent.service"

if [[ $INSTALL_EXPORTERS -eq 1 ]]; then
  extract_binary() {
    local archive=$1 binary_name=$2 output=$3 extract_dir
    extract_dir="$(mktemp -d "$TMP_DIR/extract.XXXXXX")"
    tar -xzf "$archive" -C "$extract_dir"
    local found
    found="$(find "$extract_dir" -type f -name "$binary_name" -perm -u+x -print -quit)"
    [[ -n "$found" ]] || die "archive does not contain executable $binary_name"
    install -o root -g root -m 0755 "$found" "$output"
  }
  extract_binary "$NODE_ARCHIVE" node_exporter "$LIB_DIR/node_exporter"
  extract_binary "$SMART_ARCHIVE" smartctl_exporter "$LIB_DIR/smartctl_exporter"
  install -m 0644 "$REPO_DIR/packaging/systemd/ppflight-node-exporter.service" "$SYSTEMD_DIR/ppflight-node-exporter.service"
  install -m 0644 "$REPO_DIR/packaging/systemd/ppflight-smartctl-exporter.service" "$SYSTEMD_DIR/ppflight-smartctl-exporter.service"
fi

systemctl daemon-reload
if [[ $ENABLE -eq 1 ]]; then
  systemctl enable ppflight-agent.service
  if [[ $INSTALL_EXPORTERS -eq 1 ]]; then
    systemctl enable ppflight-node-exporter.service ppflight-smartctl-exporter.service
  fi
fi
if [[ $START -eq 1 ]]; then
  systemctl start ppflight-agent.service
  if [[ $INSTALL_EXPORTERS -eq 1 ]]; then
    systemctl start ppflight-node-exporter.service ppflight-smartctl-exporter.service
  fi
fi

note "Installed $APP for PVE $pve_version. No service was started unless --start was supplied."
note "Before production: set mode=production, pve.source=api, enable exporters/destinations, replace example identifiers, and validate with: $BIN_PATH --config $ETC_DIR/agent.yaml --check-config"
