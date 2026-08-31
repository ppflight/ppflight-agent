#!/usr/bin/env bash
# Installs a released PPFlight agent on one PVE 8/9 node. It deliberately does
# not start services unless --start is passed. Run only on the target PVE host.
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly APP='ppflight-agent'
readonly ETC_DIR='/etc/ppflight-agent'
readonly STATE_DIR='/var/lib/ppflight-agent'
readonly AGENT_STATE_DIR="$STATE_DIR/agent"
readonly BINDINGS_DIR="$STATE_DIR/bindings"
readonly ASSIGNMENTS_DIR="$STATE_DIR/assignments"
readonly UPGRADES_DIR="$STATE_DIR/upgrades"
readonly UPGRADE_PENDING_DIR="$UPGRADES_DIR/pending"
readonly UPGRADE_RESULTS_DIR="$UPGRADES_DIR/results"
readonly UPGRADE_BACKUPS_DIR="$UPGRADES_DIR/backups"
readonly ASSIGNMENTS_PATH="$ASSIGNMENTS_DIR/assignments.json"
readonly LEGACY_ASSIGNMENTS_PATH="$ETC_DIR/assignments.json"
readonly LIB_DIR='/usr/local/lib/ppflight-agent'
readonly TEMPLATE_BUNDLES_DIR="$LIB_DIR/template-bundles"
readonly TEMPLATE_LINK="$LIB_DIR/template-bootstrap"
readonly PVE_BOOTSTRAP_HELPER="$LIB_DIR/create-pve-tokens.sh"
readonly PVE_REMOVE_HELPER="$LIB_DIR/remove-pve-credentials.sh"
readonly UNINSTALL_HELPER="$LIB_DIR/uninstall.sh"
readonly BIN_PATH='/usr/local/bin/ppflight-agent'
readonly SYSTEMD_DIR='/etc/systemd/system'
readonly TMPFILES_DIR='/usr/lib/tmpfiles.d'
readonly TMPFILES_PATH="$TMPFILES_DIR/ppflight-agent.conf"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
readonly TEMPLATE_SOURCE="$REPO_DIR/bundles/ppflight-cloudinit"
readonly TEMPLATE_VERIFIER="$REPO_DIR/scripts/verify-template-bundle.py"
TMP_DIR=''
TEMPLATE_STAGE=''
TEMPLATE_LINK_STAGE=''
ENABLE=0
START=0
SERVICE_WAS_ACTIVE=0
SERVICE_RESTARTED=0
PVE_PREPARATION_REQUIRED=0
INSTALL_EXPORTERS=0
INSTALL_SMARTMONTOOLS=0
BINARY=''
BINARY_SHA256=''
RELEASE_URL=''
RELEASE_SHA256=''
CONFIG_FILE="$REPO_DIR/config/agent.example.yaml"
ASSIGNMENTS_FILE="$REPO_DIR/config/assignments.example.yaml"
ASSIGNMENTS_EXPLICIT=0
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
  --assignments FILE            Initial assignment file; default config/assignments.example.yaml.
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
an existing agent.yaml, agent.env, or state assignments/assignments.json.
EOF
}

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
note() { printf '%s\n' "$*"; }

cleanup() {
  local exit_status=$?
  if [[ -n "$TEMPLATE_LINK_STAGE" ]]; then
    case "$TEMPLATE_LINK_STAGE" in
      "$LIB_DIR"/.template-bootstrap-link.*)
        [[ -L "$TEMPLATE_LINK_STAGE" ]] && rm -f -- "$TEMPLATE_LINK_STAGE"
        ;;
    esac
  fi
  if [[ -n "$TEMPLATE_STAGE" ]]; then
    case "$TEMPLATE_STAGE" in
      "$TEMPLATE_BUNDLES_DIR"/.template-bootstrap-stage.*)
        [[ ! -L "$TEMPLATE_STAGE" && -d "$TEMPLATE_STAGE" ]] && rm -rf -- "$TEMPLATE_STAGE"
        ;;
    esac
  fi
  if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
    rm -rf -- "$TMP_DIR"
  fi
  if [[ $SERVICE_WAS_ACTIVE -eq 1 && $SERVICE_RESTARTED -eq 0 ]]; then
    systemctl start ppflight-agent.service >/dev/null 2>&1 || true
  fi
  return "$exit_status"
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
    --assignments) need_value "$@"; ASSIGNMENTS_FILE=$2; ASSIGNMENTS_EXPLICIT=1; shift 2 ;;
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
command -v systemd-tmpfiles >/dev/null || die 'systemd-tmpfiles is required'
command -v install >/dev/null || die 'install command is required'
command -v sha256sum >/dev/null || die 'sha256sum is required'
command -v tar >/dev/null || die 'tar is required'
command -v python3 >/dev/null || die 'python3 is required for the bundled template workflow'
command -v pveversion >/dev/null || die 'this installer must run on Proxmox VE 8 or 9'
(( BASH_VERSINFO[0] >= 5 )) || die 'bash 5 or newer is required for the bundled template workflow'
python3 -I -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' || die 'python 3.9 or newer is required for the bundled template workflow'

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
[[ -f "$TEMPLATE_VERIFIER" && ! -L "$TEMPLATE_VERIFIER" ]] || die 'template bundle verifier is missing or unsafe'
[[ -d "$TEMPLATE_SOURCE" && ! -L "$TEMPLATE_SOURCE" ]] || die 'vendored template bundle is missing or unsafe'
python3 -I "$TEMPLATE_VERIFIER" verify "$TEMPLATE_SOURCE" >/dev/null || die 'vendored template bundle verification failed'
TEMPLATE_BUNDLE_ID="$(python3 -I "$TEMPLATE_VERIFIER" bundle-id "$TEMPLATE_SOURCE")" || die 'cannot identify vendored template bundle'
[[ "$TEMPLATE_BUNDLE_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]{1,127}$ ]] || die 'vendored template bundle ID is invalid'
python3 -I "$TEMPLATE_VERIFIER" list "$TEMPLATE_SOURCE" > "$TMP_DIR/template-files" || die 'cannot list vendored template files'
python3 -I "$TEMPLATE_VERIFIER" commands "$TEMPLATE_SOURCE" > "$TMP_DIR/template-commands" || die 'cannot list template dependencies'
python3 -I "$TEMPLATE_VERIFIER" perl-modules "$TEMPLATE_SOURCE" > "$TMP_DIR/template-perl-modules" || die 'cannot list template Perl dependencies'
while IFS= read -r dependency; do
  [[ -n "$dependency" ]] || die 'template command dependency is empty'
  command -v "$dependency" >/dev/null || die "template workflow dependency is missing: $dependency"
done < "$TMP_DIR/template-commands"
while IFS= read -r module; do
  [[ -n "$module" ]] || die 'template Perl module dependency is empty'
  perl "-M$module" -e 1 >/dev/null 2>&1 || die "template Perl dependency is missing: $module"
done < "$TMP_DIR/template-perl-modules"
if [[ -n "$RELEASE_URL" ]]; then
  [[ "$RELEASE_URL" =~ ^https:// ]] || die '--release-url must use HTTPS'
  [[ -n "$RELEASE_SHA256" ]] || die '--release-sha256 is required with --release-url'
  command -v curl >/dev/null || die 'curl is required for --release-url'
  BINARY="$TMP_DIR/$APP"
  curl --disable --ipv4 --fail --location --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 300 --output "$BINARY" "$RELEASE_URL"
  verify_sha256 "$BINARY" "$RELEASE_SHA256"
else
  [[ -n "$BINARY_SHA256" ]] || die '--binary-sha256 is required with --binary'
  [[ -f "$BINARY" ]] || die "agent binary is missing: $BINARY"
  verify_sha256 "$BINARY" "$BINARY_SHA256"
fi
# The source mode is not authoritative: curl and ordinary release downloads
# commonly create a verified binary as 0600/0644. The root-owned destination is
# made executable explicitly by install(1) below, after SHA-256 verification.
[[ -f "$BINARY" ]] || die "agent binary is not a regular file: $BINARY"

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

for managed_directory in "$ETC_DIR" "$STATE_DIR" "$AGENT_STATE_DIR" "$BINDINGS_DIR" "$ASSIGNMENTS_DIR" "$UPGRADES_DIR" "$UPGRADE_PENDING_DIR" "$UPGRADE_RESULTS_DIR" "$UPGRADE_BACKUPS_DIR"; do
  [[ ! -L "$managed_directory" ]] || die "refusing symlink at managed directory: $managed_directory"
  [[ ! -e "$managed_directory" || -d "$managed_directory" ]] || die "managed path is not a directory: $managed_directory"
done
install -d -o root -g ppflight-agent -m 0750 "$ETC_DIR"
if systemctl is-active --quiet ppflight-agent.service; then
  SERVICE_WAS_ACTIVE=1
  systemctl stop ppflight-agent.service
fi
install -d -o root -g ppflight-agent -m 0750 "$STATE_DIR"
install -d -o ppflight-agent -g ppflight-agent -m 0700 "$AGENT_STATE_DIR"

# RC.9 and earlier wrote unprivileged runtime data directly below STATE_DIR.
# Move only the exact allowlisted paths while the service is stopped. Refuse
# ambiguous or redirected state instead of merging two histories.
for legacy_name in .agent.lock queues meter run-state.json control lifecycle-state.json; do
  legacy_path="$STATE_DIR/$legacy_name"
  target_path="$AGENT_STATE_DIR/$legacy_name"
  if [[ -e "$legacy_path" || -L "$legacy_path" ]]; then
    [[ ! -L "$legacy_path" ]] || die "refusing symlink at legacy agent state: $legacy_path"
    [[ ! -e "$target_path" && ! -L "$target_path" ]] || die "both legacy and current agent state exist for $legacy_name"
    mv -- "$legacy_path" "$target_path"
  fi
done
# Binding credentials are written by the root-run ag-pve command and read by
# the service. The service group deliberately has no write permission here.
install -d -o root -g ppflight-agent -m 0750 "$BINDINGS_DIR"
install -d -o ppflight-agent -g ppflight-agent -m 0750 "$ASSIGNMENTS_DIR"
install -d -o root -g ppflight-agent -m 0750 "$UPGRADES_DIR"
install -d -o ppflight-agent -g ppflight-agent -m 0700 "$UPGRADE_PENDING_DIR" "$UPGRADE_RESULTS_DIR"
install -d -o root -g root -m 0700 "$UPGRADE_BACKUPS_DIR"
install -d -o root -g root -m 0755 "$LIB_DIR"
install -d -o root -g root -m 0755 "$TEMPLATE_BUNDLES_DIR"
install -d -o root -g root -m 0755 "$TMPFILES_DIR"
install -m 0755 "$BINARY" "$BIN_PATH"
install -o root -g root -m 0700 "$REPO_DIR/scripts/create-pve-tokens.sh" "$PVE_BOOTSTRAP_HELPER"
install -o root -g root -m 0700 "$REPO_DIR/scripts/remove-pve-credentials.sh" "$PVE_REMOVE_HELPER"
install -o root -g root -m 0700 "$REPO_DIR/scripts/uninstall.sh" "$UNINSTALL_HELPER"
ln -sfn -- "$BIN_PATH" /usr/local/bin/ag-pve
ln -sfn -- "$BIN_PATH" /usr/local/bin/ag
ln -sfn -- "$BIN_PATH" /usr/local/bin/AG

# Install the complete hash-verified cloud-template bundle into an immutable
# version directory. Switching the root-owned symlink is atomic, so AG never
# observes files from two bundle versions during an Agent upgrade. Old version
# directories are intentionally retained; an in-flight privileged helper may
# still have resolved one of them before the switch.
TEMPLATE_STAGE="$(mktemp -d "$TEMPLATE_BUNDLES_DIR/.template-bootstrap-stage.XXXXXX")"
chmod 0755 "$TEMPLATE_STAGE"
while IFS= read -r relative; do
  [[ -n "$relative" && "$relative" != /* && "$relative" != *'..'* && "$relative" != *'\\'* ]] || die 'template file list contains an unsafe path'
  destination="$TEMPLATE_STAGE/$relative"
  install -d -o root -g root -m 0755 "$(dirname -- "$destination")"
  file_mode=0644
  case "$relative" in
    *.sh|*.py) file_mode=0755 ;;
  esac
  install -o root -g root -m "$file_mode" "$TEMPLATE_SOURCE/$relative" "$destination"
done < "$TMP_DIR/template-files"
install -o root -g root -m 0644 "$TEMPLATE_SOURCE/agent-vendor-manifest.v1.json" "$TEMPLATE_STAGE/agent-vendor-manifest.v1.json"
python3 -I "$TEMPLATE_VERIFIER" verify "$TEMPLATE_STAGE" >/dev/null || die 'staged template bundle verification failed'
TEMPLATE_TARGET="$TEMPLATE_BUNDLES_DIR/$TEMPLATE_BUNDLE_ID"
if [[ -e "$TEMPLATE_TARGET" ]]; then
  [[ ! -L "$TEMPLATE_TARGET" && -d "$TEMPLATE_TARGET" ]] || die 'existing template bundle target is unsafe'
  python3 -I "$TEMPLATE_VERIFIER" verify "$TEMPLATE_TARGET" >/dev/null || die 'existing template bundle target failed verification'
  rm -rf -- "$TEMPLATE_STAGE"
  TEMPLATE_STAGE=''
else
  mv -- "$TEMPLATE_STAGE" "$TEMPLATE_TARGET"
  TEMPLATE_STAGE=''
fi
[[ ! -e "$TEMPLATE_LINK" || -L "$TEMPLATE_LINK" ]] || die 'refusing to replace a non-symlink template bundle path'
template_link_stage="$LIB_DIR/.template-bootstrap-link.$$"
[[ ! -e "$template_link_stage" && ! -L "$template_link_stage" ]] || die 'temporary template link already exists'
ln -s -- "$TEMPLATE_TARGET" "$template_link_stage"
TEMPLATE_LINK_STAGE="$template_link_stage"
mv -Tf -- "$template_link_stage" "$TEMPLATE_LINK"
TEMPLATE_LINK_STAGE=''
install -o root -g root -m 0644 "$REPO_DIR/packaging/tmpfiles.d/ppflight-agent.conf" "$TMPFILES_PATH"
systemd-tmpfiles --create "$TMPFILES_PATH"

install_if_absent() {
  local source=$1 target=$2 mode=$3 owner=$4 group=$5
  [[ ! -L "$target" ]] || die "refusing symlink at managed file: $target"
  if [[ -e "$target" ]]; then
    note "preserved existing $target"
  else
    install -o "$owner" -g "$group" -m "$mode" "$source" "$target"
  fi
}
install_if_absent "$CONFIG_FILE" "$ETC_DIR/agent.yaml" 0640 root ppflight-agent
install_if_absent "$ENV_FILE" "$ETC_DIR/agent.env" 0600 root root
install_if_absent /etc/pve/pve-root-ca.pem "$ETC_DIR/pve-root-ca.pem" 0644 root root

assignment_source="$ASSIGNMENTS_FILE"
if [[ $ASSIGNMENTS_EXPLICIT -eq 0 && ! -e "$ASSIGNMENTS_PATH" && -e "$LEGACY_ASSIGNMENTS_PATH" ]]; then
  [[ ! -L "$LEGACY_ASSIGNMENTS_PATH" && -f "$LEGACY_ASSIGNMENTS_PATH" ]] || die "legacy assignment path is unsafe: $LEGACY_ASSIGNMENTS_PATH"
  assignment_source="$LEGACY_ASSIGNMENTS_PATH"
  note "migrating existing assignments from $LEGACY_ASSIGNMENTS_PATH"
fi
install_if_absent "$assignment_source" "$ASSIGNMENTS_PATH" 0640 ppflight-agent ppflight-agent

ensure_regular_metadata() {
  local target=$1 mode=$2 owner=$3 group=$4
  [[ ! -L "$target" ]] || die "refusing symlink at managed file: $target"
  [[ ! -e "$target" || -f "$target" ]] || die "managed path is not a regular file: $target"
  if [[ -e "$target" ]]; then
    chown -- "$owner:$group" "$target"
    chmod -- "$mode" "$target"
  fi
}

# Preserve file contents on upgrades while repairing the exact metadata that
# permits the unprivileged service to read root-written state.
ensure_regular_metadata "$ASSIGNMENTS_PATH" 0640 ppflight-agent ppflight-agent
for binding_file in \
  binding-state.json \
  monitoring-binding-state.json \
  device-id \
  .website-binding-pending.json \
  .monitoring-binding-pending.json \
  .website-binding-commit.json \
  .monitoring-binding-commit.json \
  .website-unbind-commit.json \
  .monitoring-unbind-commit.json; do
  ensure_regular_metadata "$BINDINGS_DIR/$binding_file" 0640 root ppflight-agent
done

# Releases before RC.13 could leave test mode or a generated snapshot source in
# the public config. Convert either legacy state to production+disabled while
# the service is stopped; local PVE readiness must explicitly re-enable api.
# Preserve every other field, binding and private credential.
migrate_legacy_source() {
  local target=$1
  [[ ! -L "$target" && -f "$target" ]] || die "agent config is not a safe regular file: $target"
  python3 -I - "$target" <<'PY'
import json
import os
import stat
import sys
import tempfile

target = sys.argv[1]
directory = os.path.dirname(target)
flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(target, flags)
try:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise SystemExit("agent config is not a safe regular file")
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o640:
        raise SystemExit("agent config owner or mode is unsafe")
    raw = os.read(descriptor, 1 << 20 | 1)
finally:
    os.close(descriptor)
if len(raw) > 1 << 20:
    raise SystemExit("agent config is too large")
try:
    document = json.loads(raw.decode("utf-8"))
    mode = document["mode"]
    source = document["pve"]["source"]
except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
    raise SystemExit("agent config cannot be safely parsed") from error
if source == "simulator" or mode == "test":
    document["mode"] = "production"
    document["pve"]["source"] = "disabled"
    replacement, temporary = tempfile.mkstemp(prefix=".agent.yaml.rc13.", dir=directory)
    try:
        os.fchmod(replacement, 0o640)
        os.fchown(replacement, metadata.st_uid, metadata.st_gid)
        with os.fdopen(replacement, "w", encoding="utf-8", closefd=False) as output:
            json.dump(document, output, indent=2, sort_keys=False)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.close(replacement)
        replacement = -1
        os.replace(temporary, target)
        directory_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if replacement != -1:
            os.close(replacement)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    source = "disabled"
    mode = "production"
if source not in {"api", "disabled"}:
    raise SystemExit("invalid pve.source in existing Agent config")
if mode != "production":
    raise SystemExit("invalid mode in existing Agent config")
print(source)
PY
}

pve_source="$(migrate_legacy_source "$ETC_DIR/agent.yaml")" || die 'cannot safely inspect or migrate existing Agent pve.source'
if [[ "$pve_source" == 'disabled' ]]; then
  PVE_PREPARATION_REQUIRED=1
  # Never let the EXIT trap resurrect an old process after the source was
  # explicitly disabled.  The operator completes readiness through AG.
  SERVICE_RESTARTED=1
fi

install -m 0644 "$REPO_DIR/packaging/systemd/ppflight-agent.service" "$SYSTEMD_DIR/ppflight-agent.service"
install -m 0644 "$REPO_DIR/packaging/systemd/ppflight-agent-upgrade.path" "$SYSTEMD_DIR/ppflight-agent-upgrade.path"
install -m 0644 "$REPO_DIR/packaging/systemd/ppflight-agent-upgrade.service" "$SYSTEMD_DIR/ppflight-agent-upgrade.service"

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
service_user="$(systemctl show --property=User --value ppflight-agent.service)"
[[ "$service_user" == 'ppflight-agent' ]] || die "ppflight-agent.service must run as User=ppflight-agent (effective User=${service_user:-unset})"
upgrade_user="$(systemctl show --property=User --value ppflight-agent-upgrade.service)"
[[ "$upgrade_user" == 'root' ]] || die "ppflight-agent-upgrade.service must run as User=root (effective User=${upgrade_user:-unset})"
if [[ $ENABLE -eq 1 ]]; then
  systemctl enable ppflight-agent.service ppflight-agent-upgrade.path
  if [[ $INSTALL_EXPORTERS -eq 1 ]]; then
    systemctl enable ppflight-node-exporter.service ppflight-smartctl-exporter.service
  fi
fi
if [[ $START -eq 1 && $PVE_PREPARATION_REQUIRED -eq 0 ]]; then
  systemctl start ppflight-agent-upgrade.path ppflight-agent.service
  if [[ $INSTALL_EXPORTERS -eq 1 ]]; then
    systemctl start ppflight-node-exporter.service ppflight-smartctl-exporter.service
  fi
fi
if [[ $PVE_PREPARATION_REQUIRED -eq 0 && $SERVICE_WAS_ACTIVE -eq 1 && $START -eq 0 ]]; then
  systemctl start ppflight-agent-upgrade.path ppflight-agent.service
  SERVICE_RESTARTED=1
elif [[ $START -eq 1 ]]; then
  SERVICE_RESTARTED=1
fi

if [[ $PVE_PREPARATION_REQUIRED -eq 1 ]]; then
  note "Installed $APP for PVE $pve_version. PVE collection is disabled and the service remains stopped until the caller completes verified local PVE preparation."
elif [[ $SERVICE_WAS_ACTIVE -eq 1 ]]; then
  note "Installed $APP for PVE $pve_version and restored the previously active service."
else
  note "Installed $APP for PVE $pve_version. No service was started unless --start was supplied."
fi
note "Verified local PVE preparation enables pve.source=api before the service can collect or upload."
