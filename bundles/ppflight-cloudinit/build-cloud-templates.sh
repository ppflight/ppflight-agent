#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCRIPT_VERSION="3.2.0"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR
CATALOG_HELPER="$SCRIPT_DIR/tools/ppflight-template-bootstrap.py"
readonly CATALOG_HELPER

# All settings can be overridden as environment variables or in CONFIG_FILE.
# The final VM disk storage is intentionally required. A host with both an SSD
# and a RAID pool cannot be mapped safely from device names alone.
IMAGE_STORAGE="${IMAGE_STORAGE:-}"
FILE_STORAGE="${FILE_STORAGE:-local}"
BRIDGE="${BRIDGE:-vmbr0}"
INTERNAL_BRIDGE="${INTERNAL_BRIDGE:-}"
CACHE_DIR="${CACHE_DIR:-}"
DISK_SIZE="${DISK_SIZE:-16G}"
MEMORY_MB="${MEMORY_MB:-2048}"
CORES="${CORES:-2}"
CPU_TYPE="${CPU_TYPE:-host}"
BALLOON="${BALLOON:-0}"
FIREWALL="${FIREWALL:-1}"
DISK_SSD="${DISK_SSD:-1}"
DNS_SERVERS="${DNS_SERVERS-1.1.1.1 8.8.8.8}"
TIMEZONE="${TIMEZONE:-UTC}"
ALLOW_ROOT_PASSWORD_SSH="${ALLOW_ROOT_PASSWORD_SSH:-1}"
ENABLE_QOS="${ENABLE_QOS:-1}"
REPLACE_EXISTING="${REPLACE_EXISTING:-0}"
FORCE_REPLACE_UNMANAGED="${FORCE_REPLACE_UNMANAGED:-0}"
CLEANUP_FAILED_VM="${CLEANUP_FAILED_VM:-1}"
ONLY_TEMPLATES="${ONLY_TEMPLATES:-all}"
BACKUP_STORAGE="${BACKUP_STORAGE:-}"
EXPECTED_CATALOG_REVISION="${EXPECTED_CATALOG_REVISION:-}"
EXPECTED_CATALOG_SHA256="${EXPECTED_CATALOG_SHA256:-}"

# QGA must be part of the immutable guest disk, rather than being first
# installed by the customer-facing Cloud-Init boot.  PVE's `agent=enabled=1`
# switch merely exposes the virtio serial device; it does not prove that a
# guest has the qemu-guest-agent package or an enabled service.
readonly QGA_PACKAGE="qemu-guest-agent"
readonly QGA_SERVICE="qemu-guest-agent.service"
readonly QGA_MARKER_PATH="/etc/ppflight/qga-preinstalled-v1"
readonly QGA_MARKER_VALUE="qemu-guest-agent=preinstalled-and-activation-verified"

QOS_MBPS_RD="${QOS_MBPS_RD:-200}"
QOS_MBPS_WR="${QOS_MBPS_WR:-150}"
QOS_MBPS_RD_MAX="${QOS_MBPS_RD_MAX:-350}"
QOS_MBPS_WR_MAX="${QOS_MBPS_WR_MAX:-300}"
QOS_IOPS_RD="${QOS_IOPS_RD:-5000}"
QOS_IOPS_WR="${QOS_IOPS_WR:-3500}"
QOS_IOPS_RD_MAX="${QOS_IOPS_RD_MAX:-8000}"
QOS_IOPS_WR_MAX="${QOS_IOPS_WR_MAX:-6000}"
QOS_IOPS_RD_MAX_LENGTH="${QOS_IOPS_RD_MAX_LENGTH:-30}"
QOS_IOPS_WR_MAX_LENGTH="${QOS_IOPS_WR_MAX_LENGTH:-30}"

CURRENT_VMID=""
CURRENT_NAME=""
CURRENT_PREPARED_IMAGE=""
DEBIAN_SNIPPET=""
RHEL_SNIPPET=""
CREATED_VMIDS=()
SELECTED_ROWS=()
TEMPLATE_ROWS=()
CATALOG_REVISION=""
CATALOG_SHA256=""
declare -A PREPARED_IMAGES=()

log() {
  printf '[%s] %s\n' "$(date '+%F %T')" "$*"
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Build seven Proxmox Cloud-Init templates from official cloud images.

Usage:
  sudo bash build-cloud-templates.sh [options]

Options:
  --config FILE       Source configuration overrides from FILE.
  --image-storage ID  PVE storage for final template disks.
  --file-storage ID   File storage already allowing iso and snippets.
  --backup-storage ID Back up every newly created template to this PVE storage.
  --no-backup         Explicitly skip template backups (the compatibility default).
  --cache-dir PATH    Override the cloud-image download cache path.
  --bridge NAME       External/public PVE bridge used by template net0.
  --internal-bridge NAME
                      Optional internal/private PVE bridge used by template net1.
  --replace           Replace existing project-managed templates.
  --force-replace-unmanaged
                      With --replace, also replace an untagged template whose
                      VMID and name both match the selected definition.
  --only LIST         Comma-separated VMIDs or names (default: all).
  --no-qos            Do not add disk bandwidth/IOPS limits.
  --expected-catalog-revision REV
  --expected-catalog-sha256 SHA256
                      Refuse execution if the bundled catalog differs from a
                      previously confirmed Agent plan.
  --help              Show this help.

Examples:
  sudo bash build-cloud-templates.sh --image-storage local-zfs
  sudo bash build-cloud-templates.sh --image-storage raid-zfs --file-storage local
  sudo bash build-cloud-templates.sh --image-storage raid-zfs --replace
  sudo IMAGE_STORAGE=nvme-zfs bash build-cloud-templates.sh --only 9000,9001
EOF
}

parse_args() {
  while (($#)); do
    case "$1" in
      --config)
        (($# >= 2)) || die "--config requires a file"
        CONFIG_FILE="$2"
        shift 2
        ;;
      --replace)
        REPLACE_EXISTING=1
        shift
        ;;
      --force-replace-unmanaged)
        FORCE_REPLACE_UNMANAGED=1
        shift
        ;;
      --image-storage)
        (($# >= 2)) || die "--image-storage requires a PVE storage ID"
        IMAGE_STORAGE="$2"
        shift 2
        ;;
      --file-storage)
        (($# >= 2)) || die "--file-storage requires a PVE storage ID"
        FILE_STORAGE="$2"
        shift 2
        ;;
      --backup-storage)
        (($# >= 2)) || die "--backup-storage requires a PVE storage ID"
        BACKUP_STORAGE="$2"
        shift 2
        ;;
      --no-backup)
        BACKUP_STORAGE=""
        shift
        ;;
      --cache-dir)
        (($# >= 2)) || die "--cache-dir requires an absolute path"
        CACHE_DIR="$2"
        shift 2
        ;;
      --bridge)
        (($# >= 2)) || die "--bridge requires a bridge name"
        BRIDGE="$2"
        shift 2
        ;;
      --internal-bridge)
        (($# >= 2)) || die "--internal-bridge requires a bridge name"
        INTERNAL_BRIDGE="$2"
        shift 2
        ;;
      --only)
        (($# >= 2)) || die "--only requires a list"
        ONLY_TEMPLATES="$2"
        shift 2
        ;;
      --no-qos)
        ENABLE_QOS=0
        shift
        ;;
      --expected-catalog-revision)
        (($# >= 2)) || die "--expected-catalog-revision requires a value"
        EXPECTED_CATALOG_REVISION="$2"
        shift 2
        ;;
      --expected-catalog-sha256)
        (($# >= 2)) || die "--expected-catalog-sha256 requires a value"
        EXPECTED_CATALOG_SHA256="$2"
        shift 2
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *) die "unknown option: $1" ;;
    esac
  done
}

find_config_arg() {
  local args=("$@") index
  for ((index=0; index<${#args[@]}; index++)); do
    if [[ "${args[$index]}" == "--config" ]]; then
      ((index + 1 < ${#args[@]})) || die "--config requires a file"
      CONFIG_FILE="${args[$((index + 1))]}"
      return
    fi
  done
}

load_config() {
  if [[ -n "${CONFIG_FILE:-}" ]]; then
    [[ -r "$CONFIG_FILE" ]] || die "cannot read config: $CONFIG_FILE"
    # shellcheck disable=SC1090
    source "$CONFIG_FILE"
  fi
}

on_exit() {
  local rc=$? prepared
  trap - EXIT
  if [[ -n "$CURRENT_PREPARED_IMAGE" && -e "$CURRENT_PREPARED_IMAGE" ]]; then
    rm -f -- "$CURRENT_PREPARED_IMAGE" || true
  fi
  for prepared in "${PREPARED_IMAGES[@]}"; do
    [[ -z "$prepared" || "$prepared" == "$CURRENT_PREPARED_IMAGE" ]] || rm -f -- "$prepared" || true
  done
  if [[ -n "$CURRENT_VMID" && "$CLEANUP_FAILED_VM" == "1" ]]; then
    if qm status "$CURRENT_VMID" >/dev/null 2>&1 &&
       qm config "$CURRENT_VMID" | grep -qx "name: $CURRENT_NAME" &&
       qm config "$CURRENT_VMID" | grep -Eq '^tags: .*ppflight-cloudinit-build([;,]|$)'; then
      log "Cleaning incomplete project VMID $CURRENT_VMID"
      qm destroy "$CURRENT_VMID" --purge 1 --destroy-unreferenced-disks 1 || true
    fi
  fi
  if ((rc != 0)); then
    printf 'Build failed with exit code %s.\n' "$rc" >&2
  fi
  exit "$rc"
}
trap on_exit EXIT

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

load_template_catalog() {
  local rows metadata_before metadata_after
  [[ -r "$CATALOG_HELPER" ]] || die "bundled catalog helper not found: $CATALOG_HELPER"
  require_command python3
  metadata_before="$(/usr/bin/python3 -I "$CATALOG_HELPER" catalog-metadata)" || die "bundled template catalog validation failed"
  rows="$(/usr/bin/python3 -I "$CATALOG_HELPER" catalog-rows)" || die "bundled template catalog validation failed"
  metadata_after="$(/usr/bin/python3 -I "$CATALOG_HELPER" catalog-metadata)" || die "bundled template catalog validation failed"
  [[ "$metadata_before" == "$metadata_after" ]] || die "bundled template catalog changed while it was being loaded"
  IFS='|' read -r CATALOG_REVISION CATALOG_SHA256 <<< "$metadata_after"
  [[ "$CATALOG_REVISION" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}\.[1-9][0-9]*$ ]] || die "bundled catalog returned an invalid revision"
  [[ "$CATALOG_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "bundled catalog returned an invalid SHA-256"
  [[ -n "$rows" ]] || die "bundled template catalog is empty"
  mapfile -t TEMPLATE_ROWS <<< "$rows"

  if [[ -n "$EXPECTED_CATALOG_REVISION" || -n "$EXPECTED_CATALOG_SHA256" ]]; then
    [[ -n "$EXPECTED_CATALOG_REVISION" && -n "$EXPECTED_CATALOG_SHA256" ]] ||
      die "both expected catalog revision and SHA-256 are required"
    [[ "$EXPECTED_CATALOG_REVISION" == "$CATALOG_REVISION" && "$EXPECTED_CATALOG_SHA256" == "$CATALOG_SHA256" ]] ||
      die "bundled catalog differs from the confirmed plan"
  fi
}

validate_integer() {
  local name="$1" value="$2"
  [[ "$value" =~ ^[0-9]+$ ]] || die "$name must be a non-negative integer"
}

storage_is_active() {
  pvesm status 2>/dev/null | awk -v id="$1" 'NR > 1 && $1 == id && $3 == "active" { found=1 } END { exit !found }'
}

storage_value() {
  local storage="$1" key="$2"
  pvesh get "/storage/$storage" --output-format json | perl -MJSON::PP -e '
    my $key = shift @ARGV;
    local $/;
    my $data = JSON::PP::decode_json(<STDIN>);
    exit 0 if !exists $data->{$key} || !defined $data->{$key};
    my $value = $data->{$key};
    if (ref($value) eq "ARRAY") {
      print join(",", @{$value});
    } elsif (!ref($value)) {
      print $value;
    }
  ' "$key"
}

storage_content() {
  storage_value "$1" content
}

resolve_storage_content_dir() {
  local storage="$1" content_type="$2" probe_name="$3" resolved
  resolved="$(pvesm path "$storage:$content_type/$probe_name")" ||
    die "cannot resolve $content_type path on storage $storage"
  [[ -n "$resolved" && "$resolved" == /* && "$resolved" != *$'\n'* ]] ||
    die "storage $storage returned an unsafe $content_type path"
  dirname -- "$resolved"
}

storage_descriptor() {
  local storage="$1" type path pool vgname thinpool
  type="$(storage_value "$storage" type)"
  path="$(storage_value "$storage" path)"
  pool="$(storage_value "$storage" pool)"
  vgname="$(storage_value "$storage" vgname)"
  thinpool="$(storage_value "$storage" thinpool)"

  case "$type" in
    dir|nfs|cifs)
      printf 'type=%s path=%s' "$type" "${path:-unknown}"
      ;;
    zfspool)
      printf 'type=zfspool pool=%s' "${pool:-unknown}"
      ;;
    lvmthin)
      printf 'type=lvmthin vg=%s thinpool=%s' "${vgname:-unknown}" "${thinpool:-unknown}"
      ;;
    rbd)
      printf 'type=rbd pool=%s' "${pool:-unknown}"
      ;;
    *)
      printf 'type=%s' "${type:-unknown}"
      ;;
  esac
}

show_storage_layout() {
  local snippet_dir="$1" mount_info free_space
  mount_info="$(findmnt -T "$CACHE_DIR" -n -o SOURCE,FSTYPE,TARGET 2>/dev/null || true)"
  free_space="$(df -hP "$CACHE_DIR" | awk 'NR == 2 {print $4 " available on " $6}')"

  log "Resolved download cache: $CACHE_DIR"
  log "Download filesystem: ${mount_info:-unable to resolve}; ${free_space:-free space unknown}"
  log "Cloud-Init snippets: storage=$FILE_STORAGE path=$snippet_dir"
  log "Final OS and Cloud-Init disks: $IMAGE_STORAGE ($(storage_descriptor "$IMAGE_STORAGE"))"
}

select_templates() {
  local row vmid name token matched aliases
  if [[ "$ONLY_TEMPLATES" == "all" || -z "$ONLY_TEMPLATES" ]]; then
    SELECTED_ROWS=("${TEMPLATE_ROWS[@]}")
    return
  fi

  IFS=',' read -r -a requested <<< "$ONLY_TEMPLATES"
  for token in "${requested[@]}"; do
    [[ "$token" =~ ^[A-Za-z0-9._-]+$ ]] || die "unsafe template selector: $token"
    matched=0
    for row in "${TEMPLATE_ROWS[@]}"; do
      IFS='|' read -r vmid name _ <<< "$row"
      aliases="${row##*|}"
      if [[ "$token" == "$vmid" || "$token" == "$name" || ",$aliases," == *",$token,"* ]]; then
        SELECTED_ROWS+=("$row")
        matched=1
        break
      fi
    done
    ((matched == 1)) || die "unknown template in --only: $token"
  done
}

preflight() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "run this script as root on a Proxmox VE node"
  for cmd in qm pvesm pvesh pveversion qemu-img virt-customize curl sha256sum sha512sum awk grep sed stat ip findmnt df dirname flock perl python3 mktemp; do
    require_command "$cmd"
  done
  perl -MJSON::PP -e 'exit 0' >/dev/null 2>&1 || die "required Perl module not found: JSON::PP"
  [[ -d /etc/pve ]] || die "/etc/pve not found; this does not look like a Proxmox VE node"
  [[ -n "$IMAGE_STORAGE" ]] || die "final disk storage is required; use --image-storage <PVE-storage-ID>"
  [[ "$IMAGE_STORAGE" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || die "invalid image storage ID"
  [[ "$FILE_STORAGE" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || die "invalid file storage ID"
  [[ -z "$BACKUP_STORAGE" || "$BACKUP_STORAGE" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || die "invalid backup storage ID"
  storage_is_active "$IMAGE_STORAGE" || die "image storage is not active: $IMAGE_STORAGE"
  storage_is_active "$FILE_STORAGE" || die "file storage is not active: $FILE_STORAGE"
  [[ ",$(storage_content "$IMAGE_STORAGE")," == *",images,"* ]] || die "$IMAGE_STORAGE does not allow VM images"
  [[ ",$(storage_content "$FILE_STORAGE")," == *",iso,"* ]] || die "$FILE_STORAGE does not allow ISO image downloads"
  [[ ",$(storage_content "$FILE_STORAGE")," == *",snippets,"* ]] || die "$FILE_STORAGE does not allow Cloud-Init snippets"
  if [[ -n "$BACKUP_STORAGE" ]]; then
    require_command vzdump
    storage_is_active "$BACKUP_STORAGE" || die "backup storage is not active: $BACKUP_STORAGE"
    [[ ",$(storage_content "$BACKUP_STORAGE")," == *",backup,"* ]] || die "$BACKUP_STORAGE does not allow backups"
  fi
  [[ "$BRIDGE" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$ ]] || die "invalid external bridge name"
  [[ -z "$INTERNAL_BRIDGE" || "$INTERNAL_BRIDGE" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$ ]] || die "invalid internal bridge name"
  [[ -z "$INTERNAL_BRIDGE" || "$INTERNAL_BRIDGE" != "$BRIDGE" ]] || die "external and internal bridges must be different"
  ip link show "$BRIDGE" >/dev/null 2>&1 || die "external bridge not found: $BRIDGE"
  [[ -z "$INTERNAL_BRIDGE" ]] || ip link show "$INTERNAL_BRIDGE" >/dev/null 2>&1 || die "internal bridge not found: $INTERNAL_BRIDGE"

  for pair in MEMORY_MB:"$MEMORY_MB" CORES:"$CORES" BALLOON:"$BALLOON" FIREWALL:"$FIREWALL" DISK_SSD:"$DISK_SSD"; do
    validate_integer "${pair%%:*}" "${pair#*:}"
  done
  [[ "$DISK_SIZE" =~ ^[0-9]+[KMGT]$ ]] || die "DISK_SIZE must look like 16G"
  [[ -z "$CACHE_DIR" || "$CACHE_DIR" == /* ]] || die "CACHE_DIR must be an absolute path"
  [[ "$ALLOW_ROOT_PASSWORD_SSH" == "0" || "$ALLOW_ROOT_PASSWORD_SSH" == "1" ]] || die "ALLOW_ROOT_PASSWORD_SSH must be 0 or 1"
  [[ "$DISK_SSD" == "0" || "$DISK_SSD" == "1" ]] || die "DISK_SSD must be 0 or 1"
  [[ "$ENABLE_QOS" == "0" || "$ENABLE_QOS" == "1" ]] || die "ENABLE_QOS must be 0 or 1"
  [[ "$REPLACE_EXISTING" == "0" || "$REPLACE_EXISTING" == "1" ]] || die "REPLACE_EXISTING must be 0 or 1"
  [[ "$FORCE_REPLACE_UNMANAGED" == "0" || "$FORCE_REPLACE_UNMANAGED" == "1" ]] || die "FORCE_REPLACE_UNMANAGED must be 0 or 1"
  [[ "$CLEANUP_FAILED_VM" == "0" || "$CLEANUP_FAILED_VM" == "1" ]] || die "CLEANUP_FAILED_VM must be 0 or 1"
  [[ "$FORCE_REPLACE_UNMANAGED" == "0" || "$REPLACE_EXISTING" == "1" ]] || die "--force-replace-unmanaged also requires --replace"

  if [[ "$ENABLE_QOS" == "1" ]]; then
    local help field
    help="$(qm help set --verbose 2>&1)"
    for field in mbps_rd mbps_wr mbps_rd_max mbps_wr_max iops_rd iops_wr iops_rd_max iops_wr_max iops_rd_max_length iops_wr_max_length; do
      grep -q "$field" <<< "$help" || die "this PVE version does not expose disk field: $field (use --no-qos or upgrade PVE)"
    done
    for pair in \
      QOS_MBPS_RD:"$QOS_MBPS_RD" QOS_MBPS_WR:"$QOS_MBPS_WR" \
      QOS_MBPS_RD_MAX:"$QOS_MBPS_RD_MAX" QOS_MBPS_WR_MAX:"$QOS_MBPS_WR_MAX" \
      QOS_IOPS_RD:"$QOS_IOPS_RD" QOS_IOPS_WR:"$QOS_IOPS_WR" \
      QOS_IOPS_RD_MAX:"$QOS_IOPS_RD_MAX" QOS_IOPS_WR_MAX:"$QOS_IOPS_WR_MAX" \
      QOS_IOPS_RD_MAX_LENGTH:"$QOS_IOPS_RD_MAX_LENGTH" QOS_IOPS_WR_MAX_LENGTH:"$QOS_IOPS_WR_MAX_LENGTH"; do
      validate_integer "${pair%%:*}" "${pair#*:}"
    done
    ((QOS_MBPS_RD_MAX >= QOS_MBPS_RD)) || die "read burst must be >= sustained read"
    ((QOS_MBPS_WR_MAX >= QOS_MBPS_WR)) || die "write burst must be >= sustained write"
    ((QOS_IOPS_RD_MAX >= QOS_IOPS_RD)) || die "read IOPS burst must be >= sustained read IOPS"
    ((QOS_IOPS_WR_MAX >= QOS_IOPS_WR)) || die "write IOPS burst must be >= sustained write IOPS"
  fi

  virt-customize --version >/dev/null 2>&1 || die "virt-customize is unavailable; install the PVE 8 package libguestfs-tools before building templates"
  log "PVE: $(pveversion)"
  log "Selected final disk storage: $IMAGE_STORAGE; file storage: $FILE_STORAGE; external bridge: $BRIDGE; internal bridge: ${INTERNAL_BRIDGE:-disabled}"
}

write_snippets() {
  local snippet_dir permit_root password_auth
  local debian_tmp rhel_tmp debian_hash rhel_hash
  snippet_dir="$(resolve_storage_content_dir "$FILE_STORAGE" snippets ppflight-cloudinit-probe.yaml)"
  install -d -m 0755 "$snippet_dir"

  if [[ "$ALLOW_ROOT_PASSWORD_SSH" == "1" ]]; then
    permit_root=yes
    password_auth=yes
  else
    permit_root=prohibit-password
    password_auth=no
  fi

  debian_tmp="$snippet_dir/.ppflight-debian-$$.tmp"
  rhel_tmp="$snippet_dir/.ppflight-rhel-$$.tmp"
  rm -f -- "$debian_tmp" "$rhel_tmp"

  cat > "$debian_tmp" <<YAML
#cloud-config
disable_root: false
ssh_pwauth: $([[ "$ALLOW_ROOT_PASSWORD_SSH" == "1" ]] && echo true || echo false)
ssh_deletekeys: true
ssh_genkeytypes: [rsa, ecdsa, ed25519]
timezone: $TIMEZONE
ntp:
  enabled: true
growpart:
  mode: auto
  devices: ['/']
  ignore_growroot_disabled: false
resize_rootfs: true
package_update: true
packages:
  - vim
  - curl
  - net-tools
write_files:
  - path: /etc/ssh/sshd_config.d/00-ppflight-cloud.conf
    owner: root:root
    permissions: '0644'
    content: |
      PermitRootLogin $permit_root
      PasswordAuthentication $password_auth
      KbdInteractiveAuthentication no
      PermitEmptyPasswords no
  - path: /etc/modules-load.d/tcp-bbr.conf
    owner: root:root
    permissions: '0644'
    content: |
      tcp_bbr
  - path: /etc/sysctl.d/99-ppflight-cloud.conf
    owner: root:root
    permissions: '0644'
    content: |
      net.core.default_qdisc=fq
      net.ipv4.tcp_congestion_control=bbr
      kernel.dmesg_restrict=1
runcmd:
  - [modprobe, tcp_bbr]
  - [sysctl, --system]
  - [systemctl, enable, --now, ssh]
  - [systemctl, restart, ssh]
  - [systemctl, enable, serial-getty@ttyS0.service]
YAML

  debian_hash="$(sha256sum "$debian_tmp" | awk '{print $1}')"
  DEBIAN_SNIPPET="ppflight-debian-$debian_hash.yaml"
  if [[ -e "$snippet_dir/$DEBIAN_SNIPPET" ]]; then
    rm -f -- "$debian_tmp"
  else
    mv "$debian_tmp" "$snippet_dir/$DEBIAN_SNIPPET"
  fi
  chmod 0644 "$snippet_dir/$DEBIAN_SNIPPET"

  cat > "$rhel_tmp" <<YAML
#cloud-config
disable_root: false
ssh_pwauth: $([[ "$ALLOW_ROOT_PASSWORD_SSH" == "1" ]] && echo true || echo false)
ssh_deletekeys: true
ssh_genkeytypes: [rsa, ecdsa, ed25519]
timezone: $TIMEZONE
ntp:
  enabled: true
growpart:
  mode: auto
  devices: ['/']
  ignore_growroot_disabled: false
resize_rootfs: true
package_update: true
packages:
  - chrony
  - vim-enhanced
  - curl
  - net-tools
write_files:
  - path: /etc/ssh/sshd_config.d/00-ppflight-cloud.conf
    owner: root:root
    permissions: '0644'
    content: |
      PermitRootLogin $permit_root
      PasswordAuthentication $password_auth
      KbdInteractiveAuthentication no
      PermitEmptyPasswords no
  - path: /etc/modules-load.d/tcp-bbr.conf
    owner: root:root
    permissions: '0644'
    content: |
      tcp_bbr
  - path: /etc/sysctl.d/99-ppflight-cloud.conf
    owner: root:root
    permissions: '0644'
    content: |
      net.core.default_qdisc=fq
      net.ipv4.tcp_congestion_control=bbr
      kernel.dmesg_restrict=1
runcmd:
  - [modprobe, tcp_bbr]
  - [sysctl, --system]
  - [systemctl, enable, --now, sshd]
  - [systemctl, restart, sshd]
  - [systemctl, enable, --now, chronyd]
  - [systemctl, enable, serial-getty@ttyS0.service]
YAML

  rhel_hash="$(sha256sum "$rhel_tmp" | awk '{print $1}')"
  RHEL_SNIPPET="ppflight-rhel-$rhel_hash.yaml"
  if [[ -e "$snippet_dir/$RHEL_SNIPPET" ]]; then
    rm -f -- "$rhel_tmp"
  else
    mv "$rhel_tmp" "$snippet_dir/$RHEL_SNIPPET"
  fi
  chmod 0644 "$snippet_dir/$RHEL_SNIPPET"
  log "Immutable Cloud-Init profiles: $DEBIAN_SNIPPET; $RHEL_SNIPPET"
}

checksum_listing_value() {
  local filename="$1" checksum_file="$2"
  # Accept both GNU format (HASH [ *]FILENAME) and BSD format
  # (SHA256 (FILENAME) = HASH), but only for this exact basename.
  awk -v wanted="$filename" '
    {
      hash = ""
      name = ""
      if ($1 ~ /^[[:xdigit:]]+$/ && NF >= 2) {
        hash = $1
        name = $2
        sub(/^\*/, "", name)
      } else if (($1 == "SHA256" || $1 == "SHA512") && $2 == "(" wanted ")" && $3 == "=" && NF >= 4) {
        hash = $4
        name = wanted
      }
      if (name == wanted) {
        print tolower(hash)
        exit
      }
    }
  ' "$checksum_file"
}

verify_download() {
  local file="$1" algorithm="$2" upstream_expected="$3" source_sha256="$4" minimum_bytes="$5"
  local actual_upstream actual_sha256 actual_bytes expected_length
  case "$algorithm" in
    sha256)
      actual_upstream="$(sha256sum "$file" | awk '{print tolower($1)}')"
      expected_length=64
      ;;
    sha512)
      actual_upstream="$(sha512sum "$file" | awk '{print tolower($1)}')"
      expected_length=128
      ;;
    *) die "unsupported checksum algorithm: $algorithm" ;;
  esac
  [[ ${#upstream_expected} -eq $expected_length && "$upstream_expected" =~ ^[0-9a-f]+$ ]] || return 1
  [[ "$actual_upstream" == "$upstream_expected" ]] || return 1
  actual_sha256="$(sha256sum "$file" | awk '{print tolower($1)}')"
  [[ "$actual_sha256" == "$source_sha256" ]] || return 1
  actual_bytes="$(stat -c '%s' -- "$file")"
  [[ "$actual_bytes" =~ ^[0-9]+$ && "$minimum_bytes" =~ ^[0-9]+$ ]] || return 1
  ((actual_bytes >= minimum_bytes)) || return 1
  printf '%s\n' "$actual_sha256"
}

download_image() {
  local image="$1" url="$2" checksum_url="$3" algorithm="$4" upstream_expected="$5" source_sha256="$6" minimum_bytes="$7"
  local target="$CACHE_DIR/$image" checksum_file="$CACHE_DIR/$image.$algorithm.sums" actual listed attempt

  for attempt in 1 2; do
    curl --disable --ipv4 --fail --location --max-redirs 5 --proto '=https' --proto-redir '=https' \
      --show-error --silent --retry 5 --retry-delay 3 --retry-all-errors \
      --output "$checksum_file.tmp" "$checksum_url"
    mv "$checksum_file.tmp" "$checksum_file"
    listed="$(checksum_listing_value "$image" "$checksum_file")"
    [[ "$listed" == "$upstream_expected" ]] ||
      die "upstream checksum for $image differs from catalog revision $CATALOG_REVISION; update and review the catalog"

    if [[ ! -s "$target" ]]; then
      log "Downloading $image"
      curl --disable --ipv4 --fail --location --max-redirs 5 --proto '=https' --proto-redir '=https' \
        --show-error --silent --retry 8 --retry-delay 5 --retry-all-errors \
        --continue-at - --output "$target.part" "$url"
      mv "$target.part" "$target"
    else
      log "Using cached $image (checksum will still be verified)"
    fi

    if actual="$(verify_download "$target" "$algorithm" "$upstream_expected" "$source_sha256" "$minimum_bytes")"; then
      IMAGE_HASHES["$image"]="sha256:$actual"
      log "pinned SHA-256 and official $algorithm checksum verified: $image"
      qemu-img info --output=json "$target" | perl -MJSON::PP -e '
        local $/;
        my $data = JSON::PP::decode_json(<STDIN>);
        exit((ref($data) eq "HASH" && ($data->{format} // "") eq "qcow2") ? 0 : 1);
      ' || die "source image is not qcow2 as declared by the catalog: $image"
      return 0
    fi

    log "Checksum mismatch for $image on attempt $attempt/2; refreshing image and checksum"
    rm -f -- "$target" "$target.part"
  done
  die "checksum verification failed for $image"
}

check_existing_vmids() {
  local row vmid name config existing_name
  for row in "${SELECTED_ROWS[@]}"; do
    IFS='|' read -r vmid name _ <<< "$row"
    if qm status "$vmid" >/dev/null 2>&1; then
      config="$(qm config "$vmid")"
      grep -qx 'template: 1' <<< "$config" || die "VMID $vmid exists and is not a template"
      [[ "$REPLACE_EXISTING" == "1" ]] || die "template $vmid already exists; rerun with --replace"
      if ! grep -Eq '^tags: .*ppflight-cloudinit([;,]|$)' <<< "$config"; then
        existing_name="$(awk '$1 == "name:" {print $2; exit}' <<< "$config")"
        [[ "$FORCE_REPLACE_UNMANAGED" == "1" && "$existing_name" == "$name" ]] ||
          die "template $vmid is not tagged ppflight-cloudinit; refusing to replace it"
      fi
    fi
  done
}

destroy_existing_template() {
  local vmid="$1" expected_name="$2" config existing_name
  if qm status "$vmid" >/dev/null 2>&1; then
    [[ "$REPLACE_EXISTING" == "1" ]] || die "template $vmid appeared during the build; refusing to replace it without --replace"
    config="$(qm config "$vmid")"
    grep -qx 'template: 1' <<< "$config" || die "VMID $vmid changed and is no longer a template"
    existing_name="$(awk '$1 == "name:" {print $2; exit}' <<< "$config")"
    if ! grep -Eq '^tags: .*ppflight-cloudinit([;,]|$)' <<< "$config"; then
      [[ "$FORCE_REPLACE_UNMANAGED" == "1" && "$existing_name" == "$expected_name" ]] ||
        die "template $vmid is unmanaged or changed; refusing to destroy it"
    fi
    log "Replacing existing template $vmid"
    qm destroy "$vmid" --purge 1 --destroy-unreferenced-disks 1
  fi
}

disk_qos_suffix() {
  if [[ "$ENABLE_QOS" == "1" ]]; then
    printf ',mbps_rd=%s,mbps_wr=%s,mbps_rd_max=%s,mbps_wr_max=%s,iops_rd=%s,iops_wr=%s,iops_rd_max=%s,iops_wr_max=%s,iops_rd_max_length=%s,iops_wr_max_length=%s' \
      "$QOS_MBPS_RD" "$QOS_MBPS_WR" "$QOS_MBPS_RD_MAX" "$QOS_MBPS_WR_MAX" \
      "$QOS_IOPS_RD" "$QOS_IOPS_WR" "$QOS_IOPS_RD_MAX" "$QOS_IOPS_WR_MAX" \
      "$QOS_IOPS_RD_MAX_LENGTH" "$QOS_IOPS_WR_MAX_LENGTH"
  fi
}

qga_verify_command() {
  # This command is executed inside the offline guest image by
  # virt-customize. It intentionally checks the package database, executable,
  # valid systemd activation path, and PPFlight build marker independently. A PVE VM
  # config line (`agent: enabled=1`) cannot satisfy any of these checks.
  cat <<'SH'
set -eu
if command -v dpkg-query >/dev/null 2>&1; then
  test "$(dpkg-query -W -f='${db:Status-Status}' qemu-guest-agent)" = installed
elif command -v rpm >/dev/null 2>&1; then
  rpm -q --quiet qemu-guest-agent
else
  echo "unsupported package database" >&2
  exit 64
fi

test -x /usr/sbin/qemu-ga || test -x /usr/bin/qemu-ga
state="$(systemctl is-enabled qemu-guest-agent.service 2>/dev/null || true)"
case "$state" in
  enabled|enabled-runtime) ;;
  static)
    static_rule_verified=0
    for rule in /usr/lib/udev/rules.d/60-qemu-guest-agent.rules /lib/udev/rules.d/60-qemu-guest-agent.rules; do
      if test -r "$rule" && grep -Fq 'SYSTEMD_WANTS}="qemu-guest-agent.service"' "$rule"; then
        static_rule_verified=1
        break
      fi
    done
    test "$static_rule_verified" = 1
    ;;
  *)
    echo "qemu-guest-agent service activation is invalid: $state" >&2
    exit 65
    ;;
esac
test "$(cat /etc/ppflight/qga-preinstalled-v1)" = qemu-guest-agent=preinstalled-and-activation-verified
SH
}

qga_activate_service_command() {
  # Debian-family packages may intentionally ship a static unit and use the
  # qemu virtio-port udev rule to start it as soon as PVE exposes the device.
  # RHEL-family packages normally have an enable-able unit. Both are valid,
  # but a static unit without the matching udev activation rule is rejected.
  cat <<'SH'
set -eu
state="$(systemctl is-enabled qemu-guest-agent.service 2>/dev/null || true)"
case "$state" in
  static)
    for rule in /usr/lib/udev/rules.d/60-qemu-guest-agent.rules /lib/udev/rules.d/60-qemu-guest-agent.rules; do
      if test -r "$rule" && grep -Fq 'SYSTEMD_WANTS}="qemu-guest-agent.service"' "$rule"; then
        exit 0
      fi
    done
    echo "static qemu-guest-agent unit has no virtio-port udev activation rule" >&2
    exit 65
    ;;
  *)
    systemctl enable qemu-guest-agent.service
    ;;
esac
SH
}

prepare_image_with_qga() {
  local source="$1" vmid="$2" prepared
  [[ -s "$source" ]] || die "source image is missing before QGA preparation: $source"
  prepared="$(mktemp "$CACHE_DIR/.ppflight-qga-${vmid}.XXXXXX.qcow2")"
  # mktemp creates the path securely, while qemu-img requires a non-existent
  # output. The parent cache directory is protected by the root-only builder
  # lock and the template source image is never modified in place.
  rm -f -- "$prepared"
  CURRENT_PREPARED_IMAGE="$prepared"

  log "Preparing immutable QGA image copy for template $vmid"
  qemu-img convert -p -f qcow2 -O qcow2 "$source" "$prepared"
  qemu-img check "$prepared" >/dev/null || die "prepared QGA image is invalid for template $vmid"

  # --network is necessary only for the distribution package manager. The
  # catalog covers Ubuntu/Debian and RHEL-family GenericCloud images, whose
  # package name and systemd unit are intentionally the same.
  virt-customize --format qcow2 --network -a "$prepared" \
    --install "$QGA_PACKAGE" \
    --run-command "$(qga_activate_service_command)" \
    --run-command "install -d -m 0755 /etc/ppflight && printf '%s\\n' '$QGA_MARKER_VALUE' > '$QGA_MARKER_PATH'" \
    || die "failed to preinstall $QGA_PACKAGE in template $vmid"

  # Reopen the modified disk without a network, so successful eligibility is
  # based on the actual immutable filesystem state and not on a deferred
  # cloud-init package task or a PVE-side agent device setting.
  virt-customize --format qcow2 --no-network -a "$prepared" \
    --run-command "$(qga_verify_command)" \
    || die "QGA package/service verification failed for template $vmid"

  PREPARED_IMAGES["$vmid"]="$prepared"
  log "QGA package and enabled service verified in template $vmid image"
}

prepare_selected_images_with_qga() {
  local row vmid _name image
  for row in "${SELECTED_ROWS[@]}"; do
    IFS='|' read -r vmid _name image _ <<< "$row"
    prepare_image_with_qga "$CACHE_DIR/$image" "$vmid"
  done
}

create_template() {
  local row="$1" vmid name image _url _checksum_url _algorithm _upstream_expected _source_sha256 _minimum_bytes family placeholder_ip description _version _aliases
  local imported_volume snippet qos description_full prepared_image
  local -a network_args
  IFS='|' read -r vmid name image _url _checksum_url _algorithm _upstream_expected _source_sha256 _minimum_bytes family placeholder_ip description _version _aliases <<< "$row"
  snippet="$DEBIAN_SNIPPET"
  [[ "$family" == "rhel" ]] && snippet="$RHEL_SNIPPET"
  [[ -n "$snippet" ]] || die "Cloud-Init profile was not generated for $family"
  qos="$(disk_qos_suffix)"
  prepared_image="${PREPARED_IMAGES[$vmid]:-}"
  [[ -n "$prepared_image" && -s "$prepared_image" ]] || die "QGA-prepared image is missing for template $vmid"
  description_full="$description; qemu-guest-agent preinstalled and activation verified; built by ppflight-cloudinit v$SCRIPT_VERSION on $(date -u '+%F')"
  network_args=(--net0 "virtio,bridge=$BRIDGE,firewall=$FIREWALL")
  if [[ -n "$INTERNAL_BRIDGE" ]]; then
    network_args+=(--net1 "virtio,bridge=$INTERNAL_BRIDGE,firewall=$FIREWALL")
  fi

  destroy_existing_template "$vmid" "$name"
  log "Creating $vmid ($name)"
  qm create "$vmid" \
    --name "$name" \
    --description "$description_full" \
    --ostype l26 \
    --memory "$MEMORY_MB" \
    --balloon "$BALLOON" \
    --cores "$CORES" \
    --sockets 1 \
    --cpu "$CPU_TYPE" \
    "${network_args[@]}" \
    --scsihw virtio-scsi-single \
    --serial0 socket \
    --vga std \
    --agent enabled=1,fstrim_cloned_disks=1 \
    --tags 'ppflight-cloudinit-build;ppflight-qga-preinstalled' \
    --onboot 0
  CURRENT_VMID="$vmid"
  CURRENT_NAME="$name"

  qm disk import "$vmid" "$prepared_image" "$IMAGE_STORAGE"
  rm -f -- "$prepared_image"
  unset 'PREPARED_IMAGES[$vmid]'
  CURRENT_PREPARED_IMAGE=""
  imported_volume="$(qm config "$vmid" | awk -F': ' '/^unused[0-9]+:/ {print $2; exit}')"
  [[ -n "$imported_volume" ]] || die "imported disk not found for VMID $vmid"

  qm set "$vmid" --scsi0 "$imported_volume,discard=on,ssd=$DISK_SSD,iothread=1$qos"
  qm set "$vmid" --ide2 "$IMAGE_STORAGE:cloudinit"
  qm set "$vmid" --boot order=scsi0
  qm set "$vmid" --citype nocloud
  qm set "$vmid" --ciuser root
  qm set "$vmid" --ciupgrade 0
  qm set "$vmid" --cicustom "vendor=$FILE_STORAGE:snippets/$snippet"
  qm set "$vmid" --ipconfig0 "ip=$placeholder_ip/32"
  [[ -z "$DNS_SERVERS" ]] || qm set "$vmid" --nameserver "$DNS_SERVERS"
  qm resize "$vmid" scsi0 "$DISK_SIZE"
  qm cloudinit update "$vmid"
  qm template "$vmid"
  qm set "$vmid" --tags 'ppflight-cloudinit;ppflight-qga-preinstalled'
  CREATED_VMIDS+=("$vmid")
  CURRENT_VMID=""
  CURRENT_NAME=""
}

verify_template() {
  local row="$1" vmid name _image _url _checksum _algorithm _upstream_expected _source_sha256 _minimum_bytes family config disk cloudinit_disk field expected_snippet net0 net1
  IFS='|' read -r vmid name _image _url _checksum _algorithm _upstream_expected _source_sha256 _minimum_bytes family _ <<< "$row"
  expected_snippet="$DEBIAN_SNIPPET"
  [[ "$family" == "rhel" ]] && expected_snippet="$RHEL_SNIPPET"
  config="$(qm config "$vmid")"
  grep -qx 'template: 1' <<< "$config" || die "$vmid is not a template"
  grep -qx "name: $name" <<< "$config" || die "$vmid has unexpected name"
  grep -Eq '^tags: .*ppflight-cloudinit([;,]|$)' <<< "$config" || die "$vmid is missing the project tag"
  grep -Eq '^tags: .*ppflight-qga-preinstalled([;,]|$)' <<< "$config" || die "$vmid is missing the QGA-preinstalled build attestation tag"
  grep -q '^agent: enabled=1' <<< "$config" || die "$vmid does not have QEMU Agent enabled"
  grep -qx 'sockets: 1' <<< "$config" || die "$vmid does not have the required single CPU socket"
  grep -q '^serial0: socket' <<< "$config" || die "$vmid does not have serial0"
  grep -q '^vga: std' <<< "$config" || die "$vmid does not have VGA"
  grep -Fqx "cicustom: vendor=$FILE_STORAGE:snippets/$expected_snippet" <<< "$config" || die "$vmid has an unexpected Cloud-Init profile"
  net0="$(sed -n 's/^net0: //p' <<< "$config")"
  [[ ",$net0," == *",bridge=$BRIDGE,"* && ",$net0," == *",firewall=$FIREWALL,"* ]] || die "$vmid net0 does not match the external bridge policy"
  net1="$(sed -n 's/^net1: //p' <<< "$config")"
  if [[ -n "$INTERNAL_BRIDGE" ]]; then
    [[ ",$net1," == *",bridge=$INTERNAL_BRIDGE,"* && ",$net1," == *",firewall=$FIREWALL,"* ]] || die "$vmid net1 does not match the internal bridge policy"
  else
    [[ -z "$net1" ]] || die "$vmid unexpectedly contains net1"
  fi
  disk="$(sed -n 's/^scsi0: //p' <<< "$config")"
  cloudinit_disk="$(sed -n 's/^ide2: //p' <<< "$config")"
  [[ "$disk" == "$IMAGE_STORAGE:"* ]] || die "$vmid system disk is not on $IMAGE_STORAGE"
  [[ "$cloudinit_disk" == "$IMAGE_STORAGE:"* ]] || die "$vmid Cloud-Init disk is not on $IMAGE_STORAGE"
  [[ "$disk" == *"discard=on"* && "$disk" == *"iothread=1"* && "$disk" == *"ssd=$DISK_SSD"* ]] || die "$vmid disk tuning is incomplete"
  if [[ "$ENABLE_QOS" == "1" ]]; then
    for field in \
      "mbps_rd=$QOS_MBPS_RD" "mbps_wr=$QOS_MBPS_WR" \
      "mbps_rd_max=$QOS_MBPS_RD_MAX" "mbps_wr_max=$QOS_MBPS_WR_MAX" \
      "iops_rd=$QOS_IOPS_RD" "iops_wr=$QOS_IOPS_WR" \
      "iops_rd_max=$QOS_IOPS_RD_MAX" "iops_wr_max=$QOS_IOPS_WR_MAX" \
      "iops_rd_max_length=$QOS_IOPS_RD_MAX_LENGTH" "iops_wr_max_length=$QOS_IOPS_WR_MAX_LENGTH"; do
      [[ ",$disk," == *",$field,"* ]] || die "$vmid is missing $field"
    done
  fi
  qm cloudinit dump "$vmid" network >/dev/null
}

backup_templates() {
  local vmid
  [[ -n "$BACKUP_STORAGE" ]] || return 0
  for vmid in "${CREATED_VMIDS[@]}"; do
    log "Backing up newly created template $vmid to $BACKUP_STORAGE"
    vzdump "$vmid" --storage "$BACKUP_STORAGE" --mode snapshot --compress zstd
  done
}

write_manifest() {
  local manifest="$CACHE_DIR/ppflight-template-build-manifest.txt" row vmid name image backup_policy=disabled
  [[ -z "$BACKUP_STORAGE" ]] || backup_policy=required
  {
    printf 'script_version=%s\n' "$SCRIPT_VERSION"
    printf 'catalog_revision=%s\ncatalog_sha256=%s\n' "$CATALOG_REVISION" "$CATALOG_SHA256"
    printf 'built_at_utc=%s\n' "$(date -u '+%FT%TZ')"
    printf 'pve_version=%s\n' "$(pveversion)"
    printf 'image_storage=%s\nfile_storage=%s\nexternal_bridge=%s\ninternal_bridge=%s\n' "$IMAGE_STORAGE" "$FILE_STORAGE" "$BRIDGE" "${INTERNAL_BRIDGE:-disabled}"
    printf 'backup_storage=%s\nbackup_policy=%s\n' "${BACKUP_STORAGE:-disabled}" "$backup_policy"
    printf 'debian_snippet=%s\nrhel_snippet=%s\nqga_package=%s\nqga_service=%s\nqga_build_attestation=preinstalled-and-activation-verified\n' "$DEBIAN_SNIPPET" "$RHEL_SNIPPET" "$QGA_PACKAGE" "$QGA_SERVICE"
    printf 'disk_size=%s\ndisk_ssd=%s\nmemory_mb=%s\ncores=%s\ncpu_type=%s\nqos_enabled=%s\n' "$DISK_SIZE" "$DISK_SSD" "$MEMORY_MB" "$CORES" "$CPU_TYPE" "$ENABLE_QOS"
    for row in "${SELECTED_ROWS[@]}"; do
      IFS='|' read -r vmid name image _ <<< "$row"
      printf 'template=%s|%s|%s|%s\n' "$vmid" "$name" "$image" "${IMAGE_HASHES[$image]}"
    done
  } > "$manifest"
  chmod 0644 "$manifest"
  log "Manifest: $manifest"
}

main() {
  find_config_arg "$@"
  load_config
  parse_args "$@"
  load_template_catalog
  select_templates
  preflight
  exec 9>/run/lock/ppflight-cloudinit.lock
  flock -n 9 || die "another ppflight-cloudinit build is already running"

  local iso_dir snippet_dir row vmid name image url checksum_url algorithm upstream_expected source_sha256 minimum_bytes _family _ip _description _version _aliases
  iso_dir="$(resolve_storage_content_dir "$FILE_STORAGE" iso ppflight-cloudinit-probe.iso)"
  snippet_dir="$(resolve_storage_content_dir "$FILE_STORAGE" snippets ppflight-cloudinit-probe.yaml)"
  if [[ -z "$CACHE_DIR" ]]; then
    CACHE_DIR="$iso_dir/ppflight-cloudinit-cache"
  fi
  install -d -m 0755 "$CACHE_DIR"
  show_storage_layout "$snippet_dir"

  check_existing_vmids

  declare -gA IMAGE_HASHES=()
  log "Downloading and verifying all selected images before changing VMIDs"
  for row in "${SELECTED_ROWS[@]}"; do
    IFS='|' read -r vmid name image url checksum_url algorithm upstream_expected source_sha256 minimum_bytes _family _ip _description _version _aliases <<< "$row"
    download_image "$image" "$url" "$checksum_url" "$algorithm" "$upstream_expected" "$source_sha256" "$minimum_bytes"
  done

  log "Preparing and offline-verifying QGA packages before replacing any template VMID"
  prepare_selected_images_with_qga

  write_snippets

  for row in "${SELECTED_ROWS[@]}"; do
    create_template "$row"
  done

  for row in "${SELECTED_ROWS[@]}"; do
    verify_template "$row"
  done
  backup_templates
  write_manifest

  log "Completed templates: ${CREATED_VMIDS[*]}"
  qm list
}

main "$@"
