#!/usr/bin/env bash
# Bootstrap dedicated, privilege-separated Proxmox API identities for PPFlight.
# Run this only as root on the PVE node. Token secrets are never printed: use
# --write-env to persist newly generated secrets in a root-only file.
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly EXPECTED_OWNER_UID=0
readonly EXPECTED_OWNER_GID=0
readonly READ_USER='ppflight-agent@pve'
readonly READ_TOKEN='collector'
readonly CONTROL_USER='ppflight-control@pve'
readonly CONTROL_TOKEN='executor'
readonly READ_ROLE='PPFlightAgentAudit'
readonly CONTROL_ROLE='PPFlightAgentControl'
readonly READ_PRIVILEGES='Sys.Audit VM.Audit VM.Monitor Datastore.Audit'
readonly CONTROL_PRIVILEGES='Sys.Modify VM.Allocate VM.Audit VM.Backup VM.Clone VM.Config.CPU VM.Config.Cloudinit VM.Config.Disk VM.Config.HWType VM.Config.Memory VM.Config.Network VM.Config.Options VM.Console VM.Monitor VM.PowerMgmt VM.Snapshot VM.Snapshot.Rollback Datastore.Allocate Datastore.AllocateSpace Datastore.Audit SDN.Use'

ENV_FILE=''
DRY_RUN=0
ACL_ONLY=0
CONTROL_GLOBAL_ACL=0
declare -a CONTROL_SCOPES=()

usage() {
  cat <<'EOF'
Usage: sudo scripts/create-pve-tokens.sh [options]

Creates separate privilege-separated PVE API tokens for read-only collection
and control. The control token receives no ACL by default. Its backing user
and token get PPFlightAgentControl only with a reviewed --control-scope or the
explicitly dangerous --control-global-acl.

Options:
  --write-env [FILE]       Atomically save new IDs/secrets to FILE (default:
                           /etc/ppflight-agent/agent.env). Secrets never print.
  --control-scope PATH     Grant control role to its user and token at PATH;
                           repeatable (for example /pool/lab). PATH=/ is
                           rejected; use --control-global-acl explicitly.
  --control-pool NAME      Shorthand for --control-scope /pool/NAME.
  --acl-only               Do not create credentials or write secrets. Require
                           the existing dedicated control role, user and token,
                           then add only reviewed --control-scope/--control-pool
                           ACLs. Global / ACL is forbidden in this mode.
  --control-global-acl     DANGEROUS: grant the control role at /; only for an
                           isolated test cluster. Incompatible with --acl-only.
  --dry-run                Show intended work without invoking pveum.
  -h, --help               Show this help.

Existing PPFlight roles are reused only when their privilege set is an exact
match. Existing token IDs are never deleted or recreated. PVE cannot reveal a
token secret again, so credential creation fails before changing RBAC if either
requested token already exists.
EOF
}

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

valid_scope() {
  local scope=$1
  [[ $scope != '/' && $scope =~ ^/([A-Za-z0-9_.:-]+)(/[A-Za-z0-9_.:-]+)*$ ]]
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --write-env)
      ENV_FILE='/etc/ppflight-agent/agent.env'
      if [[ ${2:-} != '' && ${2:-} != --* ]]; then ENV_FILE=$2; shift; fi
      ;;
    --control-scope)
      [[ ${2:-} != '' && ${2:-} != --* ]] || die '--control-scope needs a PVE ACL path'
      valid_scope "$2" || die '--control-scope must be a canonical non-root PVE ACL path; use --control-global-acl for /'
      CONTROL_SCOPES+=("$2"); shift
      ;;
    --control-pool)
      [[ ${2:-} != '' && ${2:-} != --* ]] || die '--control-pool needs a pool name'
      [[ $2 =~ ^[A-Za-z0-9_.:-]+$ ]] || die '--control-pool must be a single canonical pool name'
      CONTROL_SCOPES+=("/pool/$2"); shift
      ;;
    --acl-only) ACL_ONLY=1 ;;
    --control-global-acl) CONTROL_GLOBAL_ACL=1 ;;
    --create-control-token) : ;; # Compatibility; control is now always created.
    --dry-run) DRY_RUN=1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done

[[ $CONTROL_GLOBAL_ACL -eq 0 || ${#CONTROL_SCOPES[@]} -eq 0 ]] || \
  die 'use either --control-global-acl or --control-scope options, not both'
if [[ $ACL_ONLY -eq 1 ]]; then
  [[ $CONTROL_GLOBAL_ACL -eq 0 ]] || die '--acl-only never grants /; use reviewed --control-scope or --control-pool paths'
  [[ -z $ENV_FILE ]] || die '--acl-only does not create or recover secrets and cannot use --write-env'
  (( ${#CONTROL_SCOPES[@]} > 0 )) || die '--acl-only requires at least one --control-scope or --control-pool'
fi

# Avoid repeating identical pveum ACL mutations while preserving CLI order.
if (( ${#CONTROL_SCOPES[@]} > 0 )); then
  declare -A seen_scope=()
  declare -a unique_scopes=()
  for scope in "${CONTROL_SCOPES[@]}"; do
    if [[ -z ${seen_scope[$scope]+present} ]]; then
      seen_scope[$scope]=1
      unique_scopes+=("$scope")
    fi
  done
  CONTROL_SCOPES=("${unique_scopes[@]}")
fi

if [[ $DRY_RUN -eq 1 ]]; then
  if [[ $ACL_ONLY -eq 1 ]]; then
    printf '%s\n' 'dry-run: would verify the existing dedicated control role/user/token and add only reviewed ACLs.'
  else
    printf '%s\n' 'dry-run: would preflight the environment target, both token IDs, roles and users, then create both tokens with compensating rollback for resources created by this run.'
    [[ -n $ENV_FILE ]] && printf 'dry-run: would atomically write root-only environment file: %s\n' "$ENV_FILE"
    [[ $CONTROL_GLOBAL_ACL -eq 1 ]] && printf '%s\n' 'dry-run: would grant the control role at / (DANGEROUS).'
  fi
  for scope in "${CONTROL_SCOPES[@]}"; do printf 'dry-run: would grant control role at %s\n' "$scope"; done
  exit 0
fi

if [[ $ACL_ONLY -eq 0 ]]; then
  # A PVE token secret is returned exactly once. Creating credentials without a
  # durable root-only destination would leave an unusable token behind.
  [[ -n $ENV_FILE ]] || die '--write-env is required when creating credentials (token secrets are never printed)'
fi

[[ $EUID -eq $EXPECTED_OWNER_UID ]] || die 'run as root on a PVE node'
command -v python3 >/dev/null 2>&1 || die 'python3 is required to safely parse pveum JSON'
PVEUM_BIN=${PVEUM_BIN:-pveum}
command -v "$PVEUM_BIN" >/dev/null 2>&1 || die 'pveum is required (set PVEUM_BIN only for a test mock)'

TMPDIR_BOOTSTRAP=$(mktemp -d "/tmp/ppflight-pve-bootstrap.XXXXXX")
chmod 700 "$TMPDIR_BOOTSTRAP"

declare -a CREATED_TOKENS=()
declare -a CREATED_USERS=()
declare -a CREATED_ROLES=()
declare -a CREATED_ACLS=()
MUTATIONS_STARTED=0
ENV_REPLACED=0

pveum() { command "$PVEUM_BIN" "$@"; }

restore_environment() {
  [[ $ENV_REPLACED -eq 1 ]] || return 0
  python3 - "$ENV_FILE" "$TMPDIR_BOOTSTRAP/env.previous" "$TMPDIR_BOOTSTRAP/env.existed" "$EXPECTED_OWNER_UID" "$EXPECTED_OWNER_GID" <<'PY'
import os, secrets, stat, sys

target, snapshot, existed_marker, expected_uid_text, expected_gid_text = sys.argv[1:]
expected_uid = int(expected_uid_text)
expected_gid = int(expected_gid_text)
parent, base = os.path.split(target)
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

def open_dir_nofollow(path):
    fd = os.open('/', flags)
    try:
        for component in [part for part in path.split('/') if part]:
            next_fd = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise

directory = open_dir_nofollow(parent)
temp_name = '.' + base + '.rollback.' + secrets.token_hex(12)
try:
    if os.path.exists(existed_marker):
        source = os.open(snapshot, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            temp = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            try:
                while True:
                    chunk = os.read(source, 65536)
                    if not chunk:
                        break
                    os.write(temp, chunk)
                os.fchmod(temp, 0o600)
                os.fchown(temp, expected_uid, expected_gid)
                os.fsync(temp)
            finally:
                os.close(temp)
        finally:
            os.close(source)
        os.replace(temp_name, base, src_dir_fd=directory, dst_dir_fd=directory)
    else:
        try:
            current = os.stat(base, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if current is not None:
            if (not stat.S_ISREG(current.st_mode) or current.st_uid != expected_uid or current.st_gid != expected_gid
                    or stat.S_IMODE(current.st_mode) != 0o600):
                raise OSError('refusing to remove an unexpected environment target during rollback')
            os.unlink(base, dir_fd=directory)
    os.fsync(directory)
finally:
    try:
        os.unlink(temp_name, dir_fd=directory)
    except FileNotFoundError:
        pass
    os.close(directory)
PY
}

rollback_created_objects() {
  local index record path kind identity role user token subject_option
  for (( index=${#CREATED_ACLS[@]}-1; index>=0; index-- )); do
    record=${CREATED_ACLS[$index]}
    IFS='|' read -r path kind identity role <<<"$record"
    subject_option='--users'
    [[ $kind == token ]] && subject_option='--tokens'
    pveum acl delete "$path" "$subject_option" "$identity" --roles "$role" >/dev/null 2>&1 || \
      printf 'warning: could not roll back newly added %s ACL for %s at %s\n' "$kind" "$identity" "$path" >&2
  done
  for (( index=${#CREATED_TOKENS[@]}-1; index>=0; index-- )); do
    identity=${CREATED_TOKENS[$index]}
    user=${identity%%!*}; token=${identity#*!}
    pveum user token remove "$user" "$token" >/dev/null 2>&1 || \
      printf 'warning: could not roll back newly created token %s; revoke it manually\n' "$identity" >&2
  done
  for (( index=${#CREATED_USERS[@]}-1; index>=0; index-- )); do
    pveum user delete "${CREATED_USERS[$index]}" >/dev/null 2>&1 || \
      printf 'warning: could not roll back newly created user %s\n' "${CREATED_USERS[$index]}" >&2
  done
  for (( index=${#CREATED_ROLES[@]}-1; index>=0; index-- )); do
    pveum role delete "${CREATED_ROLES[$index]}" >/dev/null 2>&1 || \
      printf 'warning: could not roll back newly created role %s\n' "${CREATED_ROLES[$index]}" >&2
  done
}

on_exit() {
  local status=$?
  trap - EXIT HUP INT TERM
  set +e
  if [[ $status -ne 0 && $MUTATIONS_STARTED -eq 1 ]]; then
    rollback_created_objects
    if ! restore_environment; then
      printf 'warning: could not restore the previous environment file; inspect %s without exposing its contents\n' "$ENV_FILE" >&2
    fi
  fi
  rm -rf -- "$TMPDIR_BOOTSTRAP"
  exit "$status"
}
trap on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# PVE lists are JSON arrays. Accept either short or full user!token token IDs.
json_list_has() {
  local json_file=$1 field=$2 wanted=$3 alternate=${4:-}
  python3 - "$json_file" "$field" "$wanted" "$alternate" <<'PY'
import json, sys
path, field, wanted, alternate = sys.argv[1:]
try:
    with open(path, encoding='utf-8') as source:
        payload = json.load(source)
except (OSError, ValueError):
    sys.exit(2)
items = payload if isinstance(payload, list) else payload.get('data', []) if isinstance(payload, dict) else []
if not isinstance(items, list):
    sys.exit(2)
sys.exit(0 if any(isinstance(item, dict) and str(item.get(field, '')) in (wanted, alternate) for item in items) else 1)
PY
}

list_json() {
  local out=$1; shift
  # Do not echo PVE diagnostics: token operations can contain sensitive data.
  pveum "$@" --output-format json >"$out" 2>"$TMPDIR_BOOTSTRAP/pveum.stderr" || return 1
}
role_exists() {
  local out="$TMPDIR_BOOTSTRAP/roles.json" status=0
  list_json "$out" role list || die 'could not list PVE roles'
  json_list_has "$out" roleid "$1" || status=$?
  [[ $status -eq 0 ]] && return 0
  [[ $status -eq 1 ]] && return 1
  die 'could not safely parse PVE role list JSON'
}
user_exists() {
  local out="$TMPDIR_BOOTSTRAP/users.json" status=0
  list_json "$out" user list || die 'could not list PVE users'
  json_list_has "$out" userid "$1" || status=$?
  [[ $status -eq 0 ]] && return 0
  [[ $status -eq 1 ]] && return 1
  die 'could not safely parse PVE user list JSON'
}
token_exists() {
  local user=$1 token=$2
  local out="$TMPDIR_BOOTSTRAP/token-${token}.json" status=0
  list_json "$out" user token list "$user" || die "could not list tokens for $user"
  json_list_has "$out" tokenid "$token" "$user!$token" || status=$?
  [[ $status -eq 0 ]] && return 0
  [[ $status -eq 1 ]] && return 1
  die "could not safely parse PVE token list JSON for $user"
}

ACL_SNAPSHOT="$TMPDIR_BOOTSTRAP/acls.json"
load_acl_snapshot() {
  local status=0
  list_json "$ACL_SNAPSHOT" acl list || die 'could not list PVE ACLs'
  python3 - "$ACL_SNAPSHOT" <<'PY' || status=$?
import json, sys
try:
    with open(sys.argv[1], encoding='utf-8') as source:
        payload = json.load(source)
    items = payload if isinstance(payload, list) else payload.get('data') if isinstance(payload, dict) else None
    if not isinstance(items, list):
        raise ValueError()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError()
        if not all(isinstance(item.get(field), str) and item[field] for field in ('path', 'roleid', 'type', 'ugid')):
            raise ValueError()
        if item['type'] not in ('user', 'group', 'token'):
            raise ValueError()
except (OSError, ValueError, json.JSONDecodeError):
    sys.exit(1)
PY
  [[ $status -eq 0 ]] || die 'could not safely validate PVE ACL list JSON'
}

acl_binding_exists() {
  local path=$1 kind=$2 identity=$3 role=$4
  python3 - "$ACL_SNAPSHOT" "$path" "$kind" "$identity" "$role" <<'PY'
import json, sys
source_path, wanted_path, wanted_type, wanted_identity, wanted_role = sys.argv[1:]
try:
    with open(source_path, encoding='utf-8') as source:
        payload = json.load(source)
    items = payload if isinstance(payload, list) else payload['data']
except (OSError, KeyError, ValueError, json.JSONDecodeError):
    sys.exit(2)
matches = [item for item in items if item.get('path') == wanted_path
           and item.get('type') == wanted_type and item.get('ugid') == wanted_identity
           and item.get('roleid') == wanted_role]
sys.exit(0 if len(matches) == 1 else 1 if not matches else 2)
PY
}

apply_acl() {
  local path=$1 kind=$2 identity=$3 role=$4 status=0 subject_option='--users'
  acl_binding_exists "$path" "$kind" "$identity" "$role" || status=$?
  case $status in
    0)
      printf 'Reusing existing %s ACL for %s at %s\n' "$kind" "$identity" "$path"
      return 0
      ;;
    1) ;;
    *) die "could not safely determine existing $kind ACL for $identity at $path" ;;
  esac
  [[ $kind == token ]] && subject_option='--tokens'
  MUTATIONS_STARTED=1
  pveum acl modify "$path" "$subject_option" "$identity" --roles "$role" >/dev/null
  CREATED_ACLS+=("$path|$kind|$identity|$role")
}

# Return 0 for an exact privilege match, 1 when absent, 3 for a mismatch, and
# 2 for an unreadable/ambiguous JSON contract. The PVE JSON field is expected
# to be roleid + privs; unknown shapes fail closed rather than guessing.
role_privileges_status() {
  local role=$1 expected=$2 out="$TMPDIR_BOOTSTRAP/role-contract-${role}.json"
  list_json "$out" role list || return 2
  python3 - "$out" "$role" "$expected" <<'PY'
import json, re, sys
path, wanted, expected_text = sys.argv[1:]

def privilege_set(value):
    if isinstance(value, str):
        parts = [part for part in re.split(r'[\s,]+', value.strip()) if part]
    elif isinstance(value, list) and all(isinstance(part, str) for part in value):
        parts = value
    else:
        raise ValueError()
    if len(parts) != len(set(parts)):
        raise ValueError()
    return set(parts)

try:
    with open(path, encoding='utf-8') as source:
        payload = json.load(source)
    items = payload if isinstance(payload, list) else payload.get('data') if isinstance(payload, dict) else None
    if not isinstance(items, list):
        raise ValueError()
    matches = [item for item in items if isinstance(item, dict) and item.get('roleid') == wanted]
    if not matches:
        sys.exit(1)
    if len(matches) != 1 or 'privs' not in matches[0]:
        raise ValueError()
    actual = privilege_set(matches[0]['privs'])
    expected = privilege_set(expected_text)
except (OSError, ValueError, json.JSONDecodeError):
    sys.exit(2)
sys.exit(0 if actual == expected else 3)
PY
}

inspect_role() {
  local role=$1 privileges=$2 status=0
  role_privileges_status "$role" "$privileges" || status=$?
  case $status in
    0) return 0 ;;
    1) return 1 ;;
    3) die "existing PVE role $role does not exactly match the required privilege set; refusing ACL changes" ;;
    *) die "could not safely validate privileges for PVE role $role" ;;
  esac
}

ensure_role() {
  local role=$1 privileges=$2 already_exists=$3
  if [[ $already_exists -eq 1 ]]; then
    printf 'Reusing exact-match PVE role: %s\n' "$role"
  else
    MUTATIONS_STARTED=1
    pveum role add "$role" -privs "$privileges" >/dev/null
    CREATED_ROLES+=("$role")
    printf 'Created PVE role: %s\n' "$role"
  fi
}
ensure_user() {
  local user=$1 already_exists=$2
  if [[ $already_exists -eq 1 ]]; then
    printf 'Reusing existing PVE user: %s\n' "$user"
  else
    MUTATIONS_STARTED=1
    pveum user add "$user" -comment 'PPFlight agent dedicated API account' >/dev/null
    CREATED_USERS+=("$user")
    printf 'Created PVE user: %s\n' "$user"
  fi
}

create_token() {
  local user=$1 token=$2 label=$3
  local out="$TMPDIR_BOOTSTRAP/${label}.json"
  MUTATIONS_STARTED=1
  # pveum emits the secret only in this JSON response. It stays in a private
  # temporary file, never stdout, stderr, or argv.
  if ! pveum user token add "$user" "$token" -privsep 1 --output-format json >"$out" 2>"$TMPDIR_BOOTSTRAP/${label}.stderr"; then
    die "could not create $label token (no token secret was exposed)"
  fi
  # Record creation before parsing: malformed success output still requires
  # revoking the now-unknown token during rollback.
  CREATED_TOKENS+=("$user!$token")
  if ! python3 - "$out" "$TMPDIR_BOOTSTRAP/${label}.id" "$TMPDIR_BOOTSTRAP/${label}.secret" "$user!$token" <<'PY'
import json, os, sys
source, id_path, secret_path, default_id = sys.argv[1:]
try:
    with open(source, encoding='utf-8') as handle:
        data = json.load(handle)
    secret = data.get('value') or data.get('secret')
    token_id = data.get('full-tokenid') or data.get('tokenid') or default_id
    if not isinstance(secret, str) or not secret or any(character in secret for character in '\x00\n\r'):
        raise ValueError()
    if not isinstance(token_id, str) or token_id != default_id:
        raise ValueError()
    for path, value in ((id_path, token_id), (secret_path, secret)):
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w', encoding='utf-8') as destination:
            destination.write(value + '\n')
            destination.flush()
            os.fsync(destination.fileno())
except (OSError, ValueError, json.JSONDecodeError, AttributeError):
    sys.exit(1)
PY
  then
    die "created $label token but could not securely parse its one-time response; it will be revoked"
  fi
}

preflight_environment() {
  local target=$1
  local status=0
  python3 - "$target" "$TMPDIR_BOOTSTRAP/env.previous" "$TMPDIR_BOOTSTRAP/env.existed" "$EXPECTED_OWNER_UID" "$EXPECTED_OWNER_GID" <<'PY' || status=$?
import os, secrets, stat, sys

target, snapshot, existed_marker, expected_uid_text, expected_gid_text = sys.argv[1:]
expected_uid = int(expected_uid_text)
expected_gid = int(expected_gid_text)
if not os.path.isabs(target):
    raise SystemExit(1)
parent, base = os.path.split(target)
if not base or base in ('.', '..'):
    raise SystemExit(1)
required_flags = ('O_DIRECTORY', 'O_NOFOLLOW')
if any(not hasattr(os, name) for name in required_flags):
    raise SystemExit(1)
directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

def open_dir_nofollow(path):
    descriptor = os.open('/', directory_flags)
    try:
        for component in [part for part in path.split('/') if part]:
            next_descriptor = os.open(component, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise

directory = open_dir_nofollow(parent)
probe_a = '.' + base + '.preflight.' + secrets.token_hex(12)
probe_b = probe_a + '.renamed'
try:
    parent_stat = os.fstat(directory)
    parent_mode = stat.S_IMODE(parent_stat.st_mode)
    # The installer intentionally uses root:ppflight-agent/0750 for the parent.
    # Its group is deliberately unconstrained: root ownership, owner write+search,
    # and no group/other write are the security boundary.
    if parent_stat.st_uid != expected_uid:
        raise OSError('unsafe environment parent owner')
    if (parent_mode & 0o300) != 0o300:
        raise OSError('environment parent must be owner-writable and searchable')
    if parent_mode & 0o022:
        raise OSError('unsafe environment parent ownership or mode')
    try:
        target_stat = os.stat(base, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        target_stat = None
    if target_stat is not None:
        if (not stat.S_ISREG(target_stat.st_mode) or target_stat.st_uid != expected_uid or target_stat.st_gid != expected_gid
                or stat.S_IMODE(target_stat.st_mode) != 0o600 or target_stat.st_nlink != 1):
            raise OSError('unsafe existing environment target')
        source = os.open(base, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            destination = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                while True:
                    chunk = os.read(source, 65536)
                    if not chunk:
                        break
                    os.write(destination, chunk)
                os.fsync(destination)
            finally:
                os.close(destination)
        finally:
            os.close(source)
        marker = os.open(existed_marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(marker)

    probe = os.open(probe_a, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    try:
        os.write(probe, b'ppflight-write-preflight\n')
        os.fsync(probe)
    finally:
        os.close(probe)
    os.rename(probe_a, probe_b, src_dir_fd=directory, dst_dir_fd=directory)
    os.fsync(directory)
    os.unlink(probe_b, dir_fd=directory)
    os.fsync(directory)
except (OSError, ValueError):
    raise SystemExit(1)
finally:
    for name in (probe_a, probe_b):
        try:
            os.unlink(name, dir_fd=directory)
        except FileNotFoundError:
            pass
    os.close(directory)
PY
  [[ $status -eq 0 ]] || die "environment target failed no-follow/owner/mode/atomic-write/fsync preflight: $target"
}

write_env() {
  local target=$1 status=0 marker="$TMPDIR_BOOTSTRAP/env.replaced"
  python3 - "$target" "$marker" "$EXPECTED_OWNER_UID" "$EXPECTED_OWNER_GID" \
    "$TMPDIR_BOOTSTRAP/read.id" "$TMPDIR_BOOTSTRAP/read.secret" \
    "$TMPDIR_BOOTSTRAP/control.id" "$TMPDIR_BOOTSTRAP/control.secret" <<'PY' || status=$?
import os, re, secrets, stat, sys

target, marker, expected_uid_text, expected_gid_text, *pairs = sys.argv[1:]
expected_uid = int(expected_uid_text)
expected_gid = int(expected_gid_text)
names = ('PVE_READ_TOKEN_ID', 'PVE_READ_TOKEN_SECRET', 'PVE_CONTROL_TOKEN_ID', 'PVE_CONTROL_TOKEN_SECRET')
parent, base = os.path.split(target)
directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

def open_dir_nofollow(path):
    descriptor = os.open('/', directory_flags)
    try:
        for component in [part for part in path.split('/') if part]:
            next_descriptor = os.open(component, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise

directory = open_dir_nofollow(parent)
temp_name = '.' + base + '.tmp.' + secrets.token_hex(12)

def mark_restore_needed():
    descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(descriptor, b'restore-needed\n')
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    marker_parent = os.path.dirname(marker) or '.'
    marker_directory = os.open(marker_parent, directory_flags)
    try:
        os.fsync(marker_directory)
    finally:
        os.close(marker_directory)

try:
    values = []
    for path in pairs:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, encoding='utf-8') as source:
            values.append(source.read().rstrip('\n'))
    if any(not value or any(character in value for character in '\x00\n\r') for value in values):
        raise ValueError()

    try:
        current = os.stat(base, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        current = None
    if current is not None:
        if (not stat.S_ISREG(current.st_mode) or current.st_uid != expected_uid or current.st_gid != expected_gid
                or stat.S_IMODE(current.st_mode) != 0o600 or current.st_nlink != 1):
            raise OSError('environment target changed after preflight')
        old_descriptor = os.open(base, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        with os.fdopen(old_descriptor, encoding='utf-8') as old_source:
            old = old_source.readlines()
    else:
        old = []

    assignment = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)=')
    kept = [line for line in old if not (assignment.match(line) and assignment.match(line).group(1) in names)]
    if kept and not kept[-1].endswith('\n'):
        kept[-1] += '\n'
    temp = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    try:
        with os.fdopen(temp, 'w', encoding='utf-8', newline='') as destination:
            destination.writelines(kept)
            for name, value in zip(names, values):
                destination.write(name + '=' + value + '\n')
            destination.flush()
            os.fchmod(destination.fileno(), 0o600)
            os.fchown(destination.fileno(), expected_uid, expected_gid)
            os.fsync(destination.fileno())
    except BaseException:
        try:
            os.close(temp)
        except OSError:
            pass
        raise
    # Persist recovery intent before replacing the old file. If replacement or
    # the directory fsync fails, rollback can safely restore the old snapshot;
    # it is also a no-op when the target was never replaced.
    mark_restore_needed()
    os.replace(temp_name, base, src_dir_fd=directory, dst_dir_fd=directory)
    os.fsync(directory)
except (OSError, ValueError):
    try:
        os.unlink(temp_name, dir_fd=directory)
    except FileNotFoundError:
        pass
    raise SystemExit(1)
finally:
    os.close(directory)
PY
  if [[ -f $marker ]]; then ENV_REPLACED=1; fi
  [[ $status -eq 0 ]] || die "could not atomically update root-only environment file: $target"
  printf 'Wrote token IDs and secrets to root-only environment file: %s\n' "$target"
}

role_state=0
inspect_role "$CONTROL_ROLE" "$CONTROL_PRIVILEGES" || role_state=$?
if [[ $ACL_ONLY -eq 1 ]]; then
  [[ $role_state -eq 0 ]] || die "--acl-only requires existing exact-match PVE role $CONTROL_ROLE"
  user_exists "$CONTROL_USER" || die "--acl-only requires existing dedicated PVE user $CONTROL_USER"
  token_exists "$CONTROL_USER" "$CONTROL_TOKEN" || die "--acl-only requires existing dedicated token $CONTROL_USER!$CONTROL_TOKEN"
  load_acl_snapshot
  for scope in "${CONTROL_SCOPES[@]}"; do
    apply_acl "$scope" user "$CONTROL_USER" "$CONTROL_ROLE"
    apply_acl "$scope" token "$CONTROL_USER!$CONTROL_TOKEN" "$CONTROL_ROLE"
  done
  MUTATIONS_STARTED=0
  printf '%s\n' 'PVE control ACL-only update completed; no credentials or secrets were created.'
  exit 0
fi

# The destination write/rename/fsync contract is tested before *any* PVE RBAC
# mutation. The same invariants are checked again at commit to close TOCTOU.
preflight_environment "$ENV_FILE"

# Inspect every existing role before creating either missing role. A role with
# the right name and a broader/narrower privilege set is never silently reused.
CONTROL_ROLE_EXISTING=0
[[ $role_state -eq 0 ]] && CONTROL_ROLE_EXISTING=1
READ_ROLE_EXISTING=0
role_state=0
inspect_role "$READ_ROLE" "$READ_PRIVILEGES" || role_state=$?
[[ $role_state -eq 0 ]] && READ_ROLE_EXISTING=1

READ_USER_EXISTING=0
CONTROL_USER_EXISTING=0
user_exists "$READ_USER" && READ_USER_EXISTING=1
user_exists "$CONTROL_USER" && CONTROL_USER_EXISTING=1

# Existing secrets cannot be recovered, so reject both IDs before mutations.
existing=()
if [[ $READ_USER_EXISTING -eq 1 ]]; then
  token_exists "$READ_USER" "$READ_TOKEN" && existing+=("$READ_USER!$READ_TOKEN")
fi
if [[ $CONTROL_USER_EXISTING -eq 1 ]]; then
  token_exists "$CONTROL_USER" "$CONTROL_TOKEN" && existing+=("$CONTROL_USER!$CONTROL_TOKEN")
fi
if (( ${#existing[@]} )); then
  die "existing token secret cannot be recovered; refusing to delete or recreate: ${existing[*]}. Keep the original secret or choose a new token name manually."
fi

# Snapshot and strictly validate ACL state before creating any RBAC object.
# Rollback removes only exact mappings absent from this snapshot and added by
# this invocation; pre-existing ACLs are never deleted.
load_acl_snapshot

ensure_role "$READ_ROLE" "$READ_PRIVILEGES" "$READ_ROLE_EXISTING"
ensure_role "$CONTROL_ROLE" "$CONTROL_PRIVILEGES" "$CONTROL_ROLE_EXISTING"
ensure_user "$READ_USER" "$READ_USER_EXISTING"
ensure_user "$CONTROL_USER" "$CONTROL_USER_EXISTING"

create_token "$READ_USER" "$READ_TOKEN" read
create_token "$CONTROL_USER" "$CONTROL_TOKEN" control

apply_acl / user "$READ_USER" "$READ_ROLE"
apply_acl / token "$READ_USER!$READ_TOKEN" "$READ_ROLE"

if [[ $CONTROL_GLOBAL_ACL -eq 1 ]]; then
  printf '%s\n' 'WARNING: granting control identity at / (isolated test clusters only).'
  CONTROL_SCOPES=(/)
fi
for scope in "${CONTROL_SCOPES[@]}"; do
  apply_acl "$scope" user "$CONTROL_USER" "$CONTROL_ROLE"
  apply_acl "$scope" token "$CONTROL_USER!$CONTROL_TOKEN" "$CONTROL_ROLE"
done

write_env "$ENV_FILE"
MUTATIONS_STARTED=0
ENV_REPLACED=0
if (( ${#CONTROL_SCOPES[@]} == 0 )); then
  printf '%s\n' 'Control token was created without ACLs. Add reviewed scopes later with --acl-only --control-scope/--control-pool.'
fi
printf '%s\n' 'PVE token bootstrap completed.'
