#!/usr/bin/env bash
# Revoke the fixed, dedicated PVE API identities created for PPFlight.
#
# This helper deliberately has no target/path arguments.  It only ever acts on
# PPFlight's two fixed users, their fixed tokens, and the two fixed roles.  It
# never invokes VM, template, storage, backup, or pool operations.
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly EXPECTED_OWNER_UID=0
readonly READ_USER='ppflight-agent@pve'
readonly READ_TOKEN='collector'
readonly CONTROL_USER='ppflight-control@pve'
readonly CONTROL_TOKEN='executor'
readonly READ_ROLE='PPFlightAgentAudit'
readonly CONTROL_ROLE='PPFlightAgentControl'

usage() {
  cat <<'EOF'
Usage: sudo scripts/remove-pve-credentials.sh

Revokes only PPFlight's fixed PVE API users and tokens, removes ACL bindings
owned by those identities, and removes the PPFlight roles when they are no
longer assigned elsewhere.  It never changes VMs, templates, storage, images,
or backups.
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 0 ]] || { usage >&2; die 'this helper does not accept arguments'; }
[[ ${EUID:-$(id -u)} -eq $EXPECTED_OWNER_UID ]] || die 'run as root on a PVE node'
command -v python3 >/dev/null 2>&1 || die 'python3 is required to safely parse pveum JSON'

# PVEUM_BIN is intentionally only a test seam.  All pveum subcommands and
# their arguments below are fixed by this script; no caller-controlled PVE
# object names are accepted.
PVEUM_BIN=${PVEUM_BIN:-pveum}
command -v "$PVEUM_BIN" >/dev/null 2>&1 || die 'pveum is required (set PVEUM_BIN only for a test mock)'

TMPDIR_REMOVE=$(mktemp -d '/tmp/ppflight-pve-remove.XXXXXX')
chmod 700 "$TMPDIR_REMOVE"
cleanup() {
  rm -rf -- "$TMPDIR_REMOVE"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

pveum() {
  command "$PVEUM_BIN" "$@"
}

# PVE lists are JSON arrays.  Some PVE versions wrap the same array in a
# `data` property; both forms are accepted, but malformed, ambiguous, or
# duplicate identifiers fail closed.
list_json() {
  local destination=$1
  shift
  pveum "$@" --output-format json >"$destination" 2>"$TMPDIR_REMOVE/pveum.stderr"
}

json_identifier_status() {
  local source=$1 field=$2 wanted=$3 alternate=${4:-}
  python3 - "$source" "$field" "$wanted" "$alternate" <<'PY'
import json
import sys

source, field, wanted, alternate = sys.argv[1:]
try:
    with open(source, encoding='utf-8') as handle:
        payload = json.load(handle)
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict) and isinstance(payload.get('data'), list):
        items = payload['data']
    else:
        raise ValueError('expected a JSON array')
    matches = 0
    for item in items:
        if not isinstance(item, dict):
            raise ValueError('list element is not an object')
        value = item.get(field)
        if not isinstance(value, str) or not value or any(ord(char) < 32 for char in value):
            raise ValueError('invalid identifier')
        if value == wanted or (alternate and value == alternate):
            matches += 1
    if matches == 1:
        raise SystemExit(0)
    if matches == 0:
        raise SystemExit(1)
    raise ValueError('duplicate identifier')
except (OSError, ValueError, json.JSONDecodeError, TypeError):
    raise SystemExit(2)
PY
}

identifier_exists() {
  local source=$1 field=$2 wanted=$3 alternate=${4:-} status=0
  json_identifier_status "$source" "$field" "$wanted" "$alternate" || status=$?
  case $status in
    0) return 0 ;;
    1) return 1 ;;
    *) die "could not safely parse PVE JSON while checking $wanted" ;;
  esac
}

# Write a deletion plan for every ACL owned by either dedicated PPFlight
# identity, irrespective of its assigned role.  Otherwise an unexpected ACL
# could survive token removal and regain authority when the same fixed token
# ID is created again.  ACLs held by any other subject are never deleted; they
# are used only to decide whether a PPFlight-defined role is shared and must be
# retained.  The strict path grammar also guarantees that the only value
# sourced from PVE JSON and reused as an argv is a canonical PVE ACL path.
classify_acls() {
  local source=$1 owned_plan=$2 foreign_roles=$3
  python3 - "$source" "$owned_plan" "$foreign_roles" \
    "$READ_USER" "$READ_TOKEN" "$CONTROL_USER" "$CONTROL_TOKEN" \
    "$READ_ROLE" "$CONTROL_ROLE" <<'PY'
import json
import re
import sys

(source, owned_path, foreign_path, read_user, read_token, control_user,
 control_token, read_role, control_role) = sys.argv[1:]
roles = {read_role, control_role}
users = {read_user, control_user}
tokens = {read_user + '!' + read_token, control_user + '!' + control_token}
path_pattern = re.compile(r'^/(?:[A-Za-z0-9_.:-]+(?:/[A-Za-z0-9_.:-]+)*)?$')

try:
    with open(source, encoding='utf-8') as handle:
        payload = json.load(handle)
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict) and isinstance(payload.get('data'), list):
        items = payload['data']
    else:
        raise ValueError('expected a JSON array')

    owned = []
    foreign = set()
    seen = set()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError('ACL entry is not an object')
        path = item.get('path')
        kind = item.get('type')
        identity = item.get('ugid')
        role = item.get('roleid')
        if (not isinstance(path, str) or not path_pattern.fullmatch(path) or
                kind not in {'user', 'token', 'group'} or
                not isinstance(identity, str) or not identity or
                not isinstance(role, str) or not role or
                any(ord(char) < 32 for char in identity + role)):
            raise ValueError('invalid ACL entry')
        key = (path, kind, identity, role)
        if key in seen:
            raise ValueError('duplicate ACL entry')
        seen.add(key)
        is_owned = ((kind == 'user' and identity in users) or
                    (kind == 'token' and identity in tokens))
        if is_owned:
            owned.append(key)
        elif role in roles:
            foreign.add(role)

    # Token ACLs are revoked before user ACLs.  This is not relied upon for
    # authorization, but makes the teardown sequence auditable and stable.
    kind_order = {'token': 0, 'user': 1}
    owned.sort(key=lambda value: (kind_order[value[1]], value[0], value[2], value[3]))
    with open(owned_path, 'w', encoding='utf-8', newline='\n') as destination:
        for path, kind, identity, role in owned:
            destination.write('\t'.join((path, kind, identity, role)) + '\n')
    with open(foreign_path, 'w', encoding='utf-8', newline='\n') as destination:
        for role in sorted(foreign):
            destination.write(role + '\n')
except (OSError, ValueError, json.JSONDecodeError, TypeError):
    raise SystemExit(1)
PY
}

remove_owned_acls() {
  local plan=$1 path kind identity role subject_option failed=0
  while IFS=$'\t' read -r path kind identity role; do
    [[ -n $path && -n $kind && -n $identity && -n $role ]] || die 'invalid internal ACL deletion plan'
    case $kind in
      token) subject_option='--tokens' ;;
      user) subject_option='--users' ;;
      *) die 'invalid internal ACL deletion subject' ;;
    esac
    if ! pveum acl delete "$path" "$subject_option" "$identity" --roles "$role"; then
      printf 'error: failed to remove PPFlight ACL at %s; credentials are preserved for retry\n' "$path" >&2
      failed=1
    fi
  done <"$plan"
  return "$failed"
}

require_list() {
  local destination=$1 description=$2
  shift 2
  list_json "$destination" "$@" || die "could not list $description as JSON"
}

USERS_JSON="$TMPDIR_REMOVE/users.json"
READ_TOKENS_JSON="$TMPDIR_REMOVE/read-tokens.json"
CONTROL_TOKENS_JSON="$TMPDIR_REMOVE/control-tokens.json"
ACLS_JSON="$TMPDIR_REMOVE/acls.json"
OWNED_ACLS_JSON_PLAN="$TMPDIR_REMOVE/owned-acls.plan"
FOREIGN_ROLES_PLAN="$TMPDIR_REMOVE/foreign-roles.plan"

require_list "$USERS_JSON" 'PVE users' user list
READ_USER_EXISTS=0
CONTROL_USER_EXISTS=0
identifier_exists "$USERS_JSON" userid "$READ_USER" && READ_USER_EXISTS=1
identifier_exists "$USERS_JSON" userid "$CONTROL_USER" && CONTROL_USER_EXISTS=1

READ_TOKEN_EXISTS=0
if [[ $READ_USER_EXISTS -eq 1 ]]; then
  require_list "$READ_TOKENS_JSON" "tokens for $READ_USER" user token list "$READ_USER"
  identifier_exists "$READ_TOKENS_JSON" tokenid "$READ_TOKEN" "$READ_USER!$READ_TOKEN" && READ_TOKEN_EXISTS=1
fi

CONTROL_TOKEN_EXISTS=0
if [[ $CONTROL_USER_EXISTS -eq 1 ]]; then
  require_list "$CONTROL_TOKENS_JSON" "tokens for $CONTROL_USER" user token list "$CONTROL_USER"
  identifier_exists "$CONTROL_TOKENS_JSON" tokenid "$CONTROL_TOKEN" "$CONTROL_USER!$CONTROL_TOKEN" && CONTROL_TOKEN_EXISTS=1
fi

require_list "$ACLS_JSON" 'PVE ACLs' acl list
classify_acls "$ACLS_JSON" "$OWNED_ACLS_JSON_PLAN" "$FOREIGN_ROLES_PLAN" || \
  die 'could not safely parse PVE ACL JSON'

# Remove the explicit role bindings while their user/token subjects still
# exist.  If any ACL deletion fails, stop before deleting either subject.  PVE
# releases that require the token/user to exist cannot safely retry deletion
# of an orphaned ACL after its subject has already been removed.
ACL_DELETE_FAILED=0
remove_owned_acls "$OWNED_ACLS_JSON_PLAN" || ACL_DELETE_FAILED=1
[[ $ACL_DELETE_FAILED -eq 0 ]] || die 'one or more PPFlight ACL deletions failed; credentials were preserved for a safe retry'

# Credential teardown is intentionally token -> user.  These are fixed argv
# calls and every object was checked from a strict JSON list first.
if [[ $READ_TOKEN_EXISTS -eq 1 ]]; then
  pveum user token remove "$READ_USER" "$READ_TOKEN" || die "failed to remove PVE token $READ_USER!$READ_TOKEN"
fi
if [[ $CONTROL_TOKEN_EXISTS -eq 1 ]]; then
  pveum user token remove "$CONTROL_USER" "$CONTROL_TOKEN" || die "failed to remove PVE token $CONTROL_USER!$CONTROL_TOKEN"
fi
if [[ $READ_USER_EXISTS -eq 1 ]]; then
  pveum user delete "$READ_USER" || die "failed to remove PVE user $READ_USER"
fi
if [[ $CONTROL_USER_EXISTS -eq 1 ]]; then
  pveum user delete "$CONTROL_USER" || die "failed to remove PVE user $CONTROL_USER"
fi

# PVE deletes a user's ACLs as part of user deletion.  Re-list and validate
# the ACL table before role deletion, both to prove that our owned role ACLs
# are gone and to avoid deleting a role which another subject now uses.
POST_ACLS_JSON="$TMPDIR_REMOVE/acls-post.json"
POST_OWNED_ACLS_PLAN="$TMPDIR_REMOVE/owned-acls-post.plan"
POST_FOREIGN_ROLES_PLAN="$TMPDIR_REMOVE/foreign-roles-post.plan"
require_list "$POST_ACLS_JSON" 'PVE ACLs after credential removal' acl list
classify_acls "$POST_ACLS_JSON" "$POST_OWNED_ACLS_PLAN" "$POST_FOREIGN_ROLES_PLAN" || \
  die 'could not safely parse PVE ACL JSON after credential removal'
if [[ -s $POST_OWNED_ACLS_PLAN ]]; then
  die 'PPFlight-owned role ACLs remain after credential removal; refusing role deletion'
fi

ROLES_JSON="$TMPDIR_REMOVE/roles.json"
require_list "$ROLES_JSON" 'PVE roles' role list

remove_role_if_unshared() {
  local role=$1 exists=0
  if identifier_exists "$ROLES_JSON" roleid "$role"; then
    exists=1
  fi
  [[ $exists -eq 1 ]] || return 0
  if grep -Fqx -- "$role" "$POST_FOREIGN_ROLES_PLAN"; then
    printf 'warning: preserving PVE role %s because it is still assigned to a non-PPFlight subject\n' "$role" >&2
    return 0
  fi
  pveum role delete "$role" || die "failed to remove PVE role $role"
}

# Roles are last.  A shared role contains no credential material and is safe
# to retain for an exact-match reuse on a later install; credentials have
# already been revoked successfully in that case.
remove_role_if_unshared "$READ_ROLE"
remove_role_if_unshared "$CONTROL_ROLE"

printf '%s\n' 'PPFlight fixed PVE credentials have been revoked.'
