#!/usr/bin/env bash
# Revoke the fixed, dedicated PVE API identities created for PPFlight.
#
# This helper deliberately has no target/path arguments.  It only ever acts on
# PPFlight's two fixed users, their fixed tokens, every ACL owned by those
# identities, and the two fixed role definitions when they still match a
# published PPFlight privilege contract and are not assigned to another
# subject.  It never invokes VM, template, storage, backup, or pool mutation
# operations.
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

Revokes only PPFlight's fixed PVE API users and tokens and removes every ACL
owned by those identities. The two fixed PPFlight roles are removed only when
an atomic PVE user.cfg transaction proves that each role has a known historical
PPFlight privilege set and no remaining ACL reference. Shared or customized
roles are retained. It never changes VMs, templates, storage, images, or
backups.
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

# PVE_ROLE_CLEANER_BIN is a test seam equivalent to PVEUM_BIN. Production
# leaves it empty and executes the embedded PVE cluster transaction below.
PVE_ROLE_CLEANER_BIN=${PVE_ROLE_CLEANER_BIN:-}

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
# are ignored.  The strict path grammar also guarantees that the only value
# sourced from PVE JSON and reused as an argv is a canonical PVE ACL path.
classify_acls() {
  local source=$1 owned_plan=$2
  python3 - "$source" "$owned_plan" \
    "$READ_USER" "$READ_TOKEN" "$CONTROL_USER" "$CONTROL_TOKEN" <<'PY'
import json
import re
import sys

(source, owned_path, read_user, read_token, control_user,
 control_token) = sys.argv[1:]
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

    # Token ACLs are revoked before user ACLs.  This is not relied upon for
    # authorization, but makes the teardown sequence auditable and stable.
    kind_order = {'token': 0, 'user': 1}
    owned.sort(key=lambda value: (kind_order[value[1]], value[0], value[2], value[3]))
    with open(owned_path, 'w', encoding='utf-8', newline='\n') as destination:
        for path, kind, identity, role in owned:
            destination.write('\t'.join((path, kind, identity, role)) + '\n')
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
classify_acls "$ACLS_JSON" "$OWNED_ACLS_JSON_PLAN" || \
  die 'could not safely parse PVE ACL JSON'

# Remove every ACL while its user/token subject still
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

# Re-list and validate that no ACL owned by either fixed identity remains.
POST_ACLS_JSON="$TMPDIR_REMOVE/acls-post.json"
POST_OWNED_ACLS_PLAN="$TMPDIR_REMOVE/owned-acls-post.plan"
require_list "$POST_ACLS_JSON" 'PVE ACLs after credential removal' acl list
classify_acls "$POST_ACLS_JSON" "$POST_OWNED_ACLS_PLAN" || \
  die 'could not safely parse PVE ACL JSON after credential removal'
if [[ -s $POST_OWNED_ACLS_PLAN ]]; then
  die 'PPFlight-owned ACLs remain after credential removal'
fi

# `pveum role delete` does not remove/check ACL references atomically. Perform
# the final known-role cleanup under PVE's own user.cfg cluster lock instead.
# Only exact privilege sets shipped by PPFlight are eligible, including the
# pre-SDN read role left by RC.5/RC.6-era installations. A customized or shared
# role is preserved and reported rather than guessed to be ours.
ROLE_CLEANUP_RESULT="$TMPDIR_REMOVE/role-cleanup.result"
if [[ -n $PVE_ROLE_CLEANER_BIN ]]; then
  command "$PVE_ROLE_CLEANER_BIN" >"$ROLE_CLEANUP_RESULT" || \
    die 'could not atomically clean up unused PPFlight PVE roles'
else
  command -v perl >/dev/null 2>&1 || die 'perl is required to atomically clean up PVE roles'
  perl - "$READ_ROLE" "$CONTROL_ROLE" >"$ROLE_CLEANUP_RESULT" <<'PL' || \
    die 'could not atomically clean up unused PPFlight PVE roles'
use strict;
use warnings;
use PVE::AccessControl ();
use PVE::Cluster qw(cfs_read_file cfs_write_file);

my ($read_role, $control_role) = @ARGV;
my %known = (
    $read_role => {
        join(' ', sort split(/\s+/, 'Sys.Audit VM.Audit VM.Monitor Datastore.Audit')) => 1,
        join(' ', sort split(/\s+/, 'Sys.Audit VM.Audit VM.Monitor Datastore.Audit SDN.Audit')) => 1,
    },
    $control_role => {
        join(' ', sort split(/\s+/, 'VM.Allocate VM.Clone VM.Config.CPU VM.Config.Disk VM.Config.Memory VM.Config.Network VM.Config.Options VM.Monitor VM.PowerMgmt Datastore.AllocateSpace')) => 1,
        join(' ', sort split(/\s+/, 'Sys.Modify VM.Allocate VM.Audit VM.Backup VM.Clone VM.Config.CPU VM.Config.Cloudinit VM.Config.Disk VM.Config.HWType VM.Config.Memory VM.Config.Network VM.Config.Options VM.Console VM.Monitor VM.PowerMgmt VM.Snapshot VM.Snapshot.Rollback Datastore.Allocate Datastore.AllocateSpace Datastore.Audit SDN.Use')) => 1,
    },
);
my @result;

sub acl_references_role {
    my ($node, $role) = @_;
    return 0 if ref($node) ne 'HASH';
    for my $kind (qw(users groups tokens)) {
        my $members = $node->{$kind};
        next if ref($members) ne 'HASH';
        for my $member (values %$members) {
            return 1 if ref($member) eq 'HASH' && exists($member->{$role});
        }
    }
    my $children = $node->{children};
    if (ref($children) eq 'HASH') {
        for my $child (values %$children) {
            return 1 if acl_references_role($child, $role);
        }
    }
    return 0;
}

PVE::AccessControl::lock_user_config(
    sub {
        my $usercfg = cfs_read_file('user.cfg');
        my $changed = 0;
        for my $role ($read_role, $control_role) {
            my $definition = $usercfg->{roles}->{$role};
            if (ref($definition) ne 'HASH') {
                push @result, "absent\t$role";
                next;
            }
            my $signature = join(' ', sort keys %$definition);
            if (!$known{$role}->{$signature}) {
                push @result, "preserved-custom\t$role";
                next;
            }
            if (acl_references_role($usercfg->{acl_root}, $role)) {
                push @result, "preserved-shared\t$role";
                next;
            }
            delete($usercfg->{roles}->{$role});
            $changed = 1;
            push @result, "removed\t$role";
        }
        cfs_write_file('user.cfg', $usercfg) if $changed;
    },
    'PPFlight role cleanup failed',
);

print "$_\n" for @result;
PL
fi

READ_ROLE_RESULT_COUNT=0
CONTROL_ROLE_RESULT_COUNT=0
while IFS=$'\t' read -r role_status role_name extra; do
  [[ -z $extra ]] || die 'invalid PPFlight role cleanup result'
  case "$role_name" in
    "$READ_ROLE") READ_ROLE_RESULT_COUNT=$((READ_ROLE_RESULT_COUNT + 1)) ;;
    "$CONTROL_ROLE") CONTROL_ROLE_RESULT_COUNT=$((CONTROL_ROLE_RESULT_COUNT + 1)) ;;
    *) die 'invalid PPFlight role cleanup target' ;;
  esac
  case "$role_status" in
    removed|absent) ;;
    preserved-shared)
      printf 'warning: preserved PVE role %s because another ACL still references it\n' "$role_name" >&2
      ;;
    preserved-custom)
      printf 'warning: preserved PVE role %s because its privileges are not an exact published PPFlight contract\n' "$role_name" >&2
      ;;
    *) die 'invalid PPFlight role cleanup status' ;;
  esac
done <"$ROLE_CLEANUP_RESULT"

[[ $READ_ROLE_RESULT_COUNT -eq 1 && $CONTROL_ROLE_RESULT_COUNT -eq 1 ]] || \
  die 'incomplete or duplicate PPFlight role cleanup result'

printf '%s\n' 'PPFlight fixed PVE credentials, owned ACLs, and unshared known role definitions have been removed.'
