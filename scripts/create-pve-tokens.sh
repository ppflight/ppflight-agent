#!/usr/bin/env bash
# Creates dedicated Proxmox API tokens. It prints each token secret only once;
# immediately store it in /etc/ppflight-agent/agent.env with mode 0600.
set -Eeuo pipefail
IFS=$'\n\t'

CREATE_CONTROL=0
CONTROL_GLOBAL_ACL=0
READ_USER='ppflight-agent@pve'
READ_TOKEN='collector'
CONTROL_USER='ppflight-control@pve'
CONTROL_TOKEN='executor'

usage() {
  cat <<'EOF'
Usage: sudo scripts/create-pve-tokens.sh [--create-control-token] [--control-global-acl]

Creates a privsep PVE API token for read-only collection. With
--create-control-token it also creates a separate, broader write token for the
allowlisted control executor. Keep that write token absent while
control.productionExecution=false. The script changes PVE RBAC only when you
run it on a PVE node; it does not enable the agent or any service.

The control token is created without permissions by default. The deliberately
dangerous --control-global-acl option grants its role at / and is intended only
for an isolated test cluster. Production must grant the user and token scoped
ACLs for the managed pool/VM, node and storage paths after review.
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--create-control-token) CREATE_CONTROL=1; shift ;;
		--control-global-acl) CREATE_CONTROL=1; CONTROL_GLOBAL_ACL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'error: unknown option: %s\n' "$1" >&2; exit 1 ;;
  esac
done

[[ $EUID -eq 0 ]] || { printf 'error: run as root on a PVE node\n' >&2; exit 1; }
command -v pveum >/dev/null || { printf 'error: pveum is required\n' >&2; exit 1; }

role_exists() { pveum role list --output-format json | grep -Eq '"roleid"[[:space:]]*:[[:space:]]*"'"$1"'"'; }
user_exists() { pveum user list --output-format json | grep -Eq '"userid"[[:space:]]*:[[:space:]]*"'"$1"'"'; }
token_exists() { pveum user token list "$1" --output-format json | grep -Eq '"tokenid"[[:space:]]*:[[:space:]]*"'"$2"'"'; }

ensure_role() {
  local role=$1 privileges=$2
  if role_exists "$role"; then
    pveum role modify "$role" -privs "$privileges"
  else
    pveum role add "$role" -privs "$privileges"
  fi
}
ensure_user() {
  local user=$1
  user_exists "$user" || pveum user add "$user" -comment 'PPFlight agent dedicated API account'
}
create_token() {
  local user=$1 token=$2
  token_exists "$user" "$token" && { printf 'error: token %s!%s already exists; do not delete/recreate blindly. Choose a new token name manually.\n' "$user" "$token" >&2; exit 1; }
  pveum user token add "$user" "$token" -privsep 1
}

# VM.Monitor is required for the read-only QEMU guest-agent endpoints. No
# Datastore allocation, VM mutation or power-management privilege is present.
ensure_role PPFlightAgentAudit 'Sys.Audit VM.Audit VM.Monitor Datastore.Audit'
ensure_user "$READ_USER"
pveum acl modify / -user "$READ_USER" -role PPFlightAgentAudit
printf '%s\n' 'Read-only token result (record the token secret now):'
create_token "$READ_USER" "$READ_TOKEN"
# A privilege-separated token has no effective ACL until the token itself is
# granted one. Its permissions remain the intersection with its backing user.
pveum acl modify / -token "$READ_USER!$READ_TOKEN" -role PPFlightAgentAudit
printf '%s\n' 'Verified read token permissions:'
pveum user token permissions "$READ_USER" "$READ_TOKEN"

if [[ $CREATE_CONTROL -eq 1 ]]; then
  # This is deliberately separate. It grants only the families used by the
  # executor allowlist; review it against your PVE version and policy first.
  ensure_role PPFlightAgentControl 'VM.Allocate VM.Clone VM.Config.CPU VM.Config.Disk VM.Config.Memory VM.Config.Network VM.Config.Options VM.Monitor VM.PowerMgmt Datastore.AllocateSpace'
  ensure_user "$CONTROL_USER"
  printf '%s\n' 'Control token result (high privilege; record the secret now):'
  create_token "$CONTROL_USER" "$CONTROL_TOKEN"
	if [[ $CONTROL_GLOBAL_ACL -eq 1 ]]; then
		printf '%s\n' 'WARNING: granting the control user and token at / (isolated test clusters only).'
		pveum acl modify / -user "$CONTROL_USER" -role PPFlightAgentControl
		pveum acl modify / -token "$CONTROL_USER!$CONTROL_TOKEN" -role PPFlightAgentControl
		pveum user token permissions "$CONTROL_USER" "$CONTROL_TOKEN"
	else
		printf '%s\n' 'Control token created with no effective permissions. Grant reviewed ACLs to both the backing user and the privsep token before production use.'
	fi
fi

printf '%s\n' 'Set PVE_READ_TOKEN_ID/SECRET in agent.env. Set PVE_CONTROL_TOKEN_ID/SECRET only after explicit production-control approval.'
