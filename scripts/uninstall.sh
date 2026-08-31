#!/usr/bin/env bash
# Removes PPFlight program files. Configuration and queued accounting state are
# preserved unless --purge is explicitly given.
set -Eeuo pipefail
IFS=$'\n\t'

PURGE=0
REMOVE_EXPORTERS=0

usage() {
  cat <<'EOF'
Usage: sudo scripts/uninstall.sh [--remove-exporters] [--purge]

Stops and disables PPFlight units, then removes installed binaries and unit
files. --remove-exporters also removes PPFlight's private exporter binaries.
The Agent-owned, immutable cloud-template helper bundle is removed with the
Agent binary; PVE templates and image/backup data created by it are untouched.
--purge additionally revokes PPFlight's fixed PVE credentials and removes
/etc/ppflight-agent and /var/lib/ppflight-agent; that destroys the local
durable queue and should only be used after it has drained or been backed up.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --remove-exporters) REMOVE_EXPORTERS=1; shift ;;
    --purge) PURGE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'error: unknown option: %s\n' "$1" >&2; exit 1 ;;
  esac
done

[[ $EUID -eq 0 ]] || { printf 'error: run as root\n' >&2; exit 1; }
command -v systemctl >/dev/null || { printf 'error: systemd is required\n' >&2; exit 1; }

# A running old Agent can retain HMAC credentials in memory even after its
# files are removed.  Never purge the only recovery material until systemd has
# both accepted the stop and reported no MainPID.  `not-found` is the sole
# benign exception for an already-uninstalled unit.
stop_required_unit() {
  local unit=$1 load_state active_state main_pid
  if ! load_state="$(systemctl show --property=LoadState --value "$unit" 2>/dev/null)"; then
    printf 'error: cannot inspect required unit %s\n' "$unit" >&2
    return 1
  fi
  if [[ -z "$load_state" ]]; then
    printf 'error: required unit %s has an unknown load state\n' "$unit" >&2
    return 1
  fi
  if [[ "$load_state" != 'not-found' ]]; then
    if ! systemctl disable --now "$unit"; then
      printf 'error: failed to stop required unit %s; no files were removed\n' "$unit" >&2
      return 1
    fi
  fi
  if ! active_state="$(systemctl show --property=ActiveState --value "$unit" 2>/dev/null)"; then
    printf 'error: cannot verify required unit %s stopped; no files were removed\n' "$unit" >&2
    return 1
  fi
  # .path units do not expose MainPID; an empty MainPID is therefore normal
  # for them. Services must still prove a zero PID before credentials are
  # purged, so a live process can never survive complete uninstall.
  main_pid='not-applicable'
  if [[ "$unit" == *.service ]]; then
    if ! main_pid="$(systemctl show --property=MainPID --value "$unit" 2>/dev/null)"; then
      printf 'error: cannot verify required unit %s MainPID; no files were removed\n' "$unit" >&2
      return 1
    fi
    if [[ "$load_state" != 'not-found' && -z "$main_pid" ]]; then
      printf 'error: cannot verify required unit %s MainPID; no files were removed\n' "$unit" >&2
      return 1
    fi
  fi
  if [[ ( "$unit" == *.service && -n "$main_pid" && "$main_pid" != '0' ) || ( "$active_state" != 'inactive' && "$active_state" != 'failed' ) ]]; then
    printf 'error: required unit %s is still active (state=%s pid=%s); no files were removed\n' "$unit" "$active_state" "$main_pid" >&2
    return 1
  fi
}

# The upgrade path/service can invoke the privileged helper, so they are held
# to the same fail-closed stop/zero-PID rule as the main Agent.
for required_unit in ppflight-agent-upgrade.path ppflight-agent-upgrade.service ppflight-agent.service; do
  stop_required_unit "$required_unit" || exit 1
done

# A complete purge must also revoke the cluster-side credentials created by
# automatic local PVE preparation. Otherwise agent.env would be deleted while
# the unreadable one-time token secret remained in PVE, making a clean
# reinstall impossible. The fixed helper cannot touch guests, templates,
# storage, images, backups, or caller-selected PVE objects.
PVE_CREDENTIAL_REMOVER='/usr/local/lib/ppflight-agent/remove-pve-credentials.sh'
if [[ $PURGE -eq 1 ]]; then
  [[ -x "$PVE_CREDENTIAL_REMOVER" && ! -L "$PVE_CREDENTIAL_REMOVER" ]] || {
    printf 'error: PPFlight PVE credential remover is missing or unsafe; no Agent data or credentials were removed\n' >&2
    exit 1
  }
  "$PVE_CREDENTIAL_REMOVER" || {
    printf 'error: could not fully revoke PPFlight PVE credentials; local Agent files were preserved for a safe retry\n' >&2
    exit 1
  }
fi

# Exporters carry no Agent credential authority.  Only after the primary
# Agent is proved dead may their shutdown be best-effort; keep their unit/file
# intact when systemd cannot confirm removal rather than deleting a live unit.
stop_optional_exporter() {
  local unit=$1
  if ! stop_required_unit "$unit"; then
    printf 'warning: exporter unit %s was not stopped; preserving it\n' "$unit" >&2
    return 1
  fi
  return 0
}

EXPORTERS_STOPPED=1
for exporter_unit in ppflight-node-exporter.service ppflight-smartctl-exporter.service; do
  stop_optional_exporter "$exporter_unit" || EXPORTERS_STOPPED=0
done
rm -f -- /etc/systemd/system/ppflight-agent.service /etc/systemd/system/ppflight-agent-upgrade.path /etc/systemd/system/ppflight-agent-upgrade.service
rm -f -- /usr/lib/tmpfiles.d/ppflight-agent.conf
if [[ $REMOVE_EXPORTERS -eq 1 && $EXPORTERS_STOPPED -eq 1 ]]; then
  rm -f -- /etc/systemd/system/ppflight-node-exporter.service /etc/systemd/system/ppflight-smartctl-exporter.service
  rm -f -- /usr/local/lib/ppflight-agent/node_exporter /usr/local/lib/ppflight-agent/smartctl_exporter
elif [[ $REMOVE_EXPORTERS -eq 1 ]]; then
  printf '%s\n' 'warning: kept exporter files because systemd did not confirm every exporter stopped.' >&2
fi
systemctl daemon-reload

# Keep the binary and installed uninstaller available until every preceding
# systemd and state operation has succeeded.  A daemon-reload or purge failure
# can then be fixed and retried through AG instead of leaving a half-removed
# installation with no recovery entrypoint.
if [[ $PURGE -eq 1 ]]; then
  rm -rf -- /etc/ppflight-agent /var/lib/ppflight-agent
  printf '%s\n' 'Purged configuration and durable local queue.'
else
  printf '%s\n' 'Preserved /etc/ppflight-agent and /var/lib/ppflight-agent (including durable queue).'
fi

rm -f -- /usr/local/bin/ppflight-agent /usr/local/bin/ag-pve /usr/local/bin/ag /usr/local/bin/AG
rm -f -- /usr/local/lib/ppflight-agent/template-bootstrap
rm -f -- /usr/local/lib/ppflight-agent/create-pve-tokens.sh
rm -f -- /usr/local/lib/ppflight-agent/remove-pve-credentials.sh
rm -f -- /usr/local/lib/ppflight-agent/uninstall.sh
rm -f -- /usr/local/lib/ppflight-agent/quick-install.sh
rm -rf -- /usr/local/lib/ppflight-agent/template-bundles
rm -rf -- /usr/local/lib/ppflight-agent
