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
--purge additionally removes /etc/ppflight-agent and /var/lib/ppflight-agent;
that destroys the local durable queue and should only be used after it has
drained or has been backed up.
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

for unit in ppflight-agent-upgrade.path ppflight-agent-upgrade.service ppflight-agent.service ppflight-node-exporter.service ppflight-smartctl-exporter.service; do
  systemctl disable --now "$unit" 2>/dev/null || true
done
rm -f -- /etc/systemd/system/ppflight-agent.service /etc/systemd/system/ppflight-agent-upgrade.path /etc/systemd/system/ppflight-agent-upgrade.service
rm -f -- /usr/lib/tmpfiles.d/ppflight-agent.conf
if [[ $REMOVE_EXPORTERS -eq 1 ]]; then
  rm -f -- /etc/systemd/system/ppflight-node-exporter.service /etc/systemd/system/ppflight-smartctl-exporter.service
  rm -f -- /usr/local/lib/ppflight-agent/node_exporter /usr/local/lib/ppflight-agent/smartctl_exporter
fi
rm -f -- /usr/local/bin/ppflight-agent /usr/local/bin/ag-pve /usr/local/bin/ag /usr/local/bin/AG
rm -f -- /usr/local/lib/ppflight-agent/template-bootstrap
rm -f -- /usr/local/lib/ppflight-agent/create-pve-tokens.sh
rm -f -- /usr/local/lib/ppflight-agent/uninstall.sh
rm -rf -- /usr/local/lib/ppflight-agent/template-bundles
rm -rf -- /usr/local/lib/ppflight-agent
systemctl daemon-reload

if [[ $PURGE -eq 1 ]]; then
  rm -rf -- /etc/ppflight-agent /var/lib/ppflight-agent
  printf '%s\n' 'Purged configuration and durable local queue.'
else
  printf '%s\n' 'Preserved /etc/ppflight-agent and /var/lib/ppflight-agent (including durable queue).'
fi
