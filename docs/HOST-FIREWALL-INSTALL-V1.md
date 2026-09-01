# PPFlight fresh-install host firewall contract v1

This contract applies only to the final, explicit host-firewall stage of a
verified **fresh** PPFlight Agent installation. It does not apply to
`ag-pve update`, an in-place reinstall that preserves Agent state, or remote
Agent commands.

## Operator-owned prerequisite

The installer does not inspect, install, configure, or gate on `cloudflared`,
Cloudflare Tunnel, Zero Trust, aaPanel, TCP 8888, or SSH. The operator proves
that recovery access works before starting the fresh installation. PPFlight
does not change the SSH daemon, its port, or any SSH allow rule.

## Scope separation

- The fresh installer enables the PVE Datacenter/Cluster firewall and the
  local Node firewall.
- It blocks new inbound host connections on every interface carrying a
  default IPv4 or IPv6 route. Loopback, established/related return traffic,
  and protocol traffic PVE requires before user rules are intentionally not
  described as new public inbound access.
- The Agent status endpoint and both exporters remain loopback-only. Website,
  monitoring, assignment, control, and upgrade traffic are outbound; no
  public inbound Agent port is opened.
- The installer does not enable a VM/CT firewall and does not change any guest
  `netN firewall` flag. Website customer actions own that decision.

## Why a DROP option alone is insufficient

PVE inserts built-in management accepts for its computed `management` IPSet
before the default input policy. A Cluster `policy_in=DROP` therefore does not
by itself block new connections to SSH, the PVE API/UI, consoles, SPICE, or
migration ports from that network. PPFlight must install an owned Node `IN
DROP` rule for each default-route ingress interface ahead of all administrator
and cluster rules, then verify its exact position and fields.

## Fresh-install classification

Before any installation mutation, the bootstrap records whether canonical
Agent binaries, units, configuration, runtime state, or a prior committed host
firewall journal already exist.

- No existing installation: create a root-only `initial-firewall-pending`
  journal and continue as a fresh install.
- Pending journal from the same incomplete initial install: resume or roll
  back the journal; never silently reclassify it as an update.
- Any existing installation without that pending journal: this is an update;
  preserve firewall state and skip the host-firewall stage.
- A complete uninstall removes the journal only after it has safely reverted
  PPFlight-owned firewall changes.

The classifier must reject symlinks, unexpected ownership/modes, unknown
journal versions, and conflicting markers.

## Multi-node safety gate

Enabling the Datacenter firewall is cluster-wide and the PVE Node firewall
defaults to enabled when its option is absent. A fresh install must not
activate a previously disabled Cluster firewall on a multi-node cluster from
one node. It must fail before firewall mutation unless the Cluster firewall is
already enabled or the target is a standalone one-node PVE installation.

## Transaction

The root-only journal stores schema version, node, detected ingress
interfaces, a random ownership marker, exact pre-change Cluster and Node
options, exact owned rules, digests, phase, and timestamps. It is durably
written before the first PVE mutation.

1. Read Cluster options, local Node options, local Node rules, cluster status,
   and IPv4/IPv6 default-route interfaces.
2. Reject no-route, loopback-only, unsafe interface names, duplicate owned
   markers, unsupported PVE versions, multi-node unsafe activation, and
   concurrent digest changes.
3. Create one disabled, uniquely marked Node `IN DROP` rule per ingress
   interface at the start of the Node ruleset.
4. Set Cluster `enable=1`, `policy_in=DROP`, and `policy_out=ACCEPT`; set the
   local Node `enable=1`.
5. Enable the owned rules only after the options and disabled rules are fully
   persisted.
6. Read back exact Cluster/Node options and every owned rule. Each owned rule
   must be enabled, match its interface/type/action/comment, and precede every
   non-owned Node rule.
7. Re-check local Agent/exporter services and loopback health. Do not probe
   Tunnel, Zero Trust, aaPanel, port 8888, or external SSH.
8. Commit the journal and only then print installation success.

Any error or interruption resumes from the durable phase and rolls back. A
failure must never print success.

## Rollback and complete uninstall

Rollback disables and removes only rules matching the stored random ownership
marker. It restores an option only when the current value still equals the
PPFlight-applied value; a concurrent administrator change is preserved and
reported for intervention. All updates/deletes use current PVE digests and
bounded retries.

Complete uninstall stops Agent/upgrade processes first, reverts the committed
host-firewall journal, verifies that no owned rule remains, and then continues
with credential and file removal. If firewall restoration cannot be proven,
the uninstall stops and preserves the binary, helper, journal, credentials,
and configuration for a safe retry.

## Required automated and real acceptance

- Shell/Go fixtures: fresh install, ordinary update, interrupted fresh retry,
  symlink/ownership rejection, no default route, duplicate route interfaces,
  cluster already enabled, unsafe multi-node activation, digest race, partial
  rule creation, readback mismatch, rollback, uninstall restore, and
  administrator drift preservation.
- Real standalone PVE 8/9 acceptance: operator proves Tunnel/Zero Trust first;
  fresh install succeeds; new public inbound SSH/8006/8888 connections fail;
  the existing installer session and Tunnel remain usable; Agent collection,
  website/monitoring delivery, control polling, and upgrades remain healthy.
- Guest acceptance: Create/Reinstall leaves guest and every `netN` firewall
  disabled; customer enable covers every mapped NIC with unique canonical MAC,
  exact `/32`/`/128` IPFilter entries, MACFilter, and strict readback.

