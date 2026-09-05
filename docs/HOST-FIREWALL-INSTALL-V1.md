# PPFlight PVE-only host firewall contract v1

This contract applies to every verified PPFlight Agent fresh install and
upgrade. Before installer mutation, the candidate binary runs a read-only UFW
and PVE-backend preflight. After the new Agent and its loopback services are
healthy, the root helper establishes and strictly verifies replacement PVE
protection, then removes UFW. A historical installation without a journal is
enrolled into the same durable transaction; it is not a firewall no-op.

Only the verified local installer or signed-upgrade postflight may enter this
transaction. Ordinary remote Agent actions cannot directly mutate this host
firewall state.

## Operator-owned prerequisite

The installer does not install, configure, or gate on `cloudflared`, Cloudflare
Tunnel, Zero Trust, aaPanel, TCP 8888, or SSH. The operator proves that recovery
access works before starting the fresh installation. PPFlight does not change
the SSH daemon, its port, or any SSH allow rule. It does inspect the base
IPv4/IPv6 INPUT order because an earlier aaPanel/UFW accept can otherwise
bypass PVE policy. It does not delete or rewrite aaPanel rules. UFW is handled
as a separate irreversible migration only after PVE protection is committed:
the exact Debian package, service, `ufw-*`/`ufw6-*` chain namespace and exact
jumps into that namespace are removed without executing `ufw disable`.

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

A correct Node rule is still ineffective when an independently managed base
INPUT rule accepts the packet before the normal `INPUT -> PVEFW-INPUT` jump.
PPFlight therefore atomically moves PVE's one exact native jump to the first
IPv4 INPUT position and does the same for IPv6. It never creates a second
reference to `PVEFW-INPUT`, so PVE can still delete its hook and chain during a
Cluster disable or backend switch. A root-only supervisor re-promotes only
that native hook if a local firewall manager later inserts rules ahead of it.

## Install and upgrade classification

Before any installation mutation, the bootstrap records whether canonical
Agent binaries, units, configuration, runtime state, or a prior committed host
firewall journal already exist.

- No existing installation: create a root-only `initial-firewall-pending`
  journal and continue as a fresh install.
- Pending journal from the same incomplete initial install: resume or roll
  back the journal; never silently reclassify it as an update.
- Any existing installation without a journal: this is an update; create a
  root-only transaction and establish the same PVE replacement before UFW
  removal.
- An update with a valid committed journal verifies and repairs only the exact
  owned PVE state, then resumes or verifies the UFW-removal phase.
- A reinstall after normal uninstall reuses the retained journal. A reinstall
  after purge may re-adopt only a complete, contiguous, enabled PPFlight rule
  block with one valid ownership identity, exact PVE options, and both native
  INPUT hooks already first. Ambiguous or partial residue fails closed.

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
options, exact owned rules, native IPv4/IPv6 hook tail-capture proofs, digests,
PVE phase, independent UFW phase, and timestamps. Both hook proofs are
atomically persisted before the first native-hook reorder. A re-adopted
post-uninstall transaction records that the hooks were deliberately retained
first and has no fabricated tail-rollback proof.

Before any apt, account, systemd, installed-file, or PVE mutation, the
candidate binary must:

1. Prove PVE 8/9 is using the legacy `pve-firewall` backend, not the Rust/nft
   backend.
2. Inventory the exact `ufw` dpkg state and `ufw.service` state.
3. If UFW is installed, prove one consistent Debian `/lib` (Bookworm) or
   `/usr/lib` (Trixie) package layout, root-owned non-writable package/config
   metadata, an unambiguous `MANAGE_BUILTINS=yes|no` and `ENABLED=yes|no`, and
   an ordinary packaged unit with no drop-ins or extra stop commands.

This preflight is read-only. Package absence plus an unrelated `ufw.service`,
unsafe metadata, a modified unit, or an unsupported backend aborts before
installation mutation.

The reversible PVE phase then proceeds:

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
6. Require the selected legacy `pve-firewall` backend using the Node nftables
   selector, the official Rust force-disable flag (or verified absence of the
   Rust binary), daemon state and subsequent live-chain proof. A simultaneously
   active `proxmox-firewall` daemon is not by itself proof that nft is selected.
   Prove each family has exactly one unmodified native PVE jump in PVE's
   canonical tail position. Persist that
   proof, then use one `iptables-legacy-restore --noflush` transaction per
   family to move the native jump ahead of aaPanel/UFW without modifying their
   rules. Enable the root-only supervisor and verify both native jumps are at
   position one.
7. Read back exact Cluster/Node options and every owned rule. Poll the compiled
   IPv4/IPv6 `PVEFW-HOST-IN` chains until the first user-rule block exactly
   contains one DROP for every captured default-route interface. Each owned rule
   must be enabled, match its interface/type/action/comment, and precede every
   non-owned Node rule.
8. Re-check local Agent/exporter services and loopback health. Do not probe
   Tunnel, Zero Trust, aaPanel, port 8888, or external SSH.
9. Commit the PVE journal. From this point, UFW migration failures must never
   roll the replacement PVE policy back.

The irreversible UFW phase then proceeds under the same root-only transaction
and process lock:

1. Persist `ufwPhase=removing`, then re-prove exact first-position
   `PVEFW-INPUT` hooks and unique `PVEFW-FORWARD` hooks for IPv4 and IPv6.
2. Parse bounded `iptables-legacy-save`/`ip6tables-legacy-save` snapshots for
   every table. Delete only rules whose target is a valid `ufw-*` or `ufw6-*`
   chain, then flush/delete only that namespace. Preserve every non-UFW chain
   and rule. Move the exact PVE FORWARD jump first and require its base policy
   to be `ACCEPT`.
3. UFW runtime residue is ownership evidence for restoring INPUT, OUTPUT and
   FORWARD base policies to `ACCEPT`. Without that evidence, preserve
   administrator INPUT/OUTPUT policies and fail on a non-`ACCEPT` FORWARD
   policy instead of overwriting it.
4. Atomically set `/etc/ufw/ufw.conf` to `ENABLED=no`, fsync and read it back.
   Only then stop/disable the already-proven ordinary unit. Never run `ufw
   disable`, `force-stop`, or package hooks while enabled: custom hooks and
   `MANAGE_BUILTINS=yes` could flush PVE chains.
5. Validate `dpkg --no-act --purge ufw`, then run exactly `dpkg --purge ufw`.
   Never use apt dependency solving, force flags, or autoremove. Reload
   systemd, repeat the scoped cleanup, and prove package/unit/UFW rules are
   absent while both PVE hooks and forwarding policy remain correct.
6. Persist `ufwPhase=removed`; only this verified state may report install or
   upgrade success.

An interruption before the PVE commit resumes or safely rolls back. An
interruption after that commit resumes UFW removal while keeping PVE
protection. This includes a crash after dpkg removed the unit file but before
`daemon-reload`: recovery accepts only an inactive, disabled cached unit whose
definition is still exactly the packaged Debian definition. A failure must
never print success.

## Rollback and complete uninstall

Rollback first stops the PPFlight priority supervisor while leaving PVE's sole
native INPUT jump in its fail-closed first position. It then disables/removes
only PVE rules carrying the stored random ownership marker and restores an option
only when the current value still equals the PPFlight-applied value. After all
PVE mutations have succeeded, it atomically restores the native jump to PVE's
canonical appended position. A
concurrent administrator change is preserved and reported for intervention.
All PVE updates/deletes use current digests and bounded retries. Runtime
Cluster disable is observed without recreating either hook or chain; when PVE
later appends its exact native hook again, the supervisor atomically promotes
it. Stopping or crashing the supervisor never demotes the hook. Restarts use
bounded rate limits.

Before UFW migration begins, complete uninstall uses the reversible rollback
above. Once UFW migration begins, uninstall must first finish and strictly
verify the purge, then retain the PVE Cluster/Node options, owned DROP rules,
and first-position native INPUT hooks. It disables only the PPFlight
supervisor; it never restores UFW or demotes the retained hook. Purge may then
remove the local journal, because a later reinstall can re-adopt only the exact
retained ownership block described above. If either restoration or retained
protection cannot be proven, uninstall stops and preserves the recovery
binary, journal, credentials, and configuration for retry.

That guarantee is an uninstall-time readback, not continuing enforcement after
the Agent is gone. Complete uninstall removes the supervisor, so a later PVE
firewall or aaPanel reload (including one after reboot) can change native-hook
order without PPFlight repairing it. The administrator owns recovery access
and must inspect the live dual-stack hook order after such a reload. PPFlight
does not leave its binary behind while calling the operation a complete
uninstall.

`ag-pve overview` does not treat a committed journal as proof of current
protection. For a committed transaction it separately reports the selected
legacy backend, the supervisor's active/enabled state, the IPv4/IPv6 native
hook positions, and the compiled IPv4/IPv6 runtime DROP proof. Any failed live
check is shown as an operational failure requiring immediate inspection.

## Required automated and real acceptance

- Shell/Go fixtures: fresh install, journal-less update enrollment,
  committed-journal priority migration, interrupted fresh retry,
  symlink/ownership rejection, no default route, duplicate route interfaces,
  cluster already enabled, unsafe multi-node activation, digest race, partial
  rule creation, readback mismatch, rollback, UFW absence/install/partial
  purge recovery, exact scoped dual-stack cleanup, PVE FORWARD enforcement,
  normal and purge uninstall/reinstall adoption, and administrator drift
  preservation.
- Real standalone PVE 8/9 acceptance: operator proves Tunnel/Zero Trust first;
  fresh install succeeds; PVE's sole native IPv4/IPv6 jumps are the first base INPUT
  rules, its FORWARD jumps are first with `ACCEPT` policies, UFW package/unit
  and runtime namespace are absent, and existing aaPanel state is unchanged; new public
  inbound SSH/8006/8888 connections fail;
  the existing installer session and Tunnel remain usable; Agent collection,
  website/monitoring delivery, control polling, and upgrades remain healthy.
- Guest acceptance: the host-firewall installer itself never rewrites existing
  guests. A later Create/Reinstall may pass through a dormant IPSet
  preconfiguration state, but final delivery enables guest and every managed
  `netN` firewall with `ACCEPT/ACCEPT`, unique canonical MAC, exact
  `/32`/`/128` IPFilter entries, MACFilter, and strict readback. This provider
  anti-spoof baseline is separate from the customer port-rule switch and adds
  no default `DROP`/`REJECT` rules.
