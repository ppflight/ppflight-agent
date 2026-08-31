# Monitoring network projection v1

Agent `v0.1.0-rc.22` keeps the monitoring batch `schemaVersion` at `1` and
adds one strict field to each `guests[]` item:

```json
{
  "networkProjection": {
    "schemaVersion": 1,
    "interfaces": [
      {
        "interfaceRef": "net0",
        "mappingStatus": "mapped",
        "source": "qga",
        "guestInterfaceName": "eth0",
        "canonicalMac": "02:00:00:00:00:01",
        "addresses": [{"address":"192.0.2.10","prefix":24,"type":"ipv4"}],
        "counters": {
          "available": true,
          "source": "qga",
          "rxBytes": "1",
          "txBytes": "2"
        }
      }
    ],
    "unmappedGuestInterfaces": []
  }
}
```

`interfaceRef` is the PVE `net0`-`net31` identity. QEMU interfaces are linked
only by a unique canonical six-byte unicast MAC. Names and enumeration order
are never identity. All cumulative counters use the existing `uint64` decimal
string codec; missing values are omitted and never synthesized as zero.

Exact `mappingStatus`: `mapped`, `unmapped`.

Exact `source`: `qga`, `pve-config`, `unavailable`.

Exact mapping reasons:

- `qga_interfaces_unavailable`
- `qga_mac_missing`
- `qga_mac_invalid`
- `duplicate_qga_mac`
- `pve_mac_missing`
- `pve_mac_invalid`
- `ambiguous_pve_mac`
- `pve_interface_not_found`
- `qga_interface_not_found`

Exact counter reasons:

- `qga_counters_missing`
- `qga_counters_incomplete`
- `lxc_per_nic_counters_unavailable`

For LXC, `source` is `pve-config`, `configuredAddressing.ipv4/ipv6` contains
only a validated static CIDR or exact `dhcp`, `auto`, or `manual` mode. Invalid
configuration is not echoed and becomes `mode=unavailable` with
`reason=invalid_pve_config`. LXC per-NIC counters remain explicitly
unavailable.

PVE `netin/netout` remain guest aggregate metering inputs. They are not copied
into this projection and the signed NIC metering policy is unchanged.
