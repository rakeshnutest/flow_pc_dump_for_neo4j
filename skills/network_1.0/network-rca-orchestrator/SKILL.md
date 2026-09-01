---
name: network-rca-orchestrator
description: >-
  Composite Network RCA chain for Panacea 1.0. Mandatory path includes DND,
  ping/TCP, NIC/MTU/L1-CRC, SAR+iostat host pressure, then expert checks.
  Never close without CRC/drop/link and storage classes stated.
skill_type: composite
component: networking
sub_component: network_rca_chain
keywords:
  - network-rca
  - dnd
  - ping-tcp
  - nic-mtu-ncc
  - crc
  - sar
  - firewall
  - cassandra
  - ovs
symptoms:
  - "Need bundle-wide Network RCA from Panacea / logbay evidence"
  - "Network latency, packet loss, timeout, or degraded-node symptoms"
severity: P0-P2
roles_allowed: [engineer, sre]
mcp_capabilities_required:
  - logs.search
composes:
  - networking/network-dnd-window
  - networking/network-ping-tcp-baseline
  - networking/network-nic-mtu-ncc
  - networking/network-sar-debugging
  - networking/network-firewall-iptables
  - networking/network-cassandra-metadata
  - networking/network-host-pressure
  - networking/network-storage-io
  - networking/network-upgrade-config-change
  - networking/network-ovs-host-evidence
last_verified: 2026-09-01
---

## Purpose
Coordinator checklist for Network RCA. Prefer **logbay PE bundle** when
ClickHouse lightweight bundles lack sysstats.

## Hard rule — complete class coverage

Before synthesis, every chain must emit status for:

1. **DND window**
2. **Path** (ping/TCP)
3. **L1 / CRC / link / drops** (ethtool + host_nic_stats — CRC=0 is a finding)
4. **SAR traffic** (rates, rxdrop, rxerr)
5. **Host pressure** (iostat iowait / disk await)
6. Expert branches as triggered (firewall, Cassandra, OVS, upgrade, storage-io)

Missing source → `EVIDENCE_INSUFFICIENT` for that class. Do **not** omit.

## Chain (ReAct order)

1. **DND** — [network-dnd-window](../network-dnd-window/SKILL.md)
2. **Ping/TCP** — [network-ping-tcp-baseline](../network-ping-tcp-baseline/SKILL.md)
3. **NIC + L1 CRC** — [network-nic-mtu-ncc](../network-nic-mtu-ncc/SKILL.md)
4. **SAR + iostat + L1 one-pass** — [network-sar-debugging](../network-sar-debugging/SKILL.md)
   ```bash
   python3 .../network-sar-debugging/scripts/analyze_sar_network.py \
     --bundle-root /path/to/NTNX-Log-...-PE-<cvm>
   ```
   Must detect **EXTERNAL_RX_FLOOD** (all bond members, not hardcoded NICs) and
   **PING_FLOOD_CORRELATION** from diamond/logbay only. Prefer flood over storage
   as the network root cause when ping↔flood correlates. **Do not** emit switch
   trunk/VLAN/stop-source `action_plan` — that is not in the logs.
5. **Host pressure / storage** — [network-host-pressure](../network-host-pressure/SKILL.md),
   [network-storage-io](../network-storage-io/SKILL.md) if storage class positive
   (co-contributor when flood also correlates — do not hide the flood).
6. Expert: firewall / Cassandra / OVS / upgrade as suggested by baselines
7. Synthesize primary `root_class` + contributors; list ruled-out checks

## Common Pitfalls

- Closing on SAR drops without stating **CRC**
- Treating missing CH coverage as no issue (use diamond/logbay)
- Storage RCA without L1 class (or L1 without storage when DND + iowait)
- Inventing trunk/VLAN/stop-source remediations not present in diamond logs
- Calling active-backup standby “NIC down” when link is up and member enabled

## See also

- [network-dnd-window](../network-dnd-window/SKILL.md)
- [network-ping-tcp-baseline](../network-ping-tcp-baseline/SKILL.md)
- [network-nic-mtu-ncc](../network-nic-mtu-ncc/SKILL.md)
- [network-sar-debugging](../network-sar-debugging/SKILL.md)
- [network-firewall-iptables](../network-firewall-iptables/SKILL.md)
- [network-cassandra-metadata](../network-cassandra-metadata/SKILL.md)
- [network-host-pressure](../network-host-pressure/SKILL.md)
- [network-storage-io](../network-storage-io/SKILL.md)
- [network-upgrade-config-change](../network-upgrade-config-change/SKILL.md)
- [network-ovs-host-evidence](../network-ovs-host-evidence/SKILL.md)
