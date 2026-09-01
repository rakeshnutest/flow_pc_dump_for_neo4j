---
name: network-sar-debugging
description: >-
  Full host/CVM network+pressure RCA from diamond/logbay only. ALWAYS start with
  bond/LAG member discovery (no hardcoded ethN). Detect fabric RX flood on all
  bond members from sar/host_nic_stats, correlate with ping LOST_PKT/unreachable.
  Do NOT invent switch trunk/VLAN/stop-source remediations — those are not in logs.
skill_type: atomic
component: networking
sub_component: network_sar_debugging
keywords:
  - sar
  - iostat
  - bond
  - lag
  - rx flood
  - ping
  - tso
  - gro
  - dmesg
  - crc
  - network-debugging
  - dnd
symptoms:
  - "Intermittent CVM/host connectivity or peer timeouts"
  - "Ping LOST_PKT/unreachable during traffic surge"
  - "Cassandra timeouts correlating with host RX pps spikes"
  - "Need SAR/iostat/CRC/bond root-cause for DND or packet loss"
severity: P0-P2
roles_allowed: [engineer, sre]
mcp_capabilities_required:
  - logs.search
last_verified: 2026-09-01
---

# Network SAR Debugging (diamond/logbay only)

## Hard rules

1. **Evidence scope = diamond/logbay bundle only** (`cvm_logs/sysstats`, `ahv/*/commands`).
   If the flood window is in the collected `sar.INFO*` / `ping_*.INFO*` / `host_nic_stats`,
   discover it. If not collected, emit `EVIDENCE_INSUFFICIENT` — do not invent live paste RCA.
2. **Never hardcode NIC names.** Discover members from **bond/LAG**.
3. **Always** emit: `BOND_LAG`, `EXTERNAL_RX_FLOOD`, `PING_FLOOD_CORRELATION`,
   `OFFLOAD_TSO_GRO`, `RING`, `DMESG_NIC`, L1/CRC, SAR, latency, ping.
4. Missing source → `EVIDENCE_INSUFFICIENT` for that class — do not omit the key.
5. **CRC=0 is a finding.** Soft `rx_dropped` ≠ CRC. Standby-member drops alone ≠ active-path loss.
6. **Do not** call active-backup standby “NIC down” when link is up and member is enabled.
7. When ping fails overlap SAR RX flood windows → primary root = **`EXTERNAL_RX_FLOOD`**
   (storage may be a co-contributor).
8. **Disconnected from flood RCA (do not emit):**
   - Switch trunk “allow only Nutanix VLANs”
   - Stop-source / SPAN capture playbooks
   - PC/OVN recovery sequencing as if proven by these logs  
   Those may be engineering follow-ups, but **they are not present in diamond logs** and
   must not appear as skill `action_plan` or as part of `root_cause_sentence`.

## Mandatory classes

| Class | Diamond sources | What |
|---|---|---|
| **Bond / LAG** | `ahv/*/commands/ovs-appctl_bond_show.stdout` | mode, active, member roles |
| **External RX flood** | `cvm_logs/sysstats/sar.INFO*` (all ifaces) | High `rxpck/s`; standby high RX + ~0 TX |
| **Ping↔flood** | `ping_*.INFO*` + flood windows | LOST_PKT/unreachable within ~2 min of flood |
| **Soft drops** | `host_nic_stats.INFO*`, `ethtool_-S_*.stdout` | Rising soft `rx_dropped` (not CRC) |
| **Offload / rings / dmesg** | ahv ethtool + `dmesg_-T.stdout` | TSO/GSO/GRO/LRO, rings, link flaps |
| **SSD latency** | `iostat.INFO*` | Secondary if flood correlates |
| **Path** | `ping_*.INFO*` | unreachable / LOST_PKT |

## Procedure (ReAct — bond → flood → ping from bundle)

1. Discover PE bundle root under diamond.
2. Parse bond/LAG → dynamic members + roles.
3. Per member: ethtool link/`-S`/`-k`/`-g`, dmesg flaps.
4. Scan **every** non-lo SAR iface for RX flood (≥100k rxpck/s; strong ≥500k or multi-iface / standby RX≈0 TX).
5. Parse timestamped ping fails; correlate within ~120s of flood walls.
6. Classify: ping↔flood → `EXTERNAL_RX_FLOOD`; else bond-down / soft drops / storage as appropriate.
7. Emit JSON: classes + evidence walls/rates + `root_cause_sentence` **describing log facts only**.
   No trunk/VLAN/stop-source `action_plan`.

## Script

```bash
python3 scripts/analyze_sar_network.py \
  --bundle-root /path/to/NTNX-Log-...-PE-<cvm> \
  --dnd-time '<optional DND wall>'
```

Fixture (synthetic diamond-shaped sar+ping): `fixtures/rx_flood_ping_case/`.

## See also

- [network-nic-mtu-ncc](../network-nic-mtu-ncc/SKILL.md)
- [network-rca-orchestrator](../network-rca-orchestrator/SKILL.md)
