---
name: network-nic-mtu-ncc
description: >-
  NIC bond/link, MTU/NCC, and mandatory L1 CRC/ethtool/host_nic_stats checks
  for Network RCA. Never report drops without stating CRC.
skill_type: atomic
component: networking
sub_component: network_nic_mtu_ncc
keywords:
  - network-rca-1.0
  - ethtool
  - crc
  - host_nic_stats
  - mtu
  - ncc
symptoms:
  - "NIC flap, CRC, drops, MTU mismatch, or NCC NIC checks"
  - "Need L1 vs soft-drop separation for packet loss"
severity: P0-P2
roles_allowed: [engineer, sre]
mcp_capabilities_required:
  - logs.search
last_verified: 2026-09-01
---

## Purpose
Collect NIC/MTU/NCC evidence and **always** classify L1 vs soft drops.

## Mandatory L1 checklist (never skip; never hardcode NIC names)

1. **Bond/LAG first** — `ovs-appctl bond/show`: discover members dynamically  
   (no `eth1`/`eth2` assumptions). Record active / standby / disabled.
2. For **each bond member name returned**, check:
   - `ethtool <member>` — Speed, Duplex, Link detected  
   - `ethtool -S` / `host_nic_stats` — CRC, errors, drops  
   - `ethtool -k` — TSO/GSO/GRO/LRO  
   - `dmesg -T` — NIC Link Up/Down for that member  
3. `ifconfig_-a` / `ip addr` — NO-CARRIER, errors, drops  
4. NCC / MTU config (see references)

**CRC=0 with large rx_dropped on active member → `SOFT_RX_DROPS`.**  
**Standby member drops ≠ active-path loss.**  
**active-backup standby is expected when enabled + link up.**

## Decision Tree

- Missing all L1 sources → `EVIDENCE_INSUFFICIENT` (still emit empty L1 keys)
- CRC/frame/carrier/collisions rising or link down → `L1_CRC_OR_LINK_FOUND`
- Drops with CRC≈0 → `SOFT_RX_DROPS_FOUND`
- MTU/NCC mismatch → `MTU_OR_NCC_ISSUE`
- Coverage OK, no signal → `NO_NIC_L1_ISSUE`

## Prefer companion skill

For full SAR + iostat + ping + L1 in one pass, run
[network-sar-debugging](../network-sar-debugging/SKILL.md) with `--bundle-root`.

## See also

- [network-sar-debugging](../network-sar-debugging/SKILL.md)
- [network-rca-orchestrator](../network-rca-orchestrator/SKILL.md)
- [references/proc_1_nic_bond_link.md](references/proc_1_nic_bond_link.md)
- [references/proc_2_mtu_ncc_config.md](references/proc_2_mtu_ncc_config.md)
