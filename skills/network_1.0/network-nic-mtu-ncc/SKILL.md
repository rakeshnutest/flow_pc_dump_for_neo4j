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

## Mandatory L1 checklist (never skip)

From logbay / diamond PE bundle:

1. `ahv/<host>/commands/ethtool_--statistics_<iface>.stdout`
   - `rx_crc_errors`, `rx_length_errors`, `rx_frame_errors`
   - `rx_errors`, `tx_errors`, `rx_dropped`, `tx_dropped`, `collisions`
2. `ahv/<host>/commands/ethtool_<iface>.stdout` — Speed, Duplex, Link detected
3. `cvm_logs/sysstats/host_nic_stats.INFO*` — first→last **delta** for same counters
4. `ifconfig_-a.stdout` — RX/TX errors, dropped, overruns, carrier, collisions
5. NCC / bond / MTU config (see references)

**CRC=0 with large rx_dropped → `SOFT_RX_DROPS`, not CRC fault.**

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
