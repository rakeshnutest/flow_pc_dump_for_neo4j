---
name: network-sar-debugging
description: >-
  Atomic Network RCA node for SAR/sysstats link health: EXTERNAL_RX_FLOOD on
  bond members, ping LOST_PKT correlation, soft drops vs CRC, bond roles.
  Use after DND + ping/TCP (+ NIC/L1). Never invent trunk/VLAN remediations.
skill_type: atomic
component: networking
sub_component: network_sar_debugging
keywords:
  - network-rca-1.0
  - sar
  - rx flood
  - ping LOST_PKT
  - bond
  - soft drops
  - crc
  - link saturation
symptoms:
  - "Intermittent CVM/host loss or peer timeouts with traffic spikes"
  - "Ping LOST_PKT / unreachable during RX surge"
  - "Cassandra timeouts overlapping host RX pps spikes"
severity: P0-P2
roles_allowed: [engineer, sre]
mcp_capabilities_required:
  - panacea_run_query
  - logs.search
last_verified: 2026-09-01
---

## Purpose

One underlay evidence-class node in the network_1.0 RCA graph: classify
SAR/sysstats flood, path-loss correlation, and L1 soft-drop vs CRC. It does
not time DND, run pair ping, or bring up bonds/MTU.

## Graph position (node / edges)

| Role | Skill |
|------|--------|
| Upstream edges | `network-dnd-window` → `network-ping-tcp-baseline` → `network-nic-mtu-ncc` |
| This node | `network-sar-debugging` |
| Downstream edges | `network-host-pressure` / `network-storage-io`; expert branches via orchestrator |

Orchestrator owns dispatch. If ping loss is only inside a DND window, do
not promote flood/CRC as root — hand back upstream.

## Hard rules

1. Never hardcode NIC names — use bond membership / `component_instance`.
2. Always emit classes: flood, ping↔flood, L1 CRC/drops, bond roles.
3. CRC=0 is a finding. Soft `rx_dropped` ≠ CRC.
4. Do not invent switch trunk/VLAN/stop-source remediations (not in evidence).
5. Missing metrics/logs for this class → `EVIDENCE_INSUFFICIENT` (never treat as healthy).

## Decision tree

1. Query Panacea network/sysstats for the bundle window
   (`{capability: panacea_run_query}` / skill verifier `scripts/check_sar_debugging.py`
   → `run(db_client, context)`).
2. Flood: RX pps ≥ 100k (strong ≥ 500k); standby = high RX + ~0 TX or
   inactive+enabled bond member.
3. Correlate ping `LOST_PKT` / unreachable within ~120s of flood buckets.
4. Separate soft drops vs CRC on CVM and host sides.
5. Emit one primary status; list contributors / ruled-out.

## Outcomes

| Status | Meaning |
|--------|---------|
| `EXTERNAL_RX_FLOOD_CORRELATED` | Flood + ping loss overlap |
| `EXTERNAL_RX_FLOOD_FOUND` | Flood without ping overlap |
| `PATH_LOSS_WITHOUT_FLOOD` | Ping loss; no flood signal |
| `L1_CRC_FOUND` | Rising CRC / frame errors |
| `NO_SAR_FLOOD_ISSUE` | Coverage OK; no flood/CRC/path-loss signal |
| `EVIDENCE_INSUFFICIENT` | No usable sysstats for the window |

## See also

- [network-rca-orchestrator](../network-rca-orchestrator/SKILL.md)
- [network-ping-tcp-baseline](../network-ping-tcp-baseline/SKILL.md)
- [network-nic-mtu-ncc](../network-nic-mtu-ncc/SKILL.md)
- [network-host-pressure](../network-host-pressure/SKILL.md)
- [references/sar_waterfall_checklist.md](references/sar_waterfall_checklist.md)
