---
name: network-host-pressure
description: >-
  Host CPU/disk pressure overlap with network/DND symptoms using iostat and
  SAR. Must be paired with L1 CRC checks from network-sar-debugging /
  network-nic-mtu-ncc — pressure alone is not a complete NIC RCA.
skill_type: atomic
component: networking
sub_component: network_host_pressure
keywords:
  - network-rca-1.0
  - iostat
  - iowait
  - disk-util
  - dnd-overlap
symptoms:
  - "Suspected host pressure driving peer timeouts or DND"
  - "High iowait / SSD latency overlapping network symptoms"
severity: P0-P2
roles_allowed: [engineer, sre]
mcp_capabilities_required:
  - logs.search
last_verified: 2026-09-01
---

## Purpose
Detect host storage/CPU pressure overlapping network fault windows.

## Procedure

1. Scope DND / FATAL / peer-score window.
2. Parse `iostat.INFO*`: `%iowait`, disk `%util`, `r_await`, `w_await`.
3. Mark overlap if hot within ±15 min of DND set or peer score 100.
4. **Required handoff:** also run L1 CRC/drop class via
   [network-sar-debugging](../network-sar-debugging/SKILL.md) or
   [network-nic-mtu-ncc](../network-nic-mtu-ncc/SKILL.md). Do not close RCA
   on storage alone without stating CRC/drop/link status.

## Decision Tree

- Missing iostat → `EVIDENCE_INSUFFICIENT`
- Hot disk/iowait overlapping DND → `HOST_PRESSURE_OVERLAP`
- Hot without network overlap → `HOST_PRESSURE_NO_OVERLAP`
- Coverage OK, no hot signal → `NO_HOST_PRESSURE`

## Thresholds

| Signal | Suspect |
|---|---|
| `%iowait` | > 20 |
| Disk `%util` | > 90 |
| `r_await` / `w_await` | > 30 ms (severe if hundreds–thousands ms) |

## See also

- [network-sar-debugging](../network-sar-debugging/SKILL.md)
- [network-storage-io](../network-storage-io/SKILL.md)
- [network-rca-orchestrator](../network-rca-orchestrator/SKILL.md)
- [references/proc_1_host_pressure_overlap.md](references/proc_1_host_pressure_overlap.md)
