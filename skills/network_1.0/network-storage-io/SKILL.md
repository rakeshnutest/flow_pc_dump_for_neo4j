---
name: network-storage-io
description: >-
  Confirm disk/SSD IO latency overlapping network/DND symptoms from logbay
  iostat (and ClickHouse when present). Emits explicit latency confirmation,
  not only a generic storage flag.
skill_type: atomic
component: networking
sub_component: network_storage_io
keywords:
  - network-rca-1.0
  - ssd-latency
  - iostat
  - await
  - dnd-overlap
symptoms:
  - "Need SSD/disk latency confirmation for DND or peer timeouts"
  - "NCC ssd_latency_threshold_check failed"
severity: P0-P2
roles_allowed: [engineer, sre]
mcp_capabilities_required:
  - logs.search
last_verified: 2026-09-01
---

## Purpose
**Confirm** disk/SSD latency as a causal driver (or rule it out).

Prefer the logbay one-pass:
```bash
python3 ../network-sar-debugging/scripts/analyze_sar_network.py \
  --bundle-root /path/to/NTNX-Log-...-PE-<cvm> \
  --dnd-time '<DND wall time>'
```
Read `classes.SSD_DISK_LATENCY`:
- `SSD_DISK_LATENCY_CONFIRMED` / `SEVERE` → latency is confirmed
- `NO_SSD_DISK_LATENCY` → not the driver
- `EVIDENCE_INSUFFICIENT` → missing iostat

## Confirmation thresholds

| Level | When |
|---|---|
| ELEVATED | await ≥ 30ms or util ≥ 90 or iowait ≥ 20 |
| CONFIRMED | w_await ≥ 100ms **or** r_await ≥ 50ms **or** iowait ≥ 20 with hot disk |
| SEVERE | await ≥ 500ms or iowait ≥ 40 |

Optional: `--dnd-time` → require peak within ±15 minutes of DND / peer-score 100.

## ClickHouse path (lightweight may fail)

`scripts/check_storage_io.py` queries CH sysstats/events. On
`panacea.ai-nologs` bundles expect `NO_STORAGE_IO_EVIDENCE` — use Diamond
iostat instead.

## See also
- [network-sar-debugging](../network-sar-debugging/SKILL.md)
- [network-host-pressure](../network-host-pressure/SKILL.md)
- [network-rca-orchestrator](../network-rca-orchestrator/SKILL.md)
