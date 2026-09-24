---
name: network-sar-debugging
description: >-
  Product Network SAR RCA from ClickHouse nu_metrics_sysstats (ingested SAR /
  ping LOST_PKT / host_nic / ethtool / bond). Detect EXTERNAL_RX_FLOOD on all
  bond members and correlate with ping loss. Offline diamond fallback via
  analyze_sar_network.py. Never invent trunk/VLAN remediations.
skill_type: atomic
component: networking
sub_component: network_sar_debugging
keywords:
  - sar
  - clickhouse
  - nu_metrics_sysstats
  - rx flood
  - ping
  - bond
  - host_nic
  - ethtool
  - network-debugging
  - dnd
symptoms:
  - "Intermittent CVM/host connectivity or peer timeouts"
  - "Ping LOST_PKT/unreachable during traffic surge"
  - "Cassandra timeouts correlating with host RX pps spikes"
severity: P0-P2
roles_allowed: [engineer, sre]
mcp_capabilities_required:
  - panacea_run_query
  - logs.search
last_verified: 2026-09-01
---

# Network SAR Debugging (product = ClickHouse)

## Where ingestion lives

Parsers in **panacea-ingestion-pipeline** write into `panacea.nu_metrics_sysstats`:

- Repo: `nutanix-core/panacea-ingestion-pipeline`
- Path: `services/ingestion_pipeline/parsers/ntnx_metric_parser/parsers/`
  - `sar_parser.py` — all non-guest ifaces + error/drop tables
  - `ping_all_parser.py` — `ping_all_lost_pkt` / `ping_all_unreachable`
  - `host_nic_stats_parser.py` — soft drops / CRC
  - `ethtool_bond_parsers.py` — `ethtool --statistics`, `ovs-appctl bond/show`
- PR: https://github.com/nutanix-core/panacea-ingestion-pipeline/pull/408

Without that ingest (or metrics-disabled lightweight bundles), CH returns empty →
`EVIDENCE_INSUFFICIENT`.

## Hard rules

1. **Product path = ClickHouse first** via `scripts/check_sar_debugging.py` →
   `run(db_client, context)` on `nu_metrics_sysstats` (+ anomaly).
2. **Never hardcode NIC names.** Use `bond_member_*` / `component_instance`.
3. Always emit classes: flood, ping↔flood, L1 CRC/drops, bond roles.
4. **CRC=0 is a finding.** Soft `rx_dropped` ≠ CRC.
5. Do **not** invent switch trunk/VLAN/stop-source remediations (not in metrics).

## Ingested metrics used

| Metric | Class |
|---|---|
| `sar_rx_packets_per_sec` / `sar_tx_packets_per_sec` | EXTERNAL_RX_FLOOD |
| `sar_rx_drops_per_sec` / `sar_rx_errors_per_sec` | DROPS / errors |
| `ping_all_lost_pkt` / `ping_all_unreachable` | PATH + correlation |
| `host_nic_rx_dropped` / `host_nic_rx_crc_errors` | L1 soft drop / CRC |
| `ethtool_rx_dropped` / `ethtool_rx_crc_errors` | L1 snapshot |
| `bond_member_active` / `bond_member_enabled` | BOND_LAG roles |

## Product procedure

1. Call `{capability: panacea_run_query}` / skill script `check_sar_debugging.run`
   with `bundle_id` (+ optional `cvm_ip` / time window).
2. Detect flood: `sar_rx_packets_per_sec` ≥ 100k (strong ≥ 500k); standby =
   high RX + ~0 TX or `bond_member_active=0` + enabled.
3. Correlate ping fail timestamps within ~120s of flood buckets →
   `PING_LOSS_CORRELATES_WITH_RX_FLOOD`.
4. Status: `EXTERNAL_RX_FLOOD_CORRELATED` | `EXTERNAL_RX_FLOOD_FOUND` |
   `PATH_LOSS_WITHOUT_FLOOD` | `L1_CRC_FOUND` | `NO_SAR_FLOOD_ISSUE` |
   `EVIDENCE_INSUFFICIENT`.

```bash
# Product (orchestrator injects db_client)
python -c "from check_sar_debugging import run; print(run(db, ctx))"
```

## Offline fallback (diamond files only)

When CH has no rows (lightweight / pre-ingest):

```bash
python3 scripts/analyze_sar_network.py --bundle-root /path/to/NTNX-Log-...-PE-<cvm>
```

## See also

- Ingest PR: https://github.com/nutanix-core/panacea-ingestion-pipeline/pull/408
- [network-rca-orchestrator](../network-rca-orchestrator/SKILL.md)
- [network-ping-tcp-baseline](../network-ping-tcp-baseline/SKILL.md)
