# Flat `flow_policy.portset`

One ClickHouse table. Each row has two port-set UUID columns:

- `computed_port_set_uuid` — hash from policy selectors, or zero UUID if Atlas-only
- `atlas_port_set_uuid` — UUID from `port_set.list` / `port_set.get`, or zero UUID if computed-only

Zero UUID means not present. Port-set matching is UUID-only.

FLEX dest/src keep the selector arrays **and** `applied_to_*` from the
applied_to entity group. That is two port-set UUIDs on the same row:
`port_set_uuid` (src/dest) and `applied_to_port_set_uuid`. `role =
'applied_to'` is the second UUID as its own Atlas-matching row.

One port-set UUID can belong to many rules, and each rule can have a
different service. `rule_uuids` lists those rules. `rule_u_sg` is
`Array(Tuple(rule_uuid, u_sg_id, rule_priority))`. FLEX dump
`spec.priority` (rule_priority) is per-rule on that tuple.
`flow_policy.u_sg` maps a unique service: dump `sg_id`, a list of dump
SG UUIDs (`sg_uuids`), or inline ports.

NIC membership is
`Array(Tuple(vm_name, nic_uuid, subnet, vpc, ip, host_uuid, host, cluster_uuid, cluster))`
on `computed_nics` and `atlas_nics`. Host comes from dump VM `host.ext_id`;
cluster comes from `hosts.json` → `clusters.json`. `flow_policy.vm_nic`
is the NIC lookup table.

## Workload Summary

- workload: security policy construct vs Atlas port-set
- latency target: local batch ingest, then `WHERE port_set_uuid = ?`
- data shape: ~15k component rows, ~1.3k Atlas port-sets, ~7.5k NICs
- primary query: both UUID columns present (non-zero) on the same identity
- ops: `127.0.0.1:19000` native, `127.0.0.1:8123` HTTP

## Key Decisions

- One flat table (`query-join-consider-alternatives`): both UUIDs written at ingest.
- ORDER BY starts with low-cardinality `entity_type`, then `port_set_uuid`
  (`schema-pk-cardinality-order`, `schema-pk-prioritize-filters`).
- Native `UUID` (`schema-types-native-types`). No Nullable; missing side is zero
  UUID (`schema-types-avoid-nullable`). No partition (`schema-partition-start-without`).
- Re-ingest via `ReplacingMergeTree(updated_at)` (`insert-mutation-avoid-update`).
- Inserts batched 10k rows (`insert-batch-size`).

## Presence mismatch

| `computed_port_set_uuid` | `atlas_port_set_uuid` | Result |
|---|---|---|
| present | present | match (then NIC sets must also be equal) |
| present | zero | mismatch |
| zero | present | mismatch |

## Scripts

Self-contained. Stdlib + `clickhouse-client`. No nutest, no neo4j.

```text
python3 ingest.py --dump_dir /path/to/dump
python3 compare.py
```

`compare.py` reads ClickHouse only (no JSON). It inserts replacement rows
with `match_status`, `mismatch_kind`, `only_computed_nics`, and
`only_atlas_nics` (ReplacingMergeTree, not ALTER UPDATE).
