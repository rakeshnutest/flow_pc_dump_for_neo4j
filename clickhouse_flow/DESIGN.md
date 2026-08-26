# Flat `flow_policy.portset`

One ClickHouse table. Each row has two port-set UUID columns:

- `computed_port_set_uuid` — hash from policy selectors, or zero UUID if Atlas-only
- `atlas_port_set_uuid` — UUID from `port_set.list` / `port_set.get`, or zero UUID if computed-only

Zero UUID means not present. Port-set matching is UUID-only.

FLEX dest/src keep the selector arrays **and** `applied_to_*` from the
applied_to entity group. That is two port-set UUIDs on the same row:
`port_set_uuid` (src/dest) and `applied_to_port_set_uuid`. `role =
'applied_to'` is the second UUID as its own Atlas-matching row.

One port-set UUID can belong to many policies and rules. The row has no
`policy_uuid`, `policy_name`, `rule_uuid`, or `component_id`. `rule_u_sg`
is one tuple per policy+rule that uses this hash:
`(rule_uuid, sg_id[], sg_ports, policy_name, policy_uuid, policy_type,
policy_mode, flex_policy, rule_priority, type)`.
`policy_type` is `app` / `isolation` / `quarantine`. `policy_mode` is
`enforce` / `monitor` / `save` (dump `state` `APPLY` → `enforce`).
`type` is `secured_entity`, `end_point_src`, or `end_point_dst`.
FLEX dump `spec.priority` is `rule_priority`; `rule.type == FLEX` sets
`flex_policy`.
`flow_policy.u_sg` is the unique-service lookup table.

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
- ORDER BY starts with `log_bundle_id` (filter), then low-cardinality
  `entity_type`, then `port_set_uuid`
  (`schema-pk-cardinality-order`, `schema-pk-prioritize-filters`).
- Native `UUID` (`schema-types-native-types`). No Nullable; missing side is zero
  UUID (`schema-types-avoid-nullable`).
- `PARTITION BY log_bundle_id` so re-ingest of the same Panacea bundle is
  `ALTER TABLE … DROP PARTITION` (`schema-partition-lifecycle`,
  `insert-mutation-avoid-delete`). Cardinality is retained dumps, not NICs
  (`schema-partition-low-cardinality`). This IR is not a time-series log, so
  there is no `toDate(event_time)` in the partition key.
- Re-ingest via DROP PARTITION then insert, plus `ReplacingMergeTree(updated_at)`
  (`insert-mutation-avoid-update`).
- Inserts batched 10k rows (`insert-batch-size`).
- Catalog row in `flow_policy.bundle`: dump_dir, cluster_uuid/name, pc_ip,
  nos_version, collected_at (Panacea `nu_metadata` analogue).

## Presence mismatch

| `computed_port_set_uuid` | `atlas_port_set_uuid` | Result |
|---|---|---|
| present | present | match (then NIC sets must also be equal) |
| present | zero | mismatch |
| zero | present | mismatch |

## Scripts

Self-contained. Stdlib + `clickhouse-client`. No nutest, no neo4j.

```text
python3 ingest.py --dump_dir /path/to/dump --log_bundle_id 123
python3 compare.py --log_bundle_id 123
# re-ingest the same dump: DROP PARTITION 123 only, other bundles stay
python3 ingest.py --dump_dir /path/to/dump --log_bundle_id 123
# first migration from unpartitioned tables:
python3 ingest.py --dump_dir /path/to/dump --log_bundle_id 123 --reset-schema
```

`compare.py` reads ClickHouse only (no JSON). It inserts replacement rows
with `match_status`, `mismatch_kind`, `only_computed_nics`, and
`only_atlas_nics` (ReplacingMergeTree, not ALTER UPDATE).
