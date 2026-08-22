# Flat `flow_policy.portset`

One ClickHouse table. Each row has two port-set UUID columns:

- `computed_port_set_uuid` — hash from policy selectors, or zero UUID if Atlas-only
- `atlas_port_set_uuid` — UUID from `port_set.list` / `port_set.get`, or zero UUID if computed-only

Zero UUID means not present. Port-set matching is UUID-only.

NIC membership is `Array(Tuple(vm_name, nic_uuid, subnet, vpc, ip))` on
`computed_nics` and `atlas_nics` so one NIC is one tuple. `flow_policy.vm_nic`
is the NIC lookup table for mismatch diffs.

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
