---
name: portset-leftover-observe
description: >-
  Discover Atlas-only and computed-only port-set leftovers in flow_policy
  ClickHouse, reverse-hash them against the dump, and write observations.
  Use after ingest/compare, leftover Atlas port-sets, atlas_without_computed,
  computed_without_atlas, extra port-set UUIDs, or when asked why a port-set
  has no matching policy hash. Identity is UUID-only. Names are display.
---

# Port-set leftover observations

Match identity is **port-set UUID only**. A display name can repeat on many
UUIDs; never group leftovers by name.

Compare keeps leftover Atlas-only rows as mismatches. Do not hardcode leftover
UUIDs in compare or ingest.

## When to run

After `ingest.py` / `compare.py`, or when the user asks about leftovers.

## Steps

1. Run from `/home/rakeshkumar.r/panacea/clickhouse_flow/` (files are synced
   from `flow_pc_dump_github/clickhouse_flow/`):

```bash
python3 /home/rakeshkumar.r/panacea/clickhouse_flow/observe_leftovers.py \
  --out /home/rakeshkumar.r/panacea/clickhouse_flow/leftover_observations.md
```

`--dump_dir` is optional. If the PC dump JSON directory is present, pass it
for reverse-hash notes. If it is missing, classify leftovers from ClickHouse
only (Atlas leftover vs Atlas missing vs NIC UUID bugs).

2. Read `leftover_observations.md`.
3. Summarize **only**:
   - **Atlas leftover**: this UUID is in Atlas, not in computed.
   - **Atlas missing (critical)**: this UUID is in computed, not in Atlas.
   - **NIC UUID bugs**: computed NIC UUID missing in Atlas, or Atlas NIC UUID
     missing in computed.
4. Do not explain leftovers as "same name already matched". Names are labels.
5. Do not mention kube in the analysis write-up.
6. Do not group leftovers by display name.

## Rules

- ClickHouse native `127.0.0.1:19000`, database `flow_policy`.
- Address-set hashes (`uuid5(entity, "IPv4"|"IPv6")`) are not port-sets.
